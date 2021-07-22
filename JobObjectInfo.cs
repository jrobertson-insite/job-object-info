using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Newtonsoft.Json;
// ReSharper disable InconsistentNaming
#pragma warning disable 1591

namespace JobObjectInfo
{
    public class JobObjectMemoryInfo
    {
        [JsonIgnore]
        public bool isError { get; set; }

        [JsonIgnore]
        public string message { get; set; }

        public ulong memoryLimit { get; set; }
        public ulong peakMemory { get; set; }
        public ulong currentMemory { get; set; }
    }

    public class LogMessage
    {
        public LogMessage(JobObjectMemoryInfo jobObjectMemoryInfo)
        {
            if (jobObjectMemoryInfo.isError)
            {
                level = "ERROR";
            }

            message = !string.IsNullOrEmpty(jobObjectMemoryInfo.message)
                ? jobObjectMemoryInfo.message
                : $"Container Memory: {jobObjectMemoryInfo.currentMemory}";

            containerMemory = jobObjectMemoryInfo;
        }

        public JobObjectMemoryInfo containerMemory { get; set; }

        public string logger { get; set; } = "JobObjectInfo";
        public string message { get; set; }
        public string level { get; set; } = "DEBUG";
    }

    public static class JobObjectInfo
    {
        /// <summary>
        /// Log memory usage inside windows containers to a file.
        /// </summary>
        /// <param name="logInterval">Interval (in minutes) between logging memory statistics.</param>
        /// <param name="memoryThreshold">Memory usage change required between logging memory statistics.</param>
        /// <param name="logFilePath">Path to log memory statistics.</param>
        static void Main(int logInterval = 5, int memoryThreshold = 50, string logFilePath = @"c:\inetpub\wwwroot\App_Log\memoryusage.log")
        {
            var limitInfoJobObjectLength = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
            var limitInfoJobObject = Marshal.AllocHGlobal(limitInfoJobObjectLength);

            var limitViolationJobObjectLength = Marshal.SizeOf(typeof(JobObjectLimitViolationInformation));
            var limitViolationJobObject = Marshal.AllocHGlobal(limitViolationJobObjectLength);

            var oldJobObjectStats = new JobObjectMemoryInfo();
            var lastLogMessage = DateTime.MinValue;
            while (true)
            {
                var jobObjectStats = new JobObjectMemoryInfo();
                if (QueryInformationJobObject(IntPtr.Zero, JobObjectInfoClass.JobObjectExtendedLimitInformation, limitInfoJobObject, limitInfoJobObjectLength, out _))
                {
                    var extendedInfo = (JobObjectExtendedLimitInformation) Marshal.PtrToStructure(limitInfoJobObject, typeof(JobObjectExtendedLimitInformation));
                    jobObjectStats.memoryLimit = extendedInfo.JobMemoryLimit.ToUInt64() / 1024 / 1024;
                    jobObjectStats.peakMemory = extendedInfo.PeakJobMemoryUsed.ToUInt64() / 1024 / 1024;
                }
                else
                {
                    jobObjectStats.isError = true;
                    jobObjectStats.message += "Error retrieving JobObjectExtendedLimitInformation while monitoring Docker limit information.";
                }

                if (QueryInformationJobObject(IntPtr.Zero, JobObjectInfoClass.JobObjectLimitViolationInformation, limitViolationJobObject, limitViolationJobObjectLength, out _))
                {
                    var violationInformation = (JobObjectLimitViolationInformation) Marshal.PtrToStructure(limitViolationJobObject, typeof(JobObjectLimitViolationInformation));
                    jobObjectStats.currentMemory = (uint)(violationInformation.JobMemory / 1024 / 1024);
                }
                else
                {
                    jobObjectStats.isError = true;
                    jobObjectStats.message += "Error retrieving JobObjectLimitViolationInformation while monitoring Docker limit information.";
                }

                var minutesSinceLastLogMessage = (DateTime.Now - lastLogMessage).Minutes;
                var memoryDifference = jobObjectStats.currentMemory > oldJobObjectStats.currentMemory 
                    ? jobObjectStats.currentMemory - oldJobObjectStats.currentMemory
                    : oldJobObjectStats.currentMemory - jobObjectStats.currentMemory;
                if (memoryDifference > (ulong)memoryThreshold || jobObjectStats.isError || minutesSinceLastLogMessage > logInterval)
                {
                    lastLogMessage = DateTime.Now;
                    oldJobObjectStats = jobObjectStats;
                    var logMessage = JsonConvert.SerializeObject(new LogMessage(jobObjectStats));
                    File.AppendAllText(logFilePath, logMessage);
                    Console.WriteLine(logMessage);
                }

                Thread.Sleep(TimeSpan.FromSeconds(1));
            }

#pragma warning disable 162
            File.AppendAllText(logFilePath, JsonConvert.SerializeObject(JsonConvert.SerializeObject(new LogMessage(new JobObjectMemoryInfo { isError = true, message = "JobObjectStats exited infinite loop."}), Formatting.None)));
#pragma warning restore 162
        }

        [DllImport("kernel32.dll")]
        static extern bool QueryInformationJobObject(IntPtr hJob, JobObjectInfoClass jobObjectInfoClass, [Out, MarshalAs(UnmanagedType.SysUInt)] IntPtr lpJobObjectInfo, int cbJobObjectInfoLength, out int lpReturnLength);

        public enum JobObjectInfoClass
        {
            JobObjectAssociateCompletionPortInformation = 7,
            JobObjectBasicLimitInformation = 2,
            JobObjectBasicUIRestrictions = 4,
            JobObjectEndOfJobTimeInformation = 6,
            JobObjectExtendedLimitInformation = 9,
            JobObjectSecurityLimitInformation = 5,
            JobObjectLimitViolationInformation = 13,
            JobObjectCpuRateControlInformation = 15,
            JobObjectLimitViolationInformation2 = 34
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JobObjectExtendedLimitInformation
        {
            public JobObjectBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JobObjectLimitViolationInformation {
            public JobObjectLimit LimitFlags;
            public JobObjectLimit ViolationLimitFlags;
            public ulong IoReadBytes;
            public ulong IoReadBytesLimit;
            public ulong IoWriteBytes;
            public ulong IoWriteBytesLimit;
            public TimeSpan PerJobUserTime;
            public TimeSpan PerJobUserTimeLimit;
            public ulong JobMemory;
            public ulong JobMemoryLimit;
            public JobObjectRateControlTolerance RateControlTolerance;
            public JobObjectRateControlTolerance RateControlToleranceLimit;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JobObjectBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public JobObjectLimit LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public long Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        public enum JobObjectRateControlTolerance
        {
            ToleranceLow = 1,
            ToleranceMedium,
            ToleranceHigh
        }

        [Flags]
        public enum JobObjectLimit : uint
        {
            // Basic Limits
            Workingset = 0x00000001,
            ProcessTime = 0x00000002,
            JobTime = 0x00000004,
            ActiveProcess = 0x00000008,
            Affinity = 0x00000010,
            PriorityClass = 0x00000020,
            PreserveJobTime = 0x00000040,
            SchedulingClass = 0x00000080,

            // Extended Limits
            ProcessMemory = 0x00000100,
            JobMemory = 0x00000200,
            DieOnUnhandledException = 0x00000400,
            BreakawayOk = 0x00000800,
            SilentBreakawayOk = 0x00001000,
            KillOnJobClose = 0x00002000,
            SubsetAffinity = 0x00004000,

            // Notification Limits
            JobReadBytes = 0x00010000,
            JobWriteBytes = 0x00020000,
            RateControl = 0x00040000,
        }
    }
}
