using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSProcessMonitor
{
    public enum EventClass : short
    {
        Post = 0,
        Process = 1,
        Registry = 2,
        File = 3,
        Profiling = 4,
        Network = 5,
    }

    public enum PostOperation : short
    {
        // todo?
    }

    public enum ProcessOperation : short
    {
        ProcessDefined = 0,
        ProcessCreate = 1,
        ProcessExit = 2,
        ThreadCreate = 3,
        ThreadExit = 4,
        LoadImage = 5,
        ThreadProfile = 6,
        ProcessStart = 7,
        ProcessStatistics = 8,
        SystemStatistics = 9,
    }
    public enum RegistryOperation : short
    {
        RegOpenKey = 0,
        RegCreateKey = 1,
        RegCloseKey = 2,
        RegQueryKey = 3,
        RegSetValue = 4,
        RegQueryValue = 5,
        RegEnumValue = 6,
        RegEnumKey = 7,
        RegSetInfoKey = 8,
        RegDeleteKey = 9,
        RegDeleteValue = 10,
        RegFlushKey = 11,
        RegLoadKey = 12,
        RegUnloadKey = 13,
        RegRenameKey = 14,
        RegQueryMultipleValueKey = 15,
        RegSetKeySecurity = 16,
        RegQueryKeySecurity = 17,
    }
    public enum NetworkOperation : short
    {
        Unknown = 0,
        Other = 1,
        Send = 2,
        Receive = 3,
        Accept = 4,
        Connect = 5,
        Disconnect = 6,
        Reconnect = 7,
        Retransmit = 8,
        TCPCopy = 9,
    }

    public enum ProfilingOperation : short
    {
        ThreadProfiling = 0,
        ProcessProfiling = 1,
        DebugOutputProfiling = 2,
    }

    public enum FilesystemOperation : short
    {
        VolumeDismount = 0,
        IRP_MJ_VOLUME_DISMOUNT = 0,
        VolumeMount = 1,
        IRP_MJ_VOLUME_MOUNT = 1,
        FASTIO_MDL_WRITE_COMPLETE = 2,
        WriteFile2 = 3,
        FASTIO_PREPARE_MDL_WRITE = 3,
        FASTIO_MDL_READ_COMPLETE = 4,
        ReadFile2 = 5,
        FASTIO_MDL_READ = 5,
        QueryOpen = 6,
        FASTIO_NETWORK_QUERY_OPEN = 6,
        FASTIO_CHECK_IF_POSSIBLE = 7,
        IRP_MJ_12 = 8,
        IRP_MJ_11 = 9,
        IRP_MJ_10 = 10,
        IRP_MJ_9 = 11,
        IRP_MJ_8 = 12,
        FASTIO_NOTIFY_STREAM_FO_CREATION = 13,
        FASTIO_RELEASE_FOR_CC_FLUSH = 14,
        FASTIO_ACQUIRE_FOR_CC_FLUSH = 15,
        FASTIO_RELEASE_FOR_MOD_WRITE = 16,
        FASTIO_ACQUIRE_FOR_MOD_WRITE = 17,
        FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION = 18,
        CreateFileMapping = 19,
        FASTIO_ACQUIRE_FOR_SECTION_SYNCHRONIZATION = 19,
        CreateFile = 20,
        IRP_MJ_CREATE = 20,
        CreatePipe = 21,
        IRP_MJ_CREATE_NAMED_PIPE = 21,
        IRP_MJ_CLOSE = 22,
        ReadFile = 23,
        IRP_MJ_READ = 23,
        WriteFile = 24,
        IRP_MJ_WRITE = 24,
        QueryInformationFile = 25,
        IRP_MJ_QUERY_INFORMATION = 25,
        SetInformationFile = 26,
        IRP_MJ_SET_INFORMATION = 26,
        QueryEAFile = 27,
        IRP_MJ_QUERY_EA = 27,
        SetEAFile = 28,
        IRP_MJ_SET_EA = 28,
        FlushBuffersFile = 29,
        IRP_MJ_FLUSH_BUFFERS = 29,
        QueryVolumeInformation = 30,
        IRP_MJ_QUERY_VOLUME_INFORMATION = 30,
        SetVolumeInformation = 31,
        IRP_MJ_SET_VOLUME_INFORMATION = 31,
        DirectoryControl = 32,
        IRP_MJ_DIRECTORY_CONTROL = 32,
        FileSystemControl = 33,
        IRP_MJ_FILE_SYSTEM_CONTROL = 33,
        DeviceIoControl = 34,
        IRP_MJ_DEVICE_CONTROL = 34,
        InternalDeviceIoControl = 35,
        IRP_MJ_INTERNAL_DEVICE_CONTROL = 35,
        Shutdown = 36,
        IRP_MJ_SHUTDOWN = 36,
        LockUnlockFile = 37,
        IRP_MJ_LOCK_CONTROL = 37,
        CloseFile = 38,
        IRP_MJ_CLEANUP = 38,
        CreateMailSlot = 39,
        IRP_MJ_CREATE_MAILSLOT = 39,
        QuerySecurityFile = 40,
        IRP_MJ_QUERY_SECURITY = 40,
        SetSecurityFile = 41,
        IRP_MJ_SET_SECURITY = 41,
        Power = 42,
        IRP_MJ_POWER = 42,
        SystemControl = 43,
        IRP_MJ_SYSTEM_CONTROL = 43,
        DeviceChange = 44,
        IRP_MJ_DEVICE_CHANGE = 44,
        QueryFileQuota = 45,
        IRP_MJ_QUERY_QUOTA = 45,
        SetFileQuota = 46,
        IRP_MJ_SET_QUOTA = 46,
        PlugAndPlay = 47,
        IRP_MJ_PNP = 47,
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x34)]
    public struct EventHeaderStruct
    {
        [FieldOffset(0x0)]
        public int ProcessSeq;
        [FieldOffset(0x4)]
        public int ThreadId;
        [FieldOffset(0x8)]
        public short Class;
        [FieldOffset(0xC)]
        public short Operation;
        [FieldOffset(0x10)]
        public int Sequence;
        [FieldOffset(0x14)]
        public int Duration;
        [FieldOffset(0x1C)]
        public long Timestamp;
        [FieldOffset(0x24)]
        public int Status;
        [FieldOffset(0x28)]
        public short StackTraceLength;
        [FieldOffset(0x2C)]
        public int DetailsLength;
        [FieldOffset(0x30)]
        public int DetailsOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessCreateStruct
    {
        public int ProcessSeq;
        public int ProcessId;
        public int ParentProcessSeq;
        public int ParentProcessId;
        public int SessionId;
        public int IsWow64;
        public long CreateTime;
        public LUID AuthenticationId;
        public int Virtualized;
        public byte SidLength;
        public byte IntegritySidLength;
        public ushort ProcessNameLength;
        public ushort CommandLineLength;
        public short Unknown;
    }

    public class ProcessCreateDetails
    {
        public int ProcessSeq;
        public int ProcessId;
        public int ParentProcessSeq;
        public int ParentProcessId;
        public int SessionId;
        public bool IsProcess64bit;
        public DateTime CreateTime;
        public string AuthenticationId;
        public bool Virtualized;
        public string User;
        public string UserSID;
        public string Integrity;
        public string IntegritySID;
        public string ProcessName;
        public string CommandLine;

        internal ProcessCreateDetails GetFromDataStream(DataStreamView dataStreamView)
        {
            ProcessCreateStruct processCreateStruct = dataStreamView.ReadStructure<ProcessCreateStruct>();
            string processName = null, commandLine = null, user = null, userSID = null, integrity = null, integritySID = null;
            if (processCreateStruct.SidLength != 0)
            {
                IntPtr ptrSID = dataStreamView.Ptr;
                dataStreamView.Move(processCreateStruct.SidLength);
            }
            if(processCreateStruct.IntegritySidLength != 0)
            {
                IntPtr ptrIntegritySID = dataStreamView.Ptr;
                dataStreamView.Move(processCreateStruct.IntegritySidLength);
            }
            if(processCreateStruct.ProcessNameLength != 0)
            {
                IntPtr ptrProcessName = dataStreamView.Ptr;
                processName = Marshal.PtrToStringUni(ptrProcessName);
                dataStreamView.Move(processCreateStruct.ProcessNameLength);
            }
            if(processCreateStruct.CommandLineLength != 0)
            {
                IntPtr ptrCommandLine = dataStreamView.Ptr;
                commandLine = Marshal.PtrToStringUni(ptrCommandLine);
                dataStreamView.Move(processCreateStruct.CommandLineLength);
            }

            return new ProcessCreateDetails
            {
                ProcessSeq = processCreateStruct.ProcessSeq,
                ProcessId = processCreateStruct.ProcessId,
                ParentProcessSeq = processCreateStruct.ParentProcessSeq,
                ParentProcessId = processCreateStruct.ParentProcessId,
                SessionId = processCreateStruct.SessionId,
                IsProcess64bit = (processCreateStruct.IsWow64 == 0),
                CreateTime = DateTime.FromFileTime(processCreateStruct.CreateTime),
                AuthenticationId = string.Format("{0:X08}:{1:X08}", processCreateStruct.AuthenticationId.HighPart, processCreateStruct.AuthenticationId.LowPart),
                Virtualized = (processCreateStruct.Virtualized != 0),
                User = user,
                UserSID = userSID,
                Integrity = integrity,
                IntegritySID = integritySID,
                ProcessName = processName,
                CommandLine = commandLine,
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessStartStruct
    {
        public int ParentProcessId;
        public ushort CommandNameLength;
        public ushort CurrentDirectoryLength;
        public int EnvironmentLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessExitStruct
    {
        public int ExitStatus;
        public long KernelTime;
        public long UserTime;
        public long WorkingSetSize;
        public long PeakWorkingSetSize;
        public long PagefileUsage;
        public long PeakPagefileUsage;
    }

    [StructLayout(LayoutKind.Sequential, Size = 0x10)]
    public struct ProcessLoadImage
    {
        public IntPtr ImageBase;
        public int ImageSize;
        public short ImageNameLength;
    }

    /**
     * <summary>
     * Context-less event representation
     * </summary>
     */
    public class RawEvent
    {
        public readonly EventHeaderStruct header;
        public readonly long[] stackTrace;
        public readonly DataStreamView detailsData;

        public int ProcessSeq;
        public int ThreadId;
        public EventClass Class;
        public Enum Operation;
        public int Sequence;
        public int Duration;
        public DateTime Timestamp;
        public int Status;

        private static Dictionary<EventClass, Type> operationEnumMapping = new Dictionary<EventClass, Type>
        {
            [EventClass.Post] = typeof(PostOperation),
            [EventClass.Process] = typeof(ProcessOperation),
            [EventClass.Registry] = typeof(RegistryOperation),
            [EventClass.File] = typeof(FilesystemOperation),
            [EventClass.Profiling] = typeof(ProfilingOperation),
            [EventClass.Network] = typeof(NetworkOperation),
        };

        public RawEvent(EventHeaderStruct header, long[] stackTrace, DataStreamView detailsData)
        {
            this.header = header;
            this.stackTrace = stackTrace;
            this.detailsData = detailsData;

            ProcessSeq = header.ProcessSeq;
            ThreadId = header.ThreadId;
            Class = (EventClass)header.Class;
            Operation = (Enum)Enum.ToObject(operationEnumMapping[Class], header.Operation);
            Sequence = header.Sequence;
            Duration = header.Duration;
            Timestamp = DateTime.FromFileTime(header.Timestamp);
            Status = header.Status;
        }
    }
}
