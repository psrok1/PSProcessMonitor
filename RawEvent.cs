using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSProcessMonitor
{
    public enum EventClass : short
    {
        // This is post-callback for I/O events
        // containing extra details about finished operation
        Post = 0,
        Process = 1,
        Registry = 2,
        File = 3,
        Profiling = 4,
        // This field is used in PML files only
        // Kernel driver doesn't track network events
        Network = 5,
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
        // This field is used in PML files only
        [FieldOffset(0x30)]
        public int ExtraDetailsOffset;
    }

    public abstract class EventDetails
    {
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
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
        public byte UserSidLength;
        public byte IntegritySidLength;
        public ushort ProcessNameLength;
        public ushort CommandLineLength;
        public short Unknown;
    }

    public class ProcessCreateDetails: EventDetails
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

        internal ProcessCreateDetails(DataStreamView dataStreamView)
        {
            ProcessCreateStruct processCreateStruct = dataStreamView.ReadStructure<ProcessCreateStruct>();

            ProcessSeq = processCreateStruct.ProcessSeq;
            ProcessId = processCreateStruct.ProcessId;
            ParentProcessSeq = processCreateStruct.ParentProcessSeq;
            ParentProcessId = processCreateStruct.ParentProcessId;
            SessionId = processCreateStruct.SessionId;
            IsProcess64bit = (processCreateStruct.IsWow64 == 0);
            CreateTime = DateTime.FromFileTime(processCreateStruct.CreateTime);
            AuthenticationId = string.Format("{0:X08}:{1:X08}", processCreateStruct.AuthenticationId.HighPart, processCreateStruct.AuthenticationId.LowPart);
            Virtualized = (processCreateStruct.Virtualized != 0);

            if (processCreateStruct.UserSidLength != 0)
            {
                IntPtr ptrSID = dataStreamView.Ptr;
                UserSID = NativeWin32.ConvertSidToString(ptrSID);
                User = NativeWin32.ConvertSidToAccountName(ptrSID);
                dataStreamView.Move(processCreateStruct.UserSidLength);
            }
            if(processCreateStruct.IntegritySidLength != 0)
            {
                IntPtr ptrSID = dataStreamView.Ptr;
                IntegritySID = NativeWin32.ConvertSidToString(ptrSID);
                Integrity = NativeWin32.ConvertSidToAccountName(ptrSID);
                dataStreamView.Move(processCreateStruct.IntegritySidLength);
            }
            ProcessName = dataStreamView.ReadProcmonString(processCreateStruct.ProcessNameLength);
            CommandLine = dataStreamView.ReadProcmonString(processCreateStruct.CommandLineLength);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ProcessStartStruct
    {
        public int ParentProcessId;
        public ushort CommandLineLength;
        public ushort CurrentDirectoryLength;
        public int EnvironmentLength;
    }

    public class ProcessStartDetails: EventDetails
    {
        public int ParentProcessId;
        public string CommandLine;
        public string CurrentDirectory;
        public string Environment;

        internal ProcessStartDetails(DataStreamView dataStreamView)
        {
            ProcessStartStruct processStartStruct = dataStreamView.ReadStructure<ProcessStartStruct>();

            ParentProcessId = processStartStruct.ParentProcessId;
            CommandLine = dataStreamView.ReadProcmonString(processStartStruct.CommandLineLength);
            CurrentDirectory = dataStreamView.ReadProcmonString(processStartStruct.CurrentDirectoryLength);
            Environment = dataStreamView.ReadUnicodeString(processStartStruct.EnvironmentLength);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
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

    public class ProcessExitDetails: EventDetails
    {
        public int ExitStatus;
        public long KernelTime;
        public long UserTime;
        public long WorkingSetSize;
        public long PeakWorkingSetSize;
        public long PagefileUsage;
        public long PeakPagefileUsage;

        internal ProcessExitDetails(DataStreamView dataStreamView)
        {
            ProcessExitStruct processExitStruct = dataStreamView.ReadStructure<ProcessExitStruct>();
            ExitStatus = processExitStruct.ExitStatus;
            KernelTime = processExitStruct.KernelTime;
            UserTime = processExitStruct.UserTime;
            WorkingSetSize = processExitStruct.WorkingSetSize;
            PeakWorkingSetSize = processExitStruct.PeakWorkingSetSize;
            PagefileUsage = processExitStruct.PagefileUsage;
            PeakPagefileUsage = processExitStruct.PeakPagefileUsage;
        }
    }

    [StructLayout(LayoutKind.Sequential, Size = 0x10, Pack = 1)]
    public struct LoadImageStruct
    {
        public IntPtr ImageBase;
        public int ImageSize;
        public ushort ImageNameLength;
    }

    public class LoadImageDetails: EventDetails
    {
        public IntPtr ImageBase;
        public int ImageSize;
        public string ImageName;

        internal LoadImageDetails(DataStreamView dataStreamView)
        {
            LoadImageStruct processLoadImageStruct = dataStreamView.ReadStructure<LoadImageStruct>();
            ImageBase = processLoadImageStruct.ImageBase;
            ImageSize = processLoadImageStruct.ImageSize;
            ImageName = dataStreamView.ReadProcmonString(processLoadImageStruct.ImageNameLength);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ThreadCreateStruct
    {
        public int ThreadID;
    }

    public class ThreadCreateDetails: EventDetails
    {
        public int ThreadID;
        
        internal ThreadCreateDetails(DataStreamView dataStreamView)
        {
            ThreadCreateStruct threadCreateStruct = dataStreamView.ReadStructure<ThreadCreateStruct>();
            ThreadID = threadCreateStruct.ThreadID;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ThreadExitStruct
    {
        public int ExitCode;
        public long KernelTime;
        public long UserTime;
    }

    public class ThreadExitDetails: EventDetails
    {
        public int ExitCode;
        public long KernelTime;
        public long UserTime;

        internal ThreadExitDetails(DataStreamView dataStreamView)
        {
            ThreadExitStruct threadExitStruct = dataStreamView.ReadStructure<ThreadExitStruct>();
            ExitCode = threadExitStruct.ExitCode;
            KernelTime = threadExitStruct.KernelTime;
            UserTime = threadExitStruct.UserTime;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RegistryBasicKeyStruct
    {
        public ushort PathLength;
    }

    public class RegistryBasicKeyDetails : EventDetails
    {
        public string Path;

        internal RegistryBasicKeyDetails(DataStreamView dataStreamView)
        {
            RegistryBasicKeyStruct basicKeyStruct = dataStreamView.ReadStructure<RegistryBasicKeyStruct>();
            Path = dataStreamView.ReadProcmonString(basicKeyStruct.PathLength);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct RegistryOpenCreateKeyStruct
    {
        public ushort PathLength;
        public int DesiredAccess;
    }

    public class RegistryOpenCreateKeyDetails: EventDetails
    {
        public string Path;
        public int DesiredAccess;

        internal RegistryOpenCreateKeyDetails(DataStreamView dataStreamView)
        {
            RegistryOpenCreateKeyStruct openCreateKeyStruct = dataStreamView.ReadStructure<RegistryOpenCreateKeyStruct>();
            Path = dataStreamView.ReadProcmonString(openCreateKeyStruct.PathLength);
            DesiredAccess = openCreateKeyStruct.DesiredAccess;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct RegistryPostOpenCreateKeyStruct
    {
        public int GrantedAccess;
        public int Disposition;
    }

    public class RegistryPostOpenCreateKeyDetails: EventDetails
    {
        public int GrantedAccess;
        public int Disposition;

        internal RegistryPostOpenCreateKeyDetails(DataStreamView dataStreamView)
        {
            RegistryPostOpenCreateKeyStruct postOpenCreateKeyStruct = dataStreamView.ReadStructure<RegistryPostOpenCreateKeyStruct>();
            GrantedAccess = postOpenCreateKeyStruct.GrantedAccess;
            Disposition = postOpenCreateKeyStruct.Disposition;
        }
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

        public int ProcessSeq;
        public int ThreadId;
        public EventClass Class;
        public Enum Operation;
        public int Sequence;
        public int Duration;
        public DateTime Timestamp;
        public int Status;
        public EventDetails Details;
        public EventDetails PostDetails;

        private delegate EventDetails DetailsConstructor(DataStreamView dataStreamView);

        private static Dictionary<EventClass, Type> operationEnumMapping = new Dictionary<EventClass, Type>
        {
            [EventClass.Process] = typeof(ProcessOperation),
            [EventClass.Registry] = typeof(RegistryOperation),
            [EventClass.File] = typeof(FilesystemOperation),
            [EventClass.Profiling] = typeof(ProfilingOperation),
            [EventClass.Network] = typeof(NetworkOperation),
        };

        private static Dictionary<Enum, DetailsConstructor> operationDetailsMapping = new Dictionary<Enum, DetailsConstructor>
        {
            [ProcessOperation.ProcessDefined] = (detailsData) => new ProcessCreateDetails(detailsData),
            [ProcessOperation.ProcessCreate] = (detailsData) => new ProcessCreateDetails(detailsData),
            [ProcessOperation.ProcessStart] = (detailsData) => new ProcessStartDetails(detailsData),
            [ProcessOperation.ProcessExit] = (detailsData) => new ProcessExitDetails(detailsData),
            [ProcessOperation.LoadImage] = (detailsData) => new LoadImageDetails(detailsData),
            [ProcessOperation.ThreadCreate] = (detailsData) => new ThreadCreateDetails(detailsData),
            [ProcessOperation.ThreadExit] = (detailsData) => new ThreadExitDetails(detailsData),
            [RegistryOperation.RegOpenKey] = (detailsData) => new RegistryOpenCreateKeyDetails(detailsData),
            [RegistryOperation.RegCreateKey] = (detailsData) => new RegistryOpenCreateKeyDetails(detailsData),
            [RegistryOperation.RegCloseKey] = (detailsData) => new RegistryBasicKeyDetails(detailsData),
        };

        private static Dictionary<Enum, DetailsConstructor> postOperationDetailsMapping = new Dictionary<Enum, DetailsConstructor>
        {
            [RegistryOperation.RegOpenKey] = (detailsData) => new RegistryPostOpenCreateKeyDetails(detailsData),
            [RegistryOperation.RegCreateKey] = (detailsData) => new RegistryPostOpenCreateKeyDetails(detailsData),
        };

        public RawEvent(EventHeaderStruct header, long[] stackTrace, DataStreamView detailsData)
        {
            this.header = header;
            this.stackTrace = stackTrace;

            ProcessSeq = header.ProcessSeq;
            ThreadId = header.ThreadId;
            Class = (EventClass)header.Class;
            if(Class != EventClass.Post)
            {
                Operation = (Enum)Enum.ToObject(operationEnumMapping[Class], header.Operation);
                operationDetailsMapping.TryGetValue(Operation, out DetailsConstructor detailsConstructor);
                if (detailsConstructor != null)
                {
                    Details = detailsConstructor(detailsData);
                }
            }
            Sequence = header.Sequence;
            Duration = header.Duration;
            Timestamp = DateTime.FromFileTime(header.Timestamp);
            Status = header.Status;
        }
    }
}
