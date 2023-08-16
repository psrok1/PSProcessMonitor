using System;
using System.Runtime.InteropServices;

namespace PSProcessMonitor
{
    public enum ProcessOperation : short
    {
        // These events are the first events we get from
        // the driver. Driver informs us about processes
        // in the system and their sequence identifiers
        ProcessDefined = 0,
        // That event informs us about process creation
        // but from creator process perspective (kind of pre-event)
        // ProcessSeq of event is set to the creator
        ProcessCreate = 1,
        ProcessExit = 2,
        ThreadCreate = 3,
        ThreadExit = 4,
        LoadImage = 5,
        ThreadProfile = 6,
        // That event informs us about actual process start
        ProcessStart = 7,
        ProcessStatistics = 8,
        SystemStatistics = 9,
    }

    // ProcessOperation.ProcessDefined
    // ProcessOperation.ProcessCreate

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

    public class ProcessCreateDetails : EventDetails
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
            // TODO: This could be passed via argument            
            bool resolveSIDs = typeof(MemoryDataStreamView).IsAssignableFrom(dataStreamView.GetType());

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
                byte[] userSID = dataStreamView.ReadBytes(processCreateStruct.UserSidLength);
                GCHandle handle = GCHandle.Alloc(userSID, GCHandleType.Pinned);
                IntPtr ptrSID = handle.AddrOfPinnedObject();
                UserSID = NativeWin32.ConvertSidToString(ptrSID);
                if (resolveSIDs)
                {
                    User = NativeWin32.ConvertSidToAccountName(ptrSID);
                }
                handle.Free();
            }
            if (processCreateStruct.IntegritySidLength != 0)
            {
                byte[] integritySID = dataStreamView.ReadBytes(processCreateStruct.IntegritySidLength);
                GCHandle handle = GCHandle.Alloc(integritySID, GCHandleType.Pinned);
                IntPtr ptrSID = handle.AddrOfPinnedObject();
                IntegritySID = NativeWin32.ConvertSidToString(ptrSID);
                Integrity = NativeWin32.ConvertSidToAccountName(ptrSID);
                handle.Free();
            }
            ProcessName = dataStreamView.ReadProcmonString(processCreateStruct.ProcessNameLength);
            CommandLine = dataStreamView.ReadProcmonString(processCreateStruct.CommandLineLength);
        }

        internal Process MakeProcess()
        {
            return new Process
            {
                ProcessSeq = ProcessSeq,
                ProcessId = ProcessId,
                ParentProcessId = ParentProcessId,
                AuthenticationId = AuthenticationId,
                SessionId = SessionId,
                Virtualized = Virtualized,
                IsProcess64bit = IsProcess64bit,
                Integrity = Integrity,
                IntegritySID = IntegritySID,
                User = User,
                UserSID = UserSID,
                ProcessName = ProcessName,
                CommandLine = CommandLine,
                StartTime = CreateTime,
            };
        }
    }

    // ProcessOperation.ProcessStart

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ProcessStartStruct
    {
        public int ParentProcessId;
        public ushort CommandLineLength;
        public ushort CurrentDirectoryLength;
        public int EnvironmentLength;
    }

    public class ProcessStartDetails : EventDetails
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

    // ProcessOperation.ProcessExit

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

    public class ProcessExitDetails : EventDetails
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

    // ProcessOperation.LoadImage

    [StructLayout(LayoutKind.Sequential, Size = 0x10, Pack = 1)]
    public struct LoadImageStruct
    {
        public IntPtr ImageBase;
        public int ImageSize;
        public ushort ImageNameLength;
    }

    public class LoadImageDetails : EventDetails
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

    // ProcessOperation.ThreadCreate

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ThreadCreateStruct
    {
        public int ThreadID;
    }

    public class ThreadCreateDetails : EventDetails
    {
        public int ThreadID;

        internal ThreadCreateDetails(DataStreamView dataStreamView)
        {
            ThreadCreateStruct threadCreateStruct = dataStreamView.ReadStructure<ThreadCreateStruct>();
            ThreadID = threadCreateStruct.ThreadID;
        }
    }

    // ProcessOperation.ThreadExit

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ThreadExitStruct
    {
        public int ExitCode;
        public long KernelTime;
        public long UserTime;
    }

    public class ThreadExitDetails : EventDetails
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

    // TODO
    // ProcessOperation.ThreadProfile
    // ProcessOperation.ProcessStatistics
    // ProcessOperation.SystemStatistics
}