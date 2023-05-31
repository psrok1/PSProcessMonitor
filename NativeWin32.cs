using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace PSProcessMonitor
{
    internal enum HRESULT : uint
    {
        ERROR_FILE_NOT_FOUND = 0x80070002,
        ERROR_TOO_MANY_OPEN_FILES = 0x80070004,
        ERROR_ACCESS_DENIED = 0x80070005,
        ERROR_IO_PENDING = 0x800703E5,
        ERROR_CONNECTION_COUNT_LIMIT = 0x800704D6,
    }

    internal enum NTSTATUS: uint
    {
        STATUS_SUCCESS = 0,
        STATUS_INFO_LENGTH_MISMATCH = 0xC0000004,
        STATUS_BUFFER_TOO_SMALL = 0xC0000023,
    }

    internal sealed class SafeFilterHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeFilterHandle() : base(ownsHandle: true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeWin32.CloseHandle(handle);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING_PTR
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr BufferPtr;
    }


    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr BufferPtr;

        public override string ToString()
        {
            return Marshal.PtrToStringUni(BufferPtr);
        }
    }

    public enum SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation = 0x00,
        SystemProcessorInformation = 0x01,
        SystemPerformanceInformation = 0x02,
        SystemTimeOfDayInformation = 0x03,
        SystemPathInformation = 0x04,
        SystemProcessInformation = 0x05,
        SystemCallCountInformation = 0x06,
        SystemDeviceInformation = 0x07,
        SystemProcessorPerformanceInformation = 0x08,
        SystemFlagsInformation = 0x09,
        SystemCallTimeInformation = 0x0A,
        SystemModuleInformation = 0x0B,
        SystemLocksInformation = 0x0C,
        SystemStackTraceInformation = 0x0D,
        SystemPagedPoolInformation = 0x0E,
        SystemNonPagedPoolInformation = 0x0F,
        SystemHandleInformation = 0x10,
        SystemObjectInformation = 0x11,
        MaxSystemInfoClass = 0xD2
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x100)]
    internal struct SYSTEM_PROCESS_INFORMATION_x64
    {
        [FieldOffset(0)]
        public uint NextEntryOffset;
        [FieldOffset(4)]
        public uint NumberOfThreads;
        [FieldOffset(0x20)]
        public ulong CreateTime;
        [FieldOffset(0x28)]
        public ulong UserTime;
        [FieldOffset(0x30)]
        public ulong KernelTime;
        [FieldOffset(0x38)]
        public UNICODE_STRING ImageName;
        [FieldOffset(0x48)]
        public int BasePriority;
        [FieldOffset(0x50)]
        public int UniqueProcessId; // PID
        [FieldOffset(0x58)]
        public int InheritedFromUniqueProcessId; // PPID
        [FieldOffset(0x64)]
        public int SessionId;
    }

    [StructLayout(LayoutKind.Explicit, Size = 0x50)]
    internal struct SYSTEM_THREAD_INFORMATION_x64
    {
        [FieldOffset(0)]
        public ulong KernelTime;
        [FieldOffset(0x8)]
        public ulong UserTime;
        [FieldOffset(0x10)]
        public ulong CreateTime;
        [FieldOffset(0x20)]
        public IntPtr StartAddress;
        [FieldOffset(0x28)]
        public int UniqueProcessId;
        [FieldOffset(0x30)]
        public int UniqueThreadId;
        [FieldOffset(0x38)]
        public int Priority;
        [FieldOffset(0x3C)]
        public int BasePriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniquePID;
        public IntPtr InheritedFromUniqueProcessId;
    }

    // PEB is of course much longer, but I don't need more
    // so actual size is left undefined. The same thing applies
    // to other PEB-related structures

    [StructLayout(LayoutKind.Explicit)]
    internal struct PEB
    {
        [FieldOffset(0x20)]
        public long ProcessParametersPtr;
    }


    [StructLayout(LayoutKind.Explicit)]
    internal struct RTL_USER_PROCESS_PARAMETERS
    {
        [FieldOffset(0x60)]
        public UNICODE_STRING_PTR ImagePathName;
        [FieldOffset(0x70)]
        public UNICODE_STRING_PTR CommandLine;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public uint HighPart;
    }

    internal enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation,
    }

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
    }

    public struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    public struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    public struct TOKEN_VIRTUALIZATION_ENABLED
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool IsVirtualizationEnabled;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_STATISTICS
    {
        public LUID TokenId;
        public LUID AuthenticationId;
        public ulong ExpirationTime;
        public TOKEN_TYPE TokenType;
        public int ImpersonationLevel;
        public uint DynamicCharged;
        public uint DynamicAvailable;
        public uint GroupCount;
        public uint PrivilegeCount;
        public LUID ModifiedId;
    }

    internal enum ProcessAccessFlags : uint
    {
        PROCESS_ALL_ACCESS = 0x001F0FFF,
        PROCESS_TERMINATE = 0x00000001,
        PROCESS_CREATE_THREAD = 0x00000002,
        PROCESS_VM_OPERATION = 0x00000008,
        PROCESS_VM_READ = 0x00000010,
        PROCESS_VM_WRITE = 0x00000020,
        PROCESS_DUP_HANDLE = 0x00000040,
        PROCESS_CREATE_PROCESS = 0x000000080,
        PROCESS_SET_QUOTA = 0x00000100,
        PROCESS_SET_INFORMATION = 0x00000200,
        PROCESS_QUERY_INFORMATION = 0x00000400,
        PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
        SYNCHRONIZE = 0x00100000,
    }

    internal enum TokenAccessFlags : uint
    {
        TOKEN_QUERY = 0x0008,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
    }

    internal class NativeWin32
    {
        internal static string ConvertSidToString(IntPtr pSID)
        {
            if (!IsValidSid(pSID))
            {
                return null;
            }

            int sidLength = GetLengthSid(pSID);
            byte[] sid = new byte[sidLength];
            Marshal.Copy(pSID, sid, 0, sidLength);
            SecurityIdentifier si = new SecurityIdentifier(sid, 0);
            return si.ToString();
        }

        internal static string ConvertSidToAccountName(IntPtr pSID)
        {
            StringBuilder name = new StringBuilder(2048);
            StringBuilder domainName = new StringBuilder(2048);
            int nameSize = name.Capacity / 2;
            int domainNameSize = domainName.Capacity / 2;

            if (LookupAccountSid(
                null, pSID, name, ref nameSize, domainName, ref domainNameSize, out uint _))
            {
                return string.Format("{0}\\{1}", domainName, name);
            }
            return null;
        }

        [DllImport("fltlib", SetLastError = true)]
        internal static extern uint FilterConnectCommunicationPort(
            [MarshalAs(UnmanagedType.LPWStr)] string portName,
            uint options,
            ref uint context,
            uint sizeOfContext,
            IntPtr securityAttributes,
            ref SafeFilterHandle portPtr
        );

        [DllImport("fltlib", SetLastError = true)]
        internal static extern int FilterSendMessage(
            SafeFilterHandle port,
            ref ControlMessage inBuffer,
            uint inBufferSize,
            IntPtr outBuffer,
            uint outBufferSize,
            out uint bytesReturned
        );

        [DllImport("fltlib", SetLastError = true)]
        internal static extern uint FilterGetMessage(
            SafeFilterHandle port,
            IntPtr messageBuffer,
            uint messageBufferSize,
            ref NativeOverlapped overlapped
        );

        [DllImport("kernel32", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32", EntryPoint = "RtlFillMemory", SetLastError = false)]
        internal static extern void FillMemory(IntPtr destination, uint length, byte fill);

        [DllImport("ntdll", SetLastError = true)]
        internal static extern uint NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS systemInformationClass,
            IntPtr systemInformation,
            uint systemInformationLength,
            out uint returnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        internal static extern int NtQueryInformationProcess(
            SafeProcessHandle processHandle, 
            int processInformationClass, 
            IntPtr processInformation, 
            uint processInformationLength,
            out uint returnLength
        );

        [DllImport("ntdll")]
        internal static extern uint RtlNtStatusToDosError(uint Status);

        [DllImport("kernel32", SetLastError = true)]
        internal static extern SafeProcessHandle OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId
        );

        [DllImport("kernel32", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32", SetLastError = true)]
        internal static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess, 
            out SafeAccessTokenHandle TokenHandle
        );

        [DllImport("advapi32", EntryPoint = "LookupPrivilegeValueW")]
        internal static extern bool LookupPrivilegeValue(
            [MarshalAs(UnmanagedType.LPWStr)] string lpSystemName,
            [MarshalAs(UnmanagedType.LPWStr)] string lpName,
            ref LUID lpLuid
        );

        [DllImport("advapi32", SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(
            SafeAccessTokenHandle TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            uint BufferLengthInBytes,
            IntPtr PreviousState,
            IntPtr ReturnLengthInBytes
        );

        [DllImport("advapi32", SetLastError = true)]
        internal static extern bool GetTokenInformation(
            SafeAccessTokenHandle TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength
        );

        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint = "LookupAccountSidW", SetLastError = true)]
        internal static extern bool LookupAccountSid(
            [MarshalAs(UnmanagedType.LPWStr)] string strSystemName,
            IntPtr pSid,
            StringBuilder pName,
            ref int cchName,
            StringBuilder pReferencedDomainName,
            ref int cchReferencedDomainName,
            out uint peUse
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern int GetLengthSid(IntPtr pSid);

        [DllImport("kernel32", SetLastError = true)]
        internal static extern bool IsWow64Process(
            SafeProcessHandle hProcess,
            out bool Wow64Process
        );

        [DllImport("kernel32", SetLastError = true)]
        internal static extern bool ReadProcessMemory(
            SafeProcessHandle hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            int nSize,
            out int lpNumberOfBytesRead
        );
    }
}
