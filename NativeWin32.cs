using Microsoft.Win32.SafeHandles;
using System;
using System.Management.Automation.Host;
using System.Runtime.CompilerServices;
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

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }
    public enum MachineType : ushort
    {
        I386 = 0x014c,
        AMD64 = 0x8664,
    }
    public enum MagicType : ushort
    {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,
    }
    public enum SubSystemType : ushort
    {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        [FieldOffset(0)]
        public MagicType Magic;
        [FieldOffset(2)]
        public byte MajorLinkerVersion;
        [FieldOffset(3)]
        public byte MinorLinkerVersion;
        [FieldOffset(4)]
        public uint SizeOfCode;
        [FieldOffset(8)]
        public uint SizeOfInitializedData;
        [FieldOffset(12)]
        public uint SizeOfUninitializedData;
        [FieldOffset(16)]
        public uint AddressOfEntryPoint;
        [FieldOffset(20)]
        public uint BaseOfCode;
        // PE32 contains this additional field
        [FieldOffset(24)]
        public uint BaseOfData;
        [FieldOffset(28)]
        public uint ImageBase;
        [FieldOffset(32)]
        public uint SectionAlignment;
        [FieldOffset(36)]
        public uint FileAlignment;
        [FieldOffset(40)]
        public ushort MajorOperatingSystemVersion;
        [FieldOffset(42)]
        public ushort MinorOperatingSystemVersion;
        [FieldOffset(44)]
        public ushort MajorImageVersion;
        [FieldOffset(46)]
        public ushort MinorImageVersion;
        [FieldOffset(48)]
        public ushort MajorSubsystemVersion;
        [FieldOffset(50)]
        public ushort MinorSubsystemVersion;
        [FieldOffset(52)]
        public uint Win32VersionValue;
        [FieldOffset(56)]
        public uint SizeOfImage;
        [FieldOffset(60)]
        public uint SizeOfHeaders;
        [FieldOffset(64)]
        public uint CheckSum;
        [FieldOffset(68)]
        public SubSystemType Subsystem;
        [FieldOffset(70)]
        public ushort DllCharacteristics;
        [FieldOffset(72)]
        public uint SizeOfStackReserve;
        [FieldOffset(76)]
        public uint SizeOfStackCommit;
        [FieldOffset(80)]
        public uint SizeOfHeapReserve;
        [FieldOffset(84)]
        public uint SizeOfHeapCommit;
        [FieldOffset(88)]
        public uint LoaderFlags;
        [FieldOffset(92)]
        public uint NumberOfRvaAndSizes;
        [FieldOffset(96)]
        public IMAGE_DATA_DIRECTORY ExportTable;
        [FieldOffset(104)]
        public IMAGE_DATA_DIRECTORY ImportTable;
        [FieldOffset(112)]
        public IMAGE_DATA_DIRECTORY ResourceTable;
        [FieldOffset(120)]
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        [FieldOffset(128)]
        public IMAGE_DATA_DIRECTORY CertificateTable;
        [FieldOffset(136)]
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        [FieldOffset(144)]
        public IMAGE_DATA_DIRECTORY Debug;
        [FieldOffset(152)]
        public IMAGE_DATA_DIRECTORY Architecture;
        [FieldOffset(160)]
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        [FieldOffset(168)]
        public IMAGE_DATA_DIRECTORY TLSTable;
        [FieldOffset(176)]
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        [FieldOffset(184)]
        public IMAGE_DATA_DIRECTORY BoundImport;
        [FieldOffset(192)]
        public IMAGE_DATA_DIRECTORY IAT;
        [FieldOffset(200)]
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        [FieldOffset(208)]
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        [FieldOffset(216)]
        public IMAGE_DATA_DIRECTORY Reserved;
    }
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        [FieldOffset(0)]
        public MagicType Magic;
        [FieldOffset(2)]
        public byte MajorLinkerVersion;
        [FieldOffset(3)]
        public byte MinorLinkerVersion;
        [FieldOffset(4)]
        public uint SizeOfCode;
        [FieldOffset(8)]
        public uint SizeOfInitializedData;
        [FieldOffset(12)]
        public uint SizeOfUninitializedData;
        [FieldOffset(16)]
        public uint AddressOfEntryPoint;
        [FieldOffset(20)]
        public uint BaseOfCode;
        [FieldOffset(24)]
        public ulong ImageBase;
        [FieldOffset(32)]
        public uint SectionAlignment;
        [FieldOffset(36)]
        public uint FileAlignment;
        [FieldOffset(40)]
        public ushort MajorOperatingSystemVersion;
        [FieldOffset(42)]
        public ushort MinorOperatingSystemVersion;
        [FieldOffset(44)]
        public ushort MajorImageVersion;
        [FieldOffset(46)]
        public ushort MinorImageVersion;
        [FieldOffset(48)]
        public ushort MajorSubsystemVersion;
        [FieldOffset(50)]
        public ushort MinorSubsystemVersion;
        [FieldOffset(52)]
        public uint Win32VersionValue;
        [FieldOffset(56)]
        public uint SizeOfImage;
        [FieldOffset(60)]
        public uint SizeOfHeaders;
        [FieldOffset(64)]
        public uint CheckSum;
        [FieldOffset(68)]
        public SubSystemType Subsystem;
        [FieldOffset(70)]
        public ushort DllCharacteristics;
        [FieldOffset(72)]
        public ulong SizeOfStackReserve;
        [FieldOffset(80)]
        public ulong SizeOfStackCommit;
        [FieldOffset(88)]
        public ulong SizeOfHeapReserve;
        [FieldOffset(96)]
        public ulong SizeOfHeapCommit;
        [FieldOffset(104)]
        public uint LoaderFlags;
        [FieldOffset(108)]
        public uint NumberOfRvaAndSizes;
        [FieldOffset(112)]
        public IMAGE_DATA_DIRECTORY ExportTable;
        [FieldOffset(120)]
        public IMAGE_DATA_DIRECTORY ImportTable;
        [FieldOffset(128)]
        public IMAGE_DATA_DIRECTORY ResourceTable;
        [FieldOffset(136)]
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        [FieldOffset(144)]
        public IMAGE_DATA_DIRECTORY CertificateTable;
        [FieldOffset(152)]
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        [FieldOffset(160)]
        public IMAGE_DATA_DIRECTORY Debug;
        [FieldOffset(168)]
        public IMAGE_DATA_DIRECTORY Architecture;
        [FieldOffset(176)]
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        [FieldOffset(184)]
        public IMAGE_DATA_DIRECTORY TLSTable;
        [FieldOffset(192)]
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        [FieldOffset(200)]
        public IMAGE_DATA_DIRECTORY BoundImport;
        [FieldOffset(208)]
        public IMAGE_DATA_DIRECTORY IAT;
        [FieldOffset(216)]
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        [FieldOffset(224)]
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        [FieldOffset(232)]
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public ushort NumberOfNamedEntries;
        public ushort NumberOfIdEntries;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DIRECTORY_ENTRY
    {
        public uint Name;
        public uint OffsetToData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_RESOURCE_DATA_ENTRY
    {
        public uint OffsetToData;
        public uint Size;
        public uint CodePage;
        public uint Reserved;
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

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEXW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public UInt16 wServicePackMajor;
        public UInt16 wServicePackMinor;
        public UInt16 wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public UIntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    };

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
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

        [DllImport("kernel32")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32", CharSet = CharSet.Unicode, EntryPoint = "GetVersionExW", SetLastError = true)]
        internal static extern bool GetVersionEx(ref OSVERSIONINFOEXW osvi);

        [DllImport("kernel32", SetLastError = true)]
        internal static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        internal static extern bool GetComputerNameW(StringBuilder lpBuffer, ref uint lpnSize);
    }
}
