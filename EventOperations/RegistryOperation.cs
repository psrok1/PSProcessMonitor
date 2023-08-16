using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSProcessMonitor
{
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

    [Flags]
    public enum RegistryAccessMask : int
    {
        QUERY_VALUE = 1,
        SET_VALUE = 2,
        CREATE_SUB_KEY = 4,
        ENUMERATE_SUB_KEYS = 8,
        NOTIFY = 0x10,
        CREATE_LINK = 0x20,
        WOW64_64KEY = 0x100,
        WOW64_32KEY = 0x200,
        WRITE = 0x20006,
        READ = 0x20019,
        READ_WRITE = 0x2001F,
        ALL_ACCESS = 0xF003F,
        // Common values
        DELETE = 0x10000,
        READ_CONTROL = 0x20000,
        WRITE_DAC = 0x40000,
        WRITE_OWNER = 0x80000,
        SYNCHRONIZE = 0x100000,
        ACCESS_SYSTEM_SECURITY = 0x1000000,
        MAXIMUM_ALLOWED = 0x2000000,
    }

    public enum RegistryDisposition: int
    {
        CREATED_NEW_KEY = 1,
        OPENED_EXISTING_KEY = 2,
    }

    // RegistryOperation.RegCloseKey

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

    // RegistryOperation.RegOpenKey
    // RegistryOperation.RegCreateKey

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct RegistryOpenCreateKeyStruct
    {
        public ushort PathLength;
        public int DesiredAccess;
    }

    public class RegistryOpenCreateKeyDetails : EventDetails
    {
        public string Path;
        public RegistryAccessMask DesiredAccess;

        internal RegistryOpenCreateKeyDetails(DataStreamView dataStreamView)
        {
            RegistryOpenCreateKeyStruct openCreateKeyStruct = dataStreamView.ReadStructure<RegistryOpenCreateKeyStruct>();
            Path = dataStreamView.ReadProcmonString(openCreateKeyStruct.PathLength);
            DesiredAccess = (RegistryAccessMask)openCreateKeyStruct.DesiredAccess;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct RegistryPostOpenCreateKeyStruct
    {
        public int GrantedAccess;
        public int Disposition;
    }

    public class RegistryPostOpenCreateKeyDetails : EventDetails
    {
        public RegistryAccessMask GrantedAccess;
        public RegistryDisposition Disposition;

        internal RegistryPostOpenCreateKeyDetails(DataStreamView dataStreamView)
        {
            RegistryPostOpenCreateKeyStruct postOpenCreateKeyStruct = dataStreamView.ReadStructure<RegistryPostOpenCreateKeyStruct>();
            GrantedAccess = (RegistryAccessMask)postOpenCreateKeyStruct.GrantedAccess;
            Disposition = (RegistryDisposition)postOpenCreateKeyStruct.Disposition;
        }
    }

    // RegistryOperation.RegQueryKey

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public class RegistryQueryKeyStruct
    {
        public ushort PathLength;
        public int Length;
        public int KeyInformationClass;
    }

    // RegistryOperation.RegQueryValue

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public class RegistryQueryValueStruct
    {
        public ushort PathLength;
        public int Length;
        public int KeyValueInformationClass;
    }

    // RegistryOperation.RegSetValue
    // RegistryOperation.RegEnumValue
    // RegistryOperation.RegEnumKey
    // RegistryOperation.RegSetInfoKey
    // RegistryOperation.RegDeleteKey
    // RegistryOperation.RegDeleteValue
    // RegistryOperation.RegFlushKey
    // RegistryOperation.RegLoadKey
    // RegistryOperation.RegUnloadKey
    // RegistryOperation.RegRenameKey
    // RegistryOperation.RegQueryMultipleValueKey
    // RegistryOperation.RegSetKeySecurity
    // RegistryOperation.RegQueryKeySecurity
}