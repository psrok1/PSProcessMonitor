using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PSProcessMonitor
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SystemInfoStruct
    {
        public ulong lpMaximumApplicationAddress;
        public OSVERSIONINFOEXW osVersionInfo;
        public uint dwNumberOfProcessors;
        public ulong ullTotalPhysMemory;
    }

    public class SystemInfo
    {
        public bool Is64Bit;
        public string ComputerName;
        public string SystemRootPath;
        public SystemInfoStruct DetailedInfo;

        public static SystemInfo GetComputerInfo()
        {
            SYSTEM_INFO systemInfo = new SYSTEM_INFO();
            OSVERSIONINFOEXW osVersion = new OSVERSIONINFOEXW();
            MEMORYSTATUSEX memoryStatus = new MEMORYSTATUSEX();
            StringBuilder computerName = new StringBuilder(32);
            uint computerNameSize = (uint)(computerName.Capacity / 2);

            osVersion.dwOSVersionInfoSize = Marshal.SizeOf<OSVERSIONINFOEXW>();
            memoryStatus.dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>();
            NativeWin32.GetNativeSystemInfo(ref systemInfo);
            NativeWin32.GetVersionEx(ref osVersion);
            NativeWin32.GlobalMemoryStatusEx(ref memoryStatus);
            NativeWin32.GetComputerNameW(computerName, ref computerNameSize);

            return new SystemInfo
            {
                Is64Bit = systemInfo.wProcessorArchitecture == 9, // PROCESSOR_ARCHITECTURE_AMD64
                ComputerName = computerName.ToString(),
                SystemRootPath = Path.GetPathRoot(Environment.SystemDirectory),
                DetailedInfo = new SystemInfoStruct
                {
                    lpMaximumApplicationAddress = (ulong)systemInfo.lpMaximumApplicationAddress,
                    osVersionInfo = osVersion,
                    dwNumberOfProcessors = systemInfo.dwNumberOfProcessors,
                    ullTotalPhysMemory = memoryStatus.ullTotalPhys,
                },
            };
        }
    }
}
