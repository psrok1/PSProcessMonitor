using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace PSProcessMonitor
{
    public class Process
    {
        public int ProcessSeq;
        public int ProcessId;
        public int ParentProcessId;
        public string AuthenticationId;
        public int SessionId;
        public bool? Virtualized;
        public bool? IsProcess64bit;
        public string Integrity;
        public string IntegritySID;
        public string User;
        public string UserSID;
        public string ProcessName;
        public string ImagePath;
        public string CommandLine;
        public string Company;
        public string Version;
        public string Description;
        public DateTime? StartTime;
        public DateTime? EndTime;

        public List<string> Errors = new List<string>();

        private void ReportError(string message, uint hresult)
        {
            if (hresult == 0)
            {
                Errors.Add(message);
            }
            else
            {
                Errors.Add(string.Format("{0} (HRESULT={1:X08})", message, hresult));
            }
        }

        private void ReportError(string message)
        {
            ReportError(message, (uint)Marshal.GetHRForLastWin32Error());
        }

        private MemoryDataStream ReadProcessMemory(SafeProcessHandle handle, IntPtr address, int structSize)
        {
            MemoryDataStream dataStream = new MemoryDataStream(structSize);
            if (!NativeWin32.ReadProcessMemory(handle, address, dataStream.InitialPtr, structSize, out int _))
            {
                dataStream.Dispose();
                return null;
            }
            return dataStream;
        }

        private T? ReadProcessStructure<T>(SafeProcessHandle handle, IntPtr address) where T : struct
        {
            using (StructureReader<T> buffer = new StructureReader<T>())
            {
                if (NativeWin32.ReadProcessMemory(handle, address, buffer.Ptr, buffer.Size, out int _))
                {
                    return buffer.GetStructure();
                }
            }
            return null;
        }

        private string ReadProcessUnicodeString(SafeProcessHandle handle, IntPtr address, ushort length, ushort maximumLength)
        {
            if (length == 0)
            {
                return "";
            }

            if (length > maximumLength)
            {
                return null;
            }

            MemoryDataStream dataStream = ReadProcessMemory(handle, address, maximumLength);
            if (dataStream == null)
            {
                return null;
            }

            using (dataStream)
            {
                // Remote process memory is not trusted, so let's place '\0' ourselves
                Marshal.WriteInt16(IntPtr.Add(dataStream.InitialPtr, length), 0);
                return Marshal.PtrToStringUni(dataStream.InitialPtr);
            }
        }

        private bool FetchProcessDetailsFromPEBx64(SafeProcessHandle handle, IntPtr pebPtr)
        {
            PEB? peb = ReadProcessStructure<PEB>(handle, pebPtr);
            if (peb == null)
            {
                ReportError("Failed to read PEB block");
                return false;
            }

            IntPtr processParametersPtr = (IntPtr)peb.Value.ProcessParametersPtr;
            RTL_USER_PROCESS_PARAMETERS? processParameters = ReadProcessStructure<RTL_USER_PROCESS_PARAMETERS>(handle, processParametersPtr);
            if (processParameters == null)
            {
                ReportError("Failed to read PEB.ProcessParameters block");
                return false;
            }

            UNICODE_STRING_PTR commandLine = processParameters.Value.CommandLine;
            UNICODE_STRING_PTR imagePathName = processParameters.Value.ImagePathName;
            CommandLine = ReadProcessUnicodeString(handle, commandLine.BufferPtr, commandLine.Length, commandLine.MaximumLength);
            if (CommandLine == null)
            {
                ReportError("Failed to read PEB.ProcessParameters.CommandLine");
            }
            ImagePath = ReadProcessUnicodeString(handle, imagePathName.BufferPtr, imagePathName.Length, imagePathName.MaximumLength);
            if (ImagePath == null)
            {
                ReportError("Failed to read PEB.ProcessParameters.ImagePath");
            }
            return CommandLine != null && ImagePath != null;
        }

        private IntPtr GetProcessPEBPtr(SafeProcessHandle handle)
        {
            using (StructureReader<PROCESS_BASIC_INFORMATION> buffer = new StructureReader<PROCESS_BASIC_INFORMATION>())
            {
                int ntstatus = NativeWin32.NtQueryInformationProcess(handle, 0, buffer.Ptr, (uint)buffer.Size, out uint _);
                if (ntstatus != 0)
                {
                    ReportError("NtQueryInformationProcess failed", 0x80070000 | NativeWin32.RtlNtStatusToDosError((uint)ntstatus));
                    return IntPtr.Zero;
                }
                else
                {
                    return buffer.GetStructure().PebAddress;
                }
            }
        }

        private string ConvertSidToString(IntPtr pSID)
        {
            if (!NativeWin32.IsValidSid(pSID))
            {
                return null;
            }

            int sidLength = NativeWin32.GetLengthSid(pSID);
            byte[] sid = new byte[sidLength];
            Marshal.Copy(pSID, sid, 0, sidLength);
            SecurityIdentifier si = new SecurityIdentifier(sid, 0);
            return si.ToString();
        }

        private StructureReader<T> GetTokenInformation<T>(SafeAccessTokenHandle tokenHandle, TOKEN_INFORMATION_CLASS informationClass)
            where T : struct
        {
            NativeWin32.GetTokenInformation(tokenHandle, informationClass, IntPtr.Zero, 0, out uint structSize);
            if (structSize == 0)
            {
                return null;
            }

            StructureReader<T> buffer = new StructureReader<T>((int)structSize);
            if (NativeWin32.GetTokenInformation(
                tokenHandle,
                informationClass,
                buffer.Ptr,
                (uint)buffer.Size,
                out uint _))
            {
                return buffer;
            }
            buffer.Dispose();
            return StructureReader<T>.Invalid;
        }

        private void FetchProcessDetailsFromToken(SafeProcessHandle handle)
        {
            SafeAccessTokenHandle tokenHandle;
            if (!NativeWin32.OpenProcessToken(
                handle.DangerousGetHandle(),
                (uint)TokenAccessFlags.TOKEN_QUERY,
                out tokenHandle))
            {
                ReportError("OpenProcessToken failed");
            }
            using (tokenHandle)
            {
                using (StructureReader<TOKEN_USER> buffer = GetTokenInformation<TOKEN_USER>(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser))
                {
                    if (buffer.IsInvalid())
                    {
                        ReportError("GetTokenInformation failed for User field");
                    }
                    else
                    {
                        TOKEN_USER tokenUser = buffer.GetStructure();
                        UserSID = NativeWin32.ConvertSidToString(tokenUser.User.Sid);
                        User = NativeWin32.ConvertSidToAccountName(tokenUser.User.Sid);
                    }
                }

                using (StructureReader<TOKEN_MANDATORY_LABEL> buffer = GetTokenInformation<TOKEN_MANDATORY_LABEL>(tokenHandle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel))
                {
                    if (buffer.IsInvalid())
                    {
                        ReportError("GetTokenInformation failed for Integrity field");
                    }
                    else
                    {
                        TOKEN_MANDATORY_LABEL tokenMandatoryLabel = buffer.GetStructure();
                        IntegritySID = NativeWin32.ConvertSidToString(tokenMandatoryLabel.Label.Sid);
                        Integrity = NativeWin32.ConvertSidToAccountName(tokenMandatoryLabel.Label.Sid);
                    }
                }

                using (StructureReader<TOKEN_STATISTICS> buffer = GetTokenInformation<TOKEN_STATISTICS>(tokenHandle, TOKEN_INFORMATION_CLASS.TokenStatistics))
                {
                    if (buffer.IsInvalid())
                    {
                        ReportError("GetTokenInformation failed for AuthenticationId field");
                    }
                    else
                    {
                        TOKEN_STATISTICS tokenStatistics = buffer.GetStructure();
                        AuthenticationId = string.Format("{0:X08}:{1:X08}", tokenStatistics.AuthenticationId.HighPart, tokenStatistics.AuthenticationId.LowPart);
                    }
                }

                using (StructureReader<TOKEN_VIRTUALIZATION_ENABLED> buffer = GetTokenInformation<TOKEN_VIRTUALIZATION_ENABLED>(tokenHandle, TOKEN_INFORMATION_CLASS.TokenVirtualizationEnabled))
                {
                    if (buffer.IsInvalid())
                    {
                        ReportError("GetTokenInformation failed for Virtualized field");
                    }
                    else
                    {
                        TOKEN_VIRTUALIZATION_ENABLED tokenVirtualizationEnabled = buffer.GetStructure();
                        Virtualized = tokenVirtualizationEnabled.IsVirtualizationEnabled;
                    }
                }
            }
        }

        internal void FetchProcessDetailsFromVersionInfo(string imagePath)
        {
            try
            {
                FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(imagePath);
                Company = versionInfo.CompanyName;
                Description = versionInfo.FileDescription;
                Version = versionInfo.FileVersion;
            }
            catch (FileNotFoundException)
            {
                ReportError("GetVersionInfo failed: file was not found", 0);
            }
        }

        internal bool FetchProcessDetails()
        {
            ProcessAccessFlags accessFlags =
                ProcessAccessFlags.PROCESS_QUERY_INFORMATION |
                ProcessAccessFlags.PROCESS_VM_READ
            ;
            SafeProcessHandle handle = NativeWin32.OpenProcess((uint)accessFlags, false, ProcessId);
            if (handle.IsInvalid)
            {
                ReportError("OpenProcess failed");
                return false;
            }
            using (handle)
            {
                if (NativeWin32.IsWow64Process(handle, out bool isWoW64))
                {
                    IsProcess64bit = !isWoW64; // assuming 64-bit Windows host   
                }
                IntPtr pebPtr = GetProcessPEBPtr(handle);
                if (pebPtr != IntPtr.Zero)
                {
                    FetchProcessDetailsFromPEBx64(handle, pebPtr);
                }
                FetchProcessDetailsFromToken(handle);
                if (ImagePath != null)
                {
                    FetchProcessDetailsFromVersionInfo(ImagePath);
                }
            }
            return true;
        }

        internal static Process GetFromSystemProcessInformation(SYSTEM_PROCESS_INFORMATION_x64 processInformation)
        {
            Process process = new Process
            {
                ProcessId = processInformation.UniqueProcessId,
                ParentProcessId = processInformation.InheritedFromUniqueProcessId,
                SessionId = processInformation.SessionId,
                ProcessName = processInformation.ImageName.ToString(),
                StartTime = DateTime.FromFileTime((long)processInformation.CreateTime),
            };
            process.FetchProcessDetails();
            return process;
        }
    }

    public struct Module
    {
        public IntPtr BaseAddress;
        public long Size;
        public string ImagePath;
        public string Version;
        public string Company;
        public string Description;
        public DateTime Timestamp;
    }

    /**
     * <summary>
     * Thrown when TID/ProcessSeq can't be matched to system state.
     * It should never happen and indicates a bug.
     * </summary>
     **/
    public class InconsistentSystemStateException : Exception
    {
        public InconsistentSystemStateException(string message) : base(message) { }
    }

    /**
     * <summary>
     * ProcessMonitor driver identifies event source via sequential
     * process identifier (ProcessSeq) and regular thread identifier. 
     * Mapping of the sequence number to the process id is known only 
     * locally, so we need to track opened/closed processes to be able 
     * to map sequence identifiers to proper PIDs.
     * </summary>
     **/
    public class ProcessesSet
    {
        public Dictionary<int, Process> ProcessBySeq;

        public ProcessesSet(
            Dictionary<int, Process> processBySeq)
        {
            ProcessBySeq = processBySeq;
        }

        public ProcessesSet() : this(new Dictionary<int, Process>())
        { }

        public Process GetProcessBySeq(int processSeq)
        {
            if (ProcessBySeq.TryGetValue(processSeq, out Process process))
            {
                return process;
            }

            return null;
        }

        public void AssignSeqToProcess(Process process)
        {
            ProcessBySeq[process.ProcessSeq] = process;
        }

        public static bool TryEnableDebugPrivilege()
        {
            TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES()
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES[1],
            };
            SafeAccessTokenHandle handle;
            if (!NativeWin32.OpenProcessToken(
                NativeWin32.GetCurrentProcess(),
                (uint)(TokenAccessFlags.TOKEN_ADJUST_PRIVILEGES | TokenAccessFlags.TOKEN_QUERY),
                out handle))
            {
                return false;
            }
            using (handle)
            {
                if (NativeWin32.LookupPrivilegeValue(null, "SeDebugPrivilege", ref tokenPrivileges.Privileges[0].Luid))
                {
                    tokenPrivileges.Privileges[0].Attributes = 2; // SE_PRIVILEGE_ENABLED
                    if (NativeWin32.AdjustTokenPrivileges(handle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        public Process AssignProcessForEvent(RawEvent rawEvent)
        {
            // Get process. If new one, assign to state.
            Process process = null;
            if (rawEvent.Operation != null)
            {
                if (rawEvent.Operation.Equals(ProcessOperation.ProcessDefined) || rawEvent.Operation.Equals(ProcessOperation.ProcessCreate))
                {
                    ProcessCreateDetails details = (ProcessCreateDetails)rawEvent.Details;
                    process = details.MakeProcess();
                    AssignSeqToProcess(process);
                }
            }
            if(process == null)
            {
                process = GetProcessBySeq(rawEvent.ProcessSeq);
            }
            // Handle process and thread exit.
            if (rawEvent.Operation != null && rawEvent.Operation.Equals(ProcessOperation.ProcessExit))
            {
                process.EndTime = rawEvent.Timestamp;
            }
            return process;
        }
    }
}
