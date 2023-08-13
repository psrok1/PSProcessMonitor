using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace PSProcessMonitor
{
    public class Process
    {
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
        public DateTime StartTime;
        public DateTime EndTime;

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

        private DataStream ReadProcessMemory(SafeProcessHandle handle, IntPtr address, int structSize)
        {
            DataStream dataStream = new DataStream(structSize);
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

            DataStream dataStream = ReadProcessMemory(handle, address, maximumLength);
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

        private void FetchProcessDetailsFromVersionInfo(string imagePath)
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

        public bool FetchProcessDetails()
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

    public class Thread
    {
        public int ThreadId;
        public int ProcessId;
        public DateTime CreateTime;
        public IntPtr StartAddress;

        internal static Thread GetFromSystemThreadInformation(SYSTEM_THREAD_INFORMATION_x64 threadInformation)
        {
            Thread thread = new Thread
            {
                ProcessId = threadInformation.UniqueProcessId,
                ThreadId = threadInformation.UniqueThreadId,
                CreateTime = DateTime.FromFileTime((long)threadInformation.CreateTime),
                StartAddress = threadInformation.StartAddress
            };
            return thread;
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
    public class SystemState
    {
        public Dictionary<int, Process> ProcessById;
        public Dictionary<int, Thread> ThreadById;
        public Dictionary<long, Process> ProcessBySeq;

        public SystemState(
            Dictionary<int, Process> processById,
            Dictionary<int, Thread> threadById,
            Dictionary<long, Process> processBySeq)
        {
            ProcessById = processById;
            ThreadById = threadById;
            ProcessBySeq = processBySeq;
        }

        public SystemState(
            Dictionary<int, Process> processById,
            Dictionary<int, Thread> threadById) : this(processById, threadById, new Dictionary<long, Process>())
        { }

        public Process GetProcessForEvent(long processSeq, int threadId)
        {
            Process process = this.GetProcessBySeq(processSeq);
            if (process == null)
            {
                Thread thread = this.GetThreadById(threadId);
                if (thread == null)
                {
                    // Inconsistent state: thread doesn't exist
                    throw new InconsistentSystemStateException(
                        string.Format("Thread {0} is referenced by event but is not known by system state", threadId)
                    );
                }
                process = this.GetProcessById(thread.ProcessId);
                if (process == null)
                {
                    // Inconsistent state: thread exist but process doesn't
                    throw new InconsistentSystemStateException(
                        string.Format("Thread {0} exist but related process {1} is not known by system state", threadId, thread.ProcessId)
                    );
                }
                this.AssignSeqToProcess(process, processSeq);
            }
            return process;
        }

        public Process GetProcessById(int processId)
        {
            if (ProcessById.TryGetValue(processId, out Process process))
            {
                return process;
            }

            return null;
        }

        public Process GetProcessBySeq(long processSeq)
        {
            if (ProcessBySeq.TryGetValue(processSeq, out Process process))
            {
                return process;
            }

            return null;
        }

        public Thread GetThreadById(int threadId)
        {
            if (ThreadById.TryGetValue(threadId, out Thread thread))
            {
                return thread;
            }

            return null;
        }

        public void AssignSeqToProcess(Process process, long processSeq)
        {
            ProcessBySeq[processSeq] = process;
        }

        public void AddProcess(Process process)
        {
            ProcessById[process.ProcessId] = process;
        }

        public void AddThread(Thread thread)
        {
            ThreadById[thread.ThreadId] = thread;
        }

        public void FinishProcess(Process process)
        {
            ProcessById.Remove(process.ProcessId);
        }

        public void FinishThread(Thread thread)
        {
            ThreadById.Remove(thread.ThreadId);
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

        public static SystemState GetCurrentState()
        {
            // Call this AFTER starting recording events
            int processInformationSize = 0x100000;
            int maxProcessInformationSize = 0x1000000;
            Dictionary<int, Process> processById = new Dictionary<int, Process>();
            Dictionary<int, Thread> threadById = new Dictionary<int, Thread>();

            while (processInformationSize <= maxProcessInformationSize)
            {
                IntPtr processInformationBuffer = Marshal.AllocHGlobal(processInformationSize);
                try
                {
                    uint ntstatus = NativeWin32.NtQuerySystemInformation(
                        SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
                        processInformationBuffer,
                        (uint)processInformationSize,
                        out uint _
                    );
                    if (ntstatus != (uint)NTSTATUS.STATUS_SUCCESS)
                    {
                        if (ntstatus == (uint)NTSTATUS.STATUS_INFO_LENGTH_MISMATCH ||
                           ntstatus == (uint)NTSTATUS.STATUS_BUFFER_TOO_SMALL)
                        {
                            processInformationSize *= 2;
                            continue;
                        }
                        else
                        {
                            uint win32Error = NativeWin32.RtlNtStatusToDosError(ntstatus);
                            Marshal.ThrowExceptionForHR((int)(0x80070000 | win32Error));
                        }
                    }
                    DataStreamView dataStreamView = new DataStreamView(processInformationBuffer, processInformationSize);
                    SYSTEM_PROCESS_INFORMATION_x64 processInformation;
                    do
                    {
                        processInformation = dataStreamView.ReadStructure<SYSTEM_PROCESS_INFORMATION_x64>();
                        for (int i = 0; i < processInformation.NumberOfThreads; i++)
                        {
                            SYSTEM_THREAD_INFORMATION_x64 threadInformation = dataStreamView.ReadStructure<SYSTEM_THREAD_INFORMATION_x64>();
                            threadById[threadInformation.UniqueThreadId] = Thread.GetFromSystemThreadInformation(threadInformation);
                        }
                        processById[processInformation.UniqueProcessId] = Process.GetFromSystemProcessInformation(processInformation);
                        if (processInformation.NextEntryOffset > 0)
                        {
                            dataStreamView.Move(
                                ((int)processInformation.NextEntryOffset) -
                                (int)(
                                    Marshal.SizeOf<SYSTEM_PROCESS_INFORMATION_x64>() +
                                    (Marshal.SizeOf<SYSTEM_THREAD_INFORMATION_x64>() * processInformation.NumberOfThreads)
                                )
                            );
                        }
                    } while (processInformation.NextEntryOffset > 0);
                    break;
                }
                finally
                {
                    Marshal.FreeHGlobal(processInformationBuffer);
                }
            }

            return new SystemState(processById, threadById);
        }

        public (Process process, Thread thread) GetProcessAndThreadForEvent(RawEvent rawEvent)
        {
            // Get process. If new one, assign to state.
            Process process;
            if (rawEvent.Operation != null && (rawEvent.Operation.Equals(ProcessOperation.ProcessDefined) || rawEvent.Operation.Equals(ProcessOperation.ProcessCreate)))
            {
                ProcessCreateDetails details = (ProcessCreateDetails)rawEvent.Details;
                process = new Process
                {
                    ProcessId = details.ProcessId,
                    ParentProcessId = details.ParentProcessId,
                    AuthenticationId = details.AuthenticationId,
                    SessionId = details.SessionId,
                    Virtualized = details.Virtualized,
                    IsProcess64bit = details.IsProcess64bit,
                    Integrity = details.Integrity,
                    IntegritySID = details.IntegritySID,
                    User = details.User,
                    UserSID = details.UserSID,
                    ProcessName = details.ProcessName,
                    CommandLine = details.CommandLine,
                    StartTime = details.CreateTime,
                };
                AddProcess(process);
                AssignSeqToProcess(process, rawEvent.ProcessSeq);
            }
            else
            {
                process = GetProcessBySeq(rawEvent.ProcessSeq);
            }
            // Get thread. If new one, assign to state.
            Thread thread;
            if(rawEvent.Operation != null && rawEvent.Operation.Equals(ProcessOperation.ThreadCreate))
            {
                ThreadCreateDetails details = (ThreadCreateDetails)rawEvent.Details;
                thread = new Thread
                {
                    ThreadId = details.ThreadID,
                    ProcessId = process.ProcessId,
                    CreateTime = rawEvent.Timestamp,
                };
                AddThread(thread);
            }
            else
            {
                thread = GetThreadById(rawEvent.ThreadId);
            }
            // Handle process and thread exit.
            if (rawEvent.Operation != null && rawEvent.Operation.Equals(ProcessOperation.ProcessExit))
            {
                process.EndTime = rawEvent.Timestamp;
                FinishProcess(process);
            }
            if (rawEvent.Operation != null && thread != null && rawEvent.Operation.Equals(ProcessOperation.ThreadExit))
            {
                FinishThread(thread);
            }
            return (process, thread);
        }
    }
}
