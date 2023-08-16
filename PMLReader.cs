using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PSProcessMonitor
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PMLHeader
    {
        public uint Signature;
        public uint Version;
        public uint Is64Bit;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = UnmanagedType.U1)]
        public byte[] ComputerName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 520, ArraySubType = UnmanagedType.U1)]
        public byte[] SystemRootPath;
        public uint NumberOfEvents;
        public ulong Reserved;
        public ulong EventsPtr;
        public ulong EventOffsetsPtr;
        public ulong ProcessesPtr;
        public ulong StringsPtr;
        public ulong IconsPtr;
        public SystemInfoStruct SystemInfo;
        public ulong EventsPtr2;
        public ulong HostsPortsPtr;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PMLProcess64
    {
        public int ProcessSeq;
        public int ProcessId;
        public int ParentProcessId;
        public int ParentProcessSeq;
        public long AuthenticationId;
        public int SessionId;
        public int Reserved1;
        public long StartTime;
        public long EndTime;
        public int Virtualized;
        public int Is64Bit;
        public int IntegrityStr;
        public int UserStr;
        public int ProcessNameStr;
        public int ImagePathStr;
        public int CommandLineStr;
        public int CompanyStr;
        public int VersionStr;
        public int DescriptionStr;
        public int IconSmall;
        public int IconBig;
        public long Reserved2; // 32-bit on 32-bit PML
        public int NumberOfModules;
    }

    public class PMLException : Exception {
        public PMLException(string message) : base(message) { }
    }

    public class StringsCollection
    {
        private List<string> strings;
        private Dictionary<string, int> positions;
        
        public StringsCollection()
        {
            strings = new List<string>();
            positions = new Dictionary<string, int>();
        }

        public int AddString(string str)
        {
            if(positions.ContainsKey(str))
                return positions[str];
            int index = strings.Count;
            positions.Add(str, index);
            strings.Add(str);
            return index;
        }

        public int GetIndexOfString(string str)
        {
            return positions[str];
        }

        public string GetStringByIndex(long index)
        {
            Console.WriteLine(String.Format("{0}, {1}", index, strings[(int)index]));
            return strings[(int)index];
        }
    }

    public class PMLReader : IDisposable
    {
        private FileStream fileStream;
        private bool disposedValue;

        public PMLHeader Header;
        public SystemInfo SystemInfo;
        public StringsCollection Strings;
        public SystemState SystemState;

        private static T ReadStructure<T>(BinaryReader reader)
        {
            byte[] buffer = new byte[Marshal.SizeOf<T>()];
            buffer = reader.ReadBytes(buffer.Length);
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            T structure = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            handle.Free();
            return structure;
        }

        private void ReadStrings()
        {
            fileStream.Seek((long)Header.StringsPtr, SeekOrigin.Begin);
            BinaryReader streamReader = new BinaryReader(fileStream);
            int stringsCount = streamReader.ReadInt32();
            int[] stringPtrs = new int[stringsCount];
            Strings = new StringsCollection();
            for (int i = 0; i < stringsCount; i++)
            {
                stringPtrs[i] = streamReader.ReadInt32();
            }
            for (int i = 0; i < stringsCount; i++)
            {
                int ptr = stringPtrs[i];
                fileStream.Seek((long)Header.StringsPtr + ptr, SeekOrigin.Begin);
                streamReader = new BinaryReader(fileStream);
                int size = streamReader.ReadInt32();
                byte[] buffer = streamReader.ReadBytes(size);
                string str = Encoding.Unicode.GetString(buffer);
                Strings.AddString(str);
            }
        }

        private DateTime? ConvertTime(long dateTime)
        {
            return dateTime > 0 ? (DateTime?)DateTime.FromFileTime(dateTime) : null;
        }

        private void ReadProcesses()
        {
            fileStream.Seek((long)Header.ProcessesPtr, SeekOrigin.Begin);
            BinaryReader streamReader = new BinaryReader(fileStream);
            int processesCount = streamReader.ReadInt32();
            // Dummy read to skip process indexes
            streamReader.ReadBytes(processesCount * 4);
            int[] processesPtrs = new int[processesCount];
            for (int i = 0; i < processesCount; i++)
            {
                processesPtrs[i] = streamReader.ReadInt32();
            }
            SystemState = new SystemState();
            for (int i = 0; i < processesCount; i++)
            {
                int ptr = processesPtrs[i];
                fileStream.Seek((long)Header.ProcessesPtr + ptr, SeekOrigin.Begin);
                streamReader = new BinaryReader(fileStream);
                PMLProcess64 processStruct = PMLReader.ReadStructure<PMLProcess64>(streamReader);
                // TODO: Loading modules
                Process process = new Process
                {
                    ProcessSeq = processStruct.ProcessSeq,
                    ProcessId = processStruct.ProcessId,
                    ParentProcessId = processStruct.ParentProcessId,
                    AuthenticationId = /*processStruct.AuthenticationId*/null,
                    SessionId = processStruct.SessionId,
                    Virtualized = processStruct.Virtualized != 0,
                    IsProcess64bit = processStruct.Is64Bit != 0,
                    Integrity = Strings.GetStringByIndex(processStruct.IntegrityStr),
                    User = Strings.GetStringByIndex(processStruct.UserStr),
                    ProcessName = Strings.GetStringByIndex(processStruct.ProcessNameStr),
                    ImagePath = Strings.GetStringByIndex(processStruct.ImagePathStr),
                    CommandLine = Strings.GetStringByIndex(processStruct.CommandLineStr),
                    Company = Strings.GetStringByIndex(processStruct.CompanyStr),
                    Version = Strings.GetStringByIndex(processStruct.VersionStr),
                    Description = Strings.GetStringByIndex(processStruct.DescriptionStr),
                    StartTime = ConvertTime(processStruct.StartTime),
                    EndTime = ConvertTime(processStruct.EndTime),
                };
                SystemState.AddProcess(process);
                SystemState.AssignSeqToProcess(process);
            }
        }

        public static PMLReader OpenFile(string filename)
        {
            FileStream stream = File.OpenRead(filename);
            BinaryReader streamReader = new BinaryReader(stream);
            PMLHeader header = ReadStructure<PMLHeader>(streamReader);
            if(header.Signature != 0x5F4C4D50)
            {
                throw new PMLException("File is not an PML file");
            }
            if(header.Version != 9)
            {
                throw new PMLException(string.Format("PML version not supported ({0})", header.Version));
            }
            SystemInfo systemInfo = new SystemInfo
            {
                Is64Bit = header.Is64Bit != 0,
                ComputerName = Encoding.Unicode.GetString(header.ComputerName),
                SystemRootPath = Encoding.Unicode.GetString(header.SystemRootPath),
                DetailedInfo = header.SystemInfo,
            };
            PMLReader reader = new PMLReader
            {
                fileStream = stream,
                Header = header,
                SystemInfo = systemInfo,
            };
            reader.ReadStrings();
            reader.ReadProcesses();
            return reader;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    fileStream.Dispose();
                }
                disposedValue = true;
            }
        }

        public void Close()
        {
            Dispose();
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
