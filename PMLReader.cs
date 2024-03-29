﻿using System;
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
        public ProcessesSet ProcessesSet;

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
            int stringsCount;
            int[] stringPtrs;
            fileStream.Seek((long)Header.StringsPtr, SeekOrigin.Begin);
            using (BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.Default, leaveOpen: true))
            {
                stringsCount = binaryReader.ReadInt32();
                stringPtrs = new int[stringsCount];
                Strings = new StringsCollection();
                for (int i = 0; i < stringsCount; i++)
                {
                    stringPtrs[i] = binaryReader.ReadInt32();
                }

            }
            for (int i = 0; i < stringsCount; i++)
            {
                int ptr = stringPtrs[i];
                fileStream.Seek((long)Header.StringsPtr + ptr, SeekOrigin.Begin);
                using (BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.Default, leaveOpen: true))
                {
                    int size = binaryReader.ReadInt32();
                    byte[] buffer = binaryReader.ReadBytes(size);
                    string str = Encoding.Unicode.GetString(buffer);
                    Strings.AddString(str);
                }
            }
        }

        private DateTime? ConvertTime(long dateTime)
        {
            return dateTime > 0 ? (DateTime?)DateTime.FromFileTime(dateTime) : null;
        }

        private void ReadProcesses()
        {
            int processesCount;
            int[] processesPtrs;
            ProcessesSet = new ProcessesSet();

            fileStream.Seek((long)Header.ProcessesPtr, SeekOrigin.Begin);
            using (BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.Default, leaveOpen: true))
            {

                processesCount = binaryReader.ReadInt32();
                // Dummy read to skip process indexes
                binaryReader.ReadBytes(processesCount * 4);
                processesPtrs = new int[processesCount];
                for (int i = 0; i < processesCount; i++)
                {
                    processesPtrs[i] = binaryReader.ReadInt32();
                }
            }
            for (int i = 0; i < processesCount; i++)
            {
                int ptr = processesPtrs[i];
                fileStream.Seek((long)Header.ProcessesPtr + ptr, SeekOrigin.Begin);
                using (BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.Default, leaveOpen: true))
                {
                    PMLProcess64 processStruct = ReadStructure<PMLProcess64>(binaryReader);
                    // TODO: Loading modules
                    Process process = new Process
                    {
                        ProcessSeq = processStruct.ProcessSeq,
                        ProcessId = processStruct.ProcessId,
                        ParentProcessId = processStruct.ParentProcessId,
                        AuthenticationId = /*TODO processStruct.AuthenticationId*/null,
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
                    ProcessesSet.AssignSeqToProcess(process);
                }
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

        private static EventStruct ReadEvent(DataStreamView dataStreamView)
        {
            EventHeaderStruct header = dataStreamView.ReadStructure<EventHeaderStruct>();
            long[] stackTrace = dataStreamView.ReadInt64Values(header.StackTraceLength);
            return new EventStruct
            {
                Header = header,
                StackTrace = stackTrace,
                DetailsData = dataStreamView
            };
        }

        private IEnumerable<RawEvent> ReadEvents()
        {
            uint eventsCount = Header.NumberOfEvents;
            int[] eventPtrs;
            fileStream.Seek((long)Header.EventOffsetsPtr, SeekOrigin.Begin);
            using (BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.Default, leaveOpen: true))
            {
                eventPtrs = new int[eventsCount];
                for (uint i = 0; i < eventsCount; i++)
                {
                    eventPtrs[i] = binaryReader.ReadInt32();
                    binaryReader.ReadByte(); // Unknown flag
                }
            }
            fileStream.Seek((long)Header.EventsPtr, SeekOrigin.Begin);
            using (BinaryReader binaryReader = new BinaryReader(fileStream, Encoding.Unicode, leaveOpen: true))
            {
                FileDataStreamView dataStreamView = new FileDataStreamView(binaryReader);
                for (uint i = 0; i < eventsCount; i++)
                {
                    long eventPtr = eventPtrs[i];
                    binaryReader.BaseStream.Seek(eventPtr, SeekOrigin.Begin);
                    EventStruct eventStruct = ReadEvent(dataStreamView);
                    RawEvent rawEvent = new RawEvent(eventStruct);
                    if(rawEvent.IsPreEvent())
                    {
                        // originalPosition points to the offset after parsed RawEvent (hopefully the next event)
                        long originalPosition = binaryReader.BaseStream.Position;
                        long postDetailsPosition = eventPtr + eventStruct.Header.PostDetailsOffset;
                        // We need to seek to the post details offset that originates in eventPtr
                        binaryReader.BaseStream.Seek(postDetailsPosition, SeekOrigin.Begin);
                        // Then we have uint16 length of the post details and then the actual details structure
                        ushort postDetailsLength = binaryReader.ReadUInt16();
                        EventDetails postDetails = RawEvent.ParsePostDetails(dataStreamView, rawEvent.Operation);
                        rawEvent.PostDetails = postDetails;
                        if((binaryReader.BaseStream.Position - postDetailsLength - 2) > postDetailsPosition)
                        {
                            throw new PMLException(string.Format("Buffer outrun after parsing post details ({0} != {1})",
                                binaryReader.BaseStream.Position - postDetailsPosition - 2,
                                postDetailsLength
                            ));
                        }
                        // Go back to the original position
                        binaryReader.BaseStream.Seek(originalPosition, SeekOrigin.Begin);
                    }
                    yield return rawEvent;
                }
            }
        }

        public IEnumerable<DetailedEvent> GetEvents()
        {
            foreach(RawEvent rawEvent in ReadEvents())
            {
                DetailedEvent detailedEvent = new DetailedEvent
                {
                    ProcessesSet = ProcessesSet,
                    Process = ProcessesSet.GetProcessBySeq(rawEvent.ProcessSeq),
                    Class = rawEvent.Class,
                    Operation = rawEvent.Operation,
                    Duration = rawEvent.Duration,
                    Timestamp = rawEvent.Timestamp,
                    Status = rawEvent.Status,
                    Details = rawEvent.Details,
                    PostDetails = rawEvent.PostDetails,
                };
                yield return detailedEvent;
            }
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
