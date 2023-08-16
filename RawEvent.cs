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

        public Process Process;
        public Thread Thread;

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

        public bool IsPreEvent()
        {
            return Class.Equals(EventClass.File) || Class.Equals(EventClass.Registry);
        }

        public void AssignProcessAndThread(Process process, Thread thread)
        {
            this.Process = process;
            this.Thread = thread;
        }
    }
}
