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
        public int PostDetailsOffset;
    }

    public abstract class EventDetails
    {
    }

    public struct EventStruct
    {
        public EventHeaderStruct Header;
        public long[] StackTrace;
        public DataStreamView DetailsData;
    }

    /**
     * <summary>
     * Context-less event representation
     * </summary>
     */
    public class RawEvent
    {
        public readonly EventHeaderStruct Header;
        public readonly long[] StackTrace;

        public int ProcessSeq { get; private set; }
        public int ThreadId { get; private set; }
        public EventClass Class { get; private set; }
        public Enum Operation { get; private set; }
        public int Sequence { get; private set; }
        // TODO: I think that Duration field is PML only
        public int Duration { get; private set; }
        public DateTime Timestamp { get; private set; }
        public int Status { get; private set; }
        public EventDetails Details { get; private set; }
        public EventDetails PostDetails { get; internal set; }

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

        public RawEvent(EventStruct eventStruct)
        {
            Header = eventStruct.Header;
            StackTrace = eventStruct.StackTrace;

            ProcessSeq = Header.ProcessSeq;
            ThreadId = Header.ThreadId;
            Class = (EventClass)Header.Class;
            if (Class != EventClass.Post)
            {
                Operation = (Enum)Enum.ToObject(operationEnumMapping[Class], Header.Operation);
                operationDetailsMapping.TryGetValue(Operation, out DetailsConstructor detailsConstructor);
                if (detailsConstructor != null)
                {
                    Details = detailsConstructor(eventStruct.DetailsData);
                }
            }
            Sequence = Header.Sequence;
            Duration = Header.Duration;
            Timestamp = DateTime.FromFileTime(Header.Timestamp);
            Status = Header.Status;
        }

        public static EventDetails ParsePostDetails(DataStreamView detailsData, Enum operation)
        {
            // PostDetails may come from two places:
            // - EventClass.Post event that contains it as a payload
            // - Additional attachment to event from PML file located at PostDetailsOffset
            postOperationDetailsMapping.TryGetValue(operation, out DetailsConstructor detailsConstructor);
            if (detailsConstructor == null)
                return null;
            return detailsConstructor(detailsData);
        }

        public void ApplyPostEvent(RawEvent postEvent, DataStreamView postDetailsData)
        {
            // Apply details from EventClass.Post event got from live monitoring
            Status = postEvent.Status;
            // TODO: Duration
            if(postEvent.Header.DetailsLength > 0)
            {
                PostDetails = ParsePostDetails(postDetailsData, Operation);
            }
        }

        public bool IsPreEvent()
        {
            const int STATUS_PENDING = 0x00000103;
            return (Class.Equals(EventClass.File) || Class.Equals(EventClass.Registry)) && Status == STATUS_PENDING;
        }
    }
}
