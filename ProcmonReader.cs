using System;
using System.Collections.Generic;
using System.Threading;

namespace PSProcessMonitor
{
    public struct DetailedEvent
    {
        public ProcessesSet ProcessesSet;
        public Process Process;
        public EventClass Class;
        public Enum Operation;
        public int Duration;
        public DateTime Timestamp;
        public int Status;
        public EventDetails Details;
        public EventDetails PostDetails;
    }

    public class ProcmonReaderException: Exception
    {
        public ProcmonReaderException(string message) : base(message) { }
    }

    public class ProcmonReader
    {
        private ProcessesSet processesSet;
        private Dictionary<int, RawEvent> preEventLog;

        public ProcmonReader() {
            processesSet = new ProcessesSet();
            preEventLog = new Dictionary<int, RawEvent>();
        }

        public IEnumerable<DetailedEvent> GetEvents(CancellationToken cancellationToken)
        {
            ProcmonDriverClient procmonClient;

            procmonClient = ProcmonDriverClient.Connect();
            procmonClient.ConfigureFlags(7);
            try
            {
                foreach (EventStruct eventStruct in procmonClient.ReceiveEvents(cancellationToken))
                {
                    RawEvent rawEvent = new RawEvent(eventStruct);
                    if (rawEvent.Class.Equals(EventClass.Post))
                    {
                        RawEvent completedEvent = preEventLog[rawEvent.Sequence];
                        if (completedEvent == null)
                        {
                            throw new ProcmonReaderException(string.Format("Got post event for unknown pre event (Sequence={0})", rawEvent.Sequence));
                        }
                        else {
                            preEventLog.Remove(rawEvent.Sequence);
                            completedEvent.ApplyPostEvent(rawEvent, eventStruct.DetailsData);
                            rawEvent = completedEvent;
                        }
                    }
                    else
                    {
                        processesSet.AssignProcessForEvent(rawEvent);
                        if (rawEvent.IsPreEvent())
                        {
                            preEventLog[rawEvent.Sequence] = rawEvent;
                            continue;
                        }
                    }
                    if (rawEvent != null)
                    {
                        DetailedEvent detailedEvent = new DetailedEvent
                        {
                            ProcessesSet = processesSet,
                            Process = processesSet.GetProcessBySeq(rawEvent.ProcessSeq),
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
            }
            finally
            {
                procmonClient.ConfigureFlags(0);
                procmonClient.Disconnect();
            }
        }
    }
}
