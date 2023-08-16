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
                foreach (RawEvent rawEvent in procmonClient.ReceiveEvents(cancellationToken))
                {
                    RawEvent ev = rawEvent;
                    if (rawEvent.Class.Equals(EventClass.Post))
                    {
                        RawEvent completedEvent = preEventLog[rawEvent.Sequence];
                        if (completedEvent != null)
                        {
                            preEventLog.Remove(rawEvent.Sequence);
                        } else
                        {
                            // todo: got post event for unknown pre event
                        }
                        ev = completedEvent;
                    }
                    else
                    {
                        processesSet.AssignProcessForEvent(ev);
                        if (rawEvent.IsPreEvent())
                        {
                            preEventLog[rawEvent.Sequence] = rawEvent;
                            continue;
                        }
                    }
                    if (ev != null)
                    {
                        DetailedEvent detailedEvent = new DetailedEvent
                        {
                            ProcessesSet = processesSet,
                            Process = processesSet.GetProcessBySeq(ev.ProcessSeq),
                            Class = ev.Class,
                            Operation = ev.Operation,
                            Duration = ev.Duration,
                            Timestamp = ev.Timestamp,
                            Status = ev.Status,
                            Details = ev.Details,
                            PostDetails = ev.PostDetails,
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
