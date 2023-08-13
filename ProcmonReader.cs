using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Tracing;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PSProcessMonitor
{
    public struct DetailedEvent
    {
        public SystemState SystemState;
        public Process Process;
        public Thread Thread;
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
        private SystemState systemState;
        private Dictionary<int, RawEvent> preEventLog;

        public ProcmonReader() {
            systemState = SystemState.GetCurrentState();
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
                    if(rawEvent.IsPreEvent())
                    {
                        preEventLog[rawEvent.Sequence] = rawEvent;
                        continue;
                    }
                    if(rawEvent.Class.Equals(EventClass.Post))
                    {
                        RawEvent preEvent = preEventLog[rawEvent.Sequence];
                        if(preEvent != null)
                        {
                            preEventLog.Remove(rawEvent.Sequence);
                        }
                        ev = preEvent;
                    }
                    if (ev != null)
                    {
                        (Process process, Thread thread) = systemState.GetProcessAndThreadForEvent(ev);
                        DetailedEvent detailedEvent = new DetailedEvent
                        {
                            SystemState = systemState,
                            Process = process,
                            Thread = thread,
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
