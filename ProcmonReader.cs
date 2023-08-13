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
                foreach (var rawEvent in procmonClient.ReceiveEvents(cancellationToken))
                {
                    (Process process, Thread thread) = systemState.GetProcessAndThreadForEvent(rawEvent);
                    DetailedEvent detailedEvent = new DetailedEvent
                    {
                        SystemState = systemState,
                        Process = process,
                        Thread = thread,
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
            finally
            {
                procmonClient.ConfigureFlags(0);
                procmonClient.Disconnect();
            }
        }
    }
}
