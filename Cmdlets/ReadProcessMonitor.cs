using System;
using System.Linq;
using System.Management.Automation;  // Windows PowerShell assembly.
using System.Threading;

namespace PSProcessMonitor
{
    // Declare the class as a cmdlet and specify the
    // appropriate verb and noun for the cmdlet name.
    [Cmdlet(VerbsCommunications.Read, "ProcessMonitor")]
    public class ReadProcessMonitor : Cmdlet
    {
        [Parameter]
        public string ProcessName { 
            get { return processName; } 
            set { processName = value; }
        }
        private string processName;

        [Parameter]
        public int PID
        {
            get { return pid == null ? -1 : (int)pid; }
            set { pid = value; }
        }
        private int? pid = null;

        readonly CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        private delegate bool EventFilter(DetailedEvent detailedEvent);

        protected override void ProcessRecord()
        {
            CancellationToken cancellationToken = cancellationTokenSource.Token;
            ProcmonReader reader = new ProcmonReader();
            EventFilter[] filters =
            {
                (detailedEvent) => String.IsNullOrEmpty(ProcessName) || (detailedEvent.Process != null && detailedEvent.Process.ProcessName.ToLower().Contains(processName.ToLower())),
                (detailedEvent) => pid == null || (detailedEvent.Process != null && detailedEvent.Process.ProcessId == pid)
            };

            foreach (var ev in reader.GetEvents(cancellationToken))
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        if (filters.All((filter) => filter(ev)))
                            WriteObject(ev);
                    }
                    catch (PipelineStoppedException) { }
                }
            }
        }

        protected override void StopProcessing()
        {
            cancellationTokenSource.Cancel();
        }
    }
}
