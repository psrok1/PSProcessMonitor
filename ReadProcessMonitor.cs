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
        readonly CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        protected override void ProcessRecord()
        {
            CancellationToken cancellationToken = cancellationTokenSource.Token;
            ProcmonReader reader = new ProcmonReader();

            foreach (var ev in reader.GetEvents(cancellationToken))
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
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
