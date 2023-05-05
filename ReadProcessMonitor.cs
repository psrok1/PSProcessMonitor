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
            ProcmonDriverClient procmonClient;

            procmonClient = ProcmonDriverClient.Connect();
            procmonClient.ConfigureFlags(7);
            int? lastSecond = null;
            try
            {
                foreach (var message in procmonClient.ReceiveMessages(cancellationToken))
                {
                    using (message)
                    {
                        // Even after cancellation, we need to exhaust
                        // ReceiveMessages enumeration to dispose all messages
                        // that are left in queue (they're holding unmanaged heap memory)
                        if (!cancellationToken.IsCancellationRequested)
                        {
                            DateTime currentTime = DateTime.Now;
                            RawEvent[] events = message.ParseEvents().ToArray();
                            if (lastSecond != currentTime.Second)
                            {
                                Console.WriteLine("Current time is {0}", currentTime);
                                try
                                {
                                    WriteObject(events[0], true);
                                }
                                catch (PipelineStoppedException) { }
                                lastSecond = currentTime.Second;
                            }
                        }
                    }
                }
            }
            finally
            {
                procmonClient.ConfigureFlags(0);
                procmonClient.Disconnect();
            }
        }

        protected override void StopProcessing()
        {
            cancellationTokenSource.Cancel();
        }
    }
}
