using System;
using System.Linq;
using System.Management.Automation;  // Windows PowerShell assembly.
using System.Threading;

namespace PSProcessMonitor
{
    // Declare the class as a cmdlet and specify the
    // appropriate verb and noun for the cmdlet name.
    [Cmdlet(VerbsLifecycle.Enable, "ProcessMonitor")]
    public class EnableProcessMonitor : Cmdlet
    {
        protected override void ProcessRecord()
        {
        }

        protected override void StopProcessing()
        {
        }
    }
}
