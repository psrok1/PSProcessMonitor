using System;
using System.Management.Automation;  // Windows PowerShell assembly.

namespace PSProcessMonitor
{
    // Declare the class as a cmdlet and specify the
    // appropriate verb and noun for the cmdlet name.
    [Cmdlet(VerbsCommon.Get, "SystemState")]
    public class GetSystemState : Cmdlet
    {
        protected override void ProcessRecord()
        {
            if(!ProcessState.TryEnableDebugPrivilege())
            {
                WriteWarning("Can't enable debug privilege");
            }
            ProcessState systemState = ProcessState.GetCurrentState();
            foreach(var process in systemState.ProcessById.Values)
            {
                WriteObject(process);
            }
        }
    }
}
