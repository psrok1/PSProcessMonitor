﻿using System;
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
            if(!SystemState.TryEnableDebugPrivilege())
            {
                WriteWarning("Can't enable debug privilege");
            }
            SystemState systemState = SystemState.GetCurrentState();
            foreach(var process in systemState.ProcessById.Values)
            {
                WriteObject(process);
            }
        }
    }
}
