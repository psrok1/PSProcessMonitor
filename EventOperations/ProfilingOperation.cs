using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSProcessMonitor
{
    public enum ProfilingOperation : short
    {
        ThreadProfiling = 0,
        ProcessProfiling = 1,
        DebugOutputProfiling = 2,
    }
}