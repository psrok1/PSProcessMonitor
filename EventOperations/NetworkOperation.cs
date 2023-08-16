using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSProcessMonitor
{
    public enum NetworkOperation : short
    {
        Unknown = 0,
        Other = 1,
        Send = 2,
        Receive = 3,
        Accept = 4,
        Connect = 5,
        Disconnect = 6,
        Reconnect = 7,
        Retransmit = 8,
        TCPCopy = 9,
    }
}
