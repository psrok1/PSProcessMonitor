# PSProcessMonitor

Powershell cmdlet replacement for Sysinternals Process Monitor GUI.

## Getting started



## Who needs this?

Original Process Monitor GUI is really powerful for system monitoring and debugging, but its CLI usage is pretty much limited. Process Monitor allows you to specify 
command line arguments, so you can run monitoring in the background (`/AcceptEula /Quiet /Minimized`), store events in the backing file (`/BackingFile`) and monitor
system for limited time (`/Runtime`), but in most cases it's still too much effort for quick debugging action over SSH/Powershell Remoting.

Last time, when I ended with 800MB PML file from few seconds of monitoring that needed to be transfered over the network, I decided to find or make something
useful for CLI as well!

## Acknowledgments

Process Monitor is well-known freeware software in community, but it's closed source. Nevertheless I have got lots of useful knowledge about its internals from these sources:

- https://github.com/progmboy/openprocmon - OSS implementation of a Process Monitor GUI and Process Monitor driver that is compatible with the original one.
- https://github.com/eronnen/procmon-parser - PML format parser. PML files are mostly a snapshot of current system state followed by binary log of events. 
Log is in the same format as messages from filter driver, so docs and code from this project are useful as well for making your own Process Monitor client.

These projects saved me a lot of time that would be spend on reverse-enginnering the Process Monitor driver. Kudos!

If you want to learn more about Process Monitor, I also recommend you:

- [YouTube - Sysinternals: Process Monitor deep dive](https://youtube.com/watch?v=9H0Dz3NbNYQ)