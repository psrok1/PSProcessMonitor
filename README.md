# PSProcessMonitor

**Warning:** Project is still under development and things described below are not fully working yet. Wait patiently for initial release!**

Powershell cmdlet utils for Sysinternals Process Monitor.

## Getting started

1. For live monitoring, you still need the original Process Monitor binary as its contains the driver that acts as an actual monitor
   Download it from the [official website](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
2. Run elevated Powershell
3. Download Powershell module from [Releases tab](https://github.com/psrok1/PSProcessMonitor/releases/latest) and import it

   ```
   PS C:\Users\user> Import-Module PSProcessMonitor.dll
   ```

   If you want to install it permanently to be loaded automatically for every Powershell session, [follow the instructions from Microsoft Docs](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_modules?view=powershell-7.3#how-to-install-a-module).

4. Load the Process Monitor driver. You can use `Enable-ProcessMonitor` cmdlet for that, providing a path to the original Process Monitor binary:

   ```
   PS C:\Users\user> Enable-ProcessMonitor Procmon.exe
   ```

   or just run Process Monitor yourself and close it. Driver will stay loaded in memory until next boot.

5. Finally you can start live monitoring using `Read-ProcessMonitor` cmdlet

   ```
   PS C:\Users\user> Read-ProcessMonitor
   ```

Powershell will be clogged with events very quickly, so don't keep it running for too long. Read further for instructions how to make something of value out of it.

## Reading events from PML files

If you want to process events from pre-recorded PML files, you don't need an active driver nor Powershell elevation.

Just use `Read-PML` cmdlet. It returns events from PML file in the same format as `Read-ProcessMonitor`

```
PS C:\Users\user> Read-PML Logfile.PML
```

## How to use it?

Stream of emitted events (`PSProcessMonitor.DetailedEvent` objects) have the following structure:

- `Process`: Information about process that performed the operation described in the event
- `Class`: Event type (Process, Registry, File, Profiling, Network)
- `Operation`: Event subtype specific for operation class
- `Duration`: Duration of the operation
- `Timestamp`: Timestamp of the operation
- `Status`: Status of the operation
- `Details`: Details about the arguments of the operation
- `PostDetails`: Details about the result of the operation (if available)

TODO

## Compatibility and known issues

- Currently module works only for 64-bit Windows (both live monitoring and recorded PML files)
- Live monitoring doesn't track network events, as they're not tracked by the driver. Process Monitor uses Event Tracing for Windows (ETW) mechanism for that.
- Project was tested with Process Monitor v3.93, but any version with the following numbers should work well:
  - PML in version 9 (first bytes of the PML file should be `50 4D 4C 5F 09 00 00 00`)
  - Driver in version 24 (PROCMON24, take a look at `fltmc` output when minifilter driver is loaded)

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