using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace PSProcessMonitor
{
    [StructLayout(LayoutKind.Explicit)]
    internal struct ControlMessage
    {
        [FieldOffset(0)]
        public int OperationCode;
        [FieldOffset(4)]
        public int Flags;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct DriverMessageHeader
    {
        // Previous fields belong to the FILTER_MESSAGE_HEADER
        // which is zeroed anyway in case of procmon driver
        [FieldOffset(0x10)]
        public int MessageLength;
    }

    public class DriverConnectionException : Exception
    {
        private static string getMessage(uint hResult)
        {
            switch (hResult)
            {
                case (uint)HRESULT.ERROR_FILE_NOT_FOUND:
                    return "File not found: Process Monitor driver is not loaded.";
                case (uint)HRESULT.ERROR_TOO_MANY_OPEN_FILES:
                    return "Too many open files: Process Monitor is already active in your system. Shutdown existing procmon instances.";
                case (uint)HRESULT.ERROR_ACCESS_DENIED:
                    return "Access denied: You need administrative rights to connect to Process Monitor driver.";
                case (uint)HRESULT.ERROR_CONNECTION_COUNT_LIMIT:
                    return "Connection count limit: Process Monitor is already active in your system. Shutdown existing procmon instances.";
                default:
                    return string.Format("Unknown HRESULT: 0x{0:X08}", hResult);
            }
        }
        public DriverConnectionException(uint hResult) : base(getMessage(hResult)) { }
    }

    public class DriverSynchronizationLostException : Exception { }

    public class DriverClientQueueExhausted : Exception { }

    public class DriverMessage : IDisposable
    {
        // Actual max message size is 0x20000 but we need to include some extra for headers.
        // It's one-time allocation so let's make it rounded...
        public static readonly int MaxMessageSize = 0x21000;
        private MemoryDataStream _stream;
        public int MessageLength { get; private set; }

        public DriverMessage(IntPtr messageBuffer)
        {
            DriverMessageHeader message = Marshal.PtrToStructure<DriverMessageHeader>(messageBuffer);
            MessageLength = message.MessageLength;
            if (MessageLength <= 0 || MessageLength > MaxMessageSize)
            {
                throw new IndexOutOfRangeException(
                    string.Format(
                        "Received message length ({0}) is out of expected bounds",
                        MessageLength
                    ));
            }

            IntPtr eventBuffer = IntPtr.Add(messageBuffer, Marshal.SizeOf<DriverMessageHeader>());
            _stream = new MemoryDataStream(eventBuffer, MessageLength);
        }

        public IEnumerable<RawEvent> ParseEvents()
        {
            while (!_stream.End())
            {
                EventHeaderStruct header = _stream.ReadStructure<EventHeaderStruct>();
                long[] stackTrace = _stream.ReadInt64Values(header.StackTraceLength);
                MemoryDataStreamView detailsData = _stream.ReadDataAsView(header.DetailsLength);
                RawEvent rawEvent = new RawEvent(header, stackTrace, detailsData);
                yield return rawEvent;
            }
        }

        public void Dispose()
        {
            _stream.Dispose();
        }
    }

    internal class ProcmonDriverClient : IDisposable
    {
        public static string PortName = "\\ProcessMonitor24Port";

        // Receiver thread does its best (or at least it should) to receive messages
        // as fast as possible. Driver has limited capacity and stops responding
        // if we're too slow (which is handled internally by throwing
        // DriverSynchronizationLostException)
        //
        // Nevertheless if main thread processing is not quick enough, message
        // queue will grow indefinitely. We need to stop it at some point and
        // throw exception if queue of pending events is too big.
        //
        // Let's make it somewhere around 1GB (MaxReceiverQueueSize*MaxMessageSize)
        public static readonly int MaxReceiverQueueSize = 50000;
        private SafeFilterHandle _port;

        public ProcmonDriverClient(SafeFilterHandle port)
        {
            _port = port;
        }

        ~ProcmonDriverClient()
        {
            Disconnect();
        }

        public IEnumerable<RawEvent> ReceiveEvents(CancellationToken cancellationToken)
        {
            BlockingCollection<DriverMessage> driverMessageQueue = new BlockingCollection<DriverMessage>();
            // Task cares of proper exception passing to the main thread
            Task receiver = Task.Factory.StartNew(() =>
            {
                IntPtr messageBuffer = Marshal.AllocHGlobal(DriverMessage.MaxMessageSize);
                NativeWin32.FillMemory(messageBuffer, (uint)DriverMessage.MaxMessageSize, 0);
                try
                {
                    while (!cancellationToken.IsCancellationRequested)
                    {
                        ManualResetEvent completionEvent = new ManualResetEvent(false);
                        IntPtr completionEventHandle = completionEvent.SafeWaitHandle.DangerousGetHandle();
                        NativeOverlapped overlapped = new NativeOverlapped
                        {
                            EventHandle = completionEventHandle
                        };
                        // Zero DriverMessageHeader to ensure that old message length is not left after failed read
                        NativeWin32.FillMemory(messageBuffer, (uint)Marshal.SizeOf<DriverMessageHeader>(), 0);
                        uint result = NativeWin32.FilterGetMessage(_port, messageBuffer, (uint)DriverMessage.MaxMessageSize, ref overlapped);
                        if (result != ((uint)HRESULT.ERROR_IO_PENDING))
                        {
                            Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                        }
                        WaitHandle[] waitHandles = new WaitHandle[] { completionEvent, cancellationToken.WaitHandle };
                        int index = WaitHandle.WaitAny(waitHandles, 1000);
                        if (index == WaitHandle.WaitTimeout)
                        {
                            // If we don't get anything for more than 1 second, possibly driver stopped talking
                            // due to exhausted internal queue (as we're too slow to receive)
                            throw new DriverSynchronizationLostException();
                        }
                        else if (index == 0)
                        {
                            // Message completed
                            if (driverMessageQueue.Count > MaxReceiverQueueSize)
                            {
                                throw new DriverClientQueueExhausted();
                            }
                            DriverMessage message = new DriverMessage(messageBuffer);
                            try
                            {
                                driverMessageQueue.Add(message);
                            } catch(InvalidOperationException)
                            {
                                // If adding completed on consumer side: break the loop
                                break;
                            }
                        }
                        else
                        {
                            break;
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(messageBuffer);
                    // Send signal that adding is complete
                    driverMessageQueue.CompleteAdding();
                }
            }, TaskCreationOptions.LongRunning);

            IEnumerable<DriverMessage> consumingEnumerable = driverMessageQueue.GetConsumingEnumerable();
            bool receiveCompleted = false;
            try
            {
                foreach (var message in consumingEnumerable)
                {
                    using (message)
                    {
                        foreach (var ev in message.ParseEvents())
                        {
                            yield return ev;
                        }
                    }
                }
                receiveCompleted = true;
            } finally
            {
                // So.. why we landed here? There are multiple options
                // 1. message.ParseEvents thrown exception due to a bug
                // 2. ReceiveMessages enumerable was prematurely disposed
                // 3. try block finished
                //
                // If it's fault on consumer side (receiving was not completed) then
                // we need to exhaust ReceiveMessages enumeration to dispose all messages
                // that are left in queue (they're holding unmanaged heap memory)
                if (!receiveCompleted)
                {
                    driverMessageQueue.CompleteAdding();
                    foreach (var message in consumingEnumerable)
                    {
                        message.Dispose();
                    }
                }
                // At this point, Task is in RanToCompletion or Faulted state
                // In case of Faulted, this will propagate any exceptions that occurred
                receiver.Wait();
            }
        }

        public void ConfigureFlags(int flags)
        {
            ControlMessage controlMessage = new ControlMessage()
            {
                OperationCode = 0,
                Flags = flags
            };
            int result = NativeWin32.FilterSendMessage(_port, ref controlMessage, (uint)Marshal.SizeOf(controlMessage), IntPtr.Zero, 0, out _);
            Marshal.ThrowExceptionForHR(result);
        }

        public void Disconnect()
        {
            _port.Close();
        }

        public static ProcmonDriverClient Connect()
        {
            uint flag = 0;
            SafeFilterHandle port = new SafeFilterHandle();

            uint hResult = NativeWin32.FilterConnectCommunicationPort(
                PortName,
                0,
                ref flag,
                sizeof(uint),
                IntPtr.Zero,
                ref port
            );

            if (hResult == 0)
            {
                return new ProcmonDriverClient(port);
            }
            else
            {
                if (!port.IsInvalid)
                {
                    port.Close();
                }
                throw new DriverConnectionException(hResult);
            }
        }

        public void Dispose()
        {
            Disconnect();
        }
    }
}
