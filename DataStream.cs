using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PSProcessMonitor
{
    public abstract class DataStreamView
    {
        public abstract void Move(int offset);
        public abstract T ReadStructure<T>();
        public abstract byte[] ReadBytes(int count);
        public abstract long[] ReadInt64Values(int count);
        public abstract string ReadUnicodeString(int charLength);
        public string ReadProcmonString(ushort length)
        {
            // MSB determines type of the string: 1 - ASCII, 0 - UTF-16
            int charLength = length & 0x7FFF;
            bool isAscii = (length & 0x8000) != 0;
            if (isAscii)
            {
                return Encoding.ASCII.GetString(this.ReadBytes(charLength));
            }
            else
            {
                return ReadUnicodeString(charLength);
            }
        }
    }

    public class FileDataStreamView : DataStreamView
    {
        private BinaryReader reader;

        public FileDataStreamView(BinaryReader reader)
        {
            // BinaryReader must be opened with Encoding.Unicode
            // I can't check it here though
            this.reader = reader;
        }
        public override void Move(int offset)
        {
            reader.ReadBytes(offset);
        }
        public override T ReadStructure<T>()
        {
            byte[] buffer = ReadBytes(Marshal.SizeOf<T>());
            GCHandle handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            T structure = Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
            handle.Free();
            return structure;
        }
        public override byte[] ReadBytes(int count)
        {
            byte[] buffer = new byte[count];
            return reader.ReadBytes(buffer.Length);
        }
        public override long[] ReadInt64Values(int count)
        {
            long[] values = new long[count];
            for(int i = 0; i < count; i++)
            {
                values[i] = reader.ReadInt64();
            }
            return values;
        }
        public override string ReadUnicodeString(int charLength)
        {
            // I can't check encoding of BinaryReader, so it's safer to make a new one
            using(BinaryReader ureader = new BinaryReader(reader.BaseStream, Encoding.Unicode, leaveOpen: true))
            {
                return new string(ureader.ReadChars(charLength));
            }
        }
    }

    /**
     * <summary>
     * Serves stream memory view over unowned unmanaged memory block, optionally backed by DataStream object.
     * It doesn't hold ownership on underlying memory, so it doesn't offer IDisposable interface.
     * </summary>
     */
    public class MemoryDataStreamView : DataStreamView
    {
#pragma warning disable IDE0052
        // Keeps reference to the parent DataStream that holds the actual unmanaged memory
        // Although I'm not sure if it's necessary
        private MemoryDataStream _parentRef;
#pragma warning restore IDE0052
        public IntPtr Ptr { get; private set; }
        public IntPtr InitialPtr { get; private set; }
        public int Size { get; private set; }

        public MemoryDataStreamView(IntPtr ptr, int size)
        {
            InitialPtr = Ptr = ptr;
            Size = size;
        }

        private MemoryDataStreamView(IntPtr ptr, int size, MemoryDataStream parent) : this(ptr, size)
        {
            _parentRef = parent;
        }

        protected virtual void CheckHasBytes(int howMany)
        {
            if (Size < howMany)
            {
                throw new ArgumentOutOfRangeException(nameof(howMany), $"Tried to read {howMany} but only {Size} bytes left");
            }
        }

        protected MemoryDataStreamView ReadDataAsView(int count, MemoryDataStream parent)
        {
            CheckHasBytes(count);
            MemoryDataStreamView view = new MemoryDataStreamView(Ptr, count, parent);
            MoveUnsafe(count);
            return view;
        }

        protected void MoveUnsafe(int offset)
        {
            if (Size < offset)
            {
                throw new ArgumentOutOfRangeException(nameof(offset), $"Tried to move IntPtr by {offset} but only {Size} bytes left");
            }
            Ptr = IntPtr.Add(Ptr, offset);
            Size -= offset;
        }

        public bool End()
        {
            return Size == 0;
        }

        public override void Move(int offset)
        {
            CheckHasBytes(offset);
            MoveUnsafe(offset);
        }

        public override T ReadStructure<T>()
        {
            int structSize = Marshal.SizeOf<T>();
            CheckHasBytes(structSize);
            T obj = Marshal.PtrToStructure<T>(Ptr);
            MoveUnsafe(structSize);
            return obj;
        }

        public override byte[] ReadBytes(int count)
        {
            CheckHasBytes(count);
            byte[] values = new byte[count];
            Marshal.Copy(Ptr, values, 0, count);
            MoveUnsafe(count);
            return values;
        }

        public override long[] ReadInt64Values(int count)
        {
            int structSize = Marshal.SizeOf<long>() * count;
            CheckHasBytes(structSize);
            long[] values = new long[count];
            Marshal.Copy(Ptr, values, 0, count);
            MoveUnsafe(structSize);
            return values;
        }

        public override string ReadUnicodeString(int charLength)
        {
            string decoded = Marshal.PtrToStringUni(Ptr, charLength);
            // I think this could be done better:
            // I'm getting count of Unicode characters from structure.
            // It's UTF-16, so it's at least 2 bytes per character but I
            // don't know how many actual bytes are there. So I re-encode the string,
            // with hope to achieve the same encoding and move pointer appropriately.
            Move(Encoding.Unicode.GetBytes(decoded).Length);
            return decoded;
        }
    }

    /**
     * <summary>
     * Serves stream memory view over unmanaged memory block.
     * DataStream owns unmanaged memory (optionally by making a copy), 
     * and frees the underlying memory during disposal.
     * </summary>
     */
    public sealed class MemoryDataStream : MemoryDataStreamView, IDisposable
    {
        private bool _disposed = false;

        private static IntPtr CopyFromPtr(IntPtr ptr, int size)
        {
            IntPtr ownPtr = Marshal.AllocHGlobal(size);
            NativeWin32.CopyMemory(ownPtr, ptr, (uint)size);
            return ownPtr;
        }

        public MemoryDataStream(IntPtr ptr, int size, bool makeCopy = true) : base(makeCopy ? CopyFromPtr(ptr, size) : ptr, size) { }

        public MemoryDataStream(int size) : this(Marshal.AllocHGlobal(size), size, false) { }

        protected override void CheckHasBytes(int howMany)
        {
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
            base.CheckHasBytes(howMany);
        }

        public MemoryDataStreamView ReadDataAsView(int count)
        {
            return ReadDataAsView(count, this);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Marshal.FreeHGlobal(InitialPtr);
                _disposed = true;
            }
        }
    }

    /**
     * <summary>
     * Reads structure from given IntPtr and frees the
     * underlying memory when disposed.
     * </summary>
     */
    public sealed class StructureReader<T>: IDisposable
    {
        private bool _disposed = false;

        public IntPtr Ptr { get; private set; }
        public int Size { get; private set; }

        public static StructureReader<T> Invalid = new StructureReader<T> { _disposed = true };

        public StructureReader(IntPtr ptr, int size)
        {
            Ptr = ptr;
            Size = size;
            if(ptr == IntPtr.Zero)
            {
                _disposed = true;
            }
        }

        public StructureReader(int size) : this(Marshal.AllocHGlobal(size), size) { }

        public StructureReader() : this(Marshal.SizeOf<T>()) { }

        public bool IsInvalid()
        {
            return _disposed;
        }

        public T GetStructure()
        {
            if(_disposed)
                throw new ObjectDisposedException(GetType().FullName);
            T obj = Marshal.PtrToStructure<T>(Ptr);
            return obj;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Marshal.FreeHGlobal(Ptr);
                _disposed = true;
            }
        }
    }
}
