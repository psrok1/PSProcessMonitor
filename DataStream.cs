using System;
using System.Runtime.InteropServices;

namespace PSProcessMonitor
{
    /**
     * <summary>
     * Serves stream memory view over unowned unmanaged memory block, optionally backed by DataStream object
     * </summary>
     */
    public class DataStreamView
    {
#pragma warning disable IDE0052
        // Keeps reference to the parent DataStream that holds the actual unmanaged memory
        private DataStream _parentRef;
#pragma warning restore IDE0052
        public IntPtr Ptr { get; private set; }
        public IntPtr InitialPtr { get; private set; }
        public int Size { get; private set; }
        public int InitialSize { get; private set; }

        public DataStreamView(IntPtr ptr, int size)
        {
            InitialPtr = Ptr = ptr;
            InitialSize = Size = size;
        }

        private DataStreamView(IntPtr ptr, int size, DataStream parent) : this(ptr, size)
        {
            _parentRef = parent;
        }

        protected DataStreamView ReadDataAsView(int count, DataStream parent)
        {
            CheckHasBytes(count);
            DataStreamView view = new DataStreamView(Ptr, count, parent);
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

        protected virtual void CheckHasBytes(int howMany)
        {
            if (Size < howMany)
            {
                throw new ArgumentOutOfRangeException(nameof(howMany), $"Tried to read {howMany} but only {Size} bytes left");
            }
        }

        public bool End()
        {
            return Size == 0;
        }

        public void Move(int offset)
        {
            CheckHasBytes(offset);
            MoveUnsafe(offset);
        }

        public T ReadStructure<T>()
        {
            int structSize = Marshal.SizeOf<T>();
            CheckHasBytes(structSize);
            T obj = Marshal.PtrToStructure<T>(Ptr);
            MoveUnsafe(structSize);
            return obj;
        }

        public byte[] ReadBytes(int count)
        {
            int structSize = Marshal.SizeOf<byte>() * count;
            CheckHasBytes(structSize);
            byte[] values = new byte[count];
            Marshal.Copy(Ptr, values, 0, count);
            MoveUnsafe(structSize);
            return values;
        }

        public DataStream ReadData(int count)
        {
            CheckHasBytes(count);
            DataStream value = new DataStream(Ptr, count);
            MoveUnsafe(count);
            return value;
        }

        public DataStreamView ReadDataAsView(int count)
        {
            return ReadDataAsView(count, _parentRef);
        }

        public long[] ReadInt64Values(int count)
        {
            int structSize = Marshal.SizeOf<long>() * count;
            CheckHasBytes(structSize);
            long[] values = new long[count];
            Marshal.Copy(Ptr, values, 0, count);
            MoveUnsafe(structSize);
            return values;
        }
    }

    /**
     * <summary>
     * Serves stream memory view over unmanaged memory block.
     * DataStream takes copy and owns unmanaged memory. It cares of proper disposal.
     * </summary>
     */
    public sealed class DataStream : DataStreamView, IDisposable
    {
        private bool _disposed = false;

        private static IntPtr CopyFromPtr(IntPtr ptr, int size)
        {
            IntPtr ownPtr = Marshal.AllocHGlobal(size);
            unsafe
            {
                Buffer.MemoryCopy(ptr.ToPointer(), ownPtr.ToPointer(), size, size);
            }
            return ownPtr;
        }

        public DataStream(IntPtr ptr, int size, bool makeCopy = true) : base(makeCopy ? CopyFromPtr(ptr, size) : ptr, size) { }

        public DataStream(int size) : this(Marshal.AllocHGlobal(size), size, false) { }

        protected override void CheckHasBytes(int howMany)
        {
            if (_disposed) throw new ObjectDisposedException(GetType().FullName);
            base.CheckHasBytes(howMany);
        }


        public new DataStreamView ReadDataAsView(int count)
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

    public sealed class StructureBuffer<T>: IDisposable
    {
        private bool _disposed = false;

        public IntPtr Ptr { get; private set; }
        public int Size { get; private set; }

        public static StructureBuffer<T> Invalid = new StructureBuffer<T> { _disposed = true };

        public StructureBuffer(IntPtr ptr, int size)
        {
            Ptr = ptr;
            Size = size;
            if(ptr == IntPtr.Zero)
            {
                _disposed = true;
            }
        }

        public StructureBuffer(int size) : this(Marshal.AllocHGlobal(size), size) { }

        public StructureBuffer(IntPtr ptr) : this(ptr, Marshal.SizeOf<T>()) { }

        public StructureBuffer() : this(Marshal.SizeOf<T>()) { }

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
