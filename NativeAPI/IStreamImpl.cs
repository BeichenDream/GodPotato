using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace GodPotato.NativeAPI
{
    public class IStreamImpl : IStream, IDisposable
    {
        private Stream m_stream;

        public IStreamImpl(Stream stream)
        {
            m_stream = stream;
        }


        public void Dispose()
        {
            m_stream.Dispose();
        }

        public void Close()
        {
            Dispose();
        }

        public void Clone(out IStream pStm)
        {
            throw new NotImplementedException();
        }

        public void Stat(out System.Runtime.InteropServices.ComTypes.STATSTG statStg, int grfFlags)
        {
            statStg = new System.Runtime.InteropServices.ComTypes.STATSTG();
            statStg.cbSize = m_stream.Length;
        }

        public void UnlockRegion(long libOffset, long cb, int dwLockType)
        {
            throw new NotImplementedException();
        }

        public void LockRegion(long libOffset, long cb, int dwLockType)
        {
            throw new NotImplementedException();
        }

        public void Revert()
        {
            throw new NotImplementedException();
        }

        public void Commit(int grfCommitFlags)
        {
            throw new NotImplementedException();
        }

        public void CopyTo(IStream pstm, long cb, IntPtr pcbRead, IntPtr pcbWritten)
        {
            throw new NotImplementedException();
        }

        public void SetSize(long lSize)
        {
            throw new NotImplementedException();
        }

        public void Seek(long dlibMove, int dwOrigin, IntPtr plibNewPosition)
        {
            SeekOrigin origin;

            switch (dwOrigin)
            {
                case 0:
                    origin = SeekOrigin.Begin;
                    break;
                case 1:
                    origin = SeekOrigin.Current;
                    break;
                case 2:
                    origin = SeekOrigin.End;
                    break;
                default: throw new ArgumentException();
            }
            m_stream.Seek(dlibMove, origin);
            if (plibNewPosition != IntPtr.Zero)
            {
                Marshal.WriteInt64(plibNewPosition, m_stream.Position);
            }
        }

        public void Read(byte[] pv, int cb, IntPtr pcbRead)
        {
            int readCount = m_stream.Read(pv, 0, cb);
            if (pcbRead != IntPtr.Zero)
            {
                Marshal.WriteInt32(pcbRead, readCount);
            }
        }

        public void Write(byte[] pv, int cb, IntPtr pcbWritten)
        {
            m_stream.Write(pv, 0, cb);
            if (pcbWritten != IntPtr.Zero)
            {
                Marshal.WriteInt32(pcbWritten, cb);
            }
        }
    }
}
