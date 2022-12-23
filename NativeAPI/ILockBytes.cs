using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace GodPotato.NativeAPI
{
    [ComVisible(false)]
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000000A-0000-0000-C000-000000000046")]
    public interface ILockBytes
    {
        //Note: These two by(reference 32-bit integers (ULONG) could be used as return values instead,
        //      but they are not tagged [retval] in the IDL, so for consitency's sake...
        void ReadAt(long ulOffset, System.IntPtr pv, int cb, out System.UInt32 pcbRead);
        void WriteAt(long ulOffset, System.IntPtr pv, int cb, out System.UInt32 pcbWritten);
        void Flush();
        void SetSize(long cb);
        void LockRegion(long libOffset, long cb, int dwLockType);
        void UnlockRegion(long libOffset, long cb, int dwLockType);
        void Stat(out System.Runtime.InteropServices.STATSTG pstatstg, int grfStatFlag);

    }
}
