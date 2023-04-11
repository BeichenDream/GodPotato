using System;
using System.IO;

namespace GodPotato.NativeAPI
{
    internal class UnmarshalDCOM
    {
        private readonly static Guid IID_IUnknown = new Guid("{00000000-0000-0000-C000-000000000046}");

        public static int UnmarshalObject(Stream stm, Guid iid, out IntPtr ppv)
        {
            return NativeMethods.CoUnmarshalInterface(new IStreamImpl(stm), ref iid,out ppv);
        }

        public static int UnmarshalObject(byte[] objref, out IntPtr ppv)
        {
            return UnmarshalObject(new MemoryStream(objref), IID_IUnknown,out ppv);
        }
    }
}
