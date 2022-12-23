using System;
using System.Runtime.InteropServices;
using GodPotato.NativeAPI;

[ComImport]
[Guid("00000003-0000-0000-C000-000000000046")]
[InterfaceType(1)]
[ComConversionLoss]
public interface IMarshal
{
    void GetUnmarshalClass([In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS, out Guid pCid);

    void GetMarshalSizeMax([In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS, out uint pSize);

    void MarshalInterface([In][MarshalAs(UnmanagedType.Interface)] IStream pstm, [In] ref Guid riid, [In] IntPtr pv, [In] uint dwDestContext, [In] IntPtr pvDestContext, [In] uint MSHLFLAGS);

    void UnmarshalInterface([In][MarshalAs(UnmanagedType.Interface)] IStream pstm, [In] ref Guid riid, out IntPtr ppv);

    void ReleaseMarshalData([In][MarshalAs(UnmanagedType.Interface)] IStream pstm);

    void DisconnectObject([In] uint dwReserved);
}
