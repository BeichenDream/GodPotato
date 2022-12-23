using System;
using System.Runtime.InteropServices;
using GodPotato.NativeAPI;

[ComImport]
[InterfaceType(1)]
[ComConversionLoss]
[Guid("0000000B-0000-0000-C000-000000000046")]
public interface IStorage
{
    void CreateStream([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsName, [In] uint grfMode, [In] uint reserved1, [In] uint reserved2, [MarshalAs(UnmanagedType.Interface)] out IStream ppstm);

    void OpenStream([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsName, [In] IntPtr reserved1, [In] uint grfMode, [In] uint reserved2, [MarshalAs(UnmanagedType.Interface)] out IStream ppstm);

    void CreateStorage([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsName, [In] uint grfMode, [In] uint reserved1, [In] uint reserved2, [MarshalAs(UnmanagedType.Interface)] out IStorage ppstg);

    void OpenStorage([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsName, [In][MarshalAs(UnmanagedType.Interface)] IStorage pstgPriority, [In] uint grfMode, [In] IntPtr snbExclude, [In] uint reserved, [MarshalAs(UnmanagedType.Interface)] out IStorage ppstg);

    void CopyTo([In] uint ciidExclude, [In][MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 0)] Guid[] rgiidExclude, [In] IntPtr snbExclude, [In][MarshalAs(UnmanagedType.Interface)] IStorage pstgDest);

    void MoveElementTo([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsName, [In][MarshalAs(UnmanagedType.Interface)] IStorage pstgDest, [In][MarshalAs(UnmanagedType.LPWStr)] string pwcsNewName, [In] uint grfFlags);

    void Commit([In] uint grfCommitFlags);

    void Revert();

    void EnumElements([In] uint reserved1, [In] IntPtr reserved2, [In] uint reserved3, [MarshalAs(UnmanagedType.Interface)] out IEnumSTATSTG ppEnum);

    void DestroyElement([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsName);

    void RenameElement([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsOldName, [In][MarshalAs(UnmanagedType.LPWStr)] string pwcsNewName);

    void SetElementTimes([In][MarshalAs(UnmanagedType.LPWStr)] string pwcsName, [In][MarshalAs(UnmanagedType.LPArray)] FILETIME[] pctime, [In][MarshalAs(UnmanagedType.LPArray)] FILETIME[] patime, [In][MarshalAs(UnmanagedType.LPArray)] FILETIME[] pmtime);

    void SetClass([In] ref Guid clsid);

    void SetStateBits([In] uint grfStateBits, [In] uint grfMask);

    void Stat([Out][MarshalAs(UnmanagedType.LPArray)] STATSTG[] pstatstg, [In] uint grfStatFlag);
}
