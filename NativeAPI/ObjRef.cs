using System;
using System.IO;
using System.Text;

namespace GodPotato.NativeAPI{

    public enum TowerProtocol : ushort {
        EPM_PROTOCOL_DNET_NSP = 0x04,
        EPM_PROTOCOL_OSI_TP4 = 0x05,
        EPM_PROTOCOL_OSI_CLNS = 0x06,
        EPM_PROTOCOL_TCP = 0x07,
        EPM_PROTOCOL_UDP = 0x08,
        EPM_PROTOCOL_IP = 0x09,
        EPM_PROTOCOL_NCADG = 0x0a, /* Connectionless RPC */
        EPM_PROTOCOL_NCACN = 0x0b,
        EPM_PROTOCOL_NCALRPC = 0x0c, /* Local RPC */
        EPM_PROTOCOL_UUID = 0x0d,
        EPM_PROTOCOL_IPX = 0x0e,
        EPM_PROTOCOL_SMB = 0x0f,
        EPM_PROTOCOL_NAMED_PIPE = 0x10,
        EPM_PROTOCOL_NETBIOS = 0x11,
        EPM_PROTOCOL_NETBEUI = 0x12,
        EPM_PROTOCOL_SPX = 0x13,
        EPM_PROTOCOL_NB_IPX = 0x14, /* NetBIOS over IPX */
        EPM_PROTOCOL_DSP = 0x16, /* AppleTalk Data Stream Protocol */
        EPM_PROTOCOL_DDP = 0x17, /* AppleTalk Data Datagram Protocol */
        EPM_PROTOCOL_APPLETALK = 0x18, /* AppleTalk */
        EPM_PROTOCOL_VINES_SPP = 0x1a,
        EPM_PROTOCOL_VINES_IPC = 0x1b, /* Inter Process Communication */
        EPM_PROTOCOL_STREETTALK = 0x1c, /* Vines Streettalk */
        EPM_PROTOCOL_HTTP = 0x1f,
        EPM_PROTOCOL_UNIX_DS = 0x20, /* Unix domain socket */
        EPM_PROTOCOL_NULL = 0x21
    }

    internal class ObjRef {

        [Flags]
        enum Type : uint {
            Standard = 0x1,
            Handler = 0x2,
            Custom = 0x4
        }

        const uint Signature = 0x574f454d;
        public readonly Guid Guid;
        public readonly Standard StandardObjRef;

        public ObjRef(Guid guid, Standard standardObjRef) {
            Guid = guid;
            StandardObjRef = standardObjRef;
        }

        public ObjRef(byte[] objRefBytes) {

            BinaryReader br = new BinaryReader(new MemoryStream(objRefBytes), Encoding.Unicode);

            if (br.ReadUInt32() != Signature) {
                throw new InvalidDataException("Does not look like an OBJREF stream");
            }

            uint flags = br.ReadUInt32();
            Guid = new Guid(br.ReadBytes(16));

            if ((Type)flags == Type.Standard) {
                StandardObjRef = new Standard(br);
            }
        }

        public byte[] GetBytes() {
            BinaryWriter bw = new BinaryWriter(new MemoryStream());

            bw.Write(Signature);
            bw.Write((uint)1);
            bw.Write(Guid.ToByteArray());

            StandardObjRef.Save(bw);

            return ((MemoryStream)bw.BaseStream).ToArray();
        }

        internal class SecurityBinding {

            public readonly ushort AuthnSvc;
            public readonly ushort AuthzSvc;
            public readonly string PrincipalName;

            public SecurityBinding(ushort authnSvc, ushort authzSnc, string principalName) {
                AuthnSvc = authnSvc;
                AuthzSvc = authzSnc;
                PrincipalName = principalName;
            }

            public SecurityBinding(BinaryReader br) {

                AuthnSvc = br.ReadUInt16();
                AuthzSvc = br.ReadUInt16();
                char character;
                string principalName = "";

                while ((character = br.ReadChar()) != 0) {
                    principalName += character;
                }

                br.ReadChar();
            }


            public byte[] GetBytes() {
                BinaryWriter bw = new BinaryWriter(new MemoryStream(), Encoding.Unicode);

                bw.Write(AuthnSvc);
                bw.Write(AuthzSvc);

                if (PrincipalName != null && PrincipalName.Length > 0)
                    bw.Write(Encoding.Unicode.GetBytes(PrincipalName));

                bw.Write((char)0);
                bw.Write((char)0);

                return ((MemoryStream)bw.BaseStream).ToArray();
            }
        }

        internal class StringBinding {
            public readonly TowerProtocol TowerID;
            public readonly string NetworkAddress;

            public StringBinding(TowerProtocol towerID, string networkAddress) {
                TowerID = towerID;
                NetworkAddress = networkAddress;
            }

            public StringBinding(BinaryReader br) {
                TowerID = (TowerProtocol)br.ReadUInt16();
                char character;
                string networkAddress = "";

                while ((character = br.ReadChar()) != 0) {
                    networkAddress += character;
                }

                br.ReadChar();
                NetworkAddress = networkAddress;
            }

            internal byte[] GetBytes() {
                BinaryWriter bw = new BinaryWriter(new MemoryStream(), Encoding.Unicode);

                bw.Write((ushort)TowerID);
                bw.Write(Encoding.Unicode.GetBytes(NetworkAddress));
                bw.Write((char)0);
                bw.Write((char)0);

                return ((MemoryStream)bw.BaseStream).ToArray();
            }
        }

        internal class DualStringArray {
            private readonly ushort NumEntries;
            private readonly ushort SecurityOffset;
            public readonly StringBinding StringBinding;
            public readonly SecurityBinding SecurityBinding;

            public DualStringArray(StringBinding stringBinding, SecurityBinding securityBinding) {
                NumEntries = (ushort)((stringBinding.GetBytes().Length + securityBinding.GetBytes().Length) / 2);
                SecurityOffset = (ushort)(stringBinding.GetBytes().Length / 2);

                StringBinding = stringBinding;
                SecurityBinding = securityBinding;
            }

            public DualStringArray(BinaryReader br) {
                NumEntries = br.ReadUInt16();
                SecurityOffset = br.ReadUInt16();

                StringBinding = new StringBinding(br);
                SecurityBinding = new SecurityBinding(br);
            }

            internal void Save(BinaryWriter bw) {

                byte[] stringBinding = StringBinding.GetBytes();
                byte[] securityBinding = SecurityBinding.GetBytes();

                bw.Write((ushort)((stringBinding.Length + securityBinding.Length) / 2));
                bw.Write((ushort)(stringBinding.Length / 2));
                bw.Write(stringBinding);
                bw.Write(securityBinding);
            }
        }

        internal class Standard {

            const ulong Oxid = 0x0703d84a06ec96cc;
            const ulong Oid = 0x539d029cce31ac;

            public readonly uint Flags;
            public readonly uint PublicRefs;
            public readonly ulong OXID;
            public readonly ulong OID;
            public readonly Guid IPID;
            public readonly DualStringArray DualStringArray;

            public Standard(uint flags, uint publicRefs, ulong oxid, ulong oid, Guid ipid, DualStringArray dualStringArray) {
                Flags = flags;
                PublicRefs = publicRefs;
                OXID = oxid;
                OID = oid;
                IPID = ipid;
                DualStringArray = dualStringArray;
            }

            public Standard(BinaryReader br) {
                Flags = br.ReadUInt32();
                PublicRefs = br.ReadUInt32();
                OXID = br.ReadUInt64();
                OID = br.ReadUInt64();
                IPID = new Guid(br.ReadBytes(16));

                DualStringArray = new DualStringArray(br);
            }

            internal void Save(BinaryWriter bw) {
                bw.Write(Flags);
                bw.Write(PublicRefs);
                bw.Write(OXID);
                bw.Write(OID);
                bw.Write(IPID.ToByteArray());
                DualStringArray.Save(bw);
            }
        }
    }
}
