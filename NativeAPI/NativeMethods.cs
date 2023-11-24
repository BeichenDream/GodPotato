using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Principal;
using System.Text;

namespace GodPotato.NativeAPI
{
    public class NativeMethods
    {

        public readonly static IntPtr BAD_HANLE = new IntPtr(-1);


        public static readonly uint ERROR_PIPE_CONNECTED = 0x217;

        public static readonly uint HANDLE_FLAG_INHERIT = 0x00000001;
        public static readonly uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;

        public readonly static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public readonly static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public readonly static uint TOKEN_DUPLICATE = 0x0002;
        public readonly static uint TOKEN_IMPERSONATE = 0x0004;
        public readonly static uint TOKEN_QUERY = 0x0008;
        public readonly static uint TOKEN_QUERY_SOURCE = 0x0010;
        public readonly static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public readonly static uint TOKEN_ADJUST_GROUPS = 0x0040;
        public readonly static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public readonly static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        public readonly static uint TOKEN_ELEVATION = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;

        public readonly static uint STARTF_FORCEONFEEDBACK = 0x00000040;
        public readonly static uint STARTF_FORCEOFFFEEDBACK = 0x00000080;
        public readonly static uint STARTF_PREVENTPINNING = 0x00002000;
        public readonly static uint STARTF_RUNFULLSCREEN = 0x00000020;
        public readonly static uint STARTF_TITLEISAPPID = 0x00001000;
        public readonly static uint STARTF_TITLEISLINKNAME = 0x00000800;
        public readonly static uint STARTF_UNTRUSTEDSOURCE = 0x00008000;
        public readonly static uint STARTF_USECOUNTCHARS = 0x00000008;
        public readonly static uint STARTF_USEFILLATTRIBUTE = 0x00000010;
        public readonly static uint STARTF_USEHOTKEY = 0x00000200;
        public readonly static uint STARTF_USEPOSITION = 0x00000004;
        public readonly static uint STARTF_USESHOWWINDOW = 0x00000001;
        public readonly static uint STARTF_USESIZE = 0x00000002;
        public readonly static uint STARTF_USESTDHANDLES = 0x00000100;


        public static readonly uint STATUS_SUCCESS = 0x00000000;
        public static readonly uint ERROR_SUCCESS = 0x00000000;

        public static readonly int SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public static readonly int SE_PRIVILEGE_ENABLED = 0x00000002;
        public static readonly int SE_PRIVILEGE_REMOVED = 0X00000004;

        public readonly static int E_NOINTERFACE = unchecked((int)0x80004002);
        public readonly static int NOERROR = 0;


        public readonly static int STGM_CREATE = 0x00001000;
        public readonly static int STGM_CONVERT = 0x00020000;
        public readonly static int STGM_FAILIFTHERE = 0x00000000;

        public readonly static int STGM_READ = 0x00000000;
        public readonly static int STGM_WRITE = 0x00000001;
        public readonly static int STGM_READWRITE = 0x00000002;

        public readonly static int STGM_SHARE_DENY_NONE = 0x00000040;
        public readonly static int STGM_SHARE_DENY_READ = 0x00000030;
        public readonly static int STGM_SHARE_DENY_WRITE = 0x00000020;
        public readonly static int STGM_SHARE_EXCLUSIVE = 0x00000010;


        public static readonly int NMPWAIT_WAIT_FOREVER = unchecked((int)0xffffffff);
        public static readonly int NMPWAIT_NOWAIT = 0x00000001;
        public static readonly int NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

        public static readonly int PIPE_UNLIMITED_INSTANCES = 255;

        public static readonly int PIPE_WAIT = 0x00000000;
        public static readonly int PIPE_NOWAIT = 0x00000001;
        public static readonly int PIPE_READMODE_BYTE = 0x00000000;
        public static readonly int PIPE_READMODE_MESSAGE = 0x00000002;
        public static readonly int PIPE_TYPE_BYTE = 0x00000000;
        public static readonly int PIPE_TYPE_MESSAGE = 0x00000004;
        public static readonly int PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000;
        public static readonly int PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;

        public static readonly int PIPE_ACCESS_INBOUND = 0x00000001;
        public static readonly int PIPE_ACCESS_OUTBOUND = 0x00000002;
        public static readonly int PIPE_ACCESS_DUPLEX = 0x00000003;



        public static Dictionary<Guid,IntPtr> IIDPTR = new Dictionary<Guid,IntPtr>();

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr pSecurityDescriptor;
            public bool bInheritHandle;
        }


        [StructLayout(LayoutKind.Sequential)]
        internal struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct RPC_SERVER_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr RpcProtseqEndpoint;
            public IntPtr DefaultManagerEpv;
            public IntPtr InterpreterInfo;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RPC_DISPATCH_TABLE
        {

            /// unsigned int
            public uint DispatchTableCount;

            /// RPC_DISPATCH_FUNCTION*
            public IntPtr DispatchTable;

            /// LONG_PTR->int
            public int Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIDL_SERVER_INFO
        {
            public IntPtr /* PMIDL_STUB_DESC */ pStubDesc;
            public IntPtr /* SERVER_ROUTINE* */ DispatchTable;
            public IntPtr /* PFORMAT_STRING */ ProcString;
            public IntPtr /* unsigned short* */ FmtStringOffset;
            public IntPtr /* STUB_THUNK * */ ThunkTable;
            public IntPtr /* PRPC_SYNTAX_IDENTIFIER */ pTransferSyntax;
            public IntPtr /* ULONG_PTR */ nCount;
            public IntPtr /* PMIDL_SYNTAX_INFO */ pSyntaxInfo;
        }

        void aa() { 
            
        }


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect([In] IntPtr pBlock,[In] uint size,[In] uint newProtect,[Out] out uint oldProtect);
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string StringSecurityDescriptor, uint StringSDRevision, out IntPtr SecurityDescriptor, out uint SecurityDescriptorSize);

        [DllImport("kernel32")]
        public static extern void CloseHandle(IntPtr hObject);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConnectNamedPipe(IntPtr handle, IntPtr overlapped);
        [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Unicode, EntryPoint = "CreateNamedPipeW", SetLastError = true)]
        public static extern IntPtr CreateNamedPipe(string pipeName, int openMode, int pipeMode, int maxInstances, int outBufferSize, int inBufferSize, int defaultTimeout, ref SECURITY_ATTRIBUTES securityAttributes);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
        [DllImport("ole32.dll")]
        public static extern int CoUnmarshalInterface(IStream stm, ref Guid riid, out IntPtr ppv);

        [DllImport("ole32.dll", PreserveSig = false, ExactSpelling = true)]
        public static extern int CreateBindCtx(uint reserved, out IBindCtx ppbc);

        [DllImport("ole32.dll", CharSet = CharSet.Unicode, PreserveSig = false, ExactSpelling = true)]
        public static extern int CreateObjrefMoniker(IntPtr pUnk, out IMoniker ppMoniker);
    }
}
