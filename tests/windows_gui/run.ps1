param([Parameter(Mandatory = $true)][string]$SimplewallExe)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or -not $env:RUNNER_TEMP) {
    throw 'This test runs only on a disposable GitHub-hosted Windows VM.'
}
if (-not [Environment]::UserInteractive) { throw 'No interactive Windows desktop; GUI cannot be verified.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The job must run elevated.' }
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw 'Initialize the x64 MSVC environment first.' }
if (Get-Process -Name simplewall -ErrorAction SilentlyContinue) { throw 'A simplewall process already exists.' }
$source = (Resolve-Path -LiteralPath $SimplewallExe).Path
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'A full application executable is required.' }

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class GuiNative {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint id);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder text, int length);
    [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, string s);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, StringBuilder s);
    [DllImport("user32.dll", EntryPoint="SendMessageW")] static extern IntPtr SendMessageValue(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr address, UIntPtr size, uint allocation, uint protection);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool VirtualFreeEx(IntPtr p, IntPtr address, UIntPtr size, uint freeType);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteProcessMemory(IntPtr p, IntPtr address, byte[] data, UIntPtr size, out UIntPtr written);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr p, IntPtr address, byte[] data, UIntPtr size, out UIntPtr read);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)] struct TabItem {
        public uint mask, state, stateMask;
        public IntPtr text;
        public int textMax, image;
        public IntPtr value;
    }
    static byte[] BytesOf<T>(T value) {
        int size = Marshal.SizeOf(typeof(T));
        IntPtr p = Marshal.AllocHGlobal(size);
        try { Marshal.StructureToPtr(value, p, false); byte[] bytes = new byte[size]; Marshal.Copy(p, bytes, 0, size); return bytes; }
        finally { Marshal.FreeHGlobal(p); }
    }
    static IntPtr TabProcess(IntPtr tab) {
        uint pid; GetWindowThreadProcessId(tab, out pid);
        IntPtr p = OpenProcess(0x1038, false, pid);
        if (p == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        return p;
    }
    static void WriteRemote(IntPtr p, IntPtr address, byte[] data) {
        UIntPtr written;
        if (!WriteProcessMemory(p, address, data, (UIntPtr)data.Length, out written) || written.ToUInt64() != (ulong)data.Length)
            throw new System.ComponentModel.Win32Exception();
    }
    static byte[] ReadRemote(IntPtr p, IntPtr address, int size) {
        byte[] data = new byte[size]; UIntPtr read;
        if (!ReadProcessMemory(p, address, data, (UIntPtr)size, out read) || read.ToUInt64() != (ulong)size)
            throw new System.ComponentModel.Win32Exception();
        return data;
    }
    public static string[] TabNames(IntPtr tab) {
        int count = SendMessageValue(tab, 0x1304, IntPtr.Zero, IntPtr.Zero).ToInt32();
        if (count < 1 || count > 32) throw new InvalidOperationException("Unexpected tab count: " + count);
        IntPtr p = TabProcess(tab), remote = IntPtr.Zero;
        try {
            remote = VirtualAllocEx(p, IntPtr.Zero, (UIntPtr)1024, 0x3000, 0x04);
            if (remote == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
            var names = new string[count];
            for (int i = 0; i < count; i++) {
                var item = new TabItem { mask = 1, text = IntPtr.Add(remote, 128), textMax = 256 };
                WriteRemote(p, remote, BytesOf(item));
                if (SendMessageValue(tab, 0x133c, (IntPtr)i, remote) == IntPtr.Zero)
                    throw new InvalidOperationException("Cannot read tab " + i);
                names[i] = Encoding.Unicode.GetString(ReadRemote(p, item.text, 512)).Split('\0')[0];
            }
            return names;
        } finally { if (remote != IntPtr.Zero) VirtualFreeEx(p, remote, UIntPtr.Zero, 0x8000); CloseHandle(p); }
    }
    public static void ClickTab(IntPtr tab, int index) {
        IntPtr p = TabProcess(tab), remote = IntPtr.Zero;
        try {
            remote = VirtualAllocEx(p, IntPtr.Zero, (UIntPtr)16, 0x3000, 0x04);
            if (remote == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
            if (SendMessageValue(tab, 0x130a, (IntPtr)index, remote) == IntPtr.Zero)
                throw new InvalidOperationException("Cannot read tab position");
            byte[] rect = ReadRemote(p, remote, 16);
            int x = (BitConverter.ToInt32(rect, 0) + BitConverter.ToInt32(rect, 8)) / 2;
            int y = (BitConverter.ToInt32(rect, 4) + BitConverter.ToInt32(rect, 12)) / 2;
            IntPtr point = (IntPtr)((y << 16) | (x & 0xffff));
            if (!PostMessage(tab, 0x0201, (IntPtr)1, point) || !PostMessage(tab, 0x0202, IntPtr.Zero, point))
                throw new System.ComponentModel.Win32Exception();
        } finally { if (remote != IntPtr.Zero) VirtualFreeEx(p, remote, UIntPtr.Zero, 0x8000); CloseHandle(p); }
    }
    public static IntPtr[] Windows(uint pid) {
        var list = new List<IntPtr>();
        EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p == pid && IsWindowVisible(h)) list.Add(h); return true; }, IntPtr.Zero);
        return list.ToArray();
    }
    public static IntPtr[] AllWindows(uint pid) {
        var list = new List<IntPtr>();
        EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p == pid) list.Add(h); return true; }, IntPtr.Zero);
        return list.ToArray();
    }
    public static string ClassName(IntPtr h) { var b = new StringBuilder(256); GetClassName(h, b, b.Capacity); return b.ToString(); }
    public static IntPtr Child(IntPtr parent, int id) {
        IntPtr result = IntPtr.Zero;
        EnumChildWindows(parent, (h, l) => { if (GetDlgCtrlID(h) == id) { result = h; return false; } return true; }, IntPtr.Zero);
        return result;
    }
    public static string Text(IntPtr h) { var b = new StringBuilder(2048); SendMessage(h, 0x000d, (IntPtr)b.Capacity, b); return b.ToString(); }
}
'@
$desktop = [GuiNative]::OpenInputDesktop(0, $false, 0x0100)
if ($desktop -eq [IntPtr]::Zero) { throw 'Input desktop unavailable; GUI cannot be verified.' }
[void][GuiNative]::CloseDesktop($desktop)

$runDir = Join-Path $env:RUNNER_TEMP ('simplewall-gui-' + [guid]::NewGuid().ToString('N'))
$appDir = Join-Path $runDir 'portable'
$inventory = Join-Path $runDir 'wfp_empty.exe'
$app = Join-Path $appDir 'simplewall.exe'
$profile = Join-Path $appDir 'profile.xml'
$proc = $null
$started = $false
New-Item -ItemType Directory -Path $runDir, $appDir | Out-Null
function Assert-EmptyWfp {
    & $inventory
    if ($LASTEXITCODE -ne 0) { throw 'Simplewall WFP objects found, or inventory could not be completed.' }
}
function Wait-For([scriptblock]$Condition, [string]$Description, [int]$Seconds = 20) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $value = & $Condition
        if ($value) { return $value }
        if ($proc -and $proc.HasExited) { throw "Application exited while waiting for $Description (exit $($proc.ExitCode))." }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $until)
    throw "Timed out waiting for $Description. An interactive desktop or the expected GUI may be unavailable."
}
function Window-With([int]$ControlId) {
    foreach ($h in [GuiNative]::Windows([uint32]$proc.Id)) {
        if ([GuiNative]::Child($h, $ControlId) -ne [IntPtr]::Zero) { return $h }
    }
}
function Control([IntPtr]$Window, [int]$Id) {
    $h = [GuiNative]::Child($Window, $Id)
    if ($h -eq [IntPtr]::Zero) { throw "Required control $Id not found." }
    return $h
}
function Set-Text([IntPtr]$Window, [int]$Id, [string]$Value) {
    $h = Control $Window $Id
    [void][GuiNative]::SendMessage($h, 0x000c, [IntPtr]::Zero, $Value)
    if ([GuiNative]::Text($h) -cne $Value) { throw "Control $Id did not retain its value." }
}
function Command([IntPtr]$Window, [int]$Id) {
    if (-not [GuiNative]::PostMessage($Window, 0x0111, [IntPtr]$Id, [IntPtr]::Zero)) { throw "Posting command $Id failed." }
}
function Select-AutoTab([IntPtr]$Editor) {
    $tab = Control $Editor 105
    $names = [GuiNative]::TabNames($tab)
    $index = [Array]::IndexOf($names, 'Auto match')
    if ($index -lt 0) { throw "Auto match tab is absent. Tabs: $($names -join ', ')" }
    [GuiNative]::ClickTab($tab, $index)
    $field = Control $Editor 337
    [void](Wait-For { if ([GuiNative]::IsWindowVisible($field)) { $true } } 'visible Auto match page')
}
function Open-Editor([IntPtr]$Main) {
    Command $Main 323
    return (Wait-For { Window-With 116 } 'rule editor')
}
function Save-Editor([IntPtr]$Editor) {
    Command $Editor 116
    [void](Wait-For { if (-not [GuiNative]::IsWindow($Editor)) { $true } } 'editor to close after save')
}
try {
    Push-Location $runDir
    try {
        & cl.exe /nologo /W4 /DUNICODE /D_UNICODE /Fe:wfp_empty.exe (Join-Path $PSScriptRoot 'wfp_empty.c') /link fwpuclnt.lib rpcrt4.lib
        if ($LASTEXITCODE -ne 0) { throw 'WFP inventory compilation failed.' }
    } finally { Pop-Location }
    Assert-EmptyWfp
    Copy-Item -LiteralPath $source -Destination $app
    $locale = Join-Path $PSScriptRoot '../../bin/simplewall.lng'
    if (-not (Test-Path -LiteralPath $locale -PathType Leaf)) { throw 'Built language file is missing.' }
    Copy-Item -LiteralPath $locale -Destination (Join-Path $appDir 'simplewall.lng')
    @'
[simplewall]
Language=English
ProfileType=0
CheckUpdatesPeriod=0
IsInternalRulesDisabled=true
WF_State=false
'@ | Set-Content -LiteralPath (Join-Path $appDir 'simplewall.ini') -Encoding ascii
    if (Get-Process -Name simplewall -ErrorAction SilentlyContinue) { throw 'A simplewall process appeared before startup.' }
    $proc = Start-Process -FilePath $app -WorkingDirectory $appDir -ArgumentList '-portable' -PassThru
    $started = $true
    $main = Wait-For { Window-With 111 } 'visible main window'
    Assert-EmptyWfp

    $editor = Open-Editor $main
    Set-Text $editor 210 'ci-gui-with-publisher'
    Select-AutoTab $editor
    [void](Control $editor 339)
    Set-Text $editor 341 'CI Publisher & Co'
    if ([GuiNative]::Text((Control $editor 337)) -ne '') { throw 'Filename should start empty.' }
    Command $editor 116
    try {
        $warning = Wait-For {
            if (-not [GuiNative]::IsWindow($editor)) { throw 'Editor closed without the required filename warning.' }
            foreach ($h in [GuiNative]::Windows([uint32]$proc.Id)) {
                if ($h -ne $main -and $h -ne $editor -and [GuiNative]::Child($h, 1) -ne [IntPtr]::Zero) { return $h }
            }
        } 'required filename warning'
    } catch {
        foreach ($h in [GuiNative]::AllWindows([uint32]$proc.Id)) {
            Write-Host ("GUI window: class={0}, visible={1}, title={2}, ok={3}" -f `
                [GuiNative]::ClassName($h), [GuiNative]::IsWindowVisible($h), [GuiNative]::Text($h), [GuiNative]::Child($h, 1))
        }
        if ([GuiNative]::IsWindow($editor)) {
            Write-Host ("Editor values: rule={0}, filename={1}, publisher={2}" -f `
                [GuiNative]::Text((Control $editor 210)), [GuiNative]::Text((Control $editor 337)), [GuiNative]::Text((Control $editor 341)))
        }
        throw
    }
    $root = [System.Windows.Automation.AutomationElement]::FromHandle($warning)
    $message = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty,
        'Enter an executable name before specifying a directory or publisher.')
    if (-not $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $message)) { throw 'Unexpected validation warning.' }
    Command $warning 1
    [void](Wait-For { if (-not [GuiNative]::IsWindow($warning)) { $true } } 'validation warning to close')
    if (-not [GuiNative]::IsWindow($editor)) { throw 'Editor closed despite the missing required filename.' }
    Set-Text $editor 337 'ci-gui-publisher.exe'
    Save-Editor $editor

    $editor = Open-Editor $main
    Set-Text $editor 210 'ci-gui-name-only'
    Select-AutoTab $editor
    Set-Text $editor 337 'ci-gui-name-only.exe'
    if ([GuiNative]::Text((Control $editor 341)) -ne '') { throw 'Publisher should start empty.' }
    Save-Editor $editor
    Assert-EmptyWfp
    Command $main 255
    if (-not $proc.WaitForExit(20000)) { throw 'Application did not exit cleanly.' }
    if ($proc.ExitCode -ne 0) { throw "Application exit code: $($proc.ExitCode)." }
    if (-not (Test-Path -LiteralPath $profile -PathType Leaf)) { throw 'Portable profile.xml was not written.' }
    [xml]$xml = Get-Content -LiteralPath $profile -Raw
    if ($xml.DocumentElement.Name -ne 'root' -or $xml.DocumentElement.GetAttribute('type') -ne '3') { throw 'Unexpected profile format.' }
    $with = @($xml.SelectNodes('/root/rules_auto/item') | Where-Object { $_.GetAttribute('name') -ceq 'ci-gui-with-publisher' })
    $without = @($xml.SelectNodes('/root/rules_auto/item') | Where-Object { $_.GetAttribute('name') -ceq 'ci-gui-name-only' })
    if ($with.Count -ne 1 -or $with[0].GetAttribute('auto_filename') -cne 'ci-gui-publisher.exe' -or
        $with[0].GetAttribute('auto_publisher') -cne 'CI Publisher & Co' -or
        $with[0].GetAttribute('is_block') -eq 'true' -or $with[0].GetAttribute('is_enabled') -ne 'true') { throw 'Publisher rule was not persisted correctly.' }
    if ($without.Count -ne 1 -or $without[0].GetAttribute('auto_filename') -cne 'ci-gui-name-only.exe' -or
        $without[0].GetAttribute('auto_publisher') -ne '' -or $without[0].GetAttribute('is_block') -eq 'true' -or
        $without[0].GetAttribute('is_enabled') -ne 'true') { throw 'Filename-only rule was not persisted correctly.' }
    Assert-EmptyWfp
} finally {
    if ($proc -and -not $proc.HasExited) {
        $proc.Kill()
        if (-not $proc.WaitForExit(10000)) { Write-Error 'Could not stop the test application.' }
    }
    if ($started -and (Test-Path -LiteralPath $inventory)) { Assert-EmptyWfp }
    if (Test-Path -LiteralPath $runDir) {
        $tempRoot = (Resolve-Path -LiteralPath $env:RUNNER_TEMP).ProviderPath.TrimEnd('\') + '\'
        $resolvedRunDir = (Resolve-Path -LiteralPath $runDir).ProviderPath
        if (-not $resolvedRunDir.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove a test directory outside RUNNER_TEMP.'
        }
        Remove-Item -LiteralPath $resolvedRunDir -Recurse -Force
    }
}
Write-Host 'PASS: GUI validation and both saved rules verified in the portable profile after exit.'
