param([Parameter(Mandatory = $true)][string]$SimplewallExe)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or -not $env:RUNNER_TEMP) {
    throw 'Use only a disposable GitHub-hosted Windows Actions VM.'
}
if (-not [Environment]::UserInteractive) { throw 'An interactive Windows desktop is required.' }
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'The job must run elevated.' }
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw 'Initialize the x64 MSVC environment first.' }
if (Get-Process -Name simplewall -ErrorAction SilentlyContinue) { throw 'A simplewall process already exists.' }
$source = (Resolve-Path -LiteralPath $SimplewallExe).Path
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'A full application executable is required.' }
$language = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../../bin/simplewall.lng')).Path

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class FirstConnectWindows {
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint id);
    [DllImport("user32.dll")] static extern int GetDlgCtrlID(IntPtr h);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder text, int length);
    [DllImport("user32.dll", EntryPoint="SendMessageTimeoutW")] static extern IntPtr SendMessageTimeout(IntPtr h, uint msg, IntPtr w, IntPtr l, uint flags, uint timeout, out UIntPtr result);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr h);
    public static IntPtr[] Windows(uint pid) {
        var result = new List<IntPtr>();
        EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p == pid && IsWindowVisible(h)) result.Add(h); return true; }, IntPtr.Zero);
        return result.ToArray();
    }
    public static IntPtr Child(IntPtr parent, int id) {
        IntPtr result = IntPtr.Zero;
        EnumChildWindows(parent, (h, l) => { if (GetDlgCtrlID(h) == id) { result = h; return false; } return true; }, IntPtr.Zero);
        return result;
    }
    public static bool ToolbarReady(IntPtr toolbar) {
        UIntPtr result;
        return SendMessageTimeout(toolbar, 0x0409, (IntPtr)305, IntPtr.Zero, 0x0002, 1000, out result) != IntPtr.Zero && result.ToUInt64() != 0;
    }
    public static string Title(IntPtr h) { var text = new StringBuilder(1024); GetWindowText(h, text, text.Capacity); return text.ToString(); }
}
'@
$desktop = [FirstConnectWindows]::OpenInputDesktop(0, $false, 0x0100)
if ($desktop -eq [IntPtr]::Zero) { throw 'Input desktop unavailable; GUI cannot be verified.' }
[void][FirstConnectWindows]::CloseDesktop($desktop)

$runDir = Join-Path $env:RUNNER_TEMP ('simplewall-firstconnect-' + [guid]::NewGuid().ToString('N'))
$appDir = Join-Path $runDir 'portable'
$goodDir = Join-Path $runDir 'matching'
$badDir = Join-Path $runDir 'other'
$app = Join-Path $appDir 'simplewall.exe'
$profile = Join-Path $appDir 'profile.xml'
$probe = Join-Path $runDir 'wfp_probe.exe'
$inventory = Join-Path $runDir 'wfp_empty.exe'
$client = Join-Path $goodDir 'first-connect-client.exe'
$otherClient = Join-Path $badDir 'first-connect-client.exe'
$gui = $null
$watcher = $null
$watchdog = $null
$listener = $null
$ownsWfp = $false
$cleanupFailed = $false
New-Item -ItemType Directory -Path $runDir, $appDir, $goodDir, $badDir | Out-Null

function Start-Captured([string]$File, [string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($arg in $Arguments) { [void]$info.ArgumentList.Add($arg) }
    return [Diagnostics.Process]::Start($info)
}
function Wait-Ready($Process, [string]$Name) {
    $line = $Process.StandardOutput.ReadLineAsync()
    if (-not $line.Wait(15000) -or $line.Result -ne 'READY') {
        if ($Process.HasExited) { Write-Host $Process.StandardError.ReadToEnd() }
        throw "$Name could not start or did not become ready."
    }
}
function Wait-Gui([int]$Seconds = 45) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $gui.Refresh()
        if ($gui.HasExited) { throw "The GUI exited unexpectedly: $($gui.ExitCode)." }
        foreach ($window in [FirstConnectWindows]::Windows([uint32]$gui.Id)) {
            if ([FirstConnectWindows]::Child($window, 111) -ne [IntPtr]::Zero) { return $window }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    foreach ($window in [FirstConnectWindows]::Windows([uint32]$gui.Id)) {
        Write-Host "Visible application window: $([FirstConnectWindows]::Title($window))"
        try {
            $root = [System.Windows.Automation.AutomationElement]::FromHandle($window)
            $elements = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
            foreach ($element in $elements) { if ($element.Current.Name) { Write-Host "Application message: $($element.Current.Name)" } }
        } catch { Write-Warning "Could not read application error text: $_" }
    }
    throw 'Timed out waiting for the main GUI; inspect the displayed error, including internal profile load failures.'
}
function Wait-Toolbar([IntPtr]$Main) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $gui.Refresh()
        if ($gui.HasExited) { throw 'The GUI exited during filter installation.' }
        $toolbar = [FirstConnectWindows]::Child($Main, 103)
        if ($toolbar -ne [IntPtr]::Zero -and [FirstConnectWindows]::ToolbarReady($toolbar)) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The GUI did not finish applying filters.'
}
function Wait-LoadedProfile {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        try { [xml]$saved = [IO.File]::ReadAllText($profile) } catch { $saved = $null }
        if ($saved -and $saved.DocumentElement.GetAttribute('timestamp') -ne '1') {
            $rules = @($saved.SelectNodes('/root/rules_auto/item') | Where-Object { $_.GetAttribute('name') -ceq 'ci-first-connect' })
            if ($rules.Count -ne 1 -or $rules[0].GetAttribute('auto_filename') -cne 'first-connect-client.exe' -or
                -not [string]::Equals($rules[0].GetAttribute('auto_directory'), $goodDir, [StringComparison]::OrdinalIgnoreCase) -or
                $rules[0].GetAttribute('is_enabled') -ne 'true') { throw 'The GUI did not load and save the automatic selector.' }
            foreach ($item in @($saved.SelectNodes('/root/apps/item'))) {
                $path = [Environment]::ExpandEnvironmentVariables($item.GetAttribute('path'))
                if ([string]::Equals($path, $client, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'The test client was already known before its first connection.'
                }
            }
            Write-Host 'GUI saved the selector; the client is not yet in its application list.'
            return
        }
        $gui.Refresh()
        if ($gui.HasExited) { throw 'The GUI exited before saving its profile.' }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out waiting for the GUI to save its loaded profile.'
}
function Wait-Snapshot([string]$Mode, [UInt64]$OldId, [int]$Seconds = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $output = @(& $probe $Mode $client ([string]$port) ([string]$OldId) 'ci-first-connect' 2>&1)
        $code = $LASTEXITCODE
        if ($code -eq 0) { $output | ForEach-Object { Write-Host $_ }; return ($output -join "`n") }
        if ($code -ne 2) { throw "Invalid WFP snapshot ($code): $($output -join ' ')" }
        if ($gui) { $gui.Refresh(); if ($gui.HasExited) { throw 'The GUI exited while waiting for WFP.' } }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for WFP $Mode state: $($output -join ' ')"
}
function Assert-Tcp([string]$Path, [bool]$ShouldConnect) {
    if ($listener.Pending()) { throw 'Unexpected connection left in listener backlog.' }
    $process = Start-Captured $Path @([string]$port)
    try {
        if (-not $process.WaitForExit(8000)) { $process.Kill(); [void]$process.WaitForExit(5000); throw 'TCP client timed out.' }
        $out = $process.StandardOutput.ReadToEnd().Trim()
        $err = $process.StandardError.ReadToEnd().Trim()
        Write-Host "TCP $Path expected=$ShouldConnect exit=$($process.ExitCode) $out $err"
        $expected = if ($ShouldConnect) { 0 } else { 13 }
        if ($process.ExitCode -ne $expected) { throw 'TCP result did not match the expected connect or WSAEACCES.' }
        if ($ShouldConnect) {
            $until = [DateTime]::UtcNow.AddSeconds(3)
            while (-not $listener.Pending() -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 50 }
            if (-not $listener.Pending()) { throw 'Client reported success but the listener did not receive it.' }
            $accepted = $listener.AcceptTcpClient()
            $accepted.Dispose()
        } elseif ($listener.Pending()) { throw 'The blocked TCP client reached the listener.' }
    } finally { $process.Dispose() }
}

try {
    Push-Location $runDir
    try {
        & cl.exe /nologo /W4 /WX /DUNICODE /D_UNICODE /Fe:wfp_probe.exe (Join-Path $PSScriptRoot 'wfp_probe.c') /link fwpuclnt.lib rpcrt4.lib
        if ($LASTEXITCODE -ne 0) { throw 'WFP probe compilation failed.' }
        & cl.exe /nologo /W4 /WX /DUNICODE /D_UNICODE /Fe:wfp_empty.exe (Join-Path $PSScriptRoot '../windows_gui/wfp_empty.c') /link fwpuclnt.lib rpcrt4.lib
        if ($LASTEXITCODE -ne 0) { throw 'WFP cleanup inventory compilation failed.' }
        & cl.exe /nologo /W4 /WX /Fe:tcp_client.exe (Join-Path $PSScriptRoot '../windows_integration/tcp_client.c') /link ws2_32.lib
        if ($LASTEXITCODE -ne 0) { throw 'TCP client compilation failed.' }
    } finally { Pop-Location }
    & $inventory
    if ($LASTEXITCODE -ne 0) { throw 'Pre-existing simplewall WFP objects or an inventory error.' }
    Copy-Item -LiteralPath $source -Destination $app
    Copy-Item -LiteralPath $language -Destination (Join-Path $appDir 'simplewall.lng')
    Copy-Item -LiteralPath (Join-Path $runDir 'tcp_client.exe') -Destination $client
    Copy-Item -LiteralPath (Join-Path $runDir 'tcp_client.exe') -Destination $otherClient
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Server.ExclusiveAddressUse = $true
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    # Confirm the endpoint before installing filters without running either client identity.
    $baseline = [Net.Sockets.TcpClient]::new()
    try { $baseline.Connect([Net.IPAddress]::Loopback, $port); $accepted = $listener.AcceptTcpClient(); $accepted.Dispose() }
    finally { $baseline.Dispose() }

    # Preserve the Actions worker connection while default outbound blocking is active.
    $runnerProcesses = @(Get-Process | Where-Object { $_.ProcessName -match '^Runner\.(Listener|Worker)$' })
    if (-not ($runnerProcesses | Where-Object { $_.ProcessName -eq 'Runner.Worker' })) {
        throw 'GitHub Actions worker process was not found; cannot preserve job connectivity.'
    }
    $allowPaths = @($runnerProcesses | ForEach-Object { $_.Path }) + @((Get-Process -Id $PID).Path, $env:ComSpec)
    if (@($allowPaths | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) { throw 'A runner executable path was unavailable.' }
    $appEntries = ($allowPaths | Select-Object -Unique | ForEach-Object {
        if ([string]::Equals($_, $client, [StringComparison]::OrdinalIgnoreCase)) { throw 'Client was unexpectedly pre-authorized.' }
        '<item path="{0}" is_enabled="true"/>' -f [Security.SecurityElement]::Escape($_)
    }) -join "`n"
    $directory = [Security.SecurityElement]::Escape($goodDir)
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<root type="3" version="6" timestamp="1">
 <apps>$appEntries</apps>
 <rules_config/>
 <rules_custom/>
 <rules_auto><item name="ci-first-connect" rule="$port" protocol="6" version="2" dir="0" auto_filename="first-connect-client.exe" auto_directory="$directory" is_enabled="true"/></rules_auto>
</root>
"@
    [IO.File]::WriteAllText($profile, $xml, [Text.UTF8Encoding]::new($false))
    @'
[simplewall]
Language=English
ProfileType=0
CheckUpdatesPeriod=0
BlockOutboundConnections=true
BlockInboundConnections=false
UseStealthMode=false
InstallBoottimeFilters=false
AllowLoopbackConnections=false
IsInternalRulesDisabled=false
IsNotificationsEnabled=false
IsEnableAppMonitor=false
IsWUFixEnabled=false
IsBackupProfile=false
WF_State=false
'@ | Set-Content -LiteralPath (Join-Path $appDir 'simplewall.ini') -Encoding ascii

    $pwsh = (Get-Process -Id $PID).Path
    $watchdog = Start-Captured $pwsh @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'watchdog.ps1'),
        '-ParentId', [string]$PID, '-RunDir', $runDir, '-App', $app, '-Inventory', $inventory)
    Wait-Ready $watchdog 'Cleanup watchdog'
    $watchdog.Refresh()
    if ($watchdog.HasExited) { throw 'Cleanup watchdog exited before installation.' }
    if (Get-Process -Name simplewall -ErrorAction SilentlyContinue) { throw 'A simplewall process appeared before installation.' }
    & $inventory
    if ($LASTEXITCODE -ne 0) { throw 'Simplewall WFP objects appeared before installation.' }
    $ownsWfp = $true
    $install = Start-Process -FilePath $app -WorkingDirectory $appDir -WindowStyle Hidden -PassThru `
        -ArgumentList '-install', '-temp', '-silent', '-portable'
    if (-not $install.WaitForExit(45000)) {
        Stop-Process -Id $install.Id -Force -ErrorAction SilentlyContinue
        throw 'Temporary installation timed out.'
    }
    if ($install.ExitCode -ne 0) { throw "Temporary installation exited $($install.ExitCode)." }
    $initial = Wait-Snapshot 'before' 0
    $oldId = [UInt64]([regex]::Match($initial, 'default=(\d+)').Groups[1].Value)
    $gui = Start-Process -FilePath $app -WorkingDirectory $appDir -ArgumentList '-portable' -PassThru
    $main = Wait-Gui
    Wait-Toolbar $main
    # A new default ID proves the GUI actually rebuilt filters after loading its profile.
    [void](Wait-Snapshot 'before' $oldId)
    Wait-Toolbar $main
    Wait-LoadedProfile
    Start-Sleep -Seconds 1
    $watcher = Start-Captured $probe @('watch', $client, [string]$port)
    Wait-Ready $watcher 'WFP event subscriber'
    Assert-Tcp $client $false
    if (-not $watcher.WaitForExit(25000)) { $watcher.Kill(); throw 'WFP event subscriber timed out.' }
    Write-Host $watcher.StandardOutput.ReadToEnd().Trim()
    if ($watcher.ExitCode -ne 0) { throw "First failure was not verified as a simplewall default-block event: $($watcher.StandardError.ReadToEnd())" }
    $watcher.Dispose()
    $watcher = $null
    [void](Wait-Snapshot 'after' $oldId)
    Assert-Tcp $client $true
    Assert-Tcp $otherClient $false
    [void](Wait-Snapshot 'after' $oldId)
    $gui.Refresh()
    if ($gui.HasExited) { throw 'The GUI exited before the end of the test.' }
    $watchdog.Refresh()
    if ($watchdog.HasExited) { throw 'Cleanup watchdog exited during the test.' }
} finally {
    if ($watcher) {
        try { if (-not $watcher.HasExited) { $watcher.Kill(); [void]$watcher.WaitForExit(5000) }; $watcher.Dispose() }
        catch { $cleanupFailed = $true; Write-Warning "Event subscriber cleanup failed: $_" }
    }
    if ($gui) {
        try {
            $gui.Refresh()
            if (-not $gui.HasExited) {
                if ($main) { [void][FirstConnectWindows]::PostMessage($main, 0x0111, [IntPtr]255, [IntPtr]::Zero) }
                if (-not $gui.WaitForExit(15000)) { $gui.Kill(); if (-not $gui.WaitForExit(10000)) { throw 'GUI did not terminate.' } }
            }
        } catch { $cleanupFailed = $true; Write-Warning "GUI cleanup failed: $_" }
    }
    if ($ownsWfp) {
        try {
            $uninstall = Start-Process -FilePath $app -WorkingDirectory $appDir -WindowStyle Hidden -PassThru `
                -ArgumentList '-uninstall', '-silent', '-portable'
            if (-not $uninstall.WaitForExit(30000)) {
                Stop-Process -Id $uninstall.Id -Force -ErrorAction SilentlyContinue
                throw 'Silent uninstall timed out.'
            }
            if ($uninstall.ExitCode -ne 0) { throw "Silent uninstall exited $($uninstall.ExitCode)." }
        } catch { $cleanupFailed = $true; Write-Warning "Simplewall uninstall failed: $_" }
        try {
            & $inventory
            if ($LASTEXITCODE -ne 0) { throw 'Simplewall WFP objects remain, or inventory failed.' }
            while ($listener.Pending()) { $accepted = $listener.AcceptTcpClient(); $accepted.Dispose() }
            Assert-Tcp $client $true
            Write-Host 'WFP cleanup confirmed.'
        } catch { $cleanupFailed = $true; Write-Warning "WFP cleanup verification failed: $_" }
    }
    if ($listener) { try { $listener.Stop() } catch { $cleanupFailed = $true; Write-Warning "Listener cleanup failed: $_" } }
    if ($watchdog -and -not $cleanupFailed) {
        try { if (-not $watchdog.HasExited) { $watchdog.Kill(); [void]$watchdog.WaitForExit(5000) }; $watchdog.Dispose() }
        catch { $cleanupFailed = $true; Write-Warning "Watchdog disarm failed: $_" }
    }
    if (-not $cleanupFailed -and (Test-Path -LiteralPath $runDir)) {
        $tempRoot = (Resolve-Path -LiteralPath $env:RUNNER_TEMP).ProviderPath.TrimEnd('\') + '\'
        $resolvedRun = (Resolve-Path -LiteralPath $runDir).ProviderPath
        if (-not $resolvedRun.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to remove a directory outside RUNNER_TEMP.' }
        Remove-Item -LiteralPath $resolvedRun -Recurse -Force
    }
    if ($cleanupFailed) { throw "Cleanup failed; watchdog remains active and diagnostics are retained in $runDir." }
}
Write-Host 'PASS: embedded DNS rule, first default block, app-scoped allow, retry, directory isolation, and cleanup verified.'
