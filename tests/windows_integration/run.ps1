param(
    [Parameter(Mandatory = $true)][string]$SimplewallExe
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or -not $env:RUNNER_TEMP) {
    throw 'Use only a disposable GitHub-hosted Windows Actions VM.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The Windows job must run elevated.'
}
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw 'Set up x64 MSVC first.' }
if (Get-Process -Name simplewall -ErrorAction SilentlyContinue) { throw 'A simplewall process already exists.' }
$sourceExe = (Resolve-Path -LiteralPath $SimplewallExe).Path
if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) { throw 'Build the complete application first.' }

$runDir = Join-Path $env:RUNNER_TEMP ('simplewall-integration-' + [guid]::NewGuid().ToString('N'))
$appDir = Join-Path $runDir 'portable'
$inventory = Join-Path $runDir 'wfp_inventory.exe'
$dialog = Join-Path $runDir 'uninstall_dialog.exe'
$blockExe = Join-Path $runDir 'wfp_loopback_block.exe'
$app = Join-Path $appDir 'simplewall.exe'
$profile = Join-Path $appDir 'profile.xml'
$priorRoot = $env:SIMPLEWALL_INTEGRATION_ROOT
$started = $false
$cleanupFailed = $false
$blockProcess = $null
$blockKey = [guid]::NewGuid().ToString()
$blockAttempted = $false
$listener = $null
New-Item -ItemType Directory -Path $runDir, $appDir, (Join-Path $runDir 'good'),
    (Join-Path $runDir 'bad'), (Join-Path $runDir 'empty') | Out-Null
$env:SIMPLEWALL_INTEGRATION_ROOT = $runDir

function Assert-Rule([string]$Name, [string]$ExpectedPath) {
    Write-Host "Checking $Name"
    & $inventory rule $Name $ExpectedPath
    if ($LASTEXITCODE -ne 0) { throw "WFP assertion failed for $Name." }
}
function Assert-Connectivity {
    Invoke-WebRequest -Uri 'https://github.com/' -Method Head -TimeoutSec 15 | Out-Null
    Write-Host 'Anonymous HTTPS connectivity to github.com is available.'
}
function Assert-Tcp([string]$Path, [bool]$ShouldConnect) {
    if ($listener.Pending()) { throw 'Unexpected connection remained in listener backlog.' }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Path
    $info.Arguments = [string]$port
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $client = [Diagnostics.Process]::Start($info)
    try {
        if (-not $client.WaitForExit(8000)) { $client.Kill(); throw "TCP client timed out: $Path" }
        $stdout = $client.StandardOutput.ReadToEnd().Trim()
        $stderr = $client.StandardError.ReadToEnd().Trim()
        Write-Host "TCP $([IO.Path]::GetFileName($Path)) expected=$ShouldConnect exit=$($client.ExitCode) $stdout $stderr"
        $expected = if ($ShouldConnect) { 0 } else { 13 }
        if ($client.ExitCode -ne $expected) { throw "TCP result did not match expectation: $Path" }
        if ($ShouldConnect) {
            $deadline = [DateTime]::UtcNow.AddSeconds(3)
            while (-not $listener.Pending() -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
            if (-not $listener.Pending()) { throw 'TCP client reported success without a listener connection.' }
            $accepted = $listener.AcceptTcpClient()
            $accepted.Dispose()
        } elseif ($listener.Pending()) { throw 'Blocked TCP client reached the listener.' }
    } finally { $client.Dispose() }
}
function Start-Block {
    & $inventory gone-key $blockKey
    if ($LASTEXITCODE -ne 0) { throw 'Test filter key is not available.' }
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $blockExe
    $info.Arguments = "$port $blockKey"
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $script:blockAttempted = $true
    $script:blockProcess = [Diagnostics.Process]::Start($info)
    $ready = $blockProcess.StandardOutput.ReadLineAsync()
    if (-not $ready.Wait(15000)) { throw 'Timed out adding the WFP loopback block.' }
    $line = $ready.Result
    if ($line -notmatch '^READY ([0-9]+)$') {
        if ($blockProcess.WaitForExit(2000)) { Write-Host $blockProcess.StandardError.ReadToEnd() }
        throw "Could not add the WFP loopback block: $line"
    }
    $id = $Matches[1]
    Write-Host "Dynamic block filter id=$id port=$port"
    & $inventory block $id ([string]$port)
    if ($LASTEXITCODE -ne 0) { throw 'Dynamic block has unexpected WFP conditions.' }
}
function Stop-Block {
    if (-not $blockAttempted) { return }
    $sessionFailure = $false
    if ($blockProcess) {
        if (-not $blockProcess.HasExited) {
            try { $blockProcess.StandardInput.Close() } catch { $sessionFailure = $true; Write-Warning "Could not close block helper stdin: $_" }
            if (-not $blockProcess.WaitForExit(5000)) {
                $sessionFailure = $true
                $blockProcess.Kill()
                if (-not $blockProcess.WaitForExit(5000)) { throw 'Dynamic session helper did not terminate.' }
            }
        }
        Write-Host "Dynamic session exit=$($blockProcess.ExitCode) $($blockProcess.StandardError.ReadToEnd())"
        if ($blockProcess.ExitCode -ne 0) { $sessionFailure = $true }
        $blockProcess.Dispose()
        $script:blockProcess = $null
    }
    $gone = $false
    for ($i = 0; $i -lt 20; $i++) {
        & $inventory gone-key $blockKey
        if ($LASTEXITCODE -eq 0) { $gone = $true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $gone) { throw 'Dynamic WFP filter removal could not be confirmed.' }
    $script:blockAttempted = $false
    if ($sessionFailure) { throw 'Dynamic session helper failed; filter removal was confirmed.' }
}
function Write-Profile([string]$State) {
    $directory = [Security.SecurityElement]::Escape((Join-Path $runDir 'good'))
    $emptyDirectory = [Security.SecurityElement]::Escape((Join-Path $runDir 'empty'))
    $enabled = if ($State -eq 'disabled') { 'false' } else { 'true' }
    $match = if ($State -eq 'deleted') { '' } else {
        "<item name=`"ci_match`" rule=`"127.0.0.1`" protocol=`"6`" version=`"2`" dir=`"0`" auto_filename=`"probe.exe`" auto_directory=`"$directory`" is_enabled=`"$enabled`"/>"
    }
    # Path expansion is exercised by the actual application, not by this script.
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<root type="3" version="6" timestamp="1">
 <apps>
  <item path="%SIMPLEWALL_INTEGRATION_ROOT%\good\probe.exe"/>
  <item path="%SIMPLEWALL_INTEGRATION_ROOT%\bad\probe.exe"/>
  <item path="%SIMPLEWALL_INTEGRATION_ROOT%\good\name-only.exe"/>
  <item path="%SIMPLEWALL_INTEGRATION_ROOT%\good\unmatched.exe"/>
 </apps>
 <rules_config/>
 <rules_custom/>
 <rules_auto>
  $match
  <item name="ci_name" rule="127.0.0.1" protocol="6" version="2" dir="0" auto_filename="name-only.exe" is_enabled="true"/>
  <item name="ci_wrong_dir" rule="127.0.0.1" protocol="6" version="2" dir="0" auto_filename="probe.exe" auto_directory="$emptyDirectory" is_enabled="true"/>
  <item name="ci_missing" rule="127.0.0.1" protocol="6" version="2" dir="0" auto_filename="missing.exe" is_enabled="true"/>
 </rules_auto>
</root>
"@
    [IO.File]::WriteAllText($profile, $xml, [Text.UTF8Encoding]::new($false))
}
function Install-Profile {
    $script:started = $true
    $process = Start-Process -FilePath $app -WorkingDirectory $appDir -PassThru `
        -ArgumentList '-install', '-temp', '-silent', '-portable'
    if (-not $process.WaitForExit(30000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'simplewall install/rebuild timed out.'
    }
    # The command-line path exits through application initialization. WFP state,
    # not its process status, is the assertion of successful application.
    Write-Host "simplewall install exit code: $($process.ExitCode)"
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 575) {
        throw 'simplewall terminated unexpectedly during install.'
    }
    Assert-Connectivity
}

try {
    Push-Location $runDir
    try {
        & cl.exe /nologo /W4 /DUNICODE /D_UNICODE /Fe:wfp_inventory.exe `
            (Join-Path $PSScriptRoot 'wfp_inventory.c') /link fwpuclnt.lib rpcrt4.lib
        if ($LASTEXITCODE -ne 0) { throw 'WFP inventory compilation failed.' }
        & cl.exe /nologo /W4 /DUNICODE /D_UNICODE /Fe:uninstall_dialog.exe `
            (Join-Path $PSScriptRoot 'uninstall_dialog.c') /link user32.lib
        if ($LASTEXITCODE -ne 0) { throw 'Uninstall dialog helper compilation failed.' }
        & cl.exe /nologo /W4 /DUNICODE /D_UNICODE /Fe:wfp_loopback_block.exe `
            (Join-Path $PSScriptRoot 'wfp_loopback_block.c') /link fwpuclnt.lib rpcrt4.lib
        if ($LASTEXITCODE -ne 0) { throw 'WFP loopback helper compilation failed.' }
        & cl.exe /nologo /W4 /Fe:tcp_client.exe `
            (Join-Path $PSScriptRoot 'tcp_client.c') /link ws2_32.lib
        if ($LASTEXITCODE -ne 0) { throw 'TCP fixture compilation failed.' }
    } finally { Pop-Location }

    & $inventory empty
    if ($LASTEXITCODE -ne 0) { throw 'Pre-existing simplewall WFP objects or inventory error.' }
    Assert-Connectivity
    Copy-Item -LiteralPath $sourceExe -Destination $app
    $fixture = Join-Path $runDir 'tcp_client.exe'
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $runDir 'good\probe.exe')
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $runDir 'bad\probe.exe')
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $runDir 'good\name-only.exe')
    Copy-Item -LiteralPath $fixture -Destination (Join-Path $runDir 'good\unmatched.exe')
    @'
[simplewall]
BlockOutboundConnections=false
BlockInboundConnections=false
UseStealthMode=false
InstallBoottimeFilters=false
AllowLoopbackConnections=false
AllowIPv6=false
IsInternalRulesDisabled=true
WF_State=false
'@ | Set-Content -LiteralPath (Join-Path $appDir 'simplewall.ini') -Encoding ascii

    Write-Profile 'enabled'
    Install-Profile
    Assert-Rule 'ci_match' (Join-Path $runDir 'good\probe.exe')
    Assert-Rule 'ci_name' (Join-Path $runDir 'good\name-only.exe')
    Assert-Rule 'ci_wrong_dir' '-'
    Assert-Rule 'ci_missing' '-'
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Server.ExclusiveAddressUse = $true
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $matching = Join-Path $runDir 'good\probe.exe'
    $wrongDir = Join-Path $runDir 'bad\probe.exe'
    $unmatched = Join-Path $runDir 'good\unmatched.exe'
    Assert-Tcp $matching $true
    Assert-Tcp $wrongDir $true
    Assert-Tcp $unmatched $true
    Start-Block
    Assert-Tcp $matching $true
    Assert-Tcp $wrongDir $false
    Assert-Tcp $unmatched $false

    Write-Profile 'disabled'
    Install-Profile
    Assert-Rule 'ci_match' '-'
    Assert-Rule 'ci_name' (Join-Path $runDir 'good\name-only.exe')
    Assert-Tcp $matching $false

    Write-Profile 'enabled'
    Install-Profile
    Assert-Rule 'ci_match' (Join-Path $runDir 'good\probe.exe')
    Assert-Tcp $matching $true
    Write-Profile 'deleted'
    Install-Profile
    Assert-Rule 'ci_match' '-'
    Assert-Rule 'ci_name' (Join-Path $runDir 'good\name-only.exe')
    Assert-Tcp $matching $false
    Stop-Block
    Assert-Tcp $matching $true
    Assert-Tcp $wrongDir $true
    Assert-Tcp $unmatched $true
    Write-Host 'WFP integration assertions passed.'
} finally {
    if ($blockAttempted) {
        try { Stop-Block } catch { $cleanupFailed = $true; Write-Warning "Dynamic filter cleanup failed: $_" }
    }
    if ($listener) { $listener.Stop() }
    if ($started) {
        Write-Host 'Checking and removing temporary simplewall objects.'
        try {
            & $inventory empty
            $inventoryCode = $LASTEXITCODE
            if ($inventoryCode -eq 2) {
                $uninstall = Start-Process -FilePath $app -WorkingDirectory $appDir -PassThru `
                    -ArgumentList '-uninstall', '-portable'
                & $dialog $uninstall.Id
                $dialogCode = $LASTEXITCODE
                if (-not $uninstall.WaitForExit(20000)) {
                    Stop-Process -Id $uninstall.Id -Force -ErrorAction SilentlyContinue
                    throw 'Uninstall timed out.'
                }
                Write-Host "Uninstall dialog result=$dialogCode process exit=$($uninstall.ExitCode)"
                if ($dialogCode -ne 0) { throw 'Uninstall dialog was not confirmed.' }
            } elseif ($inventoryCode -ne 0) { throw 'Cannot enumerate WFP before cleanup.' }
            & $inventory empty
            if ($LASTEXITCODE -ne 0) { throw 'Cleanup did not remove all simplewall WFP objects.' }
            Write-Host 'WFP cleanup confirmed.'
        } catch {
            $cleanupFailed = $true
            Write-Warning "Cleanup failed: $_"
        }
    }
    $env:SIMPLEWALL_INTEGRATION_ROOT = $priorRoot
    if (-not $cleanupFailed) { Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction Continue }
    else { Write-Warning "Synthetic test files retained: $runDir" }
    if ($cleanupFailed) { throw 'WFP cleanup could not be confirmed.' }
}
