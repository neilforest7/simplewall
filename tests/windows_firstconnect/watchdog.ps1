param(
    [Parameter(Mandatory)][int]$ParentId,
    [Parameter(Mandatory)][string]$RunDir,
    [Parameter(Mandatory)][string]$App,
    [Parameter(Mandatory)][string]$Inventory
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or -not $env:RUNNER_TEMP) {
    throw 'Use only a disposable GitHub-hosted Windows Actions VM.'
}
$tempRoot = (Resolve-Path -LiteralPath $env:RUNNER_TEMP).ProviderPath.TrimEnd('\') + '\'
$resolvedRun = (Resolve-Path -LiteralPath $RunDir).ProviderPath.TrimEnd('\') + '\'
$resolvedApp = (Resolve-Path -LiteralPath $App).ProviderPath
$resolvedInventory = (Resolve-Path -LiteralPath $Inventory).ProviderPath
if (-not $resolvedRun.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not $resolvedApp.StartsWith($resolvedRun, [StringComparison]::OrdinalIgnoreCase) -or
    -not $resolvedInventory.StartsWith($resolvedRun, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to clean up files outside the temporary test directory.'
}
$parent = Get-Process -Id $ParentId -ErrorAction Stop
# Open a process handle now, so a reused process ID cannot extend the deadline.
[void]$parent.Handle
Write-Output 'READY'
[Console]::Out.Flush()
if ($parent.WaitForExit(240000)) { $reason = 'parent exited before disarming watchdog' }
else { $reason = 'test exceeded watchdog deadline' }
$log = Join-Path $RunDir 'watchdog.log'
try {
    [IO.File]::AppendAllText($log, "Emergency cleanup: $reason`n")
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name = 'simplewall.exe'")) {
        if ($process.ExecutablePath -and
            [string]::Equals($process.ExecutablePath, $resolvedApp, [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
        }
    }
    $uninstall = Start-Process -FilePath $resolvedApp -WorkingDirectory (Split-Path -Parent $resolvedApp) `
        -ArgumentList '-uninstall', '-silent', '-portable' -WindowStyle Hidden -PassThru
    if (-not $uninstall.WaitForExit(30000)) {
        Stop-Process -Id $uninstall.Id -Force -ErrorAction SilentlyContinue
        throw 'Emergency uninstall timed out.'
    }
    if ($uninstall.ExitCode -ne 0) { throw "Emergency uninstall exited $($uninstall.ExitCode)." }
    & $resolvedInventory 2>&1 | Out-File -LiteralPath $log -Append -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw 'Emergency WFP cleanup could not be verified.' }
    [IO.File]::AppendAllText($log, "Emergency cleanup verified.`n")
} catch {
    [IO.File]::AppendAllText($log, "Emergency cleanup failed: $_`n")
    exit 1
}
