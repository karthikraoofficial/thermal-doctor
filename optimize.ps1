#Requires -Version 5.1
<#
.SYNOPSIS
    Previews or applies the heat-reduction actions listed in optimize-targets.json.
.DESCRIPTION
    Preview is the default and changes nothing. -Apply asks for a typed "yes" per action,
    logs each outcome to .\logs\actions.log and writes .\undo.ps1.
.PARAMETER Apply
    Perform confirmed actions. Requires Administrator rights.
.PARAMETER WhatIf
    Preview only. This is also the default.
.PARAMETER TargetsPath
    Local targets file. Defaults to optimize-targets.json beside this script.
#>
[CmdletBinding()]
param(
    [switch] $Apply,
    [switch] $WhatIf,
    [string] $TargetsPath = (Join-Path $PSScriptRoot 'optimize-targets.json')
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\Optimize.psm1') -Force

if ($Apply -and $WhatIf) { throw 'Use either -Apply or -WhatIf, not both.' }
if (-not (Test-Path -LiteralPath $TargetsPath)) {
    throw "Targets file not found: $TargetsPath. Copy optimize-targets.example.json to optimize-targets.json and edit it."
}
if ($Apply) {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '-Apply requires an elevated PowerShell. Nothing was changed.'
    }
}

$targets = Get-Content -LiteralPath $TargetsPath -Raw | ConvertFrom-Json
$now = Get-Date

function Read-PowerState {
    $scheme = (& powercfg /getactivescheme | Out-String)
    $guid = if ($scheme -match '([0-9a-fA-F-]{36})') { $Matches[1] } else { $null }
    $query = (& powercfg /query SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX | Out-String)
    $indexes = [regex]::Matches($query, ':\s*0x([0-9a-fA-F]{8})\s*(\r?\n|$)')
    $ac = $null; $dc = $null
    if ($guid -and $indexes.Count -ge 2) {
        $ac = [Convert]::ToInt32($indexes[$indexes.Count - 2].Groups[1].Value, 16)
        $dc = [Convert]::ToInt32($indexes[$indexes.Count - 1].Groups[1].Value, 16)
    }
    return [pscustomobject]@{ SchemeGuid = $guid; AcValue = $ac; DcValue = $dc }
}

function Get-RegistryValueNames($Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    return @((Get-Item -LiteralPath $Path).GetValueNames())
}

function Read-ApprovedHex($Key, $Name) {
    if (-not (Test-Path -LiteralPath $Key)) { return $null }
    $bytes = (Get-Item -LiteralPath $Key).GetValue($Name, $null)
    if ($null -eq $bytes) { return $null }
    return (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Read-RunValues {
    foreach ($target in @($targets.runRemovals)) {
        $found = (Get-RegistryValueNames $target.key) -contains $target.name
        $value = ''; $kind = 'String'
        if ($found) {
            $key = Get-Item -LiteralPath $target.key
            $value = [string]$key.GetValue($target.name, '', 'DoNotExpandEnvironmentNames')
            $kind = [string]$key.GetValueKind($target.name)
        }
        [pscustomobject]@{ Label = $target.label; Key = $target.key; Name = $target.name; Found = $found; Value = $value; ValueKind = $kind }
    }
}

function Read-StartupItems {
    foreach ($target in @($targets.startup)) {
        $name = $target.name; $command = ''; $found = $false
        if ($target.PSObject.Properties.Name -contains 'folder') {
            $folder = [Environment]::ExpandEnvironmentVariables($target.folder)
            $file = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $target.name } | Select-Object -First 1)
            if ($file.Count -gt 0) { $found = $true; $name = $file[0].Name; $command = $file[0].FullName }
        }
        else {
            $match = @(Get-RegistryValueNames $target.key | Where-Object { $_ -like $target.name } | Select-Object -First 1)
            if ($match.Count -gt 0) {
                $found = $true; $name = $match[0]
                $command = [string](Get-Item -LiteralPath $target.key).GetValue($name, '', 'DoNotExpandEnvironmentNames')
            }
        }
        $ask = ($target.PSObject.Properties.Name -contains 'ask') -and [bool]$target.ask
        [pscustomobject]@{ Label = $target.label; Name = $name; ApprovedKey = $target.approvedKey; Found = $found; Command = $command; ApprovedHex = (Read-ApprovedHex $target.approvedKey $name); Ask = $ask }
    }
}

function Read-Tasks {
    $all = @(Get-ScheduledTask)
    foreach ($target in @($targets.tasks)) {
        $matched = @($all | Where-Object { $_.TaskPath -eq $target.path -and $_.TaskName -like $target.name })
        if ($matched.Count -eq 0) {
            [pscustomobject]@{ Label = $target.label; TaskPath = $target.path; TaskName = $target.name; Found = $false; Enabled = $false; Command = '' }
            continue
        }
        foreach ($task in $matched) {
            $command = (@($task.Actions) | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
            [pscustomobject]@{ Label = $target.label; TaskPath = $task.TaskPath; TaskName = $task.TaskName; Found = $true; Enabled = ($task.State -ne 'Disabled'); Command = $command }
        }
    }
}

$wslPath = Join-Path $env:USERPROFILE '.wslconfig'
$wslExists = Test-Path -LiteralPath $wslPath
$state = [pscustomobject]@{
    Power     = Read-PowerState
    Wsl       = [pscustomobject]@{ Path = $wslPath; Exists = $wslExists; Content = $(if ($wslExists) { [IO.File]::ReadAllText($wslPath) } else { '' }) }
    RunValues = @(Read-RunValues)
    Startup   = @(Read-StartupItems)
    Tasks     = @(Read-Tasks)
}
$settings = [pscustomobject]@{
    MaxProcessorPercent = [int]$targets.power.maxProcessorPercent
    WslProcessors       = [int]$targets.wsl.processors
    WslMemory           = [string]$targets.wsl.memory
    Protected           = @($targets.protected)
}
$plan = @(New-OptimizePlan -State $state -Settings $settings -Now $now)

$mode = if ($Apply) { 'APPLY' } else { 'WHATIF: nothing will be changed' }
Write-Output "Thermal Doctor optimizer ($mode)"
$plan | Select-Object Status, Label, Action, @{ n = 'Current state'; e = { $_.Current } }, @{ n = 'New state'; e = { $_.New } }, @{ n = 'How to undo'; e = { $_.UndoText } } |
    Format-Table -AutoSize | Out-String -Width 240 | Write-Output

$installed = @(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        ForEach-Object { if ($_.PSObject.Properties.Name -contains 'DisplayName') { $_.DisplayName } })
Write-Output 'Uninstall list (print only, never run):'
foreach ($app in @($targets.uninstall)) {
    $note = if ($installed -contains $app.displayName) { '' } else { ' (not found)' }
    Write-Output "  $($app.label): Settings > Apps > Installed apps > search '$($app.displayName)' > ... > Uninstall$note"
}

if (-not $Apply) {
    Write-Output ''
    Write-Output 'No changes made. Re-run from an elevated PowerShell with -Apply to confirm each action.'
    return
}

$logDirectory = Join-Path $PSScriptRoot 'logs'
if (-not (Test-Path -LiteralPath $logDirectory)) { New-Item -ItemType Directory -Path $logDirectory | Out-Null }
$logPath = Join-Path $logDirectory 'actions.log'
$undoPath = Join-Path $PSScriptRoot 'undo.ps1'

function Write-ActionLog($Result, $Action) {
    $line = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss'), $Result, $Action.Label, "$($Action.Current) -> $($Action.New)" -join "`t"
    Add-Content -LiteralPath $logPath -Value $line -Encoding UTF8
}

function Invoke-NativeChecked {
    param([string] $File, [string[]] $Arguments)
    & $File @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "$File exited with code $LASTEXITCODE" }
}

function Invoke-OptimizeAction($Action) {
    $data = $Action.Data
    switch ($Action.Kind) {
        'PowerCap' {
            Invoke-NativeChecked powercfg @('/setacvalueindex', 'SCHEME_CURRENT', 'SUB_PROCESSOR', 'PROCTHROTTLEMAX', "$($settings.MaxProcessorPercent)")
            Invoke-NativeChecked powercfg @('/setdcvalueindex', 'SCHEME_CURRENT', 'SUB_PROCESSOR', 'PROCTHROTTLEMAX', "$($settings.MaxProcessorPercent)")
            Invoke-NativeChecked powercfg @('/setactive', 'SCHEME_CURRENT')
        }
        'WslConfig' {
            if ($data.Exists) { Copy-Item -LiteralPath $data.Path -Destination $data.BackupPath }
            [IO.File]::WriteAllText($data.Path, $data.NewContent, (New-Object Text.UTF8Encoding($false)))
        }
        'RunRemove' { Remove-ItemProperty -LiteralPath $data.Key -Name $data.Name }
        'StartupDisable' {
            if (-not (Test-Path -LiteralPath $data.ApprovedKey)) { New-Item -Path $data.ApprovedKey -Force | Out-Null }
            $bytes = [byte[]]@(for ($i = 0; $i -lt $data.NewHex.Length; $i += 2) { [Convert]::ToByte($data.NewHex.Substring($i, 2), 16) })
            New-ItemProperty -LiteralPath $data.ApprovedKey -Name $data.Name -Value $bytes -PropertyType Binary -Force | Out-Null
        }
        'TaskDisable' { Disable-ScheduledTask -TaskPath $data.TaskPath -TaskName $data.TaskName | Out-Null }
    }
}

$applied = New-Object System.Collections.Generic.List[object]
foreach ($action in @($plan | Where-Object { $_.Status -in 'Change', 'Ask' })) {
    $prefix = if ($action.Status -eq 'Ask') { 'SEPARATE DECISION: ' } else { '' }
    $answer = Read-Host "$prefix$($action.Action): $($action.Label) [$($action.Current) -> $($action.New)]. Type yes to apply"
    if ($answer -cne 'yes') { Write-ActionLog 'SKIPPED' $action; continue }

    # The undo entry is saved first so a failure part-way through can still be reversed.
    if ($applied.Count -eq 0 -and (Test-Path -LiteralPath $undoPath)) {
        Move-Item -LiteralPath $undoPath -Destination (Join-Path $logDirectory "undo-$($now.ToString('yyyyMMdd-HHmmss')).ps1")
    }
    $applied.Add($action)
    [IO.File]::WriteAllText($undoPath, (New-OptimizeUndoScript -Actions $applied.ToArray()), (New-Object Text.UTF8Encoding($true)))

    try { Invoke-OptimizeAction $action; Write-ActionLog 'APPLIED' $action; Write-Output "Applied: $($action.Label)" }
    catch { Write-ActionLog "FAILED: $($_.Exception.Message)" $action; Write-Warning "Failed: $($action.Label): $($_.Exception.Message)" }
}

if ($applied.Count -gt 0) { Write-Output "Undo script: $undoPath" }
if (@($applied | Where-Object { $_.Kind -eq 'WslConfig' }).Count -gt 0) {
    Write-Output 'WSL limits take effect after you run: wsl --shutdown (this stops running distros and Docker).'
}
