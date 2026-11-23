Set-StrictMode -Version 2.0

function ConvertTo-PsLiteral {
    param([AllowEmptyString()] [string] $Text)
    return "'" + $Text.Replace("'", "''") + "'"
}

function Test-StartupHexDisabled {
    param([AllowNull()] [string] $Hex)
    if ([string]::IsNullOrEmpty($Hex)) { return $false }
    return (([Convert]::ToInt32($Hex.Substring(0, 2), 16) -band 1) -eq 1)
}

function Test-OptimizeProtected {
    param([string[]] $Text, [string[]] $Patterns)
    $joined = ($Text | Where-Object { $_ }) -join ' '
    foreach ($pattern in $Patterns) {
        if ($joined -match "(?i)$pattern") { return $true }
    }
    return $false
}

function Get-DisabledStartupHex {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [datetime] $Now)

    $bytes = [byte[]](3, 0, 0, 0) + [BitConverter]::GetBytes([long]$Now.ToFileTimeUtc())
    return (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function ConvertTo-WslConfig {
    [CmdletBinding()]
    param(
        [AllowEmptyString()] [string] $Existing = '',
        [Parameter(Mandatory)] [int] $Processors,
        [Parameter(Mandatory)] [string] $Memory
    )

    $lines = New-Object System.Collections.Generic.List[string]
    if ($Existing.Length -gt 0) {
        foreach ($line in ($Existing -split "`r?`n")) { $lines.Add($line) }
        while ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -eq '') { $lines.RemoveAt($lines.Count - 1) }
    }

    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -ieq '[wsl2]') { $start = $i; break }
    }
    if ($start -lt 0) {
        if ($lines.Count -gt 0) { $lines.Add('') }
        $lines.Add('[wsl2]')
        $start = $lines.Count - 1
    }

    $end = $lines.Count
    for ($i = $start + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i].Trim() -match '^\[.+\]$') { $end = $i; break }
    }
    for ($i = $end - 1; $i -gt $start; $i--) {
        if ($lines[$i] -match '^\s*(processors|memory)\s*=') { $lines.RemoveAt($i); $end-- }
    }
    $lines.Insert($start + 1, "processors=$Processors")
    $lines.Insert($start + 2, "memory=$Memory")

    return (($lines -join "`r`n") + "`r`n")
}

function New-PlanRow {
    param($Kind, $Label, $Action, $Current, $New, $UndoText, $Status, $Data)
    if ($Status -notin 'Change', 'Ask') {
        $New = 'No change'
        $UndoText = 'Nothing to undo'
    }
    return [pscustomobject]@{
        Kind = $Kind; Label = $Label; Action = $Action; Current = $Current
        New = $New; UndoText = $UndoText; Status = $Status; Data = $Data
    }
}

function New-OptimizePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $State,
        [Parameter(Mandatory)] $Settings,
        [Parameter(Mandatory)] [datetime] $Now
    )

    $protected = @($Settings.Protected)
    $percent = [int]$Settings.MaxProcessorPercent
    $power = $State.Power
    $powerReadable = ($null -ne $power.AcValue -and $null -ne $power.DcValue)
    $powerStatus = if (-not $powerReadable) { 'Unavailable' }
    elseif ($power.AcValue -eq $percent -and $power.DcValue -eq $percent) { 'NoChange' }
    else { 'Change' }
    $powerCurrent = if ($powerReadable) { "AC $($power.AcValue)%, DC $($power.DcValue)%" } else { 'Unavailable' }
    $powerUndo = if ($powerReadable) { "Restore AC $($power.AcValue)%, DC $($power.DcValue)%" } else { 'n/a' }
    New-PlanRow 'PowerCap' 'CPU turbo cap' 'Set max processor state' $powerCurrent "AC $percent%, DC $percent%" $powerUndo $powerStatus $power

    $wsl = $State.Wsl
    $content = ConvertTo-WslConfig -Existing $wsl.Content -Processors $Settings.WslProcessors -Memory $Settings.WslMemory
    $wslStatus = if ($wsl.Exists -and $wsl.Content -eq $content) { 'NoChange' } else { 'Change' }
    $backup = if ($wsl.Exists) { "$($wsl.Path).bak-$($Now.ToString('yyyyMMdd-HHmmss'))" } else { $null }
    $wslCurrent = if ($wsl.Exists) { 'File exists' } else { 'No file (WSL defaults)' }
    $wslUndo = if ($wsl.Exists) { 'Restore backup copy' } else { 'Delete the new file' }
    New-PlanRow 'WslConfig' 'WSL limits' 'Write .wslconfig' $wslCurrent "processors=$($Settings.WslProcessors), memory=$($Settings.WslMemory)" $wslUndo $wslStatus ([pscustomobject]@{ Path = $wsl.Path; Exists = $wsl.Exists; NewContent = $content; BackupPath = $backup })

    foreach ($item in @($State.RunValues)) {
        $status = if (Test-OptimizeProtected -Text @($item.Label, $item.Name, $item.Value) -Patterns $protected) { 'Protected' }
        elseif (-not $item.Found) { 'NotFound' }
        else { 'Change' }
        $current = if ($item.Found) { 'In Run key' } else { 'Not present' }
        New-PlanRow 'RunRemove' $item.Label 'Remove from Run key' $current 'Starts only when launched' 'Re-add recorded Run value' $status $item
    }

    foreach ($item in @($State.Startup)) {
        $disabled = Test-StartupHexDisabled $item.ApprovedHex
        $status = if (Test-OptimizeProtected -Text @($item.Label, $item.Name, $item.Command) -Patterns $protected) { 'Protected' }
        elseif (-not $item.Found) { 'NotFound' }
        elseif ($disabled) { 'NoChange' }
        elseif ($item.Ask) { 'Ask' }
        else { 'Change' }
        $current = if (-not $item.Found) { 'Not present' } elseif ($disabled) { 'Disabled' } else { 'Enabled' }
        $undo = if ($item.ApprovedHex) { 'Restore startup approval bytes' } else { 'Remove startup approval value' }
        New-PlanRow 'StartupDisable' $item.Label 'Disable startup entry' $current 'Disabled' $undo $status ([pscustomobject]@{ ApprovedKey = $item.ApprovedKey; Name = $item.Name; ApprovedHex = $item.ApprovedHex; NewHex = (Get-DisabledStartupHex -Now $Now) })
    }

    foreach ($task in @($State.Tasks)) {
        $status = if (Test-OptimizeProtected -Text @($task.Label, "$($task.TaskPath)$($task.TaskName)", $task.Command) -Patterns $protected) { 'Protected' }
        elseif (-not $State.TasksVerified -and -not ($task.Found -and $task.Enabled)) { 'Unavailable' }
        elseif (-not $task.Found) { 'NotFound' }
        elseif (-not $task.Enabled) { 'NoChange' }
        else { 'Change' }
        $current = if ($status -eq 'Unavailable') { 'Unavailable without Administrator' }
        elseif (-not $task.Found) { 'Not present' }
        elseif ($task.Enabled) { 'Enabled' }
        else { 'Disabled' }
        New-PlanRow 'TaskDisable' $task.Label 'Disable scheduled task' $current 'Disabled' 'Enable-ScheduledTask' $status $task
    }
}

function Get-OptimizeUndoCommand {
    param($Action)

    $data = $Action.Data
    switch ($Action.Kind) {
        'PowerCap' {
            return "powercfg /setacvalueindex $($data.SchemeGuid) SUB_PROCESSOR PROCTHROTTLEMAX $($data.AcValue); powercfg /setdcvalueindex $($data.SchemeGuid) SUB_PROCESSOR PROCTHROTTLEMAX $($data.DcValue); powercfg /setactive SCHEME_CURRENT"
        }
        'WslConfig' {
            if ($data.Exists) { return "Copy-Item -LiteralPath $(ConvertTo-PsLiteral $data.BackupPath) -Destination $(ConvertTo-PsLiteral $data.Path) -Force" }
            return "Remove-Item -LiteralPath $(ConvertTo-PsLiteral $data.Path) -Force"
        }
        'RunRemove' {
            return "New-ItemProperty -LiteralPath $(ConvertTo-PsLiteral $data.Key) -Name $(ConvertTo-PsLiteral $data.Name) -Value $(ConvertTo-PsLiteral $data.Value) -PropertyType $($data.ValueKind) -Force | Out-Null"
        }
        'StartupDisable' {
            if ([string]::IsNullOrEmpty($data.ApprovedHex)) {
                return "Remove-ItemProperty -LiteralPath $(ConvertTo-PsLiteral $data.ApprovedKey) -Name $(ConvertTo-PsLiteral $data.Name)"
            }
            $pairs = for ($i = 0; $i -lt $data.ApprovedHex.Length; $i += 2) { '0x' + $data.ApprovedHex.Substring($i, 2) }
            return "New-ItemProperty -LiteralPath $(ConvertTo-PsLiteral $data.ApprovedKey) -Name $(ConvertTo-PsLiteral $data.Name) -Value ([byte[]]($($pairs -join ','))) -PropertyType Binary -Force | Out-Null"
        }
        'TaskDisable' {
            return "Enable-ScheduledTask -TaskPath $(ConvertTo-PsLiteral $data.TaskPath) -TaskName $(ConvertTo-PsLiteral $data.TaskName) | Out-Null"
        }
    }
    throw "Unknown action kind: $($Action.Kind)"
}

function New-OptimizeUndoScript {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Actions)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('#Requires -RunAsAdministrator')
    $lines.Add('# Generated by optimize.ps1. Restores the state recorded before each applied action.')
    $lines.Add("`$ErrorActionPreference = 'Stop'")
    for ($i = $Actions.Count - 1; $i -ge 0; $i--) {
        $label = ConvertTo-PsLiteral $Actions[$i].Label
        $lines.Add("try { $(Get-OptimizeUndoCommand $Actions[$i]); Write-Host ('Restored: ' + $label) } catch { Write-Warning ('Failed: ' + $label + ': ' + `$_.Exception.Message) }")
    }
    return (($lines -join "`r`n") + "`r`n")
}

Export-ModuleMember -Function New-OptimizePlan, ConvertTo-WslConfig, New-OptimizeUndoScript, Get-DisabledStartupHex, Test-OptimizeProtected
