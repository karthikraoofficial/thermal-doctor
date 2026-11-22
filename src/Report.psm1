Set-StrictMode -Version 2.0

function ConvertTo-MarkdownCell {
    param($Value)

    if ($null -eq $Value -or "$Value" -eq '') { return '-' }
    return ("$Value" -replace '\|', '\|' -replace '\r?\n', ' ')
}

function ConvertTo-ThermalReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Snapshot,
        [AllowEmptyCollection()] [object[]] $Flags = @()
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# Thermal Doctor report')
    $lines.Add('')
    $lines.Add('## Red flags')
    $lines.Add('')

    if ($Flags.Count -eq 0) {
        $lines.Add('No red flags were raised.')
    }
    foreach ($severity in 'High', 'Medium', 'Low') {
        $matching = @($Flags | Where-Object { $_.Severity -eq $severity })
        if ($matching.Count -eq 0) { continue }

        $lines.Add("### $severity")
        $lines.Add('')
        foreach ($flag in $matching) {
            $hash = if ($flag.Sha256) { " SHA256: ``$($flag.Sha256)``" } else { '' }
            $lines.Add("- **$($flag.Name)** (PID $($flag.Pid)): $($flag.Reason). Path: ``$($flag.Path)``.$hash")
        }
        $lines.Add('')
    }

    $lines.Add('')
    $lines.Add('## Top heat contributors')
    $lines.Add('')
    $lines.Add('| Process | PID | CPU % | Signature | Company | Path |')
    $lines.Add('| --- | --- | --- | --- | --- | --- |')
    $hottest = @($Snapshot.Processes | Sort-Object -Property CpuPercent -Descending | Select-Object -First 15)
    foreach ($process in $hottest) {
        $cells = @($process.Name, $process.Pid, $process.CpuPercent, $process.Signature, $process.Company, $process.Path) |
            ForEach-Object { ConvertTo-MarkdownCell $_ }
        $lines.Add('| ' + ($cells -join ' | ') + ' |')
    }

    $lines.Add('')
    $lines.Add('## Raw data')
    $lines.Add('')
    $lines.Add('```json')
    $lines.Add(($Snapshot | ConvertTo-Json -Depth 6))
    $lines.Add('```')

    return ($lines -join "`n")
}

Export-ModuleMember -Function ConvertTo-ThermalReport
