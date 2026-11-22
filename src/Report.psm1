Set-StrictMode -Version 2.0

function ConvertTo-MarkdownCell {
    param($Value)

    if ($null -eq $Value -or "$Value" -eq '') { return '-' }
    return ("$Value" -replace '\|', '\|' -replace '\r?\n', ' ')
}

function Add-MarkdownTable {
    param($Lines, [object[]] $Rows)

    if ($Rows.Count -eq 0) { return }
    $columns = @($Rows[0].PSObject.Properties.Name)
    $Lines.Add('| ' + ($columns -join ' | ') + ' |')
    $Lines.Add('| ' + (($columns | ForEach-Object { '---' }) -join ' | ') + ' |')
    foreach ($row in $Rows) {
        $cells = foreach ($column in $columns) { ConvertTo-MarkdownCell $row.$column }
        $Lines.Add('| ' + ($cells -join ' | ') + ' |')
    }
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
            $processId = if ($null -ne $flag.Pid) { " (PID $($flag.Pid))" } else { '' }
            $location = if ($flag.Path) { " Path: ``$($flag.Path)``." } else { '' }
            $lines.Add("- **$($flag.Name)**${processId}: $($flag.Reason).$location$hash")
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
    $lines.Add('### CPU: top 15 process details')
    $lines.Add('')
    Add-MarkdownTable -Lines $lines -Rows @($hottest | Select-Object Name, Pid, CpuPercent, ParentName, Signature, Company, Path, CommandLine)
    $lines.Add('')

    $sections = $Snapshot.PSObject.Properties['Sections']
    if ($sections) {
        foreach ($section in @($sections.Value)) {
            $lines.Add("### $($section.Title)")
            $lines.Add('')
            if ($section.Note) {
                $lines.Add($section.Note)
                $lines.Add('')
            }
            if (@($section.Rows).Count -gt 0) {
                Add-MarkdownTable -Lines $lines -Rows @($section.Rows)
                $lines.Add('')
            }
            elseif (-not $section.Note) {
                $lines.Add('None found.')
                $lines.Add('')
            }
        }
    }

    return ($lines -join "`n")
}

Export-ModuleMember -Function ConvertTo-ThermalReport
