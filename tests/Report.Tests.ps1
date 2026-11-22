$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\Report.psm1') -Force

Describe 'ConvertTo-ThermalReport' {
    $snapshot = Get-Content (Join-Path $PSScriptRoot 'fixtures\snapshot.json') -Raw | ConvertFrom-Json
    $flags = @(
        [pscustomobject]@{ Severity = 'Low'; Rule = 'ExampleLow'; Name = 'demo-low'; Pid = 1; Path = 'C:\Users\demo\low.exe'; Sha256 = '0000000000000000000000000000000000000000000000000000000000000003'; Reason = 'Low reason' }
        [pscustomobject]@{ Severity = 'High'; Rule = 'ExampleHigh'; Name = 'demo-high'; Pid = 2; Path = 'C:\Users\demo\high.exe'; Sha256 = '0000000000000000000000000000000000000000000000000000000000000004'; Reason = 'High reason' }
        [pscustomobject]@{ Severity = 'Medium'; Rule = 'ExampleMedium'; Name = 'demo-medium'; Pid = 3; Path = 'C:\Users\demo\medium.exe'; Sha256 = '0000000000000000000000000000000000000000000000000000000000000005'; Reason = 'Medium reason' }
    )
    $report = ConvertTo-ThermalReport -Snapshot $snapshot -Flags $flags

    It 'orders sections as Red flags, Top heat contributors, then raw data' {
        $redFlags = $report.IndexOf('## Red flags')
        $heat = $report.IndexOf('## Top heat contributors')
        $raw = $report.IndexOf('## Raw data')

        $redFlags | Should BeGreaterThan -1
        $heat | Should BeGreaterThan $redFlags
        $raw | Should BeGreaterThan $heat
    }

    It 'ranks flags High, then Medium, then Low' {
        $high = $report.IndexOf('High reason')
        $medium = $report.IndexOf('Medium reason')
        $low = $report.IndexOf('Low reason')

        $high | Should BeGreaterThan -1
        $medium | Should BeGreaterThan $high
        $low | Should BeGreaterThan $medium
    }

    It 'includes the SHA256 of a flagged executable' {
        $report | Should Match '0000000000000000000000000000000000000000000000000000000000000004'
    }

    Context 'raw sections' {
        $sectioned = [pscustomobject]@{
            Processes = @()
            Sections  = @(
                [pscustomobject]@{ Title = 'Temperatures'; Status = 'Unavailable'; Note = 'no sensor data (access denied)'; Rows = @() }
                [pscustomobject]@{ Title = 'GPU'; Status = 'Ok'; Note = ''; Rows = @([pscustomobject]@{ Process = 'demo-render'; Pid = 77; GpuPercent = 41.5 }) }
            )
        }
        $sectionReport = ConvertTo-ThermalReport -Snapshot $sectioned -Flags @()
        $raw = $sectionReport.Substring($sectionReport.IndexOf('## Raw data'))

        It 'states why an unavailable section has no data' {
            $raw | Should Match '### Temperatures'
            $raw | Should Match 'no sensor data \(access denied\)'
        }

        It 'renders section rows as a table with their column names' {
            $raw | Should Match '### GPU'
            $raw | Should Match '\| Process \| Pid \| GpuPercent \|'
            $raw | Should Match '\| demo-render \| 77 \| 41\.5 \|'
        }
    }

    It 'lists the hottest process first in Top heat contributors' {
        $section = $report.Substring($report.IndexOf('## Top heat contributors'))

        $section.IndexOf('xmrig') | Should BeGreaterThan -1
        $section.IndexOf('notepad') | Should BeGreaterThan $section.IndexOf('xmrig')
    }
}
