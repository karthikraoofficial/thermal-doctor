$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\HeatLog.psm1') -Force

Describe 'Add-HeatLogRow' {
    $top = @(
        [pscustomobject]@{ Name = 'demo-a'; CpuPercent = 40.5 }
        [pscustomobject]@{ Name = 'demo, b'; CpuPercent = 20 }
        [pscustomobject]@{ Name = 'demo-c'; CpuPercent = 10 }
        [pscustomobject]@{ Name = 'demo-d'; CpuPercent = 5 }
        [pscustomobject]@{ Name = 'demo-e'; CpuPercent = 2 }
        [pscustomobject]@{ Name = 'demo-f'; CpuPercent = 1 }
    )
    $time = [datetime]'2026-01-02T03:04:05'

    It 'writes one header and appends a row per sample' {
        $path = Join-Path $TestDrive 'nested\append.csv'

        Add-HeatLogRow -Path $path -Timestamp $time -CpuCelsius 71.5 -TotalCpuPercent 63.2 -TopProcesses $top
        Add-HeatLogRow -Path $path -Timestamp $time -CpuCelsius 72 -TotalCpuPercent 64 -TopProcesses $top

        @(Get-Content $path | Where-Object { $_ -like '*Timestamp*' }).Count | Should Be 1
        @(Import-Csv $path).Count | Should Be 2
    }

    It 'records the sample values and only the top 5 processes' {
        $path = Join-Path $TestDrive 'values.csv'

        Add-HeatLogRow -Path $path -Timestamp $time -CpuCelsius 71.5 -TotalCpuPercent 63.2 -TopProcesses $top
        $row = @(Import-Csv $path)[0]

        $row.Timestamp | Should Be '2026-01-02T03:04:05'
        $row.CpuTempC | Should Be '71.5'
        $row.TotalCpuPercent | Should Be '63.2'
        $row.Top1 | Should Be 'demo-a (40.5%)'
        $row.Top2 | Should Be 'demo, b (20%)'
        $row.Top5 | Should Be 'demo-e (2%)'
        $row.PSObject.Properties.Name -contains 'Top6' | Should Be $false
    }

    It 'leaves temperature blank when there is no sensor data' {
        $path = Join-Path $TestDrive 'blank.csv'

        Add-HeatLogRow -Path $path -Timestamp $time -CpuCelsius $null -TotalCpuPercent 10 -TopProcesses $top
        @(Import-Csv $path)[0].CpuTempC | Should Be ''
    }
}
