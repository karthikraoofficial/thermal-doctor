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

    It 'records package temperature and the flag' {
        $path = Join-Path $TestDrive 'flag.csv'

        Add-HeatLogRow -Path $path -Timestamp $time -CpuCelsius 70 -CpuPackageCelsius 81.5 -TotalCpuPercent 10 -TopProcesses $top -Flag 'TiWorker (8%)'
        $row = @(Import-Csv $path)[0]

        $row.CpuPackageTempC | Should Be '81.5'
        $row.Flag | Should Be 'TiWorker (8%)'
    }

    It 'leaves package temperature blank without a sensor reading' {
        $path = Join-Path $TestDrive 'nopackage.csv'

        Add-HeatLogRow -Path $path -Timestamp $time -CpuCelsius 70 -CpuPackageCelsius $null -TotalCpuPercent 10 -TopProcesses $top
        @(Import-Csv $path)[0].CpuPackageTempC | Should Be ''
    }

    It 'keeps an older CSV intact and writes new rows beside it' {
        $path = Join-Path $TestDrive 'old.csv'
        $old = "`"Timestamp`",`"CpuTempC`",`"TotalCpuPercent`",`"Top1`",`"Top2`",`"Top3`",`"Top4`",`"Top5`"`r`n`"2026-01-01T00:00:00`",`"60`",`"5`",`"`",`"`",`"`",`"`",`"`"`r`n"
        [IO.File]::WriteAllText($path, $old)

        Add-HeatLogRow -Path $path -Timestamp $time -CpuCelsius 70 -TotalCpuPercent 10 -TopProcesses $top

        [IO.File]::ReadAllText($path) | Should Be $old
        @(Import-Csv (Join-Path $TestDrive 'old-v2.csv')).Count | Should Be 1
    }
}

Describe 'Get-HeatFlag' {
    It 'names watched processes above 5% and sums their instances' {
        $processes = @(
            [pscustomobject]@{ Name = 'TiWorker'; CpuPercent = 3 }
            [pscustomobject]@{ Name = 'tiworker'; CpuPercent = 4 }
            [pscustomobject]@{ Name = 'SearchIndexer'; CpuPercent = 6.5 }
            [pscustomobject]@{ Name = 'demo-app'; CpuPercent = 50 }
        )
        Get-HeatFlag -Processes $processes | Should Be 'TiWorker (7%); SearchIndexer (6.5%)'
    }

    It 'does not flag a watched process at exactly 5%' {
        Get-HeatFlag -Processes @([pscustomobject]@{ Name = 'MoUsoCoreWorker'; CpuPercent = 5 }) | Should Be ''
    }

    It 'flags TrustedInstaller above 5%' {
        Get-HeatFlag -Processes @([pscustomobject]@{ Name = 'TrustedInstaller'; CpuPercent = 5.1 }) | Should Be 'TrustedInstaller (5.1%)'
    }
}
