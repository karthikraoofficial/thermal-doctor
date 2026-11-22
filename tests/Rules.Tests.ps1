$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'src\Rules.psm1') -Force

Describe 'Get-RedFlags' {
    $snapshot = Get-Content (Join-Path $PSScriptRoot 'fixtures\snapshot.json') -Raw | ConvertFrom-Json

    It 'ranks a known miner name as High and carries its SHA256' {
        $flag = @(Get-RedFlags -Snapshot $snapshot | Where-Object { $_.Pid -eq 4242 -and $_.Rule -eq 'KnownMiner' })

        $flag.Count | Should Be 1
        $flag[0].Severity | Should Be 'High'
        $flag[0].Sha256 | Should Be '0000000000000000000000000000000000000000000000000000000000000001'
    }

    It 'does not flag a signed process in its normal location' {
        @(Get-RedFlags -Snapshot $snapshot | Where-Object { $_.Pid -eq 1001 }).Count | Should Be 0
    }

    It 'flags executables running from AppData, Temp, ProgramData or Users\Public as Medium' {
        $paths = @(
            'C:\Users\demo\AppData\Roaming\demo\app.exe',
            'C:\Windows\Temp\app.exe',
            'C:\ProgramData\demo\app.exe',
            'C:\Users\Public\app.exe'
        )

        foreach ($path in $paths) {
            $candidate = [pscustomobject]@{
                Processes = @([pscustomobject]@{
                    Name = 'demo-app'; Pid = 2001; Path = $path; CommandLine = 'app.exe'; ParentName = 'explorer'
                    CpuPercent = 1.0; Signature = 'Valid'; Company = 'Example Publisher'
                    Sha256 = '0000000000000000000000000000000000000000000000000000000000000006'
                })
            }
            $flag = @(Get-RedFlags -Snapshot $candidate | Where-Object { $_.Rule -eq 'UserWritablePath' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'Medium'
        }
    }

    Context 'system-process impersonation' {
        function New-SystemProcessSnapshot($Name, $Path) {
            [pscustomobject]@{
                Processes = @([pscustomobject]@{
                    Name = $Name; Pid = 3001; Path = $Path; CommandLine = $Name; ParentName = 'demo-parent'
                    CpuPercent = 1.0; Signature = 'Valid'; Company = 'Example Publisher'
                    Sha256 = '0000000000000000000000000000000000000000000000000000000000000008'
                })
            }
        }

        It 'flags <name> outside System32 as High' -TestCases @(
            @{ name = 'svchost' }, @{ name = 'csrss' }, @{ name = 'lsass' }, @{ name = 'conhost' }, @{ name = 'dllhost' }
        ) {
            param($name)
            $flag = @(Get-RedFlags -Snapshot (New-SystemProcessSnapshot $name "C:\Users\demo\$name.exe") | Where-Object { $_.Rule -eq 'SystemNameMisplaced' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'High'
        }

        It 'does not flag a system process inside System32' {
            $result = Get-RedFlags -Snapshot (New-SystemProcessSnapshot 'svchost' 'C:\Windows\System32\svchost.exe')

            @($result | Where-Object { $_.Rule -eq 'SystemNameMisplaced' }).Count | Should Be 0
        }

        It 'does not flag a system process whose path is unreadable' {
            $result = Get-RedFlags -Snapshot (New-SystemProcessSnapshot 'csrss' $null)

            @($result | Where-Object { $_.Rule -eq 'SystemNameMisplaced' }).Count | Should Be 0
        }

        It 'reports a SysWOW64 system process as Low' {
            $flag = @(Get-RedFlags -Snapshot (New-SystemProcessSnapshot 'dllhost' 'C:\Windows\SysWOW64\dllhost.exe') | Where-Object { $_.Rule -eq 'SystemNameMisplaced' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'Low'
        }
    }

    Context 'unsigned CPU use' {
        function New-SignatureSnapshot($Signature, $Cpu) {
            [pscustomobject]@{
                Processes = @([pscustomobject]@{
                    Name = 'demo-worker'; Pid = 4001; Path = 'C:\Program Files\Demo\worker.exe'; CommandLine = 'worker.exe'; ParentName = 'demo-parent'
                    CpuPercent = $Cpu; Signature = $Signature; Company = ''
                    Sha256 = '0000000000000000000000000000000000000000000000000000000000000009'
                })
            }
        }

        It 'flags an unsigned binary above 10% CPU as Medium' {
            $flag = @(Get-RedFlags -Snapshot (New-SignatureSnapshot 'NotSigned' 10.1) | Where-Object { $_.Rule -eq 'UnsignedHighCpu' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'Medium'
        }

        It 'does not flag an unsigned binary at exactly 10% CPU' {
            @(Get-RedFlags -Snapshot (New-SignatureSnapshot 'NotSigned' 10.0) | Where-Object { $_.Rule -eq 'UnsignedHighCpu' }).Count | Should Be 0
        }

        It 'does not call a binary unsigned when its signature could not be read' {
            @(Get-RedFlags -Snapshot (New-SignatureSnapshot 'Unknown' 50.0) | Where-Object { $_.Rule -eq 'UnsignedHighCpu' }).Count | Should Be 0
        }
    }

    Context 'suspicious PowerShell' {
        function New-CommandLineSnapshot($Name, $CommandLine) {
            [pscustomobject]@{
                Processes = @([pscustomobject]@{
                    Name = $Name; Pid = 5001; Path = 'C:\Windows\System32\demo.exe'; CommandLine = $CommandLine; ParentName = 'demo-parent'
                    CpuPercent = 1.0; Signature = 'Valid'; Company = 'Example Publisher'
                    Sha256 = '000000000000000000000000000000000000000000000000000000000000000a'
                })
            }
        }

        It 'flags PowerShell launched with <commandLine> as High' -TestCases @(
            @{ commandLine = 'powershell.exe -enc ZABlAG0AbwA=' },
            @{ commandLine = 'powershell.exe -EncodedCommand ZABlAG0AbwA=' },
            @{ commandLine = 'powershell.exe -w hidden -File demo.ps1' },
            @{ commandLine = 'powershell.exe -WindowStyle Hidden -File demo.ps1' }
        ) {
            param($commandLine)
            $flag = @(Get-RedFlags -Snapshot (New-CommandLineSnapshot 'powershell' $commandLine) | Where-Object { $_.Rule -eq 'SuspiciousPowerShell' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'High'
        }

        It 'does not flag ordinary PowerShell' {
            @(Get-RedFlags -Snapshot (New-CommandLineSnapshot 'powershell' 'powershell.exe -NoProfile -File demo.ps1') | Where-Object { $_.Rule -eq 'SuspiciousPowerShell' }).Count | Should Be 0
        }

        It 'does not flag another program that uses an -enc argument' {
            @(Get-RedFlags -Snapshot (New-CommandLineSnapshot 'demo-encoder' 'demo-encoder.exe -enc h264') | Where-Object { $_.Rule -eq 'SuspiciousPowerShell' }).Count | Should Be 0
        }
    }

    Context 'persistence entries' {
        function Get-PersistenceFlags($Kind, $Command) {
            $candidate = [pscustomobject]@{
                Processes   = @()
                Persistence = @([pscustomobject]@{ Kind = $Kind; Name = 'demo-entry'; Command = $Command })
            }
            @(Get-RedFlags -Snapshot $candidate)
        }

        It 'flags a miner in a startup command as High' {
            $flag = @(Get-PersistenceFlags 'Run key' 'C:\Tools\xmrig.exe --background' | Where-Object { $_.Rule -eq 'PersistenceMiner' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'High'
        }

        It 'flags encoded PowerShell in a scheduled task as High' {
            $flag = @(Get-PersistenceFlags 'Scheduled task' 'powershell.exe -enc ZABlAG0AbwA=' | Where-Object { $_.Rule -eq 'PersistencePowerShell' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'High'
        }

        It 'flags a startup command in Temp or Users\Public as Medium' {
            foreach ($command in 'C:\Users\demo\AppData\Local\Temp\a.exe', 'C:\Users\Public\a.exe') {
                $flag = @(Get-PersistenceFlags 'Run key' $command | Where-Object { $_.Rule -eq 'PersistenceRiskyPath' })

                $flag.Count | Should Be 1
                $flag[0].Severity | Should Be 'Medium'
            }
        }

        It 'flags an AppData startup command as Low because many apps install there' {
            $flag = @(Get-PersistenceFlags 'Run key' 'C:\Users\demo\AppData\Local\Programs\Demo\demo.exe' | Where-Object { $_.Rule -eq 'PersistenceRiskyPath' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'Low'
        }

        It 'flags any WMI event subscription as Medium' {
            $flag = @(Get-PersistenceFlags 'WMI subscription' 'CommandLineEventConsumer: demo' | Where-Object { $_.Rule -eq 'WmiSubscription' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'Medium'
        }

        It 'does not flag an ordinary Program Files startup command' {
            (Get-PersistenceFlags 'Run key' '"C:\Program Files\Demo\demo.exe" --tray').Count | Should Be 0
        }
    }

    It 'does not treat an ordinary Program Files path as user-writable' {
        $candidate = [pscustomobject]@{
            Processes = @([pscustomobject]@{
                Name = 'demo-app'; Pid = 2002; Path = 'C:\Program Files\Demo\app.exe'; CommandLine = 'app.exe'; ParentName = 'explorer'
                CpuPercent = 1.0; Signature = 'Valid'; Company = 'Example Publisher'
                Sha256 = '0000000000000000000000000000000000000000000000000000000000000007'
            })
        }

        @(Get-RedFlags -Snapshot $candidate | Where-Object { $_.Rule -eq 'UserWritablePath' }).Count | Should Be 0
    }
}
