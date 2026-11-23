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

    Context 'network connections' {
        function Get-NetworkFlags($Address, $Port, $HostName) {
            $candidate = [pscustomobject]@{
                Processes   = @()
                Connections = @([pscustomobject]@{
                    ProcessName = 'demo-net'; Pid = 6001; Path = 'C:\Program Files\Demo\net.exe'
                    RemoteAddress = $Address; RemotePort = $Port; RemoteHost = $HostName
                })
            }
            @(Get-RedFlags -Snapshot $candidate)
        }

        It 'flags remote port <port> as Medium' -TestCases @(
            @{ port = 3333 }, @{ port = 4444 }, @{ port = 5555 }, @{ port = 7777 }, @{ port = 8888 }, @{ port = 14444 }, @{ port = 45700 }
        ) {
            param($port)
            $flag = @(Get-NetworkFlags '203.0.113.10' $port '' | Where-Object { $_.Rule -eq 'MiningPort' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'Medium'
        }

        It 'does not flag an ordinary HTTPS connection' {
            (Get-NetworkFlags '203.0.113.10' 443 'www.example.test').Count | Should Be 0
        }

        It 'does not flag a mining port on loopback' {
            (Get-NetworkFlags '127.0.0.1' 8888 '').Count | Should Be 0
            (Get-NetworkFlags '::1' 8888 '').Count | Should Be 0
        }

        It 'flags a host containing <hostName> as <severity>' -TestCases @(
            @{ hostName = 'xmr.example.test'; severity = 'High' },
            @{ hostName = 'eu.nicehash.example.test'; severity = 'High' },
            @{ hostName = 'pool.example.test'; severity = 'Medium' },
            @{ hostName = 'mine.example.test'; severity = 'Medium' }
        ) {
            param($hostName, $severity)
            $flag = @(Get-NetworkFlags '203.0.113.10' 443 $hostName | Where-Object { $_.Rule -eq 'MiningHost' })

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be $severity
        }
    }

    Context 'false positives and orphaned tasks' {
        It 'does not mistake -Encoding inside a -Command script for an encoded command' {
            $candidate = [pscustomobject]@{
                Processes = @([pscustomobject]@{
                    Name = 'powershell'; Pid = 7001; Path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
                    CommandLine = 'powershell.exe -NoProfile -Command "Get-Content demo.txt -Encoding utf8"'
                    ParentName = 'demo-parent'; CpuPercent = 0.1; Signature = 'Valid'; Company = 'Example Publisher'; Sha256 = $null
                })
            }

            @(Get-RedFlags -Snapshot $candidate | Where-Object { $_.Rule -eq 'SuspiciousPowerShell' }).Count | Should Be 0
        }

        It 'judges a startup entry by its executable, not by paths in its arguments' {
            $candidate = [pscustomobject]@{
                Processes   = @()
                Persistence = @([pscustomobject]@{ Kind = 'Scheduled task'; Name = 'demo'; Command = '"C:\Program Files\Demo\demo.exe" --data C:\ProgramData\Demo' })
            }

            @(Get-RedFlags -Snapshot $candidate).Count | Should Be 0
        }

        It 'flags a task whose user-writable executable is missing as High, along with executables left beside it' {
            $candidate = [pscustomobject]@{
                Processes   = @()
                Persistence = @([pscustomobject]@{
                    Kind = 'Scheduled task'; Name = '\Vendor\abcxyz'; Command = '"C:\Users\demo\AppData\Roaming\abc\host.exe" payload.dat'
                    TargetMissing = $true; Companions = @('C:\Users\demo\AppData\Roaming\abc\dropper.exe')
                })
            }
            $flags = @(Get-RedFlags -Snapshot $candidate)
            $orphan = @($flags | Where-Object { $_.Rule -eq 'OrphanedTask' })
            $companion = @($flags | Where-Object { $_.Rule -eq 'OrphanedTaskCompanion' })

            $orphan.Count | Should Be 1
            $orphan[0].Severity | Should Be 'High'
            $companion.Count | Should Be 1
            $companion[0].Severity | Should Be 'High'
            $companion[0].Path | Should Be 'C:\Users\demo\AppData\Roaming\abc\dropper.exe'
        }

        It 'collapses repeated flags for one executable into a single flag with a count' {
            $copies = 1..3 | ForEach-Object {
                [pscustomobject]@{
                    Name = 'demo-app'; Pid = 8000 + $_; Path = 'C:\Users\demo\AppData\Local\Demo\app.exe'; CommandLine = 'app.exe'
                    ParentName = 'demo-parent'; CpuPercent = 0.1; Signature = 'Valid'; Company = 'Example Publisher'; Sha256 = $null
                }
            }
            $flag = @(Get-RedFlags -Snapshot ([pscustomobject]@{ Processes = @($copies) }) | Where-Object { $_.Rule -eq 'UserWritablePath' })

            $flag.Count | Should Be 1
            $flag[0].Reason | Should Match '3 processes'
        }
    }

    Context 'trusted AppData processes and tool caches' {
        $cases = Get-Content (Join-Path $PSScriptRoot 'fixtures\appdata-processes.json') -Raw | ConvertFrom-Json |
            ForEach-Object { $_ } | Select-Object *, @{ n = 'CommandLine'; e = { 'demo.exe' } }, @{ n = 'Sha256'; e = { $null } }

        foreach ($case in $cases) {
            It "ranks $($case.Case) as $($case.Expected)" {
                $flag = @(Get-RedFlags -Snapshot ([pscustomobject]@{ Processes = @($case) }) | Where-Object { $_.Rule -eq 'UserWritablePath' })

                $flag.Count | Should Be 1
                $flag[0].Severity | Should Be $case.Expected
            }
        }

        It 'keeps a busy unsigned copy visible when an idle copy of the same file is Info' {
            $idle = [pscustomobject]@{ Name = 'demo-tool'; Pid = 9201; Path = 'C:\Users\demo\AppData\Local\uv\cache\demo\tool.exe'; CommandLine = 'tool.exe'; CpuPercent = 0.1; Signature = 'NotSigned'; Signer = ''; Company = ''; Sha256 = $null }
            $busy = [pscustomobject]@{ Name = 'demo-tool'; Pid = 9202; Path = 'C:\Users\demo\AppData\Local\uv\cache\demo\tool.exe'; CommandLine = 'tool.exe'; CpuPercent = 40.0; Signature = 'NotSigned'; Signer = ''; Company = ''; Sha256 = $null }
            $flags = @(Get-RedFlags -Snapshot ([pscustomobject]@{ Processes = @($idle, $busy) }) | Where-Object { $_.Rule -eq 'UserWritablePath' })

            @($flags | Where-Object { $_.Severity -eq 'Medium' }).Count | Should Be 1
        }

        It 'still ranks a known miner in a uv cache as High' {
            $miner = [pscustomobject]@{ Name = 'xmrig'; Pid = 9203; Path = 'C:\Users\demo\AppData\Local\uv\cache\demo\xmrig.exe'; CommandLine = 'xmrig.exe'; CpuPercent = 0.1; Signature = 'NotSigned'; Signer = ''; Company = ''; Sha256 = $null }

            @(Get-RedFlags -Snapshot ([pscustomobject]@{ Processes = @($miner) }) | Where-Object { $_.Rule -eq 'KnownMiner' -and $_.Severity -eq 'High' }).Count | Should Be 1
        }
    }

    Context 'browsers launched at raw hosts' {
        $launches = Get-Content (Join-Path $PSScriptRoot 'fixtures\browser-launches.json') -Raw | ConvertFrom-Json | ForEach-Object { $_ }

        foreach ($launch in $launches) {
            It "handles $($launch.Case)" {
                $process = [pscustomobject]@{
                    Name = $launch.Name; Pid = 9301; Path = 'C:\Program Files\Demo\browser.exe'; CommandLine = $launch.CommandLine
                    CpuPercent = 0.1; Signature = 'Valid'; Signer = ''; Company = ''; Sha256 = $null
                }
                $flag = @(Get-RedFlags -Snapshot ([pscustomobject]@{ Processes = @($process) }) | Where-Object { $_.Rule -eq 'BrowserRawHost' })

                if ($launch.Flagged) {
                    $flag.Count | Should Be 1
                    $flag[0].Severity | Should Be 'Medium'
                    $flag[0].Reason | Should Match ([regex]::Escape($launch.Host))
                }
                else { $flag.Count | Should Be 0 }
            }
        }
    }

    Context 'MSI advertised shortcuts' {
        $fixture = Get-Content (Join-Path $PSScriptRoot 'fixtures\msi-shortcuts.json') -Raw | ConvertFrom-Json
        $products = @{}
        foreach ($property in $fixture.Products.PSObject.Properties) { $products[$property.Name] = $property.Value }

        foreach ($case in @($fixture.Cases | ForEach-Object { $_ })) {
            It "describes $($case.Case)" {
                $resolved = Resolve-AdvertisedShortcut -Target $case.Target -Products $products

                $resolved.ProductCode | Should Be $case.ProductCode
                $resolved.Command | Should Be $case.Expected
            }
        }

        It 'does not treat a lookalike or ordinary path as advertised' {
            foreach ($target in @($fixture.NotAdvertisedTargets | ForEach-Object { $_ })) {
                Resolve-AdvertisedShortcut -Target $target -Products $products | Should BeNullOrEmpty
            }
        }

        It 'reads the advertised marker from the shortcut header' {
            $advertised = New-Object byte[] 76
            $advertised[0] = 0x4C
            $advertised[0x15] = 0x10
            $plain = New-Object byte[] 76
            $plain[0] = 0x4C

            Test-LnkHasDarwinId -Bytes $advertised | Should Be $true
            Test-LnkHasDarwinId -Bytes $plain | Should Be $false
            Test-LnkHasDarwinId -Bytes (New-Object byte[] 8) | Should Be $false
        }
    }

    Context 'antivirus coverage' {
        function Get-AntivirusFlags($DefenderActive, $Available, $Products) {
            $candidate = [pscustomobject]@{
                Processes = @()
                Antivirus = [pscustomobject]@{ DefenderActive = $DefenderActive; Available = $Available; Products = @($Products) }
            }
            @(Get-RedFlags -Snapshot $candidate | Where-Object { $_.Rule -eq 'DefenderOff' })
        }
        $defender = [pscustomobject]@{ Name = 'Windows Defender'; State = 'Off'; Definitions = 'Up to date' }
        $other = [pscustomobject]@{ Name = 'Demo Antivirus'; State = 'On'; Definitions = 'Up to date' }

        It 'decodes product state <state> as <expected>' -TestCases @(
            @{ state = 0x041000; expected = 'On'; definitions = 'Up to date' },
            @{ state = 0x060100; expected = 'Off'; definitions = 'Up to date' },
            @{ state = 0x041010; expected = 'On'; definitions = 'Out of date' },
            @{ state = 0x042000; expected = 'Snoozed'; definitions = 'Up to date' },
            @{ state = 0x043000; expected = 'Expired'; definitions = 'Up to date' }
        ) {
            param($state, $expected, $definitions)
            $decoded = ConvertFrom-AvProductState -ProductState $state

            $decoded.State | Should Be $expected
            $decoded.Definitions | Should Be $definitions
        }

        It 'flags Defender off when no other antivirus is registered' {
            $flag = @(Get-AntivirusFlags $false $true @($defender))

            $flag.Count | Should Be 1
            $flag[0].Severity | Should Be 'Medium'
        }

        It 'does not flag Defender off when another antivirus is registered' {
            (Get-AntivirusFlags $false $true @($defender, $other)).Count | Should Be 0
        }

        It 'does not flag Defender when it is active' {
            (Get-AntivirusFlags $true $true @($defender)).Count | Should Be 0
        }

        It 'does not claim Defender is the only product when the registry of products is unavailable' {
            (Get-AntivirusFlags $false $false @()).Count | Should Be 0
        }
    }

    Context 'network grouping' {
        It 'groups sockets by process and remote IP with a count' {
            $socket = { param($name, $id, $address, $port) [pscustomobject]@{ ProcessName = $name; Pid = $id; RemoteAddress = $address; RemotePort = $port; RemoteHost = ''; Path = 'C:\Program Files\Demo\net.exe' } }
            $rows = @(Group-NetworkConnections -Connections @(
                    (& $socket 'demo-net' 10 '203.0.113.10' 443),
                    (& $socket 'demo-net' 10 '203.0.113.10' 443),
                    (& $socket 'demo-net' 11 '203.0.113.10' 8443),
                    (& $socket 'demo-net' 10 '198.51.100.7' 443),
                    (& $socket 'demo-other' 12 '203.0.113.10' 443)
                ))

            $rows.Count | Should Be 3
            $rows[0].ProcessName | Should Be 'demo-net'
            $rows[0].RemoteAddress | Should Be '203.0.113.10'
            $rows[0].Connections | Should Be 3
            $rows[0].Pids | Should Be '10, 11'
            $rows[0].RemotePorts | Should Be '443, 8443'
        }
    }

    Context 'known findings' {
        $known = @(
            [pscustomobject]@{ Title = 'Demo driver bug'; Note = 'Known vendor issue'; Match = [pscustomobject]@{ Name = 'demo-host'; Path = 'C:\Windows\System32\demo-host.exe' } }
            [pscustomobject]@{ Title = 'Demo OEM shortcut'; Note = 'OEM bloat'; Match = [pscustomobject]@{ Name = 'Demo.lnk'; ProductCode = '{11111111-2222-4333-8444-555555555555}' } }
        )
        $hostProcess = [pscustomobject]@{ Name = 'demo-host'; Pid = 9401; Path = 'C:\Windows\System32\demo-host.exe' }
        $shortcut = [pscustomobject]@{ Kind = 'Startup folder'; Name = 'Demo.lnk'; Command = 'MSI advertised shortcut'; ProductCode = '{11111111-2222-4333-8444-555555555555}' }

        It 'moves a matching flag out of the ranked list' {
            $flag = [pscustomobject]@{ Severity = 'High'; Rule = 'Demo'; Name = 'demo-host'; Pid = 9401; Path = 'c:\windows\system32\DEMO-HOST.exe'; Sha256 = $null; Reason = 'Demo' }
            $result = Split-KnownFindings -Flags @($flag) -Snapshot ([pscustomobject]@{ Processes = @($hostProcess); Persistence = @() }) -KnownFindings $known

            @($result.Active).Count | Should Be 0
            @($result.Triaged | Where-Object { $_.Title -eq 'Demo driver bug' }).Count | Should Be 1
            @($result.Triaged | Where-Object { $_.Title -eq 'Demo driver bug' })[0].WouldBe | Should Be 'High'
        }

        It 'keeps a lookalike with the same name at another path' {
            $flag = [pscustomobject]@{ Severity = 'High'; Rule = 'Demo'; Name = 'demo-host'; Pid = 9402; Path = 'C:\Users\demo\AppData\Local\demo-host.exe'; Sha256 = $null; Reason = 'Demo' }
            $result = Split-KnownFindings -Flags @($flag) -Snapshot ([pscustomobject]@{ Processes = @(); Persistence = @() }) -KnownFindings $known

            @($result.Active).Count | Should Be 1
            @($result.Triaged).Count | Should Be 0
        }

        It 'lists a known item that was observed without raising a flag' {
            $result = Split-KnownFindings -Flags @() -Snapshot ([pscustomobject]@{ Processes = @(); Persistence = @($shortcut) }) -KnownFindings $known

            @($result.Triaged).Count | Should Be 1
            $result.Triaged[0].Title | Should Be 'Demo OEM shortcut'
            $result.Triaged[0].WouldBe | Should Be 'Not flagged'
        }

        It 'ignores a name-only entry so it cannot hide a lookalike' {
            $nameOnly = @([pscustomobject]@{ Title = 'Too broad'; Note = ''; Match = [pscustomobject]@{ Name = 'demo-host' } })
            $flag = [pscustomobject]@{ Severity = 'High'; Rule = 'Demo'; Name = 'demo-host'; Pid = 9403; Path = 'C:\Windows\System32\demo-host.exe'; Sha256 = $null; Reason = 'Demo' }
            $result = Split-KnownFindings -Flags @($flag) -Snapshot ([pscustomobject]@{ Processes = @(); Persistence = @() }) -KnownFindings $nameOnly

            @($result.Active).Count | Should Be 1
            @($result.Invalid).Count | Should Be 1
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
