Set-StrictMode -Version 2.0

# Every function in this module only reads system state.

function Get-CpuByProcessId {
    [CmdletBinding()]
    param([int] $SampleSeconds = 60)

    $intervalSeconds = 5
    $maxSamples = [math]::Max(2, [int][math]::Ceiling($SampleSeconds / $intervalSeconds) + 1)
    $cores = [Environment]::ProcessorCount
    $sampleSets = @(Get-Counter -Counter '\Process(*)\% Processor Time', '\Process(*)\ID Process' `
            -SampleInterval $intervalSeconds -MaxSamples $maxSamples -ErrorAction SilentlyContinue)

    $totals = @{}
    foreach ($set in $sampleSets) {
        # Instance names such as app#2 can move between PIDs, so map them afresh in each sample.
        $idByInstance = @{}
        foreach ($sample in $set.CounterSamples) {
            if ($sample.Path -like '*\id process') { $idByInstance[$sample.InstanceName] = [int]$sample.CookedValue }
        }
        foreach ($sample in $set.CounterSamples) {
            if ($sample.Path -notlike '*\% processor time') { continue }
            if ($sample.InstanceName -in '_total', 'idle') { continue }
            if (-not $idByInstance.ContainsKey($sample.InstanceName)) { continue }
            $id = $idByInstance[$sample.InstanceName]
            if (-not $totals.ContainsKey($id)) { $totals[$id] = 0.0 }
            $totals[$id] += [double]$sample.CookedValue
        }
    }

    $averages = @{}
    if ($sampleSets.Count -gt 0) {
        foreach ($id in $totals.Keys) {
            $averages[$id] = [math]::Round($totals[$id] / $sampleSets.Count / $cores, 2)
        }
    }
    return $averages
}

function Get-SignatureInfo {
    param([string] $Path)

    $info = @{ Signature = 'Unknown'; Company = '' }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $info }

    try {
        $status = (Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status
        $info.Signature = "$status"
    }
    catch { $info.Signature = 'Unknown' }

    try { $info.Company = "$((Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.CompanyName)" }
    catch { $info.Company = '' }

    return $info
}

function Get-ProcessSnapshot {
    [CmdletBinding()]
    param([int] $SampleSeconds = 60, [int] $IdentifyTop = 15)

    $cpu = Get-CpuByProcessId -SampleSeconds $SampleSeconds
    $all = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $nameById = @{}
    foreach ($item in $all) { $nameById[[int]$item.ProcessId] = $item.Name -replace '(?i)\.exe$', '' }

    $processes = foreach ($item in $all) {
        $id = [int]$item.ProcessId
        $parentId = [int]$item.ParentProcessId
        [pscustomobject]@{
            Name        = $item.Name -replace '(?i)\.exe$', ''
            Pid         = $id
            Path        = $item.ExecutablePath
            CommandLine = $item.CommandLine
            ParentName  = if ($nameById.ContainsKey($parentId)) { $nameById[$parentId] } else { "exited ($parentId)" }
            CpuPercent  = if ($cpu.ContainsKey($id)) { $cpu[$id] } else { 0.0 }
            Signature   = 'Unknown'
            Company     = ''
            Sha256      = $null
        }
    }

    $sorted = @($processes | Sort-Object -Property CpuPercent -Descending)
    foreach ($process in @($sorted | Select-Object -First $IdentifyTop)) {
        $signature = Get-SignatureInfo -Path $process.Path
        $process.Signature = $signature.Signature
        $process.Company = $signature.Company
    }
    return $sorted
}

function Add-FlagHashes {
    [CmdletBinding()]
    param([AllowEmptyCollection()] [object[]] $Flags = @())

    $cache = @{}
    foreach ($flag in $Flags) {
        if (-not $flag.Path) { continue }
        if (-not $cache.ContainsKey($flag.Path)) {
            if (-not (Test-Path -LiteralPath $flag.Path -PathType Leaf)) { $cache[$flag.Path] = 'unavailable (file is missing)' }
            else {
                try { $cache[$flag.Path] = (Get-FileHash -LiteralPath $flag.Path -Algorithm SHA256 -ErrorAction Stop).Hash }
                catch { $cache[$flag.Path] = 'unavailable (file could not be read)' }
            }
        }
        $flag.Sha256 = $cache[$flag.Path]
    }
    return $Flags
}

function New-Section {
    param([string] $Title, [string] $Note = '', [object[]] $Rows = @(), [string] $Status = 'Ok')

    [pscustomobject]@{ Title = $Title; Status = $Status; Note = $Note; Rows = @($Rows) }
}

function Get-GpuSection {
    [CmdletBinding()]
    param([int] $Samples = 5)

    try {
        $sets = @(Get-Counter -Counter '\GPU Engine(*)\Utilization Percentage' -SampleInterval 2 -MaxSamples $Samples -ErrorAction Stop)
    }
    catch {
        return New-Section -Title 'GPU' -Status 'Unavailable' -Note "GPU counters unavailable: $($_.Exception.Message)"
    }

    # Like Task Manager, a process's GPU load is its busiest engine type in each sample.
    $totals = @{}
    foreach ($set in $sets) {
        $byEngine = @{}
        foreach ($sample in $set.CounterSamples) {
            if ($sample.InstanceName -notmatch '^pid_(\d+)_.*engtype_(.+)$') { continue }
            $key = "$($Matches[1])|$($Matches[2])"
            if (-not $byEngine.ContainsKey($key)) { $byEngine[$key] = 0.0 }
            $byEngine[$key] += [double]$sample.CookedValue
        }
        $peak = @{}
        foreach ($key in $byEngine.Keys) {
            $id = [int]($key -split '\|')[0]
            if (-not $peak.ContainsKey($id) -or $byEngine[$key] -gt $peak[$id]) { $peak[$id] = $byEngine[$key] }
        }
        foreach ($id in $peak.Keys) {
            if (-not $totals.ContainsKey($id)) { $totals[$id] = 0.0 }
            $totals[$id] += $peak[$id]
        }
    }

    $rows = foreach ($id in $totals.Keys) {
        $average = [math]::Round($totals[$id] / $sets.Count, 2)
        if ($average -le 0) { continue }
        $process = Get-Process -Id $id -ErrorAction SilentlyContinue
        [pscustomobject]@{ Process = if ($process) { $process.ProcessName } else { 'exited' }; Pid = $id; GpuPercent = $average }
    }
    $top = @($rows | Sort-Object -Property GpuPercent -Descending | Select-Object -First 15)
    $note = if ($top.Count -eq 0) { 'No process used the GPU during the sample.' } else { '' }
    return New-Section -Title 'GPU' -Rows $top -Note $note
}

function Get-TemperatureReading {
    [CmdletBinding()]
    param()

    $problems = New-Object System.Collections.Generic.List[string]
    try {
        $sensors = @(Get-CimInstance -Namespace 'root/LibreHardwareMonitor' -ClassName Sensor -Filter "SensorType='Temperature'" -ErrorAction Stop)
        if ($sensors.Count -gt 0) {
            $rows = @($sensors | ForEach-Object { [pscustomobject]@{ Sensor = $_.Name; Celsius = [math]::Round([double]$_.Value, 1) } })
            $cpu = @($sensors | Where-Object { $_.Identifier -match '(?i)cpu' -and $_.Name -match '(?i)package|tctl|tdie' } | Select-Object -First 1)
            if ($cpu.Count -eq 0) { $cpu = @($sensors | Where-Object { $_.Identifier -match '(?i)cpu' } | Select-Object -First 1) }
            $cpuCelsius = if ($cpu.Count -gt 0) { [math]::Round([double]$cpu[0].Value, 1) } else { $null }
            return [pscustomobject]@{ Source = 'LibreHardwareMonitor'; CpuCelsius = $cpuCelsius; Rows = $rows; Note = 'Source: LibreHardwareMonitor.' }
        }
        $problems.Add('LibreHardwareMonitor returned no temperature sensors')
    }
    catch { $problems.Add('LibreHardwareMonitor is not available') }

    try {
        $zones = @(Get-CimInstance -Namespace 'root/wmi' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop)
        if ($zones.Count -gt 0) {
            $rows = @($zones | ForEach-Object {
                    [pscustomobject]@{ Sensor = $_.InstanceName; Celsius = [math]::Round(([double]$_.CurrentTemperature / 10) - 273.15, 1) }
                })
            $hottest = ($rows | Measure-Object -Property Celsius -Maximum).Maximum
            return [pscustomobject]@{ Source = 'ACPI'; CpuCelsius = $hottest; Rows = $rows; Note = 'Source: ACPI thermal zone, which is a motherboard reading and may not reflect the CPU die.' }
        }
        $problems.Add('ACPI returned no thermal zones')
    }
    catch { $problems.Add("ACPI thermal zone: $($_.Exception.Message.Trim())") }

    return [pscustomobject]@{ Source = 'None'; CpuCelsius = $null; Rows = @(); Note = "no sensor data ($($problems -join '; '))" }
}

function Get-TemperatureSection {
    [CmdletBinding()]
    param()

    $reading = Get-TemperatureReading
    $status = if ($reading.Source -eq 'None') { 'Unavailable' } else { 'Ok' }
    return New-Section -Title 'Temperatures' -Status $status -Note $reading.Note -Rows @($reading.Rows)
}

function Get-PersistenceData {
    [CmdletBinding()]
    param()

    $entries = New-Object System.Collections.Generic.List[object]
    $problems = New-Object System.Collections.Generic.List[string]
    $add = { param($Kind, $Name, $Command) $entries.Add([pscustomobject]@{ Kind = $Kind; Name = "$Name"; Command = "$Command" }) }

    $runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    foreach ($key in $runKeys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        try {
            $item = Get-Item -LiteralPath $key -ErrorAction Stop
            foreach ($valueName in $item.GetValueNames()) {
                & $add 'Run key' "$($key -replace '^(HK..):.*\\(Run(Once)?)$', '$1 $2') / $valueName" $item.GetValue($valueName)
            }
        }
        catch { $problems.Add("Run key ${key}: $($_.Exception.Message)") }
    }

    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { $problems.Add('Shortcut targets could not be resolved') }
    foreach ($folder in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup')) {
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $target = $file.FullName
            if ($shell -and $file.Extension -eq '.lnk') {
                # CreateShortcut only loads the .lnk here. It is never saved.
                $link = $shell.CreateShortcut($file.FullName)
                $target = "$($link.TargetPath) $($link.Arguments)".Trim()
            }
            & $add 'Startup folder' $file.Name $target
        }
    }

    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and "$($_.Author)" -notmatch '(?i)microsoft' })) {
            $actions = @($task.Actions | ForEach-Object {
                    if ($_.PSObject.Properties['Execute'] -and $_.Execute) { "$($_.Execute) $($_.Arguments)".Trim() } else { 'COM handler' }
                }) -join ' ; '
            $expanded = [Environment]::ExpandEnvironmentVariables($actions)
            $targetMissing = $false
            $companions = @()
            if ($expanded -match '^\s*"?([A-Za-z]:\\[^"]+?\.exe)') {
                $target = $Matches[1]
                if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
                    $targetMissing = $true
                    $folder = Split-Path -Parent $target
                    if (Test-Path -LiteralPath $folder -PathType Container) {
                        $companions = @(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
                    }
                }
            }
            $entries.Add([pscustomobject]@{
                    Kind = 'Scheduled task'; Name = "$($task.TaskPath)$($task.TaskName)"; Command = $expanded
                    TargetMissing = $targetMissing; Companions = $companions
                })
        }
    }
    catch { $problems.Add("Scheduled tasks: $($_.Exception.Message)") }

    try {
        foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            $binary = if ("$($service.PathName)" -match '^\s*"?([A-Za-z]:\\[^"]+?\.exe)') { $Matches[1] } else { $null }
            $company = ''
            if ($binary -and (Test-Path -LiteralPath $binary -PathType Leaf)) {
                try { $company = "$((Get-Item -LiteralPath $binary -ErrorAction Stop).VersionInfo.CompanyName)" } catch { $company = '' }
            }
            if ($company -notmatch '(?i)microsoft') { & $add 'Service' "$($service.Name) [$($service.State)]" $service.PathName }
        }
    }
    catch { $problems.Add("Services: $($_.Exception.Message)") }

    try {
        foreach ($consumer in @(Get-CimInstance -Namespace 'root/subscription' -ClassName __EventConsumer -ErrorAction Stop)) {
            if ($consumer.Name -in 'SCM Event Log Consumer', 'BVTConsumer') { continue }
            $detail = foreach ($property in 'CommandLineTemplate', 'ScriptText', 'ScriptFileName') {
                if ($consumer.CimInstanceProperties[$property] -and $consumer.$property) { $consumer.$property }
            }
            & $add 'WMI subscription' $consumer.Name "$($consumer.CimClass.CimClassName): $($detail -join ' ')"
        }
    }
    catch { $problems.Add("WMI event subscriptions could not be read: $($_.Exception.Message.Trim())") }

    $note = if ($problems.Count -gt 0) { "Incomplete, these sources could not be read: $($problems -join '; ')" } else { '' }
    return [pscustomobject]@{
        Entries = $entries.ToArray()
        Section = New-Section -Title 'Persistence' -Note $note -Rows @($entries | Select-Object Kind, Name, Command)
    }
}

function Get-NetworkData {
    [CmdletBinding()]
    param([object[]] $Processes = @())

    $processById = @{}
    foreach ($process in $Processes) { $processById[[int]$process.Pid] = $process }

    # Names come from the local DNS cache so that the scan generates no network traffic.
    $hostByAddress = @{}
    $notes = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($record in @(Get-DnsClientCache -ErrorAction Stop)) {
            if ($record.Data -and -not $hostByAddress.ContainsKey("$($record.Data)")) { $hostByAddress["$($record.Data)"] = "$($record.Entry)" }
        }
        $notes.Add('Host names come from the local DNS cache, so a blank host means the name was not cached.')
    }
    catch { $notes.Add("DNS cache could not be read: $($_.Exception.Message.Trim())") }

    try {
        $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
                $owner = if ($processById.ContainsKey([int]$_.OwningProcess)) { $processById[[int]$_.OwningProcess] } else { $null }
                [pscustomobject]@{
                    ProcessName   = if ($owner) { $owner.Name } else { 'unknown' }
                    Pid           = [int]$_.OwningProcess
                    RemoteAddress = $_.RemoteAddress
                    RemotePort    = [int]$_.RemotePort
                    RemoteHost    = if ($hostByAddress.ContainsKey("$($_.RemoteAddress)")) { $hostByAddress["$($_.RemoteAddress)"] } else { '' }
                    Path          = if ($owner) { $owner.Path } else { $null }
                }
            })
    }
    catch {
        return [pscustomobject]@{
            Connections = @()
            Section     = New-Section -Title 'Network' -Status 'Unavailable' -Note "TCP connections could not be read: $($_.Exception.Message.Trim())"
        }
    }

    return [pscustomobject]@{
        Connections = $connections
        Section     = New-Section -Title 'Network' -Note ($notes -join ' ') -Rows $connections
    }
}

function Get-DefenderSections {
    [CmdletBinding()]
    param()

    $defenderActive = $false
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $defenderActive = [bool]$status.AntivirusEnabled -and "$($status.AMRunningMode)" -ne 'Not running'
        $fields = 'AMRunningMode', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IsTamperProtected',
        'AntivirusSignatureLastUpdated', 'QuickScanEndTime', 'FullScanEndTime'
        $rows = foreach ($field in $fields) {
            if ($status.PSObject.Properties[$field]) { [pscustomobject]@{ Setting = $field; Value = "$($status.$field)" } }
        }
        New-Section -Title 'Defender status' -Rows @($rows)
    }
    catch { New-Section -Title 'Defender status' -Status 'Unavailable' -Note "Defender status could not be read: $($_.Exception.Message.Trim())" }

    try {
        $detections = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object -Property InitialDetectionTime -Descending | ForEach-Object {
                [pscustomobject]@{
                    Detected  = "$($_.InitialDetectionTime)"
                    ThreatId  = $_.ThreatID
                    Process   = $_.ProcessName
                    Resources = (@($_.Resources) -join '; ')
                    Succeeded = $_.ActionSuccess
                }
            })
        $note = if ($detections.Count -gt 0) { '' }
        elseif ($defenderActive) { 'Defender has no recorded threat detections.' }
        else { 'Defender is not actively scanning, so an empty history is not evidence that this PC is clean. Check the history of the antivirus product in use.' }
        New-Section -Title 'Defender threat history' -Rows $detections -Note $note
    }
    catch { New-Section -Title 'Defender threat history' -Status 'Unavailable' -Note "Threat history could not be read: $($_.Exception.Message.Trim())" }
}

function Get-StartupImpactSection {
    [CmdletBinding()]
    param()

    $directory = Join-Path $env:SystemRoot 'System32\wdi\LogFiles\StartupInfo'
    try {
        $files = @(Get-ChildItem -LiteralPath $directory -Filter '*.xml' -ErrorAction Stop)
        $totals = @{}
        foreach ($file in $files) {
            [xml] $document = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            foreach ($process in @($document.SelectNodes('//Process'))) {
                $name = Split-Path -Leaf "$($process.GetAttribute('Name'))"
                if (-not $name) { continue }
                if (-not $totals.ContainsKey($name)) { $totals[$name] = @{ Cpu = 0.0; Disk = 0.0 } }
                $cpuNode = $process.SelectSingleNode('CpuUsage')
                $diskNode = $process.SelectSingleNode('DiskUsage')
                if ($cpuNode) { $totals[$name].Cpu += [double]$cpuNode.InnerText }
                if ($diskNode) { $totals[$name].Disk += [double]$diskNode.InnerText }
            }
        }
        $rows = @($totals.Keys | ForEach-Object { [pscustomobject]@{ App = $_; CpuUsage = $totals[$_].Cpu; DiskUsage = $totals[$_].Disk } } |
            Sort-Object -Property CpuUsage, DiskUsage -Descending | Select-Object -First 10)
        if ($rows.Count -eq 0) { return New-Section -Title 'Top startup-impact apps' -Status 'Unavailable' -Note 'Windows has not recorded startup-impact data.' }
        return New-Section -Title 'Top startup-impact apps' -Rows $rows -Note 'Totals across the boot records Windows keeps.'
    }
    catch {
        return New-Section -Title 'Top startup-impact apps' -Status 'Unavailable' -Note "Startup-impact data could not be read: $($_.Exception.Message.Trim())"
    }
}

function Get-ContextSections {
    [CmdletBinding()]
    param()

    $rows = New-Object System.Collections.Generic.List[object]
    $plan = (& powercfg.exe /getactivescheme) -join ' '
    $planName = if ($plan -match '\(([^)]+)\)') { $Matches[1] } else { 'unavailable' }
    $rows.Add([pscustomobject]@{ Item = 'Power plan'; Value = $planName })

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $uptime = (Get-Date) - $os.LastBootUpTime
        $rows.Add([pscustomobject]@{ Item = 'Uptime'; Value = ('{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes) })
    }
    catch { $rows.Add([pscustomobject]@{ Item = 'Uptime'; Value = 'unavailable' }) }

    New-Section -Title 'System context' -Rows $rows.ToArray()
    Get-StartupImpactSection
}

Export-ModuleMember -Function Get-CpuByProcessId, Get-ProcessSnapshot, Add-FlagHashes, New-Section, Get-GpuSection, Get-TemperatureReading, Get-TemperatureSection, Get-PersistenceData, Get-NetworkData, Get-DefenderSections, Get-ContextSections
