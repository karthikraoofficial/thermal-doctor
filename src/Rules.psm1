Set-StrictMode -Version 2.0

$script:KnownMiners = @('xmrig', 'nicehash', 'phoenixminer', 't-rex', 'lolminer', 'nbminer', 'gminer')

$script:UserWritablePathPattern = '(?i)\\(AppData|Temp|ProgramData|Users\\Public)\\'

$script:SystemProcessNames = @('svchost', 'csrss', 'lsass', 'conhost', 'dllhost')
$script:MiningPorts = @(3333, 4444, 5555, 7777, 8888, 14444, 45700)

# PowerShell accepts abbreviated parameters, so -e, -ec, -enc and -w are all live forms.
$script:EncodedCommandPattern = '(?i)(^|\s)[-/](e|ec|en[a-z]*)\s+\S'
$script:HiddenWindowPattern = '(?i)(^|\s)[-/]w[a-z]*\s+["'']?hidden'

function New-RedFlag {
    param($Severity, $Rule, $Process, $Reason)

    [pscustomobject]@{
        Severity = $Severity
        Rule     = $Rule
        Name     = $Process.Name
        Pid      = $Process.Pid
        Path     = $Process.Path
        Sha256   = $Process.Sha256
        Reason   = $Reason
    }
}

function Get-PersistenceFlags {
    param($Entry)

    $command = "$($Entry.Command)"
    $lowered = $command.ToLowerInvariant()
    $executable = if ($command -match '^\s*"?([A-Za-z]:\\[^"]+?\.exe)') { $Matches[1] } else { $null }
    $subject = [pscustomobject]@{ Name = "$($Entry.Kind): $($Entry.Name)"; Pid = $null; Path = $executable; Sha256 = $null }

    if ($Entry.Kind -eq 'WMI subscription') {
        New-RedFlag -Severity 'Medium' -Rule 'WmiSubscription' -Process $subject -Reason 'WMI event subscriptions are rare and can run code silently'
        return
    }

    $miner = $script:KnownMiners | Where-Object { $lowered.Contains($_) } | Select-Object -First 1
    if ($miner) {
        New-RedFlag -Severity 'High' -Rule 'PersistenceMiner' -Process $subject -Reason "Starts automatically and matches known miner name '$miner'"
    }

    if ($lowered -match '(powershell|pwsh)' -and ($command -match $script:EncodedCommandPattern -or $command -match $script:HiddenWindowPattern)) {
        New-RedFlag -Severity 'High' -Rule 'PersistencePowerShell' -Process $subject -Reason 'Starts PowerShell automatically with an encoded command or hidden window'
    }

    if ($command -match '(?i)\\(Temp|Users\\Public)\\') {
        New-RedFlag -Severity 'Medium' -Rule 'PersistenceRiskyPath' -Process $subject -Reason "Starts automatically from '$($Matches[1])'"
    }
    elseif ($command -match '(?i)\\(AppData|ProgramData)\\') {
        New-RedFlag -Severity 'Low' -Rule 'PersistenceRiskyPath' -Process $subject -Reason "Starts automatically from '$($Matches[1])', where many apps legitimately install"
    }
}

function Get-ConnectionFlags {
    param($Connection)

    $address = "$($Connection.RemoteAddress)"
    if ($address -match '^(127\.|::1$|::ffff:127\.)') { return }

    $subject = [pscustomobject]@{ Name = $Connection.ProcessName; Pid = $Connection.Pid; Path = $Connection.Path; Sha256 = $null }
    $endpoint = "${address}:$($Connection.RemotePort)"

    if ($script:MiningPorts -contains [int]$Connection.RemotePort) {
        New-RedFlag -Severity 'Medium' -Rule 'MiningPort' -Process $subject -Reason "Connected to $endpoint, a port commonly used by miners or remote shells"
    }

    $remoteHost = "$($Connection.RemoteHost)".ToLowerInvariant()
    if ($remoteHost -match '(xmr|nicehash)') {
        New-RedFlag -Severity 'High' -Rule 'MiningHost' -Process $subject -Reason "Connected to '$remoteHost' ($endpoint), which contains '$($Matches[1])'"
    }
    elseif ($remoteHost -match '(pool|mine)') {
        New-RedFlag -Severity 'Medium' -Rule 'MiningHost' -Process $subject -Reason "Connected to '$remoteHost' ($endpoint), which contains '$($Matches[1])'"
    }
}

function Get-RedFlags {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot)

    $connections = $Snapshot.PSObject.Properties['Connections']
    if ($connections) {
        foreach ($connection in @($connections.Value)) { Get-ConnectionFlags -Connection $connection }
    }

    $persistence = $Snapshot.PSObject.Properties['Persistence']
    if ($persistence) {
        foreach ($entry in @($persistence.Value)) { Get-PersistenceFlags -Entry $entry }
    }

    foreach ($process in @($Snapshot.Processes)) {
        $identity = "$($process.Name) $($process.Path)".ToLowerInvariant()
        $miner = $script:KnownMiners | Where-Object { $identity.Contains($_) } | Select-Object -First 1
        if ($miner) {
            New-RedFlag -Severity 'High' -Rule 'KnownMiner' -Process $process -Reason "Matches known miner name '$miner'"
        }

        if ("$($process.Path)" -match $script:UserWritablePathPattern) {
            New-RedFlag -Severity 'Medium' -Rule 'UserWritablePath' -Process $process -Reason "Running from user-writable location '$($Matches[1])'"
        }

        $baseName = "$($process.Name)" -replace '(?i)\.exe$', ''

        if ($process.Signature -eq 'NotSigned' -and [double]$process.CpuPercent -gt 10) {
            New-RedFlag -Severity 'Medium' -Rule 'UnsignedHighCpu' -Process $process -Reason "Unsigned binary using $($process.CpuPercent)% CPU"
        }

        if ($baseName -match '(?i)^(powershell|pwsh)$') {
            $commandLine = "$($process.CommandLine)"
            if ($commandLine -match $script:EncodedCommandPattern) {
                New-RedFlag -Severity 'High' -Rule 'SuspiciousPowerShell' -Process $process -Reason 'PowerShell launched with an encoded command'
            }
            elseif ($commandLine -match $script:HiddenWindowPattern) {
                New-RedFlag -Severity 'High' -Rule 'SuspiciousPowerShell' -Process $process -Reason 'PowerShell launched with a hidden window'
            }
        }

        # An empty path means Windows withheld it from a non-admin scan, which is not evidence of impersonation.
        if ($script:SystemProcessNames -contains $baseName.ToLowerInvariant() -and $process.Path -and
            $process.Path -notmatch '(?i)^C:\\Windows\\System32\\') {
            if ($process.Path -match '(?i)^C:\\Windows\\SysWOW64\\') {
                New-RedFlag -Severity 'Low' -Rule 'SystemNameMisplaced' -Process $process -Reason "System process name '$baseName' running from SysWOW64, which is normal for 32-bit hosts"
            }
            else {
                New-RedFlag -Severity 'High' -Rule 'SystemNameMisplaced' -Process $process -Reason "System process name '$baseName' running outside System32"
            }
        }
    }
}

Export-ModuleMember -Function Get-RedFlags
