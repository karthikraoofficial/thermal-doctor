Set-StrictMode -Version 2.0

$script:KnownMiners = @('xmrig', 'nicehash', 'phoenixminer', 't-rex', 'lolminer', 'nbminer', 'gminer')

$script:UserWritablePathPattern = '(?i)\\(AppData|Temp|ProgramData|Users\\Public)\\'

$script:SystemProcessNames = @('svchost', 'csrss', 'lsass', 'conhost', 'dllhost')

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

function Get-RedFlags {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Snapshot)

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
