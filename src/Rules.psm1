Set-StrictMode -Version 2.0

$script:KnownMiners = @('xmrig', 'nicehash', 'phoenixminer', 't-rex', 'lolminer', 'nbminer', 'gminer')

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
    }
}

Export-ModuleMember -Function Get-RedFlags
