Set-StrictMode -Version 2.0

$script:KnownMiners = @('xmrig', 'nicehash', 'phoenixminer', 't-rex', 'lolminer', 'nbminer', 'gminer')

$script:UserWritablePathPattern = '(?i)\\(AppData|Temp|ProgramData|Users\\Public)\\'

$script:SystemProcessNames = @('svchost', 'csrss', 'lsass', 'conhost', 'dllhost')
$script:MiningPorts = @(3333, 4444, 5555, 7777, 8888, 14444, 45700)
$script:BrowserNames = @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi', 'iexplore')

# PowerShell accepts abbreviated parameters, so -e, -ec, -enc and -w are all live forms.
$script:EncodedCommandPattern = '(?i)(^|\s)[-/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+\S'
$script:HiddenWindowPattern = '(?i)(^|\s)[-/]w[a-z]*\s+["'']?hidden'
# Everything after -Command or -File belongs to the script, not to powershell.exe.
$script:ScriptArgumentPattern = '(?i)\s[-/](c|co|com|comm|comma|comman|command|f|fi|fil|file)(\s|$)'

function Get-PowerShellHostArguments {
    param([string] $CommandLine)

    $match = [regex]::Match($CommandLine, $script:ScriptArgumentPattern)
    if ($match.Success) { return $CommandLine.Substring(0, $match.Index) }
    return $CommandLine
}

# Compared with the signing certificate's organisation after removing punctuation and case.
$script:TrustedPublishers = @(
    'microsoft corporation', 'google llc', 'github inc', 'anthropic pbc', 'anthropic inc',
    'openai opco llc', 'openai llc', 'openai inc', 'docker inc', 'astral software inc'
)
$script:UserAppDataPattern = '(?i)^[A-Za-z]:\\Users\\[^\\]+\\AppData\\'
$script:ToolCachePattern = '(?i)^[A-Za-z]:\\Users\\[^\\]+\\AppData\\((Local|Roaming)\\uv\\|(Roaming|Local\\Programs)\\Python\\Python\d+[^\\]*\\Scripts\\)'

function Get-SignerOrganization {
    param([string] $Subject)

    $match = [regex]::Match($Subject, '(?:^|,\s*)O=(?:"((?:[^"]|"")*)"|([^,]+))')
    if (-not $match.Success) { return '' }
    if ($match.Groups[1].Success) { return $match.Groups[1].Value.Replace('""', '"').Trim() }
    return $match.Groups[2].Value.Trim()
}

function Get-UserWritableAssessment {
    param($Process)

    $medium = [pscustomobject]@{ Severity = 'Medium'; Detail = '' }
    $path = "$($Process.Path)"
    if ($path -notmatch $script:UserAppDataPattern) { return $medium }

    $signerProperty = $Process.PSObject.Properties['Signer']
    $organization = if ($signerProperty) { Get-SignerOrganization -Subject "$($signerProperty.Value)" } else { '' }
    $normalized = (($organization.ToLowerInvariant() -replace '[.,]', '') -replace '\s+', ' ').Trim()
    if ($Process.Signature -eq 'Valid' -and $script:TrustedPublishers -contains $normalized) {
        return [pscustomobject]@{ Severity = 'Info'; Detail = ", validly signed by $organization" }
    }

    if ($path -match $script:ToolCachePattern) {
        $unverified = $Process.Signature -in 'NotSigned', 'Unknown'
        if ($Process.Signature -eq 'Valid' -or ($unverified -and [double]$Process.CpuPercent -le 10)) {
            return [pscustomobject]@{ Severity = 'Info'; Detail = ', an allowlisted Python tool location' }
        }
    }
    return $medium
}

function Get-BrowserRawHosts {
    param([string] $CommandLine)

    # Child processes carry internal switches. Only the launched browser's URL is of interest.
    if ($CommandLine -match '(?i)(^|\s)--type=') { return }
    $found = foreach ($match in [regex]::Matches($CommandLine, '(?i)\bhttps?://[^\s"''<>]+')) {
        $uri = $null
        if (-not [Uri]::TryCreate($match.Value, [UriKind]::Absolute, [ref] $uri)) { continue }
        $urlHost = $uri.Host.TrimEnd('.').ToLowerInvariant()
        if ($uri.HostNameType -eq 'IPv4') {
            if ($urlHost -notmatch '^127\.') { $urlHost }
        }
        elseif ($urlHost -match '(^|\.)(sslip|nip)\.io$') { $urlHost }
    }
    @($found | Select-Object -Unique)
}

function Test-LnkHasDarwinId {
    [CmdletBinding()]
    param([AllowNull()] [byte[]] $Bytes)

    # Shell Link header: size 0x4C at offset 0, LinkFlags at 0x14, HasDarwinID is bit 0x1000.
    if ($null -eq $Bytes -or $Bytes.Length -lt 0x4C) { return $false }
    if ([BitConverter]::ToUInt32($Bytes, 0) -ne 0x4C) { return $false }
    return [bool]([BitConverter]::ToUInt32($Bytes, 0x14) -band 0x1000)
}

function Resolve-AdvertisedShortcut {
    [CmdletBinding()]
    param([string] $Target, [hashtable] $Products = @{})

    if ($Target -notmatch '(?i)^[A-Za-z]:\\Windows\\Installer\\(\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\})\\') { return $null }
    $productCode = $Matches[1].ToUpperInvariant()
    if (-not $Products.ContainsKey($productCode)) {
        return [pscustomobject]@{ ProductCode = $productCode; Command = "MSI advertised shortcut: product $productCode is not in the Uninstall registry keys" }
    }

    $product = $Products[$productCode]
    $publisher = if ($product.Publisher) { $product.Publisher } else { 'unknown publisher' }
    $installed = "$($product.InstallDate)"
    if ($installed -match '^(\d{4})(\d{2})(\d{2})$') { $installed = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
    elseif (-not $installed) { $installed = 'unknown date' }
    return [pscustomobject]@{
        ProductCode = $productCode
        Command     = "MSI advertised shortcut: $($product.DisplayName), publisher $publisher, installed $installed, product $productCode"
    }
}

function ConvertFrom-AvProductState {
    [CmdletBinding()]
    param([int] $ProductState)

    $state = switch ($ProductState -band 0xF000) {
        0x0000 { 'Off' }
        0x1000 { 'On' }
        0x2000 { 'Snoozed' }
        0x3000 { 'Expired' }
        default { 'Unknown' }
    }
    $definitions = switch ($ProductState -band 0x00F0) {
        0x00 { 'Up to date' }
        0x10 { 'Out of date' }
        default { 'Unknown' }
    }
    [pscustomobject]@{ State = $state; Definitions = $definitions }
}

function Get-AntivirusFlags {
    param($Antivirus)

    if (-not $Antivirus.Available -or $Antivirus.DefenderActive -ne $false) { return }
    $others = @($Antivirus.Products | Where-Object { $_.Name -notmatch '(?i)^(windows|microsoft) defender' })
    if ($others.Count -gt 0) { return }
    $subject = [pscustomobject]@{ Name = 'Windows Defender'; Pid = $null; Path = $null; Sha256 = $null }
    New-RedFlag -Severity 'Medium' -Rule 'DefenderOff' -Process $subject -Reason 'Defender is off and no other antivirus is registered'
}

function Group-NetworkConnections {
    [CmdletBinding()]
    param([AllowEmptyCollection()] [object[]] $Connections = @())

    $groups = @($Connections | Group-Object -Property { "$($_.ProcessName)|$($_.Path)|$($_.RemoteAddress)" })
    $rows = foreach ($group in $groups) {
        $first = $group.Group[0]
        $hostNames = @($group.Group | ForEach-Object { "$($_.RemoteHost)" } | Where-Object { $_ } | Select-Object -Unique)
        [pscustomobject]@{
            ProcessName   = $first.ProcessName
            Pids          = (@($group.Group | ForEach-Object { [int]$_.Pid } | Sort-Object -Unique) -join ', ')
            RemoteAddress = $first.RemoteAddress
            RemotePorts   = (@($group.Group | ForEach-Object { [int]$_.RemotePort } | Sort-Object -Unique) -join ', ')
            RemoteHost    = ($hostNames -join ', ')
            Connections   = $group.Count
            Path          = $first.Path
        }
    }
    @($rows | Sort-Object -Property @{ Expression = 'Connections'; Descending = $true }, ProcessName, RemoteAddress)
}

function Get-OptionalValue {
    param($Object, [string] $Name)

    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Split-KnownFindings {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] [object[]] $Flags = @(),
        [Parameter(Mandatory)] $Snapshot,
        [AllowEmptyCollection()] [object[]] $KnownFindings = @()
    )

    $processes = @(Get-OptionalValue $Snapshot 'Processes')
    $entries = @(Get-OptionalValue $Snapshot 'Persistence')
    $claimed = @{}
    $triaged = New-Object System.Collections.Generic.List[object]
    $invalid = New-Object System.Collections.Generic.List[object]

    foreach ($known in $KnownFindings) {
        $match = Get-OptionalValue $known 'Match'
        $name = "$(Get-OptionalValue $match 'Name')"
        $path = "$(Get-OptionalValue $match 'Path')"
        $productCode = "$(Get-OptionalValue $match 'ProductCode')"
        # A name alone would also hide a lookalike binary.
        if (-not $name -or (-not $path -and -not $productCode)) { $invalid.Add($known); continue }

        $flagNames = @($name)
        $observed = 0
        if ($productCode) {
            $hits = @($entries | Where-Object { $_ -and $_.Name -eq $name -and "$(Get-OptionalValue $_ 'ProductCode')" -eq $productCode })
            $observed = $hits.Count
            $flagNames = @($hits | ForEach-Object { "$($_.Kind): $($_.Name)" })
        }
        else {
            $observed = @($processes | Where-Object { $_ -and $_.Name -eq $name -and "$($_.Path)" -eq $path }).Count
        }

        $severities = New-Object System.Collections.Generic.List[string]
        for ($index = 0; $index -lt $Flags.Count; $index++) {
            $flag = $Flags[$index]
            if ($flagNames -notcontains $flag.Name) { continue }
            if (-not $productCode -and "$($flag.Path)" -ne $path) { continue }
            $claimed[$index] = $true
            $severities.Add($flag.Severity)
        }
        if ($observed -eq 0 -and $severities.Count -eq 0) { continue }

        $wouldBe = 'Not flagged'
        foreach ($severity in 'High', 'Medium', 'Low', 'Info') {
            if ($severities -contains $severity) { $wouldBe = $severity; break }
        }
        $triaged.Add([pscustomobject]@{
                Title = "$(Get-OptionalValue $known 'Title')"
                Note = "$(Get-OptionalValue $known 'Note')"
                WouldBe = $wouldBe
                Item = $name
            })
    }

    $active = New-Object System.Collections.Generic.List[object]
    for ($index = 0; $index -lt $Flags.Count; $index++) {
        if (-not $claimed.ContainsKey($index)) { $active.Add($Flags[$index]) }
    }
    [pscustomobject]@{ Active = $active.ToArray(); Triaged = $triaged.ToArray(); Invalid = $invalid.ToArray() }
}

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

    $hostArguments = Get-PowerShellHostArguments -CommandLine $command
    if ($lowered -match '(powershell|pwsh)' -and ($hostArguments -match $script:EncodedCommandPattern -or $hostArguments -match $script:HiddenWindowPattern)) {
        New-RedFlag -Severity 'High' -Rule 'PersistencePowerShell' -Process $subject -Reason 'Starts PowerShell automatically with an encoded command or hidden window'
    }

    $targetMissing = $Entry.PSObject.Properties['TargetMissing'] -and $Entry.TargetMissing
    if ($targetMissing -and $executable -match $script:UserWritablePathPattern) {
        New-RedFlag -Severity 'High' -Rule 'OrphanedTask' -Process $subject -Reason 'Scheduled task points to a missing executable in a user-writable location, a common remnant of removed malware'
        if ($Entry.PSObject.Properties['Companions']) {
            foreach ($companion in @($Entry.Companions)) {
                $companionSubject = [pscustomobject]@{ Name = (Split-Path -Leaf $companion); Pid = $null; Path = $companion; Sha256 = $null }
                New-RedFlag -Severity 'High' -Rule 'OrphanedTaskCompanion' -Process $companionSubject -Reason "Executable left in the folder of orphaned task '$($Entry.Name)'"
            }
        }
        return
    }

    $launchTarget = if ($executable) { $executable } else { $command }
    if ($launchTarget -match '(?i)\\(Temp|Users\\Public)\\') {
        New-RedFlag -Severity 'Medium' -Rule 'PersistenceRiskyPath' -Process $subject -Reason "Starts automatically from '$($Matches[1])'"
    }
    elseif ($launchTarget -match '(?i)\\(AppData|ProgramData)\\') {
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

    $flags = @(Get-UngroupedFlags -Snapshot $Snapshot)
    $seen = @{}
    $grouped = New-Object System.Collections.Generic.List[object]
    foreach ($flag in $flags) {
        if ($null -eq $flag.Pid -or -not $flag.Path -or $flag.Rule -in 'MiningPort', 'MiningHost', 'BrowserRawHost') {
            $grouped.Add($flag)
            continue
        }
        $key = "$($flag.Rule)|$($flag.Severity)|$($flag.Path.ToLowerInvariant())"
        if ($seen.ContainsKey($key)) { $seen[$key].Count++; continue }
        $seen[$key] = @{ Flag = $flag; Count = 1 }
        $grouped.Add($flag)
    }
    foreach ($entry in $seen.Values) {
        if ($entry.Count -gt 1) { $entry.Flag.Reason = "$($entry.Flag.Reason) ($($entry.Count) processes)" }
    }
    return $grouped.ToArray()
}

function Get-UngroupedFlags {
    param($Snapshot)

    $antivirus = $Snapshot.PSObject.Properties['Antivirus']
    if ($antivirus -and $antivirus.Value) { Get-AntivirusFlags -Antivirus $antivirus.Value }

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
            $location = $Matches[1]
            $assessment = Get-UserWritableAssessment -Process $process
            New-RedFlag -Severity $assessment.Severity -Rule 'UserWritablePath' -Process $process -Reason "Running from user-writable location '$location'$($assessment.Detail)"
        }

        $baseName = "$($process.Name)" -replace '(?i)\.exe$', ''

        if ($script:BrowserNames -contains $baseName.ToLowerInvariant()) {
            foreach ($rawHost in @(Get-BrowserRawHosts -CommandLine "$($process.CommandLine)")) {
                New-RedFlag -Severity 'Medium' -Rule 'BrowserRawHost' -Process $process -Reason "Browser launched with a URL at raw or wildcard-DNS host '$rawHost'"
            }
        }

        if ($process.Signature -eq 'NotSigned' -and [double]$process.CpuPercent -gt 10) {
            New-RedFlag -Severity 'Medium' -Rule 'UnsignedHighCpu' -Process $process -Reason "Unsigned binary using $($process.CpuPercent)% CPU"
        }

        if ($baseName -match '(?i)^(powershell|pwsh)$') {
            $commandLine = Get-PowerShellHostArguments -CommandLine "$($process.CommandLine)"
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

Export-ModuleMember -Function Get-RedFlags, Test-LnkHasDarwinId, Resolve-AdvertisedShortcut, ConvertFrom-AvProductState, Group-NetworkConnections, Split-KnownFindings
