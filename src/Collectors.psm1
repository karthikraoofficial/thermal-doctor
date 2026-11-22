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
            try { $cache[$flag.Path] = (Get-FileHash -LiteralPath $flag.Path -Algorithm SHA256 -ErrorAction Stop).Hash }
            catch { $cache[$flag.Path] = 'unavailable (file could not be read)' }
        }
        $flag.Sha256 = $cache[$flag.Path]
    }
    return $Flags
}

Export-ModuleMember -Function Get-ProcessSnapshot, Add-FlagHashes
