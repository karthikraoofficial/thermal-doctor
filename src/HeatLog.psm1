Set-StrictMode -Version 2.0

function Format-HeatNumber {
    param($Value)

    if ($null -eq $Value) { return '' }
    return ([double]$Value).ToString('0.##', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-HeatFlag {
    [CmdletBinding()]
    param([AllowEmptyCollection()] [object[]] $Processes = @())

    $flags = foreach ($watched in 'TiWorker', 'MoUsoCoreWorker', 'TrustedInstaller', 'SearchIndexer') {
        $matching = @($Processes | Where-Object { $_.Name -ieq $watched })
        if ($matching.Count -eq 0) { continue }
        $total = ($matching | Measure-Object -Property CpuPercent -Sum).Sum
        if ($total -gt 5) { "$watched ($(Format-HeatNumber $total)%)" }
    }
    return (@($flags) -join '; ')
}

function Resolve-HeatLogPath {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    $header = Get-Content -LiteralPath $Path -TotalCount 1
    if ($header -match '"Flag"') { return $Path }
    # Export-Csv cannot add columns to an existing file, so older logs stay untouched.
    $directory = Split-Path -Parent $Path
    $name = [IO.Path]::GetFileNameWithoutExtension($Path) + '-v2' + [IO.Path]::GetExtension($Path)
    if ($directory) { return (Join-Path $directory $name) }
    return $name
}

function Add-HeatLogRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [datetime] $Timestamp,
        [AllowNull()] $CpuCelsius,
        [AllowNull()] $CpuPackageCelsius = $null,
        [Parameter(Mandatory)] [double] $TotalCpuPercent,
        [AllowEmptyCollection()] [object[]] $TopProcesses = @(),
        [AllowEmptyString()] [string] $Flag = ''
    )

    $Path = Resolve-HeatLogPath $Path

    $row = [ordered]@{
        Timestamp       = $Timestamp.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
        CpuTempC        = Format-HeatNumber $CpuCelsius
        TotalCpuPercent = Format-HeatNumber $TotalCpuPercent
    }
    for ($index = 0; $index -lt 5; $index++) {
        $row["Top$($index + 1)"] = if ($index -lt $TopProcesses.Count) {
            "$($TopProcesses[$index].Name) ($(Format-HeatNumber $TopProcesses[$index].CpuPercent)%)"
        }
        else { '' }
    }
    $row['CpuPackageTempC'] = Format-HeatNumber $CpuPackageCelsius
    $row['Flag'] = $Flag

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [pscustomobject]$row | Export-Csv -LiteralPath $Path -Append -NoTypeInformation -Encoding UTF8
}

Export-ModuleMember -Function Add-HeatLogRow, Get-HeatFlag
