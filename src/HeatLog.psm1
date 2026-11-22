Set-StrictMode -Version 2.0

function Format-HeatNumber {
    param($Value)

    if ($null -eq $Value) { return '' }
    return ([double]$Value).ToString('0.##', [Globalization.CultureInfo]::InvariantCulture)
}

function Add-HeatLogRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [datetime] $Timestamp,
        [AllowNull()] $CpuCelsius,
        [Parameter(Mandatory)] [double] $TotalCpuPercent,
        [AllowEmptyCollection()] [object[]] $TopProcesses = @()
    )

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

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [pscustomobject]$row | Export-Csv -LiteralPath $Path -Append -NoTypeInformation -Encoding UTF8
}

Export-ModuleMember -Function Add-HeatLogRow
