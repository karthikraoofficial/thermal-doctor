#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only heat and threat scan. Its only write is one report under .\reports.
.PARAMETER SampleSeconds
    How long to sample per-process CPU. Defaults to 60.
#>
[CmdletBinding()]
param([ValidateRange(5, 600)] [int] $SampleSeconds = 60)

$ErrorActionPreference = 'Continue'
Import-Module (Join-Path $PSScriptRoot 'src\Rules.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\Report.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\Collectors.psm1') -Force

Write-Host "Sampling CPU for $SampleSeconds seconds..."
$processes = @(Get-ProcessSnapshot -SampleSeconds $SampleSeconds)
Write-Host 'Reading GPU and temperatures...'
$gpuSection = Get-GpuSection
$temperatureSection = Get-TemperatureSection
Write-Host 'Reading persistence...'
$persistence = Get-PersistenceData
Write-Host 'Reading network connections...'
$network = Get-NetworkData -Processes $processes
Write-Host 'Reading Defender and system context...'
$defenderSections = @(Get-DefenderSections)
$contextSections = @(Get-ContextSections)
$snapshot = [pscustomobject]@{
    Processes   = $processes
    Persistence = @($persistence.Entries)
    Connections = @($network.Connections)
    Sections    = @(@($gpuSection, $temperatureSection, $persistence.Section, $network.Section) + $defenderSections + $contextSections)
}

$flags = @(Get-RedFlags -Snapshot $snapshot)
$flags = @(Add-FlagHashes -Flags $flags)
$report = ConvertTo-ThermalReport -Snapshot $snapshot -Flags $flags

$reportDirectory = Join-Path $PSScriptRoot 'reports'
if (-not (Test-Path -LiteralPath $reportDirectory)) {
    New-Item -ItemType Directory -Path $reportDirectory | Out-Null
}
$reportPath = Join-Path $reportDirectory ("report-{0}.md" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
[IO.File]::WriteAllText($reportPath, $report, (New-Object Text.UTF8Encoding($false)))

Write-Host "Report written to $reportPath"
Write-Output $reportPath
