#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only heat and threat scan. Its only write is one report under .\reports.
.PARAMETER SampleSeconds
    How long to sample per-process CPU. Defaults to 60.
#>
[CmdletBinding()]
param([ValidateRange(5, 600)] [int] $SampleSeconds = 60)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('Thermal Doctor needs Administrator rights. Open PowerShell with "Run as administrator" and run .\examine.ps1 again. Nothing was scanned and no report was written.')
    exit 1
}

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
Write-Host 'Reading antivirus, Defender and system context...'
$antivirus = Get-AntivirusData
$defenderSections = @(Get-DefenderSections)
$contextSections = @(Get-ContextSections)
$snapshot = [pscustomobject]@{
    Processes   = $processes
    Persistence = @($persistence.Entries)
    Connections = @($network.Connections)
    Antivirus   = $antivirus
    Sections    = @(@($gpuSection, $temperatureSection, $persistence.Section, $network.Section, $antivirus.Section) + $defenderSections + $contextSections)
}

$known = Read-KnownFindings -Path (Join-Path $PSScriptRoot 'known-findings.json')
$triage = Split-KnownFindings -Flags @(Get-RedFlags -Snapshot $snapshot) -Snapshot $snapshot -KnownFindings @($known.Findings)
$triageWarning = $known.Warning
if (@($triage.Invalid).Count -gt 0) {
    $triageWarning = "$triageWarning Ignored $(@($triage.Invalid).Count) known-findings entries that lack a name plus a path or product code.".Trim()
}
$flags = @(Add-FlagHashes -Flags @($triage.Active))
$report = ConvertTo-ThermalReport -Snapshot $snapshot -Flags $flags -Triaged @($triage.Triaged) -TriageWarning $triageWarning

$reportDirectory = Join-Path $PSScriptRoot 'reports'
if (-not (Test-Path -LiteralPath $reportDirectory)) {
    New-Item -ItemType Directory -Path $reportDirectory | Out-Null
}
$reportPath = Join-Path $reportDirectory ("report-{0}.md" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
[IO.File]::WriteAllText($reportPath, $report, (New-Object Text.UTF8Encoding($false)))

Write-Host "Report written to $reportPath"
Write-Output $reportPath
