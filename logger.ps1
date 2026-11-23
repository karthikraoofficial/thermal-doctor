#Requires -Version 5.1
<#
.SYNOPSIS
    Appends one heat sample to the log. The scheduled task runs this every 2 minutes.
.PARAMETER LogPath
    CSV file to append to. Defaults to .\logs\heat-log.csv beside this script.
#>
[CmdletBinding()]
param([string] $LogPath = (Join-Path $PSScriptRoot 'logs\heat-log.csv'))

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\Collectors.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src\HeatLog.psm1') -Force

$timestamp = Get-Date
$cpuById = Get-CpuByProcessId -SampleSeconds 5
$totalSamples = @(Get-Counter -Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3)
$totalCpu = ($totalSamples | ForEach-Object { $_.CounterSamples[0].CookedValue } | Measure-Object -Average).Average

$namesById = @{}
foreach ($process in Get-Process) { $namesById[[int]$process.Id] = $process.ProcessName }
$top = @($cpuById.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5 | ForEach-Object {
        [pscustomobject]@{
            Name       = if ($namesById.ContainsKey([int]$_.Key)) { $namesById[[int]$_.Key] } else { "exited ($($_.Key))" }
            CpuPercent = $_.Value
        }
    })

$sampled = @($cpuById.GetEnumerator() | Where-Object { $namesById.ContainsKey([int]$_.Key) } | ForEach-Object {
        [pscustomobject]@{ Name = $namesById[[int]$_.Key]; CpuPercent = $_.Value }
    })
$flag = Get-HeatFlag -Processes $sampled

$temperature = Get-TemperatureReading
$package = Get-CpuPackageTemperature
Add-HeatLogRow -Path $LogPath -Timestamp $timestamp -CpuCelsius $temperature.CpuCelsius -CpuPackageCelsius $package -TotalCpuPercent $totalCpu -TopProcesses $top -Flag $flag
