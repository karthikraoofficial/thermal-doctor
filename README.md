# Thermal Doctor

Read-only Windows diagnostics for finding out why a PC is running hot, and whether something unwanted, such as a cryptominer, is involved.

- `examine.ps1` scans the system and writes one Markdown report to `reports\report-<timestamp>.md`.
- `logger.ps1` appends one heat sample to `logs\heat-log.csv`. A scheduled task can run it every 2 minutes.

Requires Windows PowerShell 5.1. Tests use Pester 3.4.

## Run a scan

```powershell
.\examine.ps1
```

The scan takes a little over a minute. The report opens with **Red flags** ranked High, Medium and Low, then **Top heat contributors**, then the raw data.

A red flag is a prompt to investigate, not proof of compromise. Developer tools and legitimate apps can match path and network rules.

### Run as administrator for full coverage

The scan works without admin rights, but Windows then withholds some data:

- Paths, signatures and hashes of protected processes
- ACPI temperatures
- Startup-impact data

The report says when a source could not be read. Missing data is never treated as a clean result.

### Temperatures

The scan uses LibreHardwareMonitor's WMI namespace if it is available, then ACPI thermal zones. If neither can be read, the report says "no sensor data".

## Heat logger

Run these from the project folder to sample every 2 minutes:

```powershell
$root = (Get-Location).Path
$action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument "--headless powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File `"$root\logger.ps1`"" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'Thermal Doctor Logger' -Action $action -Trigger $trigger -Settings $settings -Description 'Appends a heat sample to logs\heat-log.csv'
```

Remove it later:

```powershell
Unregister-ScheduledTask -TaskName 'Thermal Doctor Logger' -Confirm:$false
```

Removing the task keeps the existing CSV.

## Privacy

Reports and logs contain process command lines, file paths and network details. `reports/`, `logs/`, `quarantine/` and all CSV files are gitignored. Do not publish them.

## Tests

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester -Script .\tests
```
