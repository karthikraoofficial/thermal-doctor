# Thermal Doctor

Windows diagnostics for finding out why a PC is running hot, and whether something unwanted, such as a cryptominer, is involved, plus an opt-in optimizer for reducing heat.

- `examine.ps1` is read-only. It scans the system and writes one Markdown report to `reports\report-<timestamp>.md`.
- `logger.ps1` appends one heat sample to `logs\heat-log.csv`. A scheduled task can run it every 2 minutes.
- `optimize.ps1` previews heat-reduction changes and applies them only with `-Apply` and a typed "yes" per action.

Requires Windows PowerShell 5.1. Tests use Pester 3.4.

## Run a scan

Open PowerShell with **Run as administrator**, then run:

```powershell
.\examine.ps1
```

Without Administrator rights the scan exits with a message before reading anything and writes no report. The report still says when a source could not be read. Missing data is never treated as a clean result.

The scan takes a little over a minute. The report opens with **Red flags** ranked High, Medium, Low and Info, then any **Previously triaged** items, then **Top heat contributors**, then the raw data.

A red flag is a prompt to investigate, not proof of compromise. Repeated flags for one executable are collapsed into a single line with a process count.

- Scheduled tasks that point to a missing executable in a user-writable folder are High, along with any executables left in that folder.
- AppData processes validly signed by Microsoft, Google, GitHub, Anthropic, OpenAI, Docker or Astral are Info. The publisher comes from the signing certificate, not the file's company field.
- Programs in uv and Python `Scripts` folders under AppData are Info, unless they are unsigned and above 10% CPU.
- Browsers launched with a URL at a bare IPv4 address, `sslip.io` or `nip.io` are Medium. Loopback is excluded.
- Defender being off is Medium only when Security Center lists no other antivirus.

Startup shortcuts installed by MSI are shown with their owning product, publisher and install date. Network rows are grouped by process and remote IP with a connection count.

### Known findings

Items you have already investigated go in `known-findings.json` in the project folder. This file is gitignored.

```json
{
  "findings": [
    {
      "title": "Demo driver issue",
      "note": "Known vendor bug",
      "match": { "name": "demo-host", "path": "C:\\Windows\\System32\\demo-host.exe" }
    },
    {
      "title": "Demo OEM shortcut",
      "note": "OEM bloat",
      "match": { "name": "Demo.lnk", "productCode": "{11111111-2222-4333-8444-555555555555}" }
    }
  ]
}
```

Each match needs a name plus a path or MSI product code, so a lookalike with the same name stays flagged. If the file cannot be read, nothing is marked as triaged and the report says so.

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

Each row includes `CpuPackageTempC`, from LibreHardwareMonitor only, and `Flag`, which names TiWorker, MoUsoCoreWorker, TrustedInstaller or SearchIndexer above 5% CPU. LibreHardwareMonitor must be running with its WMI namespace available, otherwise the temperature stays blank. A log with the older columns is left untouched and new rows go to `heat-log-v2.csv`.

## Optimizer

Copy `optimize-targets.example.json` to `optimize-targets.json` and list your targets and protected items. That file is gitignored.

```powershell
.\optimize.ps1          # preview, changes nothing
.\optimize.ps1 -WhatIf  # same
.\optimize.ps1 -Apply   # from an elevated PowerShell, asks for "yes" per action
.\undo.ps1              # from an elevated PowerShell, reverses applied actions
```

Outcomes go to `logs\actions.log`. An earlier `undo.ps1` is moved to `logs\` rather than overwritten. WSL limits take effect after `wsl --shutdown`, which stops running distros and Docker. Apps on the uninstall list are printed and never removed.

The 99% processor cap stops turbo boost. On low-power laptop CPUs this can cut single-core speed sharply, so check that the machine still feels fast enough.

## Privacy

Reports and logs contain process command lines, file paths and network details. `reports/`, `logs/`, `quarantine/`, `known-findings.json`, `optimize-targets.json`, `undo.ps1` and all CSV files are gitignored. Do not publish them.

## Tests

```powershell
Import-Module Pester -RequiredVersion 3.4.0
Invoke-Pester -Script .\tests
```
