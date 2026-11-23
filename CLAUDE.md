# Thermal Doctor

PowerShell 5.1 diagnostics for a hot Windows PC. See `README.md` for usage and `GLOSSARY.md` for terms.

## Hard rules

- `examine.ps1` is strictly read-only. Its only write is one report under `reports/`.
- `logger.ps1` writes only to its CSV. Never register, change or remove its scheduled task unless the user asks.
- Never kill, quarantine, delete or reconfigure anything on the host. The one exception is `optimize.ps1 -Apply`, run by the user, for actions in `optimize-targets.json`, each confirmed with a typed "yes", logged and reversible through `undo.ps1`.
- `optimize.ps1` previews by default. Never run it with `-Apply` unless the user asks. Anything matching a protected pattern in the targets file must never be changed.
- The scan must generate no network traffic of its own.
- A source that cannot be read is reported as unavailable, never as clean.
- `examine.ps1` requires Administrator rights and exits before scanning without them.
- This repo is public. Never commit `reports/`, `logs/`, `quarantine/`, `known-findings.json`, `optimize-targets.json`, `undo.ps1` or any CSV. Never name the contents of the targets file in issues, docs or fixtures.
- Fixtures are fully synthetic: no real usernames, machine names, paths, IPs or hashes. Use placeholders such as `C:\Users\demo`, and documentation IP ranges.
- Commits use the repo-local GitHub noreply email.

## Commands

```powershell
.\examine.ps1  # from an elevated PowerShell
.\logger.ps1
.\optimize.ps1  # preview only; -Apply needs an elevated PowerShell
Import-Module Pester -RequiredVersion 3.4.0; Invoke-Pester -Script .\tests
```

## Testing

Test at three seams only: rules + report (snapshot in, flags and Markdown out), logger CSV rows, and optimizer plan (state in, plan and undo script out). Live collectors are verified by a real read-only run.

## Agent skills

### Issue tracker

GitHub Issues on this repo, with a GitHub Projects board. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` plus `docs/adr/`. See `docs/agents/domain.md`.
