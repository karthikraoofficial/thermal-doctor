# Thermal Doctor

PowerShell 5.1 diagnostics for a hot Windows PC. See `README.md` for usage and `GLOSSARY.md` for terms.

## Hard rules

- `examine.ps1` is strictly read-only. Its only write is one report under `reports/`.
- `logger.ps1` writes only to its CSV. Never register, change or remove its scheduled task unless the user asks.
- Never kill, quarantine, delete or reconfigure anything on the host.
- The scan must generate no network traffic of its own.
- A source that cannot be read is reported as unavailable, never as clean.
- `examine.ps1` requires Administrator rights and exits before scanning without them.
- This repo is public. Never commit `reports/`, `logs/`, `quarantine/`, `known-findings.json` or any CSV.
- Fixtures are fully synthetic: no real usernames, machine names, paths, IPs or hashes. Use placeholders such as `C:\Users\demo`, and documentation IP ranges.
- Commits use the repo-local GitHub noreply email.

## Commands

```powershell
.\examine.ps1  # from an elevated PowerShell
.\logger.ps1
Import-Module Pester -RequiredVersion 3.4.0; Invoke-Pester -Script .\tests
```

## Testing

Test at two seams only: rules + report (snapshot in, flags and Markdown out) and logger CSV rows. Live collectors are verified by a real read-only run.

## Agent skills

### Issue tracker

GitHub Issues on this repo, with a GitHub Projects board. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` plus `docs/adr/`. See `docs/agents/domain.md`.
