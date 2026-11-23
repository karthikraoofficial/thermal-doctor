# Glossary

**Snapshot**: The plain data collected from one scan. Rules and the report work from it without touching the live system.

**Collector**: Code that reads one area of the live system and returns data for the Snapshot.

**Section**: One titled block of raw data in the report. It holds rows, or a note explaining why the data is unavailable.

**Red flag**: A finding worth investigating, with a severity and a one-line reason. It is not proof of compromise.

**Severity**: High, Medium, Low or Info. High means a strong indicator such as a known miner name. Low means a weak signal that is often legitimate. Info records something expected, such as a trusted publisher's app in AppData.

**Trusted publisher**: An organisation on the scan's allowlist, read from a valid signing certificate. The file's company field does not count.

**Tool cache**: A uv or Python `Scripts` folder under a user's AppData. Its programs are Info unless unsigned and above 10% CPU.

**Advertised shortcut**: A Windows Installer shortcut whose target is resolved by MSI. Its visible path is only an icon, so the scan reports the owning product instead.

**Wildcard DNS host**: A name such as `sslip.io` or `nip.io` that resolves to an IP embedded in the name.

**Known finding**: An item the owner has already investigated, listed in the gitignored `known-findings.json`.

**Previously triaged**: The report section showing known findings seen in this scan, in place of their severity.

**Top heat contributors**: The 15 processes with the highest average CPU during the sample.

**Normalised CPU**: A process's CPU time divided by the logical core count, so 100% means the whole machine.

**Persistence**: Any mechanism that starts a program automatically, such as a Run key, Startup folder item, scheduled task, service or WMI event subscription.

**User-writable path**: A location where ordinary programs can place executables: AppData, Temp, ProgramData or Users\Public.

**Orphaned task**: A scheduled task whose executable in a user-writable path no longer exists. It is often what remains after malware is partly removed. Executables left in the same folder are flagged as its companions.

**Unavailable**: A source that could not be read. It is never equivalent to a clean result.

**Heat log**: The CSV of periodic samples written by the logger.
