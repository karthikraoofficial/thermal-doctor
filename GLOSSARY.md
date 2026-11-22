# Glossary

**Snapshot**: The plain data collected from one scan. Rules and the report work from it without touching the live system.

**Collector**: Code that reads one area of the live system and returns data for the Snapshot.

**Section**: One titled block of raw data in the report. It holds rows, or a note explaining why the data is unavailable.

**Red flag**: A finding worth investigating, with a severity and a one-line reason. It is not proof of compromise.

**Severity**: High, Medium or Low. High means a strong indicator such as a known miner name. Low means a weak signal that is often legitimate.

**Top heat contributors**: The 15 processes with the highest average CPU during the sample.

**Normalised CPU**: A process's CPU time divided by the logical core count, so 100% means the whole machine.

**Persistence**: Any mechanism that starts a program automatically, such as a Run key, Startup folder item, scheduled task, service or WMI event subscription.

**User-writable path**: A location where ordinary programs can place executables: AppData, Temp, ProgramData or Users\Public.

**Orphaned task**: A scheduled task whose executable in a user-writable path no longer exists. It is often what remains after malware is partly removed. Executables left in the same folder are flagged as its companions.

**Unavailable**: A source that could not be read. It is never equivalent to a clean result.

**Heat log**: The CSV of periodic samples written by the logger.
