# Logger task runs under headless conhost

The logger's scheduled task launches PowerShell through `conhost.exe --headless` rather than with `-WindowStyle Hidden`. Thermal Doctor flags hidden PowerShell as High severity because malware commonly uses it, so a hidden-window task would make the tool flag itself and teach the owner to ignore that signal. `--headless` is a less documented conhost option, so it should be rechecked if a Windows update changes console hosting.
