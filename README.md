![Banner](banner.png)

# monitor-autoruns
Monitors changes to autorun locations (registry keys, startup folders) to detect malware persistence mechanisms. - Focused on System monitoring and alerts

This tool runs on Windows only: it reads the Windows registry through the `winreg` module, which is part of the Windows Python standard library. On any other platform it prints that limit and exits 1. It has no third-party dependencies.

## Coverage

The monitor reads every listed registry location in both `HKEY_CURRENT_USER` and `HKEY_LOCAL_MACHINE`, labelled with its hive in log and report lines, plus the startup folders.

At startup and on every cycle the monitor logs a coverage statement: how many registry locations were read and how many entries they held, which locations could not be read and why (missing key, permission denied, or another error), and the same for the startup folders. A location that cannot be read is named in that statement and is never silently treated as a location that was read and found empty. If no location at all can be read, the coverage statement is followed by a warning that the monitor is watching nothing it can verify.

An added registry entry is reported with its name and its command value. A removed entry is reported with its name and its last known value.

## Install
`git clone https://github.com/ShadowStrikeHQ/monitor-autoruns`

## Usage
`python main.py [params]`

The interval must be a positive number of seconds; a non-positive interval is rejected at startup with exit 1 instead of spinning the monitor.

## Parameters
- `-h`: Show help message and exit
- `-i`: Interval in seconds to check for changes. Default is 60 seconds.
- `-l`: Path to the log file. Default is autorun_monitor.log
- `-r`: Path to the report file. Default is autorun_report.txt
- `-v`: Enable verbose output.

## License
Copyright (c) ShadowStrikeHQ
