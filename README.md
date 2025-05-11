# monitor-autoruns
Monitors changes to autorun locations (registry keys, startup folders) to detect malware persistence mechanisms. - Focused on System monitoring and alerts

## Install
`git clone https://github.com/ShadowStrikeHQ/monitor-autoruns`

## Usage
`./monitor-autoruns [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: Interval in seconds to check for changes. Default is 60 seconds.
- `-l`: Path to the log file. Default is autorun_monitor.log
- `-r`: Path to the report file. Default is autorun_report.txt
- `-v`: Enable verbose output.

## License
Copyright (c) ShadowStrikeHQ
