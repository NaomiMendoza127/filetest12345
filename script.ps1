# Log UAC trigger attempt
$logPath = "C:\Windows\Temp\updater_log.txt"
"[{0}] Requesting UAC from non-admin: $env:USERNAME" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Out-File $logPath -Append -Encoding utf8

# Force UAC prompt
Start-Process powershell.exe -Verb RunAs
