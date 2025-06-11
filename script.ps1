# Define log file
$logPath = "C:\Windows\Temp\updater_log.txt"
function Log($msg) {
    $ts = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    $ts | Out-File -FilePath $logPath -Append -Encoding utf8
}

Log "➡️ Script started. User: $env:USERNAME, Interactive: $([Environment]::UserInteractive)"

# If not running in interactive session (e.g., SYSTEM at boot)
if (-not ([Environment]::UserInteractive)) {
    Log "⚠️ Non-interactive session. Creating deferred UAC task..."

    $taskName = "UpdaterUACTrigger"
    $user = (Get-CimInstance Win32_ComputerSystem).UserName
    if (-not $user) {
        Log "⛔ No interactive user found. Aborting."
        exit
    }

    # Write inner task script to ProgramData
    $taskScriptPath = "$env:ProgramData\UpdaterTask.ps1"
    $taskContent = @"
Start-Sleep -Seconds 5
try {
    Add-MpPreference -ExclusionPath 'C:\Users\Public\TestSafeFolder' -ErrorAction Stop
    '$([DateTime]::Now): ✅ Exclusion added.' | Out-File 'C:\Windows\Temp\updater_log.txt' -Append
} catch {
    '$([DateTime]::Now): ❌ Error during exclusion: ' + \$_ | Out-File 'C:\Windows\Temp\updater_log.txt' -Append
    Write-Host "❌ Error: $($_.Exception.Message)"
    Pause
}
Pause
"@
    $taskContent | Out-File -FilePath $taskScriptPath -Encoding utf8

    try {
        # Clean up previous task if exists
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Log "🧹 Deleted old scheduled task '$taskName' if it existed"

        # Create new scheduled task
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`""
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1))
        $principal = New-ScheduledTaskPrincipal -UserId $user -RunLevel Highest -LogonType Interactive
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

        Log "✅ Scheduled task '$taskName' created. It will run 1 minute after user login with UAC prompt."
    } catch {
        Log "❌ Failed to create scheduled task: $_"
    }

    exit
}

# If already in interactive session (for manual test)
try {
    Add-MpPreference -ExclusionPath 'C:\Users\Public\TestSafeFolder' -ErrorAction Stop
    Log "✅ Exclusion added immediately."
} catch {
    Log "❌ Immediate exclusion failed: $_"
    Write-Host "❌ Error: $($_.Exception.Message)"
    Pause
}
