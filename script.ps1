$logPath = "C:\Windows\Temp\updater_log.txt"
function Log($msg) {
    $ts = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    $ts | Out-File -FilePath $logPath -Append -Encoding utf8
}

Log "➡️ Script started. User: $env:USERNAME, Interactive: $([Environment]::UserInteractive)"

if (-not ([Environment]::UserInteractive)) {
    Log "⚠️ Non-interactive session. Waiting for user login..."

    # Wait until a user is logged in
    $maxAttempts = 60  # 60 * 5s = 5 minutes
    $attempt = 0
    $user = $null

    while ($attempt -lt $maxAttempts -and -not $user) {
        $user = (Get-CimInstance Win32_ComputerSystem).UserName
        if (-not $user) {
            Log "⏳ No user yet. Waiting 5 seconds..."
            Start-Sleep -Seconds 5
            $attempt++
        }
    }

    if (-not $user) {
        Log "❌ Still no interactive user after waiting. Exiting..."
        exit
    }

    Log "✅ User detected: $user"

    # Setup deferred UAC task
    $taskName = "UpdaterUACTrigger"
    $taskScriptPath = "$env:ProgramData\UpdaterTask.ps1"

    $taskContent = @"
Start-Sleep -Seconds 10
try {
    Add-MpPreference -ExclusionPath 'C:\Users\Public\TestSafeFolder' -ErrorAction Stop
    '[{0}] ✅ Exclusion added.' -f (Get-Date) | Out-File '$logPath' -Append
} catch {
    '[{0}] ❌ Error: ' -f (Get-Date) + \$_ | Out-File '$logPath' -Append
    Pause  # Keep window open to see error
}
"@
    $taskContent | Out-File -FilePath $taskScriptPath -Encoding utf8
    Log "📄 Scheduled task script written to: $taskScriptPath"

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Log "🧹 Deleted old scheduled task '$taskName' if it existed"

        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$taskScriptPath`""
        $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1))
        $principal = New-ScheduledTaskPrincipal -UserId $user -RunLevel Highest -LogonType Interactive
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal

        Log "✅ Scheduled task '$taskName' created. It will run 1 minute after user login with UAC prompt."
    } catch {
        Log "❌ Failed to create task: $_"
    }

    exit
}

# If script is already running in interactive session (manually triggered)
try {
    Add-MpPreference -ExclusionPath 'C:\Users\Public\TestSafeFolder' -ErrorAction Stop
    Log "✅ Exclusion added interactively."
} catch {
    Log "❌ Error in direct add: $_"
}
