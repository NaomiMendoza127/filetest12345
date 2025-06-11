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

# Test script to force UAC prompt
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {

    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Just a dummy action
Start-Sleep -Seconds 5
