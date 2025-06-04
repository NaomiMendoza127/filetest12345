$desktopPath = [Environment]::GetFolderPath("Desktop")
"Script ran at $(Get-Date)" | Out-File -FilePath "$desktopPath\script_ran.txt" -Encoding UTF8
