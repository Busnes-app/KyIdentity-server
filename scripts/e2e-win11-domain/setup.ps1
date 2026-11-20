# One-time VM setup for scripts/e2e-win11-domain.sh. Lab only: it gives the host a SYSTEM
# command channel through the container's shared folder.
$ErrorActionPreference = 'Stop'
# The DC becomes the DNS server later and cannot resolve host.lan, so pin it now.
$ip = [Net.Dns]::GetHostAddresses('host.lan') | Where-Object AddressFamily -EQ 'InterNetwork' | Select-Object -First 1
Add-Content "$env:windir\System32\drivers\etc\hosts" "`r`n$ip host.lan"
# Refused logons must reach the Security log (4625) for the harness to read.
auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
# The host writes into the share behind Samba's back, so no lease break tells Windows to
# refresh: without this SYSTEM's cached listing of cmd\ goes stale after the domain join.
Set-SmbClientConfiguration -DirectoryCacheLifetime 0 -FileInfoCacheLifetime 0 -FileNotFoundCacheLifetime 0 -Confirm:$false
# Skip the first-logon animation so a new domain user's desktop comes up quickly.
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty $sys EnableFirstLogonAnimation 0 -Type DWord
New-Item -ItemType Directory -Force C:\kyws | Out-Null
Copy-Item C:\OEM\poller.ps1, C:\OEM\session.ps1 C:\kyws\
New-Item -ItemType Directory -Force C:\ProgramData\kyws\sessions | Out-Null
icacls.exe C:\ProgramData\kyws\sessions /grant 'Users:(OI)(CI)M' | Out-Null
icacls.exe C:\kyws /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
# Every interactive logon reports from the user's own session.
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' kyws-session `
	'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\kyws\session.ps1'
$action = New-ScheduledTaskAction powershell.exe '-NoProfile -ExecutionPolicy Bypass -File C:\kyws\poller.ps1'
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit 0 -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask kyws-poller -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) `
	-Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest) -Settings $settings | Out-Null
Start-ScheduledTask kyws-poller
