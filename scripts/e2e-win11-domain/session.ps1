# Runs at every interactive logon, as the user: who logged on, how, and the user policy.
$t = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$pol = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).DisableChangePassword
$lines = @(
	"time: $t"
	"whoami: $(whoami.exe)"
	"upn: $(whoami.exe /upn 2>&1)"
	"logonserver: $env:LOGONSERVER"
	"DisableChangePassword: $pol"
	'--- klist'
	(klist.exe 2>&1)
)
$out = "\\host.lan\Data\out\session-$t"
$lines | Set-Content "$out.tmp"
Rename-Item "$out.tmp" "session-$t.txt"
