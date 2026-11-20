# Runs at every interactive logon, as the user. Writes locally (the poller relays it): the
# share may be unreachable to this user, and whoami /upn and klist block while the DC is.
$t = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ')
$f = "C:\ProgramData\kyws\sessions\session-$t"
$pol = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).DisableChangePassword
@("time: $t", "whoami: $(whoami.exe)", "DisableChangePassword: $pol") | Set-Content "$f.tmp"
Rename-Item "$f.tmp" "session-$t.txt"
@("upn: $(whoami.exe /upn 2>&1)", '--- klist', (klist.exe 2>&1)) | Set-Content "$f.tmp"
Rename-Item "$f.tmp" "session-$t.detail"
