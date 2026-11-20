# Runs as SYSTEM from boot: runs each cmd\NAME.ps1 the host drops in the share once, and
# writes out\NAME.txt then out\NAME.rc (the exit code, written last).
$share = '\\host.lan\Data'
$run = 'C:\kyws\run'
New-Item -ItemType Directory -Force $run | Out-Null
while (-not (Test-Path "$share\out")) { Start-Sleep 2 }
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
Set-Content "$share\out\boot-$boot" (Get-Date).ToUniversalTime().ToString('o')
while ($true) {
	foreach ($f in Get-ChildItem "$share\cmd" -Filter *.ps1 -ErrorAction SilentlyContinue) {
		$n = $f.BaseName
		Move-Item $f.FullName "$run\$n.ps1" -Force
		$p = Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$run\$n.ps1" `
			-RedirectStandardOutput "$run\$n.txt" -RedirectStandardError "$run\$n.err" -WindowStyle Hidden -Wait -PassThru
		Get-Content "$run\$n.txt", "$run\$n.err" | Set-Content "$share\out\$n.txt"
		Set-Content "$share\out\$n.rc" $p.ExitCode
		Remove-Item "$run\$n.*" -Force
	}
	Start-Sleep 2
}
