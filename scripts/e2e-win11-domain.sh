#!/usr/bin/env bash
# Manual release check, not CI (about 30 GB of disk and an hour): a fresh Windows 11 Pro VM
# joins the Samba AD DC this branch's KyIdentity feeds, and the logons are proven at the
# real Windows logon. See docs/ACTIVE-DIRECTORY.md, "Windows 11 release check".
#   scripts/e2e-win11-domain.sh        (E2E_WIN11_KEEP=1 keeps the VM, DC and work dir)
#   E2E_WIN11_EVIDENCE=DIR             copies the screenshots and the log there
# Needs docker, /dev/kvm and internet access to Microsoft's download servers.
# Every docker object is kyws-win11-*; nothing else is touched.
# Guest-side PowerShell is single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail

_WIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export E2E_DC_PREFIX=kyws-win11
E2E_SOURCE_ONLY=1 source "$_WIN_ROOT/scripts/e2e-samba-ad.sh"

# dockurr/windows 5.x (2026-10-05). VERSION=11 is Windows 11 Pro.
E2E_WIN11_IMAGE=docker.io/dockurr/windows@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea
E2E_WIN11_VM=kyws-win11-vm
E2E_WIN11_VOLUME=kyws-win11-storage
export E2E_WIN11_IMAGE E2E_WIN11_VM E2E_WIN11_VOLUME

_win_log() { printf '[e2e-win11] %s\n' "$*" >&2; }
_win_die() {
	_win_log "ERROR: $*"
	return 1
}

# _win_wait SECONDS CMD...: polls CMD every 5 s until it succeeds.
_win_wait() {
	local deadline=$((SECONDS + $1))
	shift
	until "$@"; do
		((SECONDS < deadline)) || return 1
		sleep 5
	done
}

_win_boots() { find "$E2E_WIN11_SHARE/out" -maxdepth 1 -name 'boot-*' | wc -l; }
_win_sessions() { compgen -G "$E2E_WIN11_SHARE/out/session-*.txt" >/dev/null; }

# win_ps NAME [TIMEOUT] < SCRIPT: runs SCRIPT as SYSTEM in the VM and prints its output.
# Returns the script's exit code.
win_ps() {
	local name=$1 timeout=${2:-300} d=$E2E_WIN11_SHARE rc
	rm -f "$d/out/$name.txt" "$d/out/$name.rc"
	cat >"$d/cmd/.$name"
	mv "$d/cmd/.$name" "$d/cmd/$name.ps1"
	_win_wait "$timeout" test -s "$d/out/$name.rc" || _win_die "$name: no answer in ${timeout}s" || return
	sleep 1
	tr -d '\r' <"$d/out/$name.txt"
	rc=$(tr -dc '0-9' <"$d/out/$name.rc")
	rm -f "$d/out/$name.txt" "$d/out/$name.rc"
	return "${rc:-1}"
}

# _win_monitor COMMAND: one QEMU human-monitor command; prints the reply.
_win_monitor() {
	docker exec -i "$E2E_WIN11_VM" python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(30)
s.connect("/run/kyws-mon.sock")
def prompt():
    b = b""
    while not b.endswith(b"(qemu) "):
        b += s.recv(65536)
    return b.decode(errors="replace")
prompt()
s.sendall(sys.argv[1].encode() + b"\n")
print(prompt())
' "$1"
}

# win_shot NAME: a screendump of the VM display, saved as $E2E_WIN11_SHOTS/NAME.png.
win_shot() {
	_win_monitor "screendump /tmp/kyws-shot.png -f png" >/dev/null
	docker cp -q "$E2E_WIN11_VM:/tmp/kyws-shot.png" "$E2E_WIN11_SHOTS/$1.png"
	_win_log "screenshot $1.png"
}

# win_reboot: reboots the VM and waits for its command channel.
win_reboot() {
	local n
	n=$(_win_boots)
	printf 'shutdown.exe /r /t 5 /f\n' | win_ps reboot >/dev/null
	_win_wait 900 test "$(_win_boots)" -gt "$n" || _win_die "the VM did not come back within 15 min"
}

_win_autologon() {
	win_ps autologon <<-EOF >/dev/null
		\$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
		Set-ItemProperty \$k AutoAdminLogon '1'
		Set-ItemProperty \$k DefaultDomainName '$E2E_DC_DOMAIN'
		Set-ItemProperty \$k DefaultUserName '$1'
		Set-ItemProperty \$k DefaultPassword '$2'
		Remove-ItemProperty \$k AutoLogonCount -ErrorAction SilentlyContinue
	EOF
}

_win_autologon_clear() {
	win_ps autologon-clear <<-'EOF' >/dev/null
		$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
		Set-ItemProperty $k AutoAdminLogon '0'
		Remove-ItemProperty $k DefaultPassword -ErrorAction SilentlyContinue
	EOF
}

# win_logon USER PASSWORD SHOT: AutoAdminLogon once as DOMAIN\USER after a reboot. Prints
# the session report the user's own session wrote and the seconds from reboot to it.
# 0 when a session started.
win_logon() {
	local user=$1 pass=$2 shot=$3 start rc=0
	rm -f "$E2E_WIN11_SHARE"/out/session-*.txt
	_win_autologon "$user" "$pass"
	start=$SECONDS
	win_reboot
	_win_wait 900 _win_sessions || rc=$?
	if ((rc == 0)); then
		echo "logon-seconds-after-reboot: $((SECONDS - start))"
		tr -d '\r' <"$(compgen -G "$E2E_WIN11_SHARE/out/session-*.txt" | head -n 1)"
		sleep 40 # let the desktop finish drawing
	else
		echo "no session within 900 s"
	fi
	win_shot "$shot"
	_win_autologon_clear
	return "$rc"
}

# _win_4625 USER: the 4625 (logon failure) events for USER since the last boot.
_win_4625() {
	win_ps "events-4625" <<-EOF
		\$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
		Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=\$boot} -ErrorAction SilentlyContinue | ForEach-Object {
			\$d = @{}; ([xml]\$_.ToXml()).Event.EventData.Data | ForEach-Object { \$d[\$_.Name] = \$_.'#text' }
			if (\$d.TargetUserName -eq '$1') { "4625 \$(\$d.TargetDomainName)\\\$(\$d.TargetUserName) logonType=\$(\$d.LogonType) status=\$(\$d.Status) subStatus=\$(\$d.SubStatus)" }
		}
	EOF
}

# win_logon_refused USER PASSWORD SUBSTATUS SHOT: AutoAdminLogon as DOMAIN\USER after a
# reboot must be refused with a 4625 event carrying SUBSTATUS (such as 0xc000006a) and no
# session. Prints the events.
win_logon_refused() {
	local user=$1 pass=$2 want=$3 shot=$4 events="" deadline
	rm -f "$E2E_WIN11_SHARE"/out/session-*.txt
	_win_autologon "$user" "$pass"
	win_reboot
	deadline=$((SECONDS + 600))
	while ((SECONDS < deadline)); do
		events=$(_win_4625 "$user") || true
		[[ -n $events ]] && break
		sleep 10
	done
	sleep 15
	win_shot "$shot"
	_win_autologon_clear
	printf '%s\n' "${events:-no 4625 event within 600 s}"
	if _win_sessions; then
		echo "a session started"
		return 1
	fi
	grep -qi "subStatus=$want" <<<"$events"
}

# win_cad_shot NAME: Ctrl-Alt-Del in the signed-in session, screenshot, Escape.
win_cad_shot() {
	_win_monitor "sendkey ctrl-alt-delete" >/dev/null
	sleep 6
	win_shot "$1"
	_win_monitor "sendkey esc" >/dev/null
	sleep 3
}

win_dc_pause() { docker pause "$E2E_DC_CONTAINER" >/dev/null; }
win_dc_unpause() { docker unpause "$E2E_DC_CONTAINER" >/dev/null; }

# win_join: Add-Computer to the realm as the domain administrator, reboot, then check the
# secure channel. Prints what Windows reports.
win_join() {
	local pass
	pass=$(cat "$E2E_DC_ADMIN_PWFILE")
	win_ps join 600 <<-EOF
		\$ErrorActionPreference = 'Stop'
		\$c = New-Object PSCredential('$E2E_DC_DOMAIN\\Administrator', (ConvertTo-SecureString '$pass' -AsPlainText -Force))
		Add-Computer -DomainName '${E2E_DC_REALM,,}' -Credential \$c -Force
		'Add-Computer: ok'
	EOF
	win_reboot
	win_ps joined <<-'EOF'
		$cs = Get-CimInstance Win32_ComputerSystem
		"computer: $($cs.Name) partOfDomain=$($cs.PartOfDomain) domain=$($cs.Domain)"
		"secureChannel: $(Test-ComputerSecureChannel)"
		nltest.exe /dsgetdc:kyws.test
		if (-not (Test-ComputerSecureChannel)) { exit 1 }
	EOF
}

# win_gpo_apply: a GPO linked at the domain root with User Configuration > Administrative
# Templates > System > Ctrl+Alt+Del Options > Remove Change Password = Enabled.
win_gpo_apply() {
	local guid
	_dc_exec_i sh -c 'cat >/e2e/gpo.json' <<-'EOF'
		[{"keyname": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		  "valuename": "DisableChangePassword", "class": "USER", "type": "REG_DWORD", "data": 1}]
	EOF
	guid=$(_dc_exec sh -c 'PASSWD_FILE=/e2e/admin.pass samba-tool gpo create "KyIdentity baseline" -U Administrator -H ldap://dc.kyws.test' |
		grep -o '{[0-9A-Fa-f-]*}' | head -n 1)
	[[ -n $guid ]] || _win_die "gpo create printed no GUID" || return
	_dc_exec sh -c 'PASSWD_FILE=/e2e/admin.pass samba-tool gpo load "$1" --content=/e2e/gpo.json \
		--user-ext-name="{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" --user-ext-name="{D02B1F73-3407-48AE-BA88-E8213C6761F1}" \
		-U Administrator -H ldap://dc.kyws.test &&
		PASSWD_FILE=/e2e/admin.pass samba-tool gpo setlink "$2" "$1" -U Administrator -H ldap://dc.kyws.test' \
		sh "$guid" "$E2E_DC_BASE_DN" >&2
	echo "gpo: $guid linked at $E2E_DC_BASE_DN"
	win_ps gpupdate 300 <<-'EOF'
		gpupdate.exe /target:computer /force
		gpresult.exe /scope:computer /r | Select-String -Pattern 'KyIdentity|Group Policy was applied'
	EOF
}

_win_write_env() {
	cat >"$E2E_WIN11_WORKDIR/win.env" <<-EOF
		export E2E_WIN11_WORKDIR='$E2E_WIN11_WORKDIR'
		export E2E_WIN11_SHARE='$E2E_WIN11_SHARE'
		export E2E_WIN11_SHOTS='$E2E_WIN11_SHOTS'
	EOF
}

# win_up: starts a fresh VM on the DC's network, waits for the unattended install (the
# command channel answering), sets UTC time and makes the DC its DNS server.
win_up() {
	E2E_WIN11_WORKDIR=$(mktemp -d -t kyws-win11.XXXXXX)
	chmod 700 "$E2E_WIN11_WORKDIR"
	E2E_WIN11_SHARE=$E2E_WIN11_WORKDIR/share
	E2E_WIN11_SHOTS=$E2E_WIN11_WORKDIR/shots
	export E2E_WIN11_WORKDIR E2E_WIN11_SHARE E2E_WIN11_SHOTS
	mkdir -p "$E2E_WIN11_SHARE/cmd" "$E2E_WIN11_SHARE/out" "$E2E_WIN11_SHOTS" "$E2E_WIN11_WORKDIR/oem"
	# The container's Samba writes as nobody.
	chmod 0777 "$E2E_WIN11_SHARE" "$E2E_WIN11_SHARE/cmd" "$E2E_WIN11_SHARE/out"
	local f
	for f in "$_WIN_ROOT"/scripts/e2e-win11-domain/*; do
		sed 's/\r*$/\r/' "$f" >"$E2E_WIN11_WORKDIR/oem/$(basename "$f")"
	done
	_win_write_env
	_win_log "starting $E2E_WIN11_VM (install takes 20-40 min)"
	docker volume create "$E2E_WIN11_VOLUME" >/dev/null
	# Capped by docker's own cgroup: 8 GB including QEMU, 4 CPUs; guest RAM 6 GB.
	docker run -d --name "$E2E_WIN11_VM" --network "$E2E_DC_NETWORK" \
		--device /dev/kvm --device /dev/net/tun --cap-add NET_ADMIN \
		--memory 8g --memory-swap 8g --cpus 4 --pids-limit 4096 \
		-p 127.0.0.1::8006 -p 127.0.0.1::3389 \
		-e VERSION=11 -e RAM_SIZE=6G -e CPU_CORES=4 -e DISK_SIZE=64G \
		-e MONITOR=/run/kyws-mon.sock \
		-v "$E2E_WIN11_VOLUME:/storage" -v "$E2E_WIN11_WORKDIR/oem:/oem:ro" -v "$E2E_WIN11_SHARE:/shared" \
		--stop-timeout 120 "$E2E_WIN11_IMAGE" >/dev/null
	_win_log "viewer: http://$(docker port "$E2E_WIN11_VM" 8006/tcp | head -n 1)"
	_win_wait "${E2E_WIN11_INSTALL_TIMEOUT:-5400}" test "$(_win_boots)" -gt 0 ||
		_win_die "install did not finish; docker logs $E2E_WIN11_VM" || return
	_win_log "install finished; command channel up"
	win_ps setup-clock-dns <<-EOF
		\$ErrorActionPreference = 'Stop'
		Set-TimeZone -Id UTC
		Set-Date ([datetime]::Parse('$(date -u +%Y-%m-%dT%H:%M:%SZ)').ToUniversalTime()) | Out-Null
		\$nic = Get-NetAdapter | Where-Object Status -EQ Up | Select-Object -First 1
		Set-DnsClientServerAddress -InterfaceIndex \$nic.ifIndex -ServerAddresses '$E2E_DC_IP'
		"edition: \$((Get-CimInstance Win32_OperatingSystem).Caption) \$((Get-CimInstance Win32_OperatingSystem).Version)"
		"licence: \$((Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'").LicenseStatus) (1 = activated)"
		"dc lookup: \$((Resolve-DnsName -Type SRV '_ldap._tcp.dc._msdcs.${E2E_DC_REALM,,}').NameTarget)"
	EOF
}

# win_down: removes the VM container, its disk volume and the work dir.
win_down() {
	if docker container inspect "$E2E_WIN11_VM" >/dev/null 2>&1; then
		docker rm -f "$E2E_WIN11_VM" >/dev/null
	fi
	if docker volume inspect "$E2E_WIN11_VOLUME" >/dev/null 2>&1; then
		docker volume rm "$E2E_WIN11_VOLUME" >/dev/null
	fi
	if [[ -n ${E2E_WIN11_WORKDIR:-} && $E2E_WIN11_WORKDIR == */kyws-win11.* && -d $E2E_WIN11_WORKDIR ]]; then
		# The share holds files the container's Samba wrote as nobody.
		docker run --rm --name kyws-win11-cleanup -v "$E2E_WIN11_WORKDIR:/w" "$E2E_DC_IMAGE" \
			sh -c 'rm -rf /w/share' >/dev/null
		rm -rf "$E2E_WIN11_WORKDIR"
	fi
}

_win_cleanup() {
	local rc=$?
	if [[ ${E2E_WIN11_KEEP:-0} == 1 ]]; then
		_win_log "kept: $E2E_WIN11_VM, $E2E_DC_CONTAINER, $E2E_WIN11_WORKDIR ($E2E_DC_WORKDIR)"
		return "$rc"
	fi
	if [[ -n ${E2E_WIN11_EVIDENCE:-} && -d ${E2E_WIN11_SHOTS:-} ]]; then
		mkdir -p "$E2E_WIN11_EVIDENCE"
		cp "$E2E_WIN11_SHOTS"/*.png "$E2E_WIN11_EVIDENCE/" 2>/dev/null || true
	fi
	win_down
	dc_down
	docker image rm "$E2E_DC_IMAGE" >/dev/null 2>&1 || true
	_win_log "disk after: $(df -h --output=avail /var/lib/docker 2>/dev/null | tail -n 1) free"
	return "$rc"
}

_win_main() {
	cd "$_WIN_ROOT"
	_win_log "disk before: $(df -h --output=avail /var/lib/docker 2>/dev/null | tail -n 1) free"
	trap _win_cleanup EXIT
	dc_up >/dev/null
	win_up
	local cap=()
	if systemd-run --user --scope -q true >/dev/null 2>&1; then
		cap=(systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 -p CPUQuota=400% --)
	fi
	flock /tmp/ky-integ-test.lock "${cap[@]}" sh -c \
		'go build -o "$1/kyidentity-dc-agent" ./cmd/kyidentity-dc-agent && go test -c -o "$1/api.test" ./internal/api' \
		sh "$E2E_DC_WORKDIR"
	(
		cd internal/api
		PUSH_RELAY_URL='' APNS_RELAY_URL='' \
			KYIDENTITY_E2E_DC_ENV="$E2E_DC_WORKDIR/dc.env" \
			KYIDENTITY_E2E_AGENT="$E2E_DC_WORKDIR/kyidentity-dc-agent" \
			KYIDENTITY_E2E_SCRIPT="$_WIN_ROOT/scripts/e2e-samba-ad.sh" \
			KYIDENTITY_E2E_WIN11_SCRIPT="$_WIN_ROOT/scripts/e2e-win11-domain.sh" \
			KYIDENTITY_E2E_WIN11_ENV="$E2E_WIN11_WORKDIR/win.env" \
			"$E2E_DC_WORKDIR/api.test" -test.run '^TestWin11DomainEndToEnd$' -test.count=1 -test.v -test.timeout=3h
	) 2>&1 | tee "$E2E_WIN11_SHOTS/run.log"
	return "${PIPESTATUS[0]}"
}

if [[ ${BASH_SOURCE[0]} == "$0" && ${E2E_SOURCE_ONLY:-0} != 1 ]]; then
	_win_main
fi
