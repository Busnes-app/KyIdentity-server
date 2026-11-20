#!/usr/bin/env bash
# Manual release check, not CI (about 30 GB of disk and an hour): a fresh Windows 11 Pro VM
# joins the Samba AD DC this branch's KyIdentity feeds, and the logons are proven at the
# real Windows logon. See docs/ACTIVE-DIRECTORY.md, "Windows 11 release check".
#   scripts/e2e-win11-domain.sh        (E2E_WIN11_KEEP=1 keeps the VM, DC and work dir)
#   E2E_WIN11_EVIDENCE=DIR             copies the screenshots and the log there
# Needs docker, /dev/kvm and internet access to Microsoft's download servers.
# Do not wrap it in flock /tmp/ky-integ-test.lock: it takes that lock for its builds and
# would wait on itself.
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
# _win_booted_since N: more boots than N have reported (counted on every poll).
_win_booted_since() { (($(_win_boots) > $1)); }

# win_ps NAME [TIMEOUT] < SCRIPT: runs SCRIPT as SYSTEM in the VM and prints its output.
# Returns the script's exit code.
win_ps() {
	local name=$1 timeout=${2:-300} d=$E2E_WIN11_SHARE rc
	rm -f "$d/out/$name.txt" "$d/out/$name.rc"
	cat >"$d/cmd/.$name"
	mv "$d/cmd/.$name" "$d/cmd/$name.ps1"
	_win_wait "$timeout" test -s "$d/out/$name.rc" || _win_die "$name: no answer in ${timeout}s" || return
	sleep 1
	# A script with no output leaves no .txt (Set-Content of nothing writes no file).
	if [[ -f $d/out/$name.txt ]]; then tr -d '\r' <"$d/out/$name.txt"; fi
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
	_win_wait 900 _win_booted_since "$n" || _win_die "the VM did not come back within 15 min"
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

# _win_logons USER: USER's logon events since the last boot, read as SYSTEM, one per line:
# "4624 type=2" (online), "4624 type=11" (cached credentials), "4625 type=T sub=STATUS"
# (refused), then "session=active" while USER holds a console session.
_win_logons() {
	win_ps logons <<-EOF
		\$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
		Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=\$boot} -ErrorAction SilentlyContinue | Sort-Object TimeCreated | ForEach-Object {
			\$d = @{}; ([xml]\$_.ToXml()).Event.EventData.Data | ForEach-Object { \$d[\$_.Name] = \$_.'#text' }
			if (\$d.TargetUserName -eq '$1' -and (\$_.Id -eq 4625 -or \$d.LogonType -in '2','11')) {
				"\$(\$_.Id) type=\$(\$d.LogonType) sub=\$(\$d.SubStatus) at=+\$([int](\$_.TimeCreated - \$boot).TotalSeconds)s"
			}
		}
		if ((query.exe user 2>\$null) -match '^\s*>?$1\s+console\s+\d+\s+Active') { 'session=active' }
	EOF
}

# _win_after_reboot USER PASSWORD: AutoAdminLogon once as DOMAIN\USER, reboot, and wait
# (up to 10 min) for USER's first logon event. Sets _win_events; 1 if none came.
_win_after_reboot() {
	local deadline
	_win_autologon "$1" "$2"
	win_reboot
	deadline=$((SECONDS + 600))
	_win_events=""
	until [[ $_win_events == *4624* || $_win_events == *4625* ]]; do
		((SECONDS < deadline)) || return 1
		sleep 10
		_win_events=$(_win_logons "$1") || true
	done
	# A refused online check can follow a cached logon; give it time to land.
	sleep 45
	_win_events=$(_win_logons "$1") || true
}

# win_logon USER PASSWORD SHOT: AutoAdminLogon once as DOMAIN\USER after a reboot. Prints
# the logon events and the report USER's own session wrote. 0 when USER logged on and holds
# the console session.
win_logon() {
	local user=$1 out=$E2E_WIN11_SHARE/out rc=0
	rm -f "$out"/session-*
	_win_after_reboot "$user" "$2" || rc=$?
	printf '%s\n' "${_win_events:-no logon event within 600 s}"
	[[ $_win_events == *"4624 type="* && $_win_events == *session=active* ]] || rc=1
	if ((rc == 0)); then
		_win_wait 180 compgen -G "$out/session-*.detail" >/dev/null || true
		cat "$out"/session-*.txt "$out"/session-*.detail 2>/dev/null | tr -d '\r' || echo "no session report"
	fi
	win_shot "$3"
	_win_autologon_clear
	return "$rc"
}

# win_logon_refused USER PASSWORD SUBSTATUS SHOT: AutoAdminLogon as DOMAIN\USER after a
# reboot must be refused with a 4625 carrying SUBSTATUS (such as 0xc000006a), and USER must
# neither log on (no 4624, online or cached) nor hold a session. Prints the events.
win_logon_refused() {
	local rc=0
	rm -f "$E2E_WIN11_SHARE"/out/session-*
	_win_after_reboot "$1" "$2" || rc=$?
	printf '%s\n' "${_win_events:-no logon event within 600 s}"
	win_shot "$4"
	_win_autologon_clear
	((rc == 0)) && [[ $_win_events == *"4625 type="*"sub=$3"* && $_win_events != *4624* && $_win_events != *session=active* ]]
}

# win_cad_shot NAME: Ctrl-Alt-Del in the signed-in session, screenshot, Escape.
win_cad_shot() {
	_win_monitor "sendkey ctrl-alt-delete" >/dev/null
	sleep 6
	win_shot "$1"
	_win_monitor "sendkey esc" >/dev/null
	sleep 3
}

# The DC goes dark for the PC, as for a laptop off site: the VM container (which routes the
# VM's traffic) drops packets to it. docker pause is no stand-in: the frozen DC's kernel
# still completes TCP handshakes, so Windows hangs instead of failing over to the cache.
win_dc_down() { docker exec "$E2E_WIN11_VM" iptables -I FORWARD -d "$E2E_DC_IP" -j DROP; }
win_dc_up() { docker exec "$E2E_WIN11_VM" iptables -D FORWARD -d "$E2E_DC_IP" -j DROP; }

# win_join: Add-Computer to the realm as the domain administrator, reboot, then check the
# secure channel. Prints what Windows reports.
win_join() {
	local pass
	pass=$(cat "$E2E_DC_ADMIN_PWFILE")
	win_ps join 600 <<-EOF
		\$ErrorActionPreference = 'Stop'
		if ((Get-CimInstance Win32_ComputerSystem).Domain -eq '${E2E_DC_REALM,,}') { 'already joined'; exit 0 }
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

# win_gpo_apply: the documented baseline as one GPO linked at the domain root: User
# Configuration > Administrative Templates > System > Ctrl+Alt+Del Options > Remove Change
# Password, and Computer Configuration > Administrative Templates > System > Logon > Always
# wait for the network at computer startup and logon. Then gpupdate on the PC.
win_gpo_apply() {
	local guid reg='{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
	_dc_exec_i sh -c 'cat >/e2e/gpo.json' <<-'EOF'
		[{"keyname": "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
		  "valuename": "DisableChangePassword", "class": "USER", "type": "REG_DWORD", "data": 1},
		 {"keyname": "Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
		  "valuename": "SyncForegroundPolicy", "class": "MACHINE", "type": "REG_DWORD", "data": 1}]
	EOF
	guid=$(_dc_exec sh -c 'PASSWD_FILE=/e2e/admin.pass samba-tool gpo create "KyIdentity baseline" -U Administrator -H ldap://dc.kyws.test' |
		grep -o '{[0-9A-Fa-f-]*}' | head -n 1)
	[[ -n $guid ]] || _win_die "gpo create printed no GUID" || return
	# Each side lists the registry CSE, then its Administrative Templates tool.
	_dc_exec sh -c 'export PASSWD_FILE=/e2e/admin.pass
		samba-tool gpo load "$1" --content=/e2e/gpo.json -U Administrator -H ldap://dc.kyws.test \
			--machine-ext-name="$3" --machine-ext-name="{D02B1F72-3407-48AE-BA88-E8213C6761F1}" \
			--user-ext-name="$3" --user-ext-name="{D02B1F73-3407-48AE-BA88-E8213C6761F1}" &&
		samba-tool gpo setlink "$2" "$1" -U Administrator -H ldap://dc.kyws.test' \
		sh "$guid" "$E2E_DC_BASE_DN" "$reg" >&2
	echo "gpo: $guid linked at $E2E_DC_BASE_DN"
	win_ps gpupdate 300 <<-'EOF'
		gpupdate.exe /target:computer /force | Out-Null
		$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon'
		"SyncForegroundPolicy: $((Get-ItemProperty $k -ErrorAction SilentlyContinue).SyncForegroundPolicy)"
		gpresult.exe /scope:computer /r | Select-String 'KyIdentity baseline'
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
	_win_wait "${E2E_WIN11_INSTALL_TIMEOUT:-5400}" _win_booted_since 0 ||
		_win_die "install did not finish; docker logs $E2E_WIN11_VM" || return
	_win_log "install finished; command channel up"
	_win_setup
}

# _win_setup: UTC time from the host and the DC as the DNS server; prints the edition.
_win_setup() {
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
	if [[ -n ${E2E_WIN11_EVIDENCE:-} && -d ${E2E_WIN11_SHOTS:-} ]]; then
		mkdir -p "$E2E_WIN11_EVIDENCE"
		cp "$E2E_WIN11_SHOTS"/*.png "$E2E_WIN11_EVIDENCE/" 2>/dev/null || true
		cp "$E2E_WIN11_SHOTS/run.log" "$E2E_WIN11_EVIDENCE/run-log.txt" 2>/dev/null || true
	fi
	if [[ ${E2E_WIN11_KEEP:-0} == 1 ]]; then
		_win_log "kept: $E2E_WIN11_VM, $E2E_DC_CONTAINER, $E2E_WIN11_WORKDIR ($E2E_DC_WORKDIR)"
		return "$rc"
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
