#!/usr/bin/env bash
# Throwaway Samba AD DC for the KyIdentity Active Directory end-to-end test.
#
# Run directly: provisions a DC, runs the AD-side self-test, tears it down.
#   scripts/e2e-samba-ad.sh            (E2E_DC_KEEP=1 leaves the DC running)
# Source for helpers only:
#   E2E_SOURCE_ONLY=1 source scripts/e2e-samba-ad.sh; dc_up; ...; dc_down
#
# Every docker object is named kyws-windows-*; nothing else is touched.
# See scripts/e2e-samba-ad/NOTES.md for the password-policy findings.
# Container-side `sh -c '...'` snippets expand their own positional args.
# shellcheck disable=SC2016
set -euo pipefail

E2E_DC_IMAGE=kyws-windows-samba-dc:local
E2E_DC_CONTAINER=kyws-windows-dc
E2E_DC_NETWORK=kyws-windows-net
E2E_DC_REALM=KYWS.TEST
E2E_DC_DOMAIN=KYWS
E2E_DC_HOSTNAME=dc.kyws.test
E2E_DC_BASE_DN=DC=kyws,DC=test
E2E_DC_OU="OU=KyIdentity,${E2E_DC_BASE_DN}"
E2E_DC_OUTSIDE_OU="OU=Outside,${E2E_DC_BASE_DN}"
E2E_DC_ADMIN_DN="CN=Administrator,CN=Users,${E2E_DC_BASE_DN}"
E2E_DC_SYNC_DN="CN=kyidentity-sync,CN=Users,${E2E_DC_BASE_DN}"
E2E_DC_AGENT_DN="CN=kyidentity-agent,CN=Users,${E2E_DC_BASE_DN}"
E2E_DC_OUTSIDER_DN="CN=outsider,${E2E_DC_OUTSIDE_OU}"
E2E_DC_SQUATTER_DN="CN=squatter,${E2E_DC_OU}"
export E2E_DC_IMAGE E2E_DC_CONTAINER E2E_DC_NETWORK E2E_DC_REALM E2E_DC_DOMAIN \
	E2E_DC_HOSTNAME E2E_DC_BASE_DN E2E_DC_OU E2E_DC_OUTSIDE_OU E2E_DC_ADMIN_DN \
	E2E_DC_SYNC_DN E2E_DC_AGENT_DN E2E_DC_OUTSIDER_DN E2E_DC_SQUATTER_DN

_DC_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Path inside the container where the work-dir files are copied.
_DC_IN=/e2e
# Schema GUIDs used in the delegation ACEs.
_GUID_USER=bf967aba-0de6-11d0-a285-00aa003049e2
_GUID_GROUP=bf967a9c-0de6-11d0-a285-00aa003049e2
_GUID_RESET_PASSWORD=00299570-246d-11d0-a768-00aa006e0529
_GUID_PWDLASTSET=bf967a0a-0de6-11d0-a285-00aa003049e2
_GUID_UAC=bf967a68-0de6-11d0-a285-00aa003049e2

_dc_log() { printf '[e2e-samba-ad] %s\n' "$*" >&2; }
_dc_die() {
	_dc_log "ERROR: $*"
	return 1
}
_dc_exec() { docker exec "$E2E_DC_CONTAINER" "$@"; }
_dc_exec_i() { docker exec -i "$E2E_DC_CONTAINER" "$@"; }

# A random password that satisfies the default AD complexity rules.
_dc_gen_password() {
	printf 'Ky-%s-9a' "$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)"
}

# Writes a password file (mode 0600, no trailing newline) into the work dir.
_dc_write_secret() {
	local path=$1 value=$2
	(umask 077 && printf '%s' "$value" >"$path")
}

_dc_build_image() {
	if docker image inspect "$E2E_DC_IMAGE" >/dev/null 2>&1; then
		return 0
	fi
	_dc_log "building $E2E_DC_IMAGE"
	flock /tmp/ky-integ-test.lock systemd-run --user --scope -q \
		-p MemoryMax=4G -p MemorySwapMax=0 -p CPUQuota=400% -- \
		docker build -q -t "$E2E_DC_IMAGE" "$_DC_SCRIPT_DIR/e2e-samba-ad" >/dev/null
}

# Removes only the objects this script owns.
_dc_remove_objects() {
	if docker container inspect "$E2E_DC_CONTAINER" >/dev/null 2>&1; then
		docker rm -f "$E2E_DC_CONTAINER" >/dev/null
	fi
	if docker network inspect "$E2E_DC_NETWORK" >/dev/null 2>&1; then
		docker network rm "$E2E_DC_NETWORK" >/dev/null
	fi
}

_dc_gen_certs() {
	local d=$E2E_DC_WORKDIR
	openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=kyws-windows e2e CA' \
		-keyout "$d/ca.key" -out "$d/ca.pem" 2>/dev/null
	openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=kyws-windows e2e WRONG CA' \
		-keyout "$d/wrong-ca.key" -out "$d/wrong-ca.pem" 2>/dev/null
	openssl req -newkey rsa:2048 -nodes -subj "/CN=$E2E_DC_HOSTNAME" \
		-keyout "$d/server.key" -out "$d/server.csr" 2>/dev/null
	cat >"$d/server.ext" <<-EOF
		basicConstraints=CA:FALSE
		keyUsage=digitalSignature,keyEncipherment
		extendedKeyUsage=serverAuth
		subjectAltName=DNS:$E2E_DC_HOSTNAME,DNS:dc,IP:$E2E_DC_IP
	EOF
	openssl x509 -req -in "$d/server.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" \
		-CAcreateserial -days 2 -extfile "$d/server.ext" -out "$d/server.pem" 2>/dev/null
	chmod 600 "$d"/*.key
}

# ldap{search,modify,...} inside the DC against the LDAPS URL with the right CA.
# Usage: _dc_ldap_tool TOOL BIND_DN CONTAINER_PWFILE [args...]
_dc_ldap_tool() {
	local tool=$1 dn=$2 pwfile=$3
	shift 3
	_dc_exec_i env LDAPTLS_CACERT="$_DC_IN/ca.pem" LDAPTLS_REQCERT=demand \
		"$tool" -H "$E2E_DC_LDAPS_URL" -x -D "$dn" -y "$pwfile" "$@"
}

# Maps a well-known bind DN to its password file inside the container.
_dc_pwfile_for() {
	case $1 in
	"$E2E_DC_ADMIN_DN") echo "$_DC_IN/admin.pass" ;;
	"$E2E_DC_SYNC_DN") echo "$_DC_IN/sync.pass" ;;
	"$E2E_DC_AGENT_DN") echo "$_DC_IN/agent.pass" ;;
	"$E2E_DC_OUTSIDER_DN") echo "$_DC_IN/outsider.pass" ;;
	*) _dc_die "no password file known for $1" ;;
	esac
}

_dc_ldapsearch_admin() {
	_dc_ldap_tool ldapsearch "$E2E_DC_ADMIN_DN" "$_DC_IN/admin.pass" -LLL -o ldif-wrap=no "$@"
}

_dc_wait_ldaps() {
	local i
	for i in $(seq 1 90); do
		if _dc_ldapsearch_admin -b "" -s base '(objectClass=*)' dnsHostName </dev/null >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	_dc_exec sh -c 'tail -n 40 /var/log/samba/log.samba 2>/dev/null' >&2 || true
	_dc_die "LDAPS did not come up within 90s (attempt $i)"
}

# samba-tool user create with the password read from a container file.
_dc_create_user() {
	local name=$1 pwfile=$2
	shift 2
	_dc_exec sh -c 'n=$1; f=$2; shift 2; samba-tool user create "$n" "$(cat "$f")" "$@"' \
		sh "$name" "$pwfile" "$@" >/dev/null
}

_dc_delegate() {
	local sync_sid agent_sid u=$_GUID_USER g=$_GUID_GROUP
	sync_sid=$(dc_sid kyidentity-sync)
	agent_sid=$(dc_sid kyidentity-agent)
	local -a aces=(
		# kyidentity-sync: create/delete user and group children of the OU and
		# below, read/write all properties and reset password on them.
		"(OA;CI;CCDC;$u;;$sync_sid)"
		"(OA;CI;CCDC;$g;;$sync_sid)"
		"(OA;CIIO;RPWP;;$u;$sync_sid)"
		"(OA;CIIO;RPWP;;$g;$sync_sid)"
		"(OA;CIIO;CR;$_GUID_RESET_PASSWORD;$u;$sync_sid)"
		# kyidentity-agent: reset password, write pwdLastSet, read
		# userAccountControl on users only.
		"(OA;CIIO;CR;$_GUID_RESET_PASSWORD;$u;$agent_sid)"
		"(OA;CIIO;WP;$_GUID_PWDLASTSET;$u;$agent_sid)"
		"(OA;CIIO;RP;$_GUID_UAC;$u;$agent_sid)"
	)
	local ace
	for ace in "${aces[@]}"; do
		_dc_exec samba-tool dsacl set --objectdn="$E2E_DC_OU" --sddl="$ace" >/dev/null
	done
}

_dc_write_env() {
	cat >"$E2E_DC_WORKDIR/dc.env" <<-EOF
		export E2E_DC_WORKDIR='$E2E_DC_WORKDIR'
		export E2E_DC_IP='$E2E_DC_IP'
		export E2E_DC_LDAPS_URL='$E2E_DC_LDAPS_URL'
		export E2E_DC_CA='$E2E_DC_CA'
		export E2E_DC_WRONG_CA='$E2E_DC_WRONG_CA'
		export E2E_DC_ADMIN_DN='$E2E_DC_ADMIN_DN'
		export E2E_DC_ADMIN_PWFILE='$E2E_DC_ADMIN_PWFILE'
		export E2E_DC_SYNC_DN='$E2E_DC_SYNC_DN'
		export E2E_DC_SYNC_PWFILE='$E2E_DC_SYNC_PWFILE'
		export E2E_DC_AGENT_DN='$E2E_DC_AGENT_DN'
		export E2E_DC_AGENT_PWFILE='$E2E_DC_AGENT_PWFILE'
		export E2E_DC_OUTSIDER_DN='$E2E_DC_OUTSIDER_DN'
		export E2E_DC_OUTSIDER_PWFILE='$E2E_DC_OUTSIDER_PWFILE'
		export E2E_DC_SQUATTER_DN='$E2E_DC_SQUATTER_DN'
		export E2E_DC_OU='$E2E_DC_OU'
		export E2E_DC_OUTSIDE_OU='$E2E_DC_OUTSIDE_OU'
		export E2E_DC_BASE_DN='$E2E_DC_BASE_DN'
		export E2E_DC_KRB5_CONF='$E2E_DC_KRB5_CONF'
	EOF
}

# --- public helpers -------------------------------------------------------

# Starts a freshly provisioned DC. Exports the E2E_DC_* variables, writes
# them to $E2E_DC_WORKDIR/dc.env and prints the LDAPS URL. Call it directly,
# not in $(...): a subshell loses the variables and leaks the work dir.
dc_up() {
	_dc_build_image
	_dc_remove_objects
	E2E_DC_WORKDIR=$(mktemp -d -t kyws-windows-dc.XXXXXX)
	chmod 700 "$E2E_DC_WORKDIR"
	E2E_DC_CA=$E2E_DC_WORKDIR/ca.pem
	E2E_DC_WRONG_CA=$E2E_DC_WORKDIR/wrong-ca.pem
	E2E_DC_ADMIN_PWFILE=$E2E_DC_WORKDIR/admin.pass
	E2E_DC_SYNC_PWFILE=$E2E_DC_WORKDIR/sync.pass
	E2E_DC_AGENT_PWFILE=$E2E_DC_WORKDIR/agent.pass
	E2E_DC_OUTSIDER_PWFILE=$E2E_DC_WORKDIR/outsider.pass
	export E2E_DC_WORKDIR E2E_DC_CA E2E_DC_WRONG_CA E2E_DC_ADMIN_PWFILE \
		E2E_DC_SYNC_PWFILE E2E_DC_AGENT_PWFILE E2E_DC_OUTSIDER_PWFILE

	_dc_write_secret "$E2E_DC_ADMIN_PWFILE" "$(_dc_gen_password)"
	_dc_write_secret "$E2E_DC_SYNC_PWFILE" "$(_dc_gen_password)"
	_dc_write_secret "$E2E_DC_AGENT_PWFILE" "$(_dc_gen_password)"
	_dc_write_secret "$E2E_DC_OUTSIDER_PWFILE" "$(_dc_gen_password)"
	_dc_write_secret "$E2E_DC_WORKDIR/squatter.pass" "$(_dc_gen_password)"

	_dc_log "starting $E2E_DC_CONTAINER"
	docker network create "$E2E_DC_NETWORK" >/dev/null
	# CAP_SYS_ADMIN: provisioning stores NT ACLs in security.* xattrs on sysvol.
	docker run -d --name "$E2E_DC_CONTAINER" --hostname dc \
		--network "$E2E_DC_NETWORK" --network-alias "$E2E_DC_HOSTNAME" \
		--cap-add SYS_ADMIN "$E2E_DC_IMAGE" >/dev/null
	E2E_DC_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$E2E_DC_NETWORK\").IPAddress}}" "$E2E_DC_CONTAINER")
	[[ -n $E2E_DC_IP ]] || _dc_die "could not read the DC container IP"
	E2E_DC_LDAPS_URL="ldaps://$E2E_DC_IP:636"
	export E2E_DC_IP E2E_DC_LDAPS_URL

	_dc_gen_certs
	_dc_exec mkdir -p "$_DC_IN"
	local f
	for f in ca.pem wrong-ca.pem server.pem server.key admin.pass sync.pass agent.pass outsider.pass squatter.pass; do
		docker cp -q "$E2E_DC_WORKDIR/$f" "$E2E_DC_CONTAINER:$_DC_IN/$f"
	done
	_dc_exec sh -c "chown -R root:root $_DC_IN && chmod 700 $_DC_IN && chmod 600 $_DC_IN/*"

	_dc_log "provisioning realm $E2E_DC_REALM"
	_dc_exec sh -c 'rm -f /etc/samba/smb.conf &&
		samba-tool domain provision --realm="$1" --domain="$2" --server-role=dc \
			--dns-backend=SAMBA_INTERNAL --use-rfc2307 --host-name=dc \
			--adminpass="$(cat "$3/admin.pass")" >/tmp/provision.log 2>&1 ||
			{ tail -n 30 /tmp/provision.log; exit 1; }' \
		sh "$E2E_DC_REALM" "$E2E_DC_DOMAIN" "$_DC_IN" >&2
	_dc_exec awk -v d="$_DC_IN" '{ print }
		/^\[global\]$/ {
			print "\ttls enabled = yes"
			print "\ttls keyfile = " d "/server.key"
			print "\ttls certfile = " d "/server.pem"
			print "\ttls cafile = " d "/ca.pem"
		}' /etc/samba/smb.conf >"$E2E_DC_WORKDIR/smb.conf"
	docker cp -q "$E2E_DC_WORKDIR/smb.conf" "$E2E_DC_CONTAINER:/etc/samba/smb.conf"
	cat >"$E2E_DC_WORKDIR/krb5.conf" <<-EOF
		[libdefaults]
			default_realm = $E2E_DC_REALM
			dns_lookup_realm = false
			dns_lookup_kdc = false
		[realms]
			$E2E_DC_REALM = {
				kdc = $E2E_DC_IP
				admin_server = $E2E_DC_IP
			}
		[domain_realm]
			.kyws.test = $E2E_DC_REALM
			kyws.test = $E2E_DC_REALM
	EOF
	docker cp -q "$E2E_DC_WORKDIR/krb5.conf" "$E2E_DC_CONTAINER:/etc/krb5.conf"
	E2E_DC_KRB5_CONF=$E2E_DC_WORKDIR/krb5.conf
	export E2E_DC_KRB5_CONF
	# The container is its own resolver for the realm.
	_dc_exec sh -c "echo '$E2E_DC_IP $E2E_DC_HOSTNAME dc' >>/etc/hosts"
	_dc_exec samba
	_dc_wait_ldaps

	_dc_log "creating OUs, accounts and delegation"
	_dc_exec samba-tool ou create "$E2E_DC_OU" >/dev/null
	_dc_exec samba-tool ou create "$E2E_DC_OUTSIDE_OU" >/dev/null
	_dc_create_user outsider "$_DC_IN/outsider.pass" --userou=OU=Outside \
		--use-username-as-cn --given-name=Out --surname=Sider --description='pre-existing, must stay untouched'
	_dc_create_user squatter "$_DC_IN/squatter.pass" --userou=OU=KyIdentity \
		--description='pre-existing, no KyIdentity marker'
	_dc_create_user kyidentity-sync "$_DC_IN/sync.pass" --description='KyIdentity sync service account'
	_dc_create_user kyidentity-agent "$_DC_IN/agent.pass" --description='KyIdentity DC agent account'
	_dc_delegate
	_dc_write_env
	_dc_log "DC ready at $E2E_DC_LDAPS_URL (env: $E2E_DC_WORKDIR/dc.env)"
	echo "$E2E_DC_LDAPS_URL"
}

# Removes the kyws-windows-* container and network and the work dir.
dc_down() {
	_dc_remove_objects
	if [[ -n ${E2E_DC_WORKDIR:-} && -d $E2E_DC_WORKDIR && $E2E_DC_WORKDIR == */kyws-windows-dc.* ]]; then
		rm -rf "$E2E_DC_WORKDIR"
	fi
	E2E_DC_WORKDIR=
}

# dc_kinit USER PASSWORD: Kerberos AS exchange inside the DC. 0 on success.
dc_kinit() {
	local user=$1 pass=$2
	printf '%s\n' "$pass" | _dc_exec_i sh -c \
		'export KRB5CCNAME=FILE:/tmp/kinit.$$; kinit "$1@$2" >/dev/null 2>&1; rc=$?; kdestroy >/dev/null 2>&1; exit $rc' \
		sh "$user" "$E2E_DC_REALM"
}

# dc_ntlm USER PASSWORD: NTLM authentication over SMB3 inside the DC.
dc_ntlm() {
	local user=$1 pass=$2
	printf '%s\n' "$pass" | _dc_exec_i sh -c \
		'IFS= read -r PASSWD; export PASSWD; smbclient -L //127.0.0.1 -U "$1\\$2" -m SMB3 --use-kerberos=disabled >/dev/null 2>&1' \
		sh "$E2E_DC_DOMAIN" "$user"
}

# dc_ldapsearch BASE FILTER [ATTRS...]: admin bind over LDAPS, CA verified.
dc_ldapsearch() {
	local base=$1 filter=$2
	shift 2
	_dc_ldapsearch_admin -b "$base" "$filter" "$@" </dev/null
}

# dc_ldapmodify_as BIND_DN [ldapmodify args...] < LDIF. BIND_DN must be one of
# the admin/sync/agent/outsider DNs. Returns the ldapmodify exit code, which
# is the LDAP result code (19 constraintViolation, 50 insufficientAccessRights).
dc_ldapmodify_as() {
	local dn=$1 pwfile
	shift
	pwfile=$(_dc_pwfile_for "$dn")
	_dc_ldap_tool ldapmodify "$dn" "$pwfile" "$@"
}

# dc_ldapsearch_ca CA_PEM: anonymous rootDSE read over LDAPS trusting only
# CA_PEM (a host path). 0 when the TLS handshake verifies.
dc_ldapsearch_ca() {
	local ca=$1 rc=0
	docker cp -q "$ca" "$E2E_DC_CONTAINER:/tmp/probe-ca.pem"
	_dc_exec env LDAPTLS_CACERT=/tmp/probe-ca.pem LDAPTLS_REQCERT=demand \
		ldapsearch -H "$E2E_DC_LDAPS_URL" -x -LLL -b "" -s base '(objectClass=*)' dnsHostName \
		>/dev/null 2>&1 || rc=$?
	_dc_exec rm -f /tmp/probe-ca.pem
	return "$rc"
}

# dc_sid SAMACCOUNTNAME: prints the object SID.
dc_sid() {
	_dc_exec samba-tool user show "$1" --attributes=objectSid | awk '/^objectSid:/{print $2}'
}

# dc_uac SAMACCOUNTNAME: prints userAccountControl in decimal.
dc_uac() {
	dc_ldapsearch "$E2E_DC_BASE_DN" "(sAMAccountName=$1)" userAccountControl |
		awk '/^userAccountControl:/{print $2}'
}

# Attributes that change on logon, replication or any write and so are left
# out of dc_attrs_hash.
E2E_DC_VOLATILE_ATTRS='uSNChanged whenChanged lastLogon lastLogonTimestamp logonCount badPwdCount badPasswordTime lastLogoff dSCorePropagationData'
export E2E_DC_VOLATILE_ATTRS

# dc_attrs_hash DN: sha256 over the sorted LDIF of all user attributes of DN,
# minus $E2E_DC_VOLATILE_ATTRS.
dc_attrs_hash() {
	local ldif re
	ldif=$(dc_ldapsearch "$1" '(objectClass=*)' -s base '*') || return
	[[ -n $ldif ]] || _dc_die "no such object: $1" || return
	re="^($(tr ' ' '|' <<<"$E2E_DC_VOLATILE_ATTRS")):"
	grep -Ev "$re" <<<"$ldif" | LC_ALL=C sort | sha256sum | awk '{print $1}'
}

# dc_set_password USER PASSWORD: administrative reset via samba-tool.
dc_set_password() {
	printf '%s\n' "$2" | _dc_exec_i sh -c \
		'IFS= read -r p; samba-tool user setpassword "$1" --newpassword="$p" >/dev/null' sh "$1"
}

# dc_unicodepwd PASSWORD: base64 of UTF-16LE("PASSWORD"), for unicodePwd:: in LDIF.
dc_unicodepwd() {
	printf '"%s"' "$1" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
}

# --- self-test ------------------------------------------------------------

_E2E_PASS=0
_E2E_FAIL=0
_check() {
	local name=$1
	shift
	if "$@" >/dev/null 2>&1; then
		printf 'PASS  %s\n' "$name"
		_E2E_PASS=$((_E2E_PASS + 1))
	else
		printf 'FAIL  %s\n' "$name"
		_E2E_FAIL=$((_E2E_FAIL + 1))
	fi
}
_not() { ! "$@"; }
# _rc_is CODE cmd...: the command exits with exactly CODE.
_rc_is() {
	local want=$1 rc=0
	shift
	"$@" || rc=$?
	[[ $rc == "$want" ]]
}
_uac_is() { [[ $(dc_uac "$1") == "$2" ]]; }
_host_tls_ok() {
	openssl s_client -connect "$E2E_DC_IP:636" -CAfile "$E2E_DC_CA" \
		-verify_return_error -verify_ip "$E2E_DC_IP" </dev/null
}
_ou_visible() {
	dc_ldapsearch "$E2E_DC_OU" '(objectClass=organizationalUnit)' -s base dn |
		grep -q "^dn: $E2E_DC_OU"
}
_group_roundtrip() {
	dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: CN=e2e-group,$E2E_DC_OU
		changetype: add
		objectClass: group
		sAMAccountName: e2e-group
		member: CN=e2e-alice,$E2E_DC_OU

		dn: CN=e2e-group,$E2E_DC_OU
		changetype: delete
	EOF
}
_squatter_unmarked() {
	local out
	out=$(dc_ldapsearch "$E2E_DC_SQUATTER_DN" '(objectClass=*)' -s base adminDescription) &&
		[[ -n $out ]] && ! grep -q '^adminDescription' <<<"$out"
}

_dc_self_test() {
	trap 'if [[ ${E2E_DC_KEEP:-0} != 1 ]]; then dc_down; fi' EXIT
	dc_up >/dev/null

	local outsider_pw sync_pw new_pw ou=$E2E_DC_OU before after
	outsider_pw=$(cat "$E2E_DC_OUTSIDER_PWFILE")
	sync_pw=$(cat "$E2E_DC_SYNC_PWFILE")
	new_pw=$(_dc_gen_password)
	before=$(dc_attrs_hash "$E2E_DC_OUTSIDER_DN")

	echo "--- TLS"
	_check "LDAPS verifies with the generated CA" dc_ldapsearch_ca "$E2E_DC_CA"
	_check "LDAPS fails with the wrong CA" _not dc_ldapsearch_ca "$E2E_DC_WRONG_CA"
	_check "host reaches $E2E_DC_IP:636 and verifies the cert (IP SAN)" _host_tls_ok
	_check "admin ldapsearch over LDAPS returns OU=KyIdentity" _ou_visible

	echo "--- Kerberos / NTLM"
	_check "kinit outsider, right password" dc_kinit outsider "$outsider_pw"
	_check "kinit outsider, wrong password fails" _not dc_kinit outsider "wrong-$outsider_pw"
	_check "kinit kyidentity-sync" dc_kinit kyidentity-sync "$sync_pw"
	_check "NTLM outsider, right password" dc_ntlm outsider "$outsider_pw"
	_check "NTLM outsider, wrong password fails" _not dc_ntlm outsider "wrong-$outsider_pw"

	echo "--- kyidentity-sync delegation on $ou"
	_check "sync creates user with unicodePwd at create time" dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: add
		objectClass: user
		sAMAccountName: e2e-alice
		userPrincipalName: e2e-alice@kyws.test
		unicodePwd:: $(dc_unicodepwd "$new_pw")
		userAccountControl: 514
	EOF
	_check "sync sets userAccountControl 512" dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: userAccountControl
		userAccountControl: 512
	EOF
	_check "userAccountControl reads 512" _uac_is e2e-alice 512
	_check "kinit with the password set at create" dc_kinit e2e-alice "$new_pw"
	_check "sync sets userAccountControl 514" dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: userAccountControl
		userAccountControl: 514
	EOF
	_check "userAccountControl reads 514" _uac_is e2e-alice 514
	_check "kinit fails on the disabled account" _not dc_kinit e2e-alice "$new_pw"
	_check "sync writes adminDescription" dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: adminDescription
		adminDescription: kyidentity:e2e
	EOF
	_check "sync resets the password (unicodePwd replace)" dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: unicodePwd
		unicodePwd:: $(dc_unicodepwd "$new_pw-2")
	EOF
	_check "sync creates and deletes a group" _group_roundtrip
	_check "sync is refused (50) modifying outsider" _rc_is 50 dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: $E2E_DC_OUTSIDER_DN
		changetype: modify
		replace: description
		description: tampered
	EOF
	_check "sync is refused (50) resetting outsider's password" _rc_is 50 dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: $E2E_DC_OUTSIDER_DN
		changetype: modify
		replace: unicodePwd
		unicodePwd:: $(dc_unicodepwd "$new_pw")
	EOF
	_check "sync is refused (50) creating a user in CN=Users" _rc_is 50 dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
		dn: CN=e2e-escape,CN=Users,$E2E_DC_BASE_DN
		changetype: add
		objectClass: user
		sAMAccountName: e2e-escape
	EOF
	_check "sync add of sAMAccountName squatter is refused (68 entryAlreadyExists)" \
		_rc_is 68 dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
			dn: CN=squatter-2,$ou
			changetype: add
			objectClass: user
			sAMAccountName: squatter
		EOF

	echo "--- kyidentity-agent delegation on $ou"
	_check "agent resets a password in the OU" dc_ldapmodify_as "$E2E_DC_AGENT_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: unicodePwd
		unicodePwd:: $(dc_unicodepwd "$new_pw-3")
	EOF
	_check "agent writes pwdLastSet 0" dc_ldapmodify_as "$E2E_DC_AGENT_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: pwdLastSet
		pwdLastSet: 0
	EOF
	_check "agent is refused (50) writing description" _rc_is 50 dc_ldapmodify_as "$E2E_DC_AGENT_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: description
		description: nope
	EOF
	_check "agent is refused (50) writing userAccountControl" _rc_is 50 dc_ldapmodify_as "$E2E_DC_AGENT_DN" <<-EOF
		dn: CN=e2e-alice,$ou
		changetype: modify
		replace: userAccountControl
		userAccountControl: 512
	EOF
	_check "agent is refused (50) resetting outsider's password" _rc_is 50 dc_ldapmodify_as "$E2E_DC_AGENT_DN" <<-EOF
		dn: $E2E_DC_OUTSIDER_DN
		changetype: modify
		replace: unicodePwd
		unicodePwd:: $(dc_unicodepwd "$new_pw")
	EOF

	echo "--- password policy"
	_check "too-short unicodePwd is refused (19 constraintViolation)" \
		_rc_is 19 dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
			dn: CN=e2e-alice,$ou
			changetype: modify
			replace: unicodePwd
			unicodePwd:: $(dc_unicodepwd "Ab1-")
		EOF
	_check "non-complex unicodePwd is refused (19 constraintViolation)" \
		_rc_is 19 dc_ldapmodify_as "$E2E_DC_SYNC_DN" <<-EOF
			dn: CN=e2e-alice,$ou
			changetype: modify
			replace: unicodePwd
			unicodePwd:: $(dc_unicodepwd "alllowercaseletters")
		EOF

	echo "--- outside the OU"
	after=$(dc_attrs_hash "$E2E_DC_OUTSIDER_DN")
	_check "outsider attributes unchanged (hash $before)" test "$before" = "$after"
	_check "squatter still present without adminDescription" _squatter_unmarked

	echo "--- summary: $_E2E_PASS passed, $_E2E_FAIL failed"
	if ((_E2E_FAIL > 0)); then
		echo "RESULT: FAIL"
		return 1
	fi
	echo "RESULT: PASS"
}

export -f _dc_exec _dc_exec_i _dc_ldap_tool _dc_pwfile_for _dc_ldapsearch_admin _dc_die _dc_log \
	dc_kinit dc_ntlm dc_ldapsearch dc_ldapmodify_as dc_ldapsearch_ca dc_sid dc_uac \
	dc_attrs_hash dc_set_password dc_unicodepwd

if [[ ${BASH_SOURCE[0]} == "$0" && ${E2E_SOURCE_ONLY:-0} != 1 ]]; then
	_dc_self_test
fi
