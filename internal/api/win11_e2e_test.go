package api

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestWin11DomainEndToEnd proves Windows 11 logon against the Samba DC this server feeds.
// It runs only from scripts/e2e-win11-domain.sh, which starts the DC and the Windows VM.
// Steps that measure behaviour KyIdentity does not decide are logged as MEASURED.
func TestWin11DomainEndToEnd(t *testing.T) {
	winScript, winEnv := os.Getenv("KYIDENTITY_E2E_WIN11_SCRIPT"), os.Getenv("KYIDENTITY_E2E_WIN11_ENV")
	if winScript == "" {
		t.Skip("needs scripts/e2e-win11-domain.sh")
	}
	e := startSambaE2E(t)
	// win runs one helper from the Windows script and logs what it printed.
	win := func(args ...string) (string, bool) {
		start := time.Now()
		cmd := exec.Command("bash", append([]string{"-c", `E2E_SOURCE_ONLY=1 source "$0"; source "$1"; source "$2"; shift 2; "$@"`, winScript, e.envFile, winEnv}, args...)...)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		t.Logf("%s (%s):\n%s", args[0], time.Since(start).Round(time.Second), out)
		return string(out), err == nil
	}
	const p0, p1, p2 = "Kyws-Initial-Pass-1", "Kyws-Win11-Pass-2", "Kyws-Win11-Pass-3"
	user, _ := e.assignedUser("winuser", p0)
	change := func(from, to string) {
		t.Helper()
		cookie := newSession(t, e.db, user, time.Now().UTC().Add(time.Hour))
		if rr := adminRequest(t, e.srv, "POST", "/api/user/password", cookie, `{"currentPassword":"`+from+`","newPassword":"`+to+`"}`); rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
		e.agent()
		e.must("the agent set the new password in AD", e.state("winuser") == "current ")
	}
	change(p0, p1)
	uac := func(want string) {
		t.Helper()
		got, _ := e.dc("dc_uac", "winuser")
		e.must("userAccountControl is "+want, strings.TrimSpace(got) == want)
	}
	session := func(out string) bool {
		return strings.Contains(out, "upn: winuser@kyws.test") && strings.Contains(out, "krbtgt/KYWS.TEST")
	}

	_, ok := win("win_join")
	e.must("1. Windows 11 joins the domain and holds a secure channel", ok)

	out, ok := win("win_logon", "winuser", p1, "02-logon-desktop")
	e.must("2. interactive logon as the KyIdentity user, with a UPN and a Kerberos TGT in the session", ok && session(out))

	change(p1, p2)
	_, ok = win("win_logon_refused", "winuser", p1, "0xc000006a", "03-old-password-refused")
	e.must("3. after a KyIdentity password change the old password is refused (0xC000006A)", ok)
	out, ok = win("win_logon", "winuser", p2, "03-new-password-desktop")
	e.must("3. the new password logs on", ok && session(out))

	e.setStatus(user, "disabled")
	uac("514")
	_, ok = win("win_logon_refused", "winuser", p2, "0xc0000072", "04-disabled-refused")
	e.must("4. after disabling in KyIdentity the logon is refused (0xC0000072)", ok)

	e.setStatus(user, "active")
	uac("512")
	out, ok = win("win_logon", "winuser", p2, "05-online-logon")
	e.must("5. online logon again after re-enabling (caches the credential)", ok && session(out))
	_, ok = win("win_dc_pause")
	e.must("the DC is paused", ok)
	out, ok = win("win_logon", "winuser", p2, "05-cached-logon-dc-down")
	t.Logf("MEASURED: 5. cached logon with the DC down, active user: logged on=%v, ticket=%v", ok, strings.Contains(out, "krbtgt/"))
	_, ok = win("win_dc_unpause")
	e.must("the DC is back", ok)

	e.setStatus(user, "disabled")
	uac("514")
	_, ok = win("win_dc_pause")
	e.must("the DC is paused", ok)
	_, ok = win("win_logon", "winuser", p2, "05-cached-logon-disabled-dc-down")
	t.Logf("MEASURED: 5. cached logon with the DC down, user disabled in KyIdentity after their last online logon: logged on=%v", ok)
	_, ok = win("win_dc_unpause")
	e.must("the DC is back", ok)
	e.setStatus(user, "active")
	uac("512")

	out, ok = win("win_logon", "winuser", p2, "06-logon-before-gpo")
	e.must("6. logon before the GPO", ok && strings.Contains(out, "DisableChangePassword: \n"))
	_, ok = win("win_cad_shot", "06-ctrl-alt-del-before-gpo")
	e.must("6. Ctrl-Alt-Del screen captured before the GPO", ok)
	_, ok = win("win_gpo_apply")
	e.must("6. the baseline GPO is created, loaded and linked", ok)
	out, ok = win("win_logon", "winuser", p2, "06-logon-with-gpo")
	e.must("6. at logon the user hive holds Remove Change Password (DisableChangePassword=1)", ok && strings.Contains(out, "DisableChangePassword: 1"))
	_, ok = win("win_cad_shot", "06-ctrl-alt-del-with-gpo")
	e.must("6. Ctrl-Alt-Del screen captured with the GPO", ok)
	for name, secret := range map[string]string{"first password": p1, "second password": p2, "agent token": e.agentToken} {
		e.must("the agent log holds no "+name, !strings.Contains(e.agentLog, secret))
	}
}
