package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// TestSambaADEndToEnd drives this branch's HTTP server, the built DC agent and a real Samba
// AD DC. It runs only from scripts/e2e-samba-ad-kyidentity.sh, which starts the DC.
func TestSambaADEndToEnd(t *testing.T) {
	envFile, agentBin, script := os.Getenv("KYIDENTITY_E2E_DC_ENV"), os.Getenv("KYIDENTITY_E2E_AGENT"), os.Getenv("KYIDENTITY_E2E_SCRIPT")
	if envFile == "" {
		t.Skip("needs scripts/e2e-samba-ad-kyidentity.sh")
	}
	env := map[string]string{}
	raw, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export ")), "="); ok {
			env[k] = strings.Trim(v, "'")
		}
	}
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// dc runs one helper from the DC script; true when it exits 0.
	dc := func(args ...string) (string, bool) {
		cmd := exec.Command("bash", append([]string{"-c", `E2E_SOURCE_ONLY=1 source "$0"; source "$1"; shift; "$@"`, script, envFile}, args...)...)
		out, err := cmd.Output()
		return string(out), err == nil
	}
	must := func(what string, ok bool) {
		t.Helper()
		if !ok {
			t.Fatal("FAIL:", what)
		}
		t.Log("PASS:", what)
	}

	netguard.AllowPrivate = true // KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true: the DC is on a docker bridge.
	t.Cleanup(func() { netguard.AllowPrivate = false })
	srv, db, engine, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.httpServer.Handler)
	defer ts.Close()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	work := t.TempDir()
	keyOut, err := exec.Command(agentBin, "init", "-key", filepath.Join(work, "agent.key")).Output()
	if err != nil {
		t.Fatal("agent init:", err)
	}
	outsiderBefore, _ := dc("dc_attrs_hash", env["E2E_DC_OUTSIDER_DN"])
	squatterBefore, _ := dc("dc_attrs_hash", env["E2E_DC_SQUATTER_DN"])

	settings := map[string]any{"bindDn": env["E2E_DC_SYNC_DN"], "baseDn": env["E2E_DC_OU"], "caPem": read(env["E2E_DC_CA"]), "agentPublicKey": strings.TrimSpace(string(keyOut))}
	body, _ := json.Marshal(map[string]any{"name": "Samba", "systemType": "active_directory", "callbackUrl": env["E2E_DC_LDAPS_URL"], "bearerToken": read(env["E2E_DC_SYNC_PWFILE"]), "activeDirectory": settings})
	rr := adminRequest(t, srv, "POST", "/api/admin/systems", cookie, string(body))
	var created struct{ System store.PairedSystem }
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &created) != nil {
		t.Fatalf("create connector: %d %s", rr.Code, rr.Body.String())
	}
	id := created.System.ID
	must("Test connection binds and reads the OU over pinned LDAPS", adminRequest(t, srv, "POST", "/api/admin/systems/"+id+"/test", cookie, "").Code == http.StatusOK)
	put := func(ca string) int {
		b, _ := json.Marshal(map[string]any{"ldapsUrl": env["E2E_DC_LDAPS_URL"], "bindDn": settings["bindDn"], "baseDn": settings["baseDn"], "caPem": ca, "agentPublicKey": settings["agentPublicKey"]})
		return adminRequest(t, srv, "PUT", "/api/admin/systems/"+id+"/active-directory", cookie, string(b)).Code
	}
	must("settings accept another CA", put(read(env["E2E_DC_WRONG_CA"])) == http.StatusOK)
	must("Test connection fails against a CA that did not sign the DC", adminRequest(t, srv, "POST", "/api/admin/systems/"+id+"/test", cookie, "").Code == http.StatusBadRequest)
	must("settings restore the right CA", put(settings["caPem"].(string)) == http.StatusOK)

	rr = adminRequest(t, srv, "POST", "/api/admin/systems/"+id+"/active-directory/agent-token", cookie, "")
	var issued struct{ AgentToken string }
	if json.Unmarshal(rr.Body.Bytes(), &issued) != nil || issued.AgentToken == "" {
		t.Fatal("agent token", rr.Body.String())
	}
	var shown struct{ EntrySigningKey string }
	_ = json.Unmarshal(adminRequest(t, srv, "GET", "/api/admin/systems/"+id+"/active-directory", cookie, "").Body.Bytes(), &shown)
	_ = os.WriteFile(filepath.Join(work, "token"), []byte(issued.AgentToken), 0o600)
	_ = os.WriteFile(filepath.Join(work, "bind"), []byte(read(env["E2E_DC_AGENT_PWFILE"])), 0o600)
	cfg, _ := json.Marshal(map[string]string{"kyidentityUrl": ts.URL, "kyidentitySigningKey": shown.EntrySigningKey, "connectorId": id, "tokenFile": filepath.Join(work, "token"),
		"keyFile": filepath.Join(work, "agent.key"), "stateFile": filepath.Join(work, "state.json"), "ldapsUrl": env["E2E_DC_LDAPS_URL"],
		"caFile": env["E2E_DC_CA"], "bindDn": env["E2E_DC_AGENT_DN"], "bindPasswordFile": filepath.Join(work, "bind"), "baseDn": env["E2E_DC_OU"]})
	_ = os.WriteFile(filepath.Join(work, "agent.json"), cfg, 0o600)
	agentLog := ""
	agent := func() {
		out, err := exec.Command(agentBin, "run", "-config", filepath.Join(work, "agent.json"), "-once").CombinedOutput()
		agentLog += string(out)
		if err != nil {
			t.Fatalf("agent: %v\n%s", err, out)
		}
	}
	dispatch := func() {
		for range 5 {
			if err := engine.DispatchPendingEvents(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		left, _ := db.GetPendingSyncEvents(20)
		for _, ev := range left {
			t.Logf("undelivered %s for %s: %s", ev.EventType, ev.UserID, ev.LastError)
		}
	}
	state := func(user string) string {
		rr := adminRequest(t, srv, "GET", "/api/admin/systems/"+id+"/active-directory", cookie, "")
		var v struct{ Passwords []store.ADPasswordStatus }
		_ = json.Unmarshal(rr.Body.Bytes(), &v)
		for _, p := range v.Passwords {
			if p.Username == user {
				return p.State + " " + p.LastError
			}
		}
		return "absent"
	}

	// A user created with a password before assignment: only a later change reaches AD.
	if rr := adminRequest(t, srv, "POST", "/api/admin/users", cookie, `{"username":"winuser","displayName":"Win User","email":"winuser@kyws.test","password":"Kyws-Initial-Pass-1"}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	user, _ := db.GetUserByUsername("winuser")
	group := &store.Group{ID: "11111111-2222-3333-4444-555555555555", Name: "pc-users"}
	if err := db.CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.SetGroupMembership(group.ID, user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := db.ListAppRecords("", 100, 0)
	app := ""
	for _, a := range apps {
		if a.SystemID == id {
			app = a.ID
		}
	}
	if err := db.SetAppAssignment(app, "groups", group.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	dispatch()
	ldif, _ := dc("dc_ldapsearch", env["E2E_DC_OU"], "(sAMAccountName=winuser)", "-o", "ldif-wrap=no", "adminDescription", "userPrincipalName", "memberOf", "userAccountControl")
	must("an assigned user appears in the OU with its marker and UPN", strings.Contains(ldif, "adminDescription: kyidentity:"+id+":user:"+user.ID) && strings.Contains(ldif, "userPrincipalName: winuser@kyws.test"))
	must("the assigned group holds the user", strings.Contains(ldif, "memberOf: CN=pc-users,"+env["E2E_DC_OU"]))
	must("the account is enabled (512)", strings.Contains(ldif, "userAccountControl: 512"))
	must("status says the password is not yet in the directory", state("winuser") == "missing ")
	_, ok := dc("dc_kinit", "winuser", "Kyws-Initial-Pass-1")
	must("a password set before assignment does not log in", !ok)

	// An administrator's password is temporary: AD gets a random lock instead, and only the
	// password the user then chooses works on Windows.
	setByAdmin := func(password string) {
		t.Helper()
		if rr := adminRequest(t, srv, "PUT", "/api/admin/users/"+user.ID, cookie, `{"password":"`+password+`"}`); rr.Code != http.StatusOK {
			t.Fatal(rr.Body.String())
		}
	}
	var userCookie string
	change := func(from, to string) {
		t.Helper()
		if rr := adminRequest(t, srv, "POST", "/api/user/password", userCookie, `{"currentPassword":"`+from+`","newPassword":"`+to+`"}`); rr.Code != http.StatusOK {
			t.Fatal(rr.Body.String())
		}
	}
	setByAdmin("Kyws-Admin-Set-2")
	must("the new password waits for the agent", state("winuser") == "pending ")
	agent()
	_, ok = dc("dc_kinit", "winuser", "Kyws-Admin-Set-2")
	must("a temporary password an administrator set does not log in to Windows", !ok)
	must("status says the directory is locked until the user sets a password", state("winuser") == "locked ")

	userCookie = newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	change("Kyws-Admin-Set-2", "Kyws-Changed-Pass-3")
	agent()
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-3")
	must("a password the user sets in KyIdentity yields a Kerberos login (kinit)", ok)
	_, ok = dc("dc_ntlm", "winuser", "Kyws-Changed-Pass-3")
	must("the same password authenticates over NTLM (smbclient)", ok)
	must("status says the password is current", state("winuser") == "current ")
	_, ok = dc("dc_kinit", "winuser", "Kyws-Admin-Set-2")
	must("the temporary password still does not log in", !ok)

	setByAdmin("Kyws-Admin-Set-4")
	agent()
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-3")
	must("an administrator's reset locks the previous Windows password out", !ok)
	_, ok = dc("dc_kinit", "winuser", "Kyws-Admin-Set-4")
	must("the reset's temporary password does not log in either", !ok)

	userCookie = newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	change("Kyws-Admin-Set-4", "Kyws-Changed-Pass-5")
	agent()
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-5")
	must("a password change logs in with the new password", ok)
	_, ok = dc("dc_ntlm", "winuser", "Kyws-Changed-Pass-5")
	must("NTLM uses the new password", ok)

	change("Kyws-Changed-Pass-5", "onlylowercaseletterslong")
	agent()
	must("a password AD's complexity policy refuses is reported, without the password", state("winuser") == "rejected password_policy")
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-5")
	must("the refused password left the previous one in place", ok)

	if rr := adminRequest(t, srv, "PUT", "/api/admin/users/"+user.ID, cookie, `{"status":"disabled"}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	dispatch()
	uac, _ := dc("dc_uac", "winuser")
	must("disabling the user in KyIdentity disables the AD account (514)", strings.TrimSpace(uac) == "514")
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-5")
	must("the disabled account no longer logs in", !ok)

	// A reset while disabled replaces the directory's copy before the account is enabled.
	setByAdmin("Kyws-Admin-Set-6")
	if rr := adminRequest(t, srv, "PUT", "/api/admin/users/"+user.ID, cookie, `{"status":"active"}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	dispatch()
	uac, _ = dc("dc_uac", "winuser")
	must("re-enabling waits for the agent to replace the retained password", strings.TrimSpace(uac) == "514")
	agent()
	dispatch()
	uac, _ = dc("dc_uac", "winuser")
	must("the account is enabled once the reset reached the directory", strings.TrimSpace(uac) == "512")
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-5")
	must("the password from before the reset no longer logs in", !ok)

	// A KyIdentity user whose name an unmanaged AD object holds is refused, not merged.
	if rr := adminRequest(t, srv, "POST", "/api/admin/users", cookie, `{"username":"squatter","email":"squatter@kyws.test","password":"Kyws-Squatter-Pass-4"}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	squatter, _ := db.GetUserByUsername("squatter")
	if err := db.SetGroupMembership(group.ID, squatter.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	dispatch()
	pending, _ := db.GetPendingSyncEvents(20)
	conflict := false
	for _, ev := range pending {
		conflict = conflict || ev.UserID == squatter.ID && strings.Contains(ev.LastError, "does not manage")
	}
	must("a name held by an unmanaged object is reported as a conflict", conflict)
	squatterAfter, _ := dc("dc_attrs_hash", env["E2E_DC_SQUATTER_DN"])
	must("the unmanaged object in the OU is untouched", squatterBefore != "" && squatterAfter == squatterBefore)
	outsiderAfter, _ := dc("dc_attrs_hash", env["E2E_DC_OUTSIDER_DN"])
	must("an object outside the OU is untouched", outsiderBefore != "" && outsiderAfter == outsiderBefore)
	for _, secret := range []string{"Kyws-Admin-Set-2", "Kyws-Changed-Pass-5", "onlylowercaseletterslong", issued.AgentToken} {
		must("the agent log holds no "+secret[:6]+"… secret", !strings.Contains(agentLog, secret))
	}
}
