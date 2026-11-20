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

// sambaE2E is this branch's HTTP server with an Active Directory connector to the Samba DC
// that scripts/e2e-samba-ad.sh started, and the built DC agent configured for it.
type sambaE2E struct {
	t        *testing.T
	env      map[string]string
	envFile  string
	script   string
	srv      *Server
	db       *store.Store
	engine   interface{ DispatchPendingEvents(context.Context) error }
	cookie   string
	id       string
	settings map[string]any
	agentBin string
	work     string
	agentLog string
	// agentToken is the issued agent token, to prove no log holds it.
	agentToken string
}

// startSambaE2E skips unless KYIDENTITY_E2E_DC_ENV names the DC's env file.
func startSambaE2E(t *testing.T) *sambaE2E {
	e := &sambaE2E{t: t, envFile: os.Getenv("KYIDENTITY_E2E_DC_ENV"), agentBin: os.Getenv("KYIDENTITY_E2E_AGENT"), script: os.Getenv("KYIDENTITY_E2E_SCRIPT")}
	if e.envFile == "" {
		t.Skip("needs scripts/e2e-samba-ad-kyidentity.sh")
	}
	e.env = map[string]string{}
	for _, line := range strings.Split(e.read(e.envFile), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export ")), "="); ok {
			e.env[k] = strings.Trim(v, "'")
		}
	}
	netguard.AllowPrivate = true // KYIDENTITY_ALLOW_PRIVATE_CALLBACKS=true: the DC is on a docker bridge.
	t.Cleanup(func() { netguard.AllowPrivate = false })
	srv, db, engine, _, _, cleanup := setupTestServer(t)
	t.Cleanup(cleanup)
	ts := httptest.NewServer(srv.httpServer.Handler)
	t.Cleanup(ts.Close)
	e.srv, e.db, e.engine = srv, db, engine
	e.cookie = newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	e.work = t.TempDir()
	keyOut, err := exec.Command(e.agentBin, "init", "-key", filepath.Join(e.work, "agent.key")).Output()
	if err != nil {
		t.Fatal("agent init:", err)
	}
	e.settings = map[string]any{"bindDn": e.env["E2E_DC_SYNC_DN"], "baseDn": e.env["E2E_DC_OU"], "caPem": e.read(e.env["E2E_DC_CA"]), "agentPublicKey": strings.TrimSpace(string(keyOut))}
	body, _ := json.Marshal(map[string]any{"name": "Samba", "systemType": "active_directory", "callbackUrl": e.env["E2E_DC_LDAPS_URL"], "bearerToken": e.read(e.env["E2E_DC_SYNC_PWFILE"]), "activeDirectory": e.settings})
	rr := e.admin("POST", "/api/admin/systems", string(body))
	var created struct{ System store.PairedSystem }
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &created) != nil {
		t.Fatalf("create connector: %d %s", rr.Code, rr.Body.String())
	}
	e.id = created.System.ID
	e.must("Test connection binds and reads the OU over pinned LDAPS", e.admin("POST", "/api/admin/systems/"+e.id+"/test", "").Code == http.StatusOK)

	rr = e.admin("POST", "/api/admin/systems/"+e.id+"/active-directory/agent-token", "")
	var issued struct{ AgentToken string }
	if json.Unmarshal(rr.Body.Bytes(), &issued) != nil || issued.AgentToken == "" {
		t.Fatal("agent token", rr.Body.String())
	}
	var shown struct{ EntrySigningKey string }
	_ = json.Unmarshal(e.admin("GET", "/api/admin/systems/"+e.id+"/active-directory", "").Body.Bytes(), &shown)
	e.agentToken = issued.AgentToken
	_ = os.WriteFile(filepath.Join(e.work, "token"), []byte(issued.AgentToken), 0o600)
	_ = os.WriteFile(filepath.Join(e.work, "bind"), []byte(e.read(e.env["E2E_DC_AGENT_PWFILE"])), 0o600)
	cfg, _ := json.Marshal(map[string]string{"kyidentityUrl": ts.URL, "kyidentitySigningKey": shown.EntrySigningKey, "connectorId": e.id, "tokenFile": filepath.Join(e.work, "token"),
		"keyFile": filepath.Join(e.work, "agent.key"), "stateFile": filepath.Join(e.work, "state.json"), "ldapsUrl": e.env["E2E_DC_LDAPS_URL"],
		"caFile": e.env["E2E_DC_CA"], "bindDn": e.env["E2E_DC_AGENT_DN"], "bindPasswordFile": filepath.Join(e.work, "bind"), "baseDn": e.env["E2E_DC_OU"]})
	_ = os.WriteFile(filepath.Join(e.work, "agent.json"), cfg, 0o600)
	return e
}

func (e *sambaE2E) read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func (e *sambaE2E) admin(method, path, body string) *httptest.ResponseRecorder {
	return adminRequest(e.t, e.srv, method, path, e.cookie, body)
}

func (e *sambaE2E) must(what string, ok bool) {
	e.t.Helper()
	if !ok {
		e.t.Fatal("FAIL:", what)
	}
	e.t.Log("PASS:", what)
}

// dc runs one helper from the DC script; true when it exits 0.
func (e *sambaE2E) dc(args ...string) (string, bool) {
	cmd := exec.Command("bash", append([]string{"-c", `E2E_SOURCE_ONLY=1 source "$0"; source "$1"; shift; "$@"`, e.script, e.envFile}, args...)...)
	out, err := cmd.Output()
	return string(out), err == nil
}

// agent runs one pass of the DC agent.
func (e *sambaE2E) agent() {
	e.t.Helper()
	out, err := exec.Command(e.agentBin, "run", "-config", filepath.Join(e.work, "agent.json"), "-once").CombinedOutput()
	e.agentLog += string(out)
	if err != nil {
		e.t.Fatalf("agent: %v\n%s", err, out)
	}
}

func (e *sambaE2E) dispatch() {
	e.t.Helper()
	for range 5 {
		if err := e.engine.DispatchPendingEvents(context.Background()); err != nil {
			e.t.Fatal(err)
		}
	}
	left, _ := e.db.GetPendingSyncEvents(20)
	for _, ev := range left {
		e.t.Logf("undelivered %s for %s: %s", ev.EventType, ev.UserID, ev.LastError)
	}
}

// state is the connector view's directory password state for user.
func (e *sambaE2E) state(user string) string {
	rr := e.admin("GET", "/api/admin/systems/"+e.id+"/active-directory", "")
	var v struct{ Passwords []store.ADPasswordStatus }
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	for _, p := range v.Passwords {
		if p.Username == user {
			return p.State + " " + p.LastError
		}
	}
	return "absent"
}

// assignedUser creates username with password (as an administrator would) in group
// pc-users, assigns the group to the connector's app and syncs.
func (e *sambaE2E) assignedUser(username, password string) (*store.User, *store.Group) {
	t := e.t
	if rr := e.admin("POST", "/api/admin/users", `{"username":"`+username+`","displayName":"Win User","email":"`+username+`@kyws.test","password":"`+password+`"}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	user, _ := e.db.GetUserByUsername(username)
	group := &store.Group{ID: "11111111-2222-3333-4444-555555555555", Name: "pc-users"}
	if err := e.db.DefaultOrg().CreateGroup(group, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.db.DefaultOrg().SetGroupMembership(group.ID, user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	apps, _, _ := e.db.ListAppRecords("", 100, 0)
	app := ""
	for _, a := range apps {
		if a.SystemID == e.id {
			app = a.ID
		}
	}
	if err := e.db.DefaultOrg().SetAppAssignment(app, "groups", group.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	e.dispatch()
	return user, group
}

// setStatus sets the user active or disabled, as an administrator, and syncs.
func (e *sambaE2E) setStatus(user *store.User, status string) {
	e.t.Helper()
	if rr := e.admin("PUT", "/api/admin/users/"+user.ID, `{"status":"`+status+`"}`); rr.Code != http.StatusOK {
		e.t.Fatal(rr.Body.String())
	}
	e.dispatch()
}

// TestSambaADEndToEnd drives this branch's HTTP server, the built DC agent and a real Samba
// AD DC. It runs only from scripts/e2e-samba-ad-kyidentity.sh, which starts the DC.
func TestSambaADEndToEnd(t *testing.T) {
	e := startSambaE2E(t)
	env, srv, db, cookie, id, settings, dc, must, agent, dispatch, state := e.env, e.srv, e.db, e.cookie, e.id, e.settings, e.dc, e.must, e.agent, e.dispatch, e.state
	read := e.read
	outsiderBefore, _ := dc("dc_attrs_hash", env["E2E_DC_OUTSIDER_DN"])
	squatterBefore, _ := dc("dc_attrs_hash", env["E2E_DC_SQUATTER_DN"])
	put := func(ca string) int {
		b, _ := json.Marshal(map[string]any{"ldapsUrl": env["E2E_DC_LDAPS_URL"], "bindDn": settings["bindDn"], "baseDn": settings["baseDn"], "caPem": ca, "agentPublicKey": settings["agentPublicKey"]})
		return adminRequest(t, srv, "PUT", "/api/admin/systems/"+id+"/active-directory", cookie, string(b)).Code
	}
	must("settings accept another CA", put(read(env["E2E_DC_WRONG_CA"])) == http.StatusOK)
	must("Test connection fails against a CA that did not sign the DC", adminRequest(t, srv, "POST", "/api/admin/systems/"+id+"/test", cookie, "").Code == http.StatusBadRequest)
	must("settings restore the right CA", put(settings["caPem"].(string)) == http.StatusOK)

	// A user created with a password before assignment: only a later change reaches AD.
	user, group := e.assignedUser("winuser", "Kyws-Initial-Pass-1")
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

	e.setStatus(user, "disabled")
	uac, _ := dc("dc_uac", "winuser")
	must("disabling the user in KyIdentity disables the AD account (514)", strings.TrimSpace(uac) == "514")
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-5")
	must("the disabled account no longer logs in", !ok)

	// A reset while disabled replaces the directory's copy before the account is enabled.
	setByAdmin("Kyws-Admin-Set-6")
	e.setStatus(user, "active")
	uac, _ = dc("dc_uac", "winuser")
	must("re-enabling waits for the agent to replace the retained password", strings.TrimSpace(uac) == "514")
	agent()
	dispatch()
	uac, _ = dc("dc_uac", "winuser")
	must("the account is enabled once the reset reached the directory", strings.TrimSpace(uac) == "512")
	_, ok = dc("dc_kinit", "winuser", "Kyws-Changed-Pass-5")
	must("the password from before the reset no longer logs in", !ok)

	// A rename upstream (SCIM) renames the AD account: logon name, UPN and CN.
	if _, err := db.DefaultOrg().EditUser(user.ID, nil, func(x *store.User) (bool, error) { x.Username = "winuser2"; return false, nil }); err != nil {
		t.Fatal(err)
	}
	dispatch()
	renamed, _ := dc("dc_ldapsearch", env["E2E_DC_OU"], "(sAMAccountName=winuser2)", "-o", "ldif-wrap=no", "adminDescription", "userPrincipalName")
	must("a rename in KyIdentity renames the AD account", strings.Contains(renamed, "adminDescription: kyidentity:"+id+":user:"+user.ID) &&
		strings.Contains(renamed, "userPrincipalName: winuser2@kyws.test") && strings.Contains(renamed, "dn: CN=winuser2,"+env["E2E_DC_OU"]))
	old, _ := dc("dc_ldapsearch", env["E2E_DC_OU"], "(sAMAccountName=winuser)", "-o", "ldif-wrap=no", "dn")
	must("the old logon name is gone", !strings.Contains(old, "dn:"))

	// A KyIdentity user whose name an unmanaged AD object holds is refused, not merged.
	if rr := adminRequest(t, srv, "POST", "/api/admin/users", cookie, `{"username":"squatter","email":"squatter@kyws.test","password":"Kyws-Squatter-Pass-4"}`); rr.Code != http.StatusOK {
		t.Fatal(rr.Body.String())
	}
	squatter, _ := db.GetUserByUsername("squatter")
	if err := db.DefaultOrg().SetGroupMembership(group.ID, squatter.ID, true, nil); err != nil {
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
	for _, secret := range []string{"Kyws-Admin-Set-2", "Kyws-Changed-Pass-5", "onlylowercaseletterslong", e.agentToken} {
		must("the agent log holds no "+secret[:6]+"… secret", !strings.Contains(e.agentLog, secret))
	}
}
