package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/adpass"
	"github.com/Busnes-app/kyidentity-server/internal/ldaptest"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// captureOutput sends stdout, stderr and the log package to a pipe; the returned function
// restores them and hands back everything written, the audit console copies included.
func captureOutput(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	log.SetOutput(w)
	buf := &bytes.Buffer{}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(buf, r); close(done) }()
	restored := false
	restore := func() string {
		if !restored {
			restored = true
			os.Stdout, os.Stderr = stdout, stderr
			log.SetOutput(os.Stderr)
			w.Close()
			<-done
		}
		return buf.String()
	}
	t.Cleanup(func() { restore() })
	return restore
}

func agentCall(srv *Server, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func createADConnector(t *testing.T, srv *Server, cookie, name, publicKey string) (string, string) {
	t.Helper()
	_, caPEM := ldaptest.Selfsigned(t)
	body, _ := json.Marshal(map[string]any{"name": name, "systemType": "active_directory", "callbackUrl": "ldaps://dc.example.test", "bearerToken": "Bind-Secret-77",
		"activeDirectory": map[string]any{"bindDn": "CN=sync,CN=Users,DC=example,DC=test", "baseDn": "OU=KyIdentity,DC=example,DC=test",
			"caPem": caPEM, "agentPublicKey": publicKey}})
	if rr := adminRequestNoStepUp(t, srv, "POST", "/api/admin/systems", cookie, string(body)); rr.Code != http.StatusForbidden {
		t.Fatalf("creation without step-up: %d", rr.Code)
	}
	rr := adminRequest(t, srv, "POST", "/api/admin/systems", cookie, string(body))
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "Bind-Secret-77") {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created struct{ System store.PairedSystem }
	_ = json.Unmarshal(rr.Body.Bytes(), &created)
	path := "/api/admin/systems/" + created.System.ID + "/active-directory/agent-token"
	if rr := adminRequestNoStepUp(t, srv, "POST", path, cookie, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("token without step-up: %d", rr.Code)
	}
	rr = adminRequest(t, srv, "POST", path, cookie, "")
	var issued struct{ AgentToken string }
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &issued) != nil || !strings.HasPrefix(issued.AgentToken, "kyad_") {
		t.Fatalf("agent token: %d %s", rr.Code, rr.Body.String())
	}
	return created.System.ID, issued.AgentToken
}

func TestActiveDirectoryPasswordQueueEndToEnd(t *testing.T) {
	output := captureOutput(t)
	srv, db, engine, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	key, _ := adpass.GenerateKey()
	sys1, token1 := createADConnector(t, srv, cookie, "dc-one", adpass.EncodePublicKey(key.PublicKey()))
	other, _ := adpass.GenerateKey()
	sys2, token2 := createADConnector(t, srv, cookie, "dc-two", adpass.EncodePublicKey(other.PublicKey()))

	// The settings view never carries the bind password or its sealed form.
	sys, _ := db.GetPairedSystemByID(sys1)
	for _, path := range []string{"/api/admin/systems/" + sys1 + "/active-directory", "/api/admin/systems"} {
		rr := adminRequest(t, srv, "GET", path, cookie, "")
		if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "Bind-Secret-77") || strings.Contains(rr.Body.String(), sys.HMACSecretEncrypted) || strings.Contains(rr.Body.String(), token1) {
			t.Fatalf("%s exposes a secret: %d %s", path, rr.Code, rr.Body.String())
		}
	}
	if secret, err := engine.SigningSecret(sys); err != nil || secret != "Bind-Secret-77" {
		t.Fatal("bind password not sealed for the connector", err)
	}

	// Created with a password before assignment: nothing is queued for it.
	rr := adminRequest(t, srv, "POST", "/api/admin/users", cookie, `{"username":"winuser","email":"winuser@x.test","password":"Known-Test-Pass-91"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("create user: %d %s", rr.Code, rr.Body.String())
	}
	user, _ := db.GetUserByUsername("winuser")
	app := ""
	apps, _, _ := db.ListAppRecords("", 100, 0)
	for _, a := range apps {
		if a.SystemID == sys1 {
			app = a.ID
		}
	}
	if err := db.SetAppAssignment(app, "users", user.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	if rr := adminRequest(t, srv, "PUT", "/api/admin/users/"+user.ID, cookie, `{"password":"Known-Test-Pass-92"}`); rr.Code != http.StatusOK {
		t.Fatalf("admin set: %d %s", rr.Code, rr.Body.String())
	}
	userCookie := newSession(t, db, user, time.Now().UTC().Add(time.Hour))
	if rr := adminRequest(t, srv, "POST", "/api/user/password", userCookie, `{"currentPassword":"Known-Test-Pass-92","newPassword":"Known-Test-Pass-93"}`); rr.Code != http.StatusOK {
		t.Fatalf("own change: %d %s", rr.Code, rr.Body.String())
	}

	list := "/api/ad-agent/v1/passwords"
	for name, token := range map[string]string{"missing": "", "wrong": "kyad_" + strings.Repeat("0", 64), "hash": store.HashAgentToken(token1)} {
		if rr := agentCall(srv, "GET", list, token, ""); rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s token: %d", name, rr.Code)
		}
	}
	var page struct {
		ConnectorID string                  `json:"connectorId"`
		Entries     []store.ADPasswordEntry `json:"entries"`
	}
	rr = agentCall(srv, "GET", list, token2, "")
	if json.Unmarshal(rr.Body.Bytes(), &page) != nil || page.ConnectorID != sys2 || len(page.Entries) != 0 {
		t.Fatalf("another connector's token sees: %s", rr.Body.String())
	}
	rr = agentCall(srv, "GET", list, token1, "")
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &page) != nil || page.ConnectorID != sys1 || len(page.Entries) != 1 {
		t.Fatalf("queue: %d %s", rr.Code, rr.Body.String())
	}
	e := page.Entries[0]
	var settings struct{ EntrySigningKey string }
	_ = json.Unmarshal(adminRequest(t, srv, "GET", "/api/admin/systems/"+sys1+"/active-directory", cookie, "").Body.Bytes(), &settings)
	signer, err := adpass.ParseSigningKey(settings.EntrySigningKey)
	if err != nil || !adpass.VerifyEntry(signer, sys1, user.ID, e.Seq, e.ExpiresAt, e.Ciphertext, e.Signature) {
		t.Fatal("entry not signed with the key the settings page shows", err)
	}
	plain, err := adpass.Open(key, sys1, user.ID, e.Seq, e.Ciphertext)
	if err != nil || string(plain) != "Known-Test-Pass-93" {
		t.Fatal("the agent cannot open the newest password", err)
	}
	result := "/api/ad-agent/v1/passwords/" + user.ID + "/" + strconv.FormatInt(e.Seq, 10)
	if rr := agentCall(srv, "POST", result, token2, `{"outcome":"applied"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("another connector acknowledged the entry: %d", rr.Code)
	}
	if rr := agentCall(srv, "POST", result, "", `{"outcome":"applied"}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous acknowledgement: %d", rr.Code)
	}
	if rr := agentCall(srv, "POST", result, token1, `{"outcome":"applied","password":"x"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", rr.Code)
	}
	if rr := agentCall(srv, "POST", result, token1, `{"outcome":"applied"}`); rr.Code != http.StatusOK {
		t.Fatalf("acknowledge: %d %s", rr.Code, rr.Body.String())
	}
	rr = adminRequest(t, srv, "GET", "/api/admin/systems/"+sys1+"/active-directory", cookie, "")
	if !strings.Contains(rr.Body.String(), `"state":"current"`) {
		t.Fatalf("status after delivery: %s", rr.Body.String())
	}

	// No plaintext anywhere: the database file and its WAL, audit rows, logs.
	var audits strings.Builder
	rows, _, err := db.ListAuditEvents(1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	queued := 0
	for _, a := range rows {
		raw, _ := json.Marshal(a)
		audits.Write(raw)
		if a.Action == "directory.password_queued" {
			queued++
		}
	}
	if queued != 2 || !strings.Contains(audits.String(), "directory.password_delivered") {
		t.Fatalf("queue audit rows: %d", queued)
	}
	_ = db.Close()
	dump := audits.String() + output()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, _ := os.ReadFile(srv.cfg.DBPath + suffix)
		dump += string(raw)
	}
	for _, secret := range []string{"Known-Test-Pass-91", "Known-Test-Pass-92", "Known-Test-Pass-93", "Bind-Secret-77", token1, token2} {
		if strings.Contains(dump, secret) {
			t.Errorf("%q found in the database, audit rows or logs", secret)
		}
	}
	if len(dump) < 10000 {
		t.Fatal("the dump read nothing")
	}
}
