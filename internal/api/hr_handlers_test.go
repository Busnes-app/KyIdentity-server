package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func TestHRAPIAuthenticationOwnershipAndVersioning(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	c, token := connectorWithToken(t, srv, db, admin, "write")
	if err := db.CreatePairedSystem(&store.PairedSystem{ID: "post", Name: "KyPost", SystemType: "kypost", CallbackURL: "https://post.example/api/sync/webhook", Status: "active"}, nil); err != nil {
		t.Fatal(err)
	}
	config := `{"systemId":"post","domain":"example.test","writebackUrl":"https://hr.example/writeback","writebackToken":"private-writeback-token"}`
	path := "/api/admin/scim-connectors/" + c + "/hr"
	if got := adminRequestNoStepUp(t, srv, "PUT", path, admin, config); got.Code != 403 {
		t.Fatal("missing step-up accepted", got.Code)
	}
	if got := adminRequest(t, srv, "PUT", path, admin, config); got.Code != 200 {
		t.Fatal(got.Code, got.Body.String())
	}
	body := `{"sourceUid":"WID-1","sourceVersion":1,"preferredName":"alice","displayName":"Alice","active":true}`
	if got := scimCall(t, srv, "", "POST", "/hr/v1/workers", body); got.Code != 401 {
		t.Fatal("anonymous import", got.Code)
	}
	got := scimCall(t, srv, token, "POST", "/hr/v1/workers", body)
	if got.Code != 200 {
		t.Fatal(got.Code, got.Body.String())
	}
	var worker store.HRWorker
	if err := json.Unmarshal(got.Body.Bytes(), &worker); err != nil {
		t.Fatal(err)
	}
	if worker.State != "mailbox_pending" || worker.Email != "" {
		t.Fatal(worker)
	}
	if u, _ := db.DefaultOrg().GetUserByID(worker.ID); u != nil {
		t.Fatal("premature SSO identity")
	}
	for _, bad := range []string{strings.Replace(body, `"active":true`, `"active":true,"email":"takeover@example.test"`, 1), strings.Replace(body, `"active":true`, `"active":true,"role":"admin"`, 1), strings.Replace(body, `,"active":true`, "", 1), body + `{}`} {
		if got := scimCall(t, srv, token, "POST", "/hr/v1/workers", bad); got.Code != 400 {
			t.Fatal("invalid import accepted", got.Code, bad)
		}
	}
	if got := scimCall(t, srv, token, "POST", "/hr/v1/workers", strings.Replace(body, `"Alice"`, `"Changed"`, 1)); got.Code != 409 {
		t.Fatal("same-version overwrite", got.Code)
	}
	if got := scimCall(t, srv, token, "POST", "/scim/v2/Users", `{}`); got.Code != 403 {
		t.Fatal("SCIM bypass allowed", got.Code)
	}
	_, other := connectorWithToken(t, srv, db, admin, "write")
	if got := scimCall(t, srv, other, "GET", "/hr/v1/workers?sourceUid=WID-1", ""); got.Code != 404 {
		t.Fatal("cross-source read", got.Code)
	}
	read, _, err := db.DefaultOrg().IssueSCIMToken(c, "read", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := scimCall(t, srv, read, "POST", "/hr/v1/workers", body); got.Code != http.StatusForbidden {
		t.Fatal("read token wrote", got.Code)
	}
	status := adminRequest(t, srv, "GET", path, admin, "")
	if status.Code != 200 || strings.Contains(status.Body.String(), "private-writeback-token") || strings.Contains(status.Body.String(), "writebackSecret") {
		t.Fatal("status exposes secret", status.Body.String())
	}
}
