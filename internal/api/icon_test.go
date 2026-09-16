package api

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func uploadIcon(t *testing.T, srv *Server, cookie, contentType string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	csrf := srv.middleware.IssueCSRFToken(cookie)
	req := httptest.NewRequest("POST", "/api/admin/icons", bytes.NewReader(data))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 77, G: 238, B: 234, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func iconNameFrom(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("upload returned %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		IconName string `json:"iconName"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || !strings.HasPrefix(out.IconName, "icon:") {
		t.Fatalf("upload body %q is not an icon name", rr.Body.String())
	}
	return out.IconName
}

// An uploaded icon is named by a card, served to signed-in users as an image, and removed
// once the card that named it is gone.
func TestUploadedIconLifecycle(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	// The bytes decide the type, not the header.
	iconName := iconNameFrom(t, uploadIcon(t, srv, cookie, "application/octet-stream", tinyPNG(t)))
	id := strings.TrimPrefix(iconName, "icon:")

	created := adminRequestNoStepUp(t, srv, "POST", "/api/admin/applications", cookie,
		`{"name":"Portainer","url":"https://portainer.example.test","iconName":"`+iconName+`"}`)
	if created.Code != http.StatusOK {
		t.Fatalf("create with uploaded icon returned %d: %s", created.Code, created.Body.String())
	}
	var app struct {
		Application struct {
			ID string `json:"id"`
		} `json:"application"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &app); err != nil {
		t.Fatal(err)
	}

	allowTestAppAccess(t, db, app.Application.ID)
	card := cardByID(launcherCards(t, srv, cookie), app.Application.ID)
	if card == nil || card.IconName != iconName {
		t.Fatalf("launcher card = %+v, want iconName %s", card, iconName)
	}

	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/icons/"+id, nil)
		req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		return rr
	}
	served := get()
	if served.Code != http.StatusOK || served.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("serve returned %d %s", served.Code, served.Header().Get("Content-Type"))
	}
	if csp := served.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "sandbox") {
		t.Errorf("icon served without a sandboxing CSP: %q", csp)
	}
	if !bytes.Equal(served.Body.Bytes(), tinyPNG(t)) {
		t.Error("served bytes differ from the upload")
	}

	anon := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(anon, httptest.NewRequest("GET", "/api/icons/"+id, nil))
	if anon.Code != http.StatusUnauthorized {
		t.Errorf("anonymous icon fetch returned %d, want 401", anon.Code)
	}

	deleted := adminRequestNoStepUp(t, srv, "DELETE", "/api/admin/applications/"+app.Application.ID, cookie, "")
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete returned %d: %s", deleted.Code, deleted.Body.String())
	}
	if gone := get(); gone.Code != http.StatusNotFound {
		t.Errorf("icon still served after its card was deleted: %d", gone.Code)
	}
}

// An upload the picker never saved has no card to be dropped with; the sweep gets it.
func TestOrphanedIconsAreSwept(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	orphan := strings.TrimPrefix(iconNameFrom(t, uploadIcon(t, srv, cookie, "image/png", tinyPNG(t))), "icon:")
	kept := iconNameFrom(t, uploadIcon(t, srv, cookie, "image/png", tinyPNG(t)))
	if rr := adminRequestNoStepUp(t, srv, "POST", "/api/admin/applications", cookie,
		`{"name":"Kept","url":"https://kept.example.test","iconName":"`+kept+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("create returned %d: %s", rr.Code, rr.Body.String())
	}

	// Inside the grace window nothing goes.
	if n, err := db.DeleteOrphanedLauncherIcons(time.Hour); err != nil || n != 0 {
		t.Fatalf("sweep inside grace window removed %d (err %v), want 0", n, err)
	}
	if n, err := db.DeleteOrphanedLauncherIcons(0); err != nil || n != 1 {
		t.Fatalf("sweep removed %d (err %v), want the one orphan", n, err)
	}
	if icon, err := db.GetLauncherIcon(orphan); err != nil || icon != nil {
		t.Errorf("orphan still stored after sweep: %v %v", icon, err)
	}
	if icon, err := db.GetLauncherIcon(strings.TrimPrefix(kept, "icon:")); err != nil || icon == nil {
		t.Errorf("referenced icon was swept: %v %v", icon, err)
	}
}

// A client card's upload goes with the client, the same as an application card's does.
func TestDeletingClientDropsItsUploadedIcon(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))
	newClient(t, db, "kynotes", []string{"https://notes.example.test/cb"}, []string{"openid"})

	iconName := iconNameFrom(t, uploadIcon(t, srv, cookie, "image/png", tinyPNG(t)))
	id := strings.TrimPrefix(iconName, "icon:")
	if rr := adminRequestNoStepUp(t, srv, "PUT", "/api/admin/clients/kynotes/launcher", cookie,
		`{"description":"Notes","iconName":"`+iconName+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("launcher edit returned %d: %s", rr.Code, rr.Body.String())
	}

	grant := adminRequestNoStepUp(t, srv, "POST", "/api/auth/step-up", cookie, `{"password":"correct-horse-battery","operation":"DELETE /api/admin/clients/kynotes"}`)
	var stepUp struct {
		Token string `json:"stepUpToken"`
	}
	if err := json.Unmarshal(grant.Body.Bytes(), &stepUp); err != nil || stepUp.Token == "" {
		t.Fatalf("step-up grant failed: %d %s", grant.Code, grant.Body.String())
	}
	if rr := adminRequestWithStepUp(t, srv, "DELETE", "/api/admin/clients/kynotes", cookie, "", stepUp.Token); rr.Code != http.StatusOK {
		t.Fatalf("client delete returned %d: %s", rr.Code, rr.Body.String())
	}
	if icon, err := db.GetLauncherIcon(id); err != nil || icon != nil {
		t.Errorf("icon survived its client: %v %v", icon, err)
	}
}

func TestUploadedIconRejectsUnsafeContent(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newUser(t, db, "admin")
	cookie := newSession(t, db, admin, time.Now().UTC().Add(time.Hour))

	cases := map[string]struct {
		contentType string
		body        string
	}{
		"html declared as png":  {"image/png", "<html><script>alert(1)</script></html>"},
		"svg with script":       {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`},
		"svg with handler":      {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`},
		"svg with external ref": {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.test/x.png"/></svg>`},
		"svg with entities":     {"image/svg+xml", `<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>`},
		"not svg":               {"image/svg+xml", `<html xmlns="http://www.w3.org/1999/xhtml"></html>`},
		"xsl stylesheet pi":     {"image/svg+xml", `<?xml-stylesheet href="https://evil.test/x.xsl" type="text/xsl"?><svg xmlns="http://www.w3.org/2000/svg"/>`},
		"style import":          {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><style>@import url("https://evil.test/x.css");</style></svg>`},
		"style attr url":        {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://evil.test/x.svg#p)"/></svg>`},
		"animateTransform":      {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><rect><animateTransform attributeName="transform"/></rect></svg>`},
		"fill funcIRI":          {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><rect fill="url(https://evil.test/p.svg#p)"/></svg>`},
		"filter funcIRI quoted": {"image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"><rect filter="url('//evil.test/f.svg#f')"/></svg>`},
	}
	for name, c := range cases {
		if rr := uploadIcon(t, srv, cookie, c.contentType, []byte(c.body)); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: returned %d, want 400", name, rr.Code)
		}
	}

	safe := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><defs><linearGradient id="g"/></defs><style>.a{fill:url(#g)}</style><use href="#c"/><circle id="c" class="a" cx="5" cy="5" r="4" stroke="url( '#g' )" style="filter:url(#g)"/></svg>`
	if rr := uploadIcon(t, srv, cookie, "image/svg+xml", []byte(safe)); rr.Code != http.StatusOK {
		t.Errorf("plain svg rejected: %d %s", rr.Code, rr.Body.String())
	}

	big := bytes.Repeat([]byte("x"), maxIconBytes+1)
	if rr := uploadIcon(t, srv, cookie, "image/png", big); rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized upload returned %d, want 413", rr.Code)
	}

	unknown := adminRequestNoStepUp(t, srv, "POST", "/api/admin/applications", cookie,
		`{"name":"X","url":"https://x.example.test","iconName":"icon:00000000-0000-0000-0000-000000000000"}`)
	if unknown.Code != http.StatusBadRequest {
		t.Errorf("card naming a missing upload returned %d, want 400", unknown.Code)
	}
}
