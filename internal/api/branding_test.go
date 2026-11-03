package api

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func brandingPublic(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
	return rr
}

type brandingBody struct {
	Name    string `json:"name"`
	LogoURL string `json:"logoUrl"`
}

func readBranding(t *testing.T, srv *Server) brandingBody {
	t.Helper()
	rr := brandingPublic(t, srv, "/api/branding")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/branding: %d %s", rr.Code, rr.Body.String())
	}
	var b brandingBody
	if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func putLogo(t *testing.T, srv *Server, cookie, contentType string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	csrf := srv.middleware.IssueCSRFToken(cookie)
	req := httptest.NewRequest("PUT", "/api/admin/branding/logo", bytes.NewReader(data))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: cookie})
	req.AddCookie(&http.Cookie{Name: "kyidentity_csrf", Value: csrf})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

func brandingAudits(t *testing.T, db *store.Store, action string) []store.AuditEvent {
	t.Helper()
	rows, _, err := db.SearchAuditEvents(store.AuditFilter{Action: action, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func sizedPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 200, G: 80, B: 20, A: 255})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The organisation name is public for the sign-in page, set by an administrator with an
// audit row, and refuses characters that could disguise text on the sign-in page.
func TestBrandingName(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))

	if b := readBranding(t, srv); b != (brandingBody{}) {
		t.Fatalf("fresh install branding = %+v, want empty", b)
	}

	if rr := adminRequest(t, srv, "PUT", "/api/admin/branding/name", admin, `{"name":"  Acme Holdings  "}`); rr.Code != http.StatusOK {
		t.Fatalf("set name: %d %s", rr.Code, rr.Body.String())
	}
	if b := readBranding(t, srv); b.Name != "Acme Holdings" {
		t.Fatalf("name = %q", b.Name)
	}
	rows := brandingAudits(t, db, "admin.branding_name_changed")
	if len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"new":"Acme Holdings"`) {
		t.Fatalf("audit rows = %+v", rows)
	}

	for _, bad := range []string{
		`{"name":"Acme‮gnp.exe"}`,       // bidi override
		`{"name":"Acme\nSign in here"}`, // line break
		`{"name":"Ac​me"}`,              // invisible
		`{"name":"` + strings.Repeat("a", 65) + `"}`,
		`{}`,
		`{"name":"Acme","css":"body{}"}`, // nothing but the name is accepted
	} {
		if rr := adminRequest(t, srv, "PUT", "/api/admin/branding/name", admin, bad); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, rr.Code)
		}
	}
	if b := readBranding(t, srv); b.Name != "Acme Holdings" {
		t.Fatalf("a refused name changed the stored one: %q", b.Name)
	}
	if n := len(brandingAudits(t, db, "admin.branding_name_changed")); n != 1 {
		t.Fatalf("refused names were audited as changes: %d rows", n)
	}

	if rr := adminRequest(t, srv, "PUT", "/api/admin/branding/name", admin, `{"name":""}`); rr.Code != http.StatusOK {
		t.Fatalf("clear name: %d", rr.Code)
	}
	if b := readBranding(t, srv); b.Name != "" {
		t.Fatalf("cleared name = %q", b.Name)
	}
}

// A logo is accepted only as PNG or JPEG by its bytes, re-encoded so nothing rides along,
// served as an image that cannot run as a document, audited, and removable.
func TestBrandingLogo(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))

	if rr := brandingPublic(t, srv, "/api/branding/logo"); rr.Code != http.StatusNotFound {
		t.Fatalf("logo before upload: %d", rr.Code)
	}

	// A polyglot: a valid PNG with HTML after IEND. Re-encoding must drop the tail.
	polyglot := append(sizedPNG(t, 64, 32), []byte("<html><script>alert(1)</script>")...)
	if rr := putLogo(t, srv, admin, "image/png", polyglot); rr.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rr.Code, rr.Body.String())
	}
	b := readBranding(t, srv)
	if !strings.HasPrefix(b.LogoURL, "/api/branding/logo?v=") {
		t.Fatalf("logoUrl = %q", b.LogoURL)
	}
	served := brandingPublic(t, srv, b.LogoURL)
	if served.Code != http.StatusOK || served.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("serve: %d %q", served.Code, served.Header().Get("Content-Type"))
	}
	if bytes.Contains(served.Body.Bytes(), []byte("script")) {
		t.Fatal("bytes after the image survived the upload")
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(served.Body.Bytes()))
	if err != nil || cfg.Width != 64 || cfg.Height != 32 {
		t.Fatalf("served logo is not the 64x32 PNG: %+v %v", cfg, err)
	}
	h := served.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("logo headers allow it to act as a document: %v", h)
	}
	if !strings.Contains(h.Get("Cache-Control"), "immutable") {
		t.Fatalf("versioned logo not cacheable: %q", h.Get("Cache-Control"))
	}
	if cc := brandingPublic(t, srv, "/api/branding/logo?v=old").Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("stale version cached: %q", cc)
	}
	rows := brandingAudits(t, db, "admin.branding_logo_uploaded")
	if len(rows) != 1 || !strings.Contains(rows[0].DetailsJSON, `"width":64`) {
		t.Fatalf("upload audit = %+v", rows)
	}

	// JPEG stays JPEG.
	img := image.NewRGBA(image.Rect(0, 0, 40, 40))
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, img, nil); err != nil {
		t.Fatal(err)
	}
	if rr := putLogo(t, srv, admin, "image/jpeg", jb.Bytes()); rr.Code != http.StatusOK {
		t.Fatalf("jpeg upload: %d %s", rr.Code, rr.Body.String())
	}
	if ct := brandingPublic(t, srv, readBranding(t, srv).LogoURL).Header().Get("Content-Type"); ct != "image/jpeg" {
		t.Fatalf("jpeg served as %q", ct)
	}
	jpegURL := readBranding(t, srv).LogoURL

	for name, tc := range map[string]struct {
		contentType string
		data        []byte
		code        int
	}{
		"svg":             {"image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>`), 400},
		"html as png":     {"image/png", []byte("<html><script>alert(1)</script></html>"), 400},
		"gif":             {"image/gif", []byte("GIF89a\x01\x00\x01\x00\x00\x00\x00;"), 400},
		"truncated png":   {"image/png", sizedPNG(t, 8, 8)[:40], 400},
		"too wide":        {"image/png", sizedPNG(t, 513, 10), 400},
		"too large bytes": {"image/png", append(sizedPNG(t, 8, 8), make([]byte, maxLogoBytes)...), 413},
		"empty":           {"image/png", nil, 400},
	} {
		if rr := putLogo(t, srv, admin, tc.contentType, tc.data); rr.Code != tc.code {
			t.Errorf("%s: %d, want %d (%s)", name, rr.Code, tc.code, rr.Body.String())
		}
	}
	if got := readBranding(t, srv).LogoURL; got != jpegURL {
		t.Fatalf("a refused upload replaced the logo: %q", got)
	}

	if rr := adminRequest(t, srv, "DELETE", "/api/admin/branding/logo", admin, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if b := readBranding(t, srv); b.LogoURL != "" {
		t.Fatalf("logo after delete: %q", b.LogoURL)
	}
	if rr := brandingPublic(t, srv, jpegURL); rr.Code != http.StatusNotFound {
		t.Fatalf("deleted logo still served: %d", rr.Code)
	}
	if n := len(brandingAudits(t, db, "admin.branding_logo_removed")); n != 1 {
		t.Fatalf("removal audits = %d", n)
	}
}

// Only global administrators change branding, and only with the CSRF token.
func TestBrandingNeedsAdministrator(t *testing.T) {
	srv, db, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	user := newSession(t, db, newUser(t, db, "user"), time.Now().UTC().Add(time.Hour))
	if rr := adminRequest(t, srv, "PUT", "/api/admin/branding/name", user, `{"name":"Evil"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("user set the name: %d", rr.Code)
	}
	if rr := putLogo(t, srv, user, "image/png", sizedPNG(t, 4, 4)); rr.Code != http.StatusForbidden {
		t.Fatalf("user set the logo: %d", rr.Code)
	}
	// An administrator's cookie alone, without the CSRF token, changes nothing.
	admin := newSession(t, db, newUser(t, db, "admin"), time.Now().UTC().Add(time.Hour))
	req := httptest.NewRequest("PUT", "/api/admin/branding/name", strings.NewReader(`{"name":"Forged"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "kyidentity_session", Value: admin})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-site name change: %d", rr.Code)
	}
	if b := readBranding(t, srv); b != (brandingBody{}) {
		t.Fatalf("branding changed: %+v", b)
	}
}
