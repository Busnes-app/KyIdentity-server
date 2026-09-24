package api

import (
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestEmbeddedFaviconContentTypes(t *testing.T) {
	s, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	s.staticFS = fstest.MapFS{"favicon.ico": &fstest.MapFile{Data: []byte{0, 0, 1, 0}}, "favicon.svg": &fstest.MapFile{Data: []byte("<svg/>")}}
	for path, want := range map[string]string{"/favicon.ico?v=busnes-1": "image/x-icon", "/favicon.svg?v=busnes-1": "image/svg+xml"} {
		rec := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || rec.Header().Get("Content-Type") != want {
			t.Fatalf("%s: status %d, type %s", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	delete(s.staticFS.(fstest.MapFS), "favicon.ico")
	rec := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest("GET", "/favicon.ico", nil))
	if rec.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatal("SVG fallback must keep its SVG content type")
	}
}
