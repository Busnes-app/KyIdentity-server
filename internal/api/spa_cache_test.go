package api

import (
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// The entry document names the current hashed bundles, so browsers must revalidate it: a tab
// opened after an upgrade then loads the new build. Hashed assets keep their caching, and
// the fallback under /oauth/ keeps the middleware's no-store.
func TestEntryDocumentRevalidatesAndAssetsKeepCaching(t *testing.T) {
	s, _, _, _, _, cleanup := setupTestServer(t)
	defer cleanup()
	s.staticFS = fstest.MapFS{
		"index.html":          &fstest.MapFile{Data: []byte(`<script type="module" src="/assets/index-abc.js"></script>`)},
		"assets/index-abc.js": &fstest.MapFile{Data: []byte("export {}")},
	}
	for path, want := range map[string]string{"/": "no-cache", "/settings/appearance": "no-cache", "/assets/index-abc.js": "", "/oauth/unknown": "no-store"} {
		rec := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != want {
			t.Errorf("%s: status %d, Cache-Control %q, want %q", path, rec.Code, rec.Header().Get("Cache-Control"), want)
		}
	}
}
