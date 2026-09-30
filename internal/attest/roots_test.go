package attest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pemOf(c *testCA) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.rootDER}))
}

func TestRefreshingRoots(t *testing.T) {
	base := newTestCA(t, "base", time.Now().Add(time.Hour))
	extra := newTestCA(t, "extra", time.Now().Add(time.Hour))
	body, _ := json.Marshal([]string{pemOf(extra)})
	r := NewRefreshingRoots([]*x509.Certificate{base.root}, "https://x", fetchOf(string(body), "", nil))
	if _, certs := r.Pool(); len(certs) != 1 {
		t.Fatalf("before refresh: %d", len(certs))
	}
	if err := r.Refresh(); err != nil {
		t.Fatal(err)
	}
	pool, certs := r.Pool()
	if len(certs) != 2 || pool == nil {
		t.Fatalf("after refresh: %d", len(certs))
	}
	r.fetch = func(string) ([]byte, http.Header, error) { return nil, nil, errors.New("down") }
	if r.Refresh() == nil {
		t.Fatal("expected error")
	}
	if _, certs := r.Pool(); len(certs) != 2 {
		t.Fatalf("failed refresh must keep set: %d", len(certs))
	}
	if NewRefreshingRoots(nil, "", nil).Refresh() != nil {
		t.Fatal("empty url must be a no-op")
	}
}

func TestLoadExtraRoots(t *testing.T) {
	a := newTestCA(t, "a", time.Now().Add(time.Hour))
	b := newTestCA(t, "b", time.Now().Add(time.Hour))
	p := filepath.Join(t.TempDir(), "extra.pem")
	if err := os.WriteFile(p, []byte(pemOf(a)+pemOf(b)), 0o600); err != nil {
		t.Fatal(err)
	}
	certs, err := LoadExtraRoots(p)
	if err != nil || len(certs) != 2 {
		t.Fatalf("%d %v", len(certs), err)
	}
	if certs, err := LoadExtraRoots(""); err != nil || certs != nil {
		t.Fatalf("empty path: %v %v", certs, err)
	}
}
