package oauth

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Exercise the real guarded HTTPS transport with the standard httptest CA.
// Trust is private to this test process; no production certificate check is bypassed.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kyidentity-test-ca-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	server.Close()
	file := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(file, cert, 0600); err == nil {
		err = os.Setenv("SSL_CERT_FILE", file)
	}
	if err == nil {
		err = os.Setenv("SSL_CERT_DIR", dir)
	}
	if err != nil {
		os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
