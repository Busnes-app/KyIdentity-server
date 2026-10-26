package netguard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A strong server leaf avoids server-side weak-key refusal: this check proves
// the real product client refuses an undersized, explicitly trusted CA key.
func TestStrongHTTPSChecksTrustedRootKeys(t *testing.T) {
	previous := AllowLoopback
	AllowLoopback = true
	t.Cleanup(func() { AllowLoopback = previous })
	for _, bits := range []int{1024, 2047, 2048} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			rootKey, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
			rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
			if err != nil {
				t.Fatal(err)
			}
			root, err = x509.ParseCertificate(rootDER)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			peer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
			peer.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}}}
			peer.StartTLS()
			defer peer.Close()
			for _, device := range []bool{false, true} {
				client := client(5*time.Second, device)
				transport := client.Transport.(*http.Transport)
				defer transport.CloseIdleConnections()
				pool := x509.NewCertPool()
				pool.AddCert(root)
				transport.TLSClientConfig = &tls.Config{RootCAs: pool}
				before := calls.Load()
				req, err := http.NewRequest(http.MethodGet, peer.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer synthetic-credential")
				resp, err := client.Do(req)
				if resp != nil {
					resp.Body.Close()
				}
				refuse := bits < 2048 && fips140.Enabled()
				if (err != nil) != refuse {
					t.Fatalf("RSA%d device=%v configured=%v: %v", bits, device, fips140.Enabled(), err)
				}
				if refuse && calls.Load() != before {
					t.Fatal("credential crossed weak-root TLS")
				}
			}
		})
	}
}
