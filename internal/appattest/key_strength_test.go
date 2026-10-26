package appattest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/Busnes-app/kyidentity-server/internal/appattest/appattesttest"
)

func TestAppAttestCertificateKeyFloor(t *testing.T) {
	for _, role := range []string{"root", "intermediate"} {
		for _, bits := range []int{1024, 2047, 2048} {
			t.Run(fmt.Sprintf("%s/RSA%d", role, bits), func(t *testing.T) {
				key, err := rsa.GenerateKey(rand.Reader, bits)
				if err != nil {
					t.Fatal(err)
				}
				strong, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				var root, inter crypto.Signer = strong, strong
				if role == "root" {
					root = key
				} else {
					inter = key
				}
				ca := appattesttest.NewCA(t, root, inter)
				cdh := sha256.Sum256([]byte("fixture client data"))
				keyID, object := ca.Attest(t, appattesttest.Options{AppID: appID, ClientDataHash: cdh[:]})
				verifier := NewVerifierWithRoot(ca.Root, []string{appID}, false)
				err = verifier.Verify(keyID, object, cdh[:])
				if bits < 2048 {
					if err == nil {
						t.Fatalf("accepted RSA-%d %s", bits, role)
					}
				} else if err != nil {
					t.Fatalf("strong chain failed: %v", err)
				}
			})
		}
	}
}
