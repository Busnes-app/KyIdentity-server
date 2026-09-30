package attest

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	_ "embed"
)

//go:embed roots.json
var embeddedRootsJSON []byte

const LegacyRSARootSerialNumber = "f92009e853b6b045"

type Roots interface {
	Pool() (*x509.CertPool, []*x509.Certificate)
}

type StaticRoots struct{ certs []*x509.Certificate }

func (s *StaticRoots) Pool() (*x509.CertPool, []*x509.Certificate) {
	p := x509.NewCertPool()
	for _, c := range s.certs {
		p.AddCert(c)
	}
	return p, s.certs
}

func parsePEMs(pems []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, s := range pems {
		rest := []byte(s)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates")
	}
	return out, nil
}

func LoadEmbeddedRoots() (*StaticRoots, error) {
	var pems []string
	if err := json.Unmarshal(embeddedRootsJSON, &pems); err != nil {
		return nil, fmt.Errorf("embedded roots: %w", err)
	}
	certs, err := parsePEMs(pems)
	if err != nil {
		return nil, err
	}
	return &StaticRoots{certs: certs}, nil
}

func LoadExtraRoots(path string) ([]*x509.Certificate, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePEMs([]string{string(raw)})
}

// RefreshingRoots serves the embedded and extra roots plus whatever the root endpoint published
// at the last successful refresh. A failed refresh keeps the previous set.
type RefreshingRoots struct {
	mu      sync.RWMutex
	base    []*x509.Certificate
	fetched []*x509.Certificate
	url     string
	fetch   func(url string) ([]byte, http.Header, error)
}

func NewRefreshingRoots(base []*x509.Certificate, url string, fetch func(string) ([]byte, http.Header, error)) *RefreshingRoots {
	return &RefreshingRoots{base: base, url: url, fetch: fetch}
}

func (r *RefreshingRoots) Refresh() error {
	if r.url == "" {
		return nil
	}
	body, _, err := r.fetch(r.url)
	if err != nil {
		return err
	}
	var pems []string
	if err := json.Unmarshal(body, &pems); err != nil {
		return err
	}
	certs, err := parsePEMs(pems)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.fetched = certs
	r.mu.Unlock()
	return nil
}

func (r *RefreshingRoots) Pool() (*x509.CertPool, []*x509.Certificate) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	all := append(append([]*x509.Certificate{}, r.base...), r.fetched...)
	p := x509.NewCertPool()
	for _, c := range all {
		p.AddCert(c)
	}
	return p, all
}
