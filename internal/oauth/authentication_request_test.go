package oauth

import (
	"github.com/Busness-app/kyidentity-server/internal/store"
	"net/url"
	"testing"
	"time"
)

func TestAuthenticationRequest(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-time.Hour)
	for _, raw := range []string{"prompt=none+login", "prompt=consent", "prompt=", "prompt=login&prompt=none", "max_age=-1", "max_age=", "max_age=1.5", "max_age=%2B1", "max_age=2147483648", "acr_values=unknown", "acr_values=", "request_uri=https://example.com", "claims=%7B%7D"} {
		q, _ := url.ParseQuery(raw)
		if _, err := ParseAuthenticationRequest(q); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, tt := range []struct {
		raw  string
		e    store.AuthenticationEvidence
		want bool
	}{
		{"", store.AuthenticationEvidence{}, true},
		{"prompt=login", store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now}, false},
		{"max_age=0", store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now}, false},
		{"max_age=60", store.AuthenticationEvidence{}, false},
		{"max_age=60", store.AuthenticationEvidence{PrimaryAuthenticatedAt: &old}, false},
		{"max_age=60", store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now}, true},
		{"acr_values=" + MFAACR, store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "recovery"}, false},
		{"acr_values=" + MFAACR, store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now, FactorAuthenticatedAt: &now, FactorMethod: "webauthn"}, true},
	} {
		q, _ := url.ParseQuery(tt.raw)
		p, err := ParseAuthenticationRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Satisfied(tt.e, now); got != tt.want {
			t.Errorf("%s: got %v", tt.raw, got)
		}
	}
}
