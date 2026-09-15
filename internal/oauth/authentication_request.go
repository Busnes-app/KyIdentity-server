package oauth

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/store"
)

const PasswordACR = "urn:kyidentity:acr:password"
const MFAACR = "urn:kyidentity:acr:mfa"

// AuthenticationRequest only strengthens the ordinary SSO login requirements.
// A zero maximum age means one fresh interaction, not an unachievable zero-second
// lifetime for the resulting code. Positive ages are checked again at exchange.
type AuthenticationRequest struct {
	Fresh, Silent bool
	MaxAge        *int64
	ACR           string
	AppPolicy     store.AppAuthenticationPolicy
}

func ParseAuthenticationRequest(q url.Values) (AuthenticationRequest, error) {
	p := AuthenticationRequest{}
	invalid := errors.New("unsupported or malformed authentication request")
	for _, values := range q {
		if len(values) != 1 {
			return p, invalid
		}
	}
	if _, ok := q["prompt"]; ok {
		switch q.Get("prompt") {
		case "none":
			p.Silent = true
		case "login":
			p.Fresh = true
		default:
			return p, invalid
		}
	}
	if values, ok := q["max_age"]; ok {
		raw := values[0]
		if raw == "" {
			return p, invalid
		}
		for _, c := range raw {
			if c < '0' || c > '9' {
				return p, invalid
			}
		}
		age, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return p, invalid
		}
		if age == 0 {
			p.Fresh = true
		} else {
			p.MaxAge = &age
		}
	}
	if values, ok := q["acr_values"]; ok {
		choices := strings.Fields(values[0])
		if len(choices) == 0 {
			return p, invalid
		}
		for _, v := range choices {
			if v != PasswordACR && v != MFAACR {
				return p, invalid
			}
		}
		p.ACR = choices[0]
	}
	// These alternate request/claim formats are not implemented. Never silently
	// ignore an assurance requirement transported in one of them.
	for _, key := range []string{"request", "request_uri", "claims"} {
		if _, ok := q[key]; ok {
			return p, invalid
		}
	}
	return p, nil
}

func (p AuthenticationRequest) Satisfied(e store.AuthenticationEvidence, now time.Time) bool {
	if p.AppPolicy.Mode != "" && p.AppPolicy.EvidenceReason(e, now) != "" {
		return false
	}
	if p.Fresh {
		return false
	}
	if p.MaxAge != nil || p.ACR != "" {
		if e.PrimaryAuthenticatedAt == nil || e.PrimaryAuthenticatedAt.After(now) {
			return false
		}
	}
	if p.MaxAge != nil && e.PrimaryAuthenticatedAt.Before(now.Add(-time.Duration(*p.MaxAge)*time.Second)) {
		return false
	}
	if p.ACR == MFAACR {
		if e.FactorAuthenticatedAt == nil || e.FactorAuthenticatedAt.After(now) {
			return false
		}
		switch e.FactorMethod {
		case "totp", "push", "webauthn":
		default:
			return false
		}
	}
	return true
}

// App requirements and client requests combine restrictively.
func (p AuthenticationRequest) WithAppPolicy(policy store.AppAuthenticationPolicy) AuthenticationRequest {
	p.AppPolicy = policy
	p.Fresh = p.Fresh || policy.Mode == "fresh"
	return p
}
