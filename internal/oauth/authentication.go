package oauth

import "github.com/Busnes-app/kyidentity-server/internal/store"

// These context classes describe KyIdentity's verified login flow, not a NIST AAL
// or a guarantee about hardware key storage. Recovery never claims ordinary MFA.
func addAuthenticationClaims(claims map[string]any, evidence store.AuthenticationEvidence) {
	if evidence.PrimaryAuthenticatedAt == nil {
		return
	}
	methods := []string{"pwd"}
	context := "urn:kysignon:acr:password"
	if evidence.FactorAuthenticatedAt != nil {
		switch evidence.FactorMethod {
		case "totp":
			methods = append(methods, "otp", "mfa")
			context = "urn:kysignon:acr:mfa"
		case "push", "webauthn":
			methods = append(methods, "urn:kysignon:amr:"+evidence.FactorMethod, "mfa")
			context = "urn:kysignon:acr:mfa"
		case "recovery":
			methods = append(methods, "urn:kysignon:amr:recovery")
			context = "urn:kysignon:acr:recovery"
		}
	}
	// Use the primary proof time conservatively; completing a second factor does
	// not make an earlier password verification younger.
	claims["auth_time"] = evidence.PrimaryAuthenticatedAt.Unix()
	claims["amr"] = methods
	claims["acr"] = context
}
