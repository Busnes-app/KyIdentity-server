package oauth

import "errors"

// IDTokenHint is what an RP-initiated logout request can prove about the login it wants
// ended: the client it was issued to, the subject, and the client-scoped session ID.
type IDTokenHint struct {
	ClientID, Subject, SID string
}

// ParseIDTokenHint verifies an id_token_hint. Expiry is tolerated, because the point of
// the hint is to name a login that may already be old; issuer, signature and token type
// are not, because a forged or foreign hint must not steer a logout or its redirect.
func (e *Engine) ParseIDTokenHint(token string) (IDTokenHint, error) {
	claims, err := e.keyManager.VerifyExpiredJWT(token)
	if err != nil {
		return IDTokenHint{}, err
	}
	if claims["iss"] != e.issuerURL || claims["token_use"] != "id_token" {
		return IDTokenHint{}, errors.New("not an ID token from this issuer")
	}
	aud, _ := claims["aud"].(string)
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	if aud == "" || sub == "" {
		return IDTokenHint{}, errors.New("ID token hint lacks audience or subject")
	}
	return IDTokenHint{ClientID: aud, Subject: sub, SID: sid}, nil
}
