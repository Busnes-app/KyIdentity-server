package mfa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// PairingProofHeader carries pairing proof v1 on the register request and its reply. KyAuth
// proves it holds the QR pairing token without sending it, so a reader of the wire can neither
// enrol its own key nor forge the reply. Contract: design.md, "Pairing proof v1".
const PairingProofHeader = "KyIdentity-Pairing-Proof"

// pairingProofKey is K = HMAC-SHA256(token, "kyidentity-pair-key/1"). It is not token_hash,
// so reading the database does not yield it; it is stored sealed under the encryption key.
func pairingProofKey(token string) []byte {
	m := hmac.New(sha256.New, []byte(token))
	m.Write([]byte("kyidentity-pair-key/1"))
	return m.Sum(nil)
}

// PairingProof is the verified state of a proof-bound registration.
type PairingProof struct {
	// Header is the request's proof; Body the exact request bytes it covers.
	Header string
	Body   []byte
	key    []byte // pairingProofKey of the matched token
}

func pairingMAC(key []byte, parts ...[]byte) string {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// pairingRequestProof is what KyAuth sends: HMAC(K, "kyidentity-pair/1\n" + origin + "\n" + body).
func pairingRequestProof(key []byte, origin string, body []byte) string {
	return pairingMAC(key, []byte("kyidentity-pair/1\n"+origin+"\n"), body)
}

// ReplyProof authenticates resp, the exact reply body, to the device that sent p.Body.
func (e *Engine) ReplyProof(p *PairingProof, resp []byte) string {
	reqHash := sha256.Sum256(p.Body)
	return pairingMAC(p.key, []byte("kyidentity-pair-reply/1\n"+e.issuerOrigin+"\n"+base64.RawURLEncoding.EncodeToString(reqHash[:])+"\n"), resp)
}

// matches reports whether the proof was made with key, recording it on a match.
func (p *PairingProof) matches(key []byte, origin string) bool {
	if !hmac.Equal([]byte(pairingRequestProof(key, origin, p.Body)), []byte(p.Header)) {
		return false
	}
	p.key = key
	return true
}

// matchPairingProof finds the user's live pairing token the proof was made with, or nil. A
// miss spends nothing: the token never left KyAuth, so a wrong proof is no guess at it.
func (e *Engine) matchPairingProof(userID string, p *PairingProof) (*store.DevicePairingToken, error) {
	if e.issuerOrigin == "" {
		return nil, nil
	}
	tokens, err := e.store.ListValidDevicePairingTokens(userID)
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		key, err := crypto.Open(e.encryptionKey, store.SealPairingProof, t.ID, t.ProofKey)
		if err != nil || len(key) != sha256.Size {
			continue
		}
		if p.matches(key, e.issuerOrigin) {
			return t, nil
		}
	}
	return nil, nil
}

// attestCred is the credential string attestation binds to: the token itself for a legacy
// body (KyAuth still holds it), "pair1:" + hex(K) for a proof body, user|PIN for a PIN body.
func attestCred(req *NativeDeviceRegisterRequest) string {
	switch {
	case req.Proof != nil:
		return "pair1:" + hex.EncodeToString(req.Proof.key)
	case req.PairingToken != "":
		return req.PairingToken
	}
	return req.UserID + "|" + req.PINCode
}
