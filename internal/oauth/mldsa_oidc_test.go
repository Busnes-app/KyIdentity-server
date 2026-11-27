package oauth

import (
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

func decodeJWTHeader(t *testing.T, compact string) map[string]any {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWS, got %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return hdr
}

func TestPerClientSigningAlgAndDiscovery(t *testing.T) {
	dir := t.TempDir()
	s, err := store.New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer s.Close()

	km, err := crypto.LoadOrCreateSigningKeys(
		filepath.Join(dir, "jwt_rs256.key"),
		filepath.Join(dir, "jwt_mldsa65.key"),
	)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKeys: %v", err)
	}

	eng := NewEngine(s, km, "https://id.example.com")

	// Discovery advertises both ML-DSA-65 and RS256.
	disc := eng.GetOIDCConfiguration()
	if len(disc.IDTokenSigningAlgValuesSupported) != 2 ||
		disc.IDTokenSigningAlgValuesSupported[0] != crypto.AlgMLDSA65 ||
		disc.IDTokenSigningAlgValuesSupported[1] != crypto.AlgRS256 {
		t.Fatalf("discovery id_token_signing_alg_values_supported = %v, want [ML-DSA-65 RS256]", disc.IDTokenSigningAlgValuesSupported)
	}

	// Create a user.
	u := &store.User{
		ID:          "user-pq",
		Username:    "alice",
		Email:       "alice@example.com",
		DisplayName: "Alice",
		Role:        "user",
		Status:      "active",
	}
	if err := s.DefaultOrg().CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	sess := &store.Session{
		ID:        "sess-pq",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Register a third-party client (unset alg -> RS256) and a Ky PQ client (ML-DSA-65).
	rsClient := &store.OAuthClient{
		ID:                "thirdparty-rp",
		ClientName:        "Third Party",
		ClientType:        "public",
		RedirectURIsJSON:  `["https://rp.example.com/cb"]`,
		AllowedScopesJSON: `["openid","profile","email"]`,
		Enabled:           true,
	}
	if err := s.CreateOAuthClient(rsClient, nil); err != nil {
		t.Fatalf("CreateOAuthClient(thirdparty): %v", err)
	}
	pqClient := &store.OAuthClient{
		ID:                       "kypost",
		ClientName:               "KyPost",
		ClientType:               "public",
		RedirectURIsJSON:         `["https://mail.example.com/cb"]`,
		AllowedScopesJSON:        `["openid","profile","email"]`,
		IDTokenSignedResponseAlg: crypto.AlgMLDSA65,
		Enabled:                  true,
	}
	if err := s.CreateOAuthClient(pqClient, nil); err != nil {
		t.Fatalf("CreateOAuthClient(kypost): %v", err)
	}

	now := time.Now().UTC()
	exp := now.Add(15 * time.Minute)
	ev := store.AuthenticationEvidence{PrimaryAuthenticatedAt: &now}

	// Third-party client gets RS256 tokens + RS256 logout token.
	rsResp, err := eng.tokenResponse(u, rsClient.ID, sess.ID, "openid profile email", ev, "n1", "jti-rs", exp, now)
	if err != nil {
		t.Fatalf("tokenResponse(RS256): %v", err)
	}
	if alg := decodeJWTHeader(t, rsResp.IDToken)["alg"]; alg != crypto.AlgRS256 {
		t.Fatalf("third-party ID token alg = %v, want RS256", alg)
	}
	if alg := decodeJWTHeader(t, rsResp.AccessToken)["alg"]; alg != crypto.AlgRS256 {
		t.Fatalf("third-party access token alg = %v, want RS256", alg)
	}
	rsLogout, err := eng.SignLogoutToken(rsClient.ID, u.ID, "sid-rs", "")
	if err != nil {
		t.Fatalf("SignLogoutToken(RS256): %v", err)
	}
	if alg := decodeJWTHeader(t, rsLogout)["alg"]; alg != crypto.AlgRS256 {
		t.Fatalf("third-party logout token alg = %v, want RS256", alg)
	}

	// PQ Ky client gets ML-DSA-65 tokens + ML-DSA-65 logout token, verifiable using JWKS AKP pubkey.
	pqResp, err := eng.tokenResponse(u, pqClient.ID, sess.ID, "openid profile email", ev, "n2", "jti-pq", exp, now)
	if err != nil {
		t.Fatalf("tokenResponse(ML-DSA-65): %v", err)
	}
	idHdr := decodeJWTHeader(t, pqResp.IDToken)
	if idHdr["alg"] != crypto.AlgMLDSA65 || idHdr["kid"] != km.MLDSAKeyID {
		t.Fatalf("PQ ID token header = %+v, want alg=ML-DSA-65 kid=%s", idHdr, km.MLDSAKeyID)
	}
	if alg := decodeJWTHeader(t, pqResp.AccessToken)["alg"]; alg != crypto.AlgMLDSA65 {
		t.Fatalf("PQ access token alg = %v, want ML-DSA-65", alg)
	}
	pqLogout, err := eng.SignLogoutToken(pqClient.ID, u.ID, "sid-pq", "")
	if err != nil {
		t.Fatalf("SignLogoutToken(ML-DSA-65): %v", err)
	}
	logoutHdr := decodeJWTHeader(t, pqLogout)
	if logoutHdr["alg"] != crypto.AlgMLDSA65 || logoutHdr["typ"] != "logout+jwt" {
		t.Fatalf("PQ logout token header = %+v, want alg=ML-DSA-65 typ=logout+jwt", logoutHdr)
	}

	// Independent RP verification using ONLY the published JWKS AKP entry.
	var akp crypto.JWK
	for _, k := range km.GetJWKS().Keys {
		if k.Kid == km.MLDSAKeyID {
			akp = k
		}
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(akp.Pub)
	if err != nil {
		t.Fatalf("decode AKP pub: %v", err)
	}
	pubKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pubRaw)
	if err != nil {
		t.Fatalf("mldsa.NewPublicKey: %v", err)
	}
	parts := strings.Split(pqResp.IDToken, ".")
	sigRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if err := mldsa.Verify(pubKey, []byte(parts[0]+"."+parts[1]), sigRaw, nil); err != nil {
		t.Fatalf("independent mldsa.Verify against JWKS AKP failed: %v", err)
	}

	// RSA-only engine MUST fail closed when issuing tokens for an ML-DSA-65 client.
	rsaOnlyKM, err := crypto.LoadOrCreateRSAKey(filepath.Join(dir, "rsa_only.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateRSAKey: %v", err)
	}
	rsaOnlyEng := NewEngine(s, rsaOnlyKM, "https://id.example.com")
	if _, err := rsaOnlyEng.tokenResponse(u, pqClient.ID, sess.ID, "openid", ev, "n3", "jti-fail", exp, now); err == nil {
		t.Fatal("RSA-only engine must refuse to issue tokens for ML-DSA-65 client instead of downgrading to RS256")
	}
}
