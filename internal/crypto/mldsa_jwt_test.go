package crypto

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadOrCreateSigningKeysAndJWKS(t *testing.T) {
	dir := t.TempDir()
	rsaPath := filepath.Join(dir, "jwt_rs256.key")
	mldsaPath := filepath.Join(dir, "jwt_mldsa65.key")

	km1, err := LoadOrCreateSigningKeys(rsaPath, mldsaPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKeys: %v", err)
	}
	if !km1.HasMLDSA() {
		t.Fatal("expected ML-DSA-65 key to be loaded")
	}
	if km1.KeyID == "" || km1.MLDSAKeyID == "" {
		t.Fatalf("expected non-empty kids, got rsa=%q mldsa=%q", km1.KeyID, km1.MLDSAKeyID)
	}
	if km1.KeyID == km1.MLDSAKeyID {
		t.Fatalf("expected distinct kids for RSA and ML-DSA-65 keys, both %q", km1.KeyID)
	}

	// Reload from disk and verify deterministic kids survive restart.
	km2, err := LoadOrCreateSigningKeys(rsaPath, mldsaPath)
	if err != nil {
		t.Fatalf("reload LoadOrCreateSigningKeys: %v", err)
	}
	if km2.KeyID != km1.KeyID || km2.MLDSAKeyID != km1.MLDSAKeyID {
		t.Fatalf("kids changed across reload: (%q,%q) != (%q,%q)", km2.KeyID, km2.MLDSAKeyID, km1.KeyID, km1.MLDSAKeyID)
	}

	// Verify file permissions are 0600.
	fi, err := os.Stat(mldsaPath)
	if err != nil {
		t.Fatalf("stat mldsa key: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("mldsa key mode = %o, want 0600", fi.Mode().Perm())
	}

	// Verify JWKS exposes both AKP (ML-DSA-65) and RSA (RS256) with no private material.
	jwks := km2.GetJWKS()
	if len(jwks.Keys) != 2 {
		t.Fatalf("JWKS key count = %d, want 2", len(jwks.Keys))
	}
	rawJSON, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	if strings.Contains(string(rawJSON), `"priv"`) || strings.Contains(string(rawJSON), `"d"`) {
		t.Fatalf("JWKS must never expose private key fields: %s", string(rawJSON))
	}

	byKid := map[string]JWK{}
	for _, k := range jwks.Keys {
		byKid[k.Kid] = k
	}
	akp, ok := byKid[km2.MLDSAKeyID]
	if !ok || akp.Kty != "AKP" || akp.Alg != AlgMLDSA65 || akp.Use != "sig" || akp.Kid != km2.MLDSAKeyID {
		t.Fatalf("unexpected AKP JWK: %+v", akp)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(akp.Pub)
	if err != nil {
		t.Fatalf("decode AKP pub: %v", err)
	}
	if len(pubBytes) != mldsa.MLDSA65().PublicKeySize() {
		t.Fatalf("AKP pub length = %d, want %d", len(pubBytes), mldsa.MLDSA65().PublicKeySize())
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pubBytes); err != nil {
		t.Fatalf("AKP pub bytes failed mldsa.NewPublicKey: %v", err)
	}

	rsaJWK, ok := byKid[km2.KeyID]
	if !ok || rsaJWK.Kty != "RSA" || rsaJWK.Alg != AlgRS256 || rsaJWK.Use != "sig" || rsaJWK.Kid != km2.KeyID {
		t.Fatalf("unexpected RSA JWK: %+v", rsaJWK)
	}

	// Verify SupportedSigningAlgs advertises ML-DSA-65 first, then RS256.
	algs := km2.SupportedSigningAlgs()
	if len(algs) != 2 || algs[0] != AlgMLDSA65 || algs[1] != AlgRS256 {
		t.Fatalf("SupportedSigningAlgs = %v, want [ML-DSA-65 RS256]", algs)
	}
}

func TestMLDSA65SignVerifyAndRefusals(t *testing.T) {
	dir := t.TempDir()
	km, err := LoadOrCreateSigningKeys(filepath.Join(dir, "rsa.key"), filepath.Join(dir, "mldsa.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateSigningKeys: %v", err)
	}

	baseClaims := func() map[string]any {
		return map[string]any{
			"iss":       "https://id.example.com",
			"sub":       "user-1",
			"aud":       "kypost",
			"exp":       time.Now().Add(time.Hour).Unix(),
			"iat":       time.Now().Unix(),
			"token_use": "id_token",
		}
	}

	// ML-DSA-65 sign & verify.
	pqToken, err := km.SignJWTWithAlg(AlgMLDSA65, "JWT", baseClaims())
	if err != nil {
		t.Fatalf("SignJWTWithAlg(ML-DSA-65): %v", err)
	}
	got, err := km.VerifyJWT(pqToken, "https://id.example.com", "id_token")
	if err != nil {
		t.Fatalf("VerifyJWT(ML-DSA-65): %v", err)
	}
	if got["sub"] != "user-1" {
		t.Fatalf("sub = %v, want user-1", got["sub"])
	}

	// Inspect header fields.
	parts := strings.Split(pqToken, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d parts, want 3", len(parts))
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if hdr["alg"] != AlgMLDSA65 || hdr["kid"] != km.MLDSAKeyID || hdr["typ"] != "JWT" {
		t.Fatalf("unexpected ML-DSA-65 header: %+v", hdr)
	}

	// RS256 sign & verify on the same manager.
	rsaToken, err := km.SignJWTWithAlg(AlgRS256, "JWT", baseClaims())
	if err != nil {
		t.Fatalf("SignJWTWithAlg(RS256): %v", err)
	}
	if _, err := km.VerifyJWT(rsaToken, "https://id.example.com", "id_token"); err != nil {
		t.Fatalf("VerifyJWT(RS256): %v", err)
	}

	// Tampered signature must fail.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[0] ^= 0xff
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
	if _, err := km.VerifyJWT(tampered, "https://id.example.com", "id_token"); err == nil {
		t.Fatal("VerifyJWT accepted tampered ML-DSA-65 signature")
	}

	// Cross-algorithm confusion: ML-DSA-65 kid paired with RS256 alg header must fail.
	badHdr, _ := json.Marshal(map[string]any{"alg": AlgRS256, "kid": km.MLDSAKeyID, "typ": "JWT"})
	confused := base64.RawURLEncoding.EncodeToString(badHdr) + "." + parts[1] + "." + parts[2]
	if _, err := km.VerifyJWT(confused, "https://id.example.com", "id_token"); err == nil {
		t.Fatal("VerifyJWT accepted alg/kid confusion (RS256 with ML-DSA kid)")
	}

	// Cross-algorithm confusion: RSA kid paired with ML-DSA-65 alg header must fail.
	rsaParts := strings.Split(rsaToken, ".")
	badHdr2, _ := json.Marshal(map[string]any{"alg": AlgMLDSA65, "kid": km.KeyID, "typ": "JWT"})
	confused2 := base64.RawURLEncoding.EncodeToString(badHdr2) + "." + rsaParts[1] + "." + rsaParts[2]
	if _, err := km.VerifyJWT(confused2, "https://id.example.com", "id_token"); err == nil {
		t.Fatal("VerifyJWT accepted alg/kid confusion (ML-DSA-65 with RSA kid)")
	}

	// RSA-only key manager MUST fail closed when asked to sign ML-DSA-65.
	rsaOnly, err := LoadOrCreateRSAKey(filepath.Join(dir, "rsa_only.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateRSAKey: %v", err)
	}
	if _, err := rsaOnly.SignJWTWithAlg(AlgMLDSA65, "JWT", baseClaims()); err == nil {
		t.Fatal("RSA-only manager must fail closed instead of downgrading ML-DSA-65 to RS256")
	}
	if algs := rsaOnly.SupportedSigningAlgs(); len(algs) != 1 || algs[0] != AlgRS256 {
		t.Fatalf("RSA-only SupportedSigningAlgs = %v, want [RS256]", algs)
	}
}

func TestMultiKeyJWKSRotationVerifiesRetiredKeys(t *testing.T) {
	dir := t.TempDir()
	// Old active keys that will be retired after issuing tokens.
	oldKM, err := LoadOrCreateSigningKeys(filepath.Join(dir, "old_rsa.key"), filepath.Join(dir, "old_mldsa.key"))
	if err != nil {
		t.Fatalf("old keys: %v", err)
	}
	claims := map[string]any{
		"iss":       "https://id.example.com",
		"sub":       "user-rot",
		"aud":       "kypost",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"token_use": "id_token",
	}
	oldPQToken, err := oldKM.SignJWTWithAlg(AlgMLDSA65, "JWT", claims)
	if err != nil {
		t.Fatalf("sign old ML-DSA-65: %v", err)
	}
	oldRSAToken, err := oldKM.SignJWTWithAlg(AlgRS256, "JWT", claims)
	if err != nil {
		t.Fatalf("sign old RS256: %v", err)
	}

	// Rotate to fresh active keys and register retired verification keys.
	newKM, err := LoadOrCreateSigningKeys(filepath.Join(dir, "new_rsa.key"), filepath.Join(dir, "new_mldsa.key"))
	if err != nil {
		t.Fatalf("new keys: %v", err)
	}
	if _, err := newKM.VerifyJWT(oldPQToken, "https://id.example.com", "id_token"); err == nil {
		t.Fatal("expected old ML-DSA-65 token to fail before registering retired verification key")
	}
	if err := newKM.AddVerificationKey(oldKM.MLDSAKeyID, AlgMLDSA65, oldKM.MLDSAPublicKey); err != nil {
		t.Fatalf("AddVerificationKey(ML-DSA): %v", err)
	}
	if err := newKM.AddVerificationKey(oldKM.KeyID, AlgRS256, oldKM.PublicKey); err != nil {
		t.Fatalf("AddVerificationKey(RSA): %v", err)
	}

	// JWKS now advertises all 4 keys (2 active + 2 retired).
	if got := len(newKM.GetJWKS().Keys); got != 4 {
		t.Fatalf("JWKS key count after rotation = %d, want 4", got)
	}

	// Tokens signed by BOTH retired and active keys verify cleanly.
	if _, err := newKM.VerifyJWT(oldPQToken, "https://id.example.com", "id_token"); err != nil {
		t.Fatalf("retired ML-DSA-65 token failed verification: %v", err)
	}
	if _, err := newKM.VerifyJWT(oldRSAToken, "https://id.example.com", "id_token"); err != nil {
		t.Fatalf("retired RS256 token failed verification: %v", err)
	}
	newPQToken, err := newKM.SignJWTWithAlg(AlgMLDSA65, "JWT", claims)
	if err != nil {
		t.Fatalf("sign new ML-DSA-65: %v", err)
	}
	if _, err := newKM.VerifyJWT(newPQToken, "https://id.example.com", "id_token"); err != nil {
		t.Fatalf("active ML-DSA-65 token failed verification: %v", err)
	}

	// Registering an undersized RSA key must fail closed.
	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate weak rsa: %v", err)
	}
	if err := newKM.AddVerificationKey("weak", AlgRS256, &weakRSA.PublicKey); err == nil {
		t.Fatal("AddVerificationKey must reject <2048-bit RSA keys")
	}

	// Colliding with an active key's kid using a different public key must fail even
	// when the algorithm matches; re-registering the identical active key is idempotent.
	if err := newKM.AddVerificationKey(newKM.MLDSAKeyID, AlgMLDSA65, oldKM.MLDSAPublicKey); err == nil {
		t.Fatal("AddVerificationKey must reject distinct ML-DSA key reusing active MLDSAKeyID")
	}
	if err := newKM.AddVerificationKey(newKM.KeyID, AlgRS256, oldKM.PublicKey); err == nil {
		t.Fatal("AddVerificationKey must reject distinct RSA key reusing active KeyID")
	}
	if err := newKM.AddVerificationKey(newKM.MLDSAKeyID, AlgMLDSA65, newKM.MLDSAPublicKey); err != nil {
		t.Fatalf("idempotent active ML-DSA re-registration failed: %v", err)
	}
	if err := newKM.AddVerificationKey(newKM.KeyID, AlgRS256, newKM.PublicKey); err != nil {
		t.Fatalf("idempotent active RSA re-registration failed: %v", err)
	}
	if got := len(newKM.GetJWKS().Keys); got != 4 {
		t.Fatalf("JWKS key count after idempotent re-registration = %d, want 4", got)
	}
}

func TestNormalizeSigningAlg(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"  ", "", false},
		{"RS256", AlgRS256, false},
		{"ML-DSA-65", AlgMLDSA65, false},
		{"none", "", true},
		{"HS256", "", true},
		{"ML-DSA-87", "", true},
		{"ml-dsa-65", "", true},
	}
	for _, tc := range cases {
		got, err := NormalizeSigningAlg(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("NormalizeSigningAlg(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("NormalizeSigningAlg(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
