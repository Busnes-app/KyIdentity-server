package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

// Independent standard-library check of the packet opened by the WebCrypto tests.
// KyIdentity's production handlers only check envelope size and canonical encoding.
func TestKeyringWireAAD(t *testing.T) {
	const vector = "AAECAwQFBgcICQoLMz7A_2Rr9hoImes4Y1C8cOGmq38Ljj1PxG5ie_yBTGwUUtQEQ9mrL5xDJQ8dF-vu"
	fields := []string{"ky-keyring/1", "wrapper", "https://identity.example.test", "org-A", "subject-55",
		"26142ca4-a93c-4dc3-b314-dad35b7fb82f", "370e28b9-4b06-4e4d-89a6-081dd13be902", "device"}
	decrypt := func(packet []byte) ([]byte, error) {
		t.Helper()
		aad, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		key, err := hkdf.Key(sha256.New, bytes.Repeat([]byte{17}, 32), make([]byte, 32), string(aad), 32)
		if err != nil {
			t.Fatal(err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return gcm.Open(nil, packet[:12], packet[12:], aad)
	}
	packet := keyringBase64(vector, 60, 60)
	if packet == nil {
		t.Fatal("invalid reference vector")
	}
	if root, err := decrypt(packet); err != nil || !bytes.Equal(root, bytes.Repeat([]byte{34}, 32)) {
		t.Fatalf("Go and WebCrypto disagree on envelope: %v", err)
	}
	for i, field := range fields {
		fields[i] = "changed"
		if _, err := decrypt(packet); err == nil {
			t.Fatalf("changed AAD field %d accepted", i)
		}
		fields[i] = field
	}
	packet[30] ^= 0x80
	if _, err := decrypt(packet); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
