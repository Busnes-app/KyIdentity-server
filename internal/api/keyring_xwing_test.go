package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/xwing"
)

type xwingWireContext struct {
	Issuer string `json:"issuer"`
	Org    string `json:"org_id"`
	User   string `json:"user_id"`
	Ring   string `json:"keyring_version"`
}

func (c xwingWireContext) prefix(kind string) []any {
	return []any{"ky-keyring/1", kind, c.Issuer, c.Org, c.User, c.Ring}
}
func wireJSON(t *testing.T, fields []any) []byte {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// These packets were sealed by the actual browser helpers through pqwasm and by
// Go xwing.Seal. Reconstruct transcripts independently of the TypeScript code.
func TestKeyringXwingWire(t *testing.T) {
	raw, err := os.ReadFile("testdata/keyring_xwing.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Context                          xwingWireContext
		ID, Seed, Secret, Recipient, Msg string
		Transfer, Payload                struct {
			SenderKey string `json:"sender_key"`
			Sealed    string `json:"sealed"`
		}
		GoPayload struct {
			SenderKey string `json:"sender_key"`
			Sealed    string `json:"sealed"`
		} `json:"go_payload"`
		Handoff struct {
			Client   string
			Version  int
			Code     string
			Redirect string `json:"redirect_uri"`
			Nonce    string
		}
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	decode := func(s string) []byte {
		t.Helper()
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	priv, err := xwing.FromSeed(decode(v.Seed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.Public().Bytes(), decode(v.Recipient)) {
		t.Fatal("seed/public key mismatch")
	}
	transferAAD := wireJSON(t, append(v.Context.prefix("transfer-xwing/2"), v.ID, v.Recipient))
	transferInfo := append([]byte("kyidentity/keyring-transfer/2\x00"), transferAAD...)
	transferInfo = append(transferInfo, 0)
	transferInfo = append(transferInfo, decode(v.Secret)...)
	handoffAAD := wireJSON(t, append(v.Context.prefix("handoff-xwing/2"), v.Handoff.Client, v.Handoff.Version, v.Handoff.Code, v.Handoff.Redirect, v.Recipient, v.Handoff.Nonce))
	handoffInfo := append([]byte("kyidentity/keyring-handoff/2\x00"), handoffAAD...)
	for _, c := range []struct {
		name, packet string
		info, aad    []byte
	}{
		{"browser-transfer", v.Transfer.Sealed, transferInfo, transferAAD},
		{"browser-handoff", v.Payload.Sealed, handoffInfo, handoffAAD},
		{"go-handoff", v.GoPayload.Sealed, handoffInfo, handoffAAD},
	} {
		t.Run(c.name, func(t *testing.T) {
			packet := decode(c.packet)
			if !keyringXwingPacket(c.packet) {
				t.Fatal("server rejected valid packet")
			}
			plain, err := xwing.Open(priv, c.info, c.aad, packet)
			if err != nil || !bytes.Equal(plain, decode(v.Msg)) {
				t.Fatalf("wire disagreement: %v", err)
			}
			for _, field := range [][]byte{packet, c.info, c.aad} {
				for i := range field {
					field[i] ^= 1
					_, err = xwing.Open(priv, c.info, c.aad, packet)
					field[i] ^= 1
					if err == nil {
						t.Fatalf("tampering byte %d accepted", i)
					}
				}
			}
		})
	}
}

func TestKeyringXwingKeyValidation(t *testing.T) {
	key, err := xwing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.Public().Bytes())
	if !keyringXwingKey(public) || !keyringHandoffKey(public) {
		t.Fatal("X-Wing key refused")
	}
	legacy := testHandoffPoint(t)
	if !keyringHandoffKey(legacy) || keyringXwingKey(legacy) {
		t.Fatal("legacy suite confusion")
	}
	for _, bad := range []string{"", public[:len(public)-1], public + "A", public + "=", strings.Repeat("_", 1622), strings.Repeat("A", 1621), strings.Repeat("A", 1623)} {
		if keyringHandoffKey(bad) || keyringXwingKey(bad) {
			t.Fatal("malformed key accepted")
		}
	}
	for _, n := range []int{0, 60, 1168, 1170} {
		if keyringXwingPacket(base64.RawURLEncoding.EncodeToString(make([]byte, n))) {
			t.Fatal("wrong packet length accepted")
		}
	}
	packet := make([]byte, 1169)
	if keyringXwingPacket(base64.RawURLEncoding.EncodeToString(packet)) {
		t.Fatal("unknown version accepted")
	}
}
