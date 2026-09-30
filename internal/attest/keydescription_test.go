package attest

import (
	"bytes"
	"testing"
)

func TestParseKeyDescriptionRoundTrip(t *testing.T) {
	digest := bytes.Repeat([]byte{0xab}, 32)
	der := keyDescriptionDER(t, kdOpts{attLevel: 2, kmLevel: 2, challenge: []byte("chal"), hardware: goodHardware(t), software: goodSoftware(t, digest)})
	kd, err := ParseKeyDescription(der)
	if err != nil {
		t.Fatal(err)
	}
	if kd.AttestationSecurityLevel != 2 || kd.KeyMintSecurityLevel != 2 || string(kd.Challenge) != "chal" {
		t.Fatalf("%+v", kd)
	}
	h := kd.Hardware
	if len(h.Purpose) != 1 || h.Purpose[0] != 2 || *h.Algorithm != 3 || *h.ECCurve != 1 || *h.UserAuthType != 3 || h.AuthTimeout != nil || h.NoAuthRequired || *h.Origin != 0 {
		t.Fatalf("hardware: %+v", h)
	}
	if h.RootOfTrust == nil || !h.RootOfTrust.DeviceLocked || h.RootOfTrust.VerifiedBootState != 0 {
		t.Fatalf("rot: %+v", h.RootOfTrust)
	}
	if kd.Software.AppID == nil || kd.Software.AppID.Packages["org.kysecurity.authenticator"] != 1 || !bytes.Equal(kd.Software.AppID.SignatureDigests[0], digest) {
		t.Fatalf("appid: %+v", kd.Software.AppID)
	}
}

func TestParseKeyDescriptionUserAuthTypeAny(t *testing.T) {
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 0xFFFFFFFF), intTag(t, 702, 0))
	kd, err := ParseKeyDescription(keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: []byte("c"), hardware: hw, software: authList(t)}))
	if err != nil || kd.Hardware.UserAuthType == nil || *kd.Hardware.UserAuthType != 0xFFFFFFFF {
		t.Fatalf("%v %+v", err, kd)
	}
}

func TestParseKeyDescriptionTimeoutAndNoAuth(t *testing.T) {
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 2), intTag(t, 505, 30), nullTag(t, 503), intTag(t, 702, 0))
	kd, err := ParseKeyDescription(keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: []byte("c"), hardware: hw, software: authList(t)}))
	if err != nil || kd.Hardware.AuthTimeout == nil || *kd.Hardware.AuthTimeout != 30 || !kd.Hardware.NoAuthRequired {
		t.Fatalf("%v %+v", err, kd)
	}
}

func TestParseKeyDescriptionRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {0x30}, {0x04, 0x01, 0x00}, bytes.Repeat([]byte{0x30, 0x80}, 3)} {
		if _, err := ParseKeyDescription(in); err == nil {
			t.Fatalf("accepted %x", in)
		}
	}
}

func TestParseKeyDescriptionIgnoresUnknownTags(t *testing.T) {
	hw := authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 2), intTag(t, 702, 0), intTag(t, 705, 140000), intTag(t, 999, 1))
	if _, err := ParseKeyDescription(keyDescriptionDER(t, kdOpts{attLevel: 1, kmLevel: 1, challenge: []byte("c"), hardware: hw, software: authList(t)})); err != nil {
		t.Fatal(err)
	}
}
