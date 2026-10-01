package attest

import (
	"encoding/asn1"
	"math/big"
	"testing"
)

type tag struct {
	n   int
	der []byte
}

func mustMarshal(t *testing.T, v any, params string) []byte {
	t.Helper()
	b, err := asn1.MarshalWithParams(v, params)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// explicitTag wraps inner DER in [n] EXPLICIT.
func explicitTag(t *testing.T, n int, inner []byte) []byte {
	t.Helper()
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: n, IsCompound: true, Bytes: inner}, "")
}

func intTag(t *testing.T, n int, v int64) []byte {
	return explicitTag(t, n, mustMarshal(t, big.NewInt(v), ""))
}
func nullTag(t *testing.T, n int) []byte {
	return explicitTag(t, n, mustMarshal(t, asn1.NullRawValue, ""))
}
func setOfIntTag(t *testing.T, n int, vs ...int) []byte {
	return explicitTag(t, n, mustMarshal(t, vs, "set"))
}
func octetTag(t *testing.T, n int, b []byte) []byte {
	return explicitTag(t, n, mustMarshal(t, b, ""))
}

type rotDER struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte
}

func rootOfTrustTag(t *testing.T, locked bool, state int) []byte {
	return explicitTag(t, 704, mustMarshal(t, rotDER{make([]byte, 32), locked, asn1.Enumerated(state), make([]byte, 32)}, ""))
}

type pkgDER struct {
	Name    []byte
	Version int64
}
type appIDDER struct {
	Packages []pkgDER `asn1:"set"`
	Digests  [][]byte `asn1:"set"`
}

func appIDTag(t *testing.T, pkg string, digest []byte) []byte {
	inner := mustMarshal(t, appIDDER{[]pkgDER{{[]byte(pkg), 1}}, [][]byte{digest}}, "")
	return octetTag(t, 709, inner) // attestationApplicationId is an OCTET STRING holding DER
}

// authList concatenates already-tagged elements into a SEQUENCE.
func authList(t *testing.T, tags ...[]byte) []byte {
	var body []byte
	for _, x := range tags {
		body = append(body, x...)
	}
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}, "")
}

type kdOpts struct {
	attLevel, kmLevel  int
	challenge          []byte
	hardware, software []byte // pre-built AuthorizationList DER
}

func keyDescriptionDER(t *testing.T, o kdOpts) []byte {
	t.Helper()
	var body []byte
	body = append(body, mustMarshal(t, big.NewInt(300), "")...)             // attestationVersion
	body = append(body, mustMarshal(t, asn1.Enumerated(o.attLevel), "")...) // attestationSecurityLevel
	body = append(body, mustMarshal(t, big.NewInt(300), "")...)             // keyMintVersion
	body = append(body, mustMarshal(t, asn1.Enumerated(o.kmLevel), "")...)  // keyMintSecurityLevel
	body = append(body, mustMarshal(t, o.challenge, "")...)                 // attestationChallenge
	body = append(body, mustMarshal(t, []byte{}, "")...)                    // uniqueId
	body = append(body, o.software...)
	body = append(body, o.hardware...)
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}, "")
}

// goodHardware is the list a KyAuth per-use key produces.
func goodHardware(t *testing.T) []byte {
	return authList(t, setOfIntTag(t, 1, 2), intTag(t, 2, 3), intTag(t, 10, 1), intTag(t, 504, 3), intTag(t, 702, 0), rootOfTrustTag(t, true, 0))
}

func goodSoftware(t *testing.T, digest []byte) []byte {
	return authList(t, appIDTag(t, "org.kysecurity.authenticator", digest))
}
