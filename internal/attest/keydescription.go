// Package attest verifies Android Key Attestation chains for native-device registration.
package attest

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

var ExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

const (
	SecurityLevelSoftware  = 0
	SecurityLevelTEE       = 1
	SecurityLevelStrongBox = 2
)

type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState int // 0 Verified, 1 SelfSigned, 2 Unverified, 3 Failed
	VerifiedBootHash  []byte
}

type AppID struct {
	Packages         map[string]int64
	SignatureDigests [][]byte
}

type AuthList struct {
	Purpose        []int
	Algorithm      *int
	ECCurve        *int
	NoAuthRequired bool
	UserAuthType   *uint64
	AuthTimeout    *int
	Origin         *int
	RootOfTrust    *RootOfTrust
	AppID          *AppID
}

type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel int
	KeyMintVersion           int
	KeyMintSecurityLevel     int
	Challenge                []byte
	UniqueID                 []byte
	Software                 AuthList
	Hardware                 AuthList
}

// keyDescriptionWire mirrors the wire SEQUENCE; the two lists are kept raw and walked by hand
// because their members are EXPLICIT context tags with arbitrary numbers.
type keyDescriptionWire struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	Challenge                []byte
	UniqueID                 []byte
	Software                 asn1.RawValue
	Hardware                 asn1.RawValue
}

func ParseKeyDescription(der []byte) (*KeyDescription, error) {
	var kd keyDescriptionWire
	rest, err := asn1.Unmarshal(der, &kd)
	if err != nil {
		return nil, fmt.Errorf("key description: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("key description: trailing bytes")
	}
	sw, err := parseAuthList(kd.Software)
	if err != nil {
		return nil, fmt.Errorf("softwareEnforced: %w", err)
	}
	hw, err := parseAuthList(kd.Hardware)
	if err != nil {
		return nil, fmt.Errorf("hardwareEnforced: %w", err)
	}
	return &KeyDescription{
		AttestationVersion: kd.AttestationVersion, AttestationSecurityLevel: int(kd.AttestationSecurityLevel),
		KeyMintVersion: kd.KeyMintVersion, KeyMintSecurityLevel: int(kd.KeyMintSecurityLevel),
		Challenge: kd.Challenge, UniqueID: kd.UniqueID, Software: sw, Hardware: hw,
	}, nil
}

func parseAuthList(seq asn1.RawValue) (AuthList, error) {
	var out AuthList
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return out, errors.New("not a SEQUENCE")
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rv)
		if err != nil {
			return out, err
		}
		if rv.Class != asn1.ClassContextSpecific || !rv.IsCompound {
			return out, fmt.Errorf("unexpected element class %d", rv.Class)
		}
		switch rv.Tag {
		case 1:
			var vs []int
			if _, err := asn1.UnmarshalWithParams(rv.Bytes, &vs, "set"); err != nil {
				return out, fmt.Errorf("purpose: %w", err)
			}
			out.Purpose = vs
		case 2:
			out.Algorithm, err = smallInt(rv.Bytes)
		case 10:
			out.ECCurve, err = smallInt(rv.Bytes)
		case 503:
			out.NoAuthRequired = true
		case 504:
			var n *big.Int
			if _, err = asn1.Unmarshal(rv.Bytes, &n); err == nil {
				if n.Sign() < 0 || n.BitLen() > 64 {
					err = errors.New("userAuthType out of range")
				} else {
					v := n.Uint64()
					out.UserAuthType = &v
				}
			}
		case 505:
			out.AuthTimeout, err = smallInt(rv.Bytes)
		case 702:
			out.Origin, err = smallInt(rv.Bytes)
		case 704:
			var r struct {
				VerifiedBootKey   []byte
				DeviceLocked      bool
				VerifiedBootState asn1.Enumerated
				VerifiedBootHash  []byte `asn1:"optional"`
			}
			if _, err = asn1.Unmarshal(rv.Bytes, &r); err == nil {
				out.RootOfTrust = &RootOfTrust{r.VerifiedBootKey, r.DeviceLocked, int(r.VerifiedBootState), r.VerifiedBootHash}
			}
		case 709:
			var octets []byte
			if _, err = asn1.Unmarshal(rv.Bytes, &octets); err == nil {
				out.AppID, err = parseAppID(octets)
			}
		}
		if err != nil {
			return out, fmt.Errorf("tag %d: %w", rv.Tag, err)
		}
	}
	return out, nil
}

func smallInt(der []byte) (*int, error) {
	var v int
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func parseAppID(der []byte) (*AppID, error) {
	var raw struct {
		Packages []struct {
			Name    []byte
			Version int64
		} `asn1:"set"`
		Digests [][]byte `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, err
	}
	out := &AppID{Packages: map[string]int64{}, SignatureDigests: raw.Digests}
	for _, p := range raw.Packages {
		out.Packages[string(p.Name)] = p.Version
	}
	return out, nil
}
