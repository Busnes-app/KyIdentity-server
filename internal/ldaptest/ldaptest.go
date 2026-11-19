// Package ldaptest is an in-process LDAPS directory for tests: bind, search, add and modify
// over TLS with a generated certificate. It understands only the filters KyIdentity sends
// (equality, a trailing-* substring, presence and AND of those). Not for production use.
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Server is a running fake directory. Entries are keyed by lower-case DN.
type Server struct {
	URL   string
	CAPEM string
	// Users maps bind DN to password.
	Users map[string]string
	// ModifyResult, when set, decides a modify's result code (0 succeeds).
	ModifyResult func(dn string, attrs []string) uint16

	mu      sync.Mutex
	entries map[string]*Entry
	ln      net.Listener
}

// Entry is one directory object.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Selfsigned returns a certificate and key PEM for 127.0.0.1.
func Selfsigned(t testing.TB) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "ldaptest"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Start serves until the test ends.
func Start(t testing.TB) *Server {
	t.Helper()
	cert, caPEM := Selfsigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{URL: "ldaps://" + ln.Addr().String(), CAPEM: caPEM, Users: map[string]string{}, entries: map[string]*Entry{}, ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

// Put stores an entry.
func (s *Server) Put(dn string, attrs map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[strings.ToLower(dn)] = &Entry{DN: dn, Attrs: attrs}
}

// Get returns a copy of an entry, or nil.
func (s *Server) Get(dn string) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[strings.ToLower(dn)]
	if e == nil {
		return nil
	}
	c := &Entry{DN: e.DN, Attrs: map[string][]string{}}
	for k, v := range e.Attrs {
		c.Attrs[k] = append([]string(nil), v...)
	}
	return c
}

// Find returns the entries whose attribute equals value.
func (s *Server) Find(attr, value string) []*Entry {
	s.mu.Lock()
	var dns []string
	for _, e := range s.entries {
		if has(e, attr, value) {
			dns = append(dns, e.DN)
		}
	}
	s.mu.Unlock()
	var out []*Entry
	for _, dn := range dns {
		out = append(out, s.Get(dn))
	}
	return out
}

func get(e *Entry, attr string) []string {
	for k, v := range e.Attrs {
		if strings.EqualFold(k, attr) {
			return v
		}
	}
	return nil
}

func has(e *Entry, attr, value string) bool {
	for _, v := range get(e, attr) {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

func result(id int64, tag ber.Tag, code uint16) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	p.AppendChild(r)
	return p
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	bound := false
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		var out []*ber.Packet
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			dn, pw := op.Children[1].Data.String(), op.Children[2].Data.String()
			s.mu.Lock()
			want, ok := s.Users[strings.ToLower(dn)]
			s.mu.Unlock()
			bound = ok && want == pw
			code := uint16(ldap.LDAPResultSuccess)
			if !bound {
				code = ldap.LDAPResultInvalidCredentials
			}
			out = append(out, result(id, ldap.ApplicationBindResponse, code))
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationSearchRequest:
			if !bound {
				out = append(out, result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultInsufficientAccessRights))
				break
			}
			out = append(out, s.search(id, op)...)
		case ldap.ApplicationAddRequest:
			out = append(out, result(id, ldap.ApplicationAddResponse, s.add(bound, op)))
		case ldap.ApplicationModifyRequest:
			out = append(out, result(id, ldap.ApplicationModifyResponse, s.modify(bound, op)))
		case ldap.ApplicationModifyDNRequest:
			out = append(out, result(id, ldap.ApplicationModifyDNResponse, s.modifyDN(bound, op)))
		default:
			return
		}
		for _, r := range out {
			if _, err := c.Write(r.Bytes()); err != nil {
				return
			}
		}
	}
}

var clause = regexp.MustCompile(`\(([A-Za-z]+)=([^()]*)\)`)

// matches evaluates the filters KyIdentity sends: one clause or an AND of clauses.
func matches(e *Entry, filter string) bool {
	for _, m := range clause.FindAllStringSubmatch(filter, -1) {
		attr, value := m[1], m[2]
		switch {
		case value == "*":
			if strings.EqualFold(attr, "objectClass") {
				continue
			}
			if len(get(e, attr)) == 0 {
				return false
			}
		case strings.HasSuffix(value, "*"):
			ok := false
			for _, v := range get(e, attr) {
				ok = ok || strings.HasPrefix(strings.ToLower(v), strings.ToLower(strings.TrimSuffix(value, "*")))
			}
			if !ok {
				return false
			}
		default:
			if !has(e, attr, value) {
				return false
			}
		}
	}
	return true
}

func (s *Server) search(id int64, op *ber.Packet) []*ber.Packet {
	base := strings.ToLower(op.Children[0].Data.String())
	scope, _ := op.Children[1].Value.(int64)
	sizeLimit, _ := op.Children[3].Value.(int64)
	filter, err := ldap.DecompileFilter(op.Children[6])
	if err != nil {
		return []*ber.Packet{result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultProtocolError)}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if scope == int64(ldap.ScopeBaseObject) && s.entries[base] == nil {
		return []*ber.Packet{result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultNoSuchObject)}
	}
	var out []*ber.Packet
	for key, e := range s.entries {
		inScope := key == base || scope != int64(ldap.ScopeBaseObject) && strings.HasSuffix(key, ","+base)
		if !inScope || !matches(e, filter) {
			continue
		}
		if sizeLimit > 0 && int64(len(out)) >= sizeLimit {
			return append(out, result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultSizeLimitExceeded))
		}
		p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
		r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
		r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, ""))
		attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for k, vs := range e.Attrs {
			a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, ""))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			for _, v := range vs {
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
			}
			a.AppendChild(set)
			attrs.AppendChild(a)
		}
		r.AppendChild(attrs)
		p.AppendChild(r)
		out = append(out, p)
	}
	return append(out, result(id, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess))
}

func attributes(list *ber.Packet) map[string][]string {
	out := map[string][]string{}
	for _, a := range list.Children {
		name := a.Children[0].Data.String()
		vals := []string{}
		for _, v := range a.Children[1].Children {
			vals = append(vals, v.Data.String())
		}
		out[name] = vals
	}
	return out
}

func (s *Server) add(bound bool, op *ber.Packet) uint16 {
	if !bound {
		return ldap.LDAPResultInsufficientAccessRights
	}
	dn := op.Children[0].Data.String()
	attrs := attributes(op.Children[1])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries[strings.ToLower(dn)] != nil {
		return ldap.LDAPResultEntryAlreadyExists
	}
	for _, sam := range get(&Entry{Attrs: attrs}, "sAMAccountName") {
		for _, e := range s.entries {
			if has(e, "sAMAccountName", sam) {
				return ldap.LDAPResultEntryAlreadyExists
			}
		}
	}
	s.entries[strings.ToLower(dn)] = &Entry{DN: dn, Attrs: attrs}
	return ldap.LDAPResultSuccess
}

func (s *Server) modify(bound bool, op *ber.Packet) uint16 {
	if !bound {
		return ldap.LDAPResultInsufficientAccessRights
	}
	dn := op.Children[0].Data.String()
	var names []string
	for _, ch := range op.Children[1].Children {
		names = append(names, ch.Children[1].Children[0].Data.String())
	}
	if s.ModifyResult != nil {
		if code := s.ModifyResult(dn, names); code != 0 {
			return code
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[strings.ToLower(dn)]
	if e == nil {
		return ldap.LDAPResultNoSuchObject
	}
	for _, ch := range op.Children[1].Children {
		seq := ber.NewSequence("")
		seq.AppendChild(ch.Children[1])
		mod := attributes(seq)
		for _, sam := range get(&Entry{Attrs: mod}, "sAMAccountName") {
			for _, other := range s.entries {
				if other != e && has(other, "sAMAccountName", sam) {
					return ldap.LDAPResultEntryAlreadyExists
				}
			}
		}
		for k, v := range mod {
			for old := range e.Attrs {
				if strings.EqualFold(old, k) {
					delete(e.Attrs, old)
				}
			}
			if len(v) > 0 {
				e.Attrs[k] = v
			}
		}
	}
	return ldap.LDAPResultSuccess
}

// modifyDN renames an entry under the same parent and, as AD does for linked attributes,
// rewrites group members that pointed at the old name.
func (s *Server) modifyDN(bound bool, op *ber.Packet) uint16 {
	if !bound {
		return ldap.LDAPResultInsufficientAccessRights
	}
	oldDN, rdn := op.Children[0].Data.String(), op.Children[1].Data.String()
	parent := ""
	if i := strings.Index(oldDN, ","); i >= 0 {
		parent = oldDN[i:]
	}
	newDN := rdn + parent
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[strings.ToLower(oldDN)]
	if e == nil {
		return ldap.LDAPResultNoSuchObject
	}
	if s.entries[strings.ToLower(newDN)] != nil {
		return ldap.LDAPResultEntryAlreadyExists
	}
	delete(s.entries, strings.ToLower(oldDN))
	e.DN = newDN
	s.entries[strings.ToLower(newDN)] = e
	for _, other := range s.entries {
		for i, m := range other.Attrs["member"] {
			if strings.EqualFold(m, oldDN) {
				other.Attrs["member"][i] = newDN
			}
		}
	}
	return ldap.LDAPResultSuccess
}
