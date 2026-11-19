package sync

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/adpass"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/netguard"
	"github.com/Busnes-app/kyidentity-server/internal/store"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// Active Directory connector: users and groups inside one OU, marked by adminDescription.
// Design: docs/superpowers/specs/2026-11-19-active-directory-design.md.

const (
	adSystemType  = "active_directory"
	uacNormal     = "512" // NORMAL_ACCOUNT
	uacDisabled   = "514" // NORMAL_ACCOUNT | ACCOUNTDISABLE
	adGlobalGroup = "-2147483646"
)

var (
	errADConflict  = errors.New("an object KyIdentity does not manage holds this name in the directory")
	errADAmbiguous = errors.New("more than one directory object carries this KyIdentity marker")
	errADName      = errors.New("name cannot be used as an Active Directory account name")
	errADConfig    = errors.New("directory connector settings are incomplete")
)

// ADSettings is what the admin submits for a directory connector.
type ADSettings struct {
	BindDN             string `json:"bindDn"`
	BaseDN             string `json:"baseDn"`
	CAPEM              string `json:"caPem"`
	AgentPublicKey     string `json:"agentPublicKey"`
	PasswordTTLMinutes int    `json:"passwordTtlMinutes"`
}

func adMarker(systemID, kind, localID string) string { return adpass.Marker(systemID, kind, localID) }

func validateADSettings(rawURL, bindPassword string, s *ADSettings, requirePassword bool) (*store.ADConnector, error) {
	if err := netguard.ValidateLDAPS(rawURL, "ldapsUrl"); err != nil {
		return nil, store.InputError(err.Error())
	}
	if _, err := adRoots(s.CAPEM); err != nil {
		return nil, err
	}
	if dn, err := ldap.ParseDN(s.BindDN); err != nil || len(dn.RDNs) == 0 {
		return nil, store.InputError("bind DN is not a valid DN")
	}
	if adDomain(s.BaseDN) == "" {
		return nil, store.InputError("OU must be a valid DN ending in the domain's DC= parts")
	}
	if s.AgentPublicKey != "" {
		if _, err := adpass.ParsePublicKey(s.AgentPublicKey); err != nil {
			return nil, store.InputError(err.Error())
		}
	}
	if s.PasswordTTLMinutes == 0 {
		s.PasswordTTLMinutes = 1440
	}
	if s.PasswordTTLMinutes < 10 || s.PasswordTTLMinutes > 1440 {
		return nil, store.InputError("password lifetime must be 10 to 1440 minutes")
	}
	if (requirePassword || bindPassword != "") && (len(bindPassword) == 0 || len(bindPassword) > 1024) {
		return nil, store.InputError("bind password must be 1 to 1024 bytes")
	}
	return &store.ADConnector{BindDN: s.BindDN, BaseDN: s.BaseDN, CAPEM: strings.TrimSpace(s.CAPEM) + "\n",
		AgentPublicKey: strings.TrimSpace(s.AgentPublicKey), PasswordTTLMinutes: s.PasswordTTLMinutes}, nil
}

// adRoots is the pinned trust: the CA or the DC's own certificate, never system roots.
func adRoots(pemText string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return nil, store.InputError("CA must be one or more PEM certificates")
	}
	return pool, nil
}

// adDomain is the DNS domain of a DN's DC= parts ("" when it has none).
func adDomain(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return ""
	}
	var parts []string
	for _, rdn := range parsed.RDNs {
		for _, a := range rdn.Attributes {
			if strings.EqualFold(a.Type, "DC") {
				parts = append(parts, a.Value)
			}
		}
	}
	return strings.Join(parts, ".")
}

// CreateADSystem creates a directory connector; the bind password is sealed like a SCIM token.
func (e *Engine) CreateADSystem(req *CreateSystemRequest, audit func(*store.PairedSystem) *store.AuditEvent) (*store.PairedSystem, error) {
	if req.ActiveDirectory == nil {
		return nil, store.InputError("activeDirectory settings are required")
	}
	c, err := validateADSettings(req.CallbackURL, req.BearerToken, req.ActiveDirectory, true)
	if err != nil {
		return nil, err
	}
	id := uuid.New().String()
	sealed, err := crypto.Seal(e.encryptionKey, store.SealConnector, id, []byte(req.BearerToken))
	if err != nil {
		return nil, err
	}
	name := req.Name
	if name == "" {
		name = "Active Directory"
	}
	c.AgentKeyMAC = e.DirectoryKeys().KeyMAC(id, c.AgentPublicKey)
	ps := &store.PairedSystem{ID: id, Name: name, SystemType: adSystemType, Description: req.Description,
		CallbackURL: req.CallbackURL, HMACSecretEncrypted: sealed, Status: "active"}
	var row *store.AuditEvent
	if audit != nil {
		row = audit(ps)
	}
	return ps, e.store.CreateADSystem(ps, c, row)
}

// ConfigureAD replaces a directory connector's settings; an empty bindPassword keeps the
// sealed one.
func (e *Engine) ConfigureAD(sys *store.PairedSystem, ldapsURL, bindPassword string, s *ADSettings, audit *store.AuditEvent) error {
	if sys.SystemType != adSystemType {
		return store.InputError("not an Active Directory connector")
	}
	c, err := validateADSettings(ldapsURL, bindPassword, s, false)
	if err != nil {
		return err
	}
	c.AgentKeyMAC = e.DirectoryKeys().KeyMAC(sys.ID, c.AgentPublicKey)
	sealed := ""
	if bindPassword != "" {
		if sealed, err = crypto.Seal(e.encryptionKey, store.SealConnector, sys.ID, []byte(bindPassword)); err != nil {
			return err
		}
	}
	return e.store.ConfigureADSystem(sys.ID, ldapsURL, sealed, c, audit)
}

// DirectoryKeys authenticate agent keys and sign queue entries.
func (e *Engine) DirectoryKeys() store.ADKeys { return store.NewADKeys(e.encryptionKey) }

// adConn binds to the directory over LDAPS with the pinned trust, through netguard's dialer.
func (e *Engine) adConn(sys *store.PairedSystem, c *store.ADConnector, password string) (*ldap.Conn, error) {
	if err := netguard.ValidateLDAPS(sys.CallbackURL, "ldapsUrl"); err != nil {
		return nil, err
	}
	roots, err := adRoots(c.CAPEM)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(sys.CallbackURL)
	addr := sys.CallbackURL
	if u.Port() == "" {
		addr = "ldaps://" + u.Host + ":636"
	}
	conn, err := ldap.DialURL(addr, ldap.DialWithDialer(netguard.Dialer(5*time.Second)),
		ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(15 * time.Second)
	if err := conn.Bind(c.BindDN, password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e *Engine) adConnFor(sys *store.PairedSystem, password string) (*ldap.Conn, *store.ADConnector, error) {
	c, err := e.store.ADConnector(sys.ID)
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, errADConfig
	}
	conn, err := e.adConn(sys, c, password)
	return conn, c, err
}

// testAD binds and reads the OU itself.
func (e *Engine) testAD(sys *store.PairedSystem, password string) error {
	conn, c, err := e.adConnFor(sys, password)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Search(ldap.NewSearchRequest(c.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dn"}, nil))
	return err
}

// adFind returns the DN of the one object under the OU carrying marker, or "".
func adFind(conn *ldap.Conn, baseDN, marker string, attrs ...string) (*ldap.Entry, error) {
	res, err := conn.Search(ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		"(adminDescription="+ldap.EscapeFilter(marker)+")", append([]string{"adminDescription"}, attrs...), nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, errADAmbiguous
	}
	if err != nil {
		return nil, err
	}
	switch len(res.Entries) {
	case 0:
		return nil, nil
	case 1:
		// The server matched the filter; check it again so a matching rule never widens it.
		if res.Entries[0].GetAttributeValue("adminDescription") != marker {
			return nil, errADAmbiguous
		}
		return res.Entries[0], nil
	}
	return nil, errADAmbiguous
}

// validSAM reports whether name can be a sAMAccountName as it is, without truncation.
func validSAM(name string, limit int) bool {
	return name != "" && len([]rune(name)) <= limit && strings.TrimSpace(name) == name && !strings.ContainsAny(name, "\"/\\[]:;|=,+*?<>@") &&
		strings.IndexFunc(name, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

// adWrite runs one directory write. A request that may have reached the server with no
// answer fences later writes, as a SCIM write does once its headers were written.
func (e *Engine) adWrite(op func() error) error {
	err := op()
	if ldap.IsErrorWithCode(err, ldap.ErrorNetwork) {
		if t, ok := e.httpClient.Transport.(*deliveryTransport); ok {
			t.uncertain.Store(true)
		}
	}
	return err
}

func (e *Engine) deliverAD(ctx context.Context, sys *store.PairedSystem, secret, eventType, localID string, payload []byte) error {
	if localID == "" {
		return errors.New("missing local ID")
	}
	switch eventType {
	case "user.created", "user.updated", "user.deleted", "group.updated", "group.deleted":
	case "user.mfa_reset":
		return nil // Directory accounts carry no KyIdentity factors.
	default:
		return errors.New("unsupported event")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	conn, c, err := e.adConnFor(sys, secret)
	if err != nil {
		return err
	}
	defer conn.Close()
	if strings.HasPrefix(eventType, "group.") {
		return e.deliverADGroup(conn, sys, c, eventType, localID)
	}
	var desired SCIMUserResource
	if json.Unmarshal(payload, &desired) != nil {
		return errors.New("malformed user payload")
	}
	active := eventType != "user.deleted" && desired.Active
	found, err := adFind(conn, c.BaseDN, adMarker(sys.ID, "user", localID), "userAccountControl")
	if err != nil {
		return err
	}
	if found == nil {
		// Removal of an account the directory never had creates nothing.
		if !active {
			return nil
		}
		return e.createADUser(conn, sys, c, localID, &desired)
	}
	mod := ldap.NewModifyRequest(found.DN, nil)
	uac := uacDisabled
	if active {
		uac = uacNormal
		mod.Replace("displayName", nonEmpty(desired.DisplayName))
		mod.Replace("mail", nonEmpty(primaryEmail(&desired)))
	}
	mod.Replace("userAccountControl", []string{uac})
	return e.adWrite(func() error { return conn.Modify(mod) })
}

func nonEmpty(v string) []string {
	if v == "" {
		return []string{}
	}
	return []string{v}
}

func primaryEmail(u *SCIMUserResource) string {
	for _, m := range u.Emails {
		if m.Primary {
			return m.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

// createADUser adds the account enabled, with a random password nobody holds; the agent
// sets the real one.
func (e *Engine) createADUser(conn *ldap.Conn, sys *store.PairedSystem, c *store.ADConnector, localID string, u *SCIMUserResource) error {
	if !validSAM(u.UserName, 20) {
		return errADName
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	add := ldap.NewAddRequest("CN="+ldap.EscapeDN(u.UserName)+","+c.BaseDN, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{u.UserName})
	add.Attribute("userPrincipalName", []string{u.UserName + "@" + adDomain(c.BaseDN)})
	add.Attribute("adminDescription", []string{adMarker(sys.ID, "user", localID)})
	if u.DisplayName != "" {
		add.Attribute("displayName", []string{u.DisplayName})
	}
	if mail := primaryEmail(u); mail != "" {
		add.Attribute("mail", []string{mail})
	}
	add.Attribute("unicodePwd", []string{adpass.UnicodePwd(base64.RawStdEncoding.EncodeToString(random) + "aA1!")})
	add.Attribute("userAccountControl", []string{uacNormal})
	err := e.adWrite(func() error { return conn.Add(add) })
	if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) || ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation) {
		// Our own earlier create would have been found by its marker before this add.
		return errADConflict
	}
	return err
}

// deliverADGroup writes a managed group's members: the managed users in the OU whose
// marker names a current in-scope member. A removed group is emptied, never deleted.
func (e *Engine) deliverADGroup(conn *ldap.Conn, sys *store.PairedSystem, c *store.ADConnector, eventType, groupID string) error {
	name, exists, members, err := e.store.ADGroupMembers(sys.ID, groupID)
	if err != nil {
		return err
	}
	keep := eventType == "group.updated" && exists
	found, err := adFind(conn, c.BaseDN, adMarker(sys.ID, "group", groupID))
	if err != nil {
		return err
	}
	if !keep {
		if found == nil {
			return nil
		}
		mod := ldap.NewModifyRequest(found.DN, nil)
		mod.Replace("member", []string{})
		return e.adWrite(func() error { return conn.Modify(mod) })
	}
	dns, err := adMemberDNs(conn, sys.ID, c.BaseDN, members)
	if err != nil {
		return err
	}
	if found == nil {
		if !validSAM(name, 64) {
			return errADName
		}
		add := ldap.NewAddRequest("CN="+ldap.EscapeDN(name)+","+c.BaseDN, nil)
		add.Attribute("objectClass", []string{"top", "group"})
		add.Attribute("sAMAccountName", []string{name})
		add.Attribute("groupType", []string{adGlobalGroup})
		add.Attribute("adminDescription", []string{adMarker(sys.ID, "group", groupID)})
		if len(dns) > 0 {
			add.Attribute("member", dns)
		}
		err := e.adWrite(func() error { return conn.Add(add) })
		if ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) || ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation) {
			return errADConflict
		}
		return err
	}
	mod := ldap.NewModifyRequest(found.DN, nil)
	mod.Replace("member", dns)
	return e.adWrite(func() error { return conn.Modify(mod) })
}

func adMemberDNs(conn *ldap.Conn, systemID, baseDN string, userIDs []string) ([]string, error) {
	want := map[string]bool{}
	for _, id := range userIDs {
		want[adMarker(systemID, "user", id)] = true
	}
	dns := []string{}
	if len(want) == 0 {
		return dns, nil
	}
	res, err := conn.SearchWithPaging(ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		"(&(objectClass=user)(adminDescription="+ldap.EscapeFilter(adMarker(systemID, "user", ""))+"*))", []string{"adminDescription"}, nil), 500)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, entry := range res.Entries {
		m := entry.GetAttributeValue("adminDescription")
		if want[m] && !seen[m] {
			seen[m] = true
			dns = append(dns, entry.DN)
		}
	}
	return dns, nil
}

// adDeliveryError is the stored, admin-visible text: fixed words and a result code, never
// the server's diagnostic message, which can echo values.
func adDeliveryError(err error) (string, bool) {
	for _, known := range []error{errADConflict, errADAmbiguous, errADName, errADConfig} {
		if errors.Is(err, known) {
			return known.Error(), true
		}
	}
	var lerr *ldap.Error
	if errors.As(err, &lerr) {
		if lerr.ResultCode == ldap.ErrorNetwork {
			return "directory unreachable, TLS verification failed or connection lost", true
		}
		return fmt.Sprintf("LDAP result %d (%s)", lerr.ResultCode, ldap.LDAPResultCodeMap[lerr.ResultCode]), true
	}
	return "", false
}
