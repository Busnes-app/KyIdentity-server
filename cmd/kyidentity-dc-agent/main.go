// Command kyidentity-dc-agent sets Active Directory passwords from KyIdentity's encrypted
// queue. It holds the X-Wing (or legacy X25519) private key KyIdentity seals to, pulls its connector's
// entries, sets unicodePwd over LDAPS and reports each result. It never logs a password.
// Operator guide: docs/ACTIVE-DIRECTORY.md.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/adpass"
	"github.com/go-ldap/ldap/v3"
)

type config struct {
	KyIdentityURL    string `json:"kyidentityUrl"`
	KyIdentityCAFile string `json:"kyidentityCaFile"`
	// SigningKey is KyIdentity's entry-signing key from the connector's settings page.
	SigningKey       string `json:"kyidentitySigningKey"`
	ConnectorID      string `json:"connectorId"`
	TokenFile        string `json:"tokenFile"`
	KeyFile          string `json:"keyFile"`
	StateFile        string `json:"stateFile"`
	LDAPSURL         string `json:"ldapsUrl"`
	CAFile           string `json:"caFile"`
	BindDN           string `json:"bindDn"`
	BindPasswordFile string `json:"bindPasswordFile"`
	BaseDN           string `json:"baseDn"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "init":
		fs := flag.NewFlagSet("init", flag.ExitOnError)
		keyFile := fs.String("key", "", "private key file (created 0600 if absent)")
		_ = fs.Parse(os.Args[2:])
		k, err := loadOrCreateKey(*keyFile)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(adpass.EncodePublicKey(k.PublicKey()))
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		cfgFile := fs.String("config", "", "JSON configuration file")
		once := fs.Bool("once", false, "process the queue once and exit")
		_ = fs.Parse(os.Args[2:])
		a, err := newAgent(*cfgFile)
		if err != nil {
			log.Fatal(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if *once {
			if err := a.pass(ctx); err != nil {
				log.Fatal(err)
			}
			return
		}
		a.loop(ctx)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: kyidentity-dc-agent init -key FILE | run -config FILE [-once]")
	os.Exit(2)
}

// readSecretFile reads a file that must not be readable by group or others. Errors name
// the config field, never the file's contents.
func readSecretFile(field, path string) ([]byte, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", field, os.ErrNotExist)
	}
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read", field)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others; chmod 600 it", field)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read", field)
	}
	return raw, nil
}

// loadOrCreateKey is init's: it creates the key once and reloads it after.
func loadOrCreateKey(path string) (*adpass.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key is required")
	}
	k, err := loadKey(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := adpass.GenerateKey()
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		if _, err := f.WriteString(adpass.EncodePrivateKey(k) + "\n"); err != nil {
			return nil, errors.Join(err, f.Close())
		}
		return k, f.Close()
	}
	return k, err
}

// loadKey is run's: a missing key is an error, never a new key, because a new key would
// fail to open every queued entry and the server would discard them.
func loadKey(path string) (*adpass.PrivateKey, error) {
	raw, err := readSecretFile("keyFile", path)
	if err != nil {
		return nil, err
	}
	return adpass.ParsePrivateKey(string(raw))
}

type agent struct {
	cfg      config
	key      *adpass.PrivateKey
	signing  *adpass.SigningKey
	token    string
	password string
	roots    *x509.CertPool
	http     *http.Client
	state    map[string]int64
	// unsaved: state holds a sequence the state file does not, so nothing more is
	// acknowledged until it is saved; a restart would otherwise forget it.
	unsaved bool
}

func newAgent(path string) (*agent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a := &agent{state: map[string]int64{}}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a.cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c := a.cfg
	if c.ConnectorID == "" || c.BaseDN == "" || c.BindDN == "" || c.StateFile == "" || c.KeyFile == "" {
		return nil, errors.New("config needs connectorId, baseDn, bindDn, keyFile and stateFile")
	}
	u, err := url.Parse(c.KyIdentityURL)
	if err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname())) {
		return nil, errors.New("kyidentityUrl must be https (http only to loopback)")
	}
	if l, err := url.Parse(c.LDAPSURL); err != nil || l.Scheme != "ldaps" || l.Host == "" {
		return nil, errors.New("ldapsUrl must be ldaps://host[:port]")
	}
	if a.signing, err = adpass.ParseSigningKey(c.SigningKey); err != nil {
		return nil, fmt.Errorf("kyidentitySigningKey: %w", err)
	}
	if a.key, err = loadKey(c.KeyFile); errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("keyFile does not exist; create it with kyidentity-dc-agent init -key FILE and set its public key in KyIdentity")
	} else if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		field, path string
		into        *string
	}{{"tokenFile", c.TokenFile, &a.token}, {"bindPasswordFile", c.BindPasswordFile, &a.password}} {
		b, err := readSecretFile(f.field, f.path)
		if err != nil {
			return nil, err
		}
		*f.into = strings.TrimRight(string(b), "\r\n")
	}
	pemText, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, err
	}
	a.roots = x509.NewCertPool()
	if !a.roots.AppendCertsFromPEM(pemText) {
		return nil, errors.New("caFile holds no PEM certificate")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.KyIdentityCAFile != "" {
		b, err := os.ReadFile(c.KyIdentityCAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = x509.NewCertPool()
		if !tlsCfg.RootCAs.AppendCertsFromPEM(b) {
			return nil, errors.New("kyidentityCaFile holds no PEM certificate")
		}
	}
	a.http = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if raw, err := readSecretFile("stateFile", c.StateFile); err == nil {
		if err := json.Unmarshal(raw, &a.state); err != nil {
			return nil, fmt.Errorf("state file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return a, nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func (a *agent) loop(ctx context.Context) {
	delay := 30 * time.Second
	for {
		if err := a.pass(ctx); err != nil {
			log.Printf("pass failed: %v", err)
			delay = min(2*delay, 5*time.Minute)
		} else {
			delay = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

type entry struct {
	UserID     string `json:"userId"`
	Seq        int64  `json:"seq"`
	ExpiresAt  int64  `json:"expiresAt"`
	Ciphertext string `json:"ciphertext"`
	Signature  string `json:"signature"`
}

// pass handles every entry the server holds now. A directory outage stops the pass, so
// the backoff applies; each entry's own problem is reported and the pass goes on.
func (a *agent) pass(ctx context.Context) error {
	if a.unsaved {
		if err := a.saveState(); err != nil {
			return fmt.Errorf("state file not saved: %w", err)
		}
		a.unsaved = false
	}
	var page struct {
		ConnectorID string  `json:"connectorId"`
		Entries     []entry `json:"entries"`
	}
	if err := a.call(ctx, http.MethodGet, "/api/ad-agent/v1/passwords", nil, &page); err != nil {
		return err
	}
	if page.ConnectorID != a.cfg.ConnectorID {
		return errors.New("token belongs to another connector than connectorId")
	}
	if len(page.Entries) == 0 {
		return nil
	}
	conn, err := a.dial()
	if err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	defer conn.Close()
	for _, e := range page.Entries {
		outcome, reason, stop := a.apply(conn, e)
		log.Printf("user %s seq %d: %s %s", e.UserID, e.Seq, outcome, reason)
		if err := a.report(ctx, e, outcome, reason); err != nil {
			return err
		}
		if stop {
			return errors.New("directory connection failed")
		}
	}
	return nil
}

// ldapsTLSConfig returns the LDAPS TLS configuration with pinned roots and Go's default
// TLS groups (offering X25519MLKEM768 first with fallback for Windows Schannel).
func (a *agent) ldapsTLSConfig(serverName string) *tls.Config {
	return &tls.Config{RootCAs: a.roots, ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func (a *agent) dial() (*ldap.Conn, error) {
	u, _ := url.Parse(a.cfg.LDAPSURL)
	addr := a.cfg.LDAPSURL
	if u.Port() == "" {
		addr = "ldaps://" + u.Host + ":636"
	}
	conn, err := ldap.DialURL(addr, ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}),
		ldap.DialWithTLSConfig(a.ldapsTLSConfig(u.Hostname())))
	if err != nil {
		return nil, err
	}
	if state, ok := conn.TLSConnectionState(); ok {
		log.Printf("ldaps connected host=%s tls=%s group=%s",
			u.Hostname(), tls.VersionName(state.Version), state.CurveID)
	}
	conn.SetTimeout(20 * time.Second)
	if err := conn.Bind(a.cfg.BindDN, a.password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// apply sets one password. stop reports a connection failure that ends the pass.
func (a *agent) apply(conn *ldap.Conn, e entry) (outcome, reason string, stop bool) {
	// Anyone can encrypt to the public key; only KyIdentity's signature says it sent this.
	if !adpass.VerifyEntry(a.signing, a.cfg.ConnectorID, e.UserID, e.Seq, e.ExpiresAt, e.Ciphertext, e.Signature) {
		return "rejected", "signature_invalid", false
	}
	if time.Now().Unix() >= e.ExpiresAt {
		return "rejected", "expired", false
	}
	last := a.state[e.UserID]
	if e.Seq < last {
		return "rejected", "replay_refused", false
	}
	if e.Seq == last {
		// Applied before; the acknowledgement was lost.
		return "applied", "", false
	}
	plain, err := adpass.Open(a.key, a.cfg.ConnectorID, e.UserID, e.Seq, e.Ciphertext)
	if err != nil {
		return "rejected", "decrypt_failed", false
	}
	defer clear(plain)
	res, err := conn.Search(ldap.NewSearchRequest(a.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		"(adminDescription="+ldap.EscapeFilter(adpass.Marker(a.cfg.ConnectorID, "user", e.UserID))+")", []string{"adminDescription"}, nil))
	if err != nil {
		return "retry", "directory_error", ldap.IsErrorWithCode(err, ldap.ErrorNetwork)
	}
	if len(res.Entries) != 1 || res.Entries[0].GetAttributeValue("adminDescription") != adpass.Marker(a.cfg.ConnectorID, "user", e.UserID) {
		return "retry", "user_not_found", false
	}
	mod := ldap.NewModifyRequest(res.Entries[0].DN, nil)
	mod.Replace("unicodePwd", []string{adpass.UnicodePwd(string(plain))})
	err = conn.Modify(mod)
	switch {
	case err == nil:
	case ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation), ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform):
		return "rejected", "password_policy", false
	default:
		return "retry", "directory_error", ldap.IsErrorWithCode(err, ldap.ErrorNetwork)
	}
	a.state[e.UserID] = e.Seq
	if err := a.saveState(); err != nil {
		a.unsaved = true
		log.Printf("state file not saved: %v", err)
		return "retry", "directory_error", true
	}
	return "applied", "", false
}

func (a *agent) saveState() error {
	raw, err := json.Marshal(a.state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(a.cfg.StateFile), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.cfg.StateFile)
}

func (a *agent) report(ctx context.Context, e entry, outcome, reason string) error {
	body, _ := json.Marshal(map[string]string{"outcome": outcome, "reason": reason})
	err := a.call(ctx, http.MethodPost, "/api/ad-agent/v1/passwords/"+url.PathEscape(e.UserID)+"/"+strconv.FormatInt(e.Seq, 10), body, nil)
	var status statusError
	if errors.As(err, &status) && status == http.StatusNotFound {
		return nil // A newer password replaced this entry, or it expired.
	}
	return err
}

type statusError int

func (s statusError) Error() string { return "KyIdentity answered HTTP " + strconv.Itoa(int(s)) }

func (a *agent) call(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.KyIdentityURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return statusError(resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
