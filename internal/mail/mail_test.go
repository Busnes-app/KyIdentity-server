package mail

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// fakeSMTP speaks just enough SMTP to accept one message, either behind implicit TLS or
// after STARTTLS, and records what it was told.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	implicit bool
	starttls bool
	mu       sync.Mutex
	auth     string
	from, to string
	data     string
}

func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func startFake(t *testing.T, implicit, starttls bool) (*fakeSMTP, *x509.CertPool) {
	t.Helper()
	srvCfg, pool := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, tlsCfg: srvCfg, implicit: implicit, starttls: starttls}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f, pool
}

func (f *fakeSMTP) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	if f.implicit {
		conn = tls.Server(conn, f.tlsCfg)
	}
	r := bufio.NewReader(conn)
	write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	write("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			if f.starttls && !f.implicit {
				write("250-fake")
				write("250-STARTTLS")
				write("250 AUTH PLAIN")
			} else {
				write("250-fake")
				write("250 AUTH PLAIN")
			}
		case up == "STARTTLS":
			write("220 go ahead")
			conn = tls.Server(conn, f.tlsCfg)
			r = bufio.NewReader(conn)
		case strings.HasPrefix(up, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = strings.TrimPrefix(cmd, "AUTH PLAIN ")
			f.mu.Unlock()
			write("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.mu.Lock()
			f.from = cmd
			f.mu.Unlock()
			write("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			f.mu.Lock()
			f.to = cmd
			f.mu.Unlock()
			write("250 ok")
		case up == "DATA":
			write("354 end with .")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			write("250 queued")
		case up == "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func settingsFor(f *fakeSMTP, pool *x509.CertPool, security string) *Settings {
	_, port, _ := net.SplitHostPort(f.ln.Addr().String())
	var p int
	for _, ch := range port {
		p = p*10 + int(ch-'0')
	}
	return &Settings{Host: "127.0.0.1", Port: p, Username: "relay", Password: "s3cret", From: "KySignOn <id@example.test>", Security: security,
		tlsConfig: &tls.Config{ServerName: "127.0.0.1", RootCAs: pool, MinVersion: tls.VersionTLS12}}
}

func TestSendsOverStartTLSAndImplicitTLS(t *testing.T) {
	for _, tc := range []struct {
		name     string
		implicit bool
		security string
	}{{"starttls", false, "starttls"}, {"implicit", true, "tls"}} {
		t.Run(tc.name, func(t *testing.T) {
			f, pool := startFake(t, tc.implicit, true)
			s := settingsFor(f, pool, tc.security)
			if err := s.Send("Ada <ada@example.test>", "Your link", "https://id.example/activate?token=abc"); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.auth == "" || f.from != "MAIL FROM:<id@example.test>" || !strings.Contains(f.to, "ada@example.test") {
				t.Fatalf("auth=%q from=%q to=%q", f.auth, f.from, f.to)
			}
			if !strings.Contains(f.data, "Subject: Your link") || !strings.Contains(f.data, "token=abc") {
				t.Fatalf("data=%q", f.data)
			}
		})
	}
}

// A relay that will not upgrade to TLS never sees credentials or a message.
func TestRefusesToSendWithoutTLS(t *testing.T) {
	f, pool := startFake(t, false, false)
	s := settingsFor(f, pool, "starttls")
	err := s.Send("ada@example.test", "x", "y")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("sent without TLS: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "" || f.data != "" {
		t.Fatal("credentials or data reached a cleartext relay")
	}
}

func TestRecipientAndSubjectCannotInjectHeaders(t *testing.T) {
	s := &Settings{Host: "h", Port: 587, From: "a@b.test", Security: "starttls"}
	if err := s.Send("ada@example.test\r\nBcc: eve@example.test", "x", "y"); err == nil {
		t.Fatal("CRLF recipient accepted")
	}
	if err := s.Send("ada@example.test", "x\r\nBcc: eve@example.test", "y"); err == nil {
		t.Fatal("CRLF subject accepted")
	}
	var none *Settings
	if err := none.Send("ada@example.test", "x", "y"); err == nil {
		t.Fatal("unconfigured mail sent")
	}
}

func TestSettingsRoundTripKeepsThePasswordServerSide(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "mail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	if got, err := Load(db, key); err != nil || got != nil {
		t.Fatalf("unset load: %+v %v", got, err)
	}
	in := &Settings{Host: "smtp.example.test", Port: 465, Username: "u", Password: "p", From: "id@example.test", Security: "tls"}
	if err := Save(db, key, in); err != nil {
		t.Fatal(err)
	}
	if raw, _ := db.GetSetting(settingKey); strings.Contains(raw, "smtp.example.test") || strings.Contains(raw, "\"p\"") {
		t.Fatal("settings stored in the clear")
	}
	got, err := Load(db, key)
	if err != nil || got.Password != "p" || got.Host != "smtp.example.test" {
		t.Fatalf("load: %+v %v", got, err)
	}
	v := got.View()
	if v.HasPassword != true || v.Configured != true || strings.Contains(string(mustJSON(t, v)), "\"p\"") {
		t.Fatalf("view leaks: %+v", v)
	}
	// Saving without a password keeps the stored one; saving with one replaces it.
	if err := Save(db, key, &Settings{Host: "smtp.example.test", Port: 465, Username: "u", From: "id@example.test", Security: "tls"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(db, key); got.Password != "p" {
		t.Fatal("blank password wiped the stored one")
	}
	if err := Save(db, key, &Settings{Host: "smtp.example.test", Port: 465, From: "id@example.test", Security: "tls", Password: "q"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(db, key); got.Password != "q" {
		t.Fatal("new password not stored")
	}
	// A blank password does not follow the credential to a different relay.
	if err := Save(db, key, &Settings{Host: "evil.example.test", Port: 465, From: "id@example.test", Security: "tls"}); err == nil {
		t.Fatal("stored password carried to a new host")
	}
	if err := Save(db, key, &Settings{Host: "smtp.example.test", Port: 587, From: "id@example.test", Security: "starttls"}); err == nil {
		t.Fatal("stored password carried to a new port and transport")
	}
	if got, _ := Load(db, key); got.Host != "smtp.example.test" || got.Port != 465 || got.Password != "q" {
		t.Fatalf("rejected save changed settings: %+v", got)
	}
	for _, bad := range []Settings{{Port: 465, From: "a@b", Security: "tls"}, {Host: "h", Port: 0, From: "a@b", Security: "tls"}, {Host: "h", Port: 25, From: "nope", Security: "tls"}, {Host: "h", Port: 25, From: "a@b.test", Security: "none"}} {
		b := bad
		if err := b.Validate(); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if err := Clear(db); err != nil {
		t.Fatal(err)
	}
	if got, _ := Load(db, key); got != nil {
		t.Fatal("clear left settings behind")
	}
}
