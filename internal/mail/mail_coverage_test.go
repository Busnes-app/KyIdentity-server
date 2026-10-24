package mail

import (
	"bufio"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// erroringSettings is a settings store whose reads fail.
type erroringSettings struct{ store.Settings }

func (erroringSettings) GetSetting(string) (string, error) {
	return "", errors.New("database is locked")
}

// Without a test hook the relay's certificate is verified against the system roots: a
// relay presenting a self-signed certificate is refused before any credential is sent.
func TestSendVerifiesTheRelayCertificateByDefault(t *testing.T) {
	f, pool := startFake(t, true, true)
	s := settingsFor(f, pool, "tls")
	s.tlsConfig = nil
	err := s.Send("ada@example.test", "x", "y")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("self-signed relay accepted: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.auth != "" || f.data != "" {
		t.Fatal("credentials or data reached an unverified relay")
	}
}

// A relay that is not listening is a delivery error, not a silent success.
func TestSendReportsAnUnreachableRelay(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	s := &Settings{Host: "127.0.0.1", Port: addr.Port, From: "id@example.test", Security: "starttls"}
	if err := s.Send("ada@example.test", "x", "y"); err == nil {
		t.Fatal("send to a closed port succeeded")
	}
}

// A relay that never speaks SMTP is refused before anything is sent.
func TestSendRefusesANonSMTPGreeting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		_, _ = bufio.NewReader(conn).ReadString('\n')
	}()
	s := &Settings{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, From: "id@example.test", Security: "starttls"}
	if err := s.Send("ada@example.test", "x", "y"); err == nil {
		t.Fatal("a non-SMTP greeting was accepted")
	}
}

// Validate refuses anything that could not send, and Save stores nothing it refused.
func TestSaveRefusesInvalidSettings(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "mail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	base := Settings{Host: "smtp.example.test", Port: 587, From: "id@example.test", Security: "starttls", Password: "p"}
	cases := map[string]struct {
		mutate func(*Settings)
		want   string
	}{
		"no host":         {func(s *Settings) { s.Host = "  " }, "host is required"},
		"host with path":  {func(s *Settings) { s.Host = "smtp.example.test/x" }, "host is required"},
		"port zero":       {func(s *Settings) { s.Port = 0 }, "port must be between"},
		"port too big":    {func(s *Settings) { s.Port = 70000 }, "port must be between"},
		"bad sender":      {func(s *Settings) { s.From = "not an address" }, "from must be a valid email"},
		"plain transport": {func(s *Settings) { s.Security = "none" }, "security must be tls or starttls"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := base
			c.mutate(&in)
			err := Save(db, key, &in)
			var ie store.InputError
			if !errors.As(err, &ie) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want InputError %q", err, c.want)
			}
			if got, err := Load(db, key); err != nil || got != nil {
				t.Fatalf("refused settings were stored: %+v %v", got, err)
			}
		})
	}
}

// A store that cannot be read is an error, never "mail not configured": a blank password
// on save must not quietly drop the stored one because the read failed.
func TestLoadAndSaveSurfaceStoreErrors(t *testing.T) {
	key := make([]byte, 32)
	if got, err := Load(erroringSettings{}, key); err == nil || got != nil {
		t.Fatalf("Load on a failing store: %+v %v", got, err)
	}
	if err := Save(erroringSettings{}, key, &Settings{Host: "smtp.example.test", Port: 587, From: "id@example.test", Security: "starttls"}); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("Save on a failing store: %v", err)
	}
}

// Sealed bytes that are not settings JSON are an error, not empty settings.
func TestLoadRejectsCorruptPlaintext(t *testing.T) {
	db, err := store.New(filepath.Join(t.TempDir(), "mail.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	sealed, err := crypto.Seal(key, store.SealMail, settingKey, []byte("not json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(settingKey, sealed); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(db, key); err == nil || got != nil {
		t.Fatalf("corrupt settings loaded: %+v %v", got, err)
	}
}

// The unconfigured view offers the usual submission defaults and claims nothing is set.
func TestUnconfiguredView(t *testing.T) {
	var s *Settings
	v := s.View()
	if v.Configured || v.HasPassword || v.Port != 587 || v.Security != "starttls" || v.Host != "" {
		t.Fatalf("unconfigured view: %+v", v)
	}
}

// rejectingRelay is an implicit-TLS SMTP server that accepts every command until reject,
// which it answers with a permanent failure. dataSent waits for the session to end and
// reports whether message data arrived.
func rejectingRelay(t *testing.T, reject string) (s *Settings, dataSent func() bool) {
	t.Helper()
	srvCfg, pool := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var gotData bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		write("220 fake ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			up := strings.ToUpper(strings.TrimRight(line, "\r\n"))
			if inData {
				if up == "." {
					inData = false
					if reject == "." {
						write("554 message refused")
					} else {
						write("250 queued")
					}
				} else {
					gotData = true
				}
				continue
			}
			if reject != "" && reject != "." && strings.HasPrefix(up, reject) {
				write("550 refused")
				continue
			}
			switch {
			case strings.HasPrefix(up, "EHLO"):
				write("250-fake")
				write("250 AUTH PLAIN")
			case strings.HasPrefix(up, "AUTH"):
				write("235 authenticated")
			case up == "DATA":
				write("354 go ahead")
				inData = true
			case up == "QUIT":
				write("221 bye")
				return
			default:
				write("250 ok")
			}
		}
	}()
	return &Settings{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Username: "relay", Password: "s3cret", From: "KySignOn <id@example.test>", Security: "tls",
		tlsConfig: &tls.Config{ServerName: "127.0.0.1", RootCAs: pool, MinVersion: tls.VersionTLS12}}, func() bool {
		// A sender refused before it dials never reaches Accept; close the listener so
		// the check reports "no data" instead of hanging.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			ln.Close()
			<-done
		}
		return gotData
	}
}

// Every refusal from the relay surfaces as an error, and a refusal before DATA means the
// message body never left this server.
func TestSendSurfacesEveryRelayRefusal(t *testing.T) {
	for _, step := range []string{"AUTH", "MAIL FROM", "RCPT TO", "DATA", "."} {
		t.Run(step, func(t *testing.T) {
			s, dataSent := rejectingRelay(t, step)
			err := s.Send("ada@example.test", "Your link", "https://id.example/activate?token=abc")
			if err == nil || !strings.Contains(err.Error(), "refused") {
				t.Fatalf("relay refused %s but Send returned %v", step, err)
			}
			if sent := dataSent(); step != "." && sent {
				t.Fatalf("message data sent although the relay refused %s", step)
			}
		})
	}
	// An unparsable sender is refused after the transport is up, before MAIL FROM.
	s, dataSent := rejectingRelay(t, "")
	s.From = "not an address"
	if err := s.Send("ada@example.test", "x", "y"); err == nil || dataSent() {
		t.Fatalf("invalid sender: err=%v", err)
	}
}
