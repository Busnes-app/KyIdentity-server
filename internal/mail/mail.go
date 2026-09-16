// Package mail sends the few transactional messages KySignOn needs (activation and
// password reset links) over SMTP with TLS. Settings live encrypted in system_settings;
// the password is never returned to a browser.
package mail

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/Busness-app/kyidentity-server/internal/crypto"
	"github.com/Busness-app/kyidentity-server/internal/store"
)

const settingKey = "mail_settings_enc"

// Settings is the SMTP configuration an administrator enters. Password is write-only
// on the wire: it is stored here for sending and dropped by View.
type Settings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	Security string `json:"security"` // "tls" (implicit, usually 465) or "starttls" (usually 587)

	tlsConfig *tls.Config
}

// View is what the browser sees: everything but the password, plus whether one is set.
type View struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	From        string `json:"from"`
	Security    string `json:"security"`
	HasPassword bool   `json:"hasPassword"`
	Configured  bool   `json:"configured"`
}

func (s *Settings) View() View {
	if s == nil {
		return View{Security: "starttls", Port: 587}
	}
	return View{Host: s.Host, Port: s.Port, Username: s.Username, From: s.From, Security: s.Security, HasPassword: s.Password != "", Configured: true}
}

// Validate rejects anything that could not send: a missing host, a port outside range,
// an unparseable sender, or a transport that is not TLS.
func (s *Settings) Validate() error {
	s.Host, s.Username, s.From = strings.TrimSpace(s.Host), strings.TrimSpace(s.Username), strings.TrimSpace(s.From)
	if s.Host == "" || strings.ContainsAny(s.Host, " /\\") {
		return errors.New("host is required")
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if _, err := netmail.ParseAddress(s.From); err != nil {
		return errors.New("from must be a valid email address")
	}
	if s.Security != "tls" && s.Security != "starttls" {
		return errors.New("security must be tls or starttls")
	}
	return nil
}

// Load reads the stored settings; nil means mail delivery is not configured.
func Load(s *store.Store, key []byte) (*Settings, error) {
	enc, err := s.GetSetting(settingKey)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err := crypto.DecryptAESGCM(key, enc)
	if err != nil {
		return nil, err
	}
	var out Settings
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Save stores validated settings. An empty password keeps the stored one only while the
// relay it authenticates to is unchanged; pointing the settings elsewhere requires the
// password again, so the stored credential can never be replayed to a chosen host.
func Save(s *store.Store, key []byte, in *Settings) error {
	if err := in.Validate(); err != nil {
		return err
	}
	if in.Password == "" {
		current, err := Load(s, key)
		if err != nil {
			return err
		}
		if current != nil && current.Password != "" {
			if current.Host != in.Host || current.Port != in.Port || current.Username != in.Username || current.Security != in.Security {
				return errors.New("enter the password again when the relay, port, username or transport changes")
			}
			in.Password = current.Password
		}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	enc, err := crypto.EncryptAESGCM(key, raw)
	if err != nil {
		return err
	}
	return s.SetSetting(settingKey, enc)
}

func Clear(s *store.Store) error { return s.DeleteSetting(settingKey) }

const dialTimeout = 10 * time.Second

// Send delivers one plain-text message. The transport is always TLS: implicit for
// "tls", negotiated for "starttls", and a server without STARTTLS is refused rather than
// talked to in the clear.
func (s *Settings) Send(to, subject, body string) error {
	if s == nil {
		return errors.New("mail delivery is not configured")
	}
	if _, err := netmail.ParseAddress(to); err != nil || strings.ContainsAny(to, "\r\n") {
		return errors.New("invalid recipient")
	}
	if strings.ContainsAny(subject, "\r\n") {
		return errors.New("invalid subject")
	}
	tlsCfg := s.tlsConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	}
	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if s.Security == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.Security == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return err
		}
	}
	// The envelope takes the bare address; the display name belongs in the header only.
	from, err := netmail.ParseAddress(s.From)
	if err != nil {
		return err
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		s.From, to, subject, time.Now().UTC().Format(time.RFC1123Z), body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
