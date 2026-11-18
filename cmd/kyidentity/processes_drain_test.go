package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	gosync "sync"
	"syscall"
	"testing"
	"time"

	"github.com/Busnes-app/kyidentity-server/internal/backup"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// probe is a GET with its own short-lived connection, so a closed listener shows as an error.
func probe(base, path string, cookies ...*http.Cookie) (int, map[string]any, error) {
	req, err := http.NewRequest("GET", base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 40 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return res.StatusCode, body, nil
}

func sessionCookies(t *testing.T, b *browser, base string) []*http.Cookie {
	t.Helper()
	u, _ := url.Parse(base)
	cookies := b.client.Jar.Cookies(u)
	if len(cookies) == 0 {
		t.Fatal("the browser holds no cookies")
	}
	return cookies
}

// A replica told to stop leaves rotation first: its own /readyz answers 503 while its listener
// still serves, it exits cleanly inside the grace period, and the other replica keeps
// honouring the same session.
func TestStoppingAReplicaDrainsBeforeItCloses(t *testing.T) {
	c := newCluster(t)
	var live []*process
	var liveMu gosync.Mutex
	c.loadBalancer(func() []*process { liveMu.Lock(); defer liveMu.Unlock(); return live })
	a := c.spawn("a")
	b := c.spawn("b")
	c.waitReady(a)
	c.waitReady(b)
	liveMu.Lock()
	live = []*process{a, b}
	liveMu.Unlock()
	admin := newBrowser(t, "198.51.100.20")
	admin.signIn(a.url, b.url, firstPassword)
	cookies := sessionCookies(t, admin, c.issuer)

	signalled := time.Now()
	if err := a.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	sawDraining, sawLiveDuringDrain := false, false
	for {
		status, body, err := probe(a.url, "/readyz")
		if err != nil {
			break // the listener has closed
		}
		checks, _ := body["checks"].(map[string]any)
		if status == http.StatusServiceUnavailable && checks["server"] == "draining" {
			sawDraining = true
			if s, _, err := probe(a.url, "/livez"); err == nil && s == 200 {
				sawLiveDuringDrain = true
			}
		}
		if time.Since(signalled) > 25*time.Second {
			t.Fatal("a stopping replica kept its listener open past the grace period")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !sawDraining || !sawLiveDuringDrain {
		t.Fatalf("the replica closed without first answering /readyz 503 draining (draining %v, live %v)", sawDraining, sawLiveDuringDrain)
	}
	select {
	case <-a.exited:
	case <-time.After(25*time.Second - time.Since(signalled)):
		t.Fatal("the replica did not exit within 25 s of SIGTERM")
	}
	if code := a.cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("the replica exited %d", code)
	}
	t.Logf("exited %v after SIGTERM", time.Since(signalled))
	if status, _, err := probe(b.url, "/api/auth/me", cookies...); err != nil || status != 200 {
		t.Fatalf("the remaining replica no longer honours the session: %d %v", status, err)
	}
	c.checkLogs()
}

// relay forwards TCP to target and can be frozen: bytes stop moving in both directions, as on
// a paused VM or a storage hang, while every connection stays open.
type relay struct {
	ln     net.Listener
	mu     gosync.Mutex
	frozen bool
	thawed *gosync.Cond
}

func newRelay(t *testing.T, target string) *relay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{ln: ln}
	r.thawed = gosync.NewCond(&r.mu)
	t.Cleanup(func() { r.set(false); _ = ln.Close() })
	go func() {
		for {
			in, err := ln.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				continue
			}
			go r.pipe(in, out)
			go r.pipe(out, in)
		}
	}()
	return r
}

func (r *relay) set(frozen bool) {
	r.mu.Lock()
	r.frozen = frozen
	r.mu.Unlock()
	r.thawed.Broadcast()
}

func (r *relay) pipe(from, to net.Conn) {
	defer from.Close()
	defer to.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			r.mu.Lock()
			for r.frozen {
				r.thawed.Wait()
			}
			r.mu.Unlock()
			if _, werr := to.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// With the database frozen, every replica leaves rotation within seconds while staying alive,
// and an ordinary request is answered 503 at its deadline instead of hanging. Once the
// database answers again, the replicas return to rotation on their own, the earlier session
// still works, and the backup lease can be taken.
func TestReplicasSurviveAFrozenDatabase(t *testing.T) {
	if os.Getenv("KYIDENTITY_TEST_DATABASE_URL") == "" {
		t.Skip("needs KYIDENTITY_TEST_DATABASE_URL")
	}
	dir := t.TempDir()
	direct, err := store.PostgresURLForTest(filepath.Join(dir, "frozen.db"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(direct)
	if err != nil {
		t.Fatal(err)
	}
	r := newRelay(t, u.Host)
	u.Host = r.ln.Addr().String()
	c := newClusterOn(t, dir, u.String())
	var live []*process
	var liveMu gosync.Mutex
	c.loadBalancer(func() []*process { liveMu.Lock(); defer liveMu.Unlock(); return live })
	a := c.spawn("a")
	b := c.spawn("b")
	c.waitReady(a)
	c.waitReady(b)
	liveMu.Lock()
	live = []*process{a, b}
	liveMu.Unlock()
	admin := newBrowser(t, "198.51.100.30")
	admin.signIn(a.url, b.url, firstPassword)
	cookies := sessionCookies(t, admin, c.issuer)
	for _, p := range []*process{a, b} {
		if status, _, err := probe(p.url, "/api/auth/me", cookies...); err != nil || status != 200 {
			t.Fatalf("%s before the freeze: %d %v", p.name, status, err)
		}
	}

	r.set(true)
	frozen := time.Now()
	var wg gosync.WaitGroup
	outOfRotation := make([]time.Duration, 2)
	for i, p := range []*process{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if status, _, err := probe(p.url, "/readyz"); err == nil && status == http.StatusServiceUnavailable {
					outOfRotation[i] = time.Since(frozen)
					return
				}
				if time.Since(frozen) > 10*time.Second {
					outOfRotation[i] = time.Since(frozen)
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	for i, p := range []*process{a, b} {
		if outOfRotation[i] > 4*time.Second {
			t.Fatalf("%s still reported ready %v after the database froze", p.name, outOfRotation[i])
		}
		if status, _, err := probe(p.url, "/livez"); err != nil || status != 200 {
			t.Fatalf("%s is not alive while the database is frozen: %d %v", p.name, status, err)
		}
	}
	t.Logf("out of rotation after %v and %v", outOfRotation[0], outOfRotation[1])
	asked := time.Now()
	status, body, err := probe(a.url, "/api/auth/me", cookies...)
	if err != nil || status != http.StatusServiceUnavailable {
		t.Fatalf("an ordinary request against a frozen database: %d %v %v", status, body, err)
	}
	if took := time.Since(asked); took > 25*time.Second+2*time.Second {
		t.Fatalf("the request was answered after %v", took)
	} else {
		t.Logf("the ordinary request was answered %v %v after %v", status, body["error"], took)
	}
	for _, p := range []*process{a, b} {
		select {
		case <-p.exited:
			t.Fatalf("%s exited while the database was frozen:\n%s", p.name, p.log(t))
		default:
		}
	}

	r.set(false)
	thawed := time.Now()
	for _, p := range []*process{a, b} {
		for {
			if status, _, err := probe(p.url, "/readyz"); err == nil && status == 200 {
				break
			}
			if time.Since(thawed) > 15*time.Second {
				t.Fatalf("%s did not return to rotation within 15 s of the thaw", p.name)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Logf("both ready %v after the thaw", time.Since(thawed))
	for _, p := range []*process{a, b} {
		if status, _, err := probe(p.url, "/api/auth/me", cookies...); err != nil || status != 200 {
			t.Fatalf("%s after the thaw: %d %v", p.name, status, err)
		}
	}
	s, err := store.NewPostgres(direct)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	release, ok, err := s.AcquireLease(backup.Lease, time.Minute)
	if err != nil || !ok {
		t.Fatalf("the backup lease cannot be taken after the thaw: %v %v", ok, err)
	}
	release()
	c.checkLogs()
}
