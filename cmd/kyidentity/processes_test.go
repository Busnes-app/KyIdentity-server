package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyidentity-server/internal/crypto"
	"github.com/Busnes-app/kyidentity-server/internal/mfa"
	"github.com/Busnes-app/kyidentity-server/internal/store"
)

// serverBuildFlags is -race when this test binary has the race detector.
var serverBuildFlags []string

const (
	firstPassword   = "two-process-first-password"
	processPassword = "two-process-chosen-password"
)

// process is one kyidentity server: the built binary, its own data and backup
// directories, the shared database and the shared keys.
type process struct {
	name, url, dataDir, backupDir, logPath string
	env                                    []string
	cmd                                    *exec.Cmd
	spawned, ready                         time.Time
	exited                                 chan struct{}
}

type cluster struct {
	t                   *testing.T
	bin, dir, secrets   string
	issuer, databaseURL string
	procs               []*process
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}

// spawn starts a server with an empty data directory; extra overrides the environment.
func (c *cluster) spawn(name string, extra ...string) *process {
	c.t.Helper()
	port := freePort(c.t)
	p := &process{
		name: name, url: "http://localhost:" + port,
		dataDir:   filepath.Join(c.dir, name, "data"),
		backupDir: filepath.Join(c.dir, name, "backups"),
		logPath:   filepath.Join(c.dir, name+".log"),
	}
	for _, d := range []string{p.dataDir, p.backupDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			c.t.Fatal(err)
		}
	}
	p.env = append([]string{
		"PATH=" + os.Getenv("PATH"),
		"KYIDENTITY_DATA_DIR=" + p.dataDir,
		"KYIDENTITY_BACKUP_DIR=" + p.backupDir,
		"KYIDENTITY_PORT=" + port,
		"KYIDENTITY_LISTEN_HOST=127.0.0.1",
		"KYIDENTITY_ISSUER_URL=" + c.issuer,
		"KYIDENTITY_REPLICATED=true",
		"KYIDENTITY_DATABASE_URL_FILE=" + filepath.Join(c.secrets, "database-url"),
		"KYIDENTITY_SECRET_KEY_FILE=" + filepath.Join(c.secrets, "secret.key"),
		"KYIDENTITY_ENCRYPTION_KEY_FILE=" + filepath.Join(c.secrets, "encryption.key"),
		"KYIDENTITY_RSA_KEY_PATH=" + filepath.Join(c.secrets, "jwt_rs256.key"),
		"KYIDENTITY_VAPID_KEY_PATH=" + filepath.Join(c.secrets, "push-vapid-private.key"),
		"BOOTSTRAP_ADMIN_PASS=" + firstPassword,
		"TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128",
		// Nothing in this test may leave the machine.
		"PUSH_RELAY_URL=", "APNS_RELAY_URL=", "KYIDENTITY_ATTESTATION_STATUS_URL=",
	}, extra...)
	c.start(p)
	c.procs = append(c.procs, p)
	return p
}

func (c *cluster) start(p *process) {
	c.t.Helper()
	logFile, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		c.t.Fatal(err)
	}
	p.cmd = exec.Command(c.bin)
	p.cmd.Env, p.cmd.Stdout, p.cmd.Stderr = p.env, logFile, logFile
	p.spawned = time.Now()
	if err := p.cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	_ = logFile.Close()
	p.exited = make(chan struct{})
	go func(cmd *exec.Cmd, done chan struct{}) { _ = cmd.Wait(); close(done) }(p.cmd, p.exited)
}

func (p *process) log(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(p.logPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// waitReady blocks until /readyz answers 200, and fails if the process dies first.
func (c *cluster) waitReady(p *process) {
	c.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-p.exited:
			c.t.Fatalf("%s exited during start:\n%s", p.name, p.log(c.t))
		default:
		}
		if res, err := http.Get(p.url + "/readyz"); err == nil {
			_ = res.Body.Close()
			if res.StatusCode == 200 {
				p.ready = time.Now()
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.t.Fatalf("%s never became ready:\n%s", p.name, p.log(c.t))
}

// stop sends sig and returns the exit code (-1 when killed by a signal).
func (p *process) stop(t *testing.T, sig syscall.Signal) int {
	t.Helper()
	_ = p.cmd.Process.Signal(sig)
	select {
	case <-p.exited:
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		t.Fatalf("%s did not exit on %v", p.name, sig)
	}
	return p.cmd.ProcessState.ExitCode()
}

// browser is one user agent: a cookie jar and the address the proxy reports for it.
type browser struct {
	t      *testing.T
	client *http.Client
	ip     string
}

func newBrowser(t *testing.T, ip string) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, ip: ip, client: &http.Client{
		Jar: jar, Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type reply struct {
	status int
	header http.Header
	raw    []byte
	body   map[string]any
}

func (r reply) String() string { return fmt.Sprintf("%d %s", r.status, r.raw) }

// do sends one request to base. A mutating request first takes a CSRF token from csrfFrom
// (base itself when empty), so the token one server mints is the one another checks.
func (b *browser) do(base, method, path string, body any, header map[string]string, csrfFrom string) reply {
	b.t.Helper()
	var rd io.Reader
	contentType := ""
	switch v := body.(type) {
	case nil:
	case url.Values:
		rd, contentType = strings.NewReader(v.Encode()), "application/x-www-form-urlencoded"
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			b.t.Fatal(err)
		}
		rd, contentType = bytes.NewReader(raw), "application/json"
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		b.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("X-Forwarded-For", b.ip)
	if method != "GET" && strings.HasPrefix(path, "/api/") {
		if csrfFrom == "" {
			csrfFrom = base
		}
		token, _ := b.do(csrfFrom, "GET", "/api/auth/csrf", nil, nil, "").body["csrfToken"].(string)
		if token == "" {
			b.t.Fatalf("no CSRF token from %s", csrfFrom)
		}
		req.Header.Set("X-CSRF-Token", token)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := b.client.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s%s: %v", method, base, path, err)
	}
	defer res.Body.Close()
	out := reply{status: res.StatusCode, header: res.Header}
	out.raw, _ = io.ReadAll(res.Body)
	_ = json.Unmarshal(out.raw, &out.body)
	return out
}

func (b *browser) get(base, path string) reply { return b.do(base, "GET", path, nil, nil, "") }

func (b *browser) signIn(base, csrfFrom string, password ...string) {
	b.t.Helper()
	password = append(password, processPassword)
	res := b.do(base, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": password[0]}, nil, csrfFrom)
	if res.status != 200 || res.body["success"] != true {
		b.t.Fatalf("sign-in at %s: %v", base, res)
	}
}

// stepUp re-authenticates on grantFrom for one operation and returns the grant header.
func (b *browser) stepUp(grantFrom, method, path string) map[string]string {
	b.t.Helper()
	res := b.do(grantFrom, "POST", "/api/auth/step-up", map[string]string{"password": processPassword, "operation": method + " " + path}, nil, "")
	token, _ := res.body["stepUpToken"].(string)
	if res.status != 200 || token == "" {
		b.t.Fatalf("step-up for %s %s at %s: %v", method, path, grantFrom, res)
	}
	return map[string]string{"X-KyIdentity-StepUp": token}
}

// chooseFirstPassword replaces the bootstrap password: grantFrom re-authenticates, changeAt
// makes the change.
func (b *browser) chooseFirstPassword(grantFrom, changeAt string) {
	b.t.Helper()
	change := map[string]string{"currentPassword": firstPassword, "newPassword": processPassword}
	grant := b.do(grantFrom, "POST", "/api/auth/step-up", map[string]string{"password": firstPassword, "operation": "POST /api/user/password"}, nil, "")
	token, _ := grant.body["stepUpToken"].(string)
	if res := b.do(changeAt, "POST", "/api/user/password", change, map[string]string{"X-KyIdentity-StepUp": token}, grantFrom); res.status/100 != 2 {
		b.t.Fatalf("changing the first password: %v (grant %v)", res, grant)
	}
	if me := b.get(grantFrom, "/api/auth/me"); me.status != 200 {
		b.signIn(grantFrom, changeAt)
	}
}

// leaked reports whether out holds a password, a key or the database credentials.
func (c *cluster) leaked(out string) bool {
	u, _ := url.Parse(c.databaseURL)
	secrets := []string{firstPassword, processPassword, u.User.String() + "@"}
	if pw, _ := u.User.Password(); len(pw) >= 8 {
		secrets = append(secrets, pw)
	}
	for _, name := range []string{"secret.key", "encryption.key"} {
		raw, _ := os.ReadFile(filepath.Join(c.secrets, name))
		secrets = append(secrets, string(raw), hex.EncodeToString(raw))
	}
	return slices.ContainsFunc(secrets, func(s string) bool { return strings.Contains(out, s) })
}

// checkLogs fails if a process raced with itself or wrote a secret to its log.
func (c *cluster) checkLogs() {
	c.t.Helper()
	for _, p := range c.procs {
		out := p.log(c.t)
		if strings.Contains(out, "DATA RACE") {
			c.t.Fatalf("%s reported a data race:\n%s", p.name, out)
		}
		if c.leaked(out) {
			c.t.Fatalf("%s logged a secret", p.name)
		}
	}
}

// command runs the server binary as an operator would, against the shared database.
func (c *cluster) command(stdin string, args ...string) string {
	c.t.Helper()
	cmd := exec.Command(c.bin, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "KYIDENTITY_DATABASE_URL_FILE=" + filepath.Join(c.secrets, "database-url")}
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if c.leaked(string(out)) {
		c.t.Fatalf("kyidentity %s printed a secret", args[0])
	}
	if err != nil || strings.Contains(string(out), "DATA RACE") {
		c.t.Fatalf("kyidentity %s: %v\n%s", args[0], err, out)
	}
	return string(out)
}

// together runs the calls at the same instant and returns their replies in order.
func together(calls ...func() reply) []reply {
	out := make([]reply, len(calls))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, call := range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i] = call()
		}()
	}
	close(start)
	wg.Wait()
	return out
}

func countStatus(replies []reply, status int) (n int) {
	for _, r := range replies {
		if r.status == status {
			n++
		}
	}
	return n
}

func capsules(t *testing.T, procs ...*process) (n int) {
	t.Helper()
	for _, p := range procs {
		_ = filepath.WalkDir(p.backupDir, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(path, ".kycap") {
				n++
			}
			return nil
		})
	}
	return n
}

func pkce() (verifier, challenge string) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	if os.Getenv("KYIDENTITY_TEST_DATABASE_URL") == "" {
		t.Skip("needs KYIDENTITY_TEST_DATABASE_URL")
	}
	dir := t.TempDir()
	databaseURL, err := store.PostgresURLForTest(filepath.Join(dir, "cluster.db"))
	if err != nil {
		t.Fatal(err)
	}
	return newClusterOn(t, dir, databaseURL)
}

func newClusterOn(t *testing.T, dir, databaseURL string) *cluster {
	t.Helper()
	c := &cluster{t: t, dir: dir, databaseURL: databaseURL}
	c.bin = filepath.Join(c.dir, "kyidentity")
	build := exec.Command("go", append(append([]string{"build"}, serverBuildFlags...), "-o", c.bin, ".")...)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the server: %v\n%s", err, out)
	}

	// The Secret every replica mounts: the database URL and the four keys.
	c.secrets = filepath.Join(c.dir, "secret")
	if err := os.Mkdir(c.secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"database-url": c.databaseURL}
	for _, name := range []string{"secret.key", "encryption.key"} {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		files[name] = hex.EncodeToString(key)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(c.secrets, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := crypto.LoadOrCreateRSAKey(filepath.Join(c.secrets, "jwt_rs256.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := mfa.NewUnifiedPushSender(filepath.Join(c.secrets, "push-vapid-private.key"), "https://id.example", false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range c.procs {
			_ = p.cmd.Process.Kill()
			<-p.exited
			if t.Failed() {
				t.Logf("---- %s ----\n%s", p.name, p.log(t))
			}
		}
	})
	return c
}

// loadBalancer sends each request to the next live server in turn.
func (c *cluster) loadBalancer(backends func() []*process) {
	c.t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.t.Fatal(err)
	}
	c.issuer = fmt.Sprintf("http://localhost:%d", l.Addr().(*net.TCPAddr).Port)
	var turn atomic.Uint64
	srv := &http.Server{Handler: &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		live := backends()
		target, _ := url.Parse(live[turn.Add(1)%uint64(len(live))].url)
		r.SetURL(target)
		r.Out.Host = r.In.Host
		r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
	}}}
	go func() { _ = srv.Serve(l) }()
	c.t.Cleanup(func() { _ = srv.Close() })
}

// Two real server processes, each with its own empty data directory, one Postgres
// database and one set of keys, as two pods are. What one process issues, the other must
// honour, and what may happen once must happen once whichever process is asked.
func TestTwoServerProcessesAreOneIdentity(t *testing.T) {
	c := newCluster(t)
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	keyID := priv.Public().ID()
	var live []*process
	var liveMu sync.Mutex
	setLive := func(p ...*process) { liveMu.Lock(); live = p; liveMu.Unlock() }
	c.loadBalancer(func() []*process { liveMu.Lock(); defer liveMu.Unlock(); return live })

	// Both start at once on an empty database: one schema, one administrator.
	a := c.spawn("a", "KYIDENTITY_RECOVERY_KEY_ID="+keyID)
	b := c.spawn("b", "KYIDENTITY_RECOVERY_KEY_ID="+keyID)
	c.waitReady(a)
	c.waitReady(b)
	setLive(a, b)

	admin := newBrowser(t, "198.51.100.10")

	// A CSRF token minted by B is accepted by A; the session A creates is B's too.
	admin.signIn(a.url, b.url, firstPassword)
	for _, p := range []*process{a, b} {
		if me := admin.get(p.url, "/api/auth/me"); me.status != 200 {
			t.Fatalf("the session from a is not a session on %s: %v", p.name, me)
		}
	}
	// The first password must be replaced: A is asked, B makes the change.
	admin.chooseFirstPassword(a.url, b.url)
	users := admin.get(b.url, "/api/admin/users")
	if list, _ := users.body["users"].([]any); users.status != 200 || len(list) != 1 {
		t.Fatalf("two first starts did not leave exactly one account: %v", users)
	}
	if ja, jb := admin.get(a.url, "/.well-known/jwks.json"), admin.get(b.url, "/.well-known/jwks.json"); ja.status != 200 || !bytes.Equal(ja.raw, jb.raw) {
		t.Fatalf("the servers publish different signing keys:\n%s\n%s", ja.raw, jb.raw)
	}

	// A step-up grant is spent once, whichever server it is shown to: issued by A, shown
	// to both at the same instant.
	grant := admin.stepUp(a.url, "POST", "/api/admin/clients")
	client := map[string]any{"clientName": "Two process app", "clientType": "public", "redirectUris": []string{"https://app.example/cb"}}
	created := together(
		func() reply { return admin.do(a.url, "POST", "/api/admin/clients", client, grant, "") },
		func() reply { return admin.do(b.url, "POST", "/api/admin/clients", client, grant, "") },
	)
	var clientID string
	for _, r := range created {
		if made, _ := r.body["client"].(map[string]any); made != nil {
			clientID, _ = made["id"].(string)
		}
	}
	if ok := countStatus(created, 200) + countStatus(created, 201); ok != 1 || clientID == "" {
		t.Fatalf("one step-up grant authorised %d changes across two servers: %v", ok, created)
	}

	// Open the app to every user, so the administrator can authorise it.
	var appID string
	var revision float64
	registry := admin.get(a.url, "/api/admin/app-registry")
	apps, _ := registry.body["records"].([]any)
	for _, raw := range apps {
		if app, _ := raw.(map[string]any); app["clientId"] == clientID {
			appID, _ = app["id"].(string)
			revision, _ = app["revision"].(float64)
		}
	}
	if appID == "" {
		t.Fatalf("the client created on one server is not in the other's registry: %v", registry)
	}
	policyPath := "/api/admin/app-registry/" + appID + "/access-policy"
	if res := admin.do(b.url, "PUT", policyPath, map[string]any{"mode": "all_active_users", "enabled": true, "revision": revision}, admin.stepUp(a.url, "PUT", policyPath), a.url); res.status/100 != 2 {
		t.Fatalf("access policy: %v", res)
	}

	// An authorization code from one server is redeemed at the other, and the access token
	// that one mints is honoured by the first.
	authorize := func(base string) (code, verifier string) {
		t.Helper()
		verifier, challenge := pkce()
		q := url.Values{"client_id": {clientID}, "redirect_uri": {"https://app.example/cb"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
		res := admin.get(base, "/oauth/authorize?"+q.Encode())
		to, _ := url.Parse(res.header.Get("Location"))
		if code = to.Query().Get("code"); res.status != 302 || code == "" {
			t.Fatalf("authorize at %s: %v -> %s", base, res, res.header.Get("Location"))
		}
		return code, verifier
	}
	redeem := func(base, code, verifier string) reply {
		return newBrowser(t, "198.51.100.20").do(base, "POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID}, "redirect_uri": {"https://app.example/cb"}, "code_verifier": {verifier}}, nil, "")
	}
	code, verifier := authorize(a.url)
	tokens := redeem(b.url, code, verifier)
	access, _ := tokens.body["access_token"].(string)
	if tokens.status != 200 || access == "" {
		t.Fatalf("a code issued by a was refused by b: %v", tokens)
	}
	if info := admin.do(a.url, "GET", "/oauth/userinfo", nil, map[string]string{"Authorization": "Bearer " + access}, ""); info.status != 200 || info.body["sub"] == nil {
		t.Fatalf("an access token minted by b was refused by a: %v", info)
	}

	// A code is redeemed once: shown to both servers at the same instant, one answers.
	for range 5 {
		code, verifier := authorize(b.url)
		raced := together(
			func() reply { return redeem(a.url, code, verifier) },
			func() reply { return redeem(b.url, code, verifier) },
		)
		if countStatus(raced, 200) != 1 {
			t.Fatalf("one authorization code was redeemed %d times across two servers: %v", countStatus(raced, 200), raced)
		}
	}

	// Limits are counted once across servers: five password-reset requests an hour from one
	// address is five, not five per server.
	stranger := newBrowser(t, "198.51.100.30")
	allowed := 0
	for i := range 12 {
		p := []*process{a, b}[i%2]
		if res := stranger.do(p.url, "POST", "/api/auth/password/forgot", map[string]string{"identifier": "nobody@example.com"}, nil, ""); res.status != 429 {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("%d password-reset requests were let through across two servers, want 5", allowed)
	}

	// So is the lockout: ten wrong passwords spread over both servers lock the account for
	// that address on both, and for no other address.
	guesser := newBrowser(t, "198.51.100.40")
	for i := range store.MaxFailedLogins {
		p := []*process{a, b}[i%2]
		if res := guesser.do(p.url, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": "wrong-password"}, nil, ""); res.status != 401 {
			t.Fatalf("wrong password %d at %s: %v", i, p.name, res)
		}
	}
	// The login limiter (ten, refilling one every five seconds) is shared as well, so the
	// right password is tried from the locked address only once a token is back.
	time.Sleep(6 * time.Second)
	if res := guesser.do(a.url, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": processPassword}, nil, ""); res.status != 401 {
		t.Fatalf("five wrong passwords on each server did not lock the account: %v", res)
	}
	newBrowser(t, "198.51.100.41").signIn(b.url, "")

	// The recovery key: pinned on A, where it lands in A's data directory. B has no such
	// file and takes the key from the database, because its configuration names it.
	pinBody := map[string]any{"public_key": base64.StdEncoding.EncodeToString(priv.Public().Bytes()), "threshold": 2, "total_shares": 3}
	if res := admin.do(a.url, "POST", "/api/admin/backup/pin-key", pinBody, admin.stepUp(b.url, "POST", "/api/admin/backup/pin-key"), ""); res.status != 200 {
		t.Fatalf("pin: %v", res)
	}
	pinnedAt := time.Now()
	for _, p := range []*process{a, b} {
		if st := admin.get(p.url, "/api/admin/backup/status"); st.body["key_pinned"] != true || st.body["recovery_key_id"] != keyID {
			t.Fatalf("%s does not hold the pinned key: %v", p.name, st)
		}
		if _, err := os.Stat(filepath.Join(p.dataDir, "recovery.pub")); err != nil {
			t.Fatalf("%s has no recovery.pub: %v", p.name, err)
		}
	}

	// The schedule comes due in both processes. Wait until each has ticked since the pin
	// (a tick is a minute after its start, give or take the start itself): one backup ran.
	var bothTicked time.Time
	for _, p := range []*process{a, b} {
		tick := p.ready.Add(time.Minute)
		for p.spawned.Add(tick.Sub(p.ready)).Before(pinnedAt) {
			tick = tick.Add(time.Minute)
		}
		if tick.After(bothTicked) {
			bothTicked = tick
		}
	}
	time.Sleep(time.Until(bothTicked.Add(5 * time.Second)))
	if n := capsules(t, a, b); n != 1 {
		t.Fatalf("%d capsules after the schedule came due once in two processes, want 1", n)
	}
	runs := admin.get(a.url, "/api/admin/audit-events?action=admin.backup_run")
	if events, _ := runs.body["auditEvents"].([]any); runs.status != 200 || len(events) != 1 {
		t.Fatalf("scheduled backup runs recorded: %v", runs)
	}

	// Back up now on both at the same instant: no two backups overlap, and every answer of
	// "done" is a capsule sealed to the pinned key.
	before := capsules(t, a, b)
	deposits := together(
		func() reply { return admin.do(a.url, "POST", "/api/admin/backup/deposit", nil, nil, "") },
		func() reply { return admin.do(b.url, "POST", "/api/admin/backup/deposit", nil, nil, "") },
	)
	done := countStatus(deposits, 200)
	if done == 0 || done+countStatus(deposits, 409) != 2 || capsules(t, a, b)-before != done {
		t.Fatalf("two Back up now requests: %v; capsules %d -> %d", deposits, before, capsules(t, a, b))
	}
	for _, r := range deposits {
		if r.status == 200 && !strings.Contains(string(r.raw), keyID) {
			t.Fatalf("a capsule was not sealed to the pinned key: %v", r)
		}
	}

	// A third server whose configuration names no key reads the same database and seals
	// nothing: the database alone does not choose who can open a backup.
	unnamed := c.spawn("unnamed")
	c.waitReady(unnamed)
	if st := admin.get(unnamed.url, "/api/admin/backup/status"); st.body["key_pinned"] == true || !strings.Contains(fmt.Sprint(st.body["recovery_key_error"]), "KYIDENTITY_RECOVERY_KEY_ID") {
		t.Fatalf("a server with no key named reports: %v", st)
	}
	if res := admin.do(unnamed.url, "POST", "/api/admin/backup/deposit", nil, nil, ""); res.status != 412 || !strings.Contains(string(res.raw), "KYIDENTITY_RECOVERY_KEY_ID") || capsules(t, unnamed) != 0 {
		t.Fatalf("a server with no key named backed up: %v, %d capsules", res, capsules(t, unnamed))
	}
	const export = "/api/admin/backup/export-capsule"
	if res := admin.do(unnamed.url, "GET", export, nil, admin.stepUp(a.url, "GET", export), ""); res.status != 412 || !strings.Contains(string(res.raw), "KYIDENTITY_RECOVERY_KEY_ID") {
		t.Fatalf("a server with no key named exported a capsule: %d", res.status)
	}
	if res := admin.do(b.url, "GET", export, nil, admin.stepUp(a.url, "GET", export), ""); res.status != 200 || res.header.Get("X-Recovery-Key-ID") != keyID {
		t.Fatalf("export on b: %d, sealed to %q", res.status, res.header.Get("X-Recovery-Key-ID"))
	}
	if _, err := os.Stat(filepath.Join(unnamed.dataDir, "recovery.pub")); !os.IsNotExist(err) {
		t.Fatalf("a server with no key named wrote recovery.pub: %v", err)
	}
	if code := unnamed.stop(t, syscall.SIGTERM); code != 0 {
		t.Fatalf("unnamed exited %d on SIGTERM", code)
	}

	// Through the load balancer, every request of a sign-in lands on the next server.
	visitors := make([]func() reply, 8)
	for i := range visitors {
		visitors[i] = func() reply {
			v := newBrowser(t, fmt.Sprintf("198.51.100.%d", 100+i))
			v.signIn(c.issuer, "")
			return v.get(c.issuer, "/api/auth/me")
		}
	}
	if seen := together(visitors...); countStatus(seen, 200) != len(visitors) {
		t.Fatalf("sign-ins through the load balancer: %v", seen)
	}

	// A is killed outright. B still honours the session A made, and a new A with an empty
	// data directory, as a rescheduled pod has, is the same identity again.
	setLive(b)
	if code := a.stop(t, syscall.SIGKILL); code != -1 {
		t.Fatalf("a exited %d on SIGKILL", code)
	}
	if me := admin.get(b.url, "/api/auth/me"); me.status != 200 {
		t.Fatalf("b lost a's session when a died: %v", me)
	}
	if err := os.RemoveAll(a.dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(a.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c.start(a)
	c.waitReady(a)
	setLive(a, b)
	if me := admin.get(a.url, "/api/auth/me"); me.status != 200 {
		t.Fatalf("the restarted a refuses a session from before: %v", me)
	}
	if st := admin.get(a.url, "/api/admin/backup/status"); st.body["key_pinned"] != true || st.body["recovery_key_id"] != keyID {
		t.Fatalf("the restarted a lost the recovery key: %v", st)
	}

	// Signing out on one server signs out on the other.
	if res := admin.do(b.url, "POST", "/api/auth/logout", nil, nil, a.url); res.status/100 != 2 {
		t.Fatalf("sign-out: %v", res)
	}
	if me := admin.get(a.url, "/api/auth/me"); me.status != 401 {
		t.Fatalf("a still honours a session b ended: %v", me)
	}

	for _, p := range []*process{a, b} {
		if code := p.stop(t, syscall.SIGTERM); code != 0 {
			t.Fatalf("%s exited %d on SIGTERM", p.name, code)
		}
	}
	c.checkLogs()
}

// What an operator does to an install: move it from SQLite onto Postgres and replicas,
// change the session limits, replace the recovery key one replica at a time, and restore a
// capsule. Each is done here to real processes, the last three while they serve.
func TestServerProcessesThroughOperatorChanges(t *testing.T) {
	c := newCluster(t)
	var live []*process
	var liveMu sync.Mutex
	setLive := func(p ...*process) { liveMu.Lock(); live = p; liveMu.Unlock() }
	c.loadBalancer(func() []*process { liveMu.Lock(); defer liveMu.Unlock(); return live })
	oldKey, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	oldID, newID := oldKey.Public().ID(), newKey.Public().ID()
	pin := func(key recoverykey.PrivateKey) map[string]any {
		return map[string]any{"public_key": base64.StdEncoding.EncodeToString(key.Public().Bytes()), "threshold": 2, "total_shares": 3}
	}
	const pinPath, export = "/api/admin/backup/pin-key", "/api/admin/backup/export-capsule"

	// A single instance on SQLite, with keys it generated itself, gains an administrator, an
	// app and a session.
	single := c.spawn("single", "KYIDENTITY_REPLICATED=", "KYIDENTITY_DATABASE_URL_FILE=", "KYIDENTITY_SECRET_KEY_FILE=",
		"KYIDENTITY_ENCRYPTION_KEY_FILE=", "KYIDENTITY_RSA_KEY_PATH=", "KYIDENTITY_VAPID_KEY_PATH=")
	c.waitReady(single)
	setLive(single)
	admin := newBrowser(t, "198.51.100.10")
	admin.signIn(single.url, "", firstPassword)
	admin.chooseFirstPassword(single.url, single.url)
	newClient := func(base, name string) string {
		t.Helper()
		res := admin.do(base, "POST", "/api/admin/clients", map[string]any{"clientName": name, "clientType": "public", "redirectUris": []string{"https://app.example/cb"}}, admin.stepUp(base, "POST", "/api/admin/clients"), "")
		made, _ := res.body["client"].(map[string]any)
		id, _ := made["id"].(string)
		if id == "" {
			t.Fatalf("creating client %s at %s: %v", name, base, res)
		}
		return id
	}
	hasClient := func(base, id string) bool {
		t.Helper()
		res := admin.get(base, "/api/admin/clients")
		if res.status != 200 {
			t.Fatalf("clients at %s: %v", base, res)
		}
		return strings.Contains(string(res.raw), id)
	}
	firstApp := newClient(single.url, "From the SQLite days")
	jwks := admin.get(single.url, "/.well-known/jwks.json")
	if code := single.stop(t, syscall.SIGTERM); code != 0 {
		t.Fatalf("single exited %d on SIGTERM", code)
	}

	// The move in docs/RUNNING.md: the four key files into the Secret unchanged, the rows
	// into Postgres, then two replicas. The session, the app and the signing key carry over.
	for _, name := range []string{"secret.key", "encryption.key", "jwt_rs256.key", "push-vapid-private.key"} {
		raw, err := os.ReadFile(filepath.Join(single.dataDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(c.secrets, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out := c.command("", "migrate-to-postgres", "-from", filepath.Join(single.dataDir, "kyidentity.db")); !strings.Contains(out, "row count matches") {
		t.Fatalf("migrate-to-postgres: %s", out)
	}
	a := c.spawn("a", "KYIDENTITY_RECOVERY_KEY_ID="+oldID)
	b := c.spawn("b", "KYIDENTITY_RECOVERY_KEY_ID="+oldID)
	c.waitReady(a)
	c.waitReady(b)
	setLive(a, b)
	both := []*process{a, b}
	for _, p := range both {
		if me := admin.get(p.url, "/api/auth/me"); me.status != 200 {
			t.Fatalf("%s refuses the session from before the move: %v", p.name, me)
		}
		if !hasClient(p.url, firstApp) {
			t.Fatalf("%s lost the app in the move", p.name)
		}
		if got := admin.get(p.url, "/.well-known/jwks.json"); got.status != 200 || !bytes.Equal(got.raw, jwks.raw) {
			t.Fatalf("%s signs with another key after the move:\n%s\n%s", p.name, jwks.raw, got.raw)
		}
	}
	newBrowser(t, "198.51.100.11").signIn(c.issuer, "")

	// Session limits changed on A are the limits on B within five seconds, with no restart.
	const limitsPath = "/api/admin/session-settings"
	limits := map[string]any{"absolute": 7200, "idle": 600}
	if was := admin.get(b.url, limitsPath); was.status != 200 || was.body["idle"] == float64(600) {
		t.Fatalf("limits on b before the change: %v", was)
	}
	if res := admin.do(a.url, "PUT", limitsPath, limits, admin.stepUp(b.url, "PUT", limitsPath), ""); res.status != 200 {
		t.Fatalf("changing the session limits: %v", res)
	}
	changed := time.Now()
	for admin.get(b.url, limitsPath).body["idle"] != float64(600) {
		if time.Since(changed) > 7*time.Second {
			t.Fatalf("b still applies the old session limits %v after the change on a", time.Since(changed))
		}
		time.Sleep(200 * time.Millisecond)
	}

	// The recovery key, pinned and in use.
	status := func(p *process) map[string]any { return admin.get(p.url, "/api/admin/backup/status").body }
	deposit := func(p *process) reply { return admin.do(p.url, "POST", "/api/admin/backup/deposit", nil, nil, "") }
	sealsTo := func(p *process, id string) {
		t.Helper()
		if st := status(p); st["key_pinned"] != true || st["recovery_key_id"] != id {
			t.Fatalf("%s does not hold key %s: %v", p.name, id, st)
		}
		// Another backup may be running (the schedule, or the other server): ask again.
		res := deposit(p)
		for wait := time.Now(); res.status == 409 && time.Since(wait) < 30*time.Second; res = deposit(p) {
			time.Sleep(200 * time.Millisecond)
		}
		if res.status != 200 || !strings.Contains(string(res.raw), id) {
			t.Fatalf("Back up now on %s, want a capsule sealed to %s: %v", p.name, id, res)
		}
	}
	// refuses: p reports no usable key, Back up now and export seal nothing, and no capsule
	// is written there, by a request or by the schedule.
	refuses := func(p *process, why string) {
		t.Helper()
		had := capsules(t, p)
		if st := status(p); st["key_pinned"] == true || st["recovery_key_error"] == nil {
			t.Fatalf("%s: %s reports a usable key: %v", why, p.name, st)
		}
		if res := deposit(p); res.status/100 == 2 {
			t.Fatalf("%s: Back up now on %s: %v", why, p.name, res)
		}
		other := a
		if p == a {
			other = b
		}
		if res := admin.do(p.url, "GET", export, nil, admin.stepUp(other.url, "GET", export), ""); res.status/100 == 2 {
			t.Fatalf("%s: %s exported a capsule sealed to %q", why, p.name, res.header.Get("X-Recovery-Key-ID"))
		}
		if n := capsules(t, p); n != had {
			t.Fatalf("%s: %s wrote %d capsules", why, p.name, n-had)
		}
	}
	if res := admin.do(a.url, "POST", pinPath, pin(oldKey), admin.stepUp(b.url, "POST", pinPath), ""); res.status != 200 {
		t.Fatalf("pin: %v", res)
	}
	sealsTo(a, oldID)
	sealsTo(b, oldID)

	// Replacing it. The new ID is rolled out first, one replica at a time, each keeping its
	// data directory and so the old recovery.pub. A replica that names the new key seals
	// nothing until that key is pinned; one that still names the old key goes on as before.
	roll := func(p *process) {
		t.Helper()
		if code := p.stop(t, syscall.SIGTERM); code != 0 {
			t.Fatalf("%s exited %d on SIGTERM", p.name, code)
		}
		p.env = append(p.env, "KYIDENTITY_RECOVERY_KEY_ID="+newID)
		c.start(p)
		c.waitReady(p)
	}
	setLive(b)
	roll(a)
	setLive(a, b)
	refuses(a, "new ID, old key still pinned")
	sealsTo(b, oldID)
	if me := admin.get(a.url, "/api/auth/me"); me.status != 200 {
		t.Fatalf("the roll ended the administrator's session: %v", me)
	}
	setLive(a)
	roll(b)
	setLive(a, b)
	refuses(b, "new ID, old key still pinned")

	// The new key cannot be pinned over the old pin.
	if res := admin.do(a.url, "POST", pinPath, pin(newKey), admin.stepUp(b.url, "POST", pinPath), ""); res.status != 409 {
		t.Fatalf("pinning a second key over the first: %v", res)
	}
	// Clear the pin by hand, as the documentation says: the four settings, and recovery.pub
	// on the server that will pin. B keeps its old recovery.pub.
	db, err := store.NewPostgres(c.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, key := range []string{"kyrecovery_key_id", "kyrecovery_threshold", "kyrecovery_total_shares", "kyrecovery_public_key"} {
		if err := db.DeleteSetting(key); err != nil {
			t.Fatal(err)
		}
	}
	// Even with the pin gone, the old key cannot come back: both replicas name the new one.
	if res := admin.do(b.url, "POST", pinPath, pin(oldKey), admin.stepUp(a.url, "POST", pinPath), ""); res.status != 409 {
		t.Fatalf("a replica that names the new key pinned the old one: %v", res)
	}
	if res := admin.do(a.url, "POST", pinPath, pin(newKey), admin.stepUp(b.url, "POST", pinPath), ""); res.status != 409 {
		t.Fatalf("a pinned over the old recovery.pub it still holds: %v", res)
	}
	if err := os.Remove(filepath.Join(a.dataDir, "recovery.pub")); err != nil {
		t.Fatal(err)
	}
	if res := admin.do(a.url, "POST", pinPath, pin(newKey), admin.stepUp(b.url, "POST", pinPath), ""); res.status != 200 {
		t.Fatalf("pinning the new key: %v", res)
	}
	sealsTo(a, newID)
	refuses(b, "old recovery.pub, new key pinned")
	if err := os.Remove(filepath.Join(b.dataDir, "recovery.pub")); err != nil {
		t.Fatal(err)
	}
	sealsTo(b, newID)

	// A capsule is taken, and then the install changes: a second app, and a new sign-in.
	capsule := admin.do(b.url, "GET", export, nil, admin.stepUp(a.url, "GET", export), "")
	if capsule.status != 200 || capsule.header.Get("X-Recovery-Key-ID") != newID {
		t.Fatalf("export: %d, sealed to %q", capsule.status, capsule.header.Get("X-Recovery-Key-ID"))
	}
	capsulePath := filepath.Join(c.dir, "restore.kycap")
	if err := os.WriteFile(capsulePath, capsule.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	laterApp := newClient(a.url, "After the capsule")
	later := newBrowser(t, "198.51.100.12")
	later.signIn(b.url, "")

	// The capsule is restored over the database while both replicas serve. They keep
	// serving; what the capsule held is back, what came later is gone, and no session from
	// before the restore, in the capsule or not, is a session any more.
	split, err := recoverykey.Split(newKey, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	c.command(split[0].String()+"\n"+split[2].String()+"\n", "restore", "-capsule", capsulePath, "-to", filepath.Join(c.dir, "restored"),
		"-expect-digest", sha256Hex(capsule.raw), "-replace-database")
	for _, p := range both {
		if res, err := http.Get(p.url + "/readyz"); err != nil || res.StatusCode != 200 {
			t.Fatalf("%s is not ready after the restore: %v %v", p.name, res, err)
		}
		for who, session := range map[string]*browser{"from the capsule": admin, "made after the capsule": later} {
			if me := session.get(p.url, "/api/auth/me"); me.status != 401 {
				t.Fatalf("%s still honours a session %s: %v", p.name, who, me)
			}
		}
	}
	admin.signIn(a.url, b.url)
	for _, p := range both {
		if !hasClient(p.url, firstApp) || hasClient(p.url, laterApp) {
			t.Fatalf("%s after the restore: first app %v, later app %v", p.name, hasClient(p.url, firstApp), hasClient(p.url, laterApp))
		}
		if st := status(p); st["interval_sec"] != float64(0) || st["recovery_key_id"] != newID {
			t.Fatalf("%s after the restore, want the schedule off and the new key: %v", p.name, st)
		}
		if got := admin.get(p.url, limitsPath); got.body["idle"] != float64(600) {
			t.Fatalf("%s lost the session limits the capsule held: %v", p.name, got)
		}
	}
	restored := admin.get(b.url, "/api/admin/audit-events?action=system.restored")
	if events, _ := restored.body["auditEvents"].([]any); restored.status != 200 || len(events) != 1 {
		t.Fatalf("restores recorded: %v", restored)
	}

	for _, p := range both {
		if code := p.stop(t, syscall.SIGTERM); code != 0 {
			t.Fatalf("%s exited %d on SIGTERM", p.name, code)
		}
	}
	c.checkLogs()
}

// The database fails over between two real Postgres servers: the primary is killed and its
// synchronous standby promoted. Both server processes notice, refuse to be ready meanwhile,
// and carry on against the new primary with no restart and nothing lost. It starts its own
// two Postgres containers from the image KYIDENTITY_TEST_FAILOVER_IMAGE names.
func TestServerProcessesFollowAPostgresFailover(t *testing.T) {
	image := os.Getenv("KYIDENTITY_TEST_FAILOVER_IMAGE")
	if image == "" {
		t.Skip("needs docker and KYIDENTITY_TEST_FAILOVER_IMAGE, a Postgres image")
	}
	docker := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	raw := make([]byte, 4)
	_, _ = rand.Read(raw)
	network := "kyidentity-failover-" + hex.EncodeToString(raw)
	primary, standby := network+"-primary", network+"-standby"
	docker("network", "create", network)
	t.Cleanup(func() {
		for _, server := range []string{primary, standby} {
			if out, _ := exec.Command("docker", "logs", "--tail", "40", server).CombinedOutput(); t.Failed() {
				t.Logf("---- %s ----\n%s", server, out)
			}
		}
		_ = exec.Command("docker", "rm", "-f", "-v", primary, standby).Run()
		_ = exec.Command("docker", "network", "rm", network).Run()
	})
	const password = "failover-test-password"
	sql := func(server, statement string) string {
		t.Helper()
		return docker("exec", "-u", "postgres", server, "psql", "-qAtX", "-v", "ON_ERROR_STOP=1", "-c", statement)
	}
	until := func(what string, limit time.Duration, ok func() bool) time.Duration {
		t.Helper()
		start := time.Now()
		for !ok() {
			if time.Since(start) > limit {
				t.Fatalf("%s: not within %v", what, limit)
			}
			time.Sleep(250 * time.Millisecond)
		}
		return time.Since(start)
	}
	accepts := func(server string) func() bool {
		return func() bool {
			return exec.Command("docker", "exec", "-u", "postgres", server, "psql", "-qAtX", "-c", "SELECT 1").Run() == nil
		}
	}
	port := func(server string) string {
		t.Helper()
		_, p, err := net.SplitHostPort(docker("port", server, "5432/tcp"))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	docker("run", "-d", "--name", primary, "--network", network, "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD="+password, image)
	// The image starts a temporary server to initialise, then the real one: wait for TCP.
	until("the primary starts", time.Minute, func() bool {
		return exec.Command("docker", "exec", primary, "pg_isready", "-h", "127.0.0.1", "-U", "postgres").Run() == nil
	})
	docker("exec", "-u", "postgres", primary, "sh", "-c", `echo "host replication all all scram-sha-256" >> "$PGDATA/pg_hba.conf"`)
	sql(primary, "SELECT pg_reload_conf()")
	sql(primary, "CREATE DATABASE kyidentity ENCODING 'UTF8' LOCALE 'C' TEMPLATE template0")
	docker("run", "-d", "--name", standby, "--network", network, "-p", "127.0.0.1::5432", "--user", "postgres", "-e", "PGPASSWORD="+password,
		"--entrypoint", "sh", image, "-c", `pg_basebackup -h `+primary+` -U postgres -D "$PGDATA" -R -X stream -c fast && chmod 700 "$PGDATA" && exec postgres`)
	until("the standby streams", time.Minute, func() bool {
		out, err := exec.Command("docker", "exec", "-u", "postgres", primary, "psql", "-qAtX", "-c", "SELECT count(*) FROM pg_stat_replication WHERE state='streaming'").Output()
		return err == nil && strings.TrimSpace(string(out)) == "1"
	})
	// Synchronous: a commit the server acknowledged is on the standby, so the failover
	// loses nothing. An asynchronous standby may be missing the last sign-out.
	sql(primary, "ALTER SYSTEM SET synchronous_standby_names = '*'")
	sql(primary, "SELECT pg_reload_conf()")
	until("the standby is synchronous", time.Minute, func() bool {
		return sql(primary, "SELECT count(*) FROM pg_stat_replication WHERE sync_state='sync'") == "1"
	})

	// One URL naming both servers.
	c := newClusterOn(t, t.TempDir(), "postgres://postgres:"+password+"@127.0.0.1:"+port(primary)+",127.0.0.1:"+port(standby)+"/kyidentity?sslmode=disable")
	var live []*process
	var liveMu sync.Mutex
	c.loadBalancer(func() []*process { liveMu.Lock(); defer liveMu.Unlock(); return live })
	a, b := c.spawn("a"), c.spawn("b")
	c.waitReady(a)
	c.waitReady(b)
	both := []*process{a, b}
	liveMu.Lock()
	live = both
	liveMu.Unlock()
	admin := newBrowser(t, "198.51.100.10")
	admin.signIn(a.url, b.url, firstPassword)
	admin.chooseFirstPassword(a.url, b.url)
	gone := newBrowser(t, "198.51.100.11")
	gone.signIn(b.url, "")
	if res := gone.do(a.url, "POST", "/api/auth/logout", nil, nil, ""); res.status/100 != 2 {
		t.Fatalf("sign-out: %v", res)
	}
	ready := func(p *process) bool {
		res, err := http.Get(p.url + "/readyz")
		if err != nil {
			return false
		}
		_ = res.Body.Close()
		return res.StatusCode == 200
	}

	// The primary dies. Neither server may say it is ready, and neither may exit.
	docker("kill", primary)
	for _, p := range both {
		t.Logf("%s not ready %v after the primary died", p.name, until(p.name+" stops being ready", 30*time.Second, func() bool { return !ready(p) }))
	}
	if res := newBrowser(t, "198.51.100.12").do(a.url, "POST", "/api/auth/login", map[string]string{"username": "admin", "password": processPassword}, nil, ""); res.status/100 == 2 {
		t.Fatalf("a sign-in succeeded with no database: %v", res)
	}

	// The standby is promoted. Both servers find it without a restart.
	docker("exec", "-u", "postgres", standby, "sh", "-c", `pg_ctl promote -w -D "$PGDATA"`)
	until("the standby accepts connections", time.Minute, accepts(standby))
	for _, p := range both {
		t.Logf("%s ready %v after the promotion", p.name, until(p.name+" is ready again", 60*time.Second, func() bool { return ready(p) }))
		select {
		case <-p.exited:
			t.Fatalf("%s exited during the failover:\n%s", p.name, p.log(t))
		default:
		}
	}
	// What was committed before is there: the session, and the sign-out. New writes land.
	for _, p := range both {
		if me := admin.get(p.url, "/api/auth/me"); me.status != 200 {
			t.Fatalf("%s lost the administrator's session in the failover: %v", p.name, me)
		}
		if me := gone.get(p.url, "/api/auth/me"); me.status != 401 {
			t.Fatalf("%s honours a session that was signed out before the failover: %v", p.name, me)
		}
	}
	client := map[string]any{"clientName": "After the failover", "clientType": "public", "redirectUris": []string{"https://app.example/cb"}}
	if res := admin.do(b.url, "POST", "/api/admin/clients", client, admin.stepUp(a.url, "POST", "/api/admin/clients"), ""); res.status/100 != 2 {
		t.Fatalf("a write after the failover: %v", res)
	}
	newBrowser(t, "198.51.100.13").signIn(c.issuer, "")
	if sql(standby, "SELECT pg_is_in_recovery()") != "f" {
		t.Fatal("the servers are being served by a standby")
	}

	for _, p := range both {
		if code := p.stop(t, syscall.SIGTERM); code != 0 {
			t.Fatalf("%s exited %d on SIGTERM", p.name, code)
		}
	}
	c.checkLogs()
}

// A server that cannot reach its database says so and stops, without repeating the
// password it was given.
func TestServerProcessDoesNotLogTheDatabasePassword(t *testing.T) {
	c := newCluster(t)
	c.issuer = "http://localhost:1"
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	password := hex.EncodeToString(raw)
	closed := "postgres://kyidentity:" + password + "@127.0.0.1:" + freePort(t) + "/kyidentity?sslmode=disable"
	if err := os.WriteFile(filepath.Join(c.secrets, "database-url"), []byte(closed), 0o600); err != nil {
		t.Fatal(err)
	}
	p := c.spawn("unreachable")
	select {
	case <-p.exited:
	case <-time.After(60 * time.Second):
		t.Fatal("a server with no database kept running")
	}
	out := p.log(t)
	if p.cmd.ProcessState.ExitCode() == 0 || !strings.Contains(out, "database") {
		t.Fatalf("exit %d:\n%s", p.cmd.ProcessState.ExitCode(), out)
	}
	if strings.Contains(out, password) {
		t.Fatalf("the database password is in the log:\n%s", strings.ReplaceAll(out, password, "<password>"))
	}
}
