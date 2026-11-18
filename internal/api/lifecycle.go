package api

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// requestDeadline bounds every ordinary request: store calls carry no context and the
// database driver has no client-side deadline, so without it a frozen database (a paused
// VM, a storage hang) holds requests open with no limit. It stays below the listener's
// 30 s WriteTimeout so the 503 still reaches the client. A 503 after it does not prove the
// request had no effect: the handler may still finish once the database answers.
var requestDeadline = 25 * time.Second

// longRoutes are the mux patterns the deadline does not cover, each with the budget its
// outbound calls keep instead. Nothing bounds their database calls, and the listener's
// WriteTimeout does not end a handler, so on a frozen database they wait with it.
// TestLongRoutesAreExactlyTheNamedExemptions pins this list.
var longRoutes = map[string]string{
	"POST /api/admin/backup/deposit":               "depositWriteBudget (16 min): snapshot, seal and upload a capsule",
	"POST /api/admin/backup/drill":                 "depositWriteBudget (16 min): snapshot, seal and open a capsule in a sandbox",
	"GET /api/admin/backup/export-capsule":         "depositWriteBudget (16 min): snapshot, seal and download a capsule",
	"POST /api/admin/backup/pair-remote":           "KyRecovery claim: 10 s dial plus a 30 s client timeout",
	"GET /api/admin/audit-events/export":           "auditExportTimeout (30 s), streamed; buffering it would hold the export in memory",
	"POST /api/admin/mail/test":                    "SMTP: 10 s dial plus a 30 s session deadline",
	"POST /api/admin/users/{id}/activation-link":   "SMTP when the link is mailed: 10 s dial plus a 30 s session deadline",
	"POST /api/admin/users/{id}/reset-link":        "SMTP when the link is mailed: 10 s dial plus a 30 s session deadline",
	"POST /api/admin/access-requests/{id}/approve": "SMTP notice to the requester: 10 s dial plus a 30 s session deadline",
	"POST /api/admin/access-requests/{id}/deny":    "SMTP notice to the requester: 10 s dial plus a 30 s session deadline",
}

// withDeadline answers 503 JSON when next has not answered within d. Like
// http.TimeoutHandler, the handler writes into a buffer that is sent when it returns in
// time and discarded otherwise; its context ends at d, so outbound calls stop.
func withDeadline(next http.Handler, mux *http.ServeMux, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); longRoutes[pattern] != "" {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		tw := &deadlineWriter{h: http.Header{}}
		done, panicked := make(chan struct{}), make(chan any, 1)
		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicked <- p
				}
			}()
			next.ServeHTTP(tw, r.WithContext(ctx))
			close(done)
		}()
		select {
		case p := <-panicked:
			panic(p)
		case <-done:
			tw.mu.Lock()
			defer tw.mu.Unlock()
			for k, v := range tw.h {
				w.Header()[k] = v
			}
			if !tw.wroteHeader {
				tw.code = http.StatusOK
			}
			w.WriteHeader(tw.code)
			_, _ = w.Write(tw.buf.Bytes())
		case <-ctx.Done():
			tw.mu.Lock()
			defer tw.mu.Unlock()
			tw.timedOut = true
			w.Header().Set("Cache-Control", "no-store")
			writeAPIError(w, http.StatusServiceUnavailable, "request_timeout",
				"The server could not finish this request in time. It may still take effect; check before retrying.")
		}
	})
}

type deadlineWriter struct {
	mu                    sync.Mutex
	h                     http.Header
	buf                   bytes.Buffer
	code                  int
	wroteHeader, timedOut bool
}

func (tw *deadlineWriter) Header() http.Header { return tw.h }

func (tw *deadlineWriter) Write(p []byte) (int, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.timedOut {
		return 0, http.ErrHandlerTimeout
	}
	if !tw.wroteHeader {
		tw.wroteHeader, tw.code = true, http.StatusOK
	}
	return tw.buf.Write(p)
}

func (tw *deadlineWriter) WriteHeader(code int) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if !tw.timedOut && !tw.wroteHeader {
		tw.wroteHeader, tw.code = true, code
	}
}

// backupWork tracks the deposit and drill requests in flight, so a stopping server can
// cancel them and wait for each to record its outcome and give back its lease.
type backupWork struct {
	ctx      context.Context // ends at the shutdown's cancel phase
	cancel   context.CancelFunc
	mu       sync.Mutex
	draining bool
	wg       sync.WaitGroup
}

func newBackupWork() *backupWork {
	ctx, cancel := context.WithCancel(context.Background())
	return &backupWork{ctx: ctx, cancel: cancel}
}

// start registers one run and returns its context: parent, also ended by the shutdown's
// cancel phase. ok is false once draining began; the caller answers 503.
func (b *backupWork) start(parent context.Context) (ctx context.Context, done func(), ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.draining {
		return nil, nil, false
	}
	b.wg.Add(1)
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(b.ctx, cancel)
	return ctx, func() { stop(); cancel(); b.wg.Done() }, true
}

// StartDraining turns /readyz to 503 and refuses new deposits and drills. Requests in
// flight carry on; the listener keeps serving until Shutdown.
func (s *Server) StartDraining() {
	s.draining.Store(true)
	s.work.mu.Lock()
	s.work.draining = true
	s.work.mu.Unlock()
}

// CancelBackups ends the context of every deposit and drill still running.
func (s *Server) CancelBackups() { s.work.cancel() }

// WaitBackups waits for every deposit and drill to return, or for done to end, and reports
// whether they all returned. Call it after StartDraining.
func (s *Server) WaitBackups(done context.Context) bool {
	finished := make(chan struct{})
	go func() { s.work.wg.Wait(); close(finished) }()
	select {
	case <-finished:
		return true
	case <-done.Done():
		return false
	}
}

// Serve serves on ln until Shutdown; Start listens on the configured address.
func (s *Server) Serve(ln net.Listener) error {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go s.middleware.sweepLimitersEvery(ctx, time.Minute)
	return s.httpServer.Serve(ln)
}
