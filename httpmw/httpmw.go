// Package httpmw records an app's state-changing requests as chain events.
//
// It is plain net/http middleware, func(http.Handler) http.Handler, so it
// works with net/http's ServeMux, chi, Echo and Gin's adapters, and Forge.
//
// The middleware reads who is calling, through your ActorFunc, and which
// route matched, after your handler has run. Mount it inside your
// authentication middleware, so the request it holds carries the signed-in
// user, and outside your router, so the router can set r.Pattern on that
// same request:
//
//	handler := auth(httpmw.New(httpmw.Options{Chain: c, Actor: actor})(mux))
//
// By default it records only staff: the people who run the system, not its
// customers. It records the route pattern, never the path's values, the
// query string or the body.
package httpmw

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/hallproof/witness/chain"
)

const (
	// recordTimeout bounds how long recording can add to a request.
	recordTimeout = 2 * time.Second
	// warnEvery limits warnings about a failing chain.
	warnEvery = time.Minute
	// unmatched is the route recorded when no pattern matched.
	unmatched = "unmatched"
)

// Actor is who made a request.
type Actor struct {
	ID        string
	TenantID  string
	SessionID string
	// Staff is true for the people who run the system, as opposed to its
	// customers. Only staff are recorded unless Options.AllActors is set.
	Staff bool
}

// ActorFunc says who made r, reading it from the app's own
// authentication. It returns false when nobody is signed in.
type ActorFunc func(r *http.Request) (Actor, bool)

// Options configures the middleware.
type Options struct {
	// Chain is where events go. Nil means chain.Unconfigured, which
	// records nothing.
	Chain chain.Chain
	// Actor says who is calling. Without one, nothing is recorded.
	Actor ActorFunc
	// AllActors records customers too. The default records staff only.
	AllActors bool
	// SkipMethods are the methods not recorded. The default is GET, HEAD
	// and OPTIONS.
	SkipMethods []string
	// Route names the route that served r. The default is r.Pattern, which
	// net/http's ServeMux sets.
	Route func(r *http.Request) string
	// RequestIDHeader holds the request's ID. The default is X-Request-ID.
	RequestIDHeader string
	// TrustForwarded takes the client's IP from the first X-Forwarded-For
	// entry. Set it only behind a proxy that sets that header.
	TrustForwarded bool
	// Logger is where failures are logged. Nil means slog.Default().
	Logger *slog.Logger
}

// New returns the middleware.
func New(o Options) func(http.Handler) http.Handler {
	if o.Chain == nil {
		o.Chain = chain.Unconfigured{}
	}
	if o.SkipMethods == nil {
		o.SkipMethods = []string{http.MethodGet, http.MethodHead, http.MethodOptions}
	}
	if o.Route == nil {
		o.Route = func(r *http.Request) string { return r.Pattern }
	}
	if o.RequestIDHeader == "" {
		o.RequestIDHeader = "X-Request-ID"
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	skip := make(map[string]bool, len(o.SkipMethods))
	for _, m := range o.SkipMethods {
		skip[strings.ToUpper(m)] = true
	}
	m := &middleware{o: o, skip: skip}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip[r.Method] || o.Actor == nil {
				next.ServeHTTP(w, r)
				return
			}
			rec := &recorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			m.record(r, rec.code())
		})
	}
}

type middleware struct {
	o    Options
	skip map[string]bool

	mu        sync.Mutex
	lastWarn  time.Time
	lastPanic time.Time
}

// record writes r to the chain. A panic in the ActorFunc, the Route func or
// the chain is logged and goes no further: the handler already ran, and the
// response must reach the client as the handler wrote it.
func (m *middleware) record(r *http.Request, status int) {
	defer func() {
		if p := recover(); p != nil {
			if m.allow(&m.lastPanic) {
				m.o.Logger.Error("witness: recording a request panicked", "panic", p, "stack", string(debug.Stack()))
			}
		}
	}()
	actor, ok := m.o.Actor(r)
	if !ok || (!actor.Staff && !m.o.AllActors) {
		return
	}
	action, resource := route(r.Method, m.o.Route(r))
	e := chain.Event{
		Time:      time.Now().UTC(),
		Action:    action,
		Resource:  resource,
		Category:  "http",
		Outcome:   outcome(status),
		Severity:  chain.SeverityInfo,
		UserID:    actor.ID,
		TenantID:  actor.TenantID,
		SessionID: actor.SessionID,
		RequestID: r.Header.Get(m.o.RequestIDHeader),
		IP:        m.clientIP(r),
		UserAgent: r.UserAgent(),
		Metadata:  map[string]any{"status": status},
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
	defer cancel()
	err := m.o.Chain.Record(ctx, e)
	if err == nil || errors.Is(err, chain.ErrNoChain) {
		return
	}
	if m.allow(&m.lastWarn) {
		m.o.Logger.Warn("witness: couldn't record a request", "action", action, "error", err)
	}
}

// allow reports whether a log line limited to once per warnEvery may go out
// now, and if so notes the time in last.
func (m *middleware) allow(last *time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if now.Sub(*last) < warnEvery {
		return false
	}
	*last = now
	return true
}

// route turns a pattern such as "POST /items/{id}" or "/items/{id}" into
// the action ("POST /items/{id}") and the resource ("/items/{id}").
func route(method, pattern string) (action, resource string) {
	if pattern == "" {
		return method + " " + unmatched, unmatched
	}
	resource = pattern
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		resource = pattern[i:]
	}
	if strings.HasPrefix(pattern, method+" ") {
		return pattern, resource
	}
	return method + " " + resource, resource
}

func outcome(status int) string {
	switch {
	case status < 400:
		return chain.OutcomeSuccess
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return chain.OutcomeDenied
	}
	return chain.OutcomeFailure
}

func (m *middleware) clientIP(r *http.Request) string {
	if m.o.TrustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recorder notes the status a handler wrote.
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the writer underneath, for
// Flush, Hijack and deadlines.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *recorder) code() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
