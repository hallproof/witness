package httpmw_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/httpmw"
)

type recordingChain struct {
	chain.Unconfigured
	mu     sync.Mutex
	events []chain.Event
	err    error
}

func (c *recordingChain) Record(_ context.Context, e chain.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.events = append(c.events, e)
	return nil
}

func (c *recordingChain) got() []chain.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]chain.Event(nil), c.events...)
}

// actorFromHeaders reads the caller from test headers.
func actorFromHeaders(r *http.Request) (httpmw.Actor, bool) {
	id := r.Header.Get("X-Actor")
	if id == "" {
		return httpmw.Actor{}, false
	}
	return httpmw.Actor{ID: id, TenantID: "ten_1", SessionID: "ses_1", Staff: r.Header.Get("X-Staff") == "yes"}, true
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /items/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "made")
	})
	mux.HandleFunc("GET /items/{id}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "item")
	})
	mux.HandleFunc("POST /status/{code}", func(w http.ResponseWriter, r *http.Request) {
		code, _ := strconv.Atoi(r.PathValue("code"))
		if code != 0 {
			w.WriteHeader(code)
		}
	})
	mux.HandleFunc("POST /flush", func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	return mux
}

func serve(t *testing.T, o httpmw.Options, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	httpmw.New(o)(newMux()).ServeHTTP(rec, req)
	return rec
}

func staffPost(path, body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("X-Actor", "usr_1")
	r.Header.Set("X-Staff", "yes")
	r.Header.Set("X-Request-ID", "req_1")
	r.RemoteAddr = "203.0.113.7:51234"
	return r
}

func TestRecordsStaffWrite(t *testing.T) {
	c := &recordingChain{}
	rec := serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, staffPost("/items/7", ""))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d", rec.Code)
	}
	evs := c.got()
	if len(evs) != 1 {
		t.Fatalf("%d events, want 1", len(evs))
	}
	e := evs[0]
	want := chain.Event{
		Action: "POST /items/{id}", Resource: "/items/{id}", Category: "http",
		Outcome: chain.OutcomeSuccess, Severity: chain.SeverityInfo,
		UserID: "usr_1", TenantID: "ten_1", SessionID: "ses_1", RequestID: "req_1", IP: "203.0.113.7",
	}
	if e.Action != want.Action || e.Resource != want.Resource || e.Category != want.Category ||
		e.Outcome != want.Outcome || e.Severity != want.Severity || e.UserID != want.UserID ||
		e.TenantID != want.TenantID || e.SessionID != want.SessionID || e.RequestID != want.RequestID || e.IP != want.IP {
		t.Fatalf("event\n got %+v\nwant %+v", e, want)
	}
	if evs[0].Time.IsZero() {
		t.Fatal("event has no time")
	}
}

func TestSkipsSafeMethods(t *testing.T) {
	c := &recordingChain{}
	r := staffPost("/items/7", "")
	r.Method = http.MethodGet
	serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, r)
	if n := len(c.got()); n != 0 {
		t.Fatalf("%d events for a GET", n)
	}
}

func TestSkipsNonStaffByDefault(t *testing.T) {
	c := &recordingChain{}
	r := staffPost("/items/7", "")
	r.Header.Set("X-Staff", "no")
	serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, r)
	if n := len(c.got()); n != 0 {
		t.Fatalf("%d events for a customer", n)
	}
}

func TestAllActorsWidensScope(t *testing.T) {
	c := &recordingChain{}
	r := staffPost("/items/7", "")
	r.Header.Set("X-Staff", "no")
	serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders, AllActors: true}, r)
	if n := len(c.got()); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
}

func TestSkipsAnonymous(t *testing.T) {
	c := &recordingChain{}
	r := staffPost("/items/7", "")
	r.Header.Del("X-Actor")
	serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders, AllActors: true}, r)
	if n := len(c.got()); n != 0 {
		t.Fatalf("%d events for nobody", n)
	}
	serve(t, httpmw.Options{Chain: c}, staffPost("/items/7", "")) // no ActorFunc at all
	if n := len(c.got()); n != 0 {
		t.Fatalf("%d events without an ActorFunc", n)
	}
}

func TestOutcomeFromStatus(t *testing.T) {
	cases := map[string]string{
		"201": chain.OutcomeSuccess,
		"401": chain.OutcomeDenied,
		"403": chain.OutcomeDenied,
		"404": chain.OutcomeFailure,
		"500": chain.OutcomeFailure,
		"0":   chain.OutcomeSuccess, // no WriteHeader: 200
	}
	for code, want := range cases {
		c := &recordingChain{}
		serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, staffPost("/status/"+code, ""))
		evs := c.got()
		if len(evs) != 1 || evs[0].Outcome != want {
			t.Errorf("status %s: %+v, want outcome %s", code, evs, want)
		}
	}
}

func TestNeverRecordsQueryOrBody(t *testing.T) {
	c := &recordingChain{}
	serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, staffPost("/items/7?token=s3cret", "password=hunter2"))
	evs := c.got()
	if len(evs) != 1 {
		t.Fatalf("%d events", len(evs))
	}
	raw, _ := json.Marshal(evs[0])
	for _, secret := range []string{"s3cret", "hunter2", "token"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("the event holds %q: %s", secret, raw)
		}
	}
}

func TestUnmatchedRoute(t *testing.T) {
	c := &recordingChain{}
	rec := serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, staffPost("/nowhere/at/all", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
	evs := c.got()
	if len(evs) != 1 || evs[0].Resource != "unmatched" || evs[0].Action != "POST unmatched" {
		t.Fatalf("%+v", evs)
	}
	if strings.Contains(evs[0].Resource+evs[0].Action, "nowhere") {
		t.Fatal("an unmatched path was recorded")
	}
}

func TestChainErrorsDoNotTouchTheResponse(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	c := &recordingChain{err: errors.New("disk full")}
	o := httpmw.Options{Chain: c, Actor: actorFromHeaders, Logger: log}
	for range 3 {
		rec := serve(t, o, staffPost("/items/7", ""))
		if rec.Code != http.StatusCreated || rec.Body.String() != "made" {
			t.Fatalf("response %d %q", rec.Code, rec.Body)
		}
	}
	logs.Reset()
	h := httpmw.New(o)(newMux())
	for range 3 {
		h.ServeHTTP(httptest.NewRecorder(), staffPost("/items/7", ""))
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("%d warnings for three failures, want 1:\n%s", n, logs.String())
	}

	logs.Reset()
	rec := serve(t, httpmw.Options{Chain: chain.Unconfigured{}, Actor: actorFromHeaders, Logger: log}, staffPost("/items/7", ""))
	if rec.Code != http.StatusCreated || logs.Len() != 0 {
		t.Fatalf("with no chain: status %d, logs %q", rec.Code, logs.String())
	}
}

func TestResponseControllerStillWorks(t *testing.T) {
	c := &recordingChain{}
	rec := serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, staffPost("/flush", ""))
	if rec.Code != http.StatusOK || !rec.Flushed {
		t.Fatalf("status %d flushed %v: %s", rec.Code, rec.Flushed, rec.Body)
	}
}

func TestForwardedOnlyWhenTrusted(t *testing.T) {
	r := func() *http.Request {
		req := staffPost("/items/7", "")
		req.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.1")
		return req
	}
	c := &recordingChain{}
	serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders}, r())
	serve(t, httpmw.Options{Chain: c, Actor: actorFromHeaders, TrustForwarded: true}, r())
	evs := c.got()
	if evs[0].IP != "203.0.113.7" || evs[1].IP != "198.51.100.9" {
		t.Fatalf("IPs %q and %q", evs[0].IP, evs[1].IP)
	}
}

type panickingChain struct{ chain.Unconfigured }

func (panickingChain) Record(context.Context, chain.Event) error { panic("chain bug") }

// Review, Important #4: a panic while recording never reaches the request.
func TestRecordingPanicsDoNotEscape(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	for name, o := range map[string]httpmw.Options{
		"chain": {Chain: panickingChain{}, Actor: actorFromHeaders, Logger: log},
		"actor": {Actor: func(*http.Request) (httpmw.Actor, bool) { panic("actor bug") }, Logger: log},
		"route": {Actor: actorFromHeaders, Route: func(*http.Request) string { panic("route bug") }, Logger: log},
	} {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("%s: the panic escaped: %v", name, p)
				}
			}()
			rec := serve(t, o, staffPost("/items/7", ""))
			if rec.Code != http.StatusCreated || rec.Body.String() != "made" {
				t.Errorf("%s: response %d %q", name, rec.Code, rec.Body)
			}
		}()
	}
	if n := strings.Count(logs.String(), "level=ERROR"); n != 3 {
		t.Fatalf("%d error lines, want one per panic:\n%s", n, logs.String())
	}
}

// The handler's own panics still propagate, so the server's recovery sees them.
func TestHandlerPanicsStillPropagate(t *testing.T) {
	h := httpmw.New(httpmw.Options{Actor: actorFromHeaders})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		p := recover()
		if err, ok := p.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", p)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), staffPost("/x", ""))
}
