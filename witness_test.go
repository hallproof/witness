package witness_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/client"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/httpmw"
	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func stopWithin(t *testing.T, w *witness.Witness, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return w.Stop(ctx)
}

func settings(context.Context) (map[string]any, error) {
	return map[string]any{"mfa": "required"}, nil
}

func staff(context.Context) ([]map[string]any, error) {
	return []map[string]any{{"id": "u1", "role": "admin"}}, nil
}

func TestNewPassesClientErrors(t *testing.T) {
	if _, err := witness.New(witness.Options{Endpoint: "http://hallproof.example.com", IngestKey: "hpk_x"}); err == nil {
		t.Fatal("a plain-http remote endpoint was accepted")
	}
	if _, err := witness.New(witness.Options{Endpoint: "https://hallproof.example.com"}); err == nil {
		t.Fatal("a missing ingest key was accepted")
	}
}

func TestEndToEnd(t *testing.T) {
	s := ingesttest.New(t)
	s.Know(push.KindHeartbeat)
	w, err := witness.New(witness.Options{
		Endpoint: s.URL, IngestKey: s.Key, Logger: quiet, HeartbeatEvery: 50 * time.Millisecond,
		ClientOptions: []client.Option{client.WithBackoff(time.Millisecond, 10*time.Millisecond)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Snapshot(collect.Snapshot{Key: "auth-settings", Title: "Auth settings", Tests: []string{"mfa-enforced"}, Every: 50 * time.Millisecond, Collect: settings}); err != nil {
		t.Fatal(err)
	}
	if err := w.Population(collect.Population{Key: "staff-users", Title: "Staff", Source: "staff-users", Every: 50 * time.Millisecond, Collect: staff}); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(t.Context()); err != nil {
		t.Fatal(err)
	}

	eventually(t, "a snapshot, a population and a heartbeat", func() bool {
		kinds := map[push.Kind]bool{}
		for _, m := range s.Stored() {
			kinds[m.Kind] = true
		}
		return kinds[push.KindConfigSnapshot] && kinds[push.KindPopulation] && heartbeat(s) != nil
	})
	hb := heartbeat(s)
	if hb.SDK != "witness-go/"+witness.Version || hb.Replica == "" {
		t.Fatalf("heartbeat %+v", hb)
	}
	if ua := s.Requests()[0].Header.Get("User-Agent"); ua != "witness-go/"+witness.Version {
		t.Fatalf("User-Agent %q", ua)
	}
	if err := stopWithin(t, w, 2*time.Second); err != nil {
		t.Fatal(err)
	}
}

// heartbeat returns the first heartbeat the server was sent, or nil.
func heartbeat(s *ingesttest.Server) *push.Heartbeat {
	for _, r := range s.Requests() {
		for _, m := range r.Batch.Messages {
			if m.Kind == push.KindHeartbeat {
				hb, err := push.DecodeBody[push.Heartbeat](m)
				if err == nil {
					return &hb
				}
			}
		}
	}
	return nil
}

// Review Focus 5, through the whole stack.
func TestHallproofDownDoesNotBlock(t *testing.T) {
	s := ingesttest.New(t)
	s.FailNext(1_000_000, http.StatusServiceUnavailable)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Snapshot(collect.Snapshot{Key: "a", Title: "t", Every: 20 * time.Millisecond, Collect: settings}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err = w.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Fatalf("Start took %v", took)
	}
	eventually(t, "a queued message", func() bool { return w.Client().Stats().Queued > 0 })

	start = time.Now()
	err = stopWithin(t, w, 200*time.Millisecond)
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("Stop took %v", took)
	}
	if err == nil || !strings.Contains(err.Error(), "still queued") {
		t.Fatalf("err %v, want one that counts the messages left queued", err)
	}
}

func TestChainOffIsLoggedOnce(t *testing.T) {
	s := ingesttest.New(t)
	logs := &logBuffer{}
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := stopWithin(t, w, time.Second); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs.String(), "event recording is off"); n != 1 {
		t.Fatalf("%d lines say event recording is off, want 1:\n%s", n, logs)
	}
}

func TestLifecycleErrors(t *testing.T) {
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if err := stopWithin(t, w, time.Second); err != nil {
		t.Fatalf("Stop without Start: %v", err)
	}
	if err := w.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := w.Start(t.Context()); err == nil {
		t.Error("a second Start was accepted")
	}
	if err := w.Snapshot(collect.Snapshot{Key: "late", Title: "t", Collect: settings}); err == nil {
		t.Error("Snapshot after Start was accepted")
	}
	if err := stopWithin(t, w, time.Second); err != nil {
		t.Fatal(err)
	}
}

type countingChain struct {
	chain.Unconfigured
	mu sync.Mutex
	n  int
}

func (c *countingChain) Record(context.Context, chain.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return nil
}

func TestMiddlewareUsesWitnessChain(t *testing.T) {
	s := ingesttest.New(t)
	c := &countingChain{}
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key, Logger: quiet, Chain: c})
	if err != nil {
		t.Fatal(err)
	}
	h := w.Middleware(httpmw.Options{Actor: func(*http.Request) (httpmw.Actor, bool) {
		return httpmw.Actor{ID: "usr_1", Staff: true}, true
	}})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/x", nil))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n != 1 {
		t.Fatalf("%d events reached witness's chain, want 1", c.n)
	}
}
