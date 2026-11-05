package collect

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/push"
)

type fakeSender struct {
	mu   sync.Mutex
	msgs []push.Message
}

func (f *fakeSender) Enqueue(msgs ...push.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, msgs...)
}

func (f *fakeSender) sent(kind push.Kind) []push.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []push.Message
	for _, m := range f.msgs {
		if m.Kind == kind {
			out = append(out, m)
		}
	}
	return out
}

type fakeChain struct {
	chain.Unconfigured
	mu    sync.Mutex
	reqs  []chain.ProofRequest
	prove func(chain.ProofRequest) (*push.EventProof, error)
}

func (f *fakeChain) Prove(_ context.Context, r chain.ProofRequest) (*push.EventProof, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
	return f.prove(r)
}

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

func newTestScheduler(c chain.Chain) (*Scheduler, *fakeSender, *logBuffer) {
	f := &fakeSender{}
	logs := &logBuffer{}
	if c == nil {
		c = chain.Unconfigured{}
	}
	s := NewScheduler(f, c, SchedulerOptions{
		Logger:         slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		HeartbeatEvery: 10 * time.Minute,
		Replica:        "web-1",
		SDK:            "witness-go/test",
	})
	return s, f, logs
}

func settingsFrom(v *map[string]any, mu *sync.Mutex) func(context.Context) (map[string]any, error) {
	return func(context.Context) (map[string]any, error) {
		mu.Lock()
		defer mu.Unlock()
		return *v, nil
	}
}

func eventually(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAddValidates(t *testing.T) {
	s, _, _ := newTestScheduler(nil)
	ok := func(context.Context) (map[string]any, error) { return nil, nil }
	if err := s.AddSnapshot(Snapshot{Key: "a", Title: "t", Collect: ok}); err != nil {
		t.Fatal(err)
	}
	if got := s.collectors["a"].every; got != DefaultEvery {
		t.Fatalf("Every 0 became %v, want %v", got, DefaultEvery)
	}
	bad := map[string]error{
		"invalid key":       s.AddSnapshot(Snapshot{Key: "A", Title: "t", Collect: ok}),
		"key used twice":    s.AddPopulation(Population{Key: "a", Title: "t", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }}),
		"blank title":       s.AddSnapshot(Snapshot{Key: "b", Title: " ", Collect: ok}),
		"nil Collect":       s.AddSnapshot(Snapshot{Key: "c", Title: "t"}),
		"nil pop Collect":   s.AddPopulation(Population{Key: "d", Title: "t"}),
		"empty stream":      s.AddEventProof(EventProof{Key: "e", Title: "t"}),
		"negative interval": s.AddSnapshot(Snapshot{Key: "f", Title: "t", Every: -time.Second, Collect: ok}),
	}
	for name, err := range bad {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	eventually(t, "Run to start", time.Second, func() bool { return s.isRunning() })
	if err := s.AddSnapshot(Snapshot{Key: "late", Title: "t", Collect: ok}); err == nil {
		t.Error("Add after Run accepted")
	}
	if err := s.Run(ctx); err == nil {
		t.Error("a second Run started")
	}
	cancel()
	<-done
}

func TestPushesOnlyChanges(t *testing.T) {
	s, f, _ := newTestScheduler(nil)
	var mu sync.Mutex
	settings := map[string]any{"mfa": "required"}
	if err := s.AddSnapshot(Snapshot{Key: "auth", Title: "Auth", Collect: settingsFrom(&settings, &mu)}); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	s.runOnce(ctx, "auth")
	if n := len(f.sent(push.KindConfigSnapshot)); n != 1 {
		t.Fatalf("first run pushed %d, want 1", n)
	}
	s.runOnce(ctx, "auth")
	if n := len(f.sent(push.KindConfigSnapshot)); n != 1 {
		t.Fatalf("unchanged state pushed again: %d", n)
	}
	mu.Lock()
	settings = map[string]any{"mfa": "optional"}
	mu.Unlock()
	s.runOnce(ctx, "auth")
	if n := len(f.sent(push.KindConfigSnapshot)); n != 2 {
		t.Fatalf("changed state: %d pushed, want 2", n)
	}
}

func TestCollectorErrorKeepsLastHash(t *testing.T) {
	s, f, logs := newTestScheduler(nil)
	fail := false
	var mu sync.Mutex
	if err := s.AddPopulation(Population{Key: "staff", Title: "Staff", Collect: func(context.Context) ([]map[string]any, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return nil, errors.New("db down: password=hunter2")
		}
		return []map[string]any{{"id": "u1"}}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	s.runOnce(t.Context(), "staff")
	good := s.collectors["staff"].lastHash
	mu.Lock()
	fail = true
	mu.Unlock()
	s.runOnce(t.Context(), "staff")
	s.runOnce(t.Context(), "staff")

	if n := len(f.sent(push.KindPopulation)); n != 1 {
		t.Fatalf("%d populations pushed, want 1", n)
	}
	s.sendHeartbeats()
	hbs := f.sent(push.KindHeartbeat)
	if len(hbs) != 1 {
		t.Fatalf("%d heartbeats, want 1", len(hbs))
	}
	hb, err := push.DecodeBody[push.Heartbeat](hbs[0])
	if err != nil {
		t.Fatal(err)
	}
	if hb.Healthy || hb.Hash != good || hb.LastSuccess.IsZero() {
		t.Fatalf("heartbeat %+v, want unhealthy with the last good hash and time", hb)
	}
	if strings.Contains(string(hbs[0].Body), "hunter2") {
		t.Fatal("the collector's error reached the heartbeat")
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Fatalf("%d warnings for two failures in a row, want 1:\n%s", n, logs)
	}
}

// Review Focus 4: a collector that panics.
func TestPanickingCollectorDoesNotStopOthers(t *testing.T) {
	f := &fakeSender{}
	logs := &logBuffer{}
	s := NewScheduler(f, chain.Unconfigured{}, SchedulerOptions{
		Logger:         slog.New(slog.NewTextHandler(logs, nil)),
		HeartbeatEvery: 20 * time.Millisecond,
	})
	if err := s.AddSnapshot(Snapshot{Key: "boom", Title: "t", Every: 20 * time.Millisecond, Collect: func(context.Context) (map[string]any, error) {
		panic("collector bug")
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSnapshot(Snapshot{Key: "fine", Title: "t", Every: 20 * time.Millisecond, Collect: func(context.Context) (map[string]any, error) {
		return map[string]any{"ok": true}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	eventually(t, "the healthy collector's evidence and an unhealthy heartbeat", 2*time.Second, func() bool {
		if len(f.sent(push.KindConfigSnapshot)) == 0 {
			return false
		}
		for _, m := range f.sent(push.KindHeartbeat) {
			hb, _ := push.DecodeBody[push.Heartbeat](m)
			if hb.Collector == "boom" && !hb.Healthy {
				return true
			}
		}
		return false
	})
	select {
	case err := <-done:
		t.Fatalf("Run ended early: %v", err)
	default:
	}
	cancel()
	<-done
	if !strings.Contains(logs.String(), "collector bug") {
		t.Fatal("the panic wasn't logged")
	}
}

// Review Focus 4: a collector that hangs.
func TestHungCollectorTimesOut(t *testing.T) {
	s, _, _ := newTestScheduler(nil)
	if err := s.AddSnapshot(Snapshot{Key: "slow", Title: "t", Every: 50 * time.Millisecond, Collect: func(ctx context.Context) (map[string]any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s.runOnce(t.Context(), "slow")
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("runOnce took %v", took)
	}
	if c := s.collectors["slow"]; c.healthy || c.failures != 1 {
		t.Fatalf("healthy %v failures %d, want a failure", c.healthy, c.failures)
	}
}

func TestHeartbeats(t *testing.T) {
	s, f, _ := newTestScheduler(nil)
	for _, k := range []string{"a", "b", "never"} {
		if err := s.AddSnapshot(Snapshot{Key: k, Title: "t", Collect: func(context.Context) (map[string]any, error) {
			return map[string]any{"k": k}, nil
		}}); err != nil {
			t.Fatal(err)
		}
	}
	s.runOnce(t.Context(), "a")
	s.runOnce(t.Context(), "b")
	s.sendHeartbeats()

	got := map[string]push.Heartbeat{}
	for _, m := range f.sent(push.KindHeartbeat) {
		hb, err := push.DecodeBody[push.Heartbeat](m)
		if err != nil {
			t.Fatal(err)
		}
		got[hb.Collector] = hb
	}
	if len(got) != 2 {
		t.Fatalf("heartbeats for %v, want a and b", got)
	}
	for _, k := range []string{"a", "b"} {
		hb := got[k]
		if !hb.Healthy || hb.Hash == "" || hb.EverySeconds != 600 || hb.Replica != "web-1" ||
			hb.SDK != "witness-go/test" || hb.Evidence != push.KindConfigSnapshot {
			t.Errorf("%s: %+v", k, hb)
		}
	}
}

func TestEventProofAdvances(t *testing.T) {
	var answers []func() (*push.EventProof, error)
	fc := &fakeChain{}
	fc.prove = func(chain.ProofRequest) (*push.EventProof, error) {
		next := answers[0]
		answers = answers[1:]
		return next()
	}
	answers = []func() (*push.EventProof, error){
		func() (*push.EventProof, error) {
			return &push.EventProof{Cited: []uint64{3}, Checkpoint: push.Checkpoint{ID: "c1", ToHash: "h3"}}, nil
		},
		func() (*push.EventProof, error) { return &push.EventProof{Checkpoint: push.Checkpoint{ID: "c2"}}, nil },
		func() (*push.EventProof, error) { return nil, chain.ErrNothingNew },
		func() (*push.EventProof, error) { return nil, chain.ErrNoChain },
	}
	s, f, logs := newTestScheduler(fc)
	if err := s.AddEventProof(EventProof{Key: "logins", Title: "Logins", Stream: "platform", Actions: []string{"login"}}); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		s.runOnce(t.Context(), "logins")
	}
	if n := len(f.sent(push.KindEventProof)); n != 1 {
		t.Fatalf("%d proofs pushed, want 1", n)
	}
	froms := make([]string, len(fc.reqs))
	for i, r := range fc.reqs {
		froms[i] = r.From
		if r.Stream != "platform" || len(r.Actions) != 1 {
			t.Errorf("request %+v", r)
		}
	}
	if got := strings.Join(froms, ","); got != ",c1,c2,c2" {
		t.Fatalf("From went %q, want \",c1,c2,c2\"", got)
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("warned:\n%s", logs)
	}
}

func TestDelays(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2)) // #nosec G404 -- test jitter
	for range 1000 {
		if d := nextDelay(time.Minute, 0.1, r); d < 54*time.Second || d > 66*time.Second {
			t.Fatalf("nextDelay %v outside [54s, 66s]", d)
		}
		if d := firstDelay(time.Hour, r); d < 0 || d >= 30*time.Second {
			t.Fatalf("firstDelay %v outside [0, 30s)", d)
		}
		if d := firstDelay(time.Second, r); d >= time.Second {
			t.Fatalf("firstDelay %v for a 1s collector", d)
		}
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	s, _, _ := newTestScheduler(nil)
	if err := s.AddSnapshot(Snapshot{Key: "a", Title: "t", Every: time.Hour, Collect: func(context.Context) (map[string]any, error) {
		return nil, nil
	}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run didn't return within 1s of its context ending")
	}
}
