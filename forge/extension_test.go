package forge_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xraph/forge"
	forgetesting "github.com/xraph/forge/testing"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/collect"
	witnessforge "github.com/hallproof/witness/forge"
	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

// engines stands in for the libraries an app runs: a fake adapter finds its
// library when the app's container holds an *engines naming it.
type engines struct{ names []string }

func (e *engines) has(name string) bool { return slices.Contains(e.names, name) }

// seq makes fake adapter names unique, since the registry has no reset and
// lives for the whole test binary.
var seq atomic.Int64

// fake registers an adapter named "f<n>-<what>" and returns its name. build
// builds its Attach from the name.
func fake(what string, isChain bool, build func(name string) func(context.Context, adapter.Host) (bool, error)) string {
	name := fmt.Sprintf("f%d-%s", seq.Add(1), what)
	adapter.Register(adapter.Adapter{
		Name:   name,
		Module: "example.com/" + name,
		After:  []string{name + "-ext"},
		Chain:  isChain,
		Attach: build(name),
	})
	return name
}

// findEngine is the lookup a real adapter does: the library is there when
// its engine is in the container.
func findEngine(h adapter.Host, name string) bool {
	c, ok := h.Container.(forge.Container)
	if !ok || !forge.HasType[*engines](c) {
		return false
	}
	en, err := forge.InjectType[*engines](c)
	return err == nil && en != nil && en.has(name)
}

// snapshotter finds its engine and registers a snapshot keyed by its name.
func snapshotter(every time.Duration, attached *[]string, mu *sync.Mutex) func(string) func(context.Context, adapter.Host) (bool, error) {
	return func(name string) func(context.Context, adapter.Host) (bool, error) {
		return func(_ context.Context, h adapter.Host) (bool, error) {
			if mu != nil {
				mu.Lock()
				*attached = append(*attached, name)
				mu.Unlock()
			}
			if !findEngine(h, name) {
				return false, nil
			}
			return true, h.Witness.Snapshot(collect.Snapshot{
				Key: name, Title: name, Every: every,
				Collect: func(context.Context) (map[string]any, error) { return map[string]any{"on": true}, nil },
			})
		}
	}
}

// logs collects what witness logs.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *logs) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// withLogs sends witness's logs to l.
func withLogs(l *logs) witnessforge.Option {
	return witnessforge.WithWitnessOptions(func(o *witness.Options) { o.Logger = l.logger() })
}

// start builds a test-mode Forge app with ext, puts the named engines in its
// container, starts it and stops it when the test ends.
func start(t *testing.T, ext forge.Extension, running []string, more ...forge.Extension) forge.App {
	t.Helper()
	return startWith(t, nil, ext, running, more...)
}

func startWith(t *testing.T, cm forge.ConfigManager, ext forge.Extension, running []string, more ...forge.Extension) forge.App {
	t.Helper()
	app := forgetesting.NewTestAppWithConfig(forge.AppConfig{
		Name:          "witness-test",
		Environment:   "test",
		ConfigManager: cm,
		Extensions:    append([]forge.Extension{ext}, more...),
	})
	if err := forge.ProvideValue(app.Container(), &engines{names: running}); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(t.Context()); err != nil {
		t.Fatalf("app.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = app.Stop(ctx)
	})
	return app
}

// on configures witness to push to s and to look only at libraries.
func on(s *ingesttest.Server, libraries ...string) witnessforge.Config {
	return witnessforge.Config{Endpoint: s.URL, IngestKey: s.Key, Libraries: libraries}
}

// waitFor polls cond for up to 5 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// key is the collector key a stored message came from.
func key(m push.Message) string { k, _, _ := strings.Cut(m.ID, ":"); return k }

func storedKeys(s *ingesttest.Server) []string {
	stored := s.Stored()
	out := make([]string, 0, len(stored))
	for _, m := range stored {
		out = append(out, key(m))
	}
	return out
}

func hasKey(s *ingesttest.Server, k string) func() bool {
	return func() bool { return slices.Contains(storedKeys(s), k) }
}

func TestOffWithoutEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  witnessforge.Config
	}{
		{"no endpoint", witnessforge.Config{IngestKey: "hpk_test"}},
		{"disabled", witnessforge.Config{Endpoint: "https://hallproof.example.com", IngestKey: "hpk_test", Disabled: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var l logs
			ext := witnessforge.New(witnessforge.WithConfig(tc.cfg), withLogs(&l))
			app := start(t, ext, nil)
			if ext.Witness() != nil {
				t.Fatal("Witness() is set while witness is off")
			}
			if forge.HasType[*witness.Witness](app.Container()) {
				t.Fatal("the container has a *witness.Witness while witness is off")
			}
			if n := strings.Count(l.String(), "level=INFO msg=\"witness: off"); n != 1 {
				t.Fatalf("want one Info line saying witness is off, got %d in:\n%s", n, l.String())
			}
		})
	}
}

func TestBadConfigFailsRegister(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  witnessforge.Config
	}{
		{"plain http to a remote host", witnessforge.Config{Endpoint: "http://hallproof.example.com", IngestKey: "hpk_test"}},
		{"no key", witnessforge.Config{Endpoint: "https://hallproof.example.com"}},
		{"key and key file", witnessforge.Config{Endpoint: "https://hallproof.example.com", IngestKey: "hpk_test", IngestKeyFile: "/nonexistent"}},
		{"missing key file", witnessforge.Config{Endpoint: "https://hallproof.example.com", IngestKeyFile: filepath.Join(t.TempDir(), "missing")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := forgetesting.NewTestAppWithConfig(forge.AppConfig{
				Name:       "witness-test",
				Extensions: []forge.Extension{witnessforge.New(witnessforge.WithConfig(tc.cfg))},
			})
			if err := app.Start(t.Context()); err == nil {
				_ = app.Stop(context.Background())
				t.Fatal("app.Start succeeded with a bad witness config")
			}
		})
	}
}

func TestDiscoversAndSkips(t *testing.T) {
	s := ingesttest.New(t)
	var (
		mu       sync.Mutex
		attached []string
		hosts    = map[string]adapter.Host{}
	)
	found := fake("found", false, snapshotter(20*time.Millisecond, &attached, &mu))
	absent := fake("absent", false, snapshotter(20*time.Millisecond, &attached, &mu))
	recordHost := fake("host", false, func(name string) func(context.Context, adapter.Host) (bool, error) {
		return func(_ context.Context, h adapter.Host) (bool, error) {
			mu.Lock()
			hosts[name] = h
			mu.Unlock()
			return false, nil
		}
	})

	var l logs
	cfg := on(s, found, absent, recordHost)
	cfg.Scope = witnessforge.ScopeConfig{AppID: "app_platform", TenantID: "t_platform"}
	cfg.Adapters = map[string]map[string]any{recordHost: {"apps": []any{"a"}}}
	ext := witnessforge.New(witnessforge.WithConfig(cfg), withLogs(&l))
	app := start(t, ext, []string{found})

	waitFor(t, "the found adapter's snapshot", hasKey(s, found))
	if slices.Contains(storedKeys(s), absent) {
		t.Fatal("an adapter whose library isn't running pushed evidence")
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Contains(attached, found) || !slices.Contains(attached, absent) {
		t.Fatalf("attached %v, want both %s and %s tried", attached, found, absent)
	}
	h := hosts[recordHost]
	if h.Witness == nil || h.Witness != ext.Witness() {
		t.Fatal("Host.Witness isn't the extension's witness")
	}
	if c, ok := h.Container.(forge.Container); !ok || c != app.Container() {
		t.Fatal("Host.Container isn't the app's container")
	}
	if h.Scope.AppID != "app_platform" || h.Scope.TenantID != "t_platform" || h.Scope.AllTenants {
		t.Fatalf("Host.Scope = %+v", h.Scope)
	}
	if apps, _ := h.Config["apps"].([]any); len(apps) != 1 || apps[0] != "a" {
		t.Fatalf("Host.Config = %v, want the adapter's own section", h.Config)
	}
	if h.Logger == nil || h.SetChain == nil {
		t.Fatal("Host.Logger or Host.SetChain is nil")
	}
	out := l.String()
	if !strings.Contains(out, "adapter="+found) || !strings.Contains(out, "adapter="+absent) {
		t.Fatalf("logs don't name both adapters:\n%s", out)
	}
}

func TestAttachErrorSkipsOnlyThatLibrary(t *testing.T) {
	s := ingesttest.New(t)
	broken := fake("broken", false, func(string) func(context.Context, adapter.Host) (bool, error) {
		return func(context.Context, adapter.Host) (bool, error) { return true, errors.New("the engine is closed") }
	})
	panics := fake("panics", false, func(string) func(context.Context, adapter.Host) (bool, error) {
		return func(context.Context, adapter.Host) (bool, error) { panic("adapter bug") }
	})
	healthy := fake("healthy", false, snapshotter(20*time.Millisecond, nil, nil))

	var l logs
	ext := witnessforge.New(witnessforge.WithConfig(on(s, broken, panics, healthy)), withLogs(&l))
	start(t, ext, []string{healthy})

	waitFor(t, "the healthy adapter's snapshot", hasKey(s, healthy))
	out := l.String()
	if !strings.Contains(out, "the engine is closed") || !strings.Contains(out, "adapter bug") {
		t.Fatalf("the Attach failures aren't logged:\n%s", out)
	}
}

// recorder is a chain that remembers what it recorded.
type recorder struct {
	mu     sync.Mutex
	events []chain.Event
}

func (r *recorder) Record(_ context.Context, e chain.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (*recorder) Prove(context.Context, chain.ProofRequest) (*push.EventProof, error) {
	return nil, chain.ErrNothingNew
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func TestChainAdapterFirst(t *testing.T) {
	s := ingesttest.New(t)
	var (
		mu      sync.Mutex
		order   []string
		setLate func(chain.Chain)
	)
	first, late := &recorder{}, &recorder{}
	note := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}
	// The chain adapter sorts last by name, so only its Chain flag puts it
	// first.
	plain := fake("a-plain", false, func(name string) func(context.Context, adapter.Host) (bool, error) {
		return func(_ context.Context, h adapter.Host) (bool, error) {
			note(name)
			// Recording works during Attach once the chain adapter bound
			// the chain.
			return true, h.Witness.Chain().Record(t.Context(), chain.Event{Action: "attach"})
		}
	})
	chainer := fake("z-chain", true, func(name string) func(context.Context, adapter.Host) (bool, error) {
		return func(_ context.Context, h adapter.Host) (bool, error) {
			note(name)
			h.SetChain(first)
			mu.Lock()
			setLate = h.SetChain
			mu.Unlock()
			return true, nil
		}
	})

	var l logs
	ext := witnessforge.New(witnessforge.WithConfig(on(s, plain, chainer)), withLogs(&l), witnessforge.WithCoverageEvery(20*time.Millisecond))
	start(t, ext, nil)
	waitFor(t, "the coverage snapshot", hasKey(s, "witness.coverage"))

	mu.Lock()
	if len(order) != 2 || order[0] != chainer || order[1] != plain {
		t.Fatalf("attach order %v, want the chain adapter first", order)
	}
	set := setLate
	mu.Unlock()
	if first.count() != 1 {
		t.Fatalf("the bound chain recorded %d events, want 1", first.count())
	}

	set(late)
	if err := ext.Witness().Chain().Record(t.Context(), chain.Event{Action: "after"}); err != nil {
		t.Fatal(err)
	}
	if first.count() != 2 || late.count() != 0 {
		t.Fatalf("SetChain after Start took effect: first %d, late %d", first.count(), late.count())
	}
	if !strings.Contains(l.String(), "SetChain") {
		t.Fatalf("the ignored SetChain isn't logged:\n%s", l.String())
	}
}

func TestWithChainWins(t *testing.T) {
	s := ingesttest.New(t)
	given, offered := &recorder{}, &recorder{}
	chainer := fake("chain", true, func(string) func(context.Context, adapter.Host) (bool, error) {
		return func(_ context.Context, h adapter.Host) (bool, error) {
			h.SetChain(offered)
			return true, nil
		}
	})
	ext := witnessforge.New(witnessforge.WithConfig(on(s, chainer)), witnessforge.WithChain(given))
	start(t, ext, nil)
	if err := ext.Witness().Chain().Record(t.Context(), chain.Event{Action: "x"}); err != nil {
		t.Fatal(err)
	}
	if given.count() != 1 || offered.count() != 0 {
		t.Fatalf("given %d, offered %d: WithChain should win over discovery", given.count(), offered.count())
	}
}

func TestNoChainRecordsNothing(t *testing.T) {
	s := ingesttest.New(t)
	ext := witnessforge.New(witnessforge.WithConfig(on(s, "none-such")))
	start(t, ext, nil)
	err := ext.Witness().Chain().Record(t.Context(), chain.Event{Action: "x"})
	if !errors.Is(err, chain.ErrNoChain) {
		t.Fatalf("Record = %v, want ErrNoChain", err)
	}
	if _, err := ext.Witness().Chain().Prove(t.Context(), chain.ProofRequest{Stream: "s"}); !errors.Is(err, chain.ErrNoChain) {
		t.Fatalf("Prove = %v, want ErrNoChain", err)
	}
}

func TestLibrariesAndExclude(t *testing.T) {
	s := ingesttest.New(t)
	var (
		mu       sync.Mutex
		attached []string
	)
	a := fake("lib-a", false, snapshotter(time.Hour, &attached, &mu))
	b := fake("lib-b", false, snapshotter(time.Hour, &attached, &mu))
	c := fake("lib-c", false, snapshotter(time.Hour, &attached, &mu))

	var l logs
	cfg := on(s, a, b)
	cfg.Exclude = []string{b}
	ext := witnessforge.New(witnessforge.WithConfig(cfg), withLogs(&l))
	start(t, ext, []string{a, b, c})

	mu.Lock()
	defer mu.Unlock()
	if len(attached) != 1 || attached[0] != a {
		t.Fatalf("attached %v, want only %s", attached, a)
	}
	out := l.String()
	if !strings.Contains(out, "adapter="+b) || !strings.Contains(out, "adapter="+c) {
		t.Fatalf("the skipped adapters aren't logged:\n%s", out)
	}
}

// coverageAdapter is one adapter's entry in the coverage snapshot.
type coverageAdapter struct {
	Name      string   `json:"name"`
	Module    string   `json:"module"`
	Found     bool     `json:"found"`
	Error     *bool    `json:"error"`
	Widened   *bool    `json:"widened"`
	WidenedBy []string `json:"widened_by"`
}

// coverage is the witness.coverage snapshot's settings.
type coverage struct {
	Scope      string            `json:"scope"`
	AnyWidened *bool             `json:"any_widened"`
	Adapters   []coverageAdapter `json:"adapters"`
}

func coverageOf(t *testing.T, s *ingesttest.Server) (coverage, push.ConfigSnapshot, push.Message) {
	t.Helper()
	waitFor(t, "the coverage snapshot", hasKey(s, "witness.coverage"))
	for _, m := range s.Stored() {
		if key(m) != "witness.coverage" {
			continue
		}
		body, err := push.DecodeBody[push.ConfigSnapshot](m)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(body.Settings)
		if err != nil {
			t.Fatal(err)
		}
		var cov coverage
		if err := json.Unmarshal(raw, &cov); err != nil {
			t.Fatal(err)
		}
		return cov, body, m
	}
	t.Fatal("no coverage snapshot")
	return coverage{}, push.ConfigSnapshot{}, push.Message{}
}

func TestCoverageSnapshot(t *testing.T) {
	const canary = "CANARY-attach-error-text"
	s := ingesttest.New(t)
	found := fake("cov-found", false, snapshotter(time.Hour, nil, nil))
	absent := fake("cov-absent", false, snapshotter(time.Hour, nil, nil))
	broken := fake("cov-broken", false, func(string) func(context.Context, adapter.Host) (bool, error) {
		return func(context.Context, adapter.Host) (bool, error) { return false, errors.New(canary) }
	})
	excluded := fake("cov-excluded", false, snapshotter(time.Hour, nil, nil))

	cfg := on(s, found, absent, broken, excluded)
	cfg.Exclude = []string{excluded}
	ext := witnessforge.New(witnessforge.WithConfig(cfg), witnessforge.WithCoverageEvery(20*time.Millisecond))
	start(t, ext, []string{found, excluded})

	cov, body, m := coverageOf(t, s)
	if body.Title != "Witness coverage" || len(body.Tests) != 0 {
		t.Fatalf("title %q, tests %v", body.Title, body.Tests)
	}
	if strings.Contains(string(m.Body), canary) {
		t.Fatal("the coverage snapshot carries an Attach error's text")
	}
	if cov.Scope != "staff" {
		t.Fatalf("scope %q, want staff", cov.Scope)
	}
	if cov.AnyWidened != nil {
		t.Fatalf("any_widened is %v; no adapter widened, so it should be left out", *cov.AnyWidened)
	}
	want := map[string]struct{ found, err bool }{
		found: {true, false}, absent: {false, false}, broken: {false, true}, excluded: {false, false},
	}
	// Every registered adapter is listed, including other tests' fakes
	// that this app's Libraries leave out, in name order.
	if len(cov.Adapters) != len(adapter.Adapters()) {
		t.Fatalf("coverage lists %d adapters, the registry has %d", len(cov.Adapters), len(adapter.Adapters()))
	}
	if !slices.IsSortedFunc(cov.Adapters, func(a, b coverageAdapter) int {
		return strings.Compare(a.Name, b.Name)
	}) {
		t.Fatal("coverage adapters aren't sorted by name")
	}
	seen := 0
	for _, a := range cov.Adapters {
		w, ok := want[a.Name]
		if !ok {
			continue
		}
		seen++
		if a.Module != "example.com/"+a.Name || a.Found != w.found {
			t.Fatalf("%s: module %q found %v, want found %v", a.Name, a.Module, a.Found, w.found)
		}
		if w.err != (a.Error != nil && *a.Error) {
			t.Fatalf("%s: error %v, want %v", a.Name, a.Error, w.err)
		}
		if a.Error != nil && !*a.Error {
			t.Fatalf("%s: error is false; it should be left out", a.Name)
		}
		if a.Widened != nil || a.WidenedBy != nil {
			t.Fatalf("%s: widened %v by %v; it didn't widen", a.Name, a.Widened, a.WidenedBy)
		}
	}
	if seen != len(want) {
		t.Fatalf("coverage lists %d of this test's %d adapters", seen, len(want))
	}
}

func TestCoverageAllTenants(t *testing.T) {
	s := ingesttest.New(t)
	cfg := on(s, "none-such")
	cfg.Scope.AllTenants = true
	ext := witnessforge.New(witnessforge.WithConfig(cfg), witnessforge.WithCoverageEvery(20*time.Millisecond))
	start(t, ext, nil)
	if cov, _, _ := coverageOf(t, s); cov.Scope != "all_tenants" {
		t.Fatalf("scope %q, want all_tenants", cov.Scope)
	}
}

// An adapter whose own config takes it beyond staff says so through
// Host.Widened, and the coverage snapshot shows it on that adapter and at
// the top, while the scope itself stays staff.
func TestCoverageWidened(t *testing.T) {
	s := ingesttest.New(t)
	var late adapter.Host
	widens := fake("cov-widens", false, func(name string) func(context.Context, adapter.Host) (bool, error) {
		return func(ctx context.Context, h adapter.Host) (bool, error) {
			h.Widened("all_platform_users")
			h.Widened("exclude_tenants")
			h.Widened("all_platform_users")
			late = h
			return snapshotter(time.Hour, nil, nil)(name)(ctx, h)
		}
	})
	plain := fake("cov-plain", false, snapshotter(time.Hour, nil, nil))
	ext := witnessforge.New(witnessforge.WithConfig(on(s, widens, plain)), witnessforge.WithCoverageEvery(20*time.Millisecond))
	start(t, ext, []string{widens, plain})

	cov, _, _ := coverageOf(t, s)
	if cov.Scope != "staff" {
		t.Fatalf("scope %q, want staff", cov.Scope)
	}
	if cov.AnyWidened == nil || !*cov.AnyWidened {
		t.Fatalf("any_widened %v, want true", cov.AnyWidened)
	}
	// A Widen after Attach returned is too late to report, and must not
	// change the snapshot under the scheduler.
	late.Widened("too_late")
	for _, a := range cov.Adapters {
		switch a.Name {
		case widens:
			if a.Widened == nil || !*a.Widened || !slices.Equal(a.WidenedBy, []string{"all_platform_users", "exclude_tenants"}) {
				t.Fatalf("%s: widened %v by %v", a.Name, a.Widened, a.WidenedBy)
			}
		case plain:
			if a.Widened != nil || a.WidenedBy != nil {
				t.Fatalf("%s: widened %v by %v; it didn't widen", a.Name, a.Widened, a.WidenedBy)
			}
		}
	}
	// Give the coverage snapshot, every 20ms, a few more runs.
	time.Sleep(150 * time.Millisecond)
	for _, m := range s.Stored() {
		if key(m) == witnessforge.CoverageKey && strings.Contains(string(m.Body), "too_late") {
			t.Fatal("a Widen after Attach returned reached the coverage snapshot")
		}
	}
}

// consumer is an app extension that adds its own collector to witness while
// it registers.
type consumer struct {
	*forge.BaseExtension
	ext *witnessforge.Extension
	got *witness.Witness
}

func (c *consumer) Register(app forge.App) error {
	if err := c.BaseExtension.Register(app); err != nil {
		return err
	}
	w := c.ext.Witness()
	if w == nil {
		return errors.New("witness isn't built yet")
	}
	c.got = w
	return w.Snapshot(collect.Snapshot{
		Key: "app.own", Title: "App's own", Every: 20 * time.Millisecond,
		Collect: func(context.Context) (map[string]any, error) { return map[string]any{"x": 1}, nil },
	})
}

func TestProvidesWitness(t *testing.T) {
	s := ingesttest.New(t)
	found := fake("provided", false, snapshotter(20*time.Millisecond, nil, nil))
	ext := witnessforge.New(witnessforge.WithConfig(on(s, found)), witnessforge.WithCoverageEvery(20*time.Millisecond))
	c := &consumer{BaseExtension: forge.NewBaseExtension("consumer", "1.0.0", "uses witness"), ext: ext}
	c.SetDependencies([]string{witnessforge.Name})
	app := start(t, ext, []string{found}, c)

	w, err := forge.InjectType[*witness.Witness](app.Container())
	if err != nil {
		t.Fatal(err)
	}
	if w == nil || w != ext.Witness() || c.got != w {
		t.Fatal("the container's witness isn't the extension's")
	}
	// The app's collector, the adapter's and the coverage snapshot all
	// arrive: nothing started witness before the adapters attached.
	for _, k := range []string{"app.own", found, witnessforge.CoverageKey} {
		waitFor(t, k, hasKey(s, k))
	}
}

func TestDependencies(t *testing.T) {
	name := fake("deps", false, snapshotter(time.Hour, nil, nil))
	ext := witnessforge.New(witnessforge.WithConfig(witnessforge.Config{After: []string{"loomplane-identity"}}))
	deps := ext.Dependencies()
	if !slices.Contains(deps, name+"-ext") || !slices.Contains(deps, "loomplane-identity") {
		t.Fatalf("Dependencies() = %v, want every adapter's After and Config.After", deps)
	}
	if ext.Name() != "witness" || witnessforge.Name != "witness" {
		t.Fatalf("Name() = %q", ext.Name())
	}
}

// probe is an extension that stops before witness's own Stop, since it
// depends on witness. It records whether the collector still ran while it
// was stopping.
type probe struct {
	*forge.BaseExtension
	runs        *atomic.Int64
	ranInStop   atomic.Bool
	stopVisited atomic.Bool
}

func (p *probe) Stop(ctx context.Context) error {
	p.stopVisited.Store(true)
	before := p.runs.Load()
	time.Sleep(60 * time.Millisecond)
	p.ranInStop.Store(p.runs.Load() != before)
	return p.BaseExtension.Stop(ctx)
}

func TestStopsOnClose(t *testing.T) {
	s := ingesttest.New(t)
	var runs atomic.Int64
	name := fake("counter", false, func(name string) func(context.Context, adapter.Host) (bool, error) {
		return func(_ context.Context, h adapter.Host) (bool, error) {
			return true, h.Witness.Snapshot(collect.Snapshot{
				Key: name, Title: name, Every: 10 * time.Millisecond,
				Collect: func(context.Context) (map[string]any, error) {
					return map[string]any{"run": runs.Add(1)}, nil
				},
			})
		}
	})
	ext := witnessforge.New(witnessforge.WithConfig(on(s, name)))
	p := &probe{BaseExtension: forge.NewBaseExtension("probe", "1.0.0", "watches the stop"), runs: &runs}
	p.SetDependencies([]string{witnessforge.Name})
	app := forgetesting.NewTestAppWithConfig(forge.AppConfig{Name: "witness-test", Extensions: []forge.Extension{ext, p}})
	if err := app.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the collector to run", func() bool { return runs.Load() >= 3 })
	if err := app.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !p.stopVisited.Load() {
		t.Fatal("the probe extension never stopped")
	}
	// The OnClose hook stopped witness before any extension stopped.
	if p.ranInStop.Load() {
		t.Fatal("collectors still ran while extensions were stopping")
	}
	stopped := runs.Load()
	time.Sleep(100 * time.Millisecond)
	if got := runs.Load(); got != stopped {
		t.Fatalf("the collector ran %d more times after the app stopped", got-stopped)
	}
	// Stop sent what was queued.
	if len(s.Stored()) == 0 {
		t.Fatal("nothing reached Hallproof")
	}
}

func TestConfigFromFile(t *testing.T) {
	s := ingesttest.New(t)
	keyFile := filepath.Join(t.TempDir(), "ingest-key")
	if err := os.WriteFile(keyFile, []byte(s.Key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var (
		mu  sync.Mutex
		got adapter.Host
	)
	name := fake("file", false, func(name string) func(context.Context, adapter.Host) (bool, error) {
		return func(ctx context.Context, h adapter.Host) (bool, error) {
			mu.Lock()
			got = h
			mu.Unlock()
			return snapshotter(20*time.Millisecond, nil, nil)(name)(ctx, h)
		}
	})

	cm := forge.NewManager()
	cm.Set("extensions.witness", map[string]any{
		"endpoint":        s.URL,
		"ingest_key_file": keyFile,
		"libraries":       []any{name},
		"scope":           map[string]any{"app_id": "app_1", "staff_roles": []any{"ops"}, "all_tenants": true},
		"adapters":        map[string]any{name: map[string]any{"event_proofs": true}},
	})
	ext := witnessforge.New()
	startWith(t, cm, ext, []string{name})

	waitFor(t, "the adapter's snapshot", hasKey(s, name))
	mu.Lock()
	defer mu.Unlock()
	if got.Scope.AppID != "app_1" || !got.Scope.AllTenants || len(got.Scope.StaffRoles) != 1 || got.Scope.StaffRoles[0] != "ops" {
		t.Fatalf("Host.Scope = %+v", got.Scope)
	}
	if got.Config["event_proofs"] != true {
		t.Fatalf("Host.Config = %v", got.Config)
	}
}
