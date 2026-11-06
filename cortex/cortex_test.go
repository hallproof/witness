package cortex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cx "github.com/xraph/cortex"
	"github.com/xraph/cortex/agent"
	"github.com/xraph/cortex/checkpoint"
	"github.com/xraph/cortex/communication"
	"github.com/xraph/cortex/engine"
	"github.com/xraph/cortex/id"
	"github.com/xraph/cortex/llm"
	"github.com/xraph/cortex/persona"
	"github.com/xraph/cortex/prompt"
	"github.com/xraph/cortex/run"
	"github.com/xraph/cortex/store"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

const (
	staffOrg    = "org_staff"
	customerOrg = "org_customer"
	canary      = "CANARY-c0r7"
)

var t0 = time.Date(2026, 11, 1, 9, 30, 15, 123456789, time.UTC)

func orgScope(org string, more ...cx.Level) cx.Scope {
	return cx.Scope{Levels: append([]cx.Level{{Key: "org", Value: org}}, more...)}
}

// fakeStore is an in-memory stand-in for cortex's composite store. It
// implements the reads the adapter makes and panics on anything else, the
// way cortex's own scopespy double does. Lists honor the scope on the
// context like the built-in stores: a missing scope is an error, Exact
// matches the scope itself, and otherwise a list reaches every row at or
// beneath it.
type fakeStore struct {
	store.Store

	mu          sync.Mutex
	agents      []*agent.Config
	personas    []*persona.Persona
	checkpoints []*checkpoint.Checkpoint
	runs        []*run.Run
	// leaky makes every list ignore the scope, like a broken store, so a
	// test can check the adapter's own scope guard.
	leaky bool
}

func (s *fakeStore) match(ctx context.Context, row cx.Scope, exact bool) (bool, error) {
	q, err := cx.RequireScope(ctx)
	if err != nil {
		return false, err
	}
	if s.leaky {
		return true, nil
	}
	if exact {
		return q.Canonical() == row.Canonical(), nil
	}
	return q.Covers(row), nil
}

func page[T any](rows []T, limit, offset int) []T {
	if offset >= len(rows) {
		return nil
	}
	rows = rows[offset:]
	if limit > 0 && limit < len(rows) {
		rows = rows[:limit]
	}
	return rows
}

func (s *fakeStore) List(ctx context.Context, f *agent.ListFilter) ([]*agent.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f0 agent.ListFilter
	if f != nil {
		f0 = *f
	}
	var out []*agent.Config
	for _, a := range s.agents {
		ok, err := s.match(ctx, a.Scope, f0.Exact)
		if err != nil {
			return nil, err
		}
		if ok {
			c := *a
			out = append(out, &c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return page(out, f0.Limit, f0.Offset), nil
}

func (s *fakeStore) ListPersonas(ctx context.Context, f *persona.ListFilter) ([]*persona.Persona, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f0 persona.ListFilter
	if f != nil {
		f0 = *f
	}
	var out []*persona.Persona
	for _, p := range s.personas {
		ok, err := s.match(ctx, p.Scope, f0.Exact)
		if err != nil {
			return nil, err
		}
		if ok {
			c := *p
			out = append(out, &c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return page(out, f0.Limit, f0.Offset), nil
}

func (s *fakeStore) ListPending(ctx context.Context, f *checkpoint.ListFilter) ([]*checkpoint.Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f0 checkpoint.ListFilter
	if f != nil {
		f0 = *f
	}
	var out []*checkpoint.Checkpoint
	for _, cp := range s.checkpoints {
		ok, err := s.match(ctx, cp.Scope, false)
		if err != nil {
			return nil, err
		}
		if ok && cp.State == "pending" && (f0.RunID == "" || cp.RunID.String() == f0.RunID) {
			c := *cp
			out = append(out, &c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return page(out, f0.Limit, f0.Offset), nil
}

func (s *fakeStore) ListRuns(ctx context.Context, f *run.ListFilter) ([]*run.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f0 run.ListFilter
	if f != nil {
		f0 = *f
	}
	var out []*run.Run
	for _, r := range s.runs {
		ok, err := s.match(ctx, r.Scope, f0.Exact)
		if err != nil {
			return nil, err
		}
		if ok && (f0.AgentID == "" || r.AgentID.String() == f0.AgentID) && (f0.State == "" || r.State == f0.State) {
			c := *r
			out = append(out, &c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return page(out, f0.Limit, f0.Offset), nil
}

type fixture struct {
	st  *fakeStore
	eng *engine.Engine
}

func newFixture(t *testing.T, opts ...engine.Option) *fixture {
	t.Helper()
	st := &fakeStore{}
	eng, err := engine.New(append([]engine.Option{engine.WithStore(st)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, eng: eng}
}

func (f *fixture) addAgent(a *agent.Config) *agent.Config {
	if a.ID.IsNil() {
		a.ID = id.NewAgentID()
	}
	if a.Scope.IsZero() {
		a.Scope = orgScope(staffOrg)
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt, a.UpdatedAt = t0, t0
	}
	f.st.agents = append(f.st.agents, a)
	return a
}

func (f *fixture) addPersona(p *persona.Persona) *persona.Persona {
	if p.ID.IsNil() {
		p.ID = id.NewPersonaID()
	}
	if p.Scope.IsZero() {
		p.Scope = orgScope(staffOrg)
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt, p.UpdatedAt = t0, t0
	}
	f.st.personas = append(f.st.personas, p)
	return p
}

func (f *fixture) addCheckpoint(cp *checkpoint.Checkpoint) *checkpoint.Checkpoint {
	if cp.ID.IsNil() {
		cp.ID = id.NewCheckpointID()
	}
	if cp.RunID.IsNil() {
		cp.RunID = id.NewAgentRunID()
	}
	if cp.AgentID.IsNil() {
		cp.AgentID = id.NewAgentID()
	}
	if cp.Scope.IsZero() {
		cp.Scope = orgScope(staffOrg)
	}
	if cp.State == "" {
		cp.State = "pending"
	}
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt, cp.UpdatedAt = t0, t0
	}
	f.st.checkpoints = append(f.st.checkpoints, cp)
	return cp
}

func (f *fixture) addRun(r *run.Run) {
	if r.ID.IsNil() {
		r.ID = id.NewAgentRunID()
	}
	if r.Scope.IsZero() {
		r.Scope = orgScope(staffOrg)
	}
	if r.State == "" {
		r.State = run.StateCompleted
	}
	f.st.runs = append(f.st.runs, r)
}

type collected struct {
	pops   map[string]collect.Population
	snaps  map[string]collect.Snapshot
	proofs map[string]collect.EventProof
}

func collectorsOf(t *testing.T, a *Adapter) collected {
	t.Helper()
	pops, snaps, proofs, err := a.collectors()
	if err != nil {
		t.Fatal(err)
	}
	c := collected{pops: map[string]collect.Population{}, snaps: map[string]collect.Snapshot{}, proofs: map[string]collect.EventProof{}}
	for _, p := range pops {
		c.pops[p.Key] = p
	}
	for _, s := range snaps {
		c.snaps[s.Key] = s
	}
	for _, e := range proofs {
		c.proofs[e.Key] = e
	}
	return c
}

func items(t *testing.T, a *Adapter, key string) []map[string]any {
	t.Helper()
	p, ok := collectorsOf(t, a).pops[key]
	if !ok {
		t.Fatalf("no population %q", key)
	}
	out, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func settings(t *testing.T, a *Adapter, key string) map[string]any {
	t.Helper()
	s, ok := collectorsOf(t, a).snaps[key]
	if !ok {
		t.Fatalf("no snapshot %q", key)
	}
	out, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func ids(items []map[string]any) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it["id"].(string))
	}
	slices.Sort(out)
	return out
}

func sortedIDs(in ...string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// taken reports whether a population key is already registered on w.
func taken(t *testing.T, w *witness.Witness, key string) bool {
	t.Helper()
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

func assertJSON(t *testing.T, got, want any) {
	t.Helper()
	norm := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var x any
		if err := json.Unmarshal(raw, &x); err != nil {
			t.Fatal(err)
		}
		out, _ := json.Marshal(x)
		return string(out)
	}
	if g, w := norm(got), norm(want); g != w {
		t.Fatalf("got  %s\nwant %s", g, w)
	}
}

type allowAll struct{}

func (allowAll) Visible(_ context.Context, _ cx.Subject, tools []llm.Tool) []llm.Tool { return tools }
func (allowAll) Authorize(context.Context, cx.Subject, llm.ToolCall) error            { return nil }

func noop(context.Context, cx.Invocation) (string, error) { return "", nil }

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"cortex"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("cortex adapter is not registered")
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"nil": nil, "empty vessel": vessel.New(), "not a vessel": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c, Config: map[string]any{"org": staffOrg}})
			if found || err != nil {
				t.Fatalf("attach = %v, %v; want false, nil", found, err)
			}
		})
	}
}

func TestAttachRegistersFromConfig(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{
		Witness:   w,
		Container: c,
		Config:    map[string]any{"org": staffOrg, "owner_key": "owner", "event_proofs": true},
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyAgents, KeyPersonas, KeyPendingApprovals} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
}

func TestAttachWithoutOrgRegistersNothing(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c, Scope: adapter.Scope{TenantID: staffOrg, AllTenants: true}})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyAgents, KeyPersonas, KeyPendingApprovals} {
		if taken(t, w, k) {
			t.Errorf("%s was registered with no org", k)
		}
	}
}

// fakeExt stands in for cortex's Forge extension. The adapter only uses
// its getter, and calls counts how often it was asked.
type fakeExt struct {
	eng   *engine.Engine
	calls atomic.Int32
}

func (x *fakeExt) Engine() *engine.Engine {
	x.calls.Add(1)
	return x.eng
}

// extensions is a host's extension lookup that runs only x, as "cortex".
func extensions(x *fakeExt) func(string) (any, bool) {
	return func(name string) (any, bool) {
		if name == "cortex" && x != nil {
			return x, true
		}
		return nil, false
	}
}

// constructed registers eng with a constructor, the way cortex's extension
// does, and counts how often the container builds it.
func constructed(t *testing.T, eng *engine.Engine) (vessel.Vessel, *atomic.Int32) {
	t.Helper()
	var built atomic.Int32
	c := vessel.New()
	if err := vessel.Provide(c, func() (*engine.Engine, error) {
		built.Add(1)
		return eng, nil
	}); err != nil {
		t.Fatal(err)
	}
	return c, &built
}

func TestAttachUsesTheExtensionNotTheContainer(t *testing.T) {
	f := newFixture(t)
	c, built := constructed(t, f.eng)
	x := &fakeExt{eng: f.eng}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{
		Witness: w, Container: c, Extension: extensions(x),
		Config: map[string]any{"org": staffOrg},
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyAgents, KeyPersonas, KeyPendingApprovals} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
	if n := built.Load(); n != 0 {
		t.Fatalf("the container built the engine %d times, want 0", n)
	}
}

func TestAttachUsesTheExtensionWithoutAContainer(t *testing.T) {
	f := newFixture(t)
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{
		Witness: w, Extension: extensions(&fakeExt{eng: f.eng}),
		Config: map[string]any{"org": staffOrg},
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	if !taken(t, w, KeyAgents) {
		t.Fatalf("%s was not registered", KeyAgents)
	}
}

// An extension whose getter returns nil hasn't built its engine, so cortex
// counts as absent and the container is never asked instead.
func TestAttachWithAnEmptyExtensionIsNotFound(t *testing.T) {
	f := newFixture(t)
	c, built := constructed(t, f.eng)
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{
		Witness: w, Container: c, Extension: extensions(&fakeExt{}),
		Config: map[string]any{"org": staffOrg},
	})
	if found || err != nil {
		t.Fatalf("attach = %v, %v; want false, nil", found, err)
	}
	if taken(t, w, KeyAgents) {
		t.Fatalf("%s was registered with no engine", KeyAgents)
	}
	if n := built.Load(); n != 0 {
		t.Fatalf("the container built the engine %d times, want 0", n)
	}
}

// With no org there is nothing to collect, so attach must not reach for
// the engine at all: not through the extension and not through the
// container, which would build and start a second engine.
func TestAttachWithoutOrgNeverTouchesTheEngine(t *testing.T) {
	f := newFixture(t)
	for name, withExt := range map[string]bool{"extension": true, "container only": false} {
		t.Run(name, func(t *testing.T) {
			c, built := constructed(t, f.eng)
			h := adapter.Host{Witness: newWitness(t), Container: c}
			var x *fakeExt
			if withExt {
				x = &fakeExt{eng: f.eng}
				h.Extension = extensions(x)
			}
			found, err := attach(context.Background(), h)
			if !found || err != nil {
				t.Fatalf("attach = %v, %v; want true, nil", found, err)
			}
			if n := built.Load(); n != 0 {
				t.Errorf("the container built the engine %d times, want 0", n)
			}
			if x != nil && x.calls.Load() != 0 {
				t.Errorf("the extension's getter was called %d times, want 0", x.calls.Load())
			}
		})
	}
}

// Orgs is a list the host names itself, and cortex has no all-tenants
// mode, so attach never reports a widened scope.
func TestAttachNeverWidens(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	var got []string
	found, err := attach(context.Background(), adapter.Host{
		Witness: newWitness(t), Container: c, Scope: adapter.Scope{AllTenants: true},
		Config: map[string]any{"org": staffOrg, "orgs": []any{"org_customer"}},
		Widen:  func(r string) { got = append(got, r) },
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	if len(got) != 0 {
		t.Fatalf("Widen calls = %v, want none", got)
	}
}

func TestRegisterNeedsAScope(t *testing.T) {
	f := newFixture(t)
	for name, opts := range map[string][]Option{
		"none":       nil,
		"blank only": {WithOrg(" "), WithOrgs("", " ")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := New(f.eng, opts...).Register(newWitness(t)); !errors.Is(err, ErrNoOrg) {
				t.Fatalf("Register = %v, want ErrNoOrg", err)
			}
		})
	}
	if err := New(f.eng, WithScope(cx.Scope{Levels: []cx.Level{{Key: "org", Value: "a/b"}}})).Register(newWitness(t)); err == nil {
		t.Fatal("Register took an invalid scope")
	}
	if err := New(nil, WithOrg(staffOrg)).Register(newWitness(t)); err == nil {
		t.Fatal("Register took a nil engine")
	}
}

func TestAgents(t *testing.T) {
	f := newFixture(t)
	ag := f.addAgent(&agent.Config{
		Name: "triage", Scope: orgScope(staffOrg, cx.Level{Key: "project", Value: "prj_1"}),
		Model: "claude-x", ReasoningLoop: "react", MaxSteps: 12, Enabled: true,
		Tools:      []string{"search", "delete_project"},
		PersonaRef: "analyst", InlineSkills: []string{"sql", "go"}, InlineTraits: []string{"careful"}, InlineBehaviors: []string{"ask-first"},
		Guardrails: map[string]any{"pii": true, "max_cost": 3},
		Metadata:   map[string]any{"owner_id": "usr_1", "principal_id": "agt_1"},
		Entity:     cx.Entity{CreatedAt: t0, UpdatedAt: t0.Add(time.Hour)},
	})
	f.addRun(&run.Run{AgentID: ag.ID, Entity: cx.Entity{CreatedAt: t0.Add(2 * time.Hour)}})
	f.addRun(&run.Run{AgentID: ag.ID, Entity: cx.Entity{CreatedAt: t0.Add(5 * time.Hour)}})
	f.addRun(&run.Run{AgentID: id.NewAgentID(), Entity: cx.Entity{CreatedAt: t0.Add(9 * time.Hour)}})
	idle := f.addAgent(&agent.Config{Name: "idle", Metadata: map[string]any{"owner_id": 42}})

	got := items(t, New(f.eng, WithOrg(staffOrg)), KeyAgents)
	if len(got) != 2 {
		t.Fatalf("got %d agents, want 2", len(got))
	}
	byID := map[string]map[string]any{}
	for _, it := range got {
		byID[it["id"].(string)] = it
	}
	assertJSON(t, byID[ag.ID.String()], map[string]any{
		"id": ag.ID.String(), "name": "triage", "scope": "org=org_staff/project=prj_1", "enabled": true,
		"model": "claude-x", "reasoning_loop": "react", "max_steps": 12,
		"tools": []string{"delete_project", "search"}, "persona_ref": "analyst",
		"inline_skills": []string{"go", "sql"}, "inline_traits": []string{"careful"}, "inline_behaviors": []string{"ask-first"},
		"guardrail_keys": []string{"max_cost", "pii"}, "owner_id": "usr_1", "principal_id": "agt_1",
		"created_at": "2026-11-01T09:30:15Z", "updated_at": "2026-11-01T10:30:15Z", "last_run_on": "2026-11-01",
	})
	assertJSON(t, byID[idle.ID.String()], map[string]any{
		"id": idle.ID.String(), "name": "idle", "scope": "org=org_staff", "enabled": false,
		"model": "", "reasoning_loop": "", "max_steps": 0,
		"tools": []string{}, "persona_ref": "",
		"inline_skills": []string{}, "inline_traits": []string{}, "inline_behaviors": []string{},
		"guardrail_keys": []string{}, "owner_id": "", "principal_id": "",
		"created_at": "2026-11-01T09:30:15Z", "updated_at": "2026-11-01T09:30:15Z", "last_run_on": nil,
	})
}

func TestAgentRunsOnTheSameDayChangeNothing(t *testing.T) {
	f := newFixture(t)
	ag := f.addAgent(&agent.Config{Name: "triage", Enabled: true})
	f.addRun(&run.Run{AgentID: ag.ID, Entity: cx.Entity{CreatedAt: t0.Add(time.Hour)}})
	a := New(f.eng, WithOrg(staffOrg))
	before, err := json.Marshal(items(t, a, KeyAgents))
	if err != nil {
		t.Fatal(err)
	}
	f.addRun(&run.Run{AgentID: ag.ID, Entity: cx.Entity{CreatedAt: t0.Add(3 * time.Hour)}})
	after, err := json.Marshal(items(t, a, KeyAgents))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("a second run the same day changed the agent:\nbefore %s\nafter  %s", before, after)
	}
	f.addRun(&run.Run{AgentID: ag.ID, Entity: cx.Entity{CreatedAt: t0.Add(24 * time.Hour)}})
	if next := items(t, a, KeyAgents); next[0]["last_run_on"] != "2026-11-02" {
		t.Fatalf("last_run_on = %v after a run the next day, want 2026-11-02", next[0]["last_run_on"])
	}
}

func TestAgentOwners(t *testing.T) {
	f := newFixture(t)
	ag := f.addAgent(&agent.Config{Name: "a", Metadata: map[string]any{"owner_id": "usr_default", "accountable": "usr_custom", "authsome_id": "prn_9"}})

	got := items(t, New(f.eng, WithOrg(staffOrg), WithOwnerKeys("accountable", "authsome_id")), KeyAgents)
	if got[0]["owner_id"] != "usr_custom" || got[0]["principal_id"] != "prn_9" {
		t.Fatalf("owner keys: %v", got[0])
	}

	fromConfig := newAdapter(f.eng, Options{Org: staffOrg, OwnerKey: "accountable"})
	got = items(t, fromConfig, KeyAgents)
	if got[0]["owner_id"] != "usr_custom" || got[0]["principal_id"] != "" {
		t.Fatalf("owner_key from config: %v", got[0])
	}

	byHost := New(f.eng, WithOrg(staffOrg), WithOwner(func(c *agent.Config) (string, string) {
		if c.ID != ag.ID {
			t.Errorf("WithOwner got agent %s", c.ID)
		}
		return "team_ops", "prn_host"
	}))
	got = items(t, byHost, KeyAgents)
	if got[0]["owner_id"] != "team_ops" || got[0]["principal_id"] != "prn_host" {
		t.Fatalf("WithOwner: %v", got[0])
	}
}

func TestTools(t *testing.T) {
	f := newFixture(t,
		engine.WithTool(llm.Tool{Name: "delete_project"}, noop),
		engine.WithTool(llm.Tool{Name: "search"}, noop),
		engine.WithToolRetrySafe("search"),
		engine.WithExternalTool(llm.Tool{Name: "approve_invoice"}),
	)
	got := settings(t, New(f.eng, WithOrg(staffOrg)), KeyTools)
	assertJSON(t, got, map[string]any{
		"has_tool_authorizer": false,
		"tools": []map[string]any{
			{"name": "approve_invoice", "kind": "external", "retry_safe": false},
			{"name": "delete_project", "kind": "registered", "retry_safe": false},
			{"name": "search", "kind": "registered", "retry_safe": true},
		},
	})
	if tests := collectorsOf(t, New(f.eng, WithOrg(staffOrg))).snaps[KeyTools].Tests; len(tests) != 0 {
		t.Fatalf("tools tests without a classifier = %v", tests)
	}

	authz := newFixture(t,
		engine.WithTool(llm.Tool{Name: "delete_project"}, noop),
		engine.WithToolAuthorizer(allowAll{}), engine.WithPrincipalCodec(cx.JSONPrincipalCodec[any]()),
	)
	risky := New(authz.eng, WithOrg(staffOrg), WithRiskClass(func(name string) string {
		if name == "delete_project" {
			return "high"
		}
		return "low"
	}))
	assertJSON(t, settings(t, risky, KeyTools), map[string]any{
		"has_tool_authorizer": true,
		"tools":               []map[string]any{{"name": "delete_project", "kind": "registered", "retry_safe": false, "risk": "high"}},
	})
	if tests := collectorsOf(t, risky).snaps[KeyTools].Tests; !slices.Equal(tests, []string{"high-risk-approved"}) {
		t.Fatalf("tools tests with a classifier = %v", tests)
	}
}

func TestPersonas(t *testing.T) {
	f := newFixture(t)
	p := f.addPersona(&persona.Persona{
		Name:      "analyst",
		Skills:    []persona.SkillAssignment{{SkillName: "sql"}, {SkillName: "go"}},
		Traits:    []persona.TraitAssignment{{TraitName: "careful"}},
		Behaviors: []string{"ask-first"},
		Entity:    cx.Entity{CreatedAt: t0, UpdatedAt: t0.Add(time.Minute)},
	})
	got := items(t, New(f.eng, WithOrg(staffOrg)), KeyPersonas)
	if len(got) != 1 {
		t.Fatalf("got %d personas", len(got))
	}
	assertJSON(t, got[0], map[string]any{
		"id": p.ID.String(), "name": "analyst", "scope": "org=org_staff",
		"skills": []string{"go", "sql"}, "traits": []string{"careful"}, "behaviors": []string{"ask-first"},
		"created_at": "2026-11-01T09:30:15Z", "updated_at": "2026-11-01T09:31:15Z",
	})
}

func TestPendingApprovals(t *testing.T) {
	f := newFixture(t)
	cp := f.addCheckpoint(&checkpoint.Checkpoint{StepIndex: 3, Scope: orgScope(staffOrg, cx.Level{Key: "project", Value: "prj_1"})})
	f.addCheckpoint(&checkpoint.Checkpoint{State: "approved"})
	got := items(t, New(f.eng, WithOrg(staffOrg)), KeyPendingApprovals)
	if len(got) != 1 {
		t.Fatalf("got %d checkpoints, want 1", len(got))
	}
	assertJSON(t, got[0], map[string]any{
		"id": cp.ID.String(), "run_id": cp.RunID.String(), "agent_id": cp.AgentID.String(),
		"scope": "org=org_staff/project=prj_1", "state": "pending", "step_index": 3,
		"created_at": "2026-11-01T09:30:15Z",
	})
	if tests := collectorsOf(t, New(f.eng, WithOrg(staffOrg))).pops[KeyPendingApprovals].Tests; !slices.Equal(tests, []string{"high-risk-approved"}) {
		t.Fatalf("pending approval tests = %v", tests)
	}
}

func TestEventProofs(t *testing.T) {
	f := newFixture(t)
	if got := collectorsOf(t, New(f.eng, WithOrg(staffOrg))).proofs; len(got) != 0 {
		t.Fatalf("event proofs on by default: %v", got)
	}
	c := collectorsOf(t, New(f.eng, WithOrg(staffOrg), WithEventProofs()))
	ov := c.proofs[KeyOversight]
	if ov.Stream != adapter.Platform || !slices.Equal(ov.Actions, OversightActions) || !slices.Equal(ov.Tests, []string{"high-risk-approved"}) {
		t.Fatalf("oversight proof = %+v", ov)
	}
	act := c.proofs[KeyAgentActivity]
	if act.Stream != adapter.Platform || !slices.Equal(act.Actions, ActivityActions) || !slices.Equal(act.Tests, []string{"agent-events-chained"}) {
		t.Fatalf("activity proof = %+v", act)
	}
	if err := New(f.eng, WithOrg(staffOrg), WithEventProofs()).Register(newWitness(t)); err != nil {
		t.Fatal(err)
	}
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	staffAg := f.addAgent(&agent.Config{Name: "staff"})
	staffSub := f.addAgent(&agent.Config{Name: "staff project", Scope: orgScope(staffOrg, cx.Level{Key: "project", Value: "p"})})
	custAg := f.addAgent(&agent.Config{Name: "customer", Scope: orgScope(customerOrg)})
	staffP := f.addPersona(&persona.Persona{Name: "staff"})
	custP := f.addPersona(&persona.Persona{Name: "customer", Scope: orgScope(customerOrg)})
	staffCP := f.addCheckpoint(&checkpoint.Checkpoint{})
	custCP := f.addCheckpoint(&checkpoint.Checkpoint{Scope: orgScope(customerOrg)})

	cases := []struct {
		name                  string
		a                     *Adapter
		agents, personas, cps []string
	}{
		{"default", New(f.eng, WithOrg(staffOrg)),
			[]string{staffAg.ID.String(), staffSub.ID.String()}, []string{staffP.ID.String()}, []string{staffCP.ID.String()}},
		{"explicit orgs", New(f.eng, WithOrg(staffOrg), WithOrgs(customerOrg)),
			[]string{staffAg.ID.String(), staffSub.ID.String(), custAg.ID.String()}, []string{staffP.ID.String(), custP.ID.String()}, []string{staffCP.ID.String(), custCP.ID.String()}},
		{"explicit orgs from config", newAdapter(f.eng, Options{Org: staffOrg, Orgs: []string{customerOrg}}),
			[]string{staffAg.ID.String(), staffSub.ID.String(), custAg.ID.String()}, []string{staffP.ID.String(), custP.ID.String()}, []string{staffCP.ID.String(), custCP.ID.String()}},
		{"nested scopes counted once", New(f.eng, WithOrg(staffOrg), WithScope(orgScope(staffOrg, cx.Level{Key: "project", Value: "p"}))),
			[]string{staffAg.ID.String(), staffSub.ID.String()}, []string{staffP.ID.String()}, []string{staffCP.ID.String()}},
		{"other scope key", New(f.eng, WithOrg(staffOrg), WithScopeKey("workspace")), nil, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := ids(items(t, tc.a, KeyAgents)), sortedIDs(tc.agents...); !slices.Equal(got, want) {
				t.Errorf("agents = %v, want %v", got, want)
			}
			if got, want := ids(items(t, tc.a, KeyPersonas)), sortedIDs(tc.personas...); !slices.Equal(got, want) {
				t.Errorf("personas = %v, want %v", got, want)
			}
			if got, want := ids(items(t, tc.a, KeyPendingApprovals)), sortedIDs(tc.cps...); !slices.Equal(got, want) {
				t.Errorf("checkpoints = %v, want %v", got, want)
			}
		})
	}

	// A store that ignores the scope still can't hand the adapter a
	// customer's rows: the adapter checks each row's scope itself.
	f.st.leaky = true
	a := New(f.eng, WithOrg(staffOrg))
	if got, want := ids(items(t, a, KeyAgents)), sortedIDs(staffAg.ID.String(), staffSub.ID.String()); !slices.Equal(got, want) {
		t.Errorf("leaky store agents = %v, want %v", got, want)
	}
	if got := ids(items(t, a, KeyPersonas)); !slices.Equal(got, []string{staffP.ID.String()}) {
		t.Errorf("leaky store personas = %v", got)
	}
	if got := ids(items(t, a, KeyPendingApprovals)); !slices.Equal(got, []string{staffCP.ID.String()}) {
		t.Errorf("leaky store checkpoints = %v", got)
	}
}

func TestPages(t *testing.T) {
	f := newFixture(t)
	const n = 2*pageSize + 37
	for i := range n {
		at := t0.Add(time.Duration(i%7) * time.Second)
		f.addAgent(&agent.Config{Name: fmt.Sprint("a", i), Entity: cx.Entity{CreatedAt: at, UpdatedAt: at}})
		f.addPersona(&persona.Persona{Name: fmt.Sprint("p", i), Entity: cx.Entity{CreatedAt: at, UpdatedAt: at}})
		f.addCheckpoint(&checkpoint.Checkpoint{Entity: cx.Entity{CreatedAt: at, UpdatedAt: at}})
	}
	for range 30 {
		f.addAgent(&agent.Config{Scope: orgScope(customerOrg)})
	}
	a := New(f.eng, WithOrg(staffOrg))
	for _, k := range []string{KeyAgents, KeyPersonas, KeyPendingApprovals} {
		got := items(t, a, k)
		if len(got) != n {
			t.Errorf("%s = %d, want %d", k, len(got), n)
		}
		if u := ids(got); len(slices.Compact(u)) != n {
			t.Errorf("%s has repeats", k)
		}
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 5
	t.Cleanup(func() { maxItems = old })

	f := newFixture(t)
	for range 6 {
		f.addAgent(&agent.Config{})
		f.addPersona(&persona.Persona{})
		f.addCheckpoint(&checkpoint.Checkpoint{})
	}
	c := collectorsOf(t, New(f.eng, WithOrg(staffOrg)))
	for _, k := range []string{KeyAgents, KeyPersonas, KeyPendingApprovals} {
		if _, err := c.pops[k].Collect(context.Background()); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: err = %v, want ErrTooMany", k, err)
		}
	}
}

func TestNeverSendsContent(t *testing.T) {
	f := newFixture(t,
		engine.WithTool(llm.Tool{Name: "delete_project", Description: canary + "-tool-desc", Parameters: map[string]any{"x": canary + "-tool-params"}}, noop),
		engine.WithExternalTool(llm.Tool{Name: "pay", Description: canary + "-ext-desc", Parameters: map[string]any{"x": canary + "-ext-params"}}),
		engine.WithToolAuthorizer(allowAll{}), engine.WithPrincipalCodec(cx.JSONPrincipalCodec[any]()),
	)
	ag := f.addAgent(&agent.Config{
		Name: "a", Description: canary + "-agent-desc", SystemPrompt: canary + "-system-prompt",
		Sections:    []prompt.Section{{ID: "role", Title: canary + "-section-title", Body: canary + "-section-body"}},
		Guardrails:  map[string]any{"pii": canary + "-guardrail", "nested": map[string]any{"x": canary + "-guardrail-nested"}},
		Metadata:    map[string]any{"owner_id": "usr_owner", "principal_id": "prn_owner", "definition": canary + "-meta", "nested": map[string]any{"x": canary + "-meta-nested"}},
		Temperature: 0.123456, MaxTokens: 987654321,
		Tools: []string{"delete_project"},
	})
	f.addRun(&run.Run{
		AgentID: ag.ID, Input: canary + "-run-input", Output: canary + "-run-output", Error: canary + "-run-error",
		FinishReason: canary + "-finish", Metadata: map[string]any{"x": canary + "-run-meta"}, Principal: []byte(canary + "-run-principal"),
		PersonaRef: canary + "-run-persona", Entity: cx.Entity{CreatedAt: t0},
	})
	f.addPersona(&persona.Persona{
		Name: "p", Description: canary + "-persona-desc", Identity: canary + "-persona-identity",
		Metadata:           map[string]any{"x": canary + "-persona-meta"},
		CommunicationStyle: communication.Style{Tone: canary + "-tone", PreferredFormat: canary + "-format"},
		Traits:             []persona.TraitAssignment{{TraitName: "t", DimensionValues: map[string]float64{canary + "-dim": 0.5}}},
	})
	f.addCheckpoint(&checkpoint.Checkpoint{
		AgentID: ag.ID, Reason: canary + "-cp-reason", Metadata: map[string]any{"x": canary + "-cp-meta"},
		Decision: &checkpoint.Decision{Reason: canary + "-decision-reason", DecidedBy: canary + "-decided-by", DecidedByPrincipal: []byte(canary + "-decided-principal")},
	})

	a := New(f.eng, WithOrg(staffOrg), WithEventProofs(), WithRiskClass(func(string) string { return "high" }))
	c := collectorsOf(t, a)
	out := make([]any, 0, len(c.pops)+len(c.snaps)+len(c.proofs))
	for _, p := range c.pops {
		got, err := p.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got)
	}
	for _, s := range c.snaps {
		got, err := s.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got)
	}
	for _, e := range c.proofs {
		out = append(out, e)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{canary, "0.123456", "987654321", "temperature", "max_tokens", "description\":\""} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
	for _, want := range []string{`"owner_id":"usr_owner"`, `"principal_id":"prn_owner"`, `"name":"delete_project"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("output lacks %s: %s", want, raw)
		}
	}
}
