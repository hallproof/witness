package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sn "github.com/xraph/sentinel"
	"github.com/xraph/sentinel/baseline"
	"github.com/xraph/sentinel/engine"
	"github.com/xraph/sentinel/evalrun"
	"github.com/xraph/sentinel/id"
	"github.com/xraph/sentinel/store/memory"
	"github.com/xraph/sentinel/suite"
	"github.com/xraph/sentinel/testcase"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

const (
	platformApp    = "app-platform"
	otherApp       = "app-other"
	platformTenant = "platform"
	customer       = "org-customer"
)

var t0 = time.Date(2026, 11, 1, 9, 30, 15, 123456789, time.UTC)

type fixture struct {
	eng *engine.Engine
	st  *memory.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memory.New()
	cfg := sn.DefaultConfig()
	cfg.DefaultModel = "gpt-test"
	cfg.PassThreshold = 0.8
	cfg.RegressionThreshold = 0.05
	eng, err := engine.New(engine.WithStore(st), engine.WithConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{eng: eng, st: st}
}

func (f *fixture) addSuite(t *testing.T, s *suite.Suite) *suite.Suite {
	t.Helper()
	s.ID = id.NewSuiteID()
	if s.AppID == "" {
		s.AppID = platformApp
	}
	if s.Name == "" {
		s.Name = s.ID.String()
	}
	if s.Model == "" {
		s.Model = "gpt-test"
	}
	if err := f.st.CreateSuite(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	got, err := f.st.GetSuite(context.Background(), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (f *fixture) addCase(t *testing.T, s *suite.Suite, c *testcase.Case) *testcase.Case {
	t.Helper()
	c.ID = id.NewCaseID()
	c.SuiteID = s.ID
	if c.Name == "" {
		c.Name = c.ID.String()
	}
	if err := f.st.CreateCase(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

// addRun stores r for s, completed by default, created at at.
func (f *fixture) addRun(t *testing.T, s *suite.Suite, r *evalrun.Run, at time.Time) *evalrun.Run {
	t.Helper()
	ctx := context.Background()
	r.ID = id.NewEvalRunID()
	r.SuiteID = s.ID
	if r.AppID == "" {
		r.AppID = s.AppID
	}
	if r.Model == "" {
		r.Model = s.Model
	}
	if r.State == "" {
		r.State = evalrun.StateCompleted
	}
	if r.State == evalrun.StateCompleted && r.CompletedAt == nil {
		done := at.Add(time.Minute)
		r.CompletedAt = &done
	}
	if err := f.st.CreateRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.CreatedAt = at
	if err := f.st.UpdateRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) addResult(t *testing.T, run *evalrun.Run, c *testcase.Case, r *evalrun.Result) {
	t.Helper()
	r.ID = id.NewEvalResultID()
	r.RunID = run.ID
	r.CaseID = c.ID
	if r.CaseName == "" {
		r.CaseName = c.Name
	}
	if err := f.st.CreateResult(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) addBaseline(t *testing.T, s *suite.Suite, run *evalrun.Run, b *baseline.Baseline) *baseline.Baseline {
	t.Helper()
	b.ID = id.NewBaselineID()
	b.SuiteID = s.ID
	b.RunID = run.ID
	if b.Name == "" {
		b.Name = "baseline"
	}
	b.IsCurrent = true
	if err := f.st.SaveBaseline(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	return b
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

func byID(t *testing.T, a *Adapter, key string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, it := range items(t, a, key) {
		out[it["id"].(string)] = it
	}
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

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"sentinel"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("sentinel adapter is not registered")
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"nil": nil, "empty vessel": vessel.New(), "not a vessel": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c})
			if found || err != nil {
				t.Fatalf("attach = %v, %v; want false, nil", found, err)
			}
		})
	}
}

// fakeExt stands in for sentinel's Forge extension. The adapter only uses
// its getter.
type fakeExt struct{ eng *engine.Engine }

func (x fakeExt) Engine() *engine.Engine { return x.eng }

// extensions is a host's extension lookup that runs only x, as "sentinel".
func extensions(x any) func(string) (any, bool) {
	return func(name string) (any, bool) {
		if name == "sentinel" {
			return x, true
		}
		return nil, false
	}
}

// constructed registers eng with a constructor, the way sentinel's
// extension does, and counts how often the container builds it.
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
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c, Extension: extensions(fakeExt{f.eng})})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeySuites, KeyLatestScores, KeyRedTeam, KeySettings} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
	if n := built.Load(); n != 0 {
		t.Fatalf("the container built the engine %d times, want 0", n)
	}
}

// An extension whose getter returns nil hasn't built its engine, so
// sentinel counts as absent and the container is never asked instead.
func TestAttachWithAnEmptyExtensionIsNotFound(t *testing.T) {
	f := newFixture(t)
	c, built := constructed(t, f.eng)
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c, Extension: extensions(fakeExt{})})
	if found || err != nil {
		t.Fatalf("attach = %v, %v; want false, nil", found, err)
	}
	if taken(t, w, KeySuites) {
		t.Fatalf("%s was registered with no engine", KeySuites)
	}
	if n := built.Load(); n != 0 {
		t.Fatalf("the container built the engine %d times, want 0", n)
	}
}

func TestAttachRegistersFromConfig(t *testing.T) {
	f := newFixture(t)
	staff := f.addSuite(t, &suite.Suite{Name: "staff"})
	f.addSuite(t, &suite.Suite{Name: "other app", AppID: otherApp})
	// A run against the platform tenant counts as staff because attach
	// adds the witness scope's tenant.
	run := f.addRun(t, staff, &evalrun.Run{TargetTenantID: platformTenant}, t0)

	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{
		Witness:   w,
		Scope:     adapter.Scope{AppID: platformApp, TenantID: platformTenant},
		Container: c,
		Config:    map[string]any{"event_proofs": true},
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeySuites, KeyLatestScores, KeyRedTeam} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}

	// The same options attach builds: app from the scope, tenant added.
	a := newAdapter(f.eng, Options{AppID: platformApp, StaffTenants: []string{platformTenant}})
	if got := byID(t, a, KeyLatestScores); len(got) != 1 || got[staff.ID.String()]["run_id"] != run.ID.String() {
		t.Fatalf("latest scores = %v", got)
	}
}

func TestAttachTellsTheHostItWidened(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config map[string]any
		scope  bool // the witness scope's AllTenants
		want   []string
	}{
		{"own all_tenants", map[string]any{"all_tenants": true}, false, []string{"all_tenants"}},
		// The host reports its own scope; the adapter only reports its own
		// config.
		{"scope only", nil, true, nil},
		{"staff tenants", map[string]any{"staff_tenants": []any{customer}}, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			c := vessel.New()
			if err := vessel.ProvideValue(c, f.eng); err != nil {
				t.Fatal(err)
			}
			var got []string
			found, err := attach(context.Background(), adapter.Host{
				Witness: newWitness(t), Container: c, Scope: adapter.Scope{AllTenants: tc.scope}, Config: tc.config,
				Widen: func(r string) { got = append(got, r) },
			})
			if !found || err != nil {
				t.Fatalf("attach = %v, %v; want true, nil", found, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("Widen calls = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWidenedDescriptionsSayWhoTheyCover(t *testing.T) {
	f := newFixture(t)
	wide := collectorsOf(t, New(f.eng, WithAllTenants()))
	staff := collectorsOf(t, New(f.eng))
	for _, k := range []string{KeyLatestScores, KeyRedTeam} {
		if d := wide.pops[k].Description; !strings.Contains(d, "every tenant") || !strings.Contains(d, "customers") {
			t.Errorf("%s widened Description = %q, want every tenant, customers included", k, d)
		}
		if d := staff.pops[k].Description; strings.Contains(d, "every tenant") {
			t.Errorf("%s staff Description = %q, want no every tenant", k, d)
		}
	}
}

func TestAttachBadConfig(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c, Config: map[string]any{"staff_tenants": "not a list"}})
	if !found || err == nil {
		t.Fatalf("attach = %v, %v; want true and an error", found, err)
	}
}

func TestNoTestKeys(t *testing.T) {
	c := collectorsOf(t, New(newFixture(t).eng, WithEventProofs()))
	if len(c.pops) != 3 || len(c.snaps) != 1 || len(c.proofs) != 1 {
		t.Fatalf("collectors = %d pops, %d snaps, %d proofs", len(c.pops), len(c.snaps), len(c.proofs))
	}
	for k, p := range c.pops {
		if len(p.Tests) != 0 {
			t.Errorf("%s Tests = %v, want none", k, p.Tests)
		}
	}
	for k, s := range c.snaps {
		if len(s.Tests) != 0 {
			t.Errorf("%s Tests = %v, want none", k, s.Tests)
		}
	}
	for k, e := range c.proofs {
		if len(e.Tests) != 0 {
			t.Errorf("%s Tests = %v, want none", k, e.Tests)
		}
	}
}

func TestSuites(t *testing.T) {
	f := newFixture(t)
	s := f.addSuite(t, &suite.Suite{Name: "support agent", Model: "gpt-x", PersonaRef: "helper"})
	f.addCase(t, s, &testcase.Case{Tags: []string{"smoke"}})
	f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "jailbreak"}})
	f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "injection"}})
	f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "injection", "hand-written"}})
	f.addCase(t, s, &testcase.Case{Tags: []string{"redteam"}})
	run := f.addRun(t, s, &evalrun.Run{}, t0)
	b := f.addBaseline(t, s, run, &baseline.Baseline{})
	bare := f.addSuite(t, &suite.Suite{Name: "bare"})

	got := byID(t, New(f.eng, WithAppID(platformApp)), KeySuites)
	if len(got) != 2 {
		t.Fatalf("got %d suites, want 2", len(got))
	}
	assertJSON(t, got[s.ID.String()], map[string]any{
		"id": s.ID.String(), "name": "support agent", "app_id": platformApp, "model": "gpt-x",
		"persona_ref": "helper", "case_count": 5, "redteam_case_count": 4,
		"redteam_types": []string{"injection", "jailbreak", "other"},
		"has_baseline":  true, "baseline_id": b.ID.String(),
		"created_at": stamp(s.CreatedAt), "updated_at": stamp(s.UpdatedAt),
	})
	assertJSON(t, got[bare.ID.String()], map[string]any{
		"id": bare.ID.String(), "name": "bare", "app_id": platformApp, "model": "gpt-test",
		"persona_ref": "", "case_count": 0, "redteam_case_count": 0, "redteam_types": []string{},
		"has_baseline": false, "baseline_id": nil,
		"created_at": stamp(bare.CreatedAt), "updated_at": stamp(bare.UpdatedAt),
	})
}

func TestLatestScores(t *testing.T) {
	f := newFixture(t)

	// Regressed: pass rate fell 0.2, past the 0.05 threshold.
	reg := f.addSuite(t, &suite.Suite{Name: "regressed"})
	old := f.addRun(t, reg, &evalrun.Run{PassRate: 0.9, AvgScore: 0.85}, t0)
	b := f.addBaseline(t, reg, old, &baseline.Baseline{PassRate: 0.9, AvgScore: 0.85, DimensionScores: map[string]float64{"accuracy": 0.8}})
	f.addRun(t, reg, &evalrun.Run{State: evalrun.StateFailed}, t0.Add(3*time.Hour))
	f.addRun(t, reg, &evalrun.Run{State: evalrun.StateRunning}, t0.Add(4*time.Hour))
	latest := f.addRun(t, reg, &evalrun.Run{
		Model: "gpt-y", TotalCases: 10, Passed: 7, Failed: 3, PassRate: 0.7, AvgScore: 0.84,
		DimensionScores: map[string]float64{"accuracy": 0.8},
	}, t0.Add(2*time.Hour))

	// Held: a drop exactly equal to the threshold is not a regression.
	held := f.addSuite(t, &suite.Suite{Name: "held"})
	hr := f.addRun(t, held, &evalrun.Run{TotalCases: 20, Passed: 19, Failed: 1, PassRate: 0.95, AvgScore: 0.9}, t0)
	hb := f.addBaseline(t, held, hr, &baseline.Baseline{PassRate: 1.0, AvgScore: 0.9})

	// A baseline dimension the run did not measure counts as regressed.
	missing := f.addSuite(t, &suite.Suite{Name: "missing dimension"})
	mr := f.addRun(t, missing, &evalrun.Run{PassRate: 1, AvgScore: 1}, t0)
	f.addBaseline(t, missing, mr, &baseline.Baseline{PassRate: 1, AvgScore: 1, DimensionScores: map[string]float64{"tone": 0.9}})

	noBase := f.addSuite(t, &suite.Suite{Name: "no baseline"})
	nbr := f.addRun(t, noBase, &evalrun.Run{PassRate: 0.5, AvgScore: 0.5}, t0)

	never := f.addSuite(t, &suite.Suite{Name: "never ran"})

	got := byID(t, New(f.eng), KeyLatestScores)
	if len(got) != 5 {
		t.Fatalf("got %d items, want 5", len(got))
	}
	r := got[reg.ID.String()]
	assertJSON(t, r, map[string]any{
		"id": reg.ID.String(), "run_id": latest.ID.String(), "model": "gpt-y",
		"completed_at": stamp(*latest.CompletedAt), "total_cases": 10, "passed": 7, "failed": 3,
		"pass_rate": 0.7, "avg_score": 0.84, "dimension_scores": map[string]float64{"accuracy": 0.8},
		"baseline_id": b.ID.String(), "baseline_pass_rate": 0.9, "baseline_avg_score": 0.85,
		"pass_rate_delta": r["pass_rate_delta"], "avg_score_delta": r["avg_score_delta"],
		"dimension_deltas": map[string]float64{"accuracy": 0}, "missing_dimensions": []string{},
		"regression_threshold": 0.05, "regressed": true, "regression_basis": "aggregate",
	})
	if d := r["pass_rate_delta"].(float64); d > -0.199 || d < -0.201 {
		t.Errorf("pass_rate_delta = %v", d)
	}

	h := got[held.ID.String()]
	if h["regressed"] != false || h["baseline_id"] != hb.ID.String() {
		t.Errorf("held = %v", h)
	}

	m := got[missing.ID.String()]
	if m["regressed"] != true || !slices.Equal(m["missing_dimensions"].([]string), []string{"tone"}) {
		t.Errorf("missing dimension = %v", m)
	}
	if _, ok := m["dimension_deltas"].(map[string]float64)["tone"]; ok {
		t.Errorf("an unmeasured dimension has a delta: %v", m)
	}

	assertJSON(t, got[noBase.ID.String()], map[string]any{
		"id": noBase.ID.String(), "run_id": nbr.ID.String(), "model": "gpt-test",
		"completed_at": stamp(*nbr.CompletedAt), "total_cases": 0, "passed": 0, "failed": 0,
		"pass_rate": 0.5, "avg_score": 0.5, "dimension_scores": map[string]float64{},
		"baseline_id": nil, "baseline_pass_rate": nil, "baseline_avg_score": nil,
		"pass_rate_delta": nil, "avg_score_delta": nil, "dimension_deltas": nil, "missing_dimensions": nil,
		"regression_threshold": 0.05, "regressed": nil, "regression_basis": "aggregate",
	})
	assertJSON(t, got[never.ID.String()], map[string]any{
		"id": never.ID.String(), "run_id": nil, "model": nil,
		"completed_at": nil, "total_cases": nil, "passed": nil, "failed": nil,
		"pass_rate": nil, "avg_score": nil, "dimension_scores": nil,
		"baseline_id": nil, "baseline_pass_rate": nil, "baseline_avg_score": nil,
		"pass_rate_delta": nil, "avg_score_delta": nil, "dimension_deltas": nil, "missing_dimensions": nil,
		"regression_threshold": 0.05, "regressed": nil, "regression_basis": "aggregate",
	})
}

func TestRedTeam(t *testing.T) {
	f := newFixture(t)
	s := f.addSuite(t, &suite.Suite{Name: "guarded"})
	plain := f.addCase(t, s, &testcase.Case{Tags: []string{"smoke"}})
	inj1 := f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "injection"}})
	inj2 := f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "injection"}})
	jb := f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "jailbreak"}})
	leak := f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "leakage"}})

	older := f.addRun(t, s, &evalrun.Run{}, t0)
	f.addResult(t, older, inj1, &evalrun.Result{Status: evalrun.StatusFail})
	run := f.addRun(t, s, &evalrun.Run{}, t0.Add(time.Hour))
	f.addResult(t, run, plain, &evalrun.Result{Status: evalrun.StatusFail})
	f.addResult(t, run, inj1, &evalrun.Result{Status: evalrun.StatusPass})
	f.addResult(t, run, inj2, &evalrun.Result{Status: evalrun.StatusFail})
	f.addResult(t, run, jb, &evalrun.Result{Status: evalrun.StatusError})
	f.addResult(t, run, leak, &evalrun.Result{Status: evalrun.StatusPass})

	waiting := f.addSuite(t, &suite.Suite{Name: "not run yet"})
	f.addCase(t, waiting, &testcase.Case{Tags: []string{"redteam", "offtopic"}})
	f.addSuite(t, &suite.Suite{Name: "no attacks"})

	got := byID(t, New(f.eng), KeyRedTeam)
	if len(got) != 2 {
		t.Fatalf("got %d items, want 2 (suites without red-team cases are left out)", len(got))
	}
	assertJSON(t, got[s.ID.String()], map[string]any{
		"id": s.ID.String(), "run_id": run.ID.String(), "completed_at": stamp(*run.CompletedAt),
		"attacks": 4, "bypasses": 2, "bypass_rate": 0.5,
		"by_type": map[string]any{
			"injection": map[string]int{"total": 2, "bypasses": 1},
			"jailbreak": map[string]int{"total": 1, "bypasses": 1},
			"leakage":   map[string]int{"total": 1, "bypasses": 0},
		},
	})
	assertJSON(t, got[waiting.ID.String()], map[string]any{
		"id": waiting.ID.String(), "run_id": nil, "completed_at": nil,
		"attacks": 0, "bypasses": 0, "bypass_rate": nil, "by_type": map[string]any{},
	})
}

func TestSettings(t *testing.T) {
	s, ok := collectorsOf(t, New(newFixture(t).eng)).snaps[KeySettings]
	if !ok {
		t.Fatal("no settings snapshot")
	}
	got, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertJSON(t, got, map[string]any{"pass_threshold": 0.8, "regression_threshold": 0.05, "default_model": "gpt-test"})
}

func TestEventProofs(t *testing.T) {
	f := newFixture(t)
	if got := collectorsOf(t, New(f.eng)).proofs; len(got) != 0 {
		t.Fatalf("event proofs on by default: %v", got)
	}
	got := collectorsOf(t, New(f.eng, WithEventProofs())).proofs[KeyEvalActivity]
	if got.Stream != adapter.Platform || !slices.Equal(got.Actions, DefaultProofActions) {
		t.Fatalf("proof = %+v", got)
	}
	custom := collectorsOf(t, New(f.eng, WithEventProofs("sentinel.eval.run.completed"))).proofs[KeyEvalActivity]
	if !slices.Equal(custom.Actions, []string{"sentinel.eval.run.completed"}) {
		t.Fatalf("custom actions = %v", custom.Actions)
	}
	if err := New(f.eng, WithEventProofs()).Register(newWitness(t)); err != nil {
		t.Fatal(err)
	}
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	s := f.addSuite(t, &suite.Suite{Name: "agent"})
	other := f.addSuite(t, &suite.Suite{Name: "other app", AppID: otherApp})
	atk := f.addCase(t, s, &testcase.Case{Tags: []string{"redteam", "injection"}})

	staffRun := f.addRun(t, s, &evalrun.Run{PassRate: 1}, t0)
	f.addResult(t, staffRun, atk, &evalrun.Result{Status: evalrun.StatusPass})
	platRun := f.addRun(t, s, &evalrun.Run{PassRate: 0.9, TargetTenantID: platformTenant}, t0.Add(time.Hour))
	f.addResult(t, platRun, atk, &evalrun.Result{Status: evalrun.StatusPass})
	custRun := f.addRun(t, s, &evalrun.Run{PassRate: 0.1, TargetTenantID: customer}, t0.Add(2*time.Hour))
	f.addResult(t, custRun, atk, &evalrun.Result{Status: evalrun.StatusFail})

	cases := []struct {
		name     string
		opts     []Option
		suites   []string
		run      string
		bypasses int
		target   any // target_tenant_id, sent only with AllTenants
	}{
		{"default", []Option{WithAppID(platformApp)}, []string{s.ID.String()}, staffRun.ID.String(), 0, nil},
		{"platform tenant", []Option{WithAppID(platformApp), WithStaffTenants(platformTenant, " ")}, []string{s.ID.String()}, platRun.ID.String(), 0, nil},
		{"explicit list", []Option{WithAppID(platformApp), WithStaffTenants(platformTenant, customer)}, []string{s.ID.String()}, custRun.ID.String(), 1, nil},
		{"all tenants", []Option{WithAppID(platformApp), WithAllTenants()}, []string{s.ID.String()}, custRun.ID.String(), 1, customer},
		{"no app filter", nil, []string{s.ID.String(), other.ID.String()}, staffRun.ID.String(), 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(f.eng, tc.opts...)
			suites := byID(t, a, KeySuites)
			var ids []string
			for k := range suites {
				ids = append(ids, k)
			}
			slices.Sort(ids)
			want := slices.Clone(tc.suites)
			slices.Sort(want)
			if !slices.Equal(ids, want) {
				t.Errorf("suites = %v, want %v", ids, want)
			}
			ls := byID(t, a, KeyLatestScores)[s.ID.String()]
			if ls["run_id"] != tc.run {
				t.Errorf("latest run = %v, want %v", ls["run_id"], tc.run)
			}
			if v, ok := ls["target_tenant_id"]; tc.target == nil && ok || tc.target != nil && v != tc.target {
				t.Errorf("target_tenant_id = %v (sent %v), want %v", v, ok, tc.target)
			}
			rt := byID(t, a, KeyRedTeam)[s.ID.String()]
			if rt["run_id"] != tc.run || rt["bypasses"] != tc.bypasses {
				t.Errorf("red team = %v, want run %v with %d bypasses", rt, tc.run, tc.bypasses)
			}
			if v, ok := rt["target_tenant_id"]; tc.target == nil && ok || tc.target != nil && v != tc.target {
				t.Errorf("red team target_tenant_id = %v (sent %v), want %v", v, ok, tc.target)
			}
		})
	}
}

func TestPages(t *testing.T) {
	f := newFixture(t)
	const n = 2*pageSize + 5
	for i := range n {
		f.addSuite(t, &suite.Suite{Name: fmt.Sprint("s", i)})
	}
	f.addSuite(t, &suite.Suite{Name: "elsewhere", AppID: otherApp})
	if got := len(items(t, New(f.eng, WithAppID(platformApp)), KeySuites)); got != n {
		t.Errorf("suites = %d, want %d", got, n)
	}

	// The newest staff run sits behind more than two pages of runs against
	// a customer's tenant.
	g := newFixture(t)
	s := g.addSuite(t, &suite.Suite{Name: "busy"})
	staffRun := g.addRun(t, s, &evalrun.Run{}, t0)
	for i := range 2*runPageSize + 7 {
		g.addRun(t, s, &evalrun.Run{TargetTenantID: customer}, t0.Add(time.Duration(i+1)*time.Minute))
	}
	if got := byID(t, New(g.eng), KeyLatestScores)[s.ID.String()]["run_id"]; got != staffRun.ID.String() {
		t.Errorf("latest run = %v, want the staff run %v", got, staffRun.ID)
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 5
	t.Cleanup(func() { maxItems = old })

	f := newFixture(t)
	for range 6 {
		f.addSuite(t, &suite.Suite{})
	}
	c := collectorsOf(t, New(f.eng))
	for _, k := range []string{KeySuites, KeyLatestScores, KeyRedTeam} {
		if _, err := c.pops[k].Collect(context.Background()); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: err = %v, want ErrTooMany", k, err)
		}
	}
}

func TestNeverSendsContent(t *testing.T) {
	const canary = "CANARY-5e1d"
	f := newFixture(t)
	s := f.addSuite(t, &suite.Suite{
		Name: "agent", Description: canary + "-suite-desc", SystemPrompt: canary + "-suite-prompt",
		Temperature: 0.4242, Metadata: map[string]any{"note": canary + "-suite-meta"},
	})
	c := f.addCase(t, s, &testcase.Case{
		Name: canary + "-case-name", Input: canary + "-input", Expected: canary + "-expected",
		Tags:     []string{"redteam", "injection"},
		Context:  map[string]any{"doc": canary + "-context"},
		Metadata: map[string]any{"note": canary + "-case-meta"},
		Scorers:  []testcase.ScorerConfig{{Name: "contains", Config: map[string]any{"x": canary + "-scorer-config"}}},
	})
	run := f.addRun(t, s, &evalrun.Run{
		SystemPrompt: canary + "-run-prompt", Config: map[string]any{"k": canary + "-run-config"},
		Error: canary + "-run-error", TotalTokens: 4242421, TotalCost: 4242.4242, AvgLatencyMs: 4242422,
		PassRate: 1, AvgScore: 1,
	}, t0)
	f.addResult(t, run, c, &evalrun.Result{
		CaseName: canary + "-result-name", Status: evalrun.StatusFail, Output: canary + "-output",
		Error:         canary + "-result-error",
		ScorerResults: []evalrun.ScorerResult{{ScorerName: "contains", Reason: canary + "-reason", Details: map[string]any{"x": canary + "-details"}}},
		RunTrace: &evalrun.RunTrace{
			Steps:     []evalrun.StepTrace{{Output: canary + "-step"}},
			ToolCalls: []evalrun.ToolTrace{{ToolName: "t", Arguments: canary + "-args", Result: canary + "-tool-result", Error: canary + "-tool-error"}},
		},
	})
	f.addBaseline(t, s, run, &baseline.Baseline{
		Name: canary + "-baseline-name", PassRate: 1, AvgScore: 1,
		Results: []baseline.Result{{CaseID: c.ID, CaseName: canary + "-baseline-case", Score: 1, Status: "pass"}},
	})

	a := New(f.eng, WithEventProofs())
	col := collectorsOf(t, a)
	out := make([]any, 0, len(col.pops)+len(col.snaps)+len(col.proofs))
	for _, p := range col.pops {
		got, err := p.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			t.Fatalf("%s collected nothing, so the canary proves nothing", p.Key)
		}
		out = append(out, got)
	}
	for _, sn := range col.snaps {
		got, err := sn.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got)
	}
	for _, e := range col.proofs {
		out = append(out, e)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{canary, "4242421", "4242.4242", "4242422", "0.4242"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
	// The red-team result was counted, so its fields were read.
	if !strings.Contains(string(raw), `"bypasses":1`) {
		t.Fatalf("red-team bypass missing: %s", raw)
	}
}

func assertJSON(t *testing.T, got, want any) {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var gv, wv any
	_ = json.Unmarshal(g, &gv)
	_ = json.Unmarshal(w, &wv)
	gj, _ := json.Marshal(gv)
	wj, _ := json.Marshal(wv)
	if string(gj) != string(wj) {
		t.Fatalf("got  %s\nwant %s", gj, wj)
	}
}
