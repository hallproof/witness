package shield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	sh "github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/engine"
	"github.com/xraph/shield/id"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/presets"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	sqlitestore "github.com/xraph/shield/store/sqlite"
	"github.com/xraph/shield/values"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

const (
	app      = "loomplane"
	otherApp = "other-app"
	staff    = "org-staff"
	customer = "org-customer"
	another  = "org-another"
)

// fixture is a shield engine on the library's SQLite store in memory, the
// store shield's own tests use.
type fixture struct {
	eng *engine.Engine
	st  *sqlitestore.Store
}

func newFixture(t *testing.T, opts ...engine.Option) *fixture {
	t.Helper()
	ctx := context.Background()
	d := sqlitedriver.New()
	if err := d.Open(ctx, ":memory:"); err != nil {
		t.Fatal(err)
	}
	db, err := grove.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := sqlitestore.New(db)
	if err = st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(append([]engine.Option{engine.WithStore(st)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{eng: eng, st: st}
}

// in is a context for tenant on app, the way a host writes shield rows.
func in(tenant, appID string) context.Context {
	return sh.WithApp(sh.WithTenant(context.Background(), tenant), appID)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) seed(t *testing.T, tenant string) {
	t.Helper()
	if _, err := presets.InfraAgent().Seed(context.Background(), f.st, tenant, app); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) addProfile(t *testing.T, tenant string, p *profile.SafetyProfile) *profile.SafetyProfile {
	t.Helper()
	p.ID, p.AppID = id.NewSafetyProfileID(), app
	must(t, f.st.CreateProfile(in(tenant, app), p))
	return p
}

func (f *fixture) addPolicy(t *testing.T, tenant string, p *policy.Policy) *policy.Policy {
	t.Helper()
	p.ID = id.NewPolicyID()
	ctx := in(tenant, app)
	if p.ScopeLevel == policy.ScopeApp {
		// App-wide policies are an operator write: no tenant on ctx.
		ctx = sh.WithApp(context.Background(), app)
	}
	must(t, f.st.CreatePolicy(ctx, p))
	return p
}

func (f *fixture) addReport(t *testing.T, r *compliance.Report) *compliance.Report {
	t.Helper()
	r.ID = id.NewComplianceReportID()
	ctx := sh.WithApp(context.Background(), app)
	if r.ScopeLevel == string(policy.ScopeOrg) {
		ctx = in(r.ScopeKey, app)
	}
	must(t, f.st.CreateReport(ctx, r))
	return r
}

func (f *fixture) addScan(t *testing.T, tenant string, r *scan.Result) {
	t.Helper()
	r.ID = id.NewScanID()
	if r.AppID == "" {
		r.AppID = app
	}
	must(t, f.st.CreateScan(in(tenant, r.AppID), r))
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

func (c collected) keys() []string {
	out := make([]string, 0, len(c.pops)+len(c.snaps)+len(c.proofs))
	for k := range c.pops {
		out = append(out, k)
	}
	for k := range c.snaps {
		out = append(out, k)
	}
	for k := range c.proofs {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
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

func byID(items []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, it := range items {
		out[it["id"].(string)] = it
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

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// taken reports whether a collector key is already registered on w.
func taken(t *testing.T, w *witness.Witness, key string) bool {
	t.Helper()
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
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
	must(t, json.Unmarshal(g, &gv))
	must(t, json.Unmarshal(w, &wv))
	gb, _ := json.Marshal(gv)
	wb, _ := json.Marshal(wv)
	if string(gb) != string(wb) {
		t.Fatalf("got  %s\nwant %s", gb, wb)
	}
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func stampOf(at time.Time) string { return at.UTC().Truncate(time.Second).Format(time.RFC3339) }

func tenantsFrom(list ...string) TenantSource {
	return func(context.Context) ([]string, error) { return list, nil }
}

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"shield"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("shield adapter is not registered")
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"nil": nil, "empty vessel": vessel.New(), "not a vessel": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c, Config: map[string]any{"tenants": []any{staff}}})
			if found || err != nil {
				t.Fatalf("attach = %v, %v; want false, nil", found, err)
			}
		})
	}
}

func TestAttachRegistersFromConfig(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	must(t, vessel.ProvideValue(c, f.eng))
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{
		Witness:   w,
		Scope:     adapter.Scope{AppID: "app-identity", TenantID: "platform"},
		Container: c,
		Config:    map[string]any{"tenants": []any{staff}, "app_id": app},
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyEngine, KeyProfiles, KeyChecks, KeyPolicies, KeyReports, KeyScanOutcomes} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
	for _, k := range []string{KeyConformance, KeySafetyActions} {
		if taken(t, w, k) {
			t.Errorf("%s was registered by default", k)
		}
	}
}

func TestAttachWithoutTenantsCollectsEngineOnly(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	must(t, vessel.ProvideValue(c, f.eng))
	w := newWitness(t)
	// The witness scope's app is the platform's identity app, not a shield
	// app, so it never becomes the shield app on its own.
	found, err := attach(context.Background(), adapter.Host{Witness: w, Scope: adapter.Scope{AppID: app}, Container: c})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	if !taken(t, w, KeyEngine) {
		t.Error("engine snapshot was not registered")
	}
	for _, k := range []string{KeyProfiles, KeyChecks, KeyPolicies, KeyReports, KeyScanOutcomes, KeyConformance} {
		if taken(t, w, k) {
			t.Errorf("%s was registered with no tenants", k)
		}
	}
}

func TestAttachWidening(t *testing.T) {
	t.Run("without a tenant source", func(t *testing.T) {
		f := newFixture(t)
		c := vessel.New()
		must(t, vessel.ProvideValue(c, f.eng))
		w := newWitness(t)
		found, err := attach(context.Background(), adapter.Host{Witness: w, Scope: adapter.Scope{AllTenants: true}, Container: c, Config: map[string]any{"tenants": []any{staff}}})
		if !found || err != nil {
			t.Fatalf("attach = %v, %v; want true, nil", found, err)
		}
		if taken(t, w, KeyConformance) {
			t.Error("conformance registered with no way to list tenants")
		}
		if !taken(t, w, KeyProfiles) {
			t.Error("staff collectors dropped when widening failed")
		}
	})
	t.Run("with a tenant source in the container", func(t *testing.T) {
		f := newFixture(t)
		c := vessel.New()
		must(t, vessel.ProvideValue(c, f.eng))
		must(t, vessel.ProvideValue(c, tenantsFrom(staff, customer)))
		w := newWitness(t)
		found, err := attach(context.Background(), adapter.Host{Witness: w, Scope: adapter.Scope{AllTenants: true}, Container: c})
		if !found || err != nil {
			t.Fatalf("attach = %v, %v; want true, nil", found, err)
		}
		if !taken(t, w, KeyConformance) {
			t.Error("conformance was not registered")
		}
	})
}

func TestRegisterWideningNeedsATenantSource(t *testing.T) {
	f := newFixture(t)
	if err := New(f.eng, WithAllTenants()).Register(newWitness(t)); !errors.Is(err, ErrNoTenantSource) {
		t.Fatalf("Register = %v, want ErrNoTenantSource", err)
	}
}

func TestEngine(t *testing.T) {
	cfg := sh.DefaultConfig()
	cfg.DefaultProfile = "infra-agent-input"
	cfg.MaxScanBytes = 2048
	cfg.ProfileCacheTTL = time.Minute
	cfg.StoreRedacted = true
	cfg.JudgeTimeout = 3 * time.Second
	f := newFixture(t, engine.WithConfig(cfg))
	got := settings(t, New(f.eng), KeyEngine)
	caps := f.eng.Capabilities()
	assertJSON(t, got, map[string]any{
		"default_profile":           "infra-agent-input",
		"enable_short_circuit":      true,
		"max_scan_bytes":            2048,
		"profile_cache_ttl_seconds": 60,
		"store_redacted":            true,
		"model_judge":               false,
		"judge_timeout_seconds":     3,
		"capabilities": map[string]any{
			"persistence":        true,
			"tool_calls":         true,
			"model_judge":        false,
			"unavailable_layers": []string{},
			"supported":          caps.Supported,
		},
	})

	cfg.ProfileCacheTTL = -time.Nanosecond
	off := settings(t, New(newFixture(t, engine.WithConfig(cfg)).eng), KeyEngine)
	if fmt.Sprint(off["profile_cache_ttl_seconds"]) != "-1" {
		t.Errorf("a disabled profile cache is %v, want -1", off["profile_cache_ttl_seconds"])
	}
}

func TestEngineSnapshotCanBeTurnedOff(t *testing.T) {
	f := newFixture(t)
	if _, ok := collectorsOf(t, New(f.eng)).snaps[KeyEngine]; !ok {
		t.Fatal("engine snapshot off by default")
	}
	if got := collectorsOf(t, New(f.eng, WithoutEngineSnapshot())).keys(); len(got) != 0 {
		t.Fatalf("collectors with the engine snapshot off and no tenants = %v", got)
	}
	var o Options
	must(t, adapter.Decode(map[string]any{"engine_snapshot": false}, &o))
	if _, ok := collectorsOf(t, newAdapter(f.eng, o)).snaps[KeyEngine]; ok {
		t.Fatal("engine_snapshot: false left the snapshot on")
	}
}

func TestNoStoreCollectsEngineOnly(t *testing.T) {
	eng, err := engine.New()
	must(t, err)
	got := collectorsOf(t, New(eng, WithTenants(staff), WithAppID(app)))
	if !slices.Equal(got.keys(), []string{KeyEngine}) {
		t.Fatalf("collectors = %v, want the engine snapshot only", got.keys())
	}
}

func TestProfiles(t *testing.T) {
	f := newFixture(t)
	p := f.addProfile(t, staff, &profile.SafetyProfile{
		Name: "tools",
		Instincts: []profile.InstinctAssignment{
			{InstinctName: "prompt-injection", Sensitivity: instinct.SensitivityCautious},
			{InstinctName: "jailbreak"},
		},
		Judgments:  []profile.JudgmentAssignment{{JudgmentName: "pressure", Threshold: 0.9}},
		Awareness:  []profile.AwarenessAssignment{{AwarenessName: "secrets"}},
		Values:     []string{"destructive"},
		Reflexes:   []string{"approve-destructive"},
		Boundaries: []string{"agent-actions"},
		Enabled:    true,
	})
	bare := f.addProfile(t, staff, &profile.SafetyProfile{Name: "bare"})

	got := byID(items(t, New(f.eng, WithTenants(staff), WithAppID(app)), KeyProfiles))
	if len(got) != 2 {
		t.Fatalf("got %d profiles, want 2", len(got))
	}
	assertJSON(t, got[p.ID.String()], map[string]any{
		"id": p.ID.String(), "name": "tools", "app_id": app, "tenant_id": staff, "enabled": true,
		"instincts":  []map[string]any{{"name": "prompt-injection", "sensitivity": "cautious"}, {"name": "jailbreak", "sensitivity": ""}},
		"judgments":  []map[string]any{{"name": "pressure", "threshold": 0.9}},
		"awareness":  []string{"secrets"},
		"values":     []string{"destructive"},
		"reflexes":   []string{"approve-destructive"},
		"boundaries": []string{"agent-actions"},
		"created_at": stampOf(p.CreatedAt), "updated_at": stampOf(p.UpdatedAt),
	})
	assertJSON(t, got[bare.ID.String()], map[string]any{
		"id": bare.ID.String(), "name": "bare", "app_id": app, "tenant_id": staff, "enabled": false,
		"instincts": []any{}, "judgments": []any{}, "awareness": []any{}, "values": []any{},
		"reflexes": []any{}, "boundaries": []any{},
		"created_at": stampOf(bare.CreatedAt), "updated_at": stampOf(bare.UpdatedAt),
	})
}

func TestChecks(t *testing.T) {
	f := newFixture(t)
	ctx := in(staff, app)
	inst := &instinct.Instinct{
		ID: id.NewInstinctID(), Name: "prompt-injection", AppID: app, Category: instinct.CategoryInjection,
		Strategies:  []instinct.Strategy{{Name: "patterns", Weight: 0.5}, {Name: "canary"}},
		Sensitivity: instinct.SensitivityBalanced, Action: instinct.ActionRedact, Enabled: true,
	}
	must(t, f.st.CreateInstinct(ctx, inst))
	aw := &awareness.Awareness{
		ID: id.NewAwarenessID(), Name: "pii", AppID: app, Focus: awareness.FocusPII, Action: "redact", Enabled: true,
		Detectors: []awareness.Detector{{Name: "email", Focus: awareness.FocusPII}, {Name: "iban", Focus: awareness.FocusPII}},
	}
	must(t, f.st.CreateAwareness(ctx, aw))
	allAw := &awareness.Awareness{ID: id.NewAwarenessID(), Name: "secrets", AppID: app, Focus: awareness.FocusSecrets, Action: "block"}
	must(t, f.st.CreateAwareness(ctx, allAw))
	jd := &judgment.Judgment{
		ID: id.NewJudgmentID(), Name: "pressure", AppID: app, Domain: judgment.DomainCustom, Threshold: 0.9, Action: "flag", Enabled: true,
		Assessors: []judgment.Assessor{{Name: "layer_score", Domain: judgment.DomainCustom, Weight: 1}},
	}
	must(t, f.st.CreateJudgment(ctx, jd))
	vl := &values.Values{
		ID: id.NewValueID(), Name: "destructive", AppID: app, Severity: "warning", Action: "flag", Enabled: true,
		Rules: []values.Rule{{Principle: values.PrincipleSafety, Threshold: 0.5, Categories: []string{"infra"}}},
	}
	must(t, f.st.CreateValues(ctx, vl))
	rx := &reflex.Reflex{
		ID: id.NewReflexID(), Name: "approve-destructive", AppID: app, Priority: 5, Enabled: true,
		Triggers: []reflex.Trigger{
			{Type: reflex.TriggerOnContext, Pattern: "risk_class=destroy_production"},
			{Type: reflex.TriggerOnRate, Threshold: 10, Window: "1m"},
		},
		Actions: []reflex.Action{{Type: reflex.ActionLog, Target: "output"}, {Type: reflex.ActionEscalate}},
	}
	must(t, f.st.CreateReflex(ctx, rx))
	quiet := &reflex.Reflex{
		ID: id.NewReflexID(), Name: "log-only", AppID: app, Enabled: true,
		Triggers: []reflex.Trigger{{Type: reflex.TriggerOnPattern, Pattern: "(?i)drop table"}},
		Actions:  []reflex.Action{{Type: reflex.ActionFlag}},
	}
	must(t, f.st.CreateReflex(ctx, quiet))
	bd := &boundary.Boundary{
		ID: id.NewBoundaryID(), Name: "agent-actions", AppID: app, Enabled: true,
		Limits: []boundary.Limit{
			{Scope: boundary.ScopeAction, Deny: []string{"a", "b"}},
			{Scope: boundary.ScopeTopic, Allow: []string{"x"}, UseAllow: true},
		},
	}
	must(t, f.st.CreateBoundary(ctx, bd))

	got := byID(items(t, New(f.eng, WithTenants(staff), WithAppID(app)), KeyChecks))
	if len(got) != 8 {
		t.Fatalf("got %d checks, want 8: %v", len(got), ids(items(t, New(f.eng, WithTenants(staff)), KeyChecks)))
	}
	common := func(kind, shieldID, name string, at time.Time, more map[string]any) map[string]any {
		m := map[string]any{
			"id": kind + ":" + shieldID, "kind": kind, "name": name, "app_id": app, "tenant_id": staff,
			"created_at": stampOf(at), "updated_at": stampOf(at),
		}
		for k, v := range more {
			m[k] = v
		}
		return m
	}
	want := []map[string]any{
		common("instinct", inst.ID.String(), "prompt-injection", inst.CreatedAt, map[string]any{
			"category": "injection", "sensitivity": "balanced", "action": "redact", "enabled": true,
			"strategies": []string{"patterns", "canary"},
		}),
		common("awareness", aw.ID.String(), "pii", aw.CreatedAt, map[string]any{
			"focus": "pii", "action": "redact", "enabled": true, "detectors": []string{"email", "iban"},
		}),
		common("awareness", allAw.ID.String(), "secrets", allAw.CreatedAt, map[string]any{
			"focus": "secrets", "action": "block", "enabled": false, "detectors": []string{},
		}),
		common("judgment", jd.ID.String(), "pressure", jd.CreatedAt, map[string]any{
			"domain": "custom", "threshold": 0.9, "action": "flag", "enabled": true,
			"assessors": []map[string]any{{"name": "layer_score", "domain": "custom", "weight": 1}},
		}),
		common("values", vl.ID.String(), "destructive", vl.CreatedAt, map[string]any{
			"severity": "warning", "action": "flag", "enabled": true,
			"rules": []map[string]any{{"principle": "safety", "threshold": 0.5, "categories": []string{"infra"}}},
		}),
		common("reflex", rx.ID.String(), "approve-destructive", rx.CreatedAt, map[string]any{
			"priority": 5, "enabled": true, "escalates": true,
			"triggers": []map[string]any{
				{"type": "on_context", "threshold": 0, "window": "", "risk_class": "destroy_production"},
				{"type": "on_rate", "threshold": 10, "window": "1m", "risk_class": ""},
			},
			"actions": []map[string]any{{"type": "log", "target_sha256": sum("output")}, {"type": "escalate", "target_sha256": ""}},
		}),
		common("reflex", quiet.ID.String(), "log-only", quiet.CreatedAt, map[string]any{
			"priority": 0, "enabled": true, "escalates": false,
			"triggers": []map[string]any{{"type": "on_pattern", "threshold": 0, "window": "", "risk_class": ""}},
			"actions":  []map[string]any{{"type": "flag", "target_sha256": ""}},
		}),
		common("boundary", bd.ID.String(), "agent-actions", bd.CreatedAt, map[string]any{
			"enabled": true,
			"limits": []map[string]any{
				{"scope": "action", "use_allow": false, "deny_count": 2, "allow_count": 0},
				{"scope": "topic", "use_allow": true, "deny_count": 0, "allow_count": 1},
			},
		}),
	}
	for _, w := range want {
		assertJSON(t, got[w["id"].(string)], w)
	}
}

func TestChecksShowWhichRiskClassesNeedApproval(t *testing.T) {
	f := newFixture(t)
	f.seed(t, staff)
	var classes []string
	for _, it := range items(t, New(f.eng, WithTenants(staff), WithAppID(app)), KeyChecks) {
		if it["kind"] != "reflex" || it["escalates"] != true {
			continue
		}
		for _, tr := range it["triggers"].([]map[string]any) {
			classes = append(classes, tr["risk_class"].(string))
		}
	}
	slices.Sort(classes)
	if want := []string{presets.RiskDestroyProduction, presets.RiskSecretOrExternal}; !slices.Equal(classes, want) {
		t.Fatalf("escalated risk classes = %v, want %v", classes, want)
	}
}

func TestRiskClass(t *testing.T) {
	for pattern, want := range map[string]string{
		"risk_class=destroy_production": "destroy_production",
		"risk_class=read":               "read",
		"risk_class=Destroy":            "",
		"risk_class=a b":                "",
		"risk_class=":                   "",
		"tenant=org_1":                  "",
		" risk_class=read":              "",
	} {
		if got := riskClass(reflex.Trigger{Type: reflex.TriggerOnContext, Pattern: pattern}); got != want {
			t.Errorf("riskClass(%q) = %q, want %q", pattern, got, want)
		}
	}
	if got := riskClass(reflex.Trigger{Type: reflex.TriggerOnPattern, Pattern: "risk_class=read"}); got != "" {
		t.Errorf("an on_pattern trigger gave risk class %q", got)
	}
}

func TestPolicies(t *testing.T) {
	f := newFixture(t)
	org := f.addPolicy(t, staff, &policy.Policy{
		Name: "baseline", ScopeKey: staff, ScopeLevel: policy.ScopeOrg, Enabled: true,
		Rules: []policy.Rule{
			{CheckType: "awareness", Condition: policy.ConditionSecretDetected, Action: "redact"},
			{CheckType: "instinct", Action: "block", Priority: 3},
		},
	})
	appWide := f.addPolicy(t, "", &policy.Policy{Name: "app wide", ScopeKey: app, ScopeLevel: policy.ScopeApp})
	f.addPolicy(t, "", &policy.Policy{Name: "other app", ScopeKey: otherApp, ScopeLevel: policy.ScopeApp})

	got := byID(items(t, New(f.eng, WithTenants(staff), WithAppID(app)), KeyPolicies))
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}
	assertJSON(t, got[org.ID.String()], map[string]any{
		"id": org.ID.String(), "name": "baseline", "scope_level": "org", "scope_key": staff, "enabled": true,
		"rules": []map[string]any{
			{"check_type": "awareness", "action": "redact", "priority": 0, "condition_sha256": sum(policy.ConditionSecretDetected)},
			{"check_type": "instinct", "action": "block", "priority": 3, "condition_sha256": ""},
		},
		"created_at": stampOf(org.CreatedAt), "updated_at": stampOf(org.UpdatedAt),
	})
	assertJSON(t, got[appWide.ID.String()], map[string]any{
		"id": appWide.ID.String(), "name": "app wide", "scope_level": "app", "scope_key": app, "enabled": false,
		"rules": []any{}, "created_at": stampOf(appWide.CreatedAt), "updated_at": stampOf(appWide.UpdatedAt),
	})

	noApp := items(t, New(f.eng, WithTenants(staff)), KeyPolicies)
	if want := []string{org.ID.String()}; !slices.Equal(ids(noApp), want) {
		t.Fatalf("policies with no app = %v, want the org policy only", ids(noApp))
	}
}

func TestComplianceReports(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC)
	org := f.addReport(t, &compliance.Report{
		Framework: compliance.FrameworkSOC2, ScopeKey: staff, ScopeLevel: "org",
		PeriodStart: start, PeriodEnd: end, GeneratedAt: end.Add(time.Hour),
		Summary: map[string]any{"total_scans": 120, "block_rate": 0.25, "passing": true, "note": "dropped", "nested": map[string]any{"x": 1}},
	})
	appRep := f.addReport(t, &compliance.Report{
		Framework: compliance.FrameworkNIST, ScopeKey: app, ScopeLevel: "app",
		PeriodStart: start, PeriodEnd: end, GeneratedAt: end,
	})
	f.addReport(t, &compliance.Report{Framework: compliance.FrameworkSOC2, ScopeKey: otherApp, ScopeLevel: "app", PeriodStart: start, PeriodEnd: end, GeneratedAt: end})

	got := byID(items(t, New(f.eng, WithTenants(staff), WithAppID(app)), KeyReports))
	if len(got) != 2 {
		t.Fatalf("got %d reports, want 2", len(got))
	}
	assertJSON(t, got[org.ID.String()], map[string]any{
		"id": org.ID.String(), "framework": "soc2", "scope_level": "org", "scope_key": staff,
		"period_start": "2026-10-01T00:00:00Z", "period_end": "2026-10-31T23:59:59Z", "generated_at": "2026-11-01T00:59:59Z",
		"summary": map[string]any{"total_scans": 120, "block_rate": 0.25, "passing": true},
	})
	assertJSON(t, got[appRep.ID.String()], map[string]any{
		"id": appRep.ID.String(), "framework": "nist_ai_rmf", "scope_level": "app", "scope_key": app,
		"period_start": "2026-10-01T00:00:00Z", "period_end": "2026-10-31T23:59:59Z", "generated_at": "2026-10-31T23:59:59Z",
		"summary": map[string]any{},
	})
}

func TestScanOutcomes(t *testing.T) {
	f := newFixture(t)
	add := func(tenant, appID string, dir scan.Direction, dec scan.Decision) {
		f.addScan(t, tenant, &scan.Result{AppID: appID, Direction: dir, Decision: dec, Blocked: dec == scan.DecisionBlock})
	}
	add(staff, app, scan.DirectionInput, scan.DecisionBlock)
	add(staff, app, scan.DirectionInput, scan.DecisionAllow)
	add(staff, app, scan.DirectionOutput, scan.DecisionFlag)
	add(another, app, scan.DirectionOutput, scan.DecisionAllow)
	add(customer, app, scan.DirectionInput, scan.DecisionBlock)
	add(staff, otherApp, scan.DirectionInput, scan.DecisionBlock)

	// Scans are stamped now, so "yesterday" is today when the clock runs a
	// day ahead.
	old := now
	now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	t.Cleanup(func() { now = old })
	today := time.Now().UTC().Format(time.DateOnly)

	got := settings(t, New(f.eng, WithTenants(staff, another), WithAppID(app)), KeyScanOutcomes)
	assertJSON(t, got, map[string]any{
		"day": today, "total_scans": 4, "blocked": 1, "flagged": 1, "allowed": 2,
		"by_direction": map[string]any{"input": 2, "output": 2},
		"by_decision":  map[string]any{"block": 1, "allow": 2, "flag": 1},
	})

	now = time.Now // yesterday really is yesterday: nothing ran
	empty := settings(t, New(f.eng, WithTenants(staff), WithAppID(app)), KeyScanOutcomes)
	if fmt.Sprint(empty["total_scans"]) != "0" {
		t.Fatalf("scans from today counted for yesterday: %v", empty)
	}
}

func TestTenantConformance(t *testing.T) {
	f := newFixture(t)
	f.seed(t, staff)
	f.seed(t, customer)
	f.seed(t, another)
	// One workspace changed its preset.
	r, err := f.st.GetReflexByName(in(another, app), app, "approve-destructive")
	must(t, err)
	r.Enabled = false
	must(t, f.st.UpdateReflex(in(another, app), r))

	got := settings(t, New(f.eng, WithTenants(staff), WithAppID(app), WithAllTenants(), WithTenantSource(tenantsFrom(staff, customer, another, "org-empty", staff))), KeyConformance)
	confs := got["configurations"].([]map[string]any)
	if len(confs) != 3 {
		t.Fatalf("configurations = %v", confs)
	}
	if confs[0]["tenants"] != 2 || confs[1]["tenants"] != 1 || confs[2]["tenants"] != 1 {
		t.Fatalf("configurations not counted or ordered: %v", confs)
	}
	if got["tenants"] != 4 || got["distinct_configurations"] != 3 || got["tenants_without_profiles"] != 1 {
		t.Fatalf("conformance = %v", got)
	}
	raw, err := json.Marshal(got)
	must(t, err)
	for _, org := range []string{staff, customer, another, "org-empty"} {
		if strings.Contains(string(raw), org) {
			t.Fatalf("conformance names tenant %q: %s", org, raw)
		}
	}
}

func TestEventProofs(t *testing.T) {
	f := newFixture(t)
	if got := collectorsOf(t, New(f.eng, WithTenants(staff))).proofs; len(got) != 0 {
		t.Fatalf("event proofs on by default: %v", got)
	}
	got := collectorsOf(t, New(f.eng, WithEventProofs())).proofs[KeySafetyActions]
	if got.Stream != adapter.Platform || !slices.Equal(got.Actions, DefaultProofActions) || len(got.Tests) != 0 {
		t.Fatalf("proof = %+v", got)
	}
	if slices.Contains(got.Actions, "shield.policy.created") {
		t.Fatal("the mislabelled shield.policy.created is cited")
	}
	custom := collectorsOf(t, New(f.eng, WithEventProofs("shield.scan.blocked"))).proofs[KeySafetyActions]
	if !slices.Equal(custom.Actions, []string{"shield.scan.blocked"}) {
		t.Fatalf("custom actions = %v", custom.Actions)
	}
	must(t, New(f.eng, WithTenants(staff), WithEventProofs()).Register(newWitness(t)))
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	f.seed(t, staff)
	f.seed(t, customer)
	f.addPolicy(t, customer, &policy.Policy{Name: "customer own", ScopeKey: customer, ScopeLevel: policy.ScopeOrg})
	f.addReport(t, &compliance.Report{Framework: compliance.FrameworkSOC2, ScopeKey: customer, ScopeLevel: "org", PeriodStart: time.Now(), PeriodEnd: time.Now(), GeneratedAt: time.Now()})
	f.addReport(t, &compliance.Report{Framework: compliance.FrameworkSOC2, ScopeKey: staff, ScopeLevel: "org", PeriodStart: time.Now(), PeriodEnd: time.Now(), GeneratedAt: time.Now()})
	f.addScan(t, customer, &scan.Result{Direction: scan.DirectionInput, Decision: scan.DecisionBlock})
	f.addScan(t, staff, &scan.Result{Direction: scan.DirectionInput, Decision: scan.DecisionAllow})
	old := now
	now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	t.Cleanup(func() { now = old })

	tenantsIn := func(t *testing.T, a *Adapter) map[string]bool {
		t.Helper()
		seen := map[string]bool{}
		for _, k := range []string{KeyProfiles, KeyChecks} {
			for _, it := range items(t, a, k) {
				seen[it["tenant_id"].(string)] = true
			}
		}
		for _, k := range []string{KeyPolicies, KeyReports} {
			for _, it := range items(t, a, k) {
				if it["scope_level"] == "org" {
					seen[it["scope_key"].(string)] = true
				}
			}
		}
		return seen
	}

	t.Run("default", func(t *testing.T) {
		a := New(f.eng, WithTenants(staff), WithAppID(app))
		if got := tenantsIn(t, a); !got[staff] || got[customer] || len(got) != 1 {
			t.Fatalf("tenants = %v, want staff only", got)
		}
		if s := settings(t, a, KeyScanOutcomes); fmt.Sprint(s["total_scans"]) != "1" || fmt.Sprint(s["blocked"]) != "0" {
			t.Fatalf("scan outcomes counted the customer: %v", s)
		}
		if _, ok := collectorsOf(t, a).snaps[KeyConformance]; ok {
			t.Fatal("conformance on by default")
		}
		raw, err := json.Marshal(collectAll(t, a))
		must(t, err)
		if strings.Contains(string(raw), customer) {
			t.Fatalf("customer tenant in default output: %s", raw)
		}
	})
	t.Run("explicit list", func(t *testing.T) {
		a := New(f.eng, WithTenants(staff, customer, " ", staff), WithAppID(app))
		if got := tenantsIn(t, a); !got[staff] || !got[customer] || len(got) != 2 {
			t.Fatalf("tenants = %v, want staff and customer", got)
		}
		if s := settings(t, a, KeyScanOutcomes); fmt.Sprint(s["total_scans"]) != "2" {
			t.Fatalf("scan outcomes = %v", s)
		}
	})
	t.Run("all tenants", func(t *testing.T) {
		a := New(f.eng, WithTenants(staff), WithAppID(app), WithAllTenants(), WithTenantSource(tenantsFrom(staff, customer)))
		if got := tenantsIn(t, a); !got[staff] || got[customer] {
			t.Fatalf("rows widened past the configured tenants: %v", got)
		}
		s := settings(t, a, KeyConformance)
		if s["tenants"] != 2 || s["distinct_configurations"] != 2 {
			// The customer has its own org policy on top of the preset.
			t.Fatalf("conformance = %v", s)
		}
	})
	t.Run("no tenants", func(t *testing.T) {
		got := collectorsOf(t, New(f.eng, WithAppID(app)))
		// App-wide policies and reports are company configuration.
		if want := []string{KeyEngine, KeyReports, KeyPolicies}; !sameSet(got.keys(), want) {
			t.Fatalf("collectors = %v, want %v", got.keys(), want)
		}
	})
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func collectAll(t *testing.T, a *Adapter) []any {
	t.Helper()
	c := collectorsOf(t, a)
	out := make([]any, 0, len(c.pops)+len(c.snaps)+len(c.proofs))
	for _, p := range c.pops {
		got, err := p.Collect(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", p.Key, err)
		}
		out = append(out, got)
	}
	for _, s := range c.snaps {
		got, err := s.Collect(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", s.Key, err)
		}
		out = append(out, got)
	}
	for _, e := range c.proofs {
		out = append(out, e)
	}
	return out
}

func TestPages(t *testing.T) {
	old := pageSize
	pageSize = 7
	t.Cleanup(func() { pageSize = old })

	f := newFixture(t)
	const n = 3*7 + 2
	for i := range n {
		f.addProfile(t, staff, &profile.SafetyProfile{Name: fmt.Sprint("p", i)})
		must(t, f.st.CreateInstinct(in(staff, app), &instinct.Instinct{ID: id.NewInstinctID(), Name: fmt.Sprint("i", i), AppID: app, Category: "injection", Action: "flag"}))
		must(t, f.st.CreateBoundary(in(staff, app), &boundary.Boundary{ID: id.NewBoundaryID(), Name: fmt.Sprint("b", i), AppID: app}))
		f.addPolicy(t, staff, &policy.Policy{Name: fmt.Sprint("o", i), ScopeKey: staff, ScopeLevel: policy.ScopeOrg})
		f.addPolicy(t, "", &policy.Policy{Name: fmt.Sprint("a", i), ScopeKey: app, ScopeLevel: policy.ScopeApp})
		f.addReport(t, &compliance.Report{Framework: compliance.FrameworkSOC2, ScopeKey: staff, ScopeLevel: "org", PeriodStart: time.Now(), PeriodEnd: time.Now(), GeneratedAt: time.Now()})
	}
	f.addProfile(t, customer, &profile.SafetyProfile{Name: "customer"})
	a := New(f.eng, WithTenants(staff), WithAppID(app))
	for key, want := range map[string]int{KeyProfiles: n, KeyChecks: 2 * n, KeyPolicies: 2 * n, KeyReports: n} {
		if got := len(items(t, a, key)); got != want {
			t.Errorf("%s = %d items, want %d", key, got, want)
		}
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 3
	t.Cleanup(func() { maxItems = old })

	f := newFixture(t)
	for i := range 4 {
		f.addProfile(t, staff, &profile.SafetyProfile{Name: fmt.Sprint("p", i)})
		must(t, f.st.CreateInstinct(in(staff, app), &instinct.Instinct{ID: id.NewInstinctID(), Name: fmt.Sprint("i", i), AppID: app, Category: "injection", Action: "flag"}))
		f.addPolicy(t, staff, &policy.Policy{Name: fmt.Sprint("o", i), ScopeKey: staff, ScopeLevel: policy.ScopeOrg})
		f.addReport(t, &compliance.Report{Framework: compliance.FrameworkSOC2, ScopeKey: staff, ScopeLevel: "org", PeriodStart: time.Now(), PeriodEnd: time.Now(), GeneratedAt: time.Now()})
	}
	c := collectorsOf(t, New(f.eng, WithTenants(staff), WithAppID(app)))
	for _, k := range []string{KeyProfiles, KeyChecks, KeyPolicies, KeyReports} {
		if _, err := c.pops[k].Collect(context.Background()); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: err = %v, want ErrTooMany", k, err)
		}
	}
}

func TestReadErrorsFailTheRun(t *testing.T) {
	f := newFixture(t)
	failing := func(context.Context) ([]string, error) { return nil, errors.New("directory down") }
	c := collectorsOf(t, New(f.eng, WithAllTenants(), WithTenantSource(failing)))
	if _, err := c.snaps[KeyConformance].Collect(context.Background()); err == nil {
		t.Fatal("a failed tenant listing passed")
	}
}

func TestNeverSendsContent(t *testing.T) {
	const canary = "CANARY-5h1e"
	f := newFixture(t)
	ctx := in(staff, app)
	meta := func(where string) map[string]any {
		return map[string]any{"note": canary + "-" + where + "-meta", "nested": map[string]any{"x": canary + "-" + where + "-nested"}}
	}
	must(t, f.st.CreateInstinct(ctx, &instinct.Instinct{
		ID: id.NewInstinctID(), Name: "canary-trap", AppID: app, Category: instinct.CategoryExfiltration, Action: "block", Enabled: true,
		Description: canary + "-inst-desc", Metadata: meta("inst"),
		Strategies: []instinct.Strategy{{Name: "canary", Config: map[string]any{"token": canary + "-canary-token", "patterns": []any{canary + "-regex"}}}},
	}))
	must(t, f.st.CreateAwareness(ctx, &awareness.Awareness{
		ID: id.NewAwarenessID(), Name: "custom", AppID: app, Focus: awareness.FocusCustom, Action: "flag", Enabled: true,
		Description: canary + "-aw-desc", Metadata: meta("aw"),
		Detectors: []awareness.Detector{{Name: "acct", Focus: awareness.FocusCustom, Patterns: []string{canary + `-\d+`}, Config: map[string]any{"x": canary + "-det-config"}}},
	}))
	must(t, f.st.CreateValues(ctx, &values.Values{
		ID: id.NewValueID(), Name: "brand", AppID: app, Action: "flag", Enabled: true,
		Description: canary + "-val-desc", Metadata: meta("val"),
		Rules: []values.Rule{{Principle: values.PrincipleBrandSafety, Guidelines: []string{canary + "-guideline"}, Config: map[string]any{"x": canary + "-val-config"}}},
	}))
	must(t, f.st.CreateJudgment(ctx, &judgment.Judgment{
		ID: id.NewJudgmentID(), Name: "judge", AppID: app, Domain: judgment.DomainGrounding, Action: "warn", Enabled: true,
		Description: canary + "-jd-desc", Metadata: meta("jd"),
		Assessors: []judgment.Assessor{{Name: "model", Domain: judgment.DomainGrounding, Config: map[string]any{"prompt": canary + "-judge-prompt"}}},
	}))
	must(t, f.st.CreateReflex(ctx, &reflex.Reflex{
		ID: id.NewReflexID(), Name: "trap", AppID: app, Enabled: true,
		Description: canary + "-rx-desc", Metadata: meta("rx"),
		Triggers: []reflex.Trigger{
			{Type: reflex.TriggerOnPattern, Pattern: canary + "-pattern"},
			{Type: reflex.TriggerOnContext, Pattern: "risk_class=" + canary},
			{Type: reflex.TriggerOnRate, Window: canary + "-window"},
		},
		Actions: []reflex.Action{
			{Type: reflex.ActionRewrite, Value: canary + "-value", Fallback: canary + "-fallback"},
			// A redact action's target is the regex shield redacts with.
			{Type: reflex.ActionRedact, Target: canary + `-target-\d+`},
		},
	}))
	must(t, f.st.CreateBoundary(ctx, &boundary.Boundary{
		ID: id.NewBoundaryID(), Name: "fence", AppID: app, Enabled: true,
		Description: canary + "-bd-desc", Metadata: meta("bd"), Response: canary + "-response",
		Limits: []boundary.Limit{{Scope: boundary.ScopeTopic, Deny: []string{canary + "-deny"}, Allow: []string{canary + "-allow"}}},
	}))
	f.addProfile(t, staff, &profile.SafetyProfile{Name: "p", Description: canary + "-prof-desc", Metadata: meta("prof"), Enabled: true})
	f.addPolicy(t, staff, &policy.Policy{
		Name: "pol", ScopeKey: staff, ScopeLevel: policy.ScopeOrg, Enabled: true,
		Description: canary + "-pol-desc", Metadata: meta("pol"),
		Rules: []policy.Rule{{CheckType: "awareness", Condition: "text contains " + canary + "-condition", Action: "block", ErrorMessage: canary + "-error-message"}},
	})
	f.addReport(t, &compliance.Report{
		Framework: compliance.FrameworkSOC2, ScopeKey: staff, ScopeLevel: "org", PeriodStart: time.Now(), PeriodEnd: time.Now(), GeneratedAt: time.Now(),
		Summary: map[string]any{"count": 3, "note": canary + "-summary", "nested": map[string]any{"x": canary + "-summary-nested"}},
		Details: map[string]any{"x": canary + "-details"},
	})
	f.addScan(t, staff, &scan.Result{
		Direction: scan.DirectionInput, Decision: scan.DecisionBlock, Blocked: true, Redacted: canary + "-redacted",
		Findings: []*scan.Finding{{Layer: "instinct", Source: "trap", Message: canary + "-finding", Details: map[string]any{"match": canary + "-match"}}},
		Metadata: meta("scan"),
	})
	f.seed(t, customer)

	old := now
	now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	t.Cleanup(func() { now = old })

	a := New(f.eng, WithTenants(staff), WithAppID(app), WithAllTenants(), WithTenantSource(tenantsFrom(staff, customer)), WithEventProofs())
	if got, want := collectorsOf(t, a).keys(), []string{KeyReports, KeyChecks, KeyConformance, KeyEngine, KeyPolicies, KeyProfiles, KeySafetyActions, KeyScanOutcomes}; !sameSet(got, want) {
		t.Fatalf("collectors = %v, want every one: %v", got, want)
	}
	raw, err := json.Marshal(collectAll(t, a))
	must(t, err)
	if strings.Contains(string(raw), "CANARY") {
		i := strings.Index(string(raw), "CANARY")
		t.Fatalf("content reached the output near %q", string(raw)[max(0, i-120):min(len(raw), i+60)])
	}
	if !strings.Contains(string(raw), sum("text contains "+canary+"-condition")) {
		t.Fatal("the policy condition hash is missing")
	}
}
