package nexus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	nx "github.com/xraph/nexus"
	"github.com/xraph/nexus/guard"
	"github.com/xraph/nexus/id"
	"github.com/xraph/nexus/key"
	"github.com/xraph/nexus/model"
	"github.com/xraph/nexus/money"
	"github.com/xraph/nexus/provider"
	"github.com/xraph/nexus/store"
	"github.com/xraph/nexus/tenant"
	"github.com/xraph/nexus/usage"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

const canary = "CANARY-9c1d"

var t0 = time.Date(2026, 10, 1, 9, 30, 15, 123456789, time.UTC)

// fakeProvider is a provider that fails the test if the adapter calls the
// vendor. BaseURL and APIKey stand in for a real provider's settings and
// must never reach the output.
type fakeProvider struct {
	t       *testing.T
	name    string
	caps    provider.Capabilities
	BaseURL string
	APIKey  string
}

func (p *fakeProvider) Name() string                        { return p.name }
func (p *fakeProvider) Capabilities() provider.Capabilities { return p.caps }

func (p *fakeProvider) Models(context.Context) ([]provider.Model, error) {
	p.t.Error("the adapter listed a provider's models, which calls the vendor")
	return []provider.Model{{ID: canary + "-remote-model"}}, nil
}

func (p *fakeProvider) Complete(context.Context, *provider.CompletionRequest) (*provider.CompletionResponse, error) {
	p.t.Error("the adapter called a provider")
	return nil, errors.New("no")
}

func (p *fakeProvider) CompleteStream(context.Context, *provider.CompletionRequest) (provider.Stream, error) {
	p.t.Error("the adapter called a provider")
	return nil, errors.New("no")
}

func (p *fakeProvider) Embed(context.Context, *provider.EmbeddingRequest) (*provider.EmbeddingResponse, error) {
	p.t.Error("the adapter called a provider")
	return nil, errors.New("no")
}

func (p *fakeProvider) Healthy(context.Context) bool {
	p.t.Error("the adapter checked a provider's health, which calls the vendor")
	return true
}

// fakeGuard has internals (a pattern and a word list) that must never be
// sent.
type fakeGuard struct {
	name    string
	phase   guard.Phase
	Pattern string
	Words   []string
}

func (g *fakeGuard) Name() string       { return g.name }
func (g *fakeGuard) Phase() guard.Phase { return g.phase }
func (g *fakeGuard) Check(context.Context, *guard.CheckInput) (*guard.CheckResult, error) {
	return &guard.CheckResult{Passed: true, Action: guard.ActionAllow}, nil
}

type fixture struct {
	gw *nx.Gateway
	st store.Store
}

func newFixture(t *testing.T, opts ...nx.Option) *fixture {
	t.Helper()
	st := store.NewMemory()
	gw := nx.New(append([]nx.Option{nx.WithDatabase(st)}, opts...)...)
	if err := gw.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &fixture{gw: gw, st: st}
}

func (f *fixture) addTenant(t *testing.T, tn *tenant.Tenant) *tenant.Tenant {
	t.Helper()
	tn.ID = id.NewTenantID()
	if tn.Slug == "" {
		tn.Slug = tn.ID.String()
	}
	if tn.Name == "" {
		tn.Name = "tenant " + tn.Slug
	}
	if tn.Status == "" {
		tn.Status = tenant.StatusActive
	}
	if tn.CreatedAt.IsZero() {
		tn.CreatedAt, tn.UpdatedAt = t0, t0
	}
	if err := f.st.Tenants().Insert(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	return tn
}

func (f *fixture) addKey(t *testing.T, tn *tenant.Tenant, k *key.APIKey) *key.APIKey {
	t.Helper()
	k.ID = id.NewKeyID()
	k.TenantID = tn.ID
	if k.Status == "" {
		k.Status = key.KeyActive
	}
	if k.Hash == "" {
		k.Hash = "hash-" + k.ID.String()
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = t0
	}
	if err := f.st.Keys().Insert(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	return k
}

func (f *fixture) addUsage(t *testing.T, r *usage.Record) {
	t.Helper()
	r.ID = id.NewUsageID()
	if r.Outcome == "" {
		r.Outcome = usage.OutcomeOK
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().Add(-time.Minute)
	}
	if err := f.st.Usage().Insert(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

type collected struct {
	pops  map[string]collect.Population
	snaps map[string]collect.Snapshot
}

func collectorsOf(t *testing.T, a *Adapter) collected {
	t.Helper()
	pops, snaps := a.collectors()
	c := collected{pops: map[string]collect.Population{}, snaps: map[string]collect.Snapshot{}}
	for _, p := range pops {
		c.pops[p.Key] = p
	}
	for _, s := range snaps {
		c.snaps[s.Key] = s
	}
	return c
}

func items(t *testing.T, a *Adapter, k string) []map[string]any {
	t.Helper()
	p, ok := collectorsOf(t, a).pops[k]
	if !ok {
		t.Fatalf("no population %q", k)
	}
	out, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func settings(t *testing.T, a *Adapter, k string) map[string]any {
	t.Helper()
	s, ok := collectorsOf(t, a).snaps[k]
	if !ok {
		t.Fatalf("no snapshot %q", k)
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

func sorted(s ...string) []string {
	out := slices.Clone(s)
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
func taken(t *testing.T, w *witness.Witness, k string) bool {
	t.Helper()
	err := w.Population(collect.Population{Key: k, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"nexus"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("nexus adapter is not registered")
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

func provide(t *testing.T, gw *nx.Gateway) vessel.Vessel {
	t.Helper()
	c := vessel.New()
	if err := vessel.Provide(c, func() (*nx.Gateway, error) { return gw, nil }); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAttachRegistersGatewayWideByDefault(t *testing.T) {
	f := newFixture(t)
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: provide(t, f.gw)})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for k, want := range map[string]bool{KeyGateway: true, KeyModelsInUse: true, KeyKeys: false, KeyBudgets: false} {
		if got := taken(t, w, k); got != want {
			t.Errorf("%s registered = %v, want %v", k, got, want)
		}
	}
}

func TestAttachRegistersTenantCollectorsFromConfig(t *testing.T) {
	for name, h := range map[string]adapter.Host{
		"tenants":     {Config: map[string]any{"tenants": []any{"staff"}, "owner_key": "owner"}},
		"all tenants": {Scope: adapter.Scope{AllTenants: true}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			h.Witness = newWitness(t)
			h.Container = provide(t, f.gw)
			found, err := attach(context.Background(), h)
			if !found || err != nil {
				t.Fatalf("attach = %v, %v; want true, nil", found, err)
			}
			for _, k := range []string{KeyGateway, KeyModelsInUse, KeyKeys, KeyBudgets} {
				if !taken(t, h.Witness, k) {
					t.Errorf("%s was not registered", k)
				}
			}
		})
	}
}

func TestNoEventProofs(t *testing.T) {
	f := newFixture(t)
	w := newWitness(t)
	h := adapter.Host{Witness: w, Container: provide(t, f.gw), Config: map[string]any{"event_proofs": true, "tenants": []any{"staff"}}}
	if found, err := attach(context.Background(), h); !found || err != nil {
		t.Fatalf("attach = %v, %v", found, err)
	}
	for _, k := range []string{"nexus.key-lifecycle", "nexus.guardrail-actions", "nexus.budget-alerts"} {
		if taken(t, w, k) {
			t.Errorf("event proof %s was registered", k)
		}
	}
}

func TestGateway(t *testing.T) {
	f := newFixture(t,
		nx.WithConfig(&nx.Config{
			BasePath: "/nexus", DefaultTimeout: 45 * time.Second, DefaultMaxRetries: 3,
			EnableUsage: true, EnableCache: true, RequireAPIKey: true, GlobalRateLimit: 600,
		}),
		nx.WithProvider(&fakeProvider{t: t, name: "openai", caps: provider.Capabilities{Chat: true, Streaming: true, Tools: true, StreamingTools: true}}),
		nx.WithProvider(&fakeProvider{t: t, name: "anthropic", caps: provider.Capabilities{Chat: true, Thinking: true}}),
		nx.WithAlias("smart",
			model.AliasTarget{Provider: "anthropic", Model: "claude-opus", Weight: 0.7},
			model.AliasTarget{Provider: "openai", Model: "gpt-5", Weight: 0.3}),
		nx.WithAlias("fast", model.AliasTarget{Provider: "openai", Model: "gpt-5-mini"}),
		nx.WithGuard(&fakeGuard{name: "shield-output", phase: guard.PhaseOutput}),
		nx.WithGuard(&fakeGuard{name: "pii", phase: guard.PhaseBoth}),
	)
	got := settings(t, New(f.gw), KeyGateway)
	caps := func(on ...string) map[string]any {
		m := map[string]any{}
		for _, c := range capabilityNames {
			m[c] = slices.Contains(on, c)
		}
		return m
	}
	assertJSON(t, got, map[string]any{
		"providers": []any{
			map[string]any{"name": "anthropic", "capabilities": caps("chat", "thinking")},
			map[string]any{"name": "openai", "capabilities": caps("chat", "streaming", "tools", "streaming_tools")},
		},
		"aliases": []any{
			map[string]any{"name": "fast", "targets": []any{map[string]any{"provider": "openai", "model": "gpt-5-mini"}}},
			map[string]any{"name": "smart", "targets": []any{
				map[string]any{"provider": "anthropic", "model": "claude-opus"},
				map[string]any{"provider": "openai", "model": "gpt-5"},
			}},
		},
		"routing_strategy": f.gw.RoutingStrategy(),
		"guards": []any{
			map[string]any{"name": "pii", "phase": "both"},
			map[string]any{"name": "shield-output", "phase": "output"},
		},
		"require_api_key":         true,
		"enable_cache":            true,
		"enable_usage":            true,
		"global_rate_limit":       600,
		"default_max_retries":     3,
		"default_timeout_seconds": 45,
	})
	if f.gw.RoutingStrategy() == "" {
		t.Fatal("routing strategy is empty; the test would not check it")
	}
}

func TestGatewayEmpty(t *testing.T) {
	got := settings(t, New(newFixture(t).gw), KeyGateway)
	for _, k := range []string{"providers", "aliases", "guards"} {
		if v, ok := got[k].([]map[string]any); !ok || len(v) != 0 {
			t.Errorf("%s = %#v, want an empty list", k, got[k])
		}
	}
}

func TestModelsInUse(t *testing.T) {
	f := newFixture(t,
		nx.WithProvider(&fakeProvider{t: t, name: "openai"}),
		nx.WithProvider(&fakeProvider{t: t, name: "anthropic"}),
		nx.WithProvider(&fakeProvider{t: t, name: "unused"}),
		nx.WithAlias("old", model.AliasTarget{Provider: "openai", Model: "gpt-4"}),
	)
	staff := f.addTenant(t, &tenant.Tenant{Slug: "staff"})
	cust := f.addTenant(t, &tenant.Tenant{Slug: "customer"})
	f.addUsage(t, &usage.Record{TenantID: staff.ID, Provider: "openai", Model: "gpt-5"})
	f.addUsage(t, &usage.Record{TenantID: cust.ID, Provider: "openai", Model: "gpt-5"})
	f.addUsage(t, &usage.Record{TenantID: cust.ID, Provider: "anthropic", Model: "claude-opus"})
	// The same model name through a second provider is its own pair.
	f.addUsage(t, &usage.Record{Provider: "anthropic", Model: "gpt-5"})
	// Errors, blocks, refusals and cache hits are not calls a provider
	// answered.
	f.addUsage(t, &usage.Record{Provider: "openai", Model: "gpt-error", Outcome: usage.OutcomeError})
	f.addUsage(t, &usage.Record{Provider: "openai", Model: "gpt-blocked", Outcome: usage.OutcomeBlocked, BlockedBy: "pii"})
	f.addUsage(t, &usage.Record{Model: "typed-by-a-caller", Outcome: usage.OutcomeRefused, RefusalCode: "model_blocked"})
	f.addUsage(t, &usage.Record{Provider: "openai", Model: "gpt-cached", Outcome: usage.OutcomeCached})
	// Used, but more than 30 days ago: the alias makes it a candidate, and
	// the window drops it.
	f.addUsage(t, &usage.Record{Provider: "openai", Model: "gpt-4", CreatedAt: time.Now().Add(-40 * 24 * time.Hour)})

	got := items(t, New(f.gw), KeyModelsInUse)
	assertJSON(t, got, []map[string]any{
		{"id": "anthropic/claude-opus", "provider": "anthropic", "model": "claude-opus"},
		{"id": "anthropic/gpt-5", "provider": "anthropic", "model": "gpt-5"},
		{"id": "openai/gpt-5", "provider": "openai", "model": "gpt-5"},
	})
	raw, _ := json.Marshal(got)
	for _, tn := range []*tenant.Tenant{staff, cust} {
		if strings.Contains(string(raw), tn.ID.String()) {
			t.Fatalf("models in use carry a tenant ID: %s", raw)
		}
	}
}

func TestModelsInUseFindsLastWeekAcrossAMonth(t *testing.T) {
	// A record from 3 days ago is in this month's summary or in the last
	// week's, whichever day the test runs on.
	f := newFixture(t)
	f.addUsage(t, &usage.Record{Provider: "openai", Model: "gpt-5", CreatedAt: time.Now().Add(-72 * time.Hour)})
	got := items(t, New(f.gw), KeyModelsInUse)
	if len(got) != 1 || got[0]["id"] != "openai/gpt-5" {
		t.Fatalf("got %v", got)
	}
}

func TestModelsInUseQueryBudget(t *testing.T) {
	old := maxQueries
	maxQueries = 5
	t.Cleanup(func() { maxQueries = old })
	f := newFixture(t)
	for i := range 6 {
		f.addUsage(t, &usage.Record{Model: fmt.Sprint("junk-", i), Outcome: usage.OutcomeRefused})
	}
	_, err := collectorsOf(t, New(f.gw)).pops[KeyModelsInUse].Collect(context.Background())
	if !errors.Is(err, ErrTooMany) {
		t.Fatalf("err = %v, want ErrTooMany", err)
	}
}

func TestModelsInUseAliasModelsOnly(t *testing.T) {
	f := newFixture(t,
		nx.WithProvider(&fakeProvider{t: t, name: "openai"}),
		nx.WithAlias("fast", model.AliasTarget{Provider: "openai", Model: "gpt-5"}),
	)
	cust := f.addTenant(t, &tenant.Tenant{Slug: "customer"})
	f.addUsage(t, &usage.Record{Provider: "openai", Model: "gpt-5"})
	// A model a customer asked for by its own name, such as a fine-tune.
	f.addUsage(t, &usage.Record{TenantID: cust.ID, Provider: "openai", Model: "ft:acme-support-bot"})

	if got := ids(items(t, New(f.gw), KeyModelsInUse)); !slices.Equal(got, []string{"openai/ft:acme-support-bot", "openai/gpt-5"}) {
		t.Fatalf("by default got %v", got)
	}
	want := []string{"openai/gpt-5"}
	if got := ids(items(t, New(f.gw, WithAliasModelsOnly()), KeyModelsInUse)); !slices.Equal(got, want) {
		t.Fatalf("with WithAliasModelsOnly got %v, want %v", got, want)
	}
	var o Options
	if err := adapter.Decode(map[string]any{"alias_models_only": true}, &o); err != nil {
		t.Fatal(err)
	}
	if got := ids(items(t, newAdapter(f.gw, o), KeyModelsInUse)); !slices.Equal(got, want) {
		t.Fatalf("with alias_models_only got %v, want %v", got, want)
	}
}

func TestModelsInUseSaysWhatItMisses(t *testing.T) {
	d := collectorsOf(t, New(newFixture(t).gw)).pops[KeyModelsInUse].Description
	if strings.Contains(d, "last month") || !strings.Contains(d, "30 days") || !strings.Contains(d, "calendar month") {
		t.Fatalf("Description = %q, want the 30 day window and the calendar month gap", d)
	}
}

func TestKeys(t *testing.T) {
	f := newFixture(t)
	staff := f.addTenant(t, &tenant.Tenant{Slug: "staff"})
	expires := t0.Add(90 * 24 * time.Hour)
	used := time.Date(2026, 11, 4, 23, 59, 59, 0, time.FixedZone("x", -5*3600)) // 2026-11-05 in UTC
	k := f.addKey(t, staff, &key.APIKey{
		Name: "deploy bot", Prefix: "nxs_" + "abcdef12", Scopes: []string{"models", "completions"},
		ExpiresAt: &expires, LastUsedAt: &used,
		Metadata: map[string]string{"owner": "usr_1", "team": "infra"},
	})
	past := t0.Add(-time.Hour)
	expired := f.addKey(t, staff, &key.APIKey{Name: "old", ExpiresAt: &past, CreatedAt: t0.Add(-48 * time.Hour)})
	revoked := f.addKey(t, staff, &key.APIKey{Name: "gone", Status: key.KeyRevoked})

	got := items(t, New(f.gw, WithTenants("staff"), WithOwnerKey("owner")), KeyKeys)
	byID := map[string]map[string]any{}
	for _, it := range got {
		byID[it["id"].(string)] = it
	}
	if len(byID) != 3 {
		t.Fatalf("got %d keys, want 3: %v", len(got), got)
	}
	assertJSON(t, byID[k.ID.String()], map[string]any{
		"id": k.ID.String(), "tenant_id": staff.ID.String(), "name": "deploy bot",
		"scopes": []string{"completions", "models"}, "status": "active",
		"created_at": "2026-10-01T09:30:15Z", "expires_at": "2026-12-30T09:30:15Z",
		"last_used_on": "2026-11-05", "owner_id": "usr_1",
	})
	assertJSON(t, byID[expired.ID.String()], map[string]any{
		"id": expired.ID.String(), "tenant_id": staff.ID.String(), "name": "old",
		"scopes": []string{}, "status": "expired",
		"created_at": "2026-09-29T09:30:15Z", "expires_at": "2026-10-01T08:30:15Z",
		"last_used_on": nil, "owner_id": nil,
	})
	if byID[revoked.ID.String()]["status"] != "revoked" {
		t.Fatalf("revoked key = %v", byID[revoked.ID.String()])
	}

	// The default owner key is owner_id.
	f.addKey(t, staff, &key.APIKey{Name: "x", Metadata: map[string]string{"owner_id": "usr_2"}})
	owners := map[any]bool{}
	for _, it := range items(t, New(f.gw, WithTenants(staff.ID.String())), KeyKeys) {
		owners[it["owner_id"]] = true
	}
	if !owners["usr_2"] || owners["usr_1"] {
		t.Fatalf("owners with the default key = %v", owners)
	}
}

func TestBudgets(t *testing.T) {
	f := newFixture(t)
	on := true
	staff := f.addTenant(t, &tenant.Tenant{
		Slug: "staff",
		Quota: tenant.Quota{
			RPM: 60, TPM: 100000, DailyRequests: 5000, MonthlyBudgetUSD: money.MustParse("1284.370219"),
			MaxTokensPerReq: 8192, MaxStreamDuration: 2 * time.Minute, MaxStreamTokens: 4096,
		},
		Config: tenant.Config{
			AllowedModels: []string{"smart", "fast"}, BlockedModels: []string{"gpt-4"},
			DefaultModel: "fast", GuardrailPolicy: "strict", CacheEnabled: &on,
		},
	})
	bare := f.addTenant(t, &tenant.Tenant{Slug: "bare", Status: tenant.StatusSuspended})

	got := items(t, New(f.gw, WithTenants("staff", "bare")), KeyBudgets)
	byID := map[string]map[string]any{}
	for _, it := range got {
		byID[it["id"].(string)] = it
	}
	assertJSON(t, byID[staff.ID.String()], map[string]any{
		"id": staff.ID.String(), "slug": "staff", "status": "active",
		"monthly_budget_usd": json.Number("1284.370219"),
		"rpm":                60, "tpm": 100000, "daily_requests": 5000, "max_tokens_per_req": 8192,
		"max_stream_tokens": 4096, "max_stream_duration_seconds": 120,
		"allowed_models": []string{"fast", "smart"}, "blocked_models": []string{"gpt-4"},
		"default_model": "fast", "guardrail_policy": "strict", "cache_enabled": true,
	})
	assertJSON(t, byID[bare.ID.String()], map[string]any{
		"id": bare.ID.String(), "slug": "bare", "status": "suspended",
		"monthly_budget_usd": json.Number("0"),
		"rpm":                0, "tpm": 0, "daily_requests": 0, "max_tokens_per_req": 0,
		"max_stream_tokens": 0, "max_stream_duration_seconds": 0,
		"allowed_models": []string{}, "blocked_models": []string{},
		"default_model": "", "guardrail_policy": "", "cache_enabled": nil,
	})
	// Exact: the budget goes as a JSON number with every digit.
	raw, _ := json.Marshal(byID[staff.ID.String()])
	if !strings.Contains(string(raw), `"monthly_budget_usd":1284.370219`) {
		t.Fatalf("budget not exact: %s", raw)
	}
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	staff := f.addTenant(t, &tenant.Tenant{Slug: "staff"})
	cust := f.addTenant(t, &tenant.Tenant{Slug: "customer"})
	sk := f.addKey(t, staff, &key.APIKey{Name: "staff key"})
	ck := f.addKey(t, cust, &key.APIKey{Name: "customer key"})

	cases := []struct {
		name    string
		opts    []Option
		keys    []string
		tenants []string
	}{
		{"by slug", []Option{WithTenants("staff")}, []string{sk.ID.String()}, []string{staff.ID.String()}},
		{"by id", []Option{WithTenants(staff.ID.String())}, []string{sk.ID.String()}, []string{staff.ID.String()}},
		{"unknown and blank ignored", []Option{WithTenants("staff", "", " ", "nobody", id.NewTenantID().String())}, []string{sk.ID.String()}, []string{staff.ID.String()}},
		{"named twice", []Option{WithTenants("staff", staff.ID.String())}, []string{sk.ID.String()}, []string{staff.ID.String()}},
		{"explicit list", []Option{WithTenants("staff", "customer")}, []string{sk.ID.String(), ck.ID.String()}, []string{staff.ID.String(), cust.ID.String()}},
		{"all tenants", []Option{WithAllTenants()}, []string{sk.ID.String(), ck.ID.String()}, []string{staff.ID.String(), cust.ID.String()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(f.gw, tc.opts...)
			if got, want := ids(items(t, a, KeyKeys)), sorted(tc.keys...); !slices.Equal(got, want) {
				t.Errorf("keys = %v, want %v", got, want)
			}
			if got, want := ids(items(t, a, KeyBudgets)), sorted(tc.tenants...); !slices.Equal(got, want) {
				t.Errorf("budgets = %v, want %v", got, want)
			}
		})
	}

	// With no tenants named, the tenant collectors don't exist at all.
	c := collectorsOf(t, New(f.gw))
	if _, ok := c.pops[KeyKeys]; ok {
		t.Error("keys collected with no tenants named")
	}
	if _, ok := c.pops[KeyBudgets]; ok {
		t.Error("budgets collected with no tenants named")
	}
}

func TestPages(t *testing.T) {
	f := newFixture(t)
	staff := f.addTenant(t, &tenant.Tenant{Slug: "staff"})
	const keys = 2*pageSize + 37
	for i := range keys {
		f.addKey(t, staff, &key.APIKey{Name: fmt.Sprint("k", i)})
	}
	const tenants = pageSize + 20
	for range tenants {
		f.addTenant(t, &tenant.Tenant{})
	}
	cust := f.addTenant(t, &tenant.Tenant{Slug: "customer"})
	for range 10 {
		f.addKey(t, cust, &key.APIKey{})
	}
	if got := len(items(t, New(f.gw, WithTenants("staff")), KeyKeys)); got != keys {
		t.Errorf("keys = %d, want %d", got, keys)
	}
	all := New(f.gw, WithAllTenants())
	if got := len(items(t, all, KeyKeys)); got != keys+10 {
		t.Errorf("all keys = %d, want %d", got, keys+10)
	}
	if got := len(items(t, all, KeyBudgets)); got != tenants+2 {
		t.Errorf("all budgets = %d, want %d", got, tenants+2)
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 5
	t.Cleanup(func() { maxItems = old })
	f := newFixture(t)
	staff := f.addTenant(t, &tenant.Tenant{Slug: "staff"})
	for range 6 {
		f.addKey(t, staff, &key.APIKey{})
		f.addTenant(t, &tenant.Tenant{})
	}
	c := collectorsOf(t, New(f.gw, WithAllTenants()))
	for _, k := range []string{KeyKeys, KeyBudgets} {
		if _, err := c.pops[k].Collect(context.Background()); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: err = %v, want ErrTooMany", k, err)
		}
	}
}

func TestNotInitialized(t *testing.T) {
	gw := nx.New()
	c := collectorsOf(t, New(gw, WithAllTenants()))
	for k, p := range c.pops {
		if _, err := p.Collect(context.Background()); !errors.Is(err, ErrNotReady) {
			t.Errorf("%s: err = %v, want ErrNotReady", k, err)
		}
	}
	if _, err := c.snaps[KeyGateway].Collect(context.Background()); err != nil {
		t.Errorf("gateway before Initialize: %v", err)
	}
}

func TestNeverSendsContent(t *testing.T) {
	f := newFixture(t,
		nx.WithProvider(&fakeProvider{t: t, name: "openai", BaseURL: "https://" + canary + ".example/v1", APIKey: canary + "-server-key"}),
		nx.WithCredentialProvider(provider.NewStaticCredential(map[string]string{"openai": canary + "-workspace-key"})),
		nx.WithAlias("smart", model.AliasTarget{Provider: "openai", Model: "gpt-5", Weight: 0.4242}),
		nx.WithTenantAlias("tenant_"+canary, "smart", model.AliasTarget{Provider: "openai", Model: canary + "-override-model"}),
		nx.WithGuard(&fakeGuard{name: "pii", phase: guard.PhaseInput, Pattern: canary + "-regex", Words: []string{canary + "-word"}}),
	)
	staff := f.addTenant(t, &tenant.Tenant{
		Slug: "staff", Name: canary + "-tenant-name",
		Metadata: map[string]string{"org_id": canary + "-org"},
		Config: tenant.Config{
			Metadata:        map[string]string{"x": canary + "-config-meta"},
			RoutingStrategy: canary + "-routing",
		},
		UpdatedAt: time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	f.addKey(t, staff, &key.APIKey{
		Name: "k", Prefix: "nxs_" + canary, Hash: canary + "-hash",
		Metadata: map[string]string{"owner_id": "usr_1", "note": canary + "-key-meta"},
	})
	cost := money.MustParse("424242.4242")
	f.addUsage(t, &usage.Record{
		TenantID: staff.ID, Provider: "openai", Model: "gpt-5", PromptTokens: 4242421,
		CostUSD: &cost, Metadata: map[string]string{"run": canary + "-usage-meta"},
	})
	f.addUsage(t, &usage.Record{
		TenantID: staff.ID, Provider: "openai", Model: canary + "-blocked-model",
		Outcome: usage.OutcomeBlocked, BlockedBy: canary + "-guard",
	})
	f.addUsage(t, &usage.Record{
		TenantID: staff.ID, Model: canary + "-refused-model",
		Outcome: usage.OutcomeRefused, RefusalCode: canary + "-code",
	})
	f.addUsage(t, &usage.Record{
		TenantID: staff.ID, Provider: "openai", Model: canary + "-error-model", Outcome: usage.OutcomeError,
	})

	a := New(f.gw, WithTenants("staff"))
	c := collectorsOf(t, a)
	if len(c.pops)+len(c.snaps) != 4 {
		t.Fatalf("want all 4 collectors, got %d populations and %d snapshots", len(c.pops), len(c.snaps))
	}
	out := make([]any, 0, len(c.pops)+len(c.snaps))
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
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{canary, "nxs_", "hash-", "0.4242", "424242", "4242421", "2031-01-02"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
	for _, want := range []string{`"owner_id":"usr_1"`, `"openai/gpt-5"`, `"slug":"staff"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("output lacks %s: %s", want, raw)
		}
	}
}

func assertJSON(t *testing.T, got, want any) {
	t.Helper()
	norm := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var x any
		if err := json.Unmarshal(b, &x); err != nil {
			t.Fatal(err)
		}
		b, _ = json.Marshal(x)
		return string(b)
	}
	if g, w := norm(got), norm(want); g != w {
		t.Fatalf("got  %s\nwant %s", g, w)
	}
}
