package keysmith

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	ks "github.com/xraph/keysmith"
	"github.com/xraph/keysmith/id"
	"github.com/xraph/keysmith/key"
	"github.com/xraph/keysmith/policy"
	"github.com/xraph/keysmith/scope"
	"github.com/xraph/keysmith/store/memory"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

const (
	platformApp = "app-platform"
	otherApp    = "app-other"
	staff       = "org-staff"
	customer    = "org-customer"
)

var t0 = time.Date(2026, 11, 1, 9, 30, 15, 123456789, time.UTC)

type fixture struct {
	eng *ks.Engine
	st  *memory.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memory.New()
	eng, err := ks.NewEngine(ks.WithStore(st))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{eng: eng, st: st}
}

// addKey stores k with a fresh ID, filling app, tenant and created time when
// empty, and assigns scopes to it.
func (f *fixture) addKey(t *testing.T, k *key.Key, scopes ...string) *key.Key {
	t.Helper()
	ctx := context.Background()
	k.ID = id.NewKeyID()
	if k.AppID == "" {
		k.AppID = platformApp
	}
	if k.TenantID == "" {
		k.TenantID = staff
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = t0
	}
	if k.State == "" {
		k.State = key.StateActive
	}
	if k.KeyHash == "" {
		k.KeyHash = k.ID.String()
	}
	if err := f.st.Keys().Create(ctx, k); err != nil {
		t.Fatal(err)
	}
	for _, name := range scopes {
		if _, err := f.st.Scopes().GetByName(ctx, k.TenantID, name); err != nil {
			err := f.st.Scopes().Create(ctx, &scope.Scope{ID: id.NewScopeID(), TenantID: k.TenantID, AppID: k.AppID, Name: name, CreatedAt: t0})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(scopes) > 0 {
		if err := f.st.Scopes().AssignToKey(ctx, k.ID, scopes); err != nil {
			t.Fatal(err)
		}
	}
	return k
}

func (f *fixture) addPolicy(t *testing.T, p *policy.Policy) *policy.Policy {
	t.Helper()
	p.ID = id.NewPolicyID()
	if p.AppID == "" {
		p.AppID = platformApp
	}
	if p.TenantID == "" {
		p.TenantID = staff
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt, p.UpdatedAt = t0, t0
	}
	if err := f.st.Policies().Create(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	return p
}

// collectors returns a's collectors by key.
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

func sortedIDs(ids ...string) []string {
	out := slices.Clone(ids)
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

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"keysmith"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("keysmith adapter is not registered")
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"nil": nil, "empty vessel": vessel.New(), "not a vessel": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c, Config: map[string]any{"staff_tenants": []any{staff}}})
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
		Scope:     adapter.Scope{AppID: platformApp, TenantID: "platform"},
		Container: c,
		Config:    map[string]any{"staff_tenants": []any{staff}, "metadata_keys": []any{"kind"}},
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyAPIKeys, KeyPolicies} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
}

func TestAttachWithoutTenantsRegistersNothing(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Scope: adapter.Scope{AppID: platformApp}, Container: c})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyAPIKeys, KeyPolicies} {
		if taken(t, w, k) {
			t.Errorf("%s was registered with no staff tenants", k)
		}
	}
}

func TestRegisterNeedsTenants(t *testing.T) {
	f := newFixture(t)
	for name, opts := range map[string][]Option{
		"none":       nil,
		"blank only": {WithStaffTenants("", " ")},
	} {
		t.Run(name, func(t *testing.T) {
			err := New(f.eng, opts...).Register(newWitness(t))
			if !errors.Is(err, ErrNoTenants) {
				t.Fatalf("Register = %v, want ErrNoTenants", err)
			}
		})
	}
}

func TestAPIKeys(t *testing.T) {
	f := newFixture(t)
	pol := f.addPolicy(t, &policy.Policy{Name: "default"})
	expires := t0.Add(90 * 24 * time.Hour)
	rotated := t0.Add(48 * time.Hour)
	used := time.Date(2026, 11, 4, 23, 59, 59, 0, time.FixedZone("x", -5*3600)) // 2026-11-05 in UTC
	k := f.addKey(t, &key.Key{
		Name: "deploy bot", Prefix: "sk", Environment: key.EnvLive, PolicyID: &pol.ID,
		CreatedBy: "usr_1", ExpiresAt: &expires, RotatedAt: &rotated, LastUsedAt: &used,
		Metadata: map[string]any{"kind": "user", "project_id": "p1"},
	}, "write:nodes", "read:nodes")
	revoked := t0.Add(time.Hour)
	r := f.addKey(t, &key.Key{Name: "old", Prefix: "sk", Environment: key.EnvTest, State: key.StateRevoked, RevokedAt: &revoked, CreatedBy: "usr_2"})

	got := items(t, New(f.eng, WithAppID(platformApp), WithStaffTenants(staff), WithMetadataKeys("kind")), KeyAPIKeys)
	if len(got) != 2 {
		t.Fatalf("got %d items, want 2", len(got))
	}
	byID := map[string]map[string]any{}
	for _, it := range got {
		byID[it["id"].(string)] = it
	}
	want := map[string]any{
		"id": k.ID.String(), "tenant_id": staff, "app_id": platformApp, "name": "deploy bot",
		"prefix": "sk", "environment": "live", "state": "active", "policy_id": pol.ID.String(),
		"scopes": []string{"read:nodes", "write:nodes"}, "created_by": "usr_1",
		"created_at": "2026-11-01T09:30:15Z", "expires_at": "2027-01-30T09:30:15Z",
		"rotated_at": "2026-11-03T09:30:15Z", "revoked_at": nil, "last_used_on": "2026-11-05",
		"metadata": map[string]any{"kind": "user"},
	}
	assertJSON(t, byID[k.ID.String()], want)

	wantRevoked := map[string]any{
		"id": r.ID.String(), "tenant_id": staff, "app_id": platformApp, "name": "old",
		"prefix": "sk", "environment": "test", "state": "revoked", "policy_id": nil,
		"scopes": []string{}, "created_by": "usr_2",
		"created_at": "2026-11-01T09:30:15Z", "expires_at": nil, "rotated_at": nil,
		"revoked_at": "2026-11-01T10:30:15Z", "last_used_on": nil, "metadata": map[string]any{},
	}
	assertJSON(t, byID[r.ID.String()], wantRevoked)
}

func TestAPIKeysWithoutMetadataAllowlist(t *testing.T) {
	f := newFixture(t)
	f.addKey(t, &key.Key{Name: "k", Metadata: map[string]any{"kind": "user"}})
	got := items(t, New(f.eng, WithStaffTenants(staff)), KeyAPIKeys)
	if _, ok := got[0]["metadata"]; ok {
		t.Fatalf("metadata sent with no allowlist: %v", got[0])
	}
}

func TestKeyPolicies(t *testing.T) {
	f := newFixture(t)
	p := f.addPolicy(t, &policy.Policy{
		Name: "strict", RateLimit: 100, RateLimitWindow: time.Minute, BurstLimit: 10,
		AllowedScopes: []string{"write", "read"}, AllowedIPs: []string{"10.0.0.0/8", "192.168.0.1"},
		AllowedOrigins: []string{"https://a.example"}, MaxKeyLifetime: 90 * 24 * time.Hour,
		RotationPeriod: 30 * 24 * time.Hour, GracePeriod: time.Hour, DailyQuota: 1000, MonthlyQuota: 20000,
		UpdatedAt: t0.Add(time.Hour), CreatedAt: t0,
	})
	got := items(t, New(f.eng, WithStaffTenants(staff)), KeyPolicies)
	if len(got) != 1 {
		t.Fatalf("got %d items, want 1", len(got))
	}
	assertJSON(t, got[0], map[string]any{
		"id": p.ID.String(), "tenant_id": staff, "app_id": platformApp, "name": "strict",
		"max_key_lifetime_seconds": 7776000, "rotation_period_seconds": 2592000, "grace_period_seconds": 3600,
		"rate_limit": 100, "rate_limit_window_seconds": 60, "burst_limit": 10,
		"daily_quota": 1000, "monthly_quota": 20000, "allowed_scopes": []string{"read", "write"},
		"allowed_ip_count": 2, "allowed_origin_count": 1,
		"created_at": "2026-11-01T09:30:15Z", "updated_at": "2026-11-01T10:30:15Z",
	})
}

func TestRotation(t *testing.T) {
	f := newFixture(t)
	pol := f.addPolicy(t, &policy.Policy{Name: "p"})
	exp := t0.Add(time.Hour)
	rot := t0.Add(-24 * time.Hour)
	// Oldest active rotation is the newer key's created time, since the
	// older key was rotated later.
	f.addKey(t, &key.Key{CreatedAt: t0.Add(-72 * time.Hour), RotatedAt: &rot, ExpiresAt: &exp, PolicyID: &pol.ID})
	f.addKey(t, &key.Key{CreatedAt: t0.Add(-48 * time.Hour)})
	f.addKey(t, &key.Key{CreatedAt: t0.Add(-96 * time.Hour), State: key.StateRevoked})

	got := settings(t, New(f.eng, WithStaffTenants(staff)), KeyRotation)
	assertJSON(t, got, map[string]any{
		"keys_total": 3, "keys_active": 2, "oldest_active_rotation": "2026-10-30T09:30:15Z",
		"keys_without_expiry": 1, "keys_without_policy": 1,
	})

	empty := settings(t, New(newFixture(t).eng, WithStaffTenants(staff)), KeyRotation)
	assertJSON(t, empty, map[string]any{
		"keys_total": 0, "keys_active": 0, "oldest_active_rotation": nil,
		"keys_without_expiry": 0, "keys_without_policy": 0,
	})
}

func TestEventProofs(t *testing.T) {
	f := newFixture(t)
	if got := collectorsOf(t, New(f.eng, WithStaffTenants(staff))).proofs; len(got) != 0 {
		t.Fatalf("event proofs on by default: %v", got)
	}
	got := collectorsOf(t, New(f.eng, WithStaffTenants(staff), WithEventProofs())).proofs[KeyLifecycleProof]
	if got.Stream != adapter.Platform || !slices.Equal(got.Actions, DefaultProofActions) || !slices.Equal(got.Tests, []string{"keys-rotated"}) {
		t.Fatalf("proof = %+v", got)
	}
	custom := collectorsOf(t, New(f.eng, WithStaffTenants(staff), WithEventProofs("api_key.revoked"))).proofs[KeyLifecycleProof]
	if !slices.Equal(custom.Actions, []string{"api_key.revoked"}) {
		t.Fatalf("custom actions = %v", custom.Actions)
	}
	if err := New(f.eng, WithStaffTenants(staff), WithEventProofs()).Register(newWitness(t)); err != nil {
		t.Fatal(err)
	}
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	staffKey := f.addKey(t, &key.Key{Name: "staff"})
	custKey := f.addKey(t, &key.Key{Name: "customer", TenantID: customer})
	otherKey := f.addKey(t, &key.Key{Name: "other app", AppID: otherApp})
	staffPol := f.addPolicy(t, &policy.Policy{Name: "staff"})
	custPol := f.addPolicy(t, &policy.Policy{Name: "customer", TenantID: customer})
	f.addPolicy(t, &policy.Policy{Name: "other app", AppID: otherApp})

	cases := []struct {
		name     string
		opts     []Option
		keys     []string
		policies []string
	}{
		{"default", []Option{WithAppID(platformApp), WithStaffTenants(staff)}, []string{staffKey.ID.String()}, []string{staffPol.ID.String()}},
		{"all tenants", []Option{WithAppID(platformApp), WithAllTenants()}, []string{staffKey.ID.String(), custKey.ID.String()}, []string{staffPol.ID.String(), custPol.ID.String()}},
		{"explicit list", []Option{WithAppID(platformApp), WithStaffTenants(staff, customer)}, []string{staffKey.ID.String(), custKey.ID.String()}, []string{staffPol.ID.String(), custPol.ID.String()}},
		{"blank tenant ignored", []Option{WithAppID(platformApp), WithStaffTenants(staff, "")}, []string{staffKey.ID.String()}, []string{staffPol.ID.String()}},
		{"no app filter", []Option{WithStaffTenants(staff)}, []string{staffKey.ID.String(), otherKey.ID.String()}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(f.eng, tc.opts...)
			if got, want := ids(items(t, a, KeyAPIKeys)), sortedIDs(tc.keys...); !slices.Equal(got, want) {
				t.Errorf("keys = %v, want %v", got, want)
			}
			if tc.policies != nil {
				if got, want := ids(items(t, a, KeyPolicies)), sortedIDs(tc.policies...); !slices.Equal(got, want) {
					t.Errorf("policies = %v, want %v", got, want)
				}
			}
			if s := settings(t, a, KeyRotation); fmt.Sprint(s["keys_total"]) != fmt.Sprint(len(tc.keys)) {
				t.Errorf("rotation keys_total = %v, want %d", s["keys_total"], len(tc.keys))
			}
		})
	}
}

func TestPages(t *testing.T) {
	f := newFixture(t)
	const n = 2*pageSize + 500
	for i := range n {
		f.addKey(t, &key.Key{Name: fmt.Sprint("k", i), CreatedAt: t0.Add(time.Duration(i%7) * time.Second)})
		f.addPolicy(t, &policy.Policy{Name: fmt.Sprint("p", i)})
	}
	for range 30 {
		f.addKey(t, &key.Key{TenantID: customer})
	}
	a := New(f.eng, WithStaffTenants(staff))
	if got := len(items(t, a, KeyAPIKeys)); got != n {
		t.Errorf("keys = %d, want %d", got, n)
	}
	if got := len(items(t, a, KeyPolicies)); got != n {
		t.Errorf("policies = %d, want %d", got, n)
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 5
	t.Cleanup(func() { maxItems = old })

	f := newFixture(t)
	for range 6 {
		f.addKey(t, &key.Key{})
		f.addPolicy(t, &policy.Policy{Name: id.NewPolicyID().String()})
	}
	c := collectorsOf(t, New(f.eng, WithStaffTenants(staff)))
	for _, k := range []string{KeyAPIKeys, KeyPolicies} {
		if _, err := c.pops[k].Collect(context.Background()); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: err = %v, want ErrTooMany", k, err)
		}
	}
	if _, err := c.snaps[KeyRotation].Collect(context.Background()); !errors.Is(err, ErrTooMany) {
		t.Errorf("rotation: err = %v, want ErrTooMany", err)
	}
}

func TestNeverSendsContent(t *testing.T) {
	const canary = "CANARY-7f3e"
	f := newFixture(t)
	pol := f.addPolicy(t, &policy.Policy{
		Name: "p", Description: canary + "-pol-desc",
		Metadata:       map[string]any{"note": canary + "-pol-meta"},
		AllowedIPs:     []string{canary + "-ip"},
		AllowedOrigins: []string{canary + "-origin"},
		AllowedPaths:   []string{canary + "-path"},
		AllowedMethods: []string{canary + "-method"},
	})
	f.addKey(t, &key.Key{
		Name: "k", Description: canary + "-key-desc", Hint: canary + "-hint", KeyHash: canary + "-hash",
		PolicyID: &pol.ID, Version: 4242424242,
		Metadata: map[string]any{
			"kind":       "user",
			"project_id": canary + "-meta",
			"nested":     map[string]any{"x": canary + "-nested"},
			"access":     map[string]any{"x": canary + "-allowed-but-nested"},
		},
		UpdatedAt: time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC),
	}, "read")
	if err := f.st.Scopes().Create(context.Background(), &scope.Scope{
		ID: id.NewScopeID(), TenantID: staff, AppID: platformApp, Name: "unassigned",
		Description: canary + "-scope-desc", Metadata: map[string]any{"x": canary + "-scope-meta"},
	}); err != nil {
		t.Fatal(err)
	}

	a := New(f.eng, WithStaffTenants(staff), WithMetadataKeys("kind", "access"), WithEventProofs())
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
	for _, bad := range []string{canary, "4242424242", "2031-01-02"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
	if !strings.Contains(string(raw), `"kind":"user"`) {
		t.Fatalf("allowlisted metadata missing: %s", raw)
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

func TestAttachReportsWidening(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		cfg   map[string]any
		scope bool
		want  []string
	}{
		"staff tenants":          {map[string]any{"staff_tenants": []any{staff}}, false, nil},
		"host scope all tenants": {nil, true, nil},
		"all tenants":            {map[string]any{"all_tenants": true}, false, []string{"all_tenants"}},
	} {
		t.Run(name, func(t *testing.T) {
			var got []string
			found, err := attach(context.Background(), adapter.Host{
				Witness:   newWitness(t),
				Scope:     adapter.Scope{AppID: platformApp, AllTenants: tc.scope},
				Container: c,
				Config:    tc.cfg,
				Widen:     func(r string) { got = append(got, r) },
			})
			if !found || err != nil {
				t.Fatalf("attach = %v, %v", found, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Widen got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWidenedDescriptions(t *testing.T) {
	f := newFixture(t)
	wide := collectorsOf(t, New(f.eng, WithAllTenants()))
	narrow := collectorsOf(t, New(f.eng, WithStaffTenants(staff)))
	descs := func(c collected) map[string]string {
		return map[string]string{
			KeyAPIKeys:  c.pops[KeyAPIKeys].Description,
			KeyPolicies: c.pops[KeyPolicies].Description,
			KeyRotation: c.snaps[KeyRotation].Description,
		}
	}
	n := descs(narrow)
	for k, d := range descs(wide) {
		if !strings.Contains(d, "every tenant, customers included") {
			t.Errorf("%s with all_tenants: %q", k, d)
		}
		if strings.Contains(n[k], "customers") {
			t.Errorf("%s by default: %q", k, n[k])
		}
	}
}

// offsetBlind is a keysmith store whose key and policy lists ignore Offset,
// so every page is the first one. After a few calls it fails, so a walk
// that never stops shows up as that error instead of a hung test.
type offsetBlind struct {
	*memory.Store
	calls *int
}

type blindKeys struct {
	key.Store
	calls *int
}

type blindPolicies struct {
	policy.Store
	calls *int
}

var errSpun = errors.New("list called too many times")

func (s offsetBlind) Keys() key.Store        { return blindKeys{s.Store.Keys(), s.calls} }
func (s offsetBlind) Policies() policy.Store { return blindPolicies{s.Store.Policies(), s.calls} }
func (s blindKeys) List(ctx context.Context, f *key.ListFilter) ([]*key.Key, error) {
	if *s.calls++; *s.calls > 20 {
		return nil, errSpun
	}
	g := *f
	g.Offset = 0
	return s.Store.List(ctx, &g)
}
func (s blindPolicies) List(ctx context.Context, f *policy.ListFilter) ([]*policy.Policy, error) {
	if *s.calls++; *s.calls > 20 {
		return nil, errSpun
	}
	g := *f
	g.Offset = 0
	return s.Store.List(ctx, &g)
}

func TestPagingFailsWhenTheStoreIgnoresOffset(t *testing.T) {
	f := newFixture(t)
	for i := range pageSize + 5 {
		f.addKey(t, &key.Key{Name: fmt.Sprint("k", i)})
		f.addPolicy(t, &policy.Policy{Name: fmt.Sprint("p", i)})
	}
	calls := 0
	eng, err := ks.NewEngine(ks.WithStore(offsetBlind{f.st, &calls}))
	if err != nil {
		t.Fatal(err)
	}
	a := New(eng, WithStaffTenants(staff))
	for _, k := range []string{KeyAPIKeys, KeyPolicies} {
		calls = 0
		_, err := collectorsOf(t, a).pops[k].Collect(context.Background())
		if !errors.Is(err, errStuck) {
			t.Errorf("%s: err = %v, want errStuck", k, err)
		}
	}
}
