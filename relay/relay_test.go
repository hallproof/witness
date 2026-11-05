package relay

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

	xrelay "github.com/xraph/relay"
	"github.com/xraph/relay/catalog"
	"github.com/xraph/relay/endpoint"
	"github.com/xraph/relay/event"
	"github.com/xraph/relay/id"
	"github.com/xraph/relay/store"
	"github.com/xraph/relay/store/memory"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

const (
	staff    = "org-staff"
	customer = "org-customer"
)

var t0 = time.Date(2026, 11, 1, 9, 30, 15, 123456789, time.UTC)

type fixture struct {
	st *memory.Store
	r  *xrelay.Relay
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memory.New()
	r, err := xrelay.New(xrelay.WithStore(st))
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, r: r}
}

// addEndpoint stores ep with a fresh ID, filling tenant, URL, secret and
// created time when empty.
func (f *fixture) addEndpoint(t *testing.T, ep *endpoint.Endpoint) *endpoint.Endpoint {
	t.Helper()
	ep.ID = id.NewEndpointID()
	if ep.TenantID == "" {
		ep.TenantID = staff
	}
	if ep.URL == "" {
		ep.URL = "https://hooks.example.com/in"
	}
	if ep.Secret == "" {
		ep.Secret = "whsec_" + ep.ID.String()
	}
	if ep.CreatedAt.IsZero() {
		ep.CreatedAt, ep.UpdatedAt = t0, t0
	}
	if err := f.st.CreateEndpoint(context.Background(), ep); err != nil {
		t.Fatal(err)
	}
	return ep
}

func (f *fixture) addType(t *testing.T, et *catalog.EventType) {
	t.Helper()
	et.ID = id.NewEventTypeID()
	if et.CreatedAt.IsZero() {
		et.CreatedAt, et.UpdatedAt = t0, t0
	}
	if err := f.st.RegisterType(context.Background(), et); err != nil {
		t.Fatal(err)
	}
}

type collected struct {
	pops  map[string]collect.Population
	snaps map[string]collect.Snapshot
}

func collectorsOf(t *testing.T, a *Adapter) collected {
	t.Helper()
	pops, snaps, err := a.collectors()
	if err != nil {
		t.Fatal(err)
	}
	c := collected{pops: map[string]collect.Population{}, snaps: map[string]collect.Snapshot{}}
	for _, p := range pops {
		c.pops[p.Key] = p
	}
	for _, s := range snaps {
		c.snaps[s.Key] = s
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

func posture(t *testing.T, a *Adapter) map[string]any {
	t.Helper()
	s, ok := collectorsOf(t, a).snaps[KeyPosture]
	if !ok {
		t.Fatalf("no snapshot %q", KeyPosture)
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

// taken reports whether a collector key is already registered on w.
func taken(t *testing.T, w *witness.Witness, key string) bool {
	t.Helper()
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

// lockedStore wraps a store the way an app that encrypts signing secrets
// does, and fails every endpoint list, as one undecryptable secret would.
type lockedStore struct {
	store.Store
}

func (lockedStore) ListEndpoints(context.Context, string, endpoint.ListOpts) ([]*endpoint.Endpoint, error) {
	return nil, errors.New("cannot decrypt webhook signing secret")
}

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"relay"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("relay adapter is not registered")
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
	if err := vessel.ProvideValue(c, f.r); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c, Config: map[string]any{"staff_tenants": []any{staff}}})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyEndpoints, KeyPosture, KeyEventTypes} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
}

func TestAttachWithoutTenantsKeepsPosture(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.r); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	if taken(t, w, KeyEndpoints) {
		t.Errorf("%s was registered with no staff tenants", KeyEndpoints)
	}
	if !taken(t, w, KeyPosture) {
		t.Errorf("%s was not registered", KeyPosture)
	}
}

func TestAttachNothingToCollect(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue[endpoint.Store](c, f.st); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c, Config: map[string]any{"posture": false, "event_types": false}})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyEndpoints, KeyPosture, KeyEventTypes} {
		if taken(t, w, k) {
			t.Errorf("%s was registered", k)
		}
	}
}

// An app that encrypts signing secrets provides the raw store as well as
// the Relay. The adapter must read endpoints through the raw store, so one
// secret that won't decrypt can't fail the whole list.
func TestAttachPrefersRawEndpointStore(t *testing.T) {
	raw := memory.New()
	r, err := xrelay.New(xrelay.WithStore(lockedStore{raw}))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: raw, r: r}
	ep := f.addEndpoint(t, &endpoint.Endpoint{Enabled: true})
	f.addType(t, &catalog.EventType{Definition: catalog.WebhookDefinition{Name: "invoice.paid"}})

	c := vessel.New()
	if err = vessel.ProvideValue(c, r); err != nil {
		t.Fatal(err)
	}
	if err = vessel.ProvideValue[endpoint.Store](c, raw); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c, Config: map[string]any{"staff_tenants": []any{staff}}})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}

	if !taken(t, w, KeyEndpoints) {
		t.Fatalf("%s was not registered", KeyEndpoints)
	}

	resolved, err := resolve(c, Options{StaffTenants: []string{staff}})
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]*Adapter{
		"resolved": resolved,
		"explicit": New(r, WithStaffTenants(staff), WithEndpointStore(raw)),
	} {
		if got := ids(items(t, a, KeyEndpoints)); !slices.Equal(got, []string{ep.ID.String()}) {
			t.Fatalf("%s: endpoints = %v", name, got)
		}
		if got := posture(t, a)["endpoints"]; got != 1 {
			t.Fatalf("%s: posture endpoints = %v", name, got)
		}
		if got := items(t, a, KeyEventTypes); len(got) != 1 {
			t.Fatalf("%s: event types = %v", name, got)
		}
	}

	// Without the raw store the wrapper's failure fails the run, loudly.
	p := collectorsOf(t, New(r, WithStaffTenants(staff))).pops[KeyEndpoints]
	if _, err := p.Collect(context.Background()); err == nil {
		t.Fatal("collect through a failing store = nil error")
	}
}

func TestAttachStoreOnly(t *testing.T) {
	f := newFixture(t)
	ep := f.addEndpoint(t, &endpoint.Endpoint{})
	c := vessel.New()
	if err := vessel.ProvideValue[endpoint.Store](c, f.st); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c, Scope: adapter.Scope{AllTenants: true}})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyEndpoints, KeyPosture, KeyEventTypes} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
	if got := ids(items(t, NewFromStore(f.st, WithAllTenants()), KeyEndpoints)); !slices.Equal(got, []string{ep.ID.String()}) {
		t.Fatalf("endpoints = %v", got)
	}
}

func TestRegisterNeedsSomethingToCollect(t *testing.T) {
	f := newFixture(t)
	for name, opts := range map[string][]Option{
		"none":       {WithoutPosture(), WithoutEventTypes()},
		"blank only": {WithStaffTenants("", " "), WithoutPosture(), WithoutEventTypes()},
	} {
		t.Run(name, func(t *testing.T) {
			err := New(f.r, opts...).Register(newWitness(t))
			if !errors.Is(err, ErrNoTenants) {
				t.Fatalf("Register = %v, want ErrNoTenants", err)
			}
		})
	}
	if err := New(f.r).Register(newWitness(t)); err != nil {
		t.Fatalf("Register with posture on = %v", err)
	}
}

func TestWebhookEndpoints(t *testing.T) {
	f := newFixture(t)
	ep := &endpoint.Endpoint{
		URL: "HTTPS://Hooks.Example.COM:443/in/abc", Enabled: true, RateLimit: 5,
		ScopeAppID: "app-1", ScopeOrgID: staff,
		EventTypes: []string{"invoice.*", "deploy.done"},
		Headers:    map[string]string{"X-Team": "a", "authorization": "b"},
	}
	ep.CreatedAt, ep.UpdatedAt = t0, t0.Add(time.Hour)
	f.addEndpoint(t, ep)
	plain := f.addEndpoint(t, &endpoint.Endpoint{URL: "http://10.0.0.7:8080/x", Secret: " "})
	v6 := f.addEndpoint(t, &endpoint.Endpoint{URL: "https://[::1]:8443/x"})
	bad := f.addEndpoint(t, &endpoint.Endpoint{URL: "::not a url"})

	got := items(t, New(f.r, WithStaffTenants(staff)), KeyEndpoints)
	byID := map[string]map[string]any{}
	for _, it := range got {
		byID[it["id"].(string)] = it
	}
	if len(byID) != 4 {
		t.Fatalf("got %d items, want 4", len(got))
	}
	assertJSON(t, byID[ep.ID.String()], map[string]any{
		"id": ep.ID.String(), "tenant_id": staff, "scope_app_id": "app-1", "scope_org_id": staff,
		"destination_scheme": "https", "destination_host": "hooks.example.com",
		"signed": true, "enabled": true, "event_types": []string{"deploy.done", "invoice.*"},
		"rate_limit": 5, "custom_header_names": []string{"authorization", "x-team"},
		"created_at": "2026-11-01T09:30:15Z", "updated_at": "2026-11-01T10:30:15Z",
	})
	assertJSON(t, byID[plain.ID.String()], map[string]any{
		"id": plain.ID.String(), "tenant_id": staff, "scope_app_id": "", "scope_org_id": "",
		"destination_scheme": "http", "destination_host": "10.0.0.7:8080",
		"signed": false, "enabled": false, "event_types": []string{},
		"rate_limit": 0, "custom_header_names": []string{},
		"created_at": "2026-11-01T09:30:15Z", "updated_at": "2026-11-01T09:30:15Z",
	})
	if h := byID[v6.ID.String()]["destination_host"]; h != "[::1]:8443" {
		t.Errorf("IPv6 host = %v", h)
	}
	if s, h := byID[bad.ID.String()]["destination_scheme"], byID[bad.ID.String()]["destination_host"]; s != "" || h != "" {
		t.Errorf("unparsable URL gave scheme %q host %q", s, h)
	}
}

func TestDestination(t *testing.T) {
	for raw, want := range map[string][2]string{
		"https://user:pw@Example.com/p?q=1#f": {"https", "example.com"},
		"https://example.com:8443":            {"https", "example.com:8443"},
		"http://example.com:80/":              {"http", "example.com"},
		"http://example.com:443/":             {"http", "example.com:443"},
		"ftp://files.example.com/x":           {"other", "files.example.com"},
		"example.com/path":                    {"", ""},
		"mailto:a@b.example":                  {"other", ""},
		"":                                    {"", ""},
	} {
		s, h := destination(raw)
		if s != want[0] || h != want[1] {
			t.Errorf("destination(%q) = %q, %q; want %q, %q", raw, s, h, want[0], want[1])
		}
	}
}

func TestWebhookPosture(t *testing.T) {
	f := newFixture(t)
	f.addEndpoint(t, &endpoint.Endpoint{Enabled: true})
	f.addEndpoint(t, &endpoint.Endpoint{Enabled: true, URL: "http://a.example/x"})
	f.addEndpoint(t, &endpoint.Endpoint{TenantID: customer, Secret: "\t"})
	f.addEndpoint(t, &endpoint.Endpoint{TenantID: "org-3", Enabled: true, URL: "::bad", Secret: " "})

	// Posture counts every tenant, whatever the endpoint scope.
	for name, a := range map[string]*Adapter{
		"no tenants":  New(f.r),
		"staff only":  New(f.r, WithStaffTenants(staff)),
		"all tenants": New(f.r, WithAllTenants()),
	} {
		t.Run(name, func(t *testing.T) {
			assertJSON(t, posture(t, a), map[string]any{
				"endpoints": 4, "enabled": 3, "unsigned": 2, "not_https": 2, "tenants_with_endpoints": 3,
			})
		})
	}
	assertJSON(t, posture(t, New(newFixture(t).r)), map[string]any{
		"endpoints": 0, "enabled": 0, "unsigned": 0, "not_https": 0, "tenants_with_endpoints": 0,
	})
	if _, ok := collectorsOf(t, New(f.r, WithoutPosture())).snaps[KeyPosture]; ok {
		t.Fatal("posture registered with WithoutPosture")
	}
}

func TestEventTypes(t *testing.T) {
	f := newFixture(t)
	schema := json.RawMessage(`{ "type": "object" }`)
	dep := t0.Add(time.Hour)
	f.addType(t, &catalog.EventType{
		Definition: catalog.WebhookDefinition{
			Name: "invoice.paid", Description: "An invoice was paid.", Group: "billing",
			Schema: schema, SchemaVersion: "2", Version: "2026-01-01",
		},
		ScopeAppID: "app-1",
	})
	f.addType(t, &catalog.EventType{
		Definition:   catalog.WebhookDefinition{Name: "old.thing", Version: "2025-01-01"},
		IsDeprecated: true, DeprecatedAt: &dep,
	})
	got := items(t, New(f.r, WithStaffTenants(staff)), KeyEventTypes)
	if len(got) != 2 {
		t.Fatalf("got %d items, want 2", len(got))
	}
	sum := sha256.Sum256([]byte(`{"type":"object"}`))
	assertJSON(t, got[0], map[string]any{
		"id": "invoice.paid", "name": "invoice.paid", "group": "billing", "version": "2026-01-01",
		"schema_version": "2", "description": "An invoice was paid.", "deprecated": false,
		"deprecated_at": nil, "scope_app_id": "app-1", "schema_sha256": hex.EncodeToString(sum[:]),
	})
	assertJSON(t, got[1], map[string]any{
		"id": "old.thing", "name": "old.thing", "group": "", "version": "2025-01-01",
		"schema_version": "", "description": "", "deprecated": true,
		"deprecated_at": "2026-11-01T10:30:15Z", "scope_app_id": "", "schema_sha256": nil,
	})

	if _, ok := collectorsOf(t, New(f.r, WithoutEventTypes())).pops[KeyEventTypes]; ok {
		t.Fatal("event types registered with WithoutEventTypes")
	}
	// A bare endpoint store has no catalog, so there is nothing to list.
	if _, ok := collectorsOf(t, NewFromStore(endpointOnly{f.st}, WithStaffTenants(staff))).pops[KeyEventTypes]; ok {
		t.Fatal("event types registered with no catalog")
	}
}

// endpointOnly hides every method but endpoint.Store's.
type endpointOnly struct{ endpoint.Store }

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	staffEP := f.addEndpoint(t, &endpoint.Endpoint{})
	custEP := f.addEndpoint(t, &endpoint.Endpoint{TenantID: customer})

	cases := []struct {
		name string
		opts []Option
		want []string // nil means the population isn't registered
	}{
		{"default", []Option{WithStaffTenants(staff)}, []string{staffEP.ID.String()}},
		{"all tenants", []Option{WithAllTenants()}, []string{staffEP.ID.String(), custEP.ID.String()}},
		{"explicit list", []Option{WithStaffTenants(staff, customer)}, []string{staffEP.ID.String(), custEP.ID.String()}},
		{"blank tenant ignored", []Option{WithStaffTenants(staff, "", "  ")}, []string{staffEP.ID.String()}},
		{"no tenants", nil, nil},
		{"blank only", []Option{WithStaffTenants("")}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(f.r, tc.opts...)
			p, ok := collectorsOf(t, a).pops[KeyEndpoints]
			if tc.want == nil {
				if ok {
					t.Fatal("endpoint population registered with no staff tenants")
				}
				return
			}
			if !ok {
				t.Fatal("endpoint population missing")
			}
			got, err := p.Collect(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if g, w := ids(got), sortedIDs(tc.want...); !slices.Equal(g, w) {
				t.Errorf("endpoints = %v, want %v", g, w)
			}
		})
	}
}

// filterless ignores the tenant filter, as a broken store might. The
// adapter checks each row's tenant again, so the scope still holds.
type filterless struct{ endpoint.Store }

func (s filterless) ListEndpoints(ctx context.Context, _ string, opts endpoint.ListOpts) ([]*endpoint.Endpoint, error) {
	return s.Store.ListEndpoints(ctx, "", opts)
}

func TestStaffScopeSurvivesAStoreThatIgnoresTheFilter(t *testing.T) {
	f := newFixture(t)
	staffEP := f.addEndpoint(t, &endpoint.Endpoint{})
	f.addEndpoint(t, &endpoint.Endpoint{TenantID: customer})
	got := ids(items(t, NewFromStore(filterless{f.st}, WithStaffTenants(staff)), KeyEndpoints))
	if !slices.Equal(got, []string{staffEP.ID.String()}) {
		t.Fatalf("endpoints = %v", got)
	}
}

func TestPages(t *testing.T) {
	f := newFixture(t)
	const n = 2*pageSize + 123
	for i := range n {
		ep := &endpoint.Endpoint{Enabled: i%2 == 0}
		ep.CreatedAt = t0.Add(time.Duration(i%7) * time.Second)
		ep.UpdatedAt = ep.CreatedAt
		f.addEndpoint(t, ep)
		f.addType(t, &catalog.EventType{Definition: catalog.WebhookDefinition{Name: fmt.Sprintf("type.%05d", i)}})
	}
	for range 30 {
		f.addEndpoint(t, &endpoint.Endpoint{TenantID: customer})
	}
	a := New(f.r, WithStaffTenants(staff))
	if got := len(items(t, a, KeyEndpoints)); got != n {
		t.Errorf("endpoints = %d, want %d", got, n)
	}
	if got := len(items(t, a, KeyEventTypes)); got != n {
		t.Errorf("event types = %d, want %d", got, n)
	}
	if got := posture(t, a)["endpoints"]; got != n+30 {
		t.Errorf("posture endpoints = %v, want %d", got, n+30)
	}
}

// stuck ignores Offset, so a caller paging to the end would loop forever.
type stuck struct{ endpoint.Store }

func (s stuck) ListEndpoints(ctx context.Context, tenantID string, opts endpoint.ListOpts) ([]*endpoint.Endpoint, error) {
	opts.Offset = 0
	return s.Store.ListEndpoints(ctx, tenantID, opts)
}

func TestStoreThatIgnoresOffsetFails(t *testing.T) {
	f := newFixture(t)
	for range pageSize + 1 {
		f.addEndpoint(t, &endpoint.Endpoint{})
	}
	c := collectorsOf(t, NewFromStore(stuck{f.st}, WithStaffTenants(staff)))
	if _, err := c.pops[KeyEndpoints].Collect(context.Background()); err == nil {
		t.Error("endpoints: nil error from a store that ignores Offset")
	}
	if _, err := c.snaps[KeyPosture].Collect(context.Background()); err == nil {
		t.Error("posture: nil error from a store that ignores Offset")
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 5
	t.Cleanup(func() { maxItems = old })

	f := newFixture(t)
	for i := range 6 {
		f.addEndpoint(t, &endpoint.Endpoint{})
		f.addType(t, &catalog.EventType{Definition: catalog.WebhookDefinition{Name: fmt.Sprint("t", i)}})
	}
	c := collectorsOf(t, New(f.r, WithStaffTenants(staff)))
	for _, k := range []string{KeyEndpoints, KeyEventTypes} {
		if _, err := c.pops[k].Collect(context.Background()); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: err = %v, want ErrTooMany", k, err)
		}
	}
	// Posture sends counts, not rows, so the population cap doesn't apply.
	if _, err := c.snaps[KeyPosture].Collect(context.Background()); err != nil {
		t.Errorf("posture: %v", err)
	}
}

func TestNeverSendsContent(t *testing.T) {
	const canary = "CANARY-5d1a"
	f := newFixture(t)
	f.addEndpoint(t, &endpoint.Endpoint{
		URL:         "https://" + canary + "-user:" + canary + "-pass@hooks.example.com/" + canary + "-path/T0K3N?token=" + canary + "-query#" + canary + "-frag",
		Secret:      canary + "-secret",
		Description: canary + "-description",
		Headers:     map[string]string{"Authorization": "Bearer " + canary + "-header"},
		Metadata:    map[string]string{"note": canary + "-metadata"},
		EventTypes:  []string{"invoice.*"},
		Enabled:     true,
	})
	f.addEndpoint(t, &endpoint.Endpoint{TenantID: customer, URL: "https://customer.example/" + canary + "-cust-path", Secret: canary + "-cust-secret"})
	f.addType(t, &catalog.EventType{
		Definition: catalog.WebhookDefinition{
			Name:    "invoice.paid",
			Schema:  json.RawMessage(`{"title":"` + canary + `-schema"}`),
			Example: json.RawMessage(`{"amount":"` + canary + `-example"}`),
		},
		Metadata: map[string]string{"x": canary + "-type-metadata"},
	})
	if err := f.st.CreateEvent(context.Background(), &event.Event{
		ID: id.NewEventID(), Type: "invoice.paid", TenantID: staff, Data: map[string]any{"x": canary + "-event-data"},
	}); err != nil {
		t.Fatal(err)
	}

	c := collectorsOf(t, New(f.r, WithAllTenants()))
	if len(c.pops) != 2 || len(c.snaps) != 1 {
		t.Fatalf("collectors = %d populations, %d snapshots", len(c.pops), len(c.snaps))
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
	for _, bad := range []string{canary, "T0K3N", "Bearer", "whsec_"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
	if !strings.Contains(string(raw), `"destination_host":"hooks.example.com"`) {
		t.Fatalf("destination host missing: %s", raw)
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
