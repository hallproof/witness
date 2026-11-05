package bastion

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	bst "github.com/xraph/bastion"
	"github.com/xraph/bastion/routing"
	forgetesting "github.com/xraph/forge/testing"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

// newGateway builds a gateway the way gateway.Wire leaves it for the
// adapter: config from options, and an in-memory route table.
func newGateway(t *testing.T, opts ...bst.ConfigOption) (*bst.Gateway, *routing.Manager) {
	t.Helper()
	gw, ok := bst.New(opts...).(*bst.Gateway)
	if !ok {
		t.Fatal("bastion.New did not return *bastion.Gateway")
	}
	rm := routing.NewManager()
	gw.SetRouteRegistry(rm)
	return gw, rm
}

// addRoute adds r the way the gateway does. AddRoute stamps the route
// with the current time, and the helper leaves that alone, so a test sees
// what a real gateway would send.
func addRoute(t *testing.T, rm *routing.Manager, r *bst.Route) {
	t.Helper()
	if r.Source == "" {
		r.Source = bst.SourceManual
	}
	if r.Protocol == "" {
		r.Protocol = bst.ProtocolHTTP
	}
	if err := rm.AddRoute(r); err != nil {
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

func items(t *testing.T, a *Adapter) []map[string]any {
	t.Helper()
	p, ok := collectorsOf(t, a).pops[KeyRoutes]
	if !ok {
		t.Fatalf("no population %q", KeyRoutes)
	}
	out, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func settings(t *testing.T, a *Adapter) map[string]any {
	t.Helper()
	s, ok := collectorsOf(t, a).snaps[KeyGateway]
	if !ok {
		t.Fatalf("no snapshot %q", KeyGateway)
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

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"bastion"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("bastion adapter is not registered")
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

func TestAttachRegistersFromConfig(t *testing.T) {
	gw, rm := newGateway(t)
	addRoute(t, rm, &bst.Route{ID: "r1", Path: "/a", Enabled: true, Targets: []*bst.Target{{ID: "t", URL: "https://a.internal"}}})
	c := vessel.New()
	if err := vessel.ProvideValue(c, gw); err != nil {
		t.Fatal(err)
	}
	h := adapter.Host{Witness: newWitness(t), Container: c, Config: map[string]any{"targets_summary": true}}
	a, found, err := fromHost(h)
	if !found || err != nil || a == nil {
		t.Fatalf("fromHost = %v, %v, %v", a, found, err)
	}
	if !a.o.TargetsSummary {
		t.Fatal("targets_summary was not decoded")
	}
	found, err = attach(context.Background(), h)
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyRoutes, KeyGateway} {
		if !taken(t, h.Witness, k) {
			t.Errorf("%s was not registered", k)
		}
	}
}

func TestAttachBadConfig(t *testing.T) {
	gw, _ := newGateway(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, gw); err != nil {
		t.Fatal(err)
	}
	found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c, Config: map[string]any{"targets_summary": "yes"}})
	if !found || err == nil {
		t.Fatalf("attach = %v, %v; want true and an error", found, err)
	}
}

func TestRoutes(t *testing.T) {
	gw, rm := newGateway(t,
		bst.WithAuth(bst.AuthConfig{Enabled: true, Providers: []string{"apikey"}}),
		bst.WithRateLimiting(bst.RateLimitConfig{Enabled: true, RequestsPerSec: 100, Burst: 200, PerClient: true, KeyHeader: "X-Client"}),
		bst.WithCircuitBreaker(bst.CircuitBreakerConfig{Enabled: true}),
	)
	addRoute(t, rm, &bst.Route{
		ID: "manual-api-/api", Path: "/api", Methods: []string{"POST", "GET"},
		ServiceName: "api", Priority: 10, Version: 3, Enabled: true,
		StripPrefix: true, AddPrefix: "/v1", RewritePath: "/internal/{path}",
		Headers: bst.HeaderPolicy{
			Add:    map[string]string{"X-Trace": "on"},
			Set:    map[string]string{"Authorization": "Bearer x"},
			Remove: []string{"Cookie"},
		},
		Targets: []*bst.Target{
			{ID: "t1", URL: "https://api.internal:8443/base?q=1", Weight: 2, Tags: []string{"blue"}, TLS: &bst.TargetTLSConfig{
				Enabled: true, ClientCertFile: "/etc/c.pem", ClientKeyFile: "/etc/k.pem", ServerName: "api.internal",
			}},
			{ID: "t2", URL: "http://10.0.0.2:8080", Weight: 1},
		},
		RateLimit: &bst.RateLimitConfig{Enabled: true, RequestsPerSec: 5, Burst: 10, PerClient: true, KeyHeader: "X-Key"},
		Auth:      &bst.RouteAuthConfig{Enabled: true, Providers: []string{"jwt"}, Scopes: []string{"write", "read"}, ForwardAuth: true},
		Retry:     &bst.RetryConfig{Enabled: true},
		TrafficPolicy: &bst.TrafficPolicy{
			Type:         bst.TrafficMirror,
			Rules:        []bst.TrafficRule{{Match: bst.TrafficMatch{Type: bst.MatchHeader, Key: "X-Canary", Value: "1"}, Weight: 10}},
			MirrorTarget: "https://shadow.internal:9000/mirror",
		},
		Transform: &bst.TransformConfig{
			RequestHeaders:  bst.HeaderPolicy{Set: map[string]string{"X-Api-Key": "k"}},
			ResponseHeaders: bst.HeaderPolicy{Remove: []string{"Server"}},
		},
	})
	addRoute(t, rm, &bst.Route{
		ID: "discovery-users", Path: "/users", Source: bst.SourceDiscovery, ServiceName: "users", Enabled: true,
		Auth: &bst.RouteAuthConfig{SkipAuth: true},
		Targets: []*bst.Target{
			{ID: "p1", URL: "http://10.1.0.7:80"},
			{ID: "p2", URL: "https://10.1.0.8:443"},
		},
	})

	got := items(t, New(gw))
	if !slices.Equal(ids(got), []string{"discovery-users", "manual-api-/api"}) {
		t.Fatalf("ids = %v", ids(got))
	}
	globalRL := map[string]any{"enabled": true, "requests_per_sec": 100, "burst": 200, "per_client": true}
	assertJSON(t, got[1], map[string]any{
		"id": "manual-api-/api", "path": "/api", "methods": []string{"GET", "POST"},
		"protocol": "http", "source": "manual", "service_name": "api",
		"enabled": true, "priority": 10,
		"auth_required": true, "auth_providers": []string{"jwt"}, "auth_scopes": []string{"read", "write"},
		"auth_skipped": false, "forward_auth": true,
		"rate_limit_global": globalRL,
		"rate_limit_route":  map[string]any{"enabled": true, "requests_per_sec": 5, "burst": 10, "per_client": true},
		"upstream_tls":      "some", "upstream_insecure_skip_verify": false,
		"target_count": 2, "target_schemes": []string{"http", "https"},
		"targets": []map[string]any{
			{"origin": "http://10.0.0.2:8080", "weight": 1, "tls_enabled": false, "mtls": false, "server_name": "", "tags": []string{}},
			{"origin": "https://api.internal:8443", "weight": 2, "tls_enabled": true, "mtls": true, "server_name": "api.internal", "tags": []string{"blue"}},
		},
		"strip_prefix": true, "add_prefix": "/v1", "rewrite_path": "/internal/{path}",
		"header_rules": map[string]any{"add": []string{"X-Trace"}, "set": []string{"Authorization"}, "remove": []string{"Cookie"}},
		"transform": map[string]any{
			"request_headers":  map[string]any{"add": []string{}, "set": []string{"X-Api-Key"}, "remove": []string{}},
			"response_headers": map[string]any{"add": []string{}, "set": []string{}, "remove": []string{"Server"}},
		},
		"traffic_policy":          map[string]any{"type": "mirror", "rule_count": 1, "mirror_origin": "https://shadow.internal:9000"},
		"cache_enabled":           false,
		"retry_enabled":           true,
		"circuit_breaker_enabled": true,
	})
	// A discovery route sends a summary of its targets, not the list,
	// because pod addresses churn.
	d := got[0]
	if d["targets"] != nil || d["target_count"] != 2 || !slices.Equal(d["target_schemes"].([]string), []string{"http", "https"}) {
		t.Fatalf("discovery targets = %v, %v, %v", d["targets"], d["target_count"], d["target_schemes"])
	}
	if d["auth_required"] != false || d["auth_skipped"] != true || d["upstream_tls"] != "some" {
		t.Fatalf("discovery route = %v", d)
	}
	if d["header_rules"] == nil || d["transform"] != nil || d["traffic_policy"] != nil || d["rate_limit_route"] != nil {
		t.Fatalf("discovery route optional blocks = %v", d)
	}
}

func TestRoutesTargetsSummary(t *testing.T) {
	gw, rm := newGateway(t)
	addRoute(t, rm, &bst.Route{ID: "r1", Path: "/a", Enabled: true, Targets: []*bst.Target{{ID: "t", URL: "https://a.internal"}}})
	got := items(t, New(gw, WithTargetsSummary()))
	if got[0]["targets"] != nil || got[0]["target_count"] != 1 || got[0]["upstream_tls"] != "all" {
		t.Fatalf("item = %v", got[0])
	}
}

func TestRoutesAuthRequired(t *testing.T) {
	cases := []struct {
		name      string
		global    bst.AuthConfig
		route     *bst.RouteAuthConfig
		required  bool
		skipped   bool
		providers []string
	}{
		{"auth off", bst.AuthConfig{}, nil, false, false, []string{}},
		{"global providers", bst.AuthConfig{Enabled: true, Providers: []string{"apikey"}}, nil, true, false, []string{"apikey"}},
		{"route providers win", bst.AuthConfig{Enabled: true, Providers: []string{"apikey"}}, &bst.RouteAuthConfig{Enabled: true, Providers: []string{"jwt"}}, true, false, []string{"jwt"}},
		{"route skips", bst.AuthConfig{Enabled: true, Providers: []string{"apikey"}}, &bst.RouteAuthConfig{Enabled: true, SkipAuth: true}, false, true, []string{}},
		{"route disabled", bst.AuthConfig{Enabled: true, Providers: []string{"apikey"}}, &bst.RouteAuthConfig{}, false, true, []string{}},
		{"no providers allow", bst.AuthConfig{Enabled: true, DefaultPolicy: "allow"}, nil, false, false, []string{}},
		{"no providers deny", bst.AuthConfig{Enabled: true}, nil, true, false, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw, rm := newGateway(t, bst.WithAuth(tc.global))
			addRoute(t, rm, &bst.Route{ID: "r", Path: "/r", Enabled: true, Auth: tc.route})
			it := items(t, New(gw))[0]
			if it["auth_required"] != tc.required || it["auth_skipped"] != tc.skipped || !slices.Equal(it["auth_providers"].([]string), tc.providers) {
				t.Fatalf("auth = %v, %v, %v; want %v, %v, %v", it["auth_required"], it["auth_skipped"], it["auth_providers"], tc.required, tc.skipped, tc.providers)
			}
		})
	}
}

func TestRoutesInsecureSkipVerify(t *testing.T) {
	gw, rm := newGateway(t)
	addRoute(t, rm, &bst.Route{ID: "a", Path: "/a", Enabled: true, Targets: []*bst.Target{{ID: "t", URL: "https://a", TLS: &bst.TargetTLSConfig{Enabled: true, InsecureSkipVerify: true}}}})
	addRoute(t, rm, &bst.Route{ID: "b", Path: "/b", Enabled: true, Targets: []*bst.Target{{ID: "u", URL: "http://b"}}})
	got := items(t, New(gw))
	if got[0]["upstream_insecure_skip_verify"] != true || got[1]["upstream_insecure_skip_verify"] != false || got[1]["upstream_tls"] != "none" {
		t.Fatalf("items = %v", got)
	}
	// The global setting applies to every target.
	gw, rm = newGateway(t, bst.WithTLS(bst.TLSConfig{InsecureSkipVerify: true}))
	addRoute(t, rm, &bst.Route{ID: "b", Path: "/b", Enabled: true, Targets: []*bst.Target{{ID: "u", URL: "https://b"}}})
	if it := items(t, New(gw))[0]; it["upstream_insecure_skip_verify"] != true {
		t.Fatalf("item = %v", it)
	}
}

// The route table is wired after Register, so the adapter reads it when it
// collects, and a gateway with no table yet fails the run rather than
// reporting no routes.
func TestRoutesReadAtCollectTime(t *testing.T) {
	gw, ok := bst.New().(*bst.Gateway)
	if !ok {
		t.Fatal("not a gateway")
	}
	a := New(gw)
	p := collectorsOf(t, a).pops[KeyRoutes]
	if _, err := p.Collect(context.Background()); !errors.Is(err, ErrNoRouteTable) {
		t.Fatalf("collect before wiring = %v; want ErrNoRouteTable", err)
	}
	if s := settings(t, a); s["route_count"] != nil {
		t.Fatalf("route_count before wiring = %v", s["route_count"])
	}
	rm := routing.NewManager()
	gw.SetRouteRegistry(rm)
	addRoute(t, rm, &bst.Route{ID: "late", Path: "/late", Enabled: true})
	got, err := p.Collect(context.Background())
	if err != nil || !slices.Equal(ids(got), []string{"late"}) {
		t.Fatalf("collect after wiring = %v, %v", got, err)
	}
}

func TestRoutesDisabledGateway(t *testing.T) {
	gw, ok := bst.New(bst.WithEnabled(false)).(*bst.Gateway)
	if !ok {
		t.Fatal("not a gateway")
	}
	got := items(t, New(gw))
	if len(got) != 0 {
		t.Fatalf("items = %v", got)
	}
}

func TestGateway(t *testing.T) {
	gw, rm := newGateway(t,
		bst.WithBasePath("/gw"),
		bst.WithAuth(bst.AuthConfig{Enabled: true, DefaultPolicy: "deny", Providers: []string{"jwt", "apikey"}, ForwardHeaders: true}),
		bst.WithTLS(bst.TLSConfig{Enabled: true, MinVersion: "1.3", CipherSuites: []string{"TLS_AES_128_GCM_SHA256"}, ClientCertFile: "/etc/c.pem", ClientKeyFile: "/etc/k.pem", ReloadInterval: time.Hour}),
		bst.WithRateLimiting(bst.RateLimitConfig{Enabled: true, RequestsPerSec: 50, Burst: 75, PerClient: true, KeyHeader: "X-Client"}),
		bst.WithIPFilter(bst.IPFilterConfig{Enabled: true, AllowIPs: []string{"10.0.0.0/8", "192.168.0.0/16"}, DenyIPs: []string{"10.9.9.9"}}),
		bst.WithCORS(bst.CORSConfig{Enabled: true, AllowOrigins: []string{"https://app.example.com", "*"}, AllowCreds: true}),
		bst.WithDashboard(bst.DashboardConfig{Enabled: true, BasePath: "/gw/admin"}),
		bst.WithAdminToken("secret"),
		bst.WithAccessLog(bst.AccessLogConfig{Enabled: true}),
		bst.WithDiscoveryEnabled(false),
	)
	addRoute(t, rm, &bst.Route{ID: "a", Path: "/a", Enabled: true})
	addRoute(t, rm, &bst.Route{ID: "b", Path: "/b", Enabled: true})

	assertJSON(t, settings(t, New(gw)), map[string]any{
		"enabled": true, "base_path": "/gw",
		"auth": map[string]any{"enabled": true, "default_policy": "deny", "providers": []string{"apikey", "jwt"}, "forward_headers": true},
		"upstream_tls": map[string]any{
			"enabled": true, "min_version": "1.3", "insecure_skip_verify": false,
			"cipher_suites": []string{"TLS_AES_128_GCM_SHA256"}, "mtls": true, "reload_interval_seconds": 3600,
		},
		"rate_limiting": map[string]any{"enabled": true, "requests_per_sec": 50, "burst": 75, "per_client": true, "key_header": "X-Client"},
		"ip_filter":     map[string]any{"enabled": true, "allow_count": 2, "deny_count": 1},
		"cors":          map[string]any{"enabled": true, "allow_origins": []string{"*", "https://app.example.com"}, "allow_credentials": true, "wildcard_origin": true},
		"admin_api": map[string]any{
			"enabled": true, "base_path": "/gw/admin", "token_set": true, "middleware_count": 0,
			"allow_unauthenticated": false, "authenticated": true,
		},
		"access_log_enabled": true, "discovery_enabled": false, "routes_persisted": false,
		"max_request_body_bytes": 10 * 1024 * 1024, "route_count": 2,
	})
}

// Two replicas built from the same config, one an hour after the other,
// and one whose discovery poll has re-applied the route since, must send
// the same routes. Bastion stamps UpdatedAt on every AddRoute and bumps
// UpdatedAt and Version on every UpdateRoute, discovery polls included, so
// neither field can go out: N replicas would send N different
// populations, and a discovery gateway would re-send forever.
func TestRoutesSameAcrossReplicas(t *testing.T) {
	build := func() (*bst.Gateway, *routing.Manager, *bst.Route) {
		gw, rm := newGateway(t, bst.WithAuth(bst.AuthConfig{Enabled: true, Providers: []string{"apikey"}}))
		r := &bst.Route{ID: "users", Path: "/users", Source: bst.SourceDiscovery, ServiceName: "users", Enabled: true,
			Targets: []*bst.Target{{ID: "p1", URL: "http://10.1.0.7:80"}}}
		addRoute(t, rm, r)
		return gw, rm, r
	}
	early, _, r := build()
	// The first replica started an hour ago.
	r.CreatedAt = r.CreatedAt.Add(-time.Hour)
	r.UpdatedAt = r.UpdatedAt.Add(-time.Hour)

	late, rm, r2 := build()
	// A discovery poll re-applies the same route.
	again := *r2
	if err := rm.UpdateRoute(&again); err != nil {
		t.Fatal(err)
	}

	a, b := items(t, New(early)), items(t, New(late))
	ja, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ja) != string(jb) {
		t.Fatalf("replicas differ:\n%s\n%s", ja, jb)
	}
	for _, k := range []string{"updated_at", "version"} {
		if _, ok := a[0][k]; ok {
			t.Errorf("item has %q", k)
		}
	}
}

// Two replicas with the same TLS config must send the same snapshot. The
// TLS manager's last reload is per process and changes on every reload
// tick (and is read without a lock), so it isn't sent; the configured
// reload interval is.
func TestGatewaySameAcrossReplicas(t *testing.T) {
	build := func() *bst.Gateway {
		gw, ok := bst.New(bst.WithTLS(bst.TLSConfig{Enabled: true, MinVersion: "1.2", ReloadInterval: time.Hour})).(*bst.Gateway)
		if !ok {
			t.Fatal("bastion.New did not return *bastion.Gateway")
		}
		if err := gw.Register(forgetesting.NewTestApp("replica", "v0")); err != nil {
			t.Fatal(err)
		}
		gw.SetRouteRegistry(routing.NewManager())
		if gw.TLS() == nil {
			t.Fatal("no TLS manager after Register")
		}
		return gw
	}
	early := build()
	// Wait for the clock to pass the next whole second, so a reload time
	// would differ between the two.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 10*time.Millisecond)))
	late := build()

	ja, err := json.Marshal(settings(t, New(early)))
	if err != nil {
		t.Fatal(err)
	}
	jb, err := json.Marshal(settings(t, New(late)))
	if err != nil {
		t.Fatal(err)
	}
	if string(ja) != string(jb) {
		t.Fatalf("replicas differ:\n%s\n%s", ja, jb)
	}
	tlsBlock := settings(t, New(late))["upstream_tls"].(map[string]any)
	if _, ok := tlsBlock["last_reload"]; ok {
		t.Error("upstream_tls has last_reload")
	}
	if tlsBlock["reload_interval_seconds"] != int64(3600) {
		t.Errorf("reload_interval_seconds = %#v, want 3600", tlsBlock["reload_interval_seconds"])
	}
}

func TestGatewayOpenAdmin(t *testing.T) {
	gw, _ := newGateway(t, bst.WithDashboardEnabled(true))
	s := settings(t, New(gw))
	admin := s["admin_api"].(map[string]any)
	if admin["enabled"] != true || admin["authenticated"] != false || admin["token_set"] != false {
		t.Fatalf("admin_api = %v", admin)
	}
}

// Bastion has no tenants. What makes a gateway customer-scoped is who it
// fronts, so the adapter reads only the app's own gateway, the one in the
// container, and never one built by hand for a customer workload. The
// witness scope's AllTenants doesn't change that.
func TestStaffScope(t *testing.T) {
	platform, prm := newGateway(t)
	addRoute(t, prm, &bst.Route{ID: "platform-route", Path: "/p", Enabled: true})
	customer, crm := newGateway(t)
	addRoute(t, crm, &bst.Route{ID: "customer-route", Path: "/c", Enabled: true})
	_ = customer

	c := vessel.New()
	if err := vessel.ProvideValue(c, platform); err != nil {
		t.Fatal(err)
	}
	for _, all := range []bool{false, true} {
		a, found, err := fromHost(adapter.Host{Witness: newWitness(t), Container: c, Scope: adapter.Scope{AllTenants: all}})
		if !found || err != nil {
			t.Fatalf("fromHost = %v, %v", found, err)
		}
		if got := ids(items(t, a)); !slices.Equal(got, []string{"platform-route"}) {
			t.Fatalf("AllTenants=%v: ids = %v", all, got)
		}
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 2
	t.Cleanup(func() { maxItems = old })
	gw, rm := newGateway(t)
	for _, id := range []string{"a", "b", "c"} {
		addRoute(t, rm, &bst.Route{ID: id, Path: "/" + id, Enabled: true})
	}
	p := collectorsOf(t, New(gw)).pops[KeyRoutes]
	if _, err := p.Collect(context.Background()); !errors.Is(err, ErrTooMany) {
		t.Fatalf("collect = %v; want ErrTooMany", err)
	}
}

// The health monitor writes live target fields while the proxy runs. The
// adapter never reads them, so collecting during those writes doesn't race.
func TestCollectDuringHealthWrites(t *testing.T) {
	gw, rm := newGateway(t)
	tg := &bst.Target{ID: "t", URL: "https://a.internal"}
	addRoute(t, rm, &bst.Route{ID: "r", Path: "/r", Enabled: true, Targets: []*bst.Target{tg}})
	a := New(gw)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				tg.SetHealthy(!tg.IsHealthy())
				tg.IncrConns()
			}
		}
	})
	for range 50 {
		items(t, a)
	}
	close(stop)
	wg.Wait()
}

func TestNeverSendsContent(t *testing.T) {
	const canary = "CANARY-5b1d"
	gw, rm := newGateway(t,
		bst.WithAdminToken(canary+"-admin-token"),
		bst.WithDashboardEnabled(true),
		bst.WithIPFilter(bst.IPFilterConfig{Enabled: true, AllowIPs: []string{canary + "-allow-ip"}, DenyIPs: []string{canary + "-deny-ip"}}),
		bst.WithTLS(bst.TLSConfig{
			Enabled: true, CACertFile: canary + "-ca-file", ClientCertFile: canary + "-cert-file", ClientKeyFile: canary + "-key-file",
		}),
		bst.WithAccessLog(bst.AccessLogConfig{Enabled: true, RedactHeaders: []string{canary + "-redact"}}),
	)
	headers := func(where string) bst.HeaderPolicy {
		return bst.HeaderPolicy{
			Add: map[string]string{"X-Add": canary + "-" + where + "-add"},
			Set: map[string]string{"Authorization": "Bearer " + canary + "-" + where + "-set"},
		}
	}
	for _, src := range []bst.RouteSource{bst.SourceManual, bst.SourceDiscovery} {
		addRoute(t, rm, &bst.Route{
			ID: "r-" + string(src), Path: "/" + string(src), Source: src, Enabled: true,
			Headers: headers("route"),
			Targets: []*bst.Target{{
				ID:  "t-" + string(src),
				URL: "https://" + canary + "-user:" + canary + "-pass@api.internal:8443/" + canary + "-path?token=" + canary + "-query#" + canary + "-frag",
				TLS: &bst.TargetTLSConfig{
					Enabled: true, CACertFile: canary + "-t-ca", ClientCertFile: canary + "-t-cert", ClientKeyFile: canary + "-t-key",
				},
				Metadata:      map[string]string{"health_check_path": canary + "-target-meta"},
				TotalRequests: 4242424242, TotalErrors: 4343434343, AvgLatencyMs: 4444.4444, P99LatencyMs: 4545.4545,
				CircuitState: bst.CircuitState(canary + "-circuit"),
			}},
			TrafficPolicy: &bst.TrafficPolicy{
				Type:         bst.TrafficCanary,
				Rules:        []bst.TrafficRule{{Match: bst.TrafficMatch{Type: bst.MatchCookie, Key: "beta", Value: canary + "-match"}}},
				MirrorTarget: "https://" + canary + "-muser:" + canary + "-mpass@shadow.internal/" + canary + "-mpath?" + canary + "-mquery",
			},
			Transform: &bst.TransformConfig{RequestHeaders: headers("req"), ResponseHeaders: headers("resp")},
			Metadata:  map[string]any{"owner": canary + "-route-meta", "nested": map[string]any{"x": canary + "-nested"}},
		})
	}
	// A target URL that won't parse must not go out raw either.
	addRoute(t, rm, &bst.Route{ID: "bad", Path: "/bad", Enabled: true, Targets: []*bst.Target{{ID: "x", URL: canary + "-raw:%zz"}}})

	c := collectorsOf(t, New(gw))
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
	for _, bad := range []string{canary, "4242424242", "4343434343", "4444.4444", "4545.4545", "metadata", "admin_token", "allow_ips", "deny_ips"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
	// The allowed parts still go out: header names and origins.
	for _, want := range []string{`"Authorization"`, `"https://api.internal:8443"`, `"https://shadow.internal"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("output lacks %s: %s", want, raw)
		}
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
