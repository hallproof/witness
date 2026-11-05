package bastion

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	bst "github.com/xraph/bastion"

	"github.com/hallproof/witness/push"
)

// maxItems is the most routes the route collector sends before it fails
// the run. A variable so tests can lower it.
var maxItems = push.MaxItems

// collectRoutes reads the live route table. It reads RouteManager here,
// not when the adapter is built, because Bastion sets it only after the
// gateway registers.
func (a *Adapter) collectRoutes(context.Context) ([]map[string]any, error) {
	cfg := a.gw.Config()
	if !cfg.Enabled {
		// A disabled gateway serves nothing.
		return []map[string]any{}, nil
	}
	rm := a.gw.RouteManager()
	if rm == nil {
		return nil, ErrNoRouteTable
	}
	routes := rm.ListRoutes()
	if len(routes) > maxItems {
		return nil, fmt.Errorf("%w: %d routes, at most %d", ErrTooMany, len(routes), maxItems)
	}
	routes = slices.DeleteFunc(routes, func(r *bst.Route) bool { return r == nil })
	slices.SortFunc(routes, func(x, y *bst.Route) int { return strings.Compare(x.ID, y.ID) })
	out := make([]map[string]any, 0, len(routes))
	for _, r := range routes {
		out = append(out, a.route(cfg, r))
	}
	return out, nil
}

// route is one route's item. It reads only configuration fields. The
// health monitor and proxy write a target's live fields (health, open
// connections, circuit state, counters) while the gateway runs, so they
// are never read: they'd race, and they'd change the item on every run.
func (a *Adapter) route(cfg bst.Config, r *bst.Route) map[string]any {
	required, skipped, providers := authOf(cfg.Auth, r.Auth)
	var scopes []string
	var forward bool
	if r.Auth != nil {
		scopes = r.Auth.Scopes
		forward = r.Auth.ForwardAuth
	}
	var routeRL any
	if r.RateLimit != nil {
		routeRL = rateLimit(*r.RateLimit)
	}
	retry := cfg.Retry.Enabled
	if r.Retry != nil {
		retry = r.Retry.Enabled
	}

	it := map[string]any{
		"id":           r.ID,
		"path":         r.Path,
		"methods":      names(r.Methods),
		"protocol":     string(r.Protocol),
		"source":       string(r.Source),
		"service_name": r.ServiceName,
		"enabled":      r.Enabled,
		"priority":     r.Priority,
		"version":      r.Version,

		"auth_required":  required,
		"auth_providers": providers,
		"auth_scopes":    names(scopes),
		"auth_skipped":   skipped,
		"forward_auth":   forward,

		"rate_limit_global": rateLimit(cfg.RateLimiting),
		"rate_limit_route":  routeRL,

		"strip_prefix": r.StripPrefix,
		"add_prefix":   r.AddPrefix,
		"rewrite_path": r.RewritePath,
		"header_rules": headerNames(r.Headers),
		"transform":    nil,

		"traffic_policy": nil,

		// The response cache and circuit breakers are gateway-wide in
		// Bastion: a route's cache block only tunes TTL, methods and vary
		// headers, and the proxy doesn't read a route's breaker override.
		// Retries do follow the route's override.
		"cache_enabled":           cfg.Caching.Enabled,
		"retry_enabled":           retry,
		"circuit_breaker_enabled": cfg.CircuitBreaker.Enabled,
		"updated_at":              stamp(r.UpdatedAt),
	}
	if r.Transform != nil {
		it["transform"] = map[string]any{
			"request_headers":  headerNames(r.Transform.RequestHeaders),
			"response_headers": headerNames(r.Transform.ResponseHeaders),
		}
	}
	if tp := r.TrafficPolicy; tp != nil {
		// Mirroring copies live traffic to another host, which is data
		// leaving, so its origin goes out. Match values (cookie and header
		// values) don't.
		it["traffic_policy"] = map[string]any{
			"type":          string(tp.Type),
			"rule_count":    len(tp.Rules),
			"mirror_origin": originOf(tp.MirrorTarget),
		}
	}
	a.targets(cfg, r, it)
	return it
}

// targets adds the upstream fields to it.
func (a *Adapter) targets(cfg bst.Config, r *bst.Route, it map[string]any) {
	type entry struct {
		origin string
		weight int
		item   map[string]any
	}
	var entries []entry
	schemes := []string{}
	var tlsCount int
	insecure := cfg.TLS.InsecureSkipVerify
	for _, t := range r.Targets {
		if t == nil {
			continue
		}
		u := parse(t.URL)
		var origin string
		if u != nil {
			origin = u.Scheme + "://" + u.Host
			if !slices.Contains(schemes, u.Scheme) {
				schemes = append(schemes, u.Scheme)
			}
			if secure(u.Scheme) {
				tlsCount++
			}
		}
		tlsOn, mtls, serverName := false, false, ""
		if t.TLS != nil && t.TLS.Enabled {
			tlsOn = true
			mtls = t.TLS.ClientCertFile != ""
			serverName = t.TLS.ServerName
			insecure = insecure || t.TLS.InsecureSkipVerify
		}
		item := map[string]any{
			"origin":      nil,
			"weight":      t.Weight,
			"tls_enabled": tlsOn,
			"mtls":        mtls,
			"server_name": serverName,
			"tags":        names(t.Tags),
		}
		if origin != "" {
			item["origin"] = origin
		}
		entries = append(entries, entry{origin: origin, weight: t.Weight, item: item})
	}
	slices.Sort(schemes)
	slices.SortStableFunc(entries, func(x, y entry) int {
		if c := strings.Compare(x.origin, y.origin); c != 0 {
			return c
		}
		return x.weight - y.weight
	})
	list := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		list = append(list, e.item)
	}

	upstreamTLS := "none"
	switch {
	case tlsCount > 0 && tlsCount == len(list):
		upstreamTLS = "all"
	case tlsCount > 0:
		upstreamTLS = "some"
	}
	it["upstream_tls"] = upstreamTLS
	it["upstream_insecure_skip_verify"] = insecure
	it["target_count"] = len(list)
	it["target_schemes"] = schemes
	it["targets"] = nil
	if r.Source == bst.SourceManual && !a.o.TargetsSummary {
		it["targets"] = list
	}
}

// authOf works out whether a route requires authentication the way
// Bastion's security.(*Auth).Authenticate does (security/auth.go in
// v1.4.1). Bastion has no read API for this, so the logic is copied, and
// the package doc lists that as a library gap.
func authOf(global bst.AuthConfig, route *bst.RouteAuthConfig) (required, skipped bool, providers []string) {
	providers = []string{}
	if route != nil && (route.SkipAuth || !route.Enabled) {
		skipped = true
	}
	if !global.Enabled || skipped {
		return false, skipped, providers
	}
	effective := global.Providers
	if route != nil && len(route.Providers) > 0 {
		effective = route.Providers
	}
	if len(effective) == 0 {
		// No providers: Bastion lets everything through when the default
		// policy is "allow" and refuses everything otherwise.
		return global.DefaultPolicy != "allow", false, providers
	}
	return true, false, names(effective)
}

func rateLimit(rl bst.RateLimitConfig) map[string]any {
	return map[string]any{
		"enabled":          rl.Enabled,
		"requests_per_sec": rl.RequestsPerSec,
		"burst":            rl.Burst,
		"per_client":       rl.PerClient,
	}
}

// headerNames is a header policy's header names. The values are never
// sent: they can set Authorization or an API key on the upstream request.
func headerNames(h bst.HeaderPolicy) map[string]any {
	return map[string]any{
		"add":    keys(h.Add),
		"set":    keys(h.Set),
		"remove": names(h.Remove),
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// names is a sorted, deduplicated copy of s, never nil.
func names(s []string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}

// parse returns raw as a URL with a scheme and a host, or nil.
func parse(raw string) *url.URL {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u
}

// originOf is raw's scheme, host and port, with no user, path or query,
// or nil when raw is empty or isn't a URL with a host.
func originOf(raw string) any {
	u := parse(raw)
	if u == nil {
		return nil
	}
	return u.Scheme + "://" + u.Host
}

func secure(scheme string) bool {
	switch scheme {
	case "https", "wss", "grpcs":
		return true
	}
	return false
}

func (a *Adapter) collectGateway(context.Context) (map[string]any, error) {
	cfg := a.gw.Config()

	var lastReload any
	if tm := a.gw.TLS(); tm != nil && cfg.TLS.Enabled {
		if at := tm.LastReload(); !at.IsZero() {
			lastReload = stamp(at)
		}
	}
	var routeCount any
	if rm := a.gw.RouteManager(); rm != nil {
		routeCount = rm.RouteCount()
	}
	wildcard := slices.Contains(cfg.CORS.AllowOrigins, "*")

	return map[string]any{
		"enabled":   cfg.Enabled,
		"base_path": cfg.BasePath,
		"auth": map[string]any{
			"enabled":         cfg.Auth.Enabled,
			"default_policy":  cfg.Auth.DefaultPolicy,
			"providers":       names(cfg.Auth.Providers),
			"forward_headers": cfg.Auth.ForwardHeaders,
		},
		"upstream_tls": map[string]any{
			"enabled":              cfg.TLS.Enabled,
			"min_version":          cfg.TLS.MinVersion,
			"insecure_skip_verify": cfg.TLS.InsecureSkipVerify,
			"cipher_suites":        names(cfg.TLS.CipherSuites),
			"mtls":                 cfg.TLS.ClientCertFile != "",
			"last_reload":          lastReload,
		},
		"rate_limiting": map[string]any{
			"enabled":          cfg.RateLimiting.Enabled,
			"requests_per_sec": cfg.RateLimiting.RequestsPerSec,
			"burst":            cfg.RateLimiting.Burst,
			"per_client":       cfg.RateLimiting.PerClient,
			"key_header":       cfg.RateLimiting.KeyHeader,
		},
		// Counts only: the lists can hold staff home addresses.
		"ip_filter": map[string]any{
			"enabled":     cfg.IPFilter.Enabled,
			"allow_count": len(cfg.IPFilter.AllowIPs),
			"deny_count":  len(cfg.IPFilter.DenyIPs),
		},
		"cors": map[string]any{
			"enabled":           cfg.CORS.Enabled,
			"allow_origins":     names(cfg.CORS.AllowOrigins),
			"allow_credentials": cfg.CORS.AllowCreds,
			"wildcard_origin":   wildcard,
		},
		// Whether a token is set, never the token.
		"admin_api": map[string]any{
			"enabled":               cfg.Dashboard.Enabled,
			"base_path":             cfg.Dashboard.BasePath,
			"token_set":             cfg.Dashboard.AdminToken != "",
			"middleware_count":      len(cfg.Dashboard.AdminMiddleware),
			"allow_unauthenticated": cfg.Dashboard.AllowUnauthenticatedAdmin,
			"authenticated":         cfg.Dashboard.AdminAuthenticated(),
		},
		"access_log_enabled":     cfg.AccessLog.Enabled,
		"discovery_enabled":      cfg.Discovery.Enabled,
		"routes_persisted":       a.gw.RoutesPersisted(),
		"max_request_body_bytes": cfg.BufferPool.MaxRequestBodySize,
		"route_count":            routeCount,
	}, nil
}

// stamp is t in UTC to the second, or nil for the zero time.
func stamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}
