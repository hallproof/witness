package nexus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xraph/nexus/id"
	"github.com/xraph/nexus/key"
	"github.com/xraph/nexus/tenant"
	"github.com/xraph/nexus/usage"

	"github.com/hallproof/witness/push"
)

// pageSize is how many rows each list call asks for: Nexus's largest page.
const pageSize = 500

// window is how far back the models in use reach.
const window = 30 * 24 * time.Hour

// maxItems is the most rows a collector reads in scope before it fails the
// run. A variable so tests can lower it.
var maxItems = push.MaxItems

// maxQueries is the most usage queries one models-in-use run makes before
// it fails. A variable so tests can lower it.
var maxQueries = 5000

// capabilityNames are the provider capability flags sent, in the names
// provider.Capabilities.Supports takes.
var capabilityNames = []string{
	"chat", "streaming", "embeddings", "images", "vision", "tools", "json",
	"audio", "thinking", "batch", "streaming_reasoning", "streaming_tools",
	"streaming_audio", "streaming_citations", "realtime_audio",
	"realtime_video", "live_bidi",
}

func (a *Adapter) collectGateway(context.Context) (map[string]any, error) {
	gw := a.gw
	providers := []map[string]any{}
	if reg := gw.Providers(); reg != nil {
		for _, p := range reg.All() {
			// Name and Capabilities are in-memory. Models and Healthy call
			// the vendor, so they are never used here.
			caps := p.Capabilities()
			flags := make(map[string]any, len(capabilityNames))
			for _, c := range capabilityNames {
				flags[c] = caps.Supports(c)
			}
			providers = append(providers, map[string]any{"name": p.Name(), "capabilities": flags})
		}
	}
	slices.SortFunc(providers, by("name"))

	all := gw.Aliases()
	aliases := make([]map[string]any, 0, len(all))
	for _, al := range all {
		// Weights churn without meaning, and tenant overrides are keyed by
		// tenant, so both are left out. Target order is the fallback order
		// and is kept.
		targets := make([]map[string]any, 0, len(al.Targets))
		for _, t := range al.Targets {
			targets = append(targets, map[string]any{"provider": t.Provider, "model": t.Model})
		}
		aliases = append(aliases, map[string]any{"name": al.Name, "targets": targets})
	}
	slices.SortFunc(aliases, by("name"))

	guards := []map[string]any{}
	if gs := gw.Guard(); gs != nil {
		for _, g := range gs.List() {
			guards = append(guards, map[string]any{"name": g.Name(), "phase": string(g.Phase())})
		}
	}
	slices.SortStableFunc(guards, by("name", "phase"))

	out := map[string]any{
		"providers":        providers,
		"aliases":          aliases,
		"routing_strategy": gw.RoutingStrategy(),
		"guards":           guards,
	}
	if cfg := gw.Config(); cfg != nil {
		out["require_api_key"] = cfg.RequireAPIKey
		out["enable_cache"] = cfg.EnableCache
		out["enable_usage"] = cfg.EnableUsage
		out["global_rate_limit"] = cfg.GlobalRateLimit
		out["default_max_retries"] = cfg.DefaultMaxRetries
		out["default_timeout_seconds"] = seconds(cfg.DefaultTimeout)
	}
	return out, nil
}

// collectModelsInUse lists the provider and model pairs a provider answered
// in the last 30 days, across every tenant. Nexus has no read for those
// pairs, so the adapter gathers candidate model names (this month's and the
// last week's usage summaries, and the alias targets), then confirms each
// with a one-row query: first by model, which finds one provider for it,
// then by each other candidate provider.
func (a *Adapter) collectModelsInUse(ctx context.Context) ([]map[string]any, error) {
	us := a.gw.Usage()
	if us == nil {
		return nil, ErrNotReady
	}
	models, providers := map[string]bool{}, map[string]bool{}
	for _, period := range []string{"month", "week"} {
		s, err := us.Summary(ctx, "", period)
		if err != nil {
			return nil, fmt.Errorf("witness/nexus: usage summary: %w", err)
		}
		if s == nil {
			continue
		}
		for m := range s.ByModel {
			models[m] = true
		}
		for p := range s.ByProvider {
			providers[p] = true
		}
	}
	for _, al := range a.gw.Aliases() {
		for _, t := range al.Targets {
			models[t.Model] = true
			providers[t.Provider] = true
		}
	}
	if reg := a.gw.Providers(); reg != nil {
		for _, p := range reg.All() {
			providers[p.Name()] = true
		}
	}
	delete(models, "")
	delete(providers, "")
	provs := sortedKeys(providers)

	since := a.now().Add(-window)
	queries := 0
	used := func(provider, model string) (string, error) {
		queries++
		if queries > maxQueries {
			return "", fmt.Errorf("%w: more than %d usage queries to find the models in use", ErrTooMany, maxQueries)
		}
		page, err := us.Query(ctx, &usage.QueryOptions{
			Provider: provider, Model: model, Outcome: usage.OutcomeOK, StartTime: since, Limit: 1,
		})
		if err != nil {
			return "", fmt.Errorf("witness/nexus: usage query: %w", err)
		}
		if page == nil || len(page.Items) == 0 {
			return "", nil
		}
		// The store filters; checking again keeps a store that ignores a
		// filter from adding a pair that wasn't asked about.
		r := page.Items[0]
		if r.Model != model || (provider != "" && r.Provider != provider) {
			return "", nil
		}
		return r.Provider, nil
	}

	out := []map[string]any{}
	add := func(p, m string) {
		out = append(out, map[string]any{"id": p + "/" + m, "provider": p, "model": m})
	}
	for _, m := range sortedKeys(models) {
		first, err := used("", m)
		if err != nil {
			return nil, err
		}
		if first == "" {
			continue
		}
		add(first, m)
		for _, p := range provs {
			if p == first {
				continue
			}
			got, err := used(p, m)
			if err != nil {
				return nil, err
			}
			if got != "" {
				add(p, m)
			}
		}
	}
	slices.SortFunc(out, by("id"))
	return out, nil
}

// scopeTenants returns the tenants in scope. With AllTenants it returns
// nil and all true; otherwise the named tenants that exist, each found by
// ID or slug. A named tenant that doesn't exist yet is skipped.
func (a *Adapter) scopeTenants(ctx context.Context) (tenants []*tenant.Tenant, all bool, err error) {
	if a.o.AllTenants {
		return nil, true, nil
	}
	ts := a.gw.Tenants()
	if ts == nil {
		return nil, false, ErrNotReady
	}
	seen := map[string]bool{}
	for _, ref := range a.tenants {
		var tn *tenant.Tenant
		if _, perr := id.ParseTenantID(ref); perr == nil {
			tn, err = ts.Get(ctx, ref)
		} else {
			tn, err = ts.GetBySlug(ctx, ref)
		}
		if errors.Is(err, tenant.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("witness/nexus: find tenant: %w", err)
		}
		if tn == nil || seen[tn.ID.String()] {
			continue
		}
		seen[tn.ID.String()] = true
		tenants = append(tenants, tn)
	}
	return tenants, false, nil
}

// eachKey calls fn for every key in scope, paging each tenant's keys, and
// fails with ErrTooMany past maxItems keys.
func (a *Adapter) eachKey(ctx context.Context, fn func(*key.APIKey)) error {
	ks := a.gw.Keys()
	if ks == nil {
		return ErrNotReady
	}
	tenants, all, err := a.scopeTenants(ctx)
	if err != nil {
		return err
	}
	filters := []string{""} // every tenant
	if !all {
		filters = filters[:0]
		for _, tn := range tenants {
			filters = append(filters, tn.ID.String())
		}
	}
	seen := map[string]bool{}
	for _, tid := range filters {
		cursor := ""
		for {
			page, err := ks.ListPage(ctx, &key.ListOptions{TenantID: tid, Limit: pageSize, Cursor: cursor})
			if err != nil {
				return fmt.Errorf("witness/nexus: list keys: %w", err)
			}
			for _, k := range page.Items {
				kid := k.ID.String()
				// The store filters by tenant; checking again keeps a store
				// that ignores the filter from widening the scope.
				if seen[kid] || (tid != "" && k.TenantID.String() != tid) {
					continue
				}
				seen[kid] = true
				if len(seen) > maxItems {
					return fmt.Errorf("%w: more than %d keys", ErrTooMany, maxItems)
				}
				fn(k)
			}
			if page.NextCursor == "" || page.NextCursor == cursor {
				break
			}
			cursor = page.NextCursor
		}
	}
	return nil
}

func (a *Adapter) collectKeys(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := a.eachKey(ctx, func(k *key.APIKey) {
		scopes := []string{}
		for _, s := range k.Scopes {
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
		slices.Sort(scopes)
		it := map[string]any{
			"id":         k.ID.String(),
			"tenant_id":  k.TenantID.String(),
			"name":       k.Name,
			"scopes":     scopes,
			"status":     string(k.Status),
			"created_at": stamp(k.CreatedAt),
			"expires_at": stampOf(k.ExpiresAt),
			// A day, not a time: last use changes on every request, and a
			// timestamp would make every run new evidence.
			"last_used_on": nil,
			"owner_id":     nil,
		}
		if k.LastUsedAt != nil {
			it["last_used_on"] = k.LastUsedAt.UTC().Format(time.DateOnly)
		}
		if owner, ok := k.Metadata[a.ownerKey]; ok && owner != "" {
			it["owner_id"] = owner
		}
		out = append(out, it)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// eachTenant calls fn for every tenant in scope, paging every tenant when
// AllTenants is on, and fails with ErrTooMany past maxItems tenants.
func (a *Adapter) eachTenant(ctx context.Context, fn func(*tenant.Tenant)) error {
	ts := a.gw.Tenants()
	if ts == nil {
		return ErrNotReady
	}
	tenants, all, err := a.scopeTenants(ctx)
	if err != nil {
		return err
	}
	if !all {
		for _, tn := range tenants {
			fn(tn)
		}
		return nil
	}
	seen := map[string]bool{}
	cursor := ""
	for {
		page, err := ts.List(ctx, &tenant.ListOptions{Limit: pageSize, Cursor: cursor})
		if err != nil {
			return fmt.Errorf("witness/nexus: list tenants: %w", err)
		}
		for _, tn := range page.Items {
			if seen[tn.ID.String()] {
				continue
			}
			seen[tn.ID.String()] = true
			if len(seen) > maxItems {
				return fmt.Errorf("%w: more than %d tenants", ErrTooMany, maxItems)
			}
			fn(tn)
		}
		if page.NextCursor == "" || page.NextCursor == cursor {
			return nil
		}
		cursor = page.NextCursor
	}
}

func (a *Adapter) collectBudgets(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := a.eachTenant(ctx, func(tn *tenant.Tenant) {
		var cache any
		if tn.Config.CacheEnabled != nil {
			cache = *tn.Config.CacheEnabled
		}
		q := tn.Quota
		out = append(out, map[string]any{
			"id":     tn.ID.String(),
			"slug":   tn.Slug,
			"status": string(tn.Status),
			// A JSON number with every digit, never a float.
			"monthly_budget_usd":          json.Number(q.MonthlyBudgetUSD.String()),
			"rpm":                         q.RPM,
			"tpm":                         q.TPM,
			"daily_requests":              q.DailyRequests,
			"max_tokens_per_req":          q.MaxTokensPerReq,
			"max_stream_tokens":           q.MaxStreamTokens,
			"max_stream_duration_seconds": seconds(q.MaxStreamDuration),
			"allowed_models":              sortedSet(tn.Config.AllowedModels),
			"blocked_models":              sortedSet(tn.Config.BlockedModels),
			"default_model":               tn.Config.DefaultModel,
			"guardrail_policy":            tn.Config.GuardrailPolicy,
			"cache_enabled":               cache,
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// by orders maps by the string values of fields, in turn.
func by(fields ...string) func(x, y map[string]any) int {
	return func(x, y map[string]any) int {
		for _, f := range fields {
			if c := strings.Compare(fmt.Sprint(x[f]), fmt.Sprint(y[f])); c != 0 {
				return c
			}
		}
		return 0
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sortedSet(s []string) []string {
	out := slices.Clone(s)
	if out == nil {
		out = []string{}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// stamp is t in UTC to the second. Stores keep different precisions, so
// whole seconds keep a row's hash steady across them.
func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

func stampOf(t *time.Time) any {
	if t == nil {
		return nil
	}
	return stamp(*t)
}

func seconds(d time.Duration) int64 { return int64(d / time.Second) }
