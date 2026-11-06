package shield

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"

	sh "github.com/xraph/shield"
	"github.com/xraph/shield/awareness"
	"github.com/xraph/shield/boundary"
	"github.com/xraph/shield/compliance"
	"github.com/xraph/shield/instinct"
	"github.com/xraph/shield/judgment"
	"github.com/xraph/shield/policy"
	"github.com/xraph/shield/profile"
	"github.com/xraph/shield/reflex"
	"github.com/xraph/shield/scan"
	"github.com/xraph/shield/values"

	"github.com/hallproof/witness/push"
)

// pageSize is how many rows each list call asks for. A variable so tests
// can lower it.
var pageSize = 500

// maxItems is the most rows a population reads in scope before it fails
// the run. A variable so tests can lower it.
var maxItems = push.MaxItems

// maxConfigurations is how many distinct configurations the conformance
// snapshot lists. The count of all of them is always sent.
const maxConfigurations = 50

// now is the clock scan outcomes read the day from. A variable so tests can
// move it.
var now = time.Now

// riskClassPattern is the one on_context trigger pattern whose value is
// sent: the risk class form shield's InfraAgent preset uses.
var riskClassPattern = regexp.MustCompile(`^risk_class=([a-z][a-z0-9_]*)$`)

// tenantCtx is ctx read as tenant on the adapter's app, which is how shield
// scopes every primitive and profile read.
func (a *Adapter) tenantCtx(ctx context.Context, tenant string) context.Context {
	ctx = sh.WithTenant(ctx, tenant)
	if a.app != "" {
		ctx = sh.WithApp(ctx, a.app)
	}
	return ctx
}

// appCtx is ctx read as an operator of the adapter's app: no tenant, so
// shield allows app-wide policy and report reads.
func (a *Adapter) appCtx(ctx context.Context) context.Context {
	return sh.WithApp(sh.WithTenant(ctx, ""), a.app)
}

// inScope checks a row's app and tenant again after the store's own
// filter, so a store that ignores a filter field can't widen the scope.
func (a *Adapter) inScope(appID, rowTenant, tenant string) bool {
	return rowTenant == tenant && (a.app == "" || appID == a.app)
}

// each pages through list, calling fn for every row, until a short page.
func each[T any](list func(limit, offset int) ([]T, error), fn func(T) error) error {
	for off := 0; ; off += pageSize {
		page, err := list(pageSize, off)
		if err != nil {
			return err
		}
		for _, row := range page {
			if err := fn(row); err != nil {
				return err
			}
		}
		if len(page) < pageSize {
			return nil
		}
	}
}

// bag collects one population's items. It drops a row seen on an earlier
// page (offset paging can repeat a row when rows are created mid-scan) and
// fails with ErrTooMany past maxItems.
type bag struct {
	what  string
	items []map[string]any
	seen  map[string]bool
}

func newBag(what string) *bag {
	return &bag{what: what, items: []map[string]any{}, seen: map[string]bool{}}
}

func (b *bag) add(it map[string]any) error {
	id := fmt.Sprint(it["id"])
	if b.seen[id] {
		return nil
	}
	b.seen[id] = true
	if len(b.items) >= maxItems {
		return fmt.Errorf("%w: more than %d %s", ErrTooMany, maxItems, b.what)
	}
	b.items = append(b.items, it)
	return nil
}

func (a *Adapter) collectEngine(context.Context) (map[string]any, error) {
	cfg := a.eng.Config()
	caps := a.eng.Capabilities()
	ttl := seconds(cfg.ProfileCacheTTL)
	if cfg.ProfileCacheTTL < 0 {
		ttl = -1 // the cache is off
	}
	supported := make(map[string][]string, len(caps.Supported))
	for k, v := range caps.Supported {
		names := slices.Clone(v)
		if names == nil {
			names = []string{}
		}
		slices.Sort(names)
		supported[k] = names
	}
	layers := slices.Clone(caps.Layers)
	if layers == nil {
		layers = []string{}
	}
	slices.Sort(layers)
	return map[string]any{
		"default_profile":           cfg.DefaultProfile,
		"enable_short_circuit":      cfg.EnableShortCircuit,
		"max_scan_bytes":            cfg.MaxScanBytes,
		"profile_cache_ttl_seconds": ttl,
		"store_redacted":            cfg.StoreRedacted,
		"model_judge":               cfg.ModelJudge,
		"judge_timeout_seconds":     seconds(cfg.JudgeTimeout),
		"capabilities": map[string]any{
			"persistence":        caps.Persistence,
			"tool_calls":         caps.ToolCalls,
			"model_judge":        caps.ModelJudge,
			"unavailable_layers": layers,
			"supported":          supported,
		},
	}, nil
}

func (a *Adapter) collectProfiles(ctx context.Context) ([]map[string]any, error) {
	b := newBag("profiles")
	for _, t := range a.tenants {
		if err := a.eachProfile(ctx, t, b.add); err != nil {
			return nil, err
		}
	}
	return b.items, nil
}

func (a *Adapter) collectChecks(ctx context.Context) ([]map[string]any, error) {
	b := newBag("checks")
	for _, t := range a.tenants {
		if err := a.eachCheck(ctx, t, b.add); err != nil {
			return nil, err
		}
	}
	return b.items, nil
}

func (a *Adapter) collectPolicies(ctx context.Context) ([]map[string]any, error) {
	b := newBag("policies")
	for _, t := range a.tenants {
		if err := a.eachOrgPolicy(ctx, t, b.add); err != nil {
			return nil, err
		}
	}
	if a.app != "" {
		err := each(func(limit, offset int) ([]*policy.Policy, error) {
			return a.eng.Store().ListPolicies(a.appCtx(ctx), &policy.ListFilter{ScopeKey: a.app, ScopeLevel: policy.ScopeApp, Limit: limit, Offset: offset})
		}, func(p *policy.Policy) error {
			if p.ScopeLevel != policy.ScopeApp || p.ScopeKey != a.app {
				return nil
			}
			return b.add(policyItem(p))
		})
		if err != nil {
			return nil, fmt.Errorf("witness/shield: list app policies: %w", err)
		}
	}
	return b.items, nil
}

func (a *Adapter) collectReports(ctx context.Context) ([]map[string]any, error) {
	b := newBag("compliance reports")
	read := func(ctx context.Context, key, level string) error {
		return each(func(limit, offset int) ([]*compliance.Report, error) {
			return a.eng.Store().ListReports(ctx, &compliance.ListFilter{ScopeKey: key, Limit: limit, Offset: offset})
		}, func(r *compliance.Report) error {
			if r.ScopeKey != key || r.ScopeLevel != level {
				return nil
			}
			return b.add(reportItem(r))
		})
	}
	for _, t := range a.tenants {
		if err := read(a.tenantCtx(ctx, t), t, string(policy.ScopeOrg)); err != nil {
			return nil, fmt.Errorf("witness/shield: list compliance reports: %w", err)
		}
	}
	if a.app != "" {
		if err := read(a.appCtx(ctx), a.app, string(policy.ScopeApp)); err != nil {
			return nil, fmt.Errorf("witness/shield: list app compliance reports: %w", err)
		}
	}
	return b.items, nil
}

// collectScanOutcomes counts the previous complete UTC day's scans. A whole
// day keeps the hash steady until the day turns, so it pushes once a day.
func (a *Adapter) collectScanOutcomes(ctx context.Context) (map[string]any, error) {
	day := now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	var total, blocked, flagged, allowed int64
	byDirection, byDecision := map[string]int64{}, map[string]int64{}
	for _, t := range a.tenants {
		st, err := a.eng.Store().ScanStats(a.tenantCtx(ctx, t), &scan.StatsFilter{
			AppID: a.app, TenantID: t, From: day, To: day + "T23:59:59.999999Z",
		})
		if err != nil {
			return nil, fmt.Errorf("witness/shield: scan stats: %w", err)
		}
		total += st.TotalScans
		blocked += st.BlockedCount
		flagged += st.FlaggedCount
		allowed += st.AllowedCount
		for k, v := range st.ByDirection {
			byDirection[k] += v
		}
		for k, v := range st.ByDecision {
			byDecision[k] += v
		}
	}
	return map[string]any{
		"day":          day,
		"total_scans":  total,
		"blocked":      blocked,
		"flagged":      flagged,
		"allowed":      allowed,
		"by_direction": byDirection,
		"by_decision":  byDecision,
	}, nil
}

// collectConformance hashes each tenant's safety configuration, the same
// fields the profiles, checks and policies populations send minus IDs,
// tenants and times, and counts the tenants per hash. No tenant ID is sent.
func (a *Adapter) collectConformance(ctx context.Context) (map[string]any, error) {
	all, err := a.o.TenantSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("witness/shield: list tenants: %w", err)
	}
	tenants := cleanTenants(all)
	counts := map[string]int{}
	withoutProfiles := 0
	for _, t := range tenants {
		sum, profiles, err := a.tenantConfig(ctx, t)
		if err != nil {
			return nil, err
		}
		counts[sum]++
		if profiles == 0 {
			withoutProfiles++
		}
	}
	hashes := slices.Collect(maps.Keys(counts))
	sort.Slice(hashes, func(i, j int) bool {
		if counts[hashes[i]] != counts[hashes[j]] {
			return counts[hashes[i]] > counts[hashes[j]]
		}
		return hashes[i] < hashes[j]
	})
	confs := make([]map[string]any, 0, min(len(hashes), maxConfigurations))
	for _, h := range hashes[:min(len(hashes), maxConfigurations)] {
		confs = append(confs, map[string]any{"config_sha256": h, "tenants": counts[h]})
	}
	return map[string]any{
		"tenants":                  len(tenants),
		"tenants_without_profiles": withoutProfiles,
		"distinct_configurations":  len(hashes),
		"configurations":           confs,
	}, nil
}

// tenantConfig returns the hash of one tenant's configuration and how many
// profiles it has.
func (a *Adapter) tenantConfig(ctx context.Context, tenant string) (sum string, profileCount int, err error) {
	var profiles, checks, policies []string
	// strip drops what differs between tenants running the same
	// configuration: IDs, times and the tenant itself.
	strip := func(dst *[]string, tenantField string) func(map[string]any) error {
		return func(it map[string]any) error {
			for _, k := range []string{tenantField, "id", "created_at", "updated_at"} {
				delete(it, k)
			}
			raw, merr := json.Marshal(it)
			if merr != nil {
				return merr
			}
			*dst = append(*dst, string(raw))
			return nil
		}
	}
	err = a.eachProfile(ctx, tenant, strip(&profiles, "tenant_id"))
	if err != nil {
		return "", 0, err
	}
	err = a.eachCheck(ctx, tenant, strip(&checks, "tenant_id"))
	if err != nil {
		return "", 0, err
	}
	err = a.eachOrgPolicy(ctx, tenant, strip(&policies, "scope_key"))
	if err != nil {
		return "", 0, err
	}
	for _, l := range [][]string{profiles, checks, policies} {
		slices.Sort(l)
	}
	raw, err := json.Marshal(map[string][]string{"profiles": profiles, "checks": checks, "policies": policies})
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), len(profiles), nil
}

func (a *Adapter) eachProfile(ctx context.Context, tenant string, fn func(map[string]any) error) error {
	tctx := a.tenantCtx(ctx, tenant)
	err := each(func(limit, offset int) ([]*profile.SafetyProfile, error) {
		return a.eng.Store().ListProfiles(tctx, &profile.ListFilter{AppID: a.app, TenantID: tenant, Limit: limit, Offset: offset})
	}, func(p *profile.SafetyProfile) error {
		if !a.inScope(p.AppID, p.TenantID, tenant) {
			return nil
		}
		return fn(profileItem(p))
	})
	if err != nil {
		return fmt.Errorf("witness/shield: list profiles: %w", err)
	}
	return nil
}

// eachCheck calls fn with every primitive of tenant, one item per row.
func (a *Adapter) eachCheck(ctx context.Context, tenant string, fn func(map[string]any) error) error {
	tctx := a.tenantCtx(ctx, tenant)
	st := a.eng.Store()
	wrap := func(kind string, err error) error {
		if err != nil {
			return fmt.Errorf("witness/shield: list %s: %w", kind, err)
		}
		return nil
	}
	if err := wrap("instincts", each(func(limit, offset int) ([]*instinct.Instinct, error) {
		return st.ListInstincts(tctx, &instinct.ListFilter{AppID: a.app, TenantID: tenant, Limit: limit, Offset: offset})
	}, func(r *instinct.Instinct) error {
		if !a.inScope(r.AppID, r.TenantID, tenant) {
			return nil
		}
		it := checkItem("instinct", r.ID.String(), r.Name, r.AppID, r.TenantID, r.Entity)
		names := make([]string, 0, len(r.Strategies))
		for _, s := range r.Strategies {
			names = append(names, s.Name)
		}
		it["category"], it["sensitivity"], it["action"], it["enabled"] = string(r.Category), string(r.Sensitivity), r.Action, r.Enabled
		it["strategies"] = names
		return fn(it)
	})); err != nil {
		return err
	}
	if err := wrap("awareness", each(func(limit, offset int) ([]*awareness.Awareness, error) {
		return st.ListAwareness(tctx, &awareness.ListFilter{AppID: a.app, TenantID: tenant, Limit: limit, Offset: offset})
	}, func(r *awareness.Awareness) error {
		if !a.inScope(r.AppID, r.TenantID, tenant) {
			return nil
		}
		it := checkItem("awareness", r.ID.String(), r.Name, r.AppID, r.TenantID, r.Entity)
		names := make([]string, 0, len(r.Detectors))
		for _, d := range r.Detectors {
			names = append(names, d.Name)
		}
		// No detectors means every built-in one for the focus.
		it["focus"], it["action"], it["enabled"], it["detectors"] = string(r.Focus), r.Action, r.Enabled, names
		return fn(it)
	})); err != nil {
		return err
	}
	if err := wrap("judgments", each(func(limit, offset int) ([]*judgment.Judgment, error) {
		return st.ListJudgments(tctx, &judgment.ListFilter{AppID: a.app, TenantID: tenant, Limit: limit, Offset: offset})
	}, func(r *judgment.Judgment) error {
		if !a.inScope(r.AppID, r.TenantID, tenant) {
			return nil
		}
		it := checkItem("judgment", r.ID.String(), r.Name, r.AppID, r.TenantID, r.Entity)
		assessors := make([]map[string]any, 0, len(r.Assessors))
		for _, as := range r.Assessors {
			assessors = append(assessors, map[string]any{"name": as.Name, "domain": string(as.Domain), "weight": as.Weight})
		}
		it["domain"], it["threshold"], it["action"], it["enabled"] = string(r.Domain), r.Threshold, r.Action, r.Enabled
		it["assessors"] = assessors
		return fn(it)
	})); err != nil {
		return err
	}
	if err := wrap("values", each(func(limit, offset int) ([]*values.Values, error) {
		return st.ListValues(tctx, &values.ListFilter{AppID: a.app, TenantID: tenant, Limit: limit, Offset: offset})
	}, func(r *values.Values) error {
		if !a.inScope(r.AppID, r.TenantID, tenant) {
			return nil
		}
		it := checkItem("values", r.ID.String(), r.Name, r.AppID, r.TenantID, r.Entity)
		rules := make([]map[string]any, 0, len(r.Rules))
		for _, ru := range r.Rules {
			cats := slices.Clone(ru.Categories)
			if cats == nil {
				cats = []string{}
			}
			rules = append(rules, map[string]any{"principle": string(ru.Principle), "threshold": ru.Threshold, "categories": cats})
		}
		it["severity"], it["action"], it["enabled"], it["rules"] = r.Severity, r.Action, r.Enabled, rules
		return fn(it)
	})); err != nil {
		return err
	}
	if err := wrap("reflexes", each(func(limit, offset int) ([]*reflex.Reflex, error) {
		return st.ListReflexes(tctx, &reflex.ListFilter{AppID: a.app, TenantID: tenant, Limit: limit, Offset: offset})
	}, func(r *reflex.Reflex) error {
		if !a.inScope(r.AppID, r.TenantID, tenant) {
			return nil
		}
		return fn(reflexItem(r))
	})); err != nil {
		return err
	}
	return wrap("boundaries", each(func(limit, offset int) ([]*boundary.Boundary, error) {
		return st.ListBoundaries(tctx, &boundary.ListFilter{AppID: a.app, TenantID: tenant, Limit: limit, Offset: offset})
	}, func(r *boundary.Boundary) error {
		if !a.inScope(r.AppID, r.TenantID, tenant) {
			return nil
		}
		it := checkItem("boundary", r.ID.String(), r.Name, r.AppID, r.TenantID, r.Entity)
		limits := make([]map[string]any, 0, len(r.Limits))
		for _, l := range r.Limits {
			limits = append(limits, map[string]any{
				"scope": string(l.Scope), "use_allow": l.UseAllow, "deny_count": len(l.Deny), "allow_count": len(l.Allow),
			})
		}
		it["enabled"], it["limits"] = r.Enabled, limits
		return fn(it)
	}))
}

func (a *Adapter) eachOrgPolicy(ctx context.Context, tenant string, fn func(map[string]any) error) error {
	tctx := a.tenantCtx(ctx, tenant)
	err := each(func(limit, offset int) ([]*policy.Policy, error) {
		return a.eng.Store().ListPolicies(tctx, &policy.ListFilter{ScopeKey: tenant, ScopeLevel: policy.ScopeOrg, Limit: limit, Offset: offset})
	}, func(p *policy.Policy) error {
		if p.ScopeLevel != policy.ScopeOrg || p.ScopeKey != tenant {
			return nil
		}
		return fn(policyItem(p))
	})
	if err != nil {
		return fmt.Errorf("witness/shield: list policies: %w", err)
	}
	return nil
}

func profileItem(p *profile.SafetyProfile) map[string]any {
	instincts := make([]map[string]any, 0, len(p.Instincts))
	for _, ia := range p.Instincts {
		instincts = append(instincts, map[string]any{"name": ia.InstinctName, "sensitivity": string(ia.Sensitivity)})
	}
	judgments := make([]map[string]any, 0, len(p.Judgments))
	for _, j := range p.Judgments {
		judgments = append(judgments, map[string]any{"name": j.JudgmentName, "threshold": j.Threshold})
	}
	aware := make([]string, 0, len(p.Awareness))
	for _, aw := range p.Awareness {
		aware = append(aware, aw.AwarenessName)
	}
	return map[string]any{
		"id":         p.ID.String(),
		"name":       p.Name,
		"app_id":     p.AppID,
		"tenant_id":  p.TenantID,
		"enabled":    p.Enabled,
		"instincts":  instincts,
		"judgments":  judgments,
		"awareness":  aware,
		"values":     nameList(p.Values),
		"reflexes":   nameList(p.Reflexes),
		"boundaries": nameList(p.Boundaries),
		"created_at": stamp(p.CreatedAt),
		"updated_at": stamp(p.UpdatedAt),
	}
}

func checkItem(kind, shieldID, name, appID, tenantID string, e sh.Entity) map[string]any {
	return map[string]any{
		"id":         kind + ":" + shieldID,
		"kind":       kind,
		"name":       name,
		"app_id":     appID,
		"tenant_id":  tenantID,
		"created_at": stamp(e.CreatedAt),
		"updated_at": stamp(e.UpdatedAt),
	}
}

func reflexItem(r *reflex.Reflex) map[string]any {
	it := checkItem("reflex", r.ID.String(), r.Name, r.AppID, r.TenantID, r.Entity)
	triggers := make([]map[string]any, 0, len(r.Triggers))
	for _, tr := range r.Triggers {
		window := ""
		if _, err := time.ParseDuration(tr.Window); err == nil {
			window = tr.Window
		}
		triggers = append(triggers, map[string]any{
			"type": string(tr.Type), "threshold": tr.Threshold, "window": window, "risk_class": riskClass(tr),
		})
	}
	actions := make([]map[string]any, 0, len(r.Actions))
	escalates := false
	for _, ac := range r.Actions {
		// Target is free text. For a redact action it is the regex shield
		// redacts with, which can spell out the very data it hides, and
		// shield defines no fixed targets that would be safe to send. Its
		// hash still shows when a target changes.
		actions = append(actions, map[string]any{"type": string(ac.Type), "target_sha256": hash(ac.Target)})
		escalates = escalates || ac.Type == reflex.ActionEscalate
	}
	it["priority"], it["enabled"], it["escalates"] = r.Priority, r.Enabled, escalates
	it["triggers"], it["actions"] = triggers, actions
	return it
}

// riskClass is the risk class an on_context trigger matches, when its
// pattern is exactly risk_class=<lowercase word>. Any other pattern is
// never sent.
func riskClass(tr reflex.Trigger) string {
	if tr.Type != reflex.TriggerOnContext {
		return ""
	}
	if m := riskClassPattern.FindStringSubmatch(tr.Pattern); m != nil {
		return m[1]
	}
	return ""
}

func policyItem(p *policy.Policy) map[string]any {
	rules := make([]map[string]any, 0, len(p.Rules))
	for _, r := range p.Rules {
		rules = append(rules, map[string]any{
			"check_type": r.CheckType, "action": r.Action, "priority": r.Priority, "condition_sha256": hash(r.Condition),
		})
	}
	return map[string]any{
		"id":          p.ID.String(),
		"name":        p.Name,
		"scope_level": string(p.ScopeLevel),
		"scope_key":   p.ScopeKey,
		"enabled":     p.Enabled,
		"rules":       rules,
		"created_at":  stamp(p.CreatedAt),
		"updated_at":  stamp(p.UpdatedAt),
	}
}

func reportItem(r *compliance.Report) map[string]any {
	return map[string]any{
		"id":           r.ID.String(),
		"framework":    string(r.Framework),
		"scope_level":  r.ScopeLevel,
		"scope_key":    r.ScopeKey,
		"period_start": stamp(r.PeriodStart),
		"period_end":   stamp(r.PeriodEnd),
		"generated_at": stamp(r.GeneratedAt),
		"summary":      figures(r.Summary),
	}
}

// figureKey is the form a summary key must take to be sent. A host picks
// the keys, so a key outside it could carry content, such as a customer's
// name.
var figureKey = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// figures keeps the top-level numbers and booleans of a report summary
// whose keys are plain lowercase names. Strings and nested values are
// dropped, since a host can put anything there, and so are NaN and
// infinities, which JSON can't carry.
func figures(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if !figureKey.MatchString(k) {
			continue
		}
		switch n := v.(type) {
		case float64:
			if !finite(n) {
				continue
			}
		case float32:
			if !finite(float64(n)) {
				continue
			}
		case json.Number:
			f, err := strconv.ParseFloat(string(n), 64)
			if err != nil || !finite(f) || !json.Valid([]byte(n)) {
				continue
			}
		case bool, int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64:
		default:
			continue
		}
		out[k] = v
	}
	return out
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// hash is the hex SHA-256 of s, or "" when s is empty.
func hash(s string) string {
	if s == "" {
		return ""
	}
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func nameList(in []string) []string {
	out := slices.Clone(in)
	if out == nil {
		out = []string{}
	}
	return out
}

// stamp is t in UTC to the second. Stores keep different precisions, so
// whole seconds keep a row's hash steady across them.
func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

func seconds(d time.Duration) int64 { return int64(d / time.Second) }
