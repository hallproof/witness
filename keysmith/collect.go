package keysmith

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/xraph/keysmith/key"
	"github.com/xraph/keysmith/policy"

	"github.com/hallproof/witness/push"
)

// pageSize is how many rows each list call asks for.
const pageSize = 1000

// maxItems is the most rows a collector reads in scope before it fails the
// run. A variable so tests can lower it.
var maxItems = push.MaxItems

// filterTenants are the tenant IDs to list: one empty ID, which keysmith
// reads as every tenant, when AllTenants is on, else the staff tenants.
func (a *Adapter) filterTenants() []string {
	if a.o.AllTenants {
		return []string{""}
	}
	return a.tenants
}

// inScope checks a row's app and tenant again after the store's own
// filter, so a store that ignores a filter field can't widen the scope.
func (a *Adapter) inScope(appID, tenantID string) bool {
	if a.o.AppID != "" && appID != a.o.AppID {
		return false
	}
	return a.o.AllTenants || a.tenantIn[tenantID]
}

// eachKey calls fn once for every key in scope. It pages through each
// tenant, skips a key seen on an earlier page (offset paging can repeat a
// row when keys are created mid-scan), and fails with ErrTooMany past
// maxItems keys.
func (a *Adapter) eachKey(ctx context.Context, fn func(*key.Key) error) error {
	seen := map[string]bool{}
	for _, t := range a.filterTenants() {
		for off := 0; ; off += pageSize {
			page, err := a.eng.ListKeys(ctx, &key.ListFilter{TenantID: t, Limit: pageSize, Offset: off})
			if err != nil {
				return fmt.Errorf("witness/keysmith: list keys: %w", err)
			}
			for _, k := range page {
				kid := k.ID.String()
				if !a.inScope(k.AppID, k.TenantID) || seen[kid] {
					continue
				}
				seen[kid] = true
				if len(seen) > maxItems {
					return fmt.Errorf("%w: more than %d keys", ErrTooMany, maxItems)
				}
				if err := fn(k); err != nil {
					return err
				}
			}
			if len(page) < pageSize {
				break
			}
		}
	}
	return nil
}

func (a *Adapter) eachPolicy(ctx context.Context, fn func(*policy.Policy)) error {
	seen := map[string]bool{}
	for _, t := range a.filterTenants() {
		for off := 0; ; off += pageSize {
			page, err := a.eng.ListPolicies(ctx, &policy.ListFilter{TenantID: t, Limit: pageSize, Offset: off})
			if err != nil {
				return fmt.Errorf("witness/keysmith: list policies: %w", err)
			}
			for _, p := range page {
				pid := p.ID.String()
				if !a.inScope(p.AppID, p.TenantID) || seen[pid] {
					continue
				}
				seen[pid] = true
				if len(seen) > maxItems {
					return fmt.Errorf("%w: more than %d policies", ErrTooMany, maxItems)
				}
				fn(p)
			}
			if len(page) < pageSize {
				break
			}
		}
	}
	return nil
}

func (a *Adapter) collectKeys(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := a.eachKey(ctx, func(k *key.Key) error {
		scopes, err := a.eng.Store().Scopes().ListByKey(ctx, k.ID)
		if err != nil {
			return fmt.Errorf("witness/keysmith: list a key's scopes: %w", err)
		}
		names := make([]string, 0, len(scopes))
		for _, s := range scopes {
			if !slices.Contains(names, s.Name) {
				names = append(names, s.Name)
			}
		}
		slices.Sort(names)
		it := map[string]any{
			"id":           k.ID.String(),
			"tenant_id":    k.TenantID,
			"app_id":       k.AppID,
			"name":         k.Name,
			"prefix":       k.Prefix,
			"environment":  string(k.Environment),
			"state":        string(k.State),
			"policy_id":    nil,
			"scopes":       names,
			"created_by":   k.CreatedBy,
			"created_at":   stamp(k.CreatedAt),
			"expires_at":   stampOf(k.ExpiresAt),
			"rotated_at":   stampOf(k.RotatedAt),
			"revoked_at":   stampOf(k.RevokedAt),
			"last_used_on": nil,
		}
		if k.PolicyID != nil {
			it["policy_id"] = k.PolicyID.String()
		}
		if k.LastUsedAt != nil {
			// A day, not a time: last use changes on every request, and a
			// timestamp would make every run new evidence.
			it["last_used_on"] = k.LastUsedAt.UTC().Format(time.DateOnly)
		}
		if len(a.meta) > 0 {
			it["metadata"] = a.metadata(k.Metadata)
		}
		out = append(out, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// metadata keeps the allowlisted entries of m that hold plain values.
func (a *Adapter) metadata(m map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range a.meta {
		switch v := m[k].(type) {
		case string, bool, json.Number,
			int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64,
			float32, float64:
			out[k] = v
		}
	}
	return out
}

func (a *Adapter) collectPolicies(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := a.eachPolicy(ctx, func(p *policy.Policy) {
		scopes := slices.Clone(p.AllowedScopes)
		if scopes == nil {
			scopes = []string{}
		}
		slices.Sort(scopes)
		out = append(out, map[string]any{
			"id":                        p.ID.String(),
			"tenant_id":                 p.TenantID,
			"app_id":                    p.AppID,
			"name":                      p.Name,
			"max_key_lifetime_seconds":  seconds(p.MaxKeyLifetime),
			"rotation_period_seconds":   seconds(p.RotationPeriod),
			"grace_period_seconds":      seconds(p.GracePeriod),
			"rate_limit":                p.RateLimit,
			"rate_limit_window_seconds": seconds(p.RateLimitWindow),
			"burst_limit":               p.BurstLimit,
			"daily_quota":               p.DailyQuota,
			"monthly_quota":             p.MonthlyQuota,
			"allowed_scopes":            scopes,
			"allowed_ip_count":          len(p.AllowedIPs),
			"allowed_origin_count":      len(p.AllowedOrigins),
			"created_at":                stamp(p.CreatedAt),
			"updated_at":                stamp(p.UpdatedAt),
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Adapter) collectRotation(ctx context.Context) (map[string]any, error) {
	var total, active, noExpiry, noPolicy int
	var oldest time.Time
	err := a.eachKey(ctx, func(k *key.Key) error {
		total++
		if k.State != key.StateActive || k.RevokedAt != nil {
			return nil
		}
		active++
		if k.ExpiresAt == nil {
			noExpiry++
		}
		if k.PolicyID == nil {
			noPolicy++
		}
		at := k.CreatedAt
		if k.RotatedAt != nil {
			at = *k.RotatedAt
		}
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var oldestAt any
	if !oldest.IsZero() {
		oldestAt = stamp(oldest)
	}
	return map[string]any{
		"keys_total":             total,
		"keys_active":            active,
		"oldest_active_rotation": oldestAt,
		"keys_without_expiry":    noExpiry,
		"keys_without_policy":    noPolicy,
	}, nil
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
