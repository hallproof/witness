package vault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/xraph/vessel"

	xvault "github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/push"
)

// Name is the adapter's name: its config key under
// extensions.witness.adapters and the name in witness's logs.
const Name = "vault"

// Module is the library this adapter reads.
const Module = "github.com/xraph/vault"

// extensionName is Vault's own Forge extension, which provides the engine.
const extensionName = "vault"

// defaultPageSize is how many rows one list call asks for.
const defaultPageSize = 500

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{extensionName},
		Attach: attach,
	})
}

// Options is the adapter's config section. In a Forge app it is
// extensions.witness.adapters.vault.
type Options struct {
	// Apps are the Vault app IDs whose secrets, rotation policies and
	// encryption counts are collected. Vault can't list its app IDs, so
	// nothing is collected for an app you don't name here. Empty means the
	// engine's own app ID when the adapter has a *vault.Vault, and nothing
	// at all when it has only a store.
	Apps []string `json:"apps"`
	// Tenants widens the secret population to these tenants' secrets inside
	// Apps. Empty means app-level secrets only, the default.
	Tenants []string `json:"tenants"`
	// FlagConfigApps are the app IDs whose feature flags and runtime config
	// are collected. Empty means the same as Apps when the adapter has a
	// *vault.Vault, and none when it has only a store.
	FlagConfigApps []string `json:"flag_config_apps"`
	// ConfigAllowlist names the runtime config keys whose values are sent.
	// Every other key goes out without its value.
	ConfigAllowlist []string `json:"config_allowlist"`
	// EventProofs turns on the vault.rotation-events collector. Off by
	// default.
	EventProofs bool `json:"event_proofs"`
}

// Option changes an Adapter.
type Option func(*Adapter)

// WithOptions applies o, as decoded from config. Its lists replace any set
// before it.
func WithOptions(o Options) Option {
	return func(a *Adapter) {
		a.opts = Options{
			Apps:            slices.Clone(o.Apps),
			Tenants:         slices.Clone(o.Tenants),
			FlagConfigApps:  slices.Clone(o.FlagConfigApps),
			ConfigAllowlist: slices.Clone(o.ConfigAllowlist),
			EventProofs:     o.EventProofs,
		}
	}
}

// WithApps sets the app IDs whose secrets are collected.
func WithApps(ids ...string) Option {
	return func(a *Adapter) { a.opts.Apps = slices.Clone(ids) }
}

// WithTenants widens the secret population to these tenants.
func WithTenants(ids ...string) Option {
	return func(a *Adapter) { a.opts.Tenants = slices.Clone(ids) }
}

// WithFlagConfigApps sets the app IDs whose feature flags and runtime
// config are collected.
func WithFlagConfigApps(ids ...string) Option {
	return func(a *Adapter) { a.opts.FlagConfigApps = slices.Clone(ids) }
}

// WithConfigValues names the runtime config keys whose values are sent.
func WithConfigValues(keys ...string) Option {
	return func(a *Adapter) { a.opts.ConfigAllowlist = slices.Clone(keys) }
}

// WithEventProofs turns the vault.rotation-events collector on or off.
func WithEventProofs(on bool) Option {
	return func(a *Adapter) { a.opts.EventProofs = on }
}

// WithLogger sets where the adapter logs. Nil means slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(a *Adapter) { a.log = l }
}

// reader is every store method the adapter calls. Holding the store
// through it means the adapter can't reach a method that returns secret
// bytes, such as GetSecret or ListUnrecordedVersions.
type reader interface {
	ListSecrets(ctx context.Context, appID string, opts secret.ListOpts) ([]*secret.Meta, error)
	CountSecrets(ctx context.Context, appID string) (int64, error)
	CountSecretsUnencrypted(ctx context.Context, appID string) (int64, error)
	CountVersionEncryption(ctx context.Context, appID string) (secret.VersionEncryptionCounts, error)
	ListRotationPolicies(ctx context.Context, appID string) ([]*rotation.Policy, error)
	ListFlagDefinitions(ctx context.Context, appID string, opts flag.ListOpts) ([]*flag.Definition, error)
	GetFlagRules(ctx context.Context, key, appID string) ([]*flag.Rule, error)
	ListFlagTenantOverrides(ctx context.Context, key, appID string) ([]*flag.TenantOverride, error)
	ListConfig(ctx context.Context, appID string, opts config.ListOpts) ([]*config.Entry, error)
	ListOverridesByKey(ctx context.Context, key, appID string) ([]*override.Override, error)
}

// engine is what the adapter reads from a *vault.Vault beyond its store.
type engine interface {
	EncryptionEnabled() bool
	EncryptionAlgorithm() string
}

// Adapter collects evidence from one Vault store.
type Adapter struct {
	store  reader
	engine engine // nil for a bare store
	appID  string // the engine's own app ID, "" for a bare store
	opts   Options
	log    *slog.Logger

	now      func() time.Time
	pageSize int
	maxItems int
}

// New returns an adapter that reads s. With only a store, the adapter
// collects nothing until you name app IDs with WithApps or
// WithFlagConfigApps.
func New(s store.Store, opts ...Option) *Adapter {
	a := &Adapter{now: time.Now, pageSize: defaultPageSize, maxItems: push.MaxItems}
	if s != nil {
		a.store = s
	}
	for _, o := range opts {
		o(a)
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	return a
}

// NewFromVault returns an adapter that reads v's store and reports v's
// encryption settings. With no app IDs named, it collects v's own app.
func NewFromVault(v *xvault.Vault, opts ...Option) *Adapter {
	if v == nil {
		return New(nil, opts...)
	}
	a := New(v.Store(), opts...)
	a.engine, a.appID = v, v.AppID()
	return a
}

// apps returns the app IDs for secrets.
func (a *Adapter) apps() []string {
	if len(a.opts.Apps) > 0 {
		return a.opts.Apps
	}
	if a.appID != "" {
		return []string{a.appID}
	}
	return nil
}

// flagConfigApps returns the app IDs for flags and config.
func (a *Adapter) flagConfigApps() []string {
	if len(a.opts.FlagConfigApps) > 0 {
		return a.opts.FlagConfigApps
	}
	if a.engine != nil {
		return a.apps()
	}
	return nil
}

// Register adds the adapter's collectors to w and logs what it covers.
// Register them before w starts.
func (a *Adapter) Register(w *witness.Witness) error {
	if a.store == nil {
		return errors.New("witness/vault: no store")
	}
	set := a.collectors()
	for _, s := range set.snapshots {
		if err := w.Snapshot(s); err != nil {
			return err
		}
	}
	for _, p := range set.populations {
		if err := w.Population(p); err != nil {
			return err
		}
	}
	for _, e := range set.proofs {
		if err := w.EventProof(e); err != nil {
			return err
		}
	}
	a.logCoverage()
	return nil
}

func (a *Adapter) logCoverage() {
	apps, fc := a.apps(), a.flagConfigApps()
	if len(apps) == 0 && len(fc) == 0 {
		a.log.Warn("witness/vault: no Vault app IDs are configured, so nothing is collected; name them in apps")
		return
	}
	a.log.Info("witness/vault: collecting",
		"apps", apps,
		"tenants", a.opts.Tenants,
		"flag_config_apps", fc,
		"config_values", len(a.opts.ConfigAllowlist),
		"event_proofs", a.opts.EventProofs,
	)
}

type collectorSet struct {
	snapshots   []collect.Snapshot
	populations []collect.Population
	proofs      []collect.EventProof
}

func (a *Adapter) collectors() collectorSet {
	var set collectorSet
	if len(a.apps()) > 0 {
		set.populations = append(set.populations,
			collect.Population{
				Key:         "vault.secrets",
				Title:       "Vault secrets",
				Description: "Every platform secret Vault holds, with its version, encryption and age, never its value.",
				Source:      "secrets",
				Tests:       []string{"keys-rotated", "storage-encrypted"},
				Collect:     a.secrets,
			},
			collect.Population{
				Key:         "vault.rotation-policies",
				Title:       "Vault rotation policies",
				Description: "Each secret rotation policy, whether it is on, its interval and when it last ran.",
				Source:      "rotation-policies",
				Tests:       []string{"keys-rotated"},
				Collect:     a.rotationPolicies,
			},
		)
		set.snapshots = append(set.snapshots, collect.Snapshot{
			Key:         "vault.encryption",
			Title:       "Vault encryption at rest",
			Description: "Whether Vault encrypts secret values, and how many stored values are not encrypted.",
			Tests:       []string{"storage-encrypted"},
			Collect:     a.encryption,
		})
		if a.opts.EventProofs {
			set.proofs = append(set.proofs, collect.EventProof{
				Key:         "vault.rotation-events",
				Title:       "Vault rotation events",
				Description: "Signed proof of each secret rotation and each rotation policy change.",
				Tests:       []string{"keys-rotated"},
				Stream:      adapter.Platform,
				Actions:     []string{"secret.rotated", "rotation.policy_saved", "rotation.policy_deleted"},
			})
		}
	}
	if len(a.flagConfigApps()) > 0 {
		set.populations = append(set.populations,
			collect.Population{
				Key:         "vault.flags",
				Title:       "Feature flags",
				Description: "Every feature flag Vault defines, whether it is on and how it is targeted.",
				Source:      "feature-flags",
				Collect:     a.flags,
			},
			collect.Population{
				Key:         "vault.config",
				Title:       "Runtime config",
				Description: "Every runtime config key Vault holds, its type and version, with values only for keys you allow.",
				Source:      "runtime-config",
				Collect:     a.config,
			},
		)
	}
	return set
}

// errTooMany fails a run whose population would pass push.MaxItems, rather
// than sending part of it.
func (a *Adapter) errTooMany(what string) error {
	return fmt.Errorf("witness/vault: more than %d %s; refusing to send a partial list", a.maxItems, what)
}

// pages calls list with growing offsets until a short page, failing once
// more than maxItems rows have come back.
func pages[T any](a *Adapter, what string, list func(limit, offset int) ([]T, error)) ([]T, error) {
	var out []T
	for offset := 0; ; offset += a.pageSize {
		page, err := list(a.pageSize, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(out) > a.maxItems {
			return nil, a.errTooMany(what)
		}
		if len(page) < a.pageSize {
			return out, nil
		}
	}
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func setTime(item map[string]any, key string, t *time.Time) {
	if t != nil && !t.IsZero() {
		item[key] = stamp(*t)
	}
}

func (a *Adapter) secrets(ctx context.Context) ([]map[string]any, error) {
	items := []map[string]any{}
	tenants := append([]string{""}, a.opts.Tenants...)
	for _, app := range a.apps() {
		policies, err := a.store.ListRotationPolicies(ctx, app)
		if err != nil {
			return nil, fmt.Errorf("witness/vault: rotation policies of %s: %w", app, err)
		}
		byKey := make(map[string]*rotation.Policy, len(policies))
		for _, p := range policies {
			byKey[p.SecretKey] = p
		}
		for _, tenant := range tenants {
			metas, err := pages(a, "secrets", func(limit, offset int) ([]*secret.Meta, error) {
				return a.store.ListSecrets(ctx, app, secret.ListOpts{Limit: limit, Offset: offset, TenantID: tenant})
			})
			if err != nil {
				return nil, fmt.Errorf("witness/vault: secrets of %s: %w", app, err)
			}
			for _, m := range metas {
				var policy *rotation.Policy
				if tenant == "" {
					policy = byKey[m.Key]
				}
				items = append(items, secretItem(m, policy))
			}
			if len(items) > a.maxItems {
				return nil, a.errTooMany("secrets")
			}
		}
	}
	return items, nil
}

func secretItem(m *secret.Meta, p *rotation.Policy) map[string]any {
	itemID := m.AppID + "/" + m.Key
	if m.TenantID != "" {
		itemID = m.AppID + "/" + m.TenantID + "/" + m.Key
	}
	item := map[string]any{
		"id":          itemID,
		"vault_id":    m.ID.String(),
		"app_id":      m.AppID,
		"key":         m.Key,
		"version":     m.Version,
		"encrypted":   m.EncryptionAlg != "",
		"created_at":  stamp(m.CreatedAt),
		"last_set_at": stamp(m.UpdatedAt),
	}
	if m.TenantID != "" {
		item["tenant_id"] = m.TenantID
	}
	if m.EncryptionAlg != "" {
		item["encryption_alg"] = m.EncryptionAlg
	}
	setTime(item, "expires_at", m.ExpiresAt)
	if p != nil {
		item["rotation_enabled"] = p.Enabled
		item["rotation_interval_seconds"] = int64(p.Interval / time.Second)
		setTime(item, "last_rotated_at", p.LastRotatedAt)
		setTime(item, "next_rotation_at", p.NextRotationAt)
	}
	return item
}

func (a *Adapter) rotationPolicies(ctx context.Context) ([]map[string]any, error) {
	items := []map[string]any{}
	now := a.now()
	for _, app := range a.apps() {
		policies, err := a.store.ListRotationPolicies(ctx, app)
		if err != nil {
			return nil, fmt.Errorf("witness/vault: rotation policies of %s: %w", app, err)
		}
		for _, p := range policies {
			item := map[string]any{
				"id":               app + "/" + p.SecretKey,
				"app_id":           app,
				"secret_key":       p.SecretKey,
				"enabled":          p.Enabled,
				"interval_seconds": int64(p.Interval / time.Second),
				"overdue":          p.Enabled && p.NextRotationAt != nil && p.NextRotationAt.Before(now),
			}
			setTime(item, "last_rotated_at", p.LastRotatedAt)
			setTime(item, "next_rotation_at", p.NextRotationAt)
			items = append(items, item)
		}
		if len(items) > a.maxItems {
			return nil, a.errTooMany("rotation policies")
		}
	}
	return items, nil
}

func (a *Adapter) encryption(ctx context.Context) (map[string]any, error) {
	settings := map[string]any{}
	if a.engine != nil {
		settings["engine_encryption_enabled"] = a.engine.EncryptionEnabled()
		settings["engine_encryption_algorithm"] = a.engine.EncryptionAlgorithm()
	}
	apps := map[string]any{}
	for _, app := range a.apps() {
		total, err := a.store.CountSecrets(ctx, app)
		if err != nil {
			return nil, fmt.Errorf("witness/vault: counting secrets of %s: %w", app, err)
		}
		plain, err := a.store.CountSecretsUnencrypted(ctx, app)
		if err != nil {
			return nil, fmt.Errorf("witness/vault: counting unencrypted secrets of %s: %w", app, err)
		}
		versions, err := a.store.CountVersionEncryption(ctx, app)
		if err != nil {
			return nil, fmt.Errorf("witness/vault: counting versions of %s: %w", app, err)
		}
		apps[app] = map[string]any{
			"secrets":             total,
			"unencrypted_current": plain,
			"plaintext_versions":  versions.Plaintext,
			"unrecorded_versions": versions.Unrecorded,
		}
	}
	settings["apps"] = apps
	return settings, nil
}

func (a *Adapter) flags(ctx context.Context) ([]map[string]any, error) {
	items := []map[string]any{}
	for _, app := range a.flagConfigApps() {
		defs, err := pages(a, "feature flags", func(limit, offset int) ([]*flag.Definition, error) {
			return a.store.ListFlagDefinitions(ctx, app, flag.ListOpts{Limit: limit, Offset: offset})
		})
		if err != nil {
			return nil, fmt.Errorf("witness/vault: flags of %s: %w", app, err)
		}
		for _, d := range defs {
			rules, err := a.store.GetFlagRules(ctx, d.Key, app)
			if err != nil {
				return nil, fmt.Errorf("witness/vault: rules of flag %s/%s: %w", app, d.Key, err)
			}
			overrides, err := a.store.ListFlagTenantOverrides(ctx, d.Key, app)
			if err != nil {
				return nil, fmt.Errorf("witness/vault: overrides of flag %s/%s: %w", app, d.Key, err)
			}
			items = append(items, flagItem(app, d, rules, len(overrides)))
		}
		if len(items) > a.maxItems {
			return nil, a.errTooMany("feature flags")
		}
	}
	return items, nil
}

func flagItem(app string, d *flag.Definition, rules []*flag.Rule, overrides int) map[string]any {
	item := map[string]any{
		"id":                    app + "/" + d.Key,
		"app_id":                app,
		"key":                   d.Key,
		"type":                  string(d.Type),
		"enabled":               d.Enabled,
		"tags":                  slices.Clone(d.Tags),
		"updated_at":            stamp(d.UpdatedAt),
		"variant_count":         len(d.Variants),
		"tenant_override_count": overrides,
	}
	if item["tags"] == nil {
		item["tags"] = []string{}
	}
	// Only a bool default is safe to send: any other type can hold text.
	if b, ok := d.DefaultValue.(bool); ok && d.Type == flag.TypeBool {
		item["default_value"] = b
	}
	rs := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		rule := map[string]any{
			"priority":     r.Priority,
			"type":         string(r.Type),
			"tenant_count": len(r.Config.TenantIDs),
			"user_count":   len(r.Config.UserIDs),
		}
		if r.Type == flag.RuleRollout {
			rule["percentage"] = r.Config.Percentage
		}
		setTime(rule, "start_at", r.Config.StartAt)
		setTime(rule, "end_at", r.Config.EndAt)
		rs = append(rs, rule)
	}
	item["rules"] = rs
	return item
}

func (a *Adapter) config(ctx context.Context) ([]map[string]any, error) {
	items := []map[string]any{}
	for _, app := range a.flagConfigApps() {
		entries, err := pages(a, "config entries", func(limit, offset int) ([]*config.Entry, error) {
			return a.store.ListConfig(ctx, app, config.ListOpts{Limit: limit, Offset: offset})
		})
		if err != nil {
			return nil, fmt.Errorf("witness/vault: config of %s: %w", app, err)
		}
		for _, e := range entries {
			overrides, err := a.store.ListOverridesByKey(ctx, e.Key, app)
			if err != nil {
				return nil, fmt.Errorf("witness/vault: overrides of config %s/%s: %w", app, e.Key, err)
			}
			item := map[string]any{
				"id":             app + "/" + e.Key,
				"app_id":         app,
				"key":            e.Key,
				"value_type":     e.ValueType,
				"version":        e.Version,
				"updated_at":     stamp(e.UpdatedAt),
				"override_count": len(overrides),
			}
			if slices.Contains(a.opts.ConfigAllowlist, e.Key) {
				item["value"] = e.Value
			}
			items = append(items, item)
		}
		if len(items) > a.maxItems {
			return nil, a.errTooMany("config entries")
		}
	}
	return items, nil
}

// attach finds Vault in a Forge app's container: the engine first, then a
// bare store.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil {
		return false, nil
	}
	hasEngine, hasStore := vessel.HasType[*xvault.Vault](c), vessel.HasType[store.Store](c)
	if !hasEngine && !hasStore {
		return false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return true, err
	}
	opts := []Option{WithOptions(o), WithLogger(h.Logger)}

	var a *Adapter
	if hasEngine {
		v, err := vessel.Inject[*xvault.Vault](c)
		if err != nil {
			return true, fmt.Errorf("witness/vault: resolving the vault: %w", err)
		}
		a = NewFromVault(v, opts...)
	} else {
		s, err := vessel.Inject[store.Store](c)
		if err != nil {
			return true, fmt.Errorf("witness/vault: resolving the vault store: %w", err)
		}
		a = New(s, opts...)
	}
	if h.Scope.AllTenants && len(o.Tenants) == 0 {
		a.log.Warn("witness/vault: the scope covers all tenants, but Vault can't list its tenants; name them in tenants to collect their secrets")
	}
	return true, a.Register(h.Witness)
}
