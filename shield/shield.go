package shield

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/xraph/shield/engine"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "shield"

// Module is the library this adapter reads.
const Module = "github.com/xraph/shield"

// Collector keys.
const (
	KeyEngine        = "shield.engine"
	KeyProfiles      = "shield.profiles"
	KeyChecks        = "shield.checks"
	KeyPolicies      = "shield.policies"
	KeyReports       = "shield.compliance-reports"
	KeyScanOutcomes  = "shield.scan-outcomes"
	KeyConformance   = "shield.tenant-conformance"
	KeySafetyActions = "shield.safety-actions"
)

// DefaultProofActions are the audit actions the safety actions proof cites
// when you turn event proofs on without naming any. Shield's audit_hook
// plugin records them.
//
// shield.policy.created is left out on purpose. In shield v1.10.0 the
// audit_hook records it for every policy evaluation, not for a policy being
// created, so it would prove the wrong thing.
var DefaultProofActions = []string{
	"shield.scan.blocked",
	"shield.boundary.enforced",
	"shield.reflex.fired",
	"shield.pii.redacted",
}

// ErrNoTenantSource is what Register returns when AllTenants is on but
// nothing lists the tenants. Shield can't list its own tenants, so widening
// needs a TenantSource.
var ErrNoTenantSource = errors.New("witness/shield: all_tenants needs a TenantSource, because shield can't list its tenants")

// ErrTooMany is what a collector returns when the scope holds more rows
// than one population can carry (push.MaxItems). The run fails, and its
// heartbeat says so, rather than sending a list that looks complete but
// isn't.
var ErrTooMany = errors.New("witness/shield: more rows in scope than one population can carry")

// TenantSource lists every shield tenant ID your app has, such as every
// workspace's organization ID. Shield keeps no list of tenants, so the
// adapter needs one from you to widen past the tenants you name. In a Forge
// app, provide one in the container and the adapter finds it.
type TenantSource func(ctx context.Context) ([]string, error)

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.shield.
type Options struct {
	// AppID is the shield app ID, such as "loomplane". Rows of other apps
	// are left out, and app-wide policies and reports are read for this
	// app. Empty reads every app in the named tenants and no app-wide rows.
	AppID string `json:"app_id"`
	// Tenants are the shield tenant IDs to read, usually your own
	// company's organization. Empty means no tenant is read, never every
	// tenant.
	Tenants []string `json:"tenants"`
	// AllTenants adds shield.tenant-conformance: how many tenants run each
	// distinct safety configuration, without naming any tenant. It needs a
	// TenantSource. In a Forge app the witness scope's AllTenants turns it
	// on too.
	AllTenants bool `json:"all_tenants"`
	// EngineSnapshot turns the shield.engine snapshot off when false. It
	// is on when unset.
	EngineSnapshot *bool `json:"engine_snapshot"`
	// EventProofs turns on the safety actions event proof. Off by default.
	EventProofs bool `json:"event_proofs"`
	// ProofActions are the actions the event proof cites. Empty means
	// DefaultProofActions.
	ProofActions []string `json:"proof_actions"`
	// TenantSource lists every tenant when AllTenants is on. In a Forge
	// app it comes from the container.
	TenantSource TenantSource `json:"-"`
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithAppID sets the shield app ID to read.
func WithAppID(appID string) Option { return func(o *Options) { o.AppID = appID } }

// WithTenants adds shield tenant IDs to read.
func WithTenants(tenantIDs ...string) Option {
	return func(o *Options) { o.Tenants = append(o.Tenants, tenantIDs...) }
}

// WithAllTenants adds the tenant conformance snapshot across every tenant.
// It needs WithTenantSource.
func WithAllTenants() Option { return func(o *Options) { o.AllTenants = true } }

// WithTenantSource sets how the adapter lists every tenant when AllTenants
// is on.
func WithTenantSource(src TenantSource) Option { return func(o *Options) { o.TenantSource = src } }

// WithoutEngineSnapshot turns the shield.engine snapshot off.
func WithoutEngineSnapshot() Option {
	return func(o *Options) {
		off := false
		o.EngineSnapshot = &off
	}
}

// WithEventProofs turns on the safety actions event proof, citing actions,
// or DefaultProofActions when you name none.
func WithEventProofs(actions ...string) Option {
	return func(o *Options) {
		o.EventProofs = true
		o.ProofActions = append(o.ProofActions, actions...)
	}
}

// Adapter collects shield evidence from one engine.
type Adapter struct {
	eng      *engine.Engine
	o        Options
	app      string
	tenants  []string // trimmed and deduplicated
	tenantIn map[string]bool
}

// New returns an adapter that reads eng.
func New(eng *engine.Engine, opts ...Option) *Adapter {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return newAdapter(eng, o)
}

func newAdapter(eng *engine.Engine, o Options) *Adapter {
	a := &Adapter{eng: eng, o: o, app: strings.TrimSpace(o.AppID), tenantIn: map[string]bool{}}
	a.tenants = cleanTenants(o.Tenants)
	for _, t := range a.tenants {
		a.tenantIn[t] = true
	}
	return a
}

// cleanTenants drops blank and repeated tenant IDs. A blank tenant would
// make shield fall back to the context tenant, so it is never read.
func cleanTenants(in []string) []string {
	var out []string
	for _, t := range in {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// Register adds the adapter's collectors to w. It returns ErrNoTenantSource,
// and adds nothing, when AllTenants is on without a TenantSource.
func (a *Adapter) Register(w *witness.Witness) error {
	pops, snaps, proofs, err := a.collectors()
	if err != nil {
		return err
	}
	for _, p := range pops {
		if err := w.Population(p); err != nil {
			return err
		}
	}
	for _, s := range snaps {
		if err := w.Snapshot(s); err != nil {
			return err
		}
	}
	for _, e := range proofs {
		if err := w.EventProof(e); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) collectors() ([]collect.Population, []collect.Snapshot, []collect.EventProof, error) {
	if a.eng == nil {
		return nil, nil, nil, errors.New("witness/shield: no engine")
	}
	if a.o.AllTenants && a.o.TenantSource == nil {
		return nil, nil, nil, ErrNoTenantSource
	}
	var (
		pops   []collect.Population
		snaps  []collect.Snapshot
		proofs []collect.EventProof
	)
	if a.o.EngineSnapshot == nil || *a.o.EngineSnapshot {
		snaps = append(snaps, collect.Snapshot{
			Key:         KeyEngine,
			Title:       "AI safety engine settings",
			Description: "How the safety engine runs: default profile, scan limits, whether a model judge is on, and the detectors it supports.",
			Every:       time.Hour,
			Collect:     a.collectEngine,
		})
	}
	// Without a store there is nothing to read but the engine's settings,
	// which say persistence is off.
	if a.eng.Store() != nil {
		if len(a.tenants) > 0 {
			pops = append(pops,
				collect.Population{
					Key:         KeyProfiles,
					Title:       "AI safety profiles",
					Description: "Each safety profile in scope and the safety checks it is built from.",
					Source:      "shield-profiles",
					Every:       time.Hour,
					Collect:     a.collectProfiles,
				},
				collect.Population{
					Key:         KeyChecks,
					Title:       "AI safety checks",
					Description: "Every detector, rule and limit the safety profiles use, with its action and whether it is on.",
					Source:      "shield-checks",
					Tests:       []string{"high-risk-approved"},
					Every:       time.Hour,
					Collect:     a.collectChecks,
				},
			)
			snaps = append(snaps, collect.Snapshot{
				Key:         KeyScanOutcomes,
				Title:       "AI safety scan outcomes",
				Description: "How many safety scans ran yesterday and how many were blocked, flagged or allowed.",
				Every:       time.Hour,
				Collect:     a.collectScanOutcomes,
			})
		}
		if len(a.tenants) > 0 || a.app != "" {
			pops = append(pops,
				collect.Population{
					Key:         KeyPolicies,
					Title:       "AI safety policies",
					Description: "Each safety policy in scope and what its rules do.",
					Source:      "shield-policies",
					Every:       time.Hour,
					Collect:     a.collectPolicies,
				},
				collect.Population{
					Key:         KeyReports,
					Title:       "AI compliance reports",
					Description: "Compliance reports generated for each framework, with their period and headline figures.",
					Source:      "shield-reports",
					Every:       6 * time.Hour,
					Collect:     a.collectReports,
				},
			)
		}
		if a.o.AllTenants {
			snaps = append(snaps, collect.Snapshot{
				Key:         KeyConformance,
				Title:       "AI safety configuration across tenants",
				Description: "How many tenants run each distinct safety configuration, across every tenant your tenant source lists, customers included, without naming any tenant.",
				Every:       6 * time.Hour,
				Collect:     a.collectConformance,
			})
		}
	}
	if a.o.EventProofs {
		actions := a.o.ProofActions
		if len(actions) == 0 {
			actions = DefaultProofActions
		}
		proofs = append(proofs, collect.EventProof{
			Key:         KeySafetyActions,
			Title:       "AI safety actions",
			Description: "Signed audit events for scans the safety engine blocked, limits it enforced, rules that fired and personal data it redacted.",
			Every:       15 * time.Minute,
			Stream:      adapter.Platform,
			Actions:     slices.Clone(actions),
		})
	}
	return pops, snaps, proofs, nil
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"shield"},
		Attach: attach,
	})
}

// extensionName is the name shield's Forge extension registers under.
const extensionName = "shield"

// engineGetter is the one method of shield's Forge extension the adapter
// uses. A structural interface keeps the extension module out of the
// adapter's dependencies.
type engineGetter interface{ Engine() *engine.Engine }

// attach registers the collectors. A TenantSource in the container serves
// AllTenants. It decides from config first whether there is anything to
// collect, and only then reads the engine: through shield's extension when
// the app runs it, and from the container otherwise.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	ext, hasExt := h.Ext(extensionName)
	c, isVessel := h.Container.(vessel.Vessel)
	inContainer := isVessel && c != nil && vessel.HasType[*engine.Engine](c)
	if !hasExt && !inContainer {
		return false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return true, err
	}
	log := h.Logger
	if log == nil {
		log = slog.Default()
	}
	own := o.AllTenants
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	if o.AllTenants && c != nil && vessel.HasType[TenantSource](c) {
		src, err := vessel.Inject[TenantSource](c)
		if err != nil {
			return true, fmt.Errorf("witness/shield: resolve the tenant source: %w", err)
		}
		o.TenantSource = src
	}
	if o.AllTenants && o.TenantSource == nil {
		log.Warn("witness: shield can't list its tenants and no shield.TenantSource is in the container, so the scope is not widened")
		o.AllTenants = false
	}
	if nothingToCollect(o) {
		log.Info("witness: shield found, but engine_snapshot is off and no tenants, app or event proofs are set, so nothing is collected")
		return true, nil
	}
	var eng *engine.Engine
	if hasExt {
		g, ok := ext.(engineGetter)
		if !ok {
			log.Warn("witness: the shield extension has no Engine getter, so shield is skipped", "type", fmt.Sprintf("%T", ext))
			return false, nil
		}
		if eng = g.Engine(); eng == nil {
			log.Warn("witness: the shield extension has no engine yet, so shield is skipped")
			return false, nil
		}
	} else {
		// The app doesn't run shield's extension and provided the engine
		// itself. A finished value is never started again.
		var err error
		if eng, err = vessel.Inject[*engine.Engine](c); err != nil {
			return true, fmt.Errorf("witness/shield: resolve the engine: %w", err)
		}
	}
	// The host reports its own scope. Only this adapter's config is ours to
	// report, and only when it really widened.
	if own && o.AllTenants {
		h.Widened("all_tenants")
	}
	if eng.Store() == nil {
		log.Warn("witness: shield has no store, so only its engine settings are collected")
	} else if len(cleanTenants(o.Tenants)) == 0 {
		log.Info("witness: no shield tenants are set, so no profiles, checks or scan outcomes are collected")
	}
	return true, newAdapter(eng, o).Register(h.Witness)
}

// nothingToCollect reports whether o, once AllTenants is settled, leaves
// every collector off whatever the engine holds.
func nothingToCollect(o Options) bool {
	snapshot := o.EngineSnapshot == nil || *o.EngineSnapshot
	return !snapshot && !o.AllTenants && !o.EventProofs &&
		len(cleanTenants(o.Tenants)) == 0 && strings.TrimSpace(o.AppID) == ""
}
