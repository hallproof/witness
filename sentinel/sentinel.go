package sentinel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/xraph/sentinel/engine"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "sentinel"

// Module is the library this adapter reads.
const Module = "github.com/xraph/sentinel"

// Collector keys.
const (
	KeySuites       = "sentinel.suites"
	KeyLatestScores = "sentinel.latest-scores"
	KeyRedTeam      = "sentinel.redteam"
	KeySettings     = "sentinel.settings"
	KeyEvalActivity = "sentinel.eval-activity"
)

// DefaultProofActions are the audit actions the eval activity proof cites
// when you turn event proofs on without naming any. Sentinel's engine emits
// them, and its audit_hook plugin records them.
var DefaultProofActions = []string{
	"sentinel.eval.run.completed",
	"sentinel.eval.run.failed",
	"sentinel.regression.detected",
	"sentinel.baseline.saved",
}

// ErrTooMany is what a collector returns when the scope holds more suites
// than one population can carry (push.MaxItems). The run fails, and its
// heartbeat says so, rather than sending a list that looks complete but
// isn't.
var ErrTooMany = errors.New("witness/sentinel: more suites in scope than one population can carry")

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.sentinel.
type Options struct {
	// AppID keeps suites and runs of this sentinel app ID only. Empty
	// keeps every app. In a Forge app it defaults to the witness scope's
	// AppID.
	AppID string `json:"app_id"`
	// StaffTenants are target tenant IDs whose runs count as your own,
	// besides runs with no target tenant. A run that evaluated an agent in
	// any other tenant is skipped. In a Forge app the witness scope's
	// TenantID is added.
	StaffTenants []string `json:"staff_tenants"`
	// AllTenants counts runs against every tenant, your customers'
	// included, and sends the target tenant ID with each run. In a Forge
	// app the witness scope's AllTenants turns it on too.
	AllTenants bool `json:"all_tenants"`
	// EventProofs turns on the eval activity event proof. Off by default.
	EventProofs bool `json:"event_proofs"`
	// ProofActions are the actions the event proof cites. Empty means
	// DefaultProofActions.
	ProofActions []string `json:"proof_actions"`
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithAppID keeps suites and runs of this app ID only.
func WithAppID(appID string) Option { return func(o *Options) { o.AppID = appID } }

// WithStaffTenants adds target tenant IDs whose runs count as your own.
func WithStaffTenants(tenantIDs ...string) Option {
	return func(o *Options) { o.StaffTenants = append(o.StaffTenants, tenantIDs...) }
}

// WithAllTenants counts runs against every tenant, customers' included.
func WithAllTenants() Option { return func(o *Options) { o.AllTenants = true } }

// WithEventProofs turns on the eval activity event proof, citing actions,
// or DefaultProofActions when you name none.
func WithEventProofs(actions ...string) Option {
	return func(o *Options) {
		o.EventProofs = true
		o.ProofActions = append(o.ProofActions, actions...)
	}
}

// Adapter collects sentinel evidence from one engine.
type Adapter struct {
	eng      *engine.Engine
	o        Options
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
	a := &Adapter{eng: eng, o: o, tenantIn: map[string]bool{}}
	for _, t := range o.StaffTenants {
		// A blank tenant is the same as no target tenant, which is
		// already staff, so it adds nothing.
		if t = strings.TrimSpace(t); t != "" {
			a.tenantIn[t] = true
		}
	}
	return a
}

// Register adds the adapter's collectors to w.
// It adds them all or none: when one fails, the ones added before it
// are taken out again.
func (a *Adapter) Register(w *witness.Witness) error {
	pops, snaps, proofs, err := a.collectors()
	if err != nil {
		return err
	}
	var set adapter.Set
	set.Population(pops...)
	set.Snapshot(snaps...)
	set.EventProof(proofs...)
	return set.Register(w)
}

// collectors builds every collector. None has Tests yet: Hallproof has no
// test key for AI evaluation evidence, and the nearest one,
// vulnerability-scanning, would mislead an auditor.
func (a *Adapter) collectors() ([]collect.Population, []collect.Snapshot, []collect.EventProof, error) {
	if a.eng == nil {
		return nil, nil, nil, errors.New("witness/sentinel: no engine")
	}
	// Which runs count: by default only runs against your own agents.
	runs := " Only runs with no target tenant or against a staff tenant count."
	if a.o.AllTenants {
		runs = " Runs against every tenant count, customers included, because all_tenants is on, and each goes with its target tenant ID."
	}
	pops := []collect.Population{
		{
			Key:         KeySuites,
			Title:       "AI evaluation suites",
			Description: "Each evaluation suite, the model it tests, how many cases and red-team cases it has, and whether it has a baseline.",
			Source:      "sentinel-suites",
			Every:       time.Hour,
			Collect:     a.collectSuites,
		},
		{
			Key:         KeyLatestScores,
			Title:       "Latest AI evaluation scores",
			Description: "Each suite's most recent completed run, its scores, and how they compare with the suite's baseline." + runs,
			Source:      "sentinel-latest-runs",
			Every:       time.Hour,
			Collect:     a.collectLatestScores,
		},
		{
			Key:         KeyRedTeam,
			Title:       "AI red-team results",
			Description: "For each suite with red-team cases, the latest run's attack count and how many attacks got through, by attack type." + runs,
			Source:      "sentinel-redteam",
			Every:       6 * time.Hour,
			Collect:     a.collectRedTeam,
		},
	}
	snaps := []collect.Snapshot{{
		Key:         KeySettings,
		Title:       "AI evaluation settings",
		Description: "The pass mark and regression threshold evaluations are judged against.",
		Every:       time.Hour,
		Collect:     a.collectSettings,
	}}
	var proofs []collect.EventProof
	if a.o.EventProofs {
		actions := a.o.ProofActions
		if len(actions) == 0 {
			actions = DefaultProofActions
		}
		proofs = append(proofs, collect.EventProof{
			Key:         KeyEvalActivity,
			Title:       "AI evaluation activity",
			Description: "Signed audit events for evaluation runs completing or failing, regressions being found and baselines being saved.",
			Every:       time.Hour,
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
		After:  []string{"sentinel"},
		Attach: attach,
	})
}

// extensionName is the name sentinel's Forge extension registers under.
const extensionName = "sentinel"

// engineGetter is the one method of sentinel's Forge extension the adapter
// uses. A structural interface keeps the extension module out of the
// adapter's dependencies.
type engineGetter interface{ Engine() *engine.Engine }

// attach registers the collectors. It reads the engine through sentinel's
// extension when the app runs it, and from the container otherwise.
// Sentinel always has collectors to register, so there is no config that
// leaves nothing to collect.
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
	var eng *engine.Engine
	if hasExt {
		g, ok := ext.(engineGetter)
		if !ok {
			log.Warn("witness: the sentinel extension has no Engine getter, so sentinel is skipped", "type", fmt.Sprintf("%T", ext))
			return false, nil
		}
		if eng = g.Engine(); eng == nil {
			log.Warn("witness: the sentinel extension has no engine yet, so sentinel is skipped")
			return false, nil
		}
	} else {
		// The app doesn't run sentinel's extension and provided the engine
		// itself. A finished value is never started again.
		var err error
		if eng, err = vessel.Inject[*engine.Engine](c); err != nil {
			return true, fmt.Errorf("witness/sentinel: resolve the engine: %w", err)
		}
	}
	if o.AppID == "" {
		o.AppID = h.Scope.AppID
	}
	if h.Scope.TenantID != "" {
		o.StaffTenants = append(o.StaffTenants, h.Scope.TenantID)
	}
	// The host reports its own scope. Only this adapter's config is ours to
	// report.
	if o.AllTenants {
		h.Widened("all_tenants")
	}
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	return true, newAdapter(eng, o).Register(h.Witness)
}
