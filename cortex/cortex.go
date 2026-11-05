package cortex

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	cx "github.com/xraph/cortex"
	"github.com/xraph/cortex/agent"
	"github.com/xraph/cortex/engine"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "cortex"

// Module is the library this adapter reads.
const Module = "github.com/xraph/cortex"

// Collector keys.
const (
	KeyAgents           = "cortex.agents"
	KeyTools            = "cortex.tools"
	KeyPersonas         = "cortex.personas"
	KeyPendingApprovals = "cortex.pending-approvals"
	KeyOversight        = "cortex.oversight"
	KeyAgentActivity    = "cortex.agent-activity"
)

// Defaults for the scope level key and the agent metadata keys that hold an
// agent's owner.
const (
	DefaultScopeKey     = "org"
	DefaultOwnerKey     = "owner_id"
	DefaultPrincipalKey = "principal_id"
)

// OversightActions are the audit actions the oversight proof cites. Cortex's
// audit_hook plugin records them when a run pauses for approval and when a
// person decides.
var OversightActions = []string{"cortex.checkpoint.created", "cortex.checkpoint.resolved"}

// ActivityActions are the audit actions the agent activity proof cites.
var ActivityActions = []string{
	"cortex.agent.run.started",
	"cortex.agent.run.completed",
	"cortex.agent.run.failed",
	"cortex.agent.run.terminated",
	"cortex.tool.called",
	"cortex.tool.completed",
	"cortex.tool.failed",
	"cortex.publication.rejected",
}

// ErrNoOrg is what Register returns when no scope is set. Cortex refuses
// a read without a scope, and the adapter won't guess one, so with nothing
// to read it registers nothing.
var ErrNoOrg = errors.New("witness/cortex: no org is set, so no agents are collected; set org to your platform org's ID")

// ErrTooMany is what a collector returns when the scope holds more rows
// than one population can carry (push.MaxItems). The run fails, and its
// heartbeat says so, rather than sending a list that looks complete but
// isn't.
var ErrTooMany = errors.New("witness/cortex: more rows in scope than one population can carry")

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.cortex.
type Options struct {
	// Org is your platform org's ID. The adapter reads the cortex scope
	// ScopeKey=Org and everything beneath it.
	Org string `json:"org"`
	// ScopeKey is the key of the scope's first level. Empty means "org".
	ScopeKey string `json:"scope_key"`
	// Orgs are more orgs to read, such as customer workspaces your audit
	// covers. Empty by default. Their IDs go to Hallproof.
	Orgs []string `json:"orgs"`
	// OwnerKey and PrincipalKey are the agent metadata keys that hold the
	// agent's owner and its principal ID. Empty means "owner_id" and
	// "principal_id". Only string values are sent.
	OwnerKey     string `json:"owner_key"`
	PrincipalKey string `json:"principal_key"`
	// EventProofs turns on the oversight and agent activity event proofs.
	// Off by default.
	EventProofs bool `json:"event_proofs"`

	// Scopes are whole cortex scopes to read, for a host whose scopes
	// aren't org-shaped. Set them with WithScope.
	Scopes []cx.Scope `json:"-"`
	// Owner, when set, says who owns each agent instead of the metadata
	// keys. Set it with WithOwner.
	Owner func(*agent.Config) (ownerID, principalID string) `json:"-"`
	// RiskClass, when set, names each tool's risk class, such as "high".
	// Set it with WithRiskClass.
	RiskClass func(tool string) string `json:"-"`
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithOrg sets your platform org's ID.
func WithOrg(orgID string) Option { return func(o *Options) { o.Org = orgID } }

// WithOrgs adds more orgs to read, such as customer workspaces.
func WithOrgs(orgIDs ...string) Option {
	return func(o *Options) { o.Orgs = append(o.Orgs, orgIDs...) }
}

// WithScopeKey sets the key of the scope's first level, "org" by default.
func WithScopeKey(key string) Option { return func(o *Options) { o.ScopeKey = key } }

// WithScope adds whole cortex scopes to read.
func WithScope(scopes ...cx.Scope) Option {
	return func(o *Options) { o.Scopes = append(o.Scopes, scopes...) }
}

// WithOwnerKeys sets the agent metadata keys that hold the owner and the
// principal ID. An empty key keeps its default.
func WithOwnerKeys(owner, principal string) Option {
	return func(o *Options) { o.OwnerKey, o.PrincipalKey = owner, principal }
}

// WithOwner says who owns each agent, for a host that keeps ownership
// outside cortex. It replaces the metadata keys.
func WithOwner(fn func(*agent.Config) (ownerID, principalID string)) Option {
	return func(o *Options) { o.Owner = fn }
}

// WithRiskClass names each tool's risk class in the tool catalog.
func WithRiskClass(fn func(tool string) string) Option {
	return func(o *Options) { o.RiskClass = fn }
}

// WithEventProofs turns on the oversight and agent activity event proofs.
func WithEventProofs() Option { return func(o *Options) { o.EventProofs = true } }

// Adapter collects cortex evidence from one engine.
type Adapter struct {
	eng      *engine.Engine
	o        Options
	scopes   []cx.Scope
	scopeErr error
	ownerKey string
	prinKey  string
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
	a := &Adapter{eng: eng, o: o, ownerKey: DefaultOwnerKey, prinKey: DefaultPrincipalKey}
	if k := strings.TrimSpace(o.OwnerKey); k != "" {
		a.ownerKey = k
	}
	if k := strings.TrimSpace(o.PrincipalKey); k != "" {
		a.prinKey = k
	}
	key := strings.TrimSpace(o.ScopeKey)
	if key == "" {
		key = DefaultScopeKey
	}
	all := make([]cx.Scope, 0, 1+len(o.Orgs)+len(o.Scopes))
	for _, org := range append([]string{o.Org}, o.Orgs...) {
		// A blank org would be no scope at all, so it is dropped.
		if org = strings.TrimSpace(org); org != "" {
			all = append(all, cx.Scope{Levels: []cx.Level{{Key: key, Value: org}}})
		}
	}
	all = append(all, o.Scopes...)
	seen := map[string]bool{}
	for _, s := range all {
		if err := cx.ValidateScope(s); err != nil {
			a.scopeErr = fmt.Errorf("witness/cortex: scope %q: %w", s.Canonical(), err)
			return a
		}
		if c := s.Canonical(); !seen[c] {
			seen[c] = true
			a.scopes = append(a.scopes, cx.Scope{Levels: slices.Clone(s.Levels)})
		}
	}
	return a
}

// Register adds the adapter's collectors to w. It returns ErrNoOrg, and
// adds nothing, when no org or scope is set.
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
		return nil, nil, nil, errors.New("witness/cortex: no engine")
	}
	if a.scopeErr != nil {
		return nil, nil, nil, a.scopeErr
	}
	if len(a.scopes) == 0 {
		return nil, nil, nil, ErrNoOrg
	}
	pops := []collect.Population{
		{
			Key:         KeyAgents,
			Title:       "AI agents",
			Description: "Every Cortex agent in scope, with its owner, model, tools and whether it is enabled.",
			Source:      "cortex-agents",
			Tests:       []string{"agent-has-owner", "agent-owner-active", "no-orphaned-agents"},
			Every:       15 * time.Minute,
			Collect:     a.collectAgents,
		},
		{
			Key:         KeyPersonas,
			Title:       "Agent personas",
			Description: "Every persona in scope and the skills, traits and behaviours it composes.",
			Source:      "cortex-personas",
			Every:       time.Hour,
			Collect:     a.collectPersonas,
		},
		{
			Key:         KeyPendingApprovals,
			Title:       "Agent actions waiting for a person",
			Description: "Checkpoints where an agent run is paused for human approval, with how long each has waited.",
			Source:      "cortex-pending-approvals",
			Tests:       []string{"high-risk-approved"},
			Every:       15 * time.Minute,
			Collect:     a.collectPending,
		},
	}
	var toolTests []string
	if a.o.RiskClass != nil {
		toolTests = []string{"high-risk-approved"}
	}
	snaps := []collect.Snapshot{{
		Key:         KeyTools,
		Title:       "Agent tool catalog",
		Description: "The tools the Cortex engine can offer a model, where each comes from, and whether a host authorizer gates them.",
		Tests:       toolTests,
		Every:       time.Hour,
		Collect:     a.collectTools,
	}}
	var proofs []collect.EventProof
	if a.o.EventProofs {
		proofs = append(proofs,
			collect.EventProof{
				Key:         KeyOversight,
				Title:       "Human approvals of agent actions",
				Description: "Signed audit events for agent runs pausing for approval and the decisions people made.",
				Tests:       []string{"high-risk-approved"},
				Every:       15 * time.Minute,
				Stream:      adapter.Platform,
				Actions:     slices.Clone(OversightActions),
			},
			collect.EventProof{
				Key:         KeyAgentActivity,
				Title:       "Agent run and tool events",
				Description: "Signed audit events for agent runs starting and ending and for the tools they called.",
				Tests:       []string{"agent-events-chained"},
				Every:       15 * time.Minute,
				Stream:      adapter.Platform,
				Actions:     slices.Clone(ActivityActions),
			},
		)
	}
	return pops, snaps, proofs, nil
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"cortex"},
		Attach: attach,
	})
}

// extensionName is the name cortex's Forge extension registers under.
const extensionName = "cortex"

// engineGetter is the one method of cortex's Forge extension the adapter
// uses. A structural interface keeps the extension module out of the
// adapter's dependencies.
type engineGetter interface{ Engine() *engine.Engine }

// attach registers the collectors. It looks for cortex first and decides
// from config alone whether there is anything to collect, so with no org
// it logs why and returns without touching the engine. Only then does it
// read the engine, through cortex's extension when the app runs it and
// from the container otherwise.
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
	if h.Scope.AllTenants {
		log.Warn("witness: cortex can't list agents across scopes, so all_tenants reads only the orgs named in org and orgs")
	}
	a := newAdapter(nil, o)
	if a.scopeErr != nil {
		return true, a.scopeErr
	}
	if len(a.scopes) == 0 {
		log.Warn("witness: cortex found, but no org is set, so no agents are collected")
		return true, nil
	}
	var eng *engine.Engine
	if hasExt {
		g, ok := ext.(engineGetter)
		if !ok {
			log.Warn("witness: the cortex extension has no Engine getter, so cortex is skipped", "type", fmt.Sprintf("%T", ext))
			return false, nil
		}
		if eng = g.Engine(); eng == nil {
			log.Warn("witness: the cortex extension has no engine yet, so cortex is skipped")
			return false, nil
		}
	} else {
		// The app doesn't run cortex's extension and provided the engine
		// itself. Reading a provided value doesn't start it; only a
		// constructor registration would be built and started here.
		var err error
		if eng, err = vessel.Inject[*engine.Engine](c); err != nil {
			return true, fmt.Errorf("witness/cortex: resolve the engine: %w", err)
		}
	}
	a.eng = eng
	return true, a.Register(h.Witness)
}
