package warden

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/xraph/vessel"
	"github.com/xraph/warden"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/push"
)

const (
	// Name is the adapter's name: its config key under
	// extensions.witness.adapters and its name in logs.
	Name = "warden"
	// Module is the library this adapter reads.
	Module = "github.com/xraph/warden"
	// ConfigEngine is the config key a host can set to a *warden.Engine
	// when the engine isn't in the container. Only a host that builds the
	// config map in Go can use it; YAML can't carry an engine.
	ConfigEngine = "engine"
)

// DefaultExcludeRoleSlugs are the roles whose assignments the adapter drops
// in staff scope. Authsome gives every user of the platform app
// platform-user, and in a product like Loomplane every customer is such a
// user, so those assignments would put every customer in the staff list.
var DefaultExcludeRoleSlugs = []string{"platform-user"}

// Options configures the adapter. In a Forge app they come from
// extensions.witness.adapters.warden; the json tags are the config keys.
type Options struct {
	// Tenants are the Warden tenants that hold staff access. Empty in a
	// Forge app means the platform app ID from the witness scope, which is
	// where Authsome keeps its platform roles.
	Tenants []string `json:"tenants"`
	// AllTenants widens the roles, assignments, policies and relations
	// collectors to every tenant, customers included. Off by default.
	AllTenants bool `json:"all_tenants"`
	// ExcludeRoleSlugs are roles whose assignments are dropped. Nil means
	// DefaultExcludeRoleSlugs in staff scope and nothing with AllTenants;
	// an empty list drops nothing.
	ExcludeRoleSlugs []string `json:"exclude_role_slugs"`
	// Privileged are the role slugs marked privileged. Empty means the
	// witness scope's staff roles, platform-owner and platform-admin unless
	// the host names others.
	Privileged []string `json:"privileged"`
	// Relations turns on the warden.relations collector. Off by default:
	// tuples name product resources and can be very many.
	Relations bool `json:"relations"`
	// MaxRelations is the most tuples warden.relations collects before it
	// fails the run instead. Zero means push.MaxItems.
	MaxRelations int `json:"max_relations"`
	// EventProofs turns on warden.access-change-proof. Off by default:
	// Warden has no audit bridge to Chronicle yet, so it proves nothing.
	EventProofs bool `json:"event_proofs"`
}

// Option changes the Options New starts from.
type Option func(*Options)

// WithOptions replaces every option with o.
func WithOptions(o Options) Option { return func(dst *Options) { *dst = o } }

// WithTenants sets the staff tenants.
func WithTenants(tenants ...string) Option {
	return func(o *Options) { o.Tenants = tenants }
}

// WithAllTenants widens collection to every tenant, customers included.
func WithAllTenants() Option { return func(o *Options) { o.AllTenants = true } }

// WithExcludeRoleSlugs sets the roles whose assignments are dropped. With
// no slugs, nothing is dropped.
func WithExcludeRoleSlugs(slugs ...string) Option {
	return func(o *Options) { o.ExcludeRoleSlugs = append([]string{}, slugs...) }
}

// WithPrivileged sets the role slugs marked privileged.
func WithPrivileged(slugs ...string) Option {
	return func(o *Options) { o.Privileged = slugs }
}

// WithRelations turns on warden.relations, failing a run that would collect
// more than limit tuples. Zero means push.MaxItems.
func WithRelations(limit int) Option {
	return func(o *Options) { o.Relations, o.MaxRelations = true, limit }
}

// WithEventProofs turns on warden.access-change-proof.
func WithEventProofs() Option { return func(o *Options) { o.EventProofs = true } }

// Adapter collects access evidence from one Warden engine.
type Adapter struct {
	eng  *warden.Engine
	opts Options
}

// New returns an adapter for eng. Use it when you build the witness
// yourself; a Forge app gets one from witness/forge instead.
func New(eng *warden.Engine, opts ...Option) *Adapter {
	a := &Adapter{eng: eng}
	for _, opt := range opts {
		opt(&a.opts)
	}
	a.opts = a.opts.withDefaults()
	return a
}

func (o Options) withDefaults() Options {
	if len(o.Privileged) == 0 {
		o.Privileged = append([]string(nil), adapter.DefaultStaffRoles...)
	}
	if o.ExcludeRoleSlugs == nil && !o.AllTenants {
		o.ExcludeRoleSlugs = append([]string(nil), DefaultExcludeRoleSlugs...)
	}
	if o.MaxRelations <= 0 || o.MaxRelations > push.MaxItems {
		o.MaxRelations = push.MaxItems
	}
	return o
}

var (
	errNoEngine = errors.New("witness/warden: no engine")
	errNoScope  = errors.New("witness/warden: no staff tenants; set tenants, or all_tenants to collect every tenant")
)

// Register adds the adapter's collectors to w. It fails when the adapter
// has no engine, or neither tenants nor AllTenants.
func (a *Adapter) Register(w *witness.Witness) error {
	if a.eng == nil {
		return errNoEngine
	}
	if len(a.opts.Tenants) == 0 && !a.opts.AllTenants {
		return errNoScope
	}
	snaps, pops, proofs := a.collectors()
	for _, s := range snaps {
		if err := w.Snapshot(s); err != nil {
			return err
		}
	}
	for _, p := range pops {
		if err := w.Population(p); err != nil {
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

// where says, in a collector description, which tenants it reads.
func (a *Adapter) where() string {
	if a.opts.AllTenants {
		return "every tenant, customers' included"
	}
	return "the staff tenants"
}

// keptDefaults are the default exclusions an explicit exclude_role_slugs
// leaves in. In staff scope those assignments belong to customers too.
func (a *Adapter) keptDefaults() []string {
	if a.opts.AllTenants {
		return nil
	}
	var kept []string
	for _, slug := range DefaultExcludeRoleSlugs {
		if !slices.Contains(a.opts.ExcludeRoleSlugs, slug) {
			kept = append(kept, slug)
		}
	}
	return kept
}

// keptNote tells Hallproof, in the assignments description, when the
// exclude list keeps a role every customer holds.
func (a *Adapter) keptNote() string {
	kept := a.keptDefaults()
	if len(kept) == 0 {
		return ""
	}
	return " exclude_role_slugs keeps " + strings.Join(kept, " and ") + ", so customers holding it are listed too."
}

// collectors returns every collector the options turn on.
func (a *Adapter) collectors() (snaps []collect.Snapshot, pops []collect.Population, proofs []collect.EventProof) {
	if len(a.opts.Tenants) > 0 {
		snaps = append(snaps, collect.Snapshot{
			Key:         "warden.model",
			Title:       "Authorization model",
			Description: "A fingerprint of each staff tenant's roles, permissions, resource types and policies as they are in force now.",
			Every:       time.Hour,
			Collect:     a.collectModel,
		})
	}
	pops = append(pops,
		collect.Population{
			Key:         "warden.roles",
			Title:       "Roles",
			Description: "Every role in " + a.where() + ", the permissions it grants and the role it inherits from.",
			Source:      "roles",
			Tests:       []string{"privileged-reviewed", "review-signed-off"},
			Every:       15 * time.Minute,
			Collect:     a.collectRoles,
		},
		collect.Population{
			Key:         "warden.assignments",
			Title:       "Role assignments",
			Description: "Who holds which role in " + a.where() + ", since when, and until when." + a.keptNote(),
			Source:      "role-assignments",
			Tests:       []string{"privileged-reviewed", "review-signed-off", "no-active-leavers"},
			Every:       15 * time.Minute,
			Collect:     a.collectAssignments,
		},
		collect.Population{
			Key:         "warden.policies",
			Title:       "Access policies",
			Description: "Every allow or deny policy in " + a.where() + ", whether it is active, and what it matches.",
			Source:      "access-policies",
			Every:       15 * time.Minute,
			Collect:     a.collectPolicies,
		},
	)
	if a.opts.Relations {
		pops = append(pops, collect.Population{
			Key:         "warden.relations",
			Title:       "Relationship tuples",
			Description: "Every relationship tuple in " + a.where() + ", the ReBAC side of who can reach what.",
			Source:      "relations",
			Tests:       []string{"review-signed-off"},
			Every:       time.Hour,
			Collect:     a.collectRelations,
		})
	}
	if a.opts.EventProofs {
		proofs = append(proofs, collect.EventProof{
			Key:         "warden.access-change-proof",
			Title:       "Access changes",
			Description: "Signed proof of role grants, revocations and permission changes on the platform stream.",
			Tests:       []string{"privileged-reviewed", "no-active-leavers"},
			Every:       15 * time.Minute,
			Stream:      adapter.Platform,
			Actions: []string{
				"warden.assignment.created",
				"warden.assignment.deleted",
				"warden.role.permissions_set",
				"warden.permission.attached",
				"warden.permission.detached",
			},
		})
	}
	return snaps, pops, proofs
}

// extensionName is Warden's own Forge extension, which builds and starts
// the engine.
const extensionName = "warden"

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{extensionName},
		Attach: attach,
	})
}

// attach finds the engine, from the config's ConfigEngine key, Warden's
// extension or the container, and registers the collectors the scope
// allows.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	eng, err := engine(h)
	if err != nil {
		return true, err
	}
	if eng == nil {
		return false, nil
	}
	cfg := maps.Clone(h.Config)
	delete(cfg, ConfigEngine)
	var o Options
	if err := adapter.Decode(cfg, &o); err != nil {
		return true, err
	}
	own := o.AllTenants
	o, ok := options(h, o)
	if !ok {
		logger(h).Info("witness/warden: no staff tenant to collect; set adapters.warden.tenants, or a scope app ID")
		return true, nil
	}
	a := New(eng, WithOptions(o))
	if err := a.Register(h.Witness); err != nil {
		return true, err
	}
	// The host reports its own all-tenants scope; these are the adapter's.
	if own {
		h.Widened("all_tenants")
	}
	if len(a.keptDefaults()) > 0 {
		h.Widened("exclude_role_slugs")
	}
	return true, nil
}

// engine returns the host's Warden engine, or nil when it has none. An
// engine under the config's ConfigEngine key comes first. Next it reads the
// engine through Warden's extension when the app runs it, and never asks
// the container then: the extension registers the engine with a
// constructor, and a container that builds it starts it a second time.
// Only an app without the extension is looked up in the container, where an
// app that builds its own engine provides the finished value. It fails when
// the container has an engine that won't resolve.
func engine(h adapter.Host) (*warden.Engine, error) {
	if eng, ok := h.Config[ConfigEngine].(*warden.Engine); ok && eng != nil {
		return eng, nil
	}
	if x, ok := h.Ext(extensionName); ok {
		if g, ok := x.(interface{ Engine() *warden.Engine }); ok {
			if eng := g.Engine(); eng != nil {
				return eng, nil
			}
			logger(h).Warn("witness/warden: the warden extension has no engine yet, so nothing is collected")
			return nil, nil
		}
	}
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*warden.Engine](c) {
		return nil, nil
	}
	eng, err := vessel.Inject[*warden.Engine](c)
	if err != nil {
		return nil, fmt.Errorf("witness/warden: resolve the engine: %w", err)
	}
	return eng, nil
}

// options fills o's gaps from the host's scope. ok is false when there is
// nothing to collect.
func options(h adapter.Host, o Options) (Options, bool) {
	if len(o.Tenants) == 0 && h.Scope.AppID != "" {
		o.Tenants = []string{h.Scope.AppID}
	}
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	if len(o.Privileged) == 0 {
		o.Privileged = h.Scope.Roles()
	}
	return o, len(o.Tenants) > 0 || o.AllTenants
}

func logger(h adapter.Host) *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}
