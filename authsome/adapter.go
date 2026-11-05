package authsome

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	authsome "github.com/xraph/authsome"
	"github.com/xraph/authsome/plugins/agentauth"
	"github.com/xraph/authsome/plugins/mfa"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key under
// extensions.witness.adapters and its name in logs.
const Name = "authsome"

// Module is the library this adapter reads.
const Module = "github.com/xraph/authsome"

// every is how often each collector runs.
const every = 15 * time.Minute

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"authsome"},
		Attach: attach,
	})
}

// attach finds *authsome.Engine in the host's container. An app without one
// doesn't run Authsome, which is not an error.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*authsome.Engine](c) {
		return false, nil
	}
	eng, err := vessel.Inject[*authsome.Engine](c)
	if err != nil {
		return true, fmt.Errorf("witness/authsome: resolve the engine: %w", err)
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return true, err
	}
	if err := New(eng, WithScope(h.Scope), WithOptions(o), WithLogger(h.Logger)).Register(h.Witness); err != nil {
		return true, err
	}
	if o.AllPlatformUsers {
		h.Widened("all_platform_users")
	}
	return true, nil
}

// Options are the adapter's switches. In a Forge app they come from
// extensions.witness.adapters.authsome.
type Options struct {
	// AllPlatformUsers treats every user of the platform app as staff,
	// instead of only those holding a staff role. Turn it on when the
	// platform app is a separate operator console and customers sign in to
	// other apps. In an app whose customers sign up to the platform app it
	// puts every customer in Hallproof.
	AllPlatformUsers bool `json:"all_platform_users"`
	// APIKeys collects Authsome's own API keys even when the apikey plugin
	// isn't installed. Service account keys exist without the plugin.
	APIKeys bool `json:"api_keys"`
	// InactivityEnforced tells Hallproof the inactivity timeout is enforced.
	// Only Authsome's Forge extension middleware enforces it, and the
	// adapter can't see whether that middleware is mounted, so it reports
	// false unless you say so.
	InactivityEnforced bool `json:"inactivity_enforced"`
	// EventProofs registers the event proof collectors. Off by default:
	// see the package doc.
	EventProofs bool `json:"event_proofs"`
}

// Option configures an Adapter.
type Option func(*Adapter)

// WithScope sets whose evidence to collect. The zero Scope means staff
// holding platform-owner or platform-admin in the engine's platform app.
func WithScope(s adapter.Scope) Option { return func(a *Adapter) { a.scope = s } }

// WithOptions sets every option at once, as a config section decodes them.
func WithOptions(o Options) Option { return func(a *Adapter) { a.opts = o } }

// WithAllPlatformUsers treats every platform-app user as staff.
func WithAllPlatformUsers() Option { return func(a *Adapter) { a.opts.AllPlatformUsers = true } }

// WithAPIKeys collects Authsome API keys without the apikey plugin.
func WithAPIKeys() Option { return func(a *Adapter) { a.opts.APIKeys = true } }

// WithInactivityEnforced reports the inactivity timeout as enforced.
func WithInactivityEnforced() Option { return func(a *Adapter) { a.opts.InactivityEnforced = true } }

// WithEventProofs registers the event proof collectors.
func WithEventProofs() Option { return func(a *Adapter) { a.opts.EventProofs = true } }

// WithLogger sets where the adapter logs. Nil means slog.Default().
func WithLogger(l *slog.Logger) Option { return func(a *Adapter) { a.log = l } }

// Adapter collects evidence from one Authsome engine.
type Adapter struct {
	eng   *authsome.Engine
	scope adapter.Scope
	opts  Options
	log   *slog.Logger
	now   func() time.Time
}

// New returns an adapter for eng. Call Register to add its collectors to a
// witness.
func New(eng *authsome.Engine, opts ...Option) *Adapter {
	a := &Adapter{eng: eng, now: time.Now}
	for _, o := range opts {
		o(a)
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	return a
}

// Register adds the adapter's collectors to w. Call it before w.Start.
func (a *Adapter) Register(w *witness.Witness) error {
	if a.eng == nil {
		return errors.New("witness/authsome: no engine")
	}
	if w == nil {
		return errors.New("witness/authsome: no witness")
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
	a.log.Info("witness/authsome: collecting", "staff", a.staffRule(), "collectors", len(snaps)+len(pops)+len(proofs))
	return nil
}

// collectors builds the collectors this engine supports.
func (a *Adapter) collectors() ([]collect.Snapshot, []collect.Population, []collect.EventProof) {
	snaps := []collect.Snapshot{a.authPolicy()}
	pops := []collect.Population{a.staffUsers(), a.staffSessions(), a.serviceAccounts(), a.agentGrants()}
	if a.opts.APIKeys || a.eng.Plugin("apikey") != nil {
		pops = append(pops, a.staffAPIKeys())
	}
	if a.agentauth() != nil {
		pops = append(pops, a.agents())
	}
	var proofs []collect.EventProof
	if a.opts.EventProofs {
		proofs = eventProofs()
	}
	return snaps, pops, proofs
}

// mfaPlugin returns the mfa plugin, or nil when it isn't installed.
func (a *Adapter) mfaPlugin() *mfa.Plugin {
	p, ok := a.eng.Plugin("mfa").(*mfa.Plugin)
	if !ok {
		return nil
	}
	return p
}

// agentauth returns the agentauth plugin's store, or nil when the plugin
// isn't installed.
func (a *Adapter) agentauth() agentauth.Store {
	p, ok := a.eng.Plugin("agentauth").(*agentauth.Plugin)
	if !ok || p == nil {
		return nil
	}
	return p.Store()
}
