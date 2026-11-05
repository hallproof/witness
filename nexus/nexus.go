package nexus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	nx "github.com/xraph/nexus"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "nexus"

// Module is the library this adapter reads.
const Module = "github.com/xraph/nexus"

// Collector keys.
const (
	KeyGateway     = "nexus.gateway"
	KeyModelsInUse = "nexus.models-in-use"
	KeyKeys        = "nexus.keys"
	KeyBudgets     = "nexus.budgets"
)

// DefaultOwnerKey is the key metadata entry read as a key's owner when you
// don't name one.
const DefaultOwnerKey = "owner_id"

// ErrTooMany is what a collector returns when the scope holds more rows
// than one population can carry (push.MaxItems), or when finding the models
// in use would take more queries than the adapter allows itself. The run
// fails, and its heartbeat says so, rather than sending a list that looks
// complete but isn't.
var ErrTooMany = errors.New("witness/nexus: more in scope than one run can carry")

// ErrNotReady is what a collector that reads the gateway's store returns
// when the gateway hasn't been initialized yet, so its services don't
// exist.
var ErrNotReady = errors.New("witness/nexus: the gateway is not initialized")

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.nexus.
type Options struct {
	// Tenants are the Nexus tenants, by ID or slug, whose keys and budgets
	// are collected, such as your own company's tenant. Empty means the
	// key and budget collectors are not registered, never every tenant.
	Tenants []string `json:"tenants"`
	// AllTenants collects every tenant's keys and budgets, your customers'
	// included. In a Forge app the witness scope's AllTenants turns it on
	// too.
	AllTenants bool `json:"all_tenants"`
	// OwnerKey is the key metadata entry sent as each key's owner_id.
	// Empty means DefaultOwnerKey. No other metadata is sent.
	OwnerKey string `json:"owner_key"`
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithTenants names the tenants, by ID or slug, whose keys and budgets are
// collected.
func WithTenants(tenants ...string) Option {
	return func(o *Options) { o.Tenants = append(o.Tenants, tenants...) }
}

// WithAllTenants collects every tenant's keys and budgets, customers'
// included.
func WithAllTenants() Option { return func(o *Options) { o.AllTenants = true } }

// WithOwnerKey sets the key metadata entry sent as each key's owner_id.
func WithOwnerKey(k string) Option { return func(o *Options) { o.OwnerKey = k } }

// Adapter collects Nexus evidence from one gateway.
type Adapter struct {
	gw       *nx.Gateway
	o        Options
	tenants  []string // trimmed, deduplicated tenant IDs or slugs
	ownerKey string
	now      func() time.Time
}

// New returns an adapter that reads gw.
func New(gw *nx.Gateway, opts ...Option) *Adapter {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return newAdapter(gw, o)
}

func newAdapter(gw *nx.Gateway, o Options) *Adapter {
	a := &Adapter{gw: gw, o: o, ownerKey: strings.TrimSpace(o.OwnerKey), now: time.Now}
	if a.ownerKey == "" {
		a.ownerKey = DefaultOwnerKey
	}
	seen := map[string]bool{}
	for _, t := range o.Tenants {
		// A blank entry would read as every tenant to Nexus, so it is
		// dropped.
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		a.tenants = append(a.tenants, t)
	}
	return a
}

// tenantScoped reports whether the key and budget collectors run: only for
// named tenants, or for every tenant when AllTenants is on.
func (a *Adapter) tenantScoped() bool { return a.o.AllTenants || len(a.tenants) > 0 }

// Register adds the adapter's collectors to w: the gateway-wide ones
// always, and the key and budget populations when tenants are named or
// AllTenants is on.
func (a *Adapter) Register(w *witness.Witness) error {
	if a.gw == nil {
		return errors.New("witness/nexus: no gateway")
	}
	pops, snaps := a.collectors()
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
	return nil
}

func (a *Adapter) collectors() ([]collect.Population, []collect.Snapshot) {
	snaps := []collect.Snapshot{{
		Key:         KeyGateway,
		Title:       "AI gateway settings",
		Description: "Which AI providers the gateway can call, what each supports, the model aliases, the guardrails and the gateway's own security settings.",
		Every:       time.Hour,
		Collect:     a.collectGateway,
	}}
	pops := []collect.Population{{
		Key:         KeyModelsInUse,
		Title:       "AI models in use",
		Description: "Each provider and model the gateway actually called in the last month.",
		Source:      "nexus-models",
		Every:       6 * time.Hour,
		Collect:     a.collectModelsInUse,
	}}
	if a.tenantScoped() {
		pops = append(pops,
			collect.Population{
				Key:         KeyKeys,
				Title:       "AI gateway API keys",
				Description: "Every Nexus API key in scope, with its scopes, status, age and owner.",
				Source:      "nexus-keys",
				Tests:       []string{"keys-rotated"},
				Every:       15 * time.Minute,
				Collect:     a.collectKeys,
			},
			collect.Population{
				Key:         KeyBudgets,
				Title:       "AI budgets and limits",
				Description: "Each in-scope tenant's AI spending budget, rate limits and model restrictions.",
				Source:      "nexus-tenants",
				Every:       time.Hour,
				Collect:     a.collectBudgets,
			},
		)
	}
	return pops, snaps
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"nexus"},
		Attach: attach,
	})
}

// attach finds *nexus.Gateway in the host's container and registers the
// collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*nx.Gateway](c) {
		return false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return true, err
	}
	gw, err := vessel.Inject[*nx.Gateway](c)
	if err != nil {
		return true, fmt.Errorf("witness/nexus: resolve the gateway: %w", err)
	}
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	log := h.Logger
	if log == nil {
		log = slog.Default()
	}
	if on, ok := h.Config["event_proofs"].(bool); ok && on {
		log.Warn("witness: nexus has no event proofs yet, because its audit actions (key.created and the like) aren't namespaced; event_proofs is ignored")
	}
	a := newAdapter(gw, o)
	if !a.tenantScoped() {
		log.Info("witness: nexus found; no tenants are named, so keys and budgets are not collected")
	}
	return true, a.Register(h.Witness)
}
