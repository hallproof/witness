package relay

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	xrelay "github.com/xraph/relay"
	"github.com/xraph/relay/catalog"
	"github.com/xraph/relay/endpoint"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "relay"

// Module is the library this adapter reads.
const Module = "github.com/xraph/relay"

// Collector keys.
const (
	KeyEndpoints  = "relay.webhook-endpoints"
	KeyPosture    = "relay.webhook-posture"
	KeyEventTypes = "relay.event-types"
)

// Tests are the test keys the endpoint and posture collectors support.
// Hallproof's library doesn't have them yet; until it does, the evidence
// arrives but lands on no test.
var Tests = []string{"webhooks-signed", "webhooks-encrypted"}

// ErrNoTenants is what Register returns when it has nothing to register:
// no staff tenants, AllTenants off, and the posture and event-type
// collectors turned off or unavailable. The adapter never reads every
// tenant's endpoints by default.
var ErrNoTenants = errors.New("witness/relay: no staff tenants are set and the other collectors are off, so nothing is collected; set staff_tenants, or all_tenants to collect every tenant")

// ErrTooMany is what a population returns when the scope holds more rows
// than one population can carry (push.MaxItems). The run fails, and its
// heartbeat says so, rather than sending a list that looks complete but
// isn't.
var ErrTooMany = errors.New("witness/relay: more rows in scope than one population can carry")

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.relay.
type Options struct {
	// StaffTenants are the relay tenant IDs whose webhook endpoints are
	// staff endpoints, such as your own company's organization. Empty
	// means the endpoint population isn't collected, never every tenant.
	StaffTenants []string `json:"staff_tenants"`
	// AllTenants collects every tenant's endpoints, your customers'
	// included. In a Forge app the witness scope's AllTenants turns it on
	// too.
	AllTenants bool `json:"all_tenants"`
	// Posture turns the relay.webhook-posture snapshot on or off. Unset
	// means on.
	Posture *bool `json:"posture"`
	// EventTypes turns the relay.event-types population on or off. Unset
	// means on, when the store has an event catalog.
	EventTypes *bool `json:"event_types"`

	endpoints endpoint.Store
	log       *slog.Logger
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithStaffTenants sets the tenant IDs whose endpoints are staff endpoints.
func WithStaffTenants(tenantIDs ...string) Option {
	return func(o *Options) { o.StaffTenants = append(o.StaffTenants, tenantIDs...) }
}

// WithAllTenants collects every tenant's endpoints, customers' included.
func WithAllTenants() Option { return func(o *Options) { o.AllTenants = true } }

// WithoutPosture turns off the relay.webhook-posture snapshot.
func WithoutPosture() Option { return func(o *Options) { o.Posture = ptr(false) } }

// WithoutEventTypes turns off the relay.event-types population.
func WithoutEventTypes() Option { return func(o *Options) { o.EventTypes = ptr(false) } }

// WithEndpointStore reads endpoints from s instead of the Relay's own
// store. Pass the raw database store when the one you gave Relay wraps it
// to decrypt signing secrets: the adapter never needs a secret's value,
// and a wrapper that fails a whole list over one bad secret would fail the
// run.
func WithEndpointStore(s endpoint.Store) Option { return func(o *Options) { o.endpoints = s } }

// WithLogger sets where the adapter logs. The default is slog.Default().
func WithLogger(l *slog.Logger) Option { return func(o *Options) { o.log = l } }

// Adapter collects relay evidence from one store.
type Adapter struct {
	eps      endpoint.Store
	cat      catalog.Store // nil when the store has no event catalog
	o        Options
	tenants  []string // trimmed, deduplicated staff tenants
	tenantIn map[string]bool
	log      *slog.Logger
}

// New returns an adapter that reads r's store: endpoints, unless
// WithEndpointStore names another store, and the event catalog.
func New(r *xrelay.Relay, opts ...Option) *Adapter {
	o := options(opts)
	var eps endpoint.Store
	var cat catalog.Store
	if r != nil {
		if st := r.Store(); st != nil {
			eps, cat = st, st
		}
	}
	return newAdapter(eps, cat, o)
}

// NewFromStore returns an adapter that reads endpoints from s, such as the
// relay Postgres store. When s is also a catalog.Store, as every full
// relay store is, it lists event types too.
func NewFromStore(s endpoint.Store, opts ...Option) *Adapter {
	var cat catalog.Store
	if c, ok := s.(catalog.Store); ok {
		cat = c
	}
	return newAdapter(s, cat, options(opts))
}

func options(opts []Option) Options {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func newAdapter(eps endpoint.Store, cat catalog.Store, o Options) *Adapter {
	if o.endpoints != nil {
		eps = o.endpoints
	}
	a := &Adapter{eps: eps, cat: cat, o: o, tenantIn: map[string]bool{}, log: o.log}
	if a.log == nil {
		a.log = slog.Default()
	}
	for _, t := range o.StaffTenants {
		// A blank tenant would list every tenant, so it is dropped.
		t = strings.TrimSpace(t)
		if t == "" || a.tenantIn[t] {
			continue
		}
		a.tenantIn[t] = true
		a.tenants = append(a.tenants, t)
	}
	return a
}

// Register adds the adapter's collectors to w. With no staff tenants and
// AllTenants off it skips the endpoint population and logs why. It returns
// ErrNoTenants, and adds nothing, when that leaves nothing to collect.
// It adds them all or none: when one fails, the ones added before it
// are taken out again.
func (a *Adapter) Register(w *witness.Witness) error {
	pops, snaps, err := a.collectors()
	if err != nil {
		return err
	}
	if !a.endpointsInScope() {
		a.log.Warn("witness/relay: no staff_tenants are set, so webhook endpoints are not collected")
	}
	var set adapter.Set
	set.Population(pops...)
	set.Snapshot(snaps...)
	return set.Register(w)
}

func (a *Adapter) endpointsInScope() bool { return a.o.AllTenants || len(a.tenants) > 0 }

// where says, in a collector description, which tenants it reads.
func (a *Adapter) where() string {
	if a.o.AllTenants {
		return "every tenant, customers included"
	}
	return "the staff tenants"
}

func (a *Adapter) collectors() ([]collect.Population, []collect.Snapshot, error) {
	if a.eps == nil {
		return nil, nil, errors.New("witness/relay: no endpoint store")
	}
	var pops []collect.Population
	var snaps []collect.Snapshot
	if a.endpointsInScope() {
		pops = append(pops, collect.Population{
			Key:         KeyEndpoints,
			Title:       "Webhook destinations",
			Description: "Every webhook endpoint in " + a.where() + ", with where it sends data, whether deliveries are signed and which events it receives.",
			Source:      "webhook-endpoints",
			Tests:       append([]string(nil), Tests...),
			Every:       30 * time.Minute,
			Collect:     a.collectEndpoints,
		})
	}
	if a.o.Posture == nil || *a.o.Posture {
		snaps = append(snaps, collect.Snapshot{
			Key:         KeyPosture,
			Title:       "Webhook signing and encryption posture",
			Description: "Counts of webhook endpoints across the whole system, and how many are unsigned or not HTTPS.",
			Tests:       append([]string(nil), Tests...),
			Every:       time.Hour,
			Collect:     a.collectPosture,
		})
	}
	if a.cat != nil && (a.o.EventTypes == nil || *a.o.EventTypes) {
		pops = append(pops, collect.Population{
			Key:         KeyEventTypes,
			Title:       "Webhook event types",
			Description: "The event types the system can send to webhooks, with their version and whether they are deprecated.",
			Source:      "webhook-event-types",
			Every:       6 * time.Hour,
			Collect:     a.collectEventTypes,
		})
	}
	if len(pops) == 0 && len(snaps) == 0 {
		return nil, nil, ErrNoTenants
	}
	return pops, snaps, nil
}

// extensionName is Relay's own Forge extension, which builds and starts
// the Relay.
const extensionName = "relay"

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{extensionName},
		Attach: attach,
	})
}

// attach finds relay through its extension or the host's container and
// registers the collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	r, eps, found, err := find(h)
	if !found || err != nil {
		return found, err
	}
	var o Options
	err = adapter.Decode(h.Config, &o)
	if err != nil {
		return true, err
	}
	// The host reports its own all-tenants scope; this is the adapter's.
	own := o.AllTenants
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	o.log = h.Logger
	a := build(r, eps, o)
	err = a.Register(h.Witness)
	if errors.Is(err, ErrNoTenants) {
		a.log.Warn("witness: relay found, but no staff_tenants are set and the posture snapshot is off, so nothing is collected")
		return true, nil
	}
	if err != nil {
		return true, err
	}
	if own {
		h.Widened("all_tenants")
	}
	return true, nil
}

// find returns the app's Relay and any bare endpoint.Store it provides.
// found is false when the app has neither.
//
// The Relay comes through Relay's extension when the app runs it, and the
// container is never asked for it then: the extension registers the Relay
// with a constructor, and a container that builds it starts it a second
// time. Only an app without the extension is looked up in the container,
// where an app that builds its own Relay provides the finished value. An
// extension with no Relay getter, or no Relay yet, counts as no relay, and
// then the container isn't asked for the endpoint store either.
//
// Otherwise the bare endpoint.Store always comes from the container. Relay's
// extension doesn't provide one; an app that wraps Relay's store to decrypt
// secrets provides the raw one, as a value, for this adapter.
func find(h adapter.Host) (*xrelay.Relay, endpoint.Store, bool, error) {
	var r *xrelay.Relay
	ext := false
	if x, ok := h.Ext(extensionName); ok {
		g, ok := x.(interface{ Relay() *xrelay.Relay })
		if !ok {
			logger(h).Warn("witness/relay: the relay extension has no Relay getter, so nothing is collected", "type", fmt.Sprintf("%T", x))
			return nil, nil, false, nil
		}
		if r = g.Relay(); r == nil {
			logger(h).Warn("witness/relay: the relay extension has no Relay yet, so nothing is collected")
			return nil, nil, false, nil
		}
		ext = true
	}
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil {
		return r, nil, ext, nil
	}
	var eps endpoint.Store
	if vessel.HasType[endpoint.Store](c) {
		st, err := vessel.Inject[endpoint.Store](c)
		if err != nil {
			return nil, nil, true, fmt.Errorf("witness/relay: resolve the endpoint store: %w", err)
		}
		eps = st
	}
	if !ext && vessel.HasType[*xrelay.Relay](c) {
		got, err := vessel.Inject[*xrelay.Relay](c)
		if err != nil {
			return nil, nil, true, fmt.Errorf("witness/relay: resolve relay: %w", err)
		}
		r = got
	}
	return r, eps, r != nil || eps != nil, nil
}

// build makes the adapter. A bare endpoint.Store wins for endpoints; the
// Relay, when there is one, supplies the event catalog.
func build(r *xrelay.Relay, eps endpoint.Store, o Options) *Adapter {
	if eps != nil {
		o.endpoints = eps
	}
	if r != nil {
		return New(r, withOptions(o))
	}
	return NewFromStore(o.endpoints, withOptions(o))
}

func logger(h adapter.Host) *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

func withOptions(o Options) Option { return func(dst *Options) { *dst = o } }

func ptr[T any](v T) *T { return &v }
