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
func (a *Adapter) Register(w *witness.Witness) error {
	pops, snaps, err := a.collectors()
	if err != nil {
		return err
	}
	if !a.endpointsInScope() {
		a.log.Warn("witness/relay: no staff_tenants are set, so webhook endpoints are not collected")
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
	return nil
}

func (a *Adapter) endpointsInScope() bool { return a.o.AllTenants || len(a.tenants) > 0 }

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
			Description: "Every webhook endpoint in scope, with where it sends data, whether deliveries are signed and which events it receives.",
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

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"relay"},
		Attach: attach,
	})
}

// attach finds relay in the host's container and registers the
// collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || (!vessel.HasType[*xrelay.Relay](c) && !vessel.HasType[endpoint.Store](c)) {
		return false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return true, err
	}
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	o.log = h.Logger
	a, err := resolve(c, o)
	if err != nil {
		return true, err
	}
	err = a.Register(h.Witness)
	if errors.Is(err, ErrNoTenants) {
		a.log.Warn("witness: relay found, but no staff_tenants are set and the posture snapshot is off, so nothing is collected")
		return true, nil
	}
	return true, err
}

// resolve builds the adapter from a container. A bare endpoint.Store
// wins for endpoints, because an app that wraps Relay's store to decrypt
// secrets provides the raw one for this; the Relay, when present, supplies
// the event catalog.
func resolve(c vessel.Vessel, o Options) (*Adapter, error) {
	if vessel.HasType[endpoint.Store](c) {
		st, err := vessel.Inject[endpoint.Store](c)
		if err != nil {
			return nil, fmt.Errorf("witness/relay: resolve the endpoint store: %w", err)
		}
		o.endpoints = st
	}
	if vessel.HasType[*xrelay.Relay](c) {
		r, err := vessel.Inject[*xrelay.Relay](c)
		if err != nil {
			return nil, fmt.Errorf("witness/relay: resolve relay: %w", err)
		}
		return New(r, withOptions(o)), nil
	}
	return NewFromStore(o.endpoints, withOptions(o)), nil
}

func withOptions(o Options) Option { return func(dst *Options) { *dst = o } }

func ptr[T any](v T) *T { return &v }
