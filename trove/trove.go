package trove

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	xtrove "github.com/xraph/trove"
	"github.com/xraph/trove/extension"
	"github.com/xraph/trove/extension/store"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/push"
)

// Name is the adapter's name: its config key and log name.
const Name = "trove"

// Module is the library this adapter reads.
const Module = "github.com/xraph/trove"

// Collector keys.
const (
	KeyStores  = "trove.stores"
	KeyBuckets = "trove.buckets"
)

// DefaultStore is the name New gives its one store, and the name attach
// uses when the app runs a single store with no manager.
const DefaultStore = "default"

// ErrTooMany is what a collector returns when there are more rows in scope
// than one population can carry (push.MaxItems). The run fails, and its
// heartbeat says so, rather than sending a list that looks complete but
// isn't.
var ErrTooMany = errors.New("witness/trove: more rows in scope than one population can carry")

// maxItems is the most rows a collector sends before it fails the run. A
// variable so tests can lower it.
var maxItems = push.MaxItems

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.trove.
type Options struct {
	// AllTenants adds bucket records that belong to a tenant, your
	// customers' buckets, to trove.buckets. Off by default, so only the
	// buckets the platform keeps for itself are sent. In a Forge app the
	// witness scope's AllTenants turns it on too. Either way only bucket
	// settings are sent, never objects.
	AllTenants bool `json:"all_tenants"`
}

// Option changes how New or NewManager builds an adapter.
type Option func(*settings)

type settings struct {
	o    Options
	meta store.Store
}

// WithAllTenants adds tenant bucket records to trove.buckets.
func WithAllTenants() Option { return func(s *settings) { s.o.AllTenants = true } }

// WithMetadataStore gives New's one store the metadata store its bucket
// records live in, which turns on trove.buckets. NewManager ignores it and
// reads each store's own from the manager.
func WithMetadataStore(s store.Store) Option { return func(st *settings) { st.meta = s } }

// Adapter collects Trove evidence from one store or from every store a
// TroveManager holds.
type Adapter struct {
	o Options
	// stores lists the stores to read. It is called on every run, so a
	// store added to the manager later is still read.
	stores func() []storeRef
	// hasMeta is whether any store has a metadata store, which decides
	// whether trove.buckets is registered.
	hasMeta bool
}

// storeRef is one named Trove store and its metadata store, which may be
// nil.
type storeRef struct {
	name      string
	t         *xtrove.Trove
	meta      store.Store
	isDefault bool
}

// New returns an adapter that reads one store, named "default".
func New(t *xtrove.Trove, opts ...Option) *Adapter {
	var s settings
	for _, opt := range opts {
		opt(&s)
	}
	return newSingle(t, s.meta, s.o)
}

// NewManager returns an adapter that reads every store in m, the way the
// Trove Forge extension runs several stores.
func NewManager(m *extension.TroveManager, opts ...Option) *Adapter {
	var s settings
	for _, opt := range opts {
		opt(&s)
	}
	return newManager(m, s.o)
}

func newSingle(t *xtrove.Trove, meta store.Store, o Options) *Adapter {
	ref := storeRef{name: DefaultStore, t: t, meta: meta, isDefault: true}
	return &Adapter{
		o:       o,
		hasMeta: meta != nil,
		stores: func() []storeRef {
			if t == nil {
				return nil
			}
			return []storeRef{ref}
		},
	}
}

func newManager(m *extension.TroveManager, o Options) *Adapter {
	a := &Adapter{o: o, stores: func() []storeRef { return managerStores(m) }}
	for _, ref := range a.stores() {
		if ref.meta != nil {
			a.hasMeta = true
			break
		}
	}
	return a
}

// managerStores lists m's stores. It reads only what the manager holds in
// memory.
func managerStores(m *extension.TroveManager) []storeRef {
	if m == nil {
		return nil
	}
	def := m.DefaultName()
	all := m.All()
	out := make([]storeRef, 0, len(all))
	for name, t := range all {
		if t == nil {
			continue
		}
		ref := storeRef{name: name, t: t, isDefault: name == def}
		if s, err := m.GetStore(name); err == nil {
			ref.meta = s
		}
		out = append(out, ref)
	}
	return out
}

// Register adds the adapter's collectors to w: trove.stores always, and
// trove.buckets when a store has a metadata store.
// It adds them all or none: when one fails, the ones added before it
// are taken out again.
func (a *Adapter) Register(w *witness.Witness) error {
	var set adapter.Set
	set.Population(a.populations()...)
	return set.Register(w)
}

func (a *Adapter) populations() []collect.Population {
	pops := []collect.Population{{
		Key:         KeyStores,
		Title:       "Object stores",
		Description: "Each Trove store and its bucket, the driver behind it, and which protections Trove applies when objects are written.",
		Source:      "object-stores",
		Tests:       []string{"storage-encrypted"},
		Every:       15 * time.Minute,
		Collect:     a.collectStores,
	}}
	if a.hasMeta {
		desc := "Buckets recorded in Trove's metadata store with their versioning, lifecycle rules and quotas. Trove records only buckets made through its own API or dashboard, so this list can be empty."
		if a.o.AllTenants {
			desc += " Widened to every tenant: your customers' bucket records are included and marked tenanted."
		}
		pops = append(pops, collect.Population{
			Key:         KeyBuckets,
			Title:       "Trove bucket records",
			Description: desc,
			Source:      "object-buckets",
			Every:       time.Hour,
			Collect:     a.collectBuckets,
		})
	}
	return pops
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{extension.ExtensionName},
		Attach: attach,
	})
}

// options decodes the host's config section and applies its scope. When
// the adapter's own all_tenants is set it tells the host, which already
// knows about the witness scope's AllTenants.
func options(h adapter.Host) (Options, error) {
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return o, err
	}
	if o.AllTenants {
		h.Widened("all_tenants")
	}
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	return o, nil
}

// attach finds Trove, through Trove's own extension or else the container,
// and registers the collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	if x, ok := h.Ext(extension.ExtensionName); ok {
		return attachExtension(h, x)
	}
	return attachContainer(h)
}

// Trove's Forge extension, read through its getters.
type (
	managerGetter interface {
		Manager() *extension.TroveManager
	}
	troveGetter interface{ Trove() *xtrove.Trove }
	storeGetter interface{ Store() store.Store }
)

// attachExtension reads Trove through its extension x: every store its
// manager holds, or else its lone store and that store's metadata store. It
// never asks the container, where the extension registers them with
// constructors, because the container starts whatever a constructor builds
// the first time anyone asks for it.
func attachExtension(h adapter.Host, x any) (bool, error) {
	var (
		m    *extension.TroveManager
		t    *xtrove.Trove
		meta store.Store
	)
	if g, ok := x.(managerGetter); ok {
		m = g.Manager()
	}
	if m == nil {
		if g, ok := x.(troveGetter); ok {
			t = g.Trove()
		}
		if g, ok := x.(storeGetter); ok {
			meta = g.Store()
		}
	}
	if m == nil && t == nil {
		log := h.Logger
		if log == nil {
			log = slog.Default()
		}
		log.Warn("witness: the trove extension has no store yet, so trove is skipped", "type", fmt.Sprintf("%T", x))
		return false, nil
	}
	o, err := options(h)
	if err != nil {
		return true, err
	}
	if m != nil {
		return true, newManager(m, o).Register(h.Witness)
	}
	return true, newSingle(t, meta, o).Register(h.Witness)
}

// attachContainer finds Trove in the host's container, for an app that
// doesn't run Trove's extension: an *extension.TroveManager when it runs
// several stores, else a lone *trove.Trove, read as one store named
// "default".
func attachContainer(h adapter.Host) (bool, error) {
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil {
		return false, nil
	}
	hasManager := vessel.HasType[*extension.TroveManager](c)
	if !hasManager && !vessel.HasType[*xtrove.Trove](c) {
		return false, nil
	}
	o, err := options(h)
	if err != nil {
		return true, err
	}
	var a *Adapter
	if hasManager {
		m, err := vessel.Inject[*extension.TroveManager](c)
		if err != nil {
			return true, fmt.Errorf("witness/trove: resolve the store manager: %w", err)
		}
		a = newManager(m, o)
	} else {
		t, err := vessel.Inject[*xtrove.Trove](c)
		if err != nil {
			return true, fmt.Errorf("witness/trove: resolve the store: %w", err)
		}
		a = newSingle(t, nil, o)
	}
	return true, a.Register(h.Witness)
}
