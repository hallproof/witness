package trove

import (
	"context"
	"errors"
	"fmt"
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
func (a *Adapter) Register(w *witness.Witness) error {
	for _, p := range a.populations() {
		if err := w.Population(p); err != nil {
			return err
		}
	}
	return nil
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
		pops = append(pops, collect.Population{
			Key:         KeyBuckets,
			Title:       "Trove bucket records",
			Description: "Buckets recorded in Trove's metadata store with their versioning, lifecycle rules and quotas. Trove records only buckets made through its own API or dashboard, so this list can be empty.",
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

// options decodes the host's config section and applies its scope.
func options(h adapter.Host) (Options, error) {
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return o, err
	}
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	return o, nil
}

// attach finds Trove in the host's container: the extension's
// *extension.TroveManager when it runs several stores, else a lone
// *trove.Trove, read as one store named "default".
func attach(_ context.Context, h adapter.Host) (bool, error) {
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
