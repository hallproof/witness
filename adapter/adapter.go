// Package adapter is the registry library adapters join, the way
// database/sql drivers do.
//
// An adapter is a nested module, such as github.com/hallproof/witness/keysmith,
// that knows one library. It registers itself from init, and a host such as
// witness/forge calls each registered adapter's Attach with the app's
// container. Attach finds the library's engine there, or reports that the app
// doesn't run that library, and registers its collectors on the witness.
// An adapter registers them through a Set, all at once or not at all, so an
// adapter that fails part-way leaves none of its collectors behind.
//
// This package imports only the standard library and witness itself, so an
// adapter pays for nothing here beyond what its own library needs.
package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/collect"
)

// Platform is the stream name event-proof collectors ask the chain for: the
// stream that holds the platform's staff events.
const Platform = "platform"

// DefaultStaffRoles are the role names that make a user staff when the host
// names none.
var DefaultStaffRoles = []string{"platform-owner", "platform-admin"}

// Scope is whose evidence adapters collect. The default is staff only: the
// people who run the platform, its service accounts and keys, never the
// product's customers.
type Scope struct {
	// AppID is the platform app, and TenantID the tenant staff events are
	// recorded under.
	AppID, TenantID string
	// StaffRoles are the role names that make a user staff. Empty means
	// DefaultStaffRoles.
	StaffRoles []string
	// AllTenants widens collection to customer tenants. Off by default; a
	// company whose audit scope includes customer access turns it on, and
	// Hallproof shows that the scope was widened.
	AllTenants bool
}

// Roles returns the staff role names, DefaultStaffRoles when none are set.
func (s Scope) Roles() []string {
	if len(s.StaffRoles) == 0 {
		return append([]string(nil), DefaultStaffRoles...)
	}
	return s.StaffRoles
}

// Host is what a host hands an adapter's Attach.
type Host struct {
	Witness *witness.Witness
	Scope   Scope
	Logger  *slog.Logger
	// Container is where the app keeps its engines: a vessel.Vessel in a
	// Forge app.
	Container any
	// Config is this adapter's own config section, which the adapter
	// decodes with Decode.
	Config map[string]any
	// SetChain binds the chain that event proofs and the middleware use.
	// Only chain adapters call it, and only before the witness starts.
	SetChain func(chain.Chain)
	// Widen tells the host that this adapter collects beyond staff, because
	// its own config widened it (all_tenants or the like), so the host can
	// tell Hallproof. reason says how, in a few words, and never names a
	// tenant. Nil means the host doesn't track it; adapters call it through
	// (Host).Widened, which allows for that.
	Widen func(reason string)
	// Extension looks up one of the app's extensions by name, such as
	// "dispatch". Read a library's engine through its extension's getter
	// (Engine, Gateway and the like) before asking Container: a container
	// can start a value the first time it builds it, and an engine its
	// extension already started must not start twice. Nil means the host
	// has no extensions; adapters call it through (Host).Ext.
	Extension func(name string) (any, bool)
}

// Ext looks up the app's extension called name. It reports false when the
// host set no Extension or the app doesn't run that extension.
func (h Host) Ext(name string) (any, bool) {
	if h.Extension == nil {
		return nil, false
	}
	return h.Extension(name)
}

// Widened reports that the adapter collects beyond staff. It is safe to call
// when the host set no Widen.
func (h Host) Widened(reason string) {
	if h.Widen != nil {
		h.Widen(reason)
	}
}

// Adapter is one library's adapter.
type Adapter struct {
	// Name is the config key and log name, such as "keysmith".
	Name string
	// Module is the library's module path, for coverage reports.
	Module string
	// After names Forge extensions that must start first, usually the
	// library's own.
	After []string
	// Chain marks an adapter that binds the chain. Hosts attach those
	// before the rest.
	Chain bool
	// Attach finds the library in h and registers its collectors. found is
	// false when the app doesn't run the library.
	Attach func(ctx context.Context, h Host) (found bool, err error)
}

var (
	mu       sync.Mutex
	registry = map[string]Adapter{}
)

// Register adds a. It panics when a has no Name or Attach, or when another
// adapter has its Name, like sql.Register: both are programming errors.
func Register(a Adapter) {
	if a.Name == "" {
		panic("witness/adapter: Register needs a name")
	}
	if a.Attach == nil {
		panic(fmt.Sprintf("witness/adapter: adapter %q has no Attach", a.Name))
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[a.Name]; dup {
		panic(fmt.Sprintf("witness/adapter: adapter %q registered twice", a.Name))
	}
	registry[a.Name] = a
}

// Adapters returns every registered adapter, sorted by Name.
func Adapters() []Adapter {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Adapter, 0, len(registry))
	for _, a := range registry {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Decode fills dst, a pointer to an adapter's options struct with json tags,
// from a config section. Keys dst doesn't have are ignored, so a newer
// config still loads.
func Decode(src map[string]any, dst any) error {
	if len(src) == 0 {
		return nil
	}
	raw, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("witness/adapter: config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("witness/adapter: config: %w", err)
	}
	return nil
}

// Set is a group of collectors that are registered together or not at all.
// An adapter adds its snapshots, populations and event proofs to a Set and
// calls Register once, so a collector that fails part-way (a key already
// used, a bad title) doesn't leave the ones before it running while the host
// reports the library as skipped.
//
// The zero Set is empty and ready to use.
type Set struct {
	items []setItem
}

type setItem struct {
	key string
	add func(*witness.Witness) error
}

// Snapshot adds snapshot collectors to the set.
func (s *Set) Snapshot(cs ...collect.Snapshot) {
	for _, c := range cs {
		s.items = append(s.items, setItem{c.Key, func(w *witness.Witness) error { return w.Snapshot(c) }})
	}
}

// Population adds population collectors to the set.
func (s *Set) Population(cs ...collect.Population) {
	for _, c := range cs {
		s.items = append(s.items, setItem{c.Key, func(w *witness.Witness) error { return w.Population(c) }})
	}
}

// EventProof adds event proof collectors to the set.
func (s *Set) EventProof(cs ...collect.EventProof) {
	for _, c := range cs {
		s.items = append(s.items, setItem{c.Key, func(w *witness.Witness) error { return w.EventProof(c) }})
	}
}

// Len is how many collectors the set holds.
func (s *Set) Len() int { return len(s.items) }

// Register adds every collector in the set to w, in the order they were
// added to the set. When one fails, it removes the ones it added before it
// (never a collector someone else registered) and returns that error, so w
// holds either all of the set or none of it. Call it before w.Start: a
// witness that starts while Register runs refuses the rest and can't give
// back the ones already added, and the error then names them.
func (s *Set) Register(w *witness.Witness) error {
	if w == nil {
		return errors.New("witness/adapter: Set.Register needs a witness")
	}
	for i, it := range s.items {
		err := it.add(w)
		if err == nil {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			if !w.Remove(s.items[j].key) {
				err = errors.Join(err, fmt.Errorf("witness/adapter: couldn't take collector %q back out", s.items[j].key))
			}
		}
		return err
	}
	return nil
}
