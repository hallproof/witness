// Package adapter is the registry library adapters join, the way
// database/sql drivers do.
//
// An adapter is a nested module, such as github.com/hallproof/witness/keysmith,
// that knows one library. It registers itself from init, and a host such as
// witness/forge calls each registered adapter's Attach with the app's
// container. Attach finds the library's engine there, or reports that the app
// doesn't run that library, and registers its collectors on the witness.
//
// This package imports only the standard library and witness itself, so an
// adapter pays for nothing here beyond what its own library needs.
package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/chain"
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
