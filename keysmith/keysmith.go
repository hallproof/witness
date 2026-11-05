package keysmith

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	ks "github.com/xraph/keysmith"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "keysmith"

// Module is the library this adapter reads.
const Module = "github.com/xraph/keysmith"

// Collector keys.
const (
	KeyAPIKeys        = "keysmith.api-keys"
	KeyPolicies       = "keysmith.key-policies"
	KeyRotation       = "keysmith.rotation"
	KeyLifecycleProof = "keysmith.key-lifecycle-proof"
)

// DefaultProofActions are the audit actions the lifecycle proof cites when
// you turn event proofs on without naming any. Keysmith's audit_hook plugin
// records them.
var DefaultProofActions = []string{"keysmith.key.rotated", "keysmith.key.revoked", "keysmith.key.expired"}

// ErrNoTenants is what Register returns when there are no staff tenants and
// AllTenants is off. The adapter never reads every tenant by default, so
// with nothing to read it registers nothing.
var ErrNoTenants = errors.New("witness/keysmith: no staff tenants are set, so no keys are collected; set staff_tenants, or all_tenants to collect every tenant")

// ErrTooMany is what a collector returns when the scope holds more rows
// than one population can carry (push.MaxItems). The run fails, and its
// heartbeat says so, rather than sending a list that looks complete but
// isn't.
var ErrTooMany = errors.New("witness/keysmith: more rows in scope than one population can carry")

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.keysmith.
type Options struct {
	// AppID keeps keys and policies of this keysmith app ID only. Empty
	// keeps every app. In a Forge app it defaults to the witness scope's
	// AppID.
	AppID string `json:"app_id"`
	// StaffTenants are the keysmith tenant IDs whose keys are staff keys,
	// such as your own company's organization. Empty means nothing is
	// collected, never every tenant.
	StaffTenants []string `json:"staff_tenants"`
	// AllTenants collects every tenant's keys, your customers' included.
	// In a Forge app the witness scope's AllTenants turns it on too.
	AllTenants bool `json:"all_tenants"`
	// MetadataKeys are the key metadata entries sent with each key, such as
	// "kind". Only plain values (strings, numbers, booleans) are sent.
	// Empty sends no metadata.
	MetadataKeys []string `json:"metadata_keys"`
	// EventProofs turns on the key lifecycle event proof. Off by default.
	EventProofs bool `json:"event_proofs"`
	// ProofActions are the actions the event proof cites. Empty means
	// DefaultProofActions.
	ProofActions []string `json:"proof_actions"`
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithAppID keeps keys and policies of this app ID only.
func WithAppID(appID string) Option { return func(o *Options) { o.AppID = appID } }

// WithStaffTenants sets the tenant IDs whose keys are staff keys.
func WithStaffTenants(tenantIDs ...string) Option {
	return func(o *Options) { o.StaffTenants = append(o.StaffTenants, tenantIDs...) }
}

// WithAllTenants collects every tenant's keys, customers' included.
func WithAllTenants() Option { return func(o *Options) { o.AllTenants = true } }

// WithMetadataKeys sends these key metadata entries with each key.
func WithMetadataKeys(keys ...string) Option {
	return func(o *Options) { o.MetadataKeys = append(o.MetadataKeys, keys...) }
}

// WithEventProofs turns on the key lifecycle event proof, citing actions, or
// DefaultProofActions when you name none.
func WithEventProofs(actions ...string) Option {
	return func(o *Options) {
		o.EventProofs = true
		o.ProofActions = append(o.ProofActions, actions...)
	}
}

// Adapter collects keysmith evidence from one engine.
type Adapter struct {
	eng      *ks.Engine
	o        Options
	tenants  []string // trimmed, deduplicated staff tenants
	meta     []string
	tenantIn map[string]bool
}

// New returns an adapter that reads eng.
func New(eng *ks.Engine, opts ...Option) *Adapter {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return newAdapter(eng, o)
}

func newAdapter(eng *ks.Engine, o Options) *Adapter {
	a := &Adapter{eng: eng, o: o, tenantIn: map[string]bool{}}
	for _, t := range o.StaffTenants {
		// A blank tenant would list every tenant, so it is dropped.
		t = strings.TrimSpace(t)
		if t == "" || a.tenantIn[t] {
			continue
		}
		a.tenantIn[t] = true
		a.tenants = append(a.tenants, t)
	}
	for _, k := range o.MetadataKeys {
		if k = strings.TrimSpace(k); k != "" && !slices.Contains(a.meta, k) {
			a.meta = append(a.meta, k)
		}
	}
	return a
}

// Register adds the adapter's collectors to w. It returns ErrNoTenants, and
// adds nothing, when no staff tenant is set and AllTenants is off.
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

// where says, in a collector description, which tenants it reads.
func (a *Adapter) where() string {
	if a.o.AllTenants {
		return "every tenant, customers included"
	}
	return "the staff tenants"
}

func (a *Adapter) collectors() ([]collect.Population, []collect.Snapshot, []collect.EventProof, error) {
	if a.eng == nil {
		return nil, nil, nil, errors.New("witness/keysmith: no engine")
	}
	if !a.o.AllTenants && len(a.tenants) == 0 {
		return nil, nil, nil, ErrNoTenants
	}
	pops := []collect.Population{
		{
			Key:         KeyAPIKeys,
			Title:       "API keys",
			Description: "Every API key in " + a.where() + ", with its owner, scopes, state, expiry and rotation date.",
			Source:      "api-keys",
			Tests:       []string{"keys-rotated", "no-active-leavers"},
			Every:       15 * time.Minute,
			Collect:     a.collectKeys,
		},
		{
			Key:         KeyPolicies,
			Title:       "Key policies",
			Description: "The rules each key in " + a.where() + " is held to, including how long a key may live and how often it must rotate.",
			Source:      "key-policies",
			Tests:       []string{"keys-rotated"},
			Every:       time.Hour,
			Collect:     a.collectPolicies,
		},
	}
	snaps := []collect.Snapshot{{
		Key:         KeyRotation,
		Title:       "Key rotation",
		Description: "How many keys there are in " + a.where() + ", how many are active, and the oldest rotation date among active keys.",
		Tests:       []string{"keys-rotated"},
		Every:       15 * time.Minute,
		Collect:     a.collectRotation,
	}}
	var proofs []collect.EventProof
	if a.o.EventProofs {
		actions := a.o.ProofActions
		if len(actions) == 0 {
			actions = DefaultProofActions
		}
		proofs = append(proofs, collect.EventProof{
			Key:         KeyLifecycleProof,
			Title:       "Key lifecycle events",
			Description: "Signed audit events for staff keys being rotated, revoked or expiring.",
			Tests:       []string{"keys-rotated"},
			Every:       15 * time.Minute,
			Stream:      adapter.Platform,
			Actions:     slices.Clone(actions),
		})
	}
	return pops, snaps, proofs, nil
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"keysmith"},
		Attach: attach,
	})
}

// attach finds *keysmith.Engine in the host's container and registers the
// collectors. With no staff tenants it logs why and registers nothing.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*ks.Engine](c) {
		return false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return true, err
	}
	eng, err := vessel.Inject[*ks.Engine](c)
	if err != nil {
		return true, fmt.Errorf("witness/keysmith: resolve the engine: %w", err)
	}
	if o.AppID == "" {
		o.AppID = h.Scope.AppID
	}
	// The host reports its own all-tenants scope; this is the adapter's.
	own := o.AllTenants
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	err = newAdapter(eng, o).Register(h.Witness)
	if errors.Is(err, ErrNoTenants) {
		log := h.Logger
		if log == nil {
			log = slog.Default()
		}
		log.Warn("witness: keysmith found, but no staff_tenants are set, so no keys are collected")
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
