package forge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xraph/forge"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/chain"
)

// Name is the extension's name, and its config key: extensions.witness.
const Name = "witness"

// stopTimeout is how long witness gets to send what is queued when the app
// stops.
const stopTimeout = 10 * time.Second

// Config is the extension's config, read from extensions.witness (or the
// top-level witness key). Fields you set in code with WithConfig win over
// the file.
type Config struct {
	// Endpoint is your Hallproof's base URL. Empty turns witness off.
	Endpoint string `json:"endpoint" mapstructure:"endpoint" yaml:"endpoint"`
	// IngestKey is the system's ingest key, from Hallproof.
	IngestKey string `json:"ingest_key" mapstructure:"ingest_key" yaml:"ingest_key"`
	// IngestKeyFile is a file holding the ingest key, such as a mounted
	// secret. Set IngestKey or IngestKeyFile, not both.
	IngestKeyFile string `json:"ingest_key_file" mapstructure:"ingest_key_file" yaml:"ingest_key_file"`
	// Disabled turns witness off even with an endpoint.
	Disabled bool `json:"disabled" mapstructure:"disabled" yaml:"disabled"`
	// Libraries limits witness to these adapters. Empty means every
	// registered adapter whose library the app runs.
	Libraries []string `json:"libraries" mapstructure:"libraries" yaml:"libraries"`
	// Exclude names adapters to leave out.
	Exclude []string `json:"exclude" mapstructure:"exclude" yaml:"exclude"`
	// Scope is whose evidence adapters collect. Staff only by default.
	Scope ScopeConfig `json:"scope" mapstructure:"scope" yaml:"scope"`
	// HeartbeatEvery is how often each collector's heartbeat is sent. Zero
	// means witness's default, 10 minutes.
	HeartbeatEvery time.Duration `json:"heartbeat_every" mapstructure:"heartbeat_every" yaml:"heartbeat_every"`
	// Replica names this copy of the app in heartbeats. Empty means the
	// host name plus a random suffix.
	Replica string `json:"replica" mapstructure:"replica" yaml:"replica"`
	// After names more extensions to start before witness, such as an app
	// extension that provides library engines ("loomplane-identity").
	// Forge orders extensions before it reads config, so only a value set
	// in code with WithConfig changes the order.
	After []string `json:"after" mapstructure:"after" yaml:"after"`
	// Adapters holds each adapter's own options, keyed by adapter name.
	Adapters map[string]map[string]any `json:"adapters" mapstructure:"adapters" yaml:"adapters"`
	// RequireConfig makes a missing witness section in the config file an
	// error.
	RequireConfig bool `json:"-" yaml:"-"`
}

// ScopeConfig is whose evidence adapters collect. See adapter.Scope.
type ScopeConfig struct {
	// AppID is the platform app.
	AppID string `json:"app_id" mapstructure:"app_id" yaml:"app_id"`
	// TenantID is the tenant staff events are recorded under.
	TenantID string `json:"tenant_id" mapstructure:"tenant_id" yaml:"tenant_id"`
	// StaffRoles are the role names that make a user staff. Empty means
	// adapter.DefaultStaffRoles.
	StaffRoles []string `json:"staff_roles" mapstructure:"staff_roles" yaml:"staff_roles"`
	// AllTenants widens collection to customer tenants. Off by default,
	// and Hallproof is told when it is on.
	AllTenants bool `json:"all_tenants" mapstructure:"all_tenants" yaml:"all_tenants"`
}

func (s ScopeConfig) scope() adapter.Scope {
	return adapter.Scope{
		AppID:      s.AppID,
		TenantID:   s.TenantID,
		StaffRoles: append([]string(nil), s.StaffRoles...),
		AllTenants: s.AllTenants,
	}
}

// Option configures an Extension.
type Option func(*Extension)

// WithConfig sets the config in code. Its non-zero fields win over the
// config file.
func WithConfig(c Config) Option {
	return func(e *Extension) { e.code = c }
}

// WithWitnessOptions changes the witness.Options the extension builds from
// its config, such as the HTTP client, the logger or client options. It
// runs after the config is applied, so what it sets wins. Call it more than
// once to add more changes.
func WithWitnessOptions(f func(*witness.Options)) Option {
	return func(e *Extension) {
		if f != nil {
			e.witnessOpts = append(e.witnessOpts, f)
		}
	}
}

// WithChain sets the chain witness records to and proves from. It wins
// over any chain a chain adapter offers.
func WithChain(c chain.Chain) Option {
	return func(e *Extension) { e.given = c }
}

// Extension is the witness Forge extension. Add it to your app with
// New, and blank-import the adapters for the libraries you run.
type Extension struct {
	*forge.BaseExtension

	code        Config
	witnessOpts []func(*witness.Options)
	given       chain.Chain
	chain       *lazyChain
	// coverageEvery is the coverage snapshot's interval. Zero means
	// collect.DefaultEvery.
	coverageEvery time.Duration

	mu   sync.Mutex
	cfg  Config
	w    *witness.Witness
	log  *slog.Logger
	stop sync.Once
}

var _ forge.Extension = (*Extension)(nil)

// New returns the extension.
func New(opts ...Option) *Extension {
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(Name, witness.Version, "Pushes compliance evidence to Hallproof"),
		chain:         &lazyChain{},
	}
	for _, o := range opts {
		o(e)
	}
	e.cfg = e.code
	return e
}

// Witness returns the extension's witness, or nil before Register or when
// witness is off. Use it from an app extension that depends on Name to add
// collectors or mount the middleware before the app has started; the
// container holds the witness only once the app has started.
func (e *Extension) Witness() *witness.Witness {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.w
}

// Dependencies names the extensions witness starts after: every registered
// adapter's After, plus Config.After. Forge skips names the app doesn't
// run.
func (e *Extension) Dependencies() []string {
	set := map[string]bool{}
	for _, a := range adapter.Adapters() {
		for _, n := range a.After {
			set[n] = true
		}
	}
	e.mu.Lock()
	for _, n := range e.cfg.After {
		set[n] = true
	}
	e.mu.Unlock()
	delete(set, Name)
	delete(set, "")
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Register loads the config and builds the witness. App extensions that
// register after witness can reach it with Witness to add their own
// collectors and mount its middleware. Once every extension has started,
// witness attaches the adapters, provides itself in the container as
// *witness.Witness and starts.
//
// With no endpoint, or Disabled, witness is off: Register logs that once and
// provides nothing. A bad endpoint or key fails Register.
func (e *Extension) Register(app forge.App) error {
	if err := e.BaseExtension.Register(app); err != nil {
		return err
	}
	var cfg Config
	if err := e.LoadConfig(Name, &cfg, e.code, Config{}, e.code.RequireConfig); err != nil {
		return fmt.Errorf("witness: config: %w", err)
	}

	o := witness.Options{
		Endpoint:       cfg.Endpoint,
		IngestKey:      cfg.IngestKey,
		Chain:          e.chain,
		Logger:         newForgeLogger(app.Logger()),
		HeartbeatEvery: cfg.HeartbeatEvery,
		Replica:        cfg.Replica,
	}
	for _, f := range e.witnessOpts {
		f(&o)
	}
	if o.Logger == nil {
		o.Logger = newForgeLogger(app.Logger())
	}
	e.mu.Lock()
	e.cfg, e.log = cfg, o.Logger
	e.mu.Unlock()

	switch {
	case cfg.Disabled:
		o.Logger.Info("witness: off, because it is disabled in config")
		return nil
	case o.Endpoint == "":
		o.Logger.Info("witness: off, because no endpoint is configured")
		return nil
	}

	if err := e.resolveKey(&o, cfg); err != nil {
		return err
	}
	if err := e.bindChain(&o); err != nil {
		return err
	}
	w, err := witness.New(o)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.w = w
	e.mu.Unlock()

	if err := forge.OnClose(app, "witness-stop", func(ctx context.Context, _ forge.App) error {
		e.stopWitness(ctx)
		return nil
	}); err != nil {
		return err
	}
	return forge.OnStarted(app, "witness-start", func(ctx context.Context, a forge.App) error {
		e.discoverAndStart(ctx, a.Container())
		return nil
	})
}

// resolveKey reads the ingest key from IngestKeyFile when that is how it is
// configured.
func (*Extension) resolveKey(o *witness.Options, cfg Config) error {
	if cfg.IngestKeyFile == "" {
		return nil
	}
	if cfg.IngestKey != "" {
		return errors.New("witness: set ingest_key or ingest_key_file, not both")
	}
	if o.IngestKey != "" {
		// WithWitnessOptions set the key in code; it wins.
		return nil
	}
	raw, err := os.ReadFile(cfg.IngestKeyFile)
	if err != nil {
		return fmt.Errorf("witness: read ingest_key_file: %w", err)
	}
	o.IngestKey = strings.TrimSpace(string(raw))
	return nil
}

// bindChain makes o's chain the lazy one, binding the chain given in code,
// by WithChain or as o.Chain, so it wins over discovery.
func (e *Extension) bindChain(o *witness.Options) error {
	given := e.given
	if o.Chain != nil && o.Chain != chain.Chain(e.chain) && given == nil {
		given = o.Chain
	}
	o.Chain = e.chain
	if given == nil {
		return nil
	}
	if err := e.chain.bind(given, "WithChain"); err != nil && !errors.Is(err, errNilChain) {
		return fmt.Errorf("witness: %w", err)
	}
	return nil
}

// Stop stops witness, if the OnClose hook didn't already.
func (e *Extension) Stop(ctx context.Context) error {
	e.stopWitness(ctx)
	return e.BaseExtension.Stop(ctx)
}

// stopWitness stops witness once, giving it stopTimeout to send what is
// queued. It never fails shutdown.
func (e *Extension) stopWitness(ctx context.Context) {
	e.stop.Do(func() {
		e.mu.Lock()
		w, log := e.w, e.log
		e.mu.Unlock()
		if w == nil {
			return
		}
		stopCtx, cancel := context.WithTimeout(ctx, stopTimeout)
		defer cancel()
		if err := w.Stop(stopCtx); err != nil {
			log.Warn("witness: stopped with evidence unsent", "error", err)
		}
	})
}
