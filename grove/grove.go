package grove

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	gv "github.com/xraph/grove"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "grove"

// Module is the library this adapter reads.
const Module = "github.com/xraph/grove"

// DefaultDatabase is the label of the database you pass to New, the one a
// Forge app provides without a name.
const DefaultDatabase = "default"

// Collector keys.
const (
	KeyMigrations = "grove.migrations"
	KeyStatus     = "grove.migration-status"
)

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.grove.
type Options struct {
	// Databases are the names of the named grove databases to read, besides
	// the default one. Empty reads the default database only.
	Databases []string `json:"databases"`
}

// Option changes how New builds an adapter.
type Option func(*Adapter)

// WithDatabase reads db as well, and labels its migrations with name. The
// name can't be empty, "default" (unless db is the default database, which
// is then read once), or hold a slash.
func WithDatabase(name string, db *gv.DB) Option {
	return func(a *Adapter) { a.add(strings.TrimSpace(name), db) }
}

// database is one grove database and its label in the evidence.
type database struct {
	label string
	db    *gv.DB
}

// Adapter collects grove migration evidence from one or more databases.
type Adapter struct {
	dbs []database
	err error
}

// New returns an adapter that reads db, labelled DefaultDatabase, and any
// databases you add with WithDatabase.
func New(db *gv.DB, opts ...Option) *Adapter {
	a := &Adapter{}
	if db != nil {
		a.dbs = append(a.dbs, database{label: DefaultDatabase, db: db})
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Adapter) add(label string, db *gv.DB) {
	if a.err != nil {
		return
	}
	if db == nil {
		a.err = fmt.Errorf("witness/grove: database %q is nil", label)
		return
	}
	if label == "" || strings.Contains(label, "/") {
		a.err = fmt.Errorf("witness/grove: database name %q must be non-empty and hold no slash", label)
		return
	}
	for _, d := range a.dbs {
		if d.db == db {
			// The same database under a second name: read it once.
			return
		}
		if d.label == label {
			a.err = fmt.Errorf("witness/grove: two databases are named %q", label)
			return
		}
	}
	a.dbs = append(a.dbs, database{label: label, db: db})
}

// Register adds the adapter's collectors to w.
// It adds them all or none: when one fails, the ones added before it
// are taken out again.
func (a *Adapter) Register(w *witness.Witness) error {
	pops, snaps, err := a.collectors()
	if err != nil {
		return err
	}
	var set adapter.Set
	set.Population(pops...)
	set.Snapshot(snaps...)
	return set.Register(w)
}

func (a *Adapter) collectors() ([]collect.Population, []collect.Snapshot, error) {
	if a.err != nil {
		return nil, nil, a.err
	}
	if len(a.dbs) == 0 {
		return nil, nil, errors.New("witness/grove: no database")
	}
	pops := []collect.Population{{
		Key:         KeyMigrations,
		Title:       "Applied database migrations",
		Description: "Every schema migration recorded as applied in each database, with its version, owning module and time applied.",
		Source:      "applied-migrations",
		Every:       time.Hour,
		Collect:     a.collectMigrations,
	}}
	snaps := []collect.Snapshot{{
		Key:         KeyStatus,
		Title:       "Database schema status",
		Description: "For each database, its driver, how many migrations are applied in total and per module, and the latest one applied.",
		Every:       time.Hour,
		Collect:     a.collectStatus,
	}}
	return pops, snaps, nil
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"grove"},
		Attach: attach,
	})
}

// attach finds the default grove database, and the named ones the config
// lists, and registers the collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	a, found, err := fromHost(h)
	if !found || err != nil {
		return found, err
	}
	return true, a.Register(h.Witness)
}

// fromHost builds the adapter on the app's grove databases: through grove's
// own extension when the app runs it, else from the container.
func fromHost(h adapter.Host) (*Adapter, bool, error) {
	if x, ok := h.Ext(extensionName); ok {
		return fromExtension(h, x)
	}
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*gv.DB](c) {
		return nil, false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return nil, true, err
	}
	a, err := fromContainer(c, o)
	if err != nil {
		return nil, true, err
	}
	return a, true, nil
}

// fromContainer builds an adapter on the unnamed *grove.DB in c and the
// named ones o lists.
func fromContainer(c vessel.Vessel, o Options) (*Adapter, error) {
	db, err := vessel.Inject[*gv.DB](c)
	if err != nil {
		return nil, fmt.Errorf("witness/grove: resolve the default database: %w", err)
	}
	opts := make([]Option, 0, len(o.Databases))
	for _, name := range o.Databases {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !vessel.HasTypeNamed[*gv.DB](c, name) {
			return nil, fmt.Errorf("witness/grove: database %q is in the config but grove provides no database by that name", name)
		}
		named, err := vessel.InjectNamed[*gv.DB](c, name)
		if err != nil {
			return nil, fmt.Errorf("witness/grove: resolve database %q: %w", name, err)
		}
		opts = append(opts, WithDatabase(name, named))
	}
	return New(db, opts...), nil
}

// extensionName is the name grove's own Forge extension registers under.
const extensionName = "grove"

// dbGetter is grove's Forge extension, read through its DB getter, so the
// adapter needn't import the extension package.
type dbGetter interface{ DB() *gv.DB }

// namedDBs is the part of grove/extension's DBManager the adapter uses.
type namedDBs interface {
	Get(name string) (*gv.DB, error)
}

// fromExtension builds the adapter on the databases grove's extension x
// runs. It never asks the container: the extension registers its databases
// there with constructors, and the container starts whatever a constructor
// builds the first time anyone asks for it.
func fromExtension(h adapter.Host, x any) (*Adapter, bool, error) {
	log := h.Logger
	if log == nil {
		log = slog.Default()
	}
	g, ok := x.(dbGetter)
	if !ok {
		log.Warn("witness: the grove extension has no DB getter, so grove is skipped", "type", fmt.Sprintf("%T", x))
		return nil, false, nil
	}
	db := g.DB()
	if db == nil {
		log.Warn("witness: the grove extension has no database yet, so grove is skipped")
		return nil, false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return nil, true, err
	}
	mgr := manager(x)
	opts := make([]Option, 0, len(o.Databases))
	for _, name := range o.Databases {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if mgr == nil {
			return nil, true, fmt.Errorf("witness/grove: database %q is in the config but grove runs a single database", name)
		}
		named, err := mgr.Get(name)
		if err != nil {
			return nil, true, fmt.Errorf("witness/grove: database %q is in the config but grove provides no database by that name: %w", name, err)
		}
		if named == nil {
			return nil, true, fmt.Errorf("witness/grove: database %q is in the config but grove provides no database by that name", name)
		}
		opts = append(opts, WithDatabase(name, named))
	}
	return New(db, opts...), true, nil
}

// manager returns the named databases of grove's extension x, through its
// Manager getter, or nil when it runs a single database. Manager returns
// grove/extension's own DBManager type, which an interface here can't name
// without importing that module and all of Forge with it, so it's called by
// reflection and its result asserted to namedDBs.
func manager(x any) namedDBs {
	m := reflect.ValueOf(x).MethodByName("Manager")
	if !m.IsValid() || m.Type().NumIn() != 0 || m.Type().NumOut() != 1 {
		return nil
	}
	out := m.Call(nil)[0]
	switch out.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		if out.IsNil() {
			return nil
		}
	default:
	}
	if g, ok := out.Interface().(namedDBs); ok {
		return g
	}
	return nil
}
