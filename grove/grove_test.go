package grove

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gv "github.com/xraph/grove"
	"github.com/xraph/grove/driver"
	"github.com/xraph/grove/drivers/sqlitedriver"
	"github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate"
	"github.com/xraph/grove/migrate"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

// openSQLite opens a grove database on a SQLite file named file in a
// temporary directory.
func openSQLite(t *testing.T, file string) *gv.DB {
	t.Helper()
	drv := sqlitedriver.New()
	if err := drv.Open(context.Background(), filepath.Join(t.TempDir(), file)); err != nil {
		t.Fatal(err)
	}
	db, err := gv.Open(drv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func sqliteExec(t *testing.T, db *gv.DB) migrate.Executor {
	t.Helper()
	drv, ok := db.Driver().(driver.Driver)
	if !ok {
		t.Fatalf("driver %T is not a driver.Driver", db.Driver())
	}
	return sqlitemigrate.New(drv)
}

// noop is a migration step that runs no SQL.
func noop(context.Context, migrate.Executor) error { return nil }

// migrateUp applies groups to db, then sets each applied row's time to the
// matching entry of at, in apply order, so tests don't depend on the clock.
func migrateUp(t *testing.T, db *gv.DB, at []string, groups ...*migrate.Group) {
	t.Helper()
	ctx := context.Background()
	ex := sqliteExec(t, db)
	if _, err := migrate.NewOrchestrator(ex, groups...).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	applied, err := ex.ListApplied(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != len(at) {
		t.Fatalf("applied %d migrations, have %d times", len(applied), len(at))
	}
	for i, a := range applied {
		if _, err := ex.Exec(ctx, `UPDATE grove_migrations SET migrated_at = ? WHERE id = ?`, at[i], a.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func group(t *testing.T, name string, ms ...*migrate.Migration) *migrate.Group {
	t.Helper()
	g := migrate.NewGroup(name)
	if err := g.Register(ms...); err != nil {
		t.Fatal(err)
	}
	return g
}

// standard applies two groups, three migrations, to db.
func standard(t *testing.T, db *gv.DB) {
	t.Helper()
	migrateUp(t, db,
		[]string{"2026-11-01 09:00:00", "2026-11-01 09:00:01", "2026-11-02 14:30:00"},
		group(t, "core",
			&migrate.Migration{Name: "create_users", Version: "20260101000000", Up: noop, Down: noop},
			&migrate.Migration{Name: "add_email_index", Version: "20260102000000", Up: noop, Down: noop},
		),
		group(t, "billing",
			&migrate.Migration{Name: "create_invoices", Version: "20260201000000", Up: noop, Down: noop},
		),
	)
}

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// taken reports whether a population key is already registered on w.
func taken(t *testing.T, w *witness.Witness, key string) bool {
	t.Helper()
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

func snapTaken(t *testing.T, w *witness.Witness, key string) bool {
	t.Helper()
	err := w.Snapshot(collect.Snapshot{Key: key, Title: "probe", Collect: func(context.Context) (map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

type collected struct {
	pops  map[string]collect.Population
	snaps map[string]collect.Snapshot
}

func collectorsOf(t *testing.T, a *Adapter) collected {
	t.Helper()
	pops, snaps, err := a.collectors()
	if err != nil {
		t.Fatal(err)
	}
	c := collected{pops: map[string]collect.Population{}, snaps: map[string]collect.Snapshot{}}
	for _, p := range pops {
		c.pops[p.Key] = p
	}
	for _, s := range snaps {
		c.snaps[s.Key] = s
	}
	return c
}

func items(t *testing.T, a *Adapter) []map[string]any {
	t.Helper()
	got, err := collectorsOf(t, a).pops[KeyMigrations].Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func settings(t *testing.T, a *Adapter) map[string]any {
	t.Helper()
	got, err := collectorsOf(t, a).snaps[KeyStatus].Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// roundTrip returns v as it reads after a JSON round trip, which is what
// Hallproof receives.
func roundTrip(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func ids(got []map[string]any) []string {
	out := make([]string, 0, len(got))
	for _, it := range got {
		id, _ := it["id"].(string)
		out = append(out, id)
	}
	return out
}

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"grove"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("grove adapter is not registered")
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"nil": nil, "empty vessel": vessel.New(), "not a vessel": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c})
			if found || err != nil {
				t.Fatalf("attach = %v, %v; want false, nil", found, err)
			}
		})
	}
}

// provide puts db in c the way the grove extension does: unnamed when name
// is empty, named otherwise.
func provide(t *testing.T, c vessel.Vessel, name string, db *gv.DB) {
	t.Helper()
	var err error
	if name == "" {
		err = vessel.Provide(c, func() (*gv.DB, error) { return db, nil })
	} else {
		err = vessel.ProvideNamed(c, name, func() *gv.DB { return db })
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestAttachRegisters(t *testing.T) {
	db := openSQLite(t, "app.db")
	standard(t, db)
	c := vessel.New()
	provide(t, c, "", db)
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	if !taken(t, w, KeyMigrations) || !snapTaken(t, w, KeyStatus) {
		t.Fatal("attach did not register both collectors")
	}
}

func TestAttachFailsOnMissingNamedDatabase(t *testing.T) {
	c := vessel.New()
	provide(t, c, "", openSQLite(t, "app.db"))
	found, err := attach(context.Background(), adapter.Host{
		Witness: newWitness(t), Container: c,
		Config: map[string]any{"databases": []any{"analytics"}},
	})
	if !found || err == nil || !strings.Contains(err.Error(), `"analytics"`) {
		t.Fatalf("attach = %v, %v; want true and an error naming the database", found, err)
	}
}

func TestRegisterNeedsADatabase(t *testing.T) {
	if err := New(nil).Register(newWitness(t)); err == nil {
		t.Fatal("Register with no database succeeded")
	}
}

func TestMigrations(t *testing.T) {
	db := openSQLite(t, "app.db")
	standard(t, db)
	got := roundTrip(t, items(t, New(db)))
	want := roundTrip(t, []map[string]any{
		{"id": "default/core/20260101000000", "database": "default", "group": "core", "version": "20260101000000", "name": "create_users", "applied_at": "2026-11-01T09:00:00Z", "seq": 1},
		{"id": "default/core/20260102000000", "database": "default", "group": "core", "version": "20260102000000", "name": "add_email_index", "applied_at": "2026-11-01T09:00:01Z", "seq": 2},
		{"id": "default/billing/20260201000000", "database": "default", "group": "billing", "version": "20260201000000", "name": "create_invoices", "applied_at": "2026-11-02T14:30:00Z", "seq": 3},
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("items =\n%v\nwant\n%v", got, want)
	}
	p := collectorsOf(t, New(db)).pops[KeyMigrations]
	if p.Source != "applied-migrations" || p.Title == "" || p.Every.Hours() != 1 {
		t.Fatalf("population = %+v", p)
	}
}

func TestMigrationsWithNoTable(t *testing.T) {
	// A database nothing has migrated has no grove_migrations table. The
	// adapter reads; it never creates the table, so the run fails.
	db := openSQLite(t, "empty.db")
	_, err := collectorsOf(t, New(db)).pops[KeyMigrations].Collect(context.Background())
	if err == nil {
		t.Fatal("collect on a database with no migration table succeeded")
	}
}

func TestMigrationStatus(t *testing.T) {
	db := openSQLite(t, "app.db")
	standard(t, db)
	got := roundTrip(t, settings(t, New(db)))
	want := roundTrip(t, map[string]any{
		"databases": map[string]any{
			"default": map[string]any{
				"driver":  "sqlite",
				"applied": 3,
				"groups":  map[string]any{"core": 2, "billing": 1},
				"latest_applied": map[string]any{
					"group": "billing", "version": "20260201000000", "name": "create_invoices", "applied_at": "2026-11-02T14:30:00Z",
				},
			},
		},
		"pending_reported": false,
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settings =\n%v\nwant\n%v", got, want)
	}
}

func TestMigrationStatusEmptyTable(t *testing.T) {
	db := openSQLite(t, "app.db")
	if err := sqliteExec(t, db).EnsureMigrationTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := roundTrip(t, settings(t, New(db)))
	want := roundTrip(t, map[string]any{
		"databases":        map[string]any{"default": map[string]any{"driver": "sqlite", "applied": 0, "groups": map[string]any{}}},
		"pending_reported": false,
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settings = %v, want %v", got, want)
	}
}

func TestAppliedAt(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2026-11-03 10:00:00.123+00", "2026-11-03T10:00:00Z"},              // Postgres ::text, UTC session
		{"2026-11-03 10:00:00+00", "2026-11-03T10:00:00Z"},                  // Postgres, no fraction
		{"2026-11-03 12:30:00.5+02:30", "2026-11-03T10:00:00Z"},             // Postgres, other zone
		{"2026-11-03 05:00:00-05", "2026-11-03T10:00:00Z"},                  // Postgres, negative hours
		{"2026-11-03 10:53:28+00:53:28", "2026-11-03T10:00:00Z"},            // Postgres, offset in seconds
		{"2026-11-03 10:00:00", "2026-11-03T10:00:00Z"},                     // SQLite and Turso DATETIME('now')
		{"2026-11-03 10:00:00.123456", "2026-11-03T10:00:00Z"},              // MySQL DATETIME(6) as CHAR
		{"2026-11-03T10:00:00Z", "2026-11-03T10:00:00Z"},                    // Mongo RFC 3339
		{"2026-11-03T11:00:00+01:00", "2026-11-03T10:00:00Z"},               // RFC 3339 with zone
		{"2026-11-03T10:00:00.999999999Z", "2026-11-03T10:00:00Z"},          // RFC 3339 nano
		{"2026-11-03 10:00:00 +0000 UTC", "2026-11-03T10:00:00Z"},           // time.Time.String
		{"  2026-11-03 10:00:00  ", "2026-11-03T10:00:00Z"},                 // padding
		{"2026-11-03 10:00:00.123 +0000 UTC", "2026-11-03T10:00:00Z"},       // time.Time.String with fraction
		{"2026-11-03 10:00:00.123456789 +0000 UTC", "2026-11-03T10:00:00Z"}, // ClickHouse via a time value
	} {
		got, err := appliedAt(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("appliedAt(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "yesterday", "2026-13-40 10:00:00", "infinity"} {
		if got, err := appliedAt(bad); err == nil {
			t.Errorf("appliedAt(%q) = %q, want an error", bad, got)
		}
	}
}

// fakeDriver is a grove driver with no database behind it. Its name picks
// the fake executor.
type fakeDriver struct{ name string }

func (d fakeDriver) Name() string             { return d.name }
func (fakeDriver) Close() error               { return nil }
func (fakeDriver) Ping(context.Context) error { return nil }

// fakeExec is a migration executor that serves rows from memory and records
// every method called on it.
type fakeExec struct {
	mu    sync.Mutex
	rows  []*migrate.AppliedMigration
	err   error
	calls []string
}

func (f *fakeExec) call(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeExec) Exec(context.Context, string, ...any) (driver.Result, error) {
	f.call("Exec")
	return nil, errors.New("fake: Exec")
}

func (f *fakeExec) Query(context.Context, string, ...any) (driver.Rows, error) {
	f.call("Query")
	return nil, errors.New("fake: Query")
}

func (f *fakeExec) EnsureMigrationTable(context.Context) error {
	f.call("EnsureMigrationTable")
	return nil
}

func (f *fakeExec) EnsureLockTable(context.Context) error {
	f.call("EnsureLockTable")
	return nil
}

func (f *fakeExec) AcquireLock(context.Context, string) error {
	f.call("AcquireLock")
	return nil
}

func (f *fakeExec) ReleaseLock(context.Context) error {
	f.call("ReleaseLock")
	return nil
}

func (f *fakeExec) ListApplied(context.Context) ([]*migrate.AppliedMigration, error) {
	f.call("ListApplied")
	if f.err != nil {
		return nil, f.err
	}
	out := make([]*migrate.AppliedMigration, len(f.rows))
	for i, r := range f.rows {
		c := *r
		out[i] = &c
	}
	return out, nil
}

func (f *fakeExec) RecordApplied(context.Context, *migrate.Migration) error {
	f.call("RecordApplied")
	return nil
}

func (f *fakeExec) RemoveApplied(context.Context, *migrate.Migration) error {
	f.call("RemoveApplied")
	return nil
}

var (
	fakesMu sync.Mutex
	fakes   = map[string]*fakeExec{}
)

// fakeDB returns a grove database whose migration executor is ex, under a
// driver name unique to the test.
func fakeDB(t *testing.T, ex *fakeExec) *gv.DB {
	t.Helper()
	name := "witness-fake-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	fakesMu.Lock()
	fakes[name] = ex
	fakesMu.Unlock()
	migrate.RegisterExecutor(name, func(drv any) migrate.Executor {
		fakesMu.Lock()
		defer fakesMu.Unlock()
		return fakes[drv.(fakeDriver).name]
	})
	db, err := gv.Open(fakeDriver{name: name})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestPostgresTimesAndReadOnly(t *testing.T) {
	ex := &fakeExec{rows: []*migrate.AppliedMigration{
		{ID: 7, Version: "20260101000000", Name: "create_users", Group: "core", MigratedAt: "2026-11-03 10:00:00.123+00"},
		{ID: 9, Version: "20260301000000", Name: "create_keys", Group: "keysmith", MigratedAt: "2026-11-04 01:15:00+01"},
	}}
	a := New(fakeDB(t, ex))
	got := roundTrip(t, items(t, a))
	want := roundTrip(t, []map[string]any{
		{"id": "default/core/20260101000000", "database": "default", "group": "core", "version": "20260101000000", "name": "create_users", "applied_at": "2026-11-03T10:00:00Z", "seq": 7},
		{"id": "default/keysmith/20260301000000", "database": "default", "group": "keysmith", "version": "20260301000000", "name": "create_keys", "applied_at": "2026-11-04T00:15:00Z", "seq": 9},
	})
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("items =\n%v\nwant\n%v", got, want)
	}
	_ = settings(t, a)
	ex.mu.Lock()
	defer ex.mu.Unlock()
	for _, c := range ex.calls {
		if c != "ListApplied" {
			t.Fatalf("the adapter called %s; it may only read with ListApplied (calls: %v)", c, ex.calls)
		}
	}
	if len(ex.calls) != 2 {
		t.Fatalf("calls = %v, want ListApplied twice", ex.calls)
	}
}

func TestBadTimeFailsTheRun(t *testing.T) {
	ex := &fakeExec{rows: []*migrate.AppliedMigration{{ID: 1, Version: "1", Name: "n", Group: "g", MigratedAt: "last tuesday"}}}
	c := collectorsOf(t, New(fakeDB(t, ex)))
	if _, err := c.pops[KeyMigrations].Collect(context.Background()); err == nil {
		t.Fatal("population with an unreadable time succeeded")
	}
	if _, err := c.snaps[KeyStatus].Collect(context.Background()); err == nil {
		t.Fatal("snapshot with an unreadable time succeeded")
	}
}

func TestReadErrorFailsTheRun(t *testing.T) {
	ex := &fakeExec{err: errors.New("connection refused")}
	_, err := collectorsOf(t, New(fakeDB(t, ex))).pops[KeyMigrations].Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), `"default"`) {
		t.Fatalf("err = %v, want one naming the database", err)
	}
}

func TestNoExecutorFailsTheRun(t *testing.T) {
	db, err := gv.Open(fakeDriver{name: "witness-unregistered"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = collectorsOf(t, New(db)).pops[KeyMigrations].Collect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "witness-unregistered") {
		t.Fatalf("err = %v, want one naming the driver", err)
	}
}

func TestNamedDatabases(t *testing.T) {
	main := openSQLite(t, "main.db")
	standard(t, main)
	audit := openSQLite(t, "audit.db")
	migrateUp(t, audit, []string{"2026-10-01 08:00:00"},
		group(t, "chronicle", &migrate.Migration{Name: "create_events", Version: "20261001000000", Up: noop, Down: noop}))

	// Naming the default database again doesn't collect it twice.
	a := New(main, WithDatabase("audit", audit), WithDatabase("primary", main))
	got := ids(items(t, a))
	want := []string{
		"default/core/20260101000000", "default/core/20260102000000", "default/billing/20260201000000",
		"audit/chronicle/20261001000000",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	dbs, _ := roundTrip(t, settings(t, a)).(map[string]any)["databases"].(map[string]any)
	if len(dbs) != 2 || dbs["audit"] == nil || dbs["default"] == nil {
		t.Fatalf("databases = %v", dbs)
	}

	// A distinct database can't take the default database's label.
	if err := New(main, WithDatabase(DefaultDatabase, audit)).Register(newWitness(t)); err == nil {
		t.Fatal("a second database named default registered")
	}
	if err := New(main, WithDatabase("bad/name", audit)).Register(newWitness(t)); err == nil {
		t.Fatal("a database name with a slash registered")
	}
}

func TestStaffScope(t *testing.T) {
	// Migrations belong to the platform, not to a tenant, so the scope is a
	// question of which databases. An app that keeps a database per
	// customer and registers them with grove gets none of them by default.
	main := openSQLite(t, "main.db")
	standard(t, main)
	customer := openSQLite(t, "customer.db")
	migrateUp(t, customer, []string{"2026-10-01 08:00:00"},
		group(t, "core", &migrate.Migration{Name: "create_users", Version: "20260101000000", Up: noop, Down: noop}))

	c := vessel.New()
	provide(t, c, "", main)
	provide(t, c, "customer-acme", customer)

	run := func(cfg map[string]any) []string {
		t.Helper()
		var o Options
		if err := adapter.Decode(cfg, &o); err != nil {
			t.Fatal(err)
		}
		a, err := fromContainer(c, o)
		if err != nil {
			t.Fatal(err)
		}
		return ids(items(t, a))
	}

	for _, id := range run(nil) {
		if strings.HasPrefix(id, "customer-acme/") {
			t.Fatalf("customer database collected by default: %s", id)
		}
	}
	// all_tenants is not a database list: it widens nothing here.
	for _, id := range run(map[string]any{"all_tenants": true}) {
		if strings.HasPrefix(id, "customer-acme/") {
			t.Fatalf("customer database collected with all_tenants: %s", id)
		}
	}
	got := run(map[string]any{"databases": []any{"customer-acme"}})
	if !slices.Contains(got, "customer-acme/core/20260101000000") {
		t.Fatalf("named database not collected when listed: %v", got)
	}
}

func TestNeverSendsContent(t *testing.T) {
	// The canary goes in the SQL each migration runs (table and column
	// names, the down step), the row data it writes, the developer comment,
	// the database file path (the DSN) and the migration lock holder.
	const canary = "canary7f3e"
	ctx := context.Background()
	db := openSQLite(t, canary+"-dsn.db")

	up := func(ctx context.Context, ex migrate.Executor) error {
		if _, e := ex.Exec(ctx, `CREATE TABLE `+canary+`_table (`+canary+`_col TEXT)`); e != nil {
			return e
		}
		_, e := ex.Exec(ctx, `INSERT INTO `+canary+`_table VALUES (?)`, canary+"-row-data")
		return e
	}
	down := func(ctx context.Context, ex migrate.Executor) error {
		_, e := ex.Exec(ctx, `DROP TABLE `+canary+`_table`)
		return e
	}
	migrateUp(t, db, []string{"2026-11-01 09:00:00"},
		group(t, "core", &migrate.Migration{Name: "create_things", Version: "20260101000000", Up: up, Down: down, Comment: canary + "-comment"}))

	ex := sqliteExec(t, db)
	if err := ex.EnsureLockTable(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ex.AcquireLock(ctx, canary+"-host:4242"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ex.ReleaseLock(ctx) })

	c := collectorsOf(t, New(db))
	out := make([]any, 0, len(c.pops)+len(c.snaps))
	for _, p := range c.pops {
		got, err := p.Collect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p.Title, p.Description, got)
	}
	for _, s := range c.snaps {
		got, err := s.Collect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s.Title, s.Description, got)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{canary, "4242", "CREATE", "INSERT", "DROP"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
	if !strings.Contains(string(raw), "create_things") {
		t.Fatalf("migration name missing: %s", raw)
	}
}

// groveExt stands in for grove's Forge extension: DB is the default
// database, and Manager the named ones (nil in single-database mode).
type groveExt struct {
	db  *gv.DB
	mgr *dbManager
}

func (x groveExt) DB() *gv.DB          { return x.db }
func (x groveExt) Manager() *dbManager { return x.mgr }

// dbManager stands in for grove/extension's DBManager.
type dbManager struct{ dbs map[string]*gv.DB }

func (m *dbManager) Get(name string) (*gv.DB, error) {
	if db, ok := m.dbs[name]; ok {
		return db, nil
	}
	return nil, errors.New("no such database")
}

func extensions(byName map[string]any) func(string) (any, bool) {
	return func(name string) (any, bool) {
		x, ok := byName[name]
		return x, ok
	}
}

// countingContainer registers db and audit the way grove's extension does,
// with constructors, and counts how often the container calls them.
func countingContainer(t *testing.T, db, audit *gv.DB) (vessel.Vessel, *atomic.Int32) {
	t.Helper()
	var built atomic.Int32
	c := vessel.New()
	if err := vessel.Provide(c, func() (*gv.DB, error) {
		built.Add(1)
		return db, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := vessel.ProvideNamed(c, "audit", func() *gv.DB {
		built.Add(1)
		return audit
	}); err != nil {
		t.Fatal(err)
	}
	return c, &built
}

// The grove extension registers its databases with constructors, and the
// container starts what a constructor builds the first time anyone asks.
// Attach reads them through the extension's getters instead.
func TestAttachUsesTheExtensionNotTheContainer(t *testing.T) {
	main := openSQLite(t, "main.db")
	standard(t, main)
	audit := openSQLite(t, "audit.db")
	migrateUp(t, audit, []string{"2026-10-01 08:00:00"},
		group(t, "chronicle", &migrate.Migration{Name: "create_events", Version: "20261001000000", Up: noop, Down: noop}))
	c, built := countingContainer(t, main, audit)
	h := adapter.Host{
		Witness: newWitness(t), Container: c,
		Config:    map[string]any{"databases": []any{"audit"}},
		Extension: extensions(map[string]any{"grove": groveExt{db: main, mgr: &dbManager{dbs: map[string]*gv.DB{"audit": audit}}}}),
	}
	found, err := attach(context.Background(), h)
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	if !taken(t, h.Witness, KeyMigrations) || !snapTaken(t, h.Witness, KeyStatus) {
		t.Fatal("attach did not register both collectors")
	}
	a, found, err := fromHost(h)
	if !found || err != nil {
		t.Fatalf("fromHost = %v, %v", found, err)
	}
	got := ids(items(t, a))
	want := []string{
		"default/core/20260101000000", "default/core/20260102000000", "default/billing/20260201000000",
		"audit/chronicle/20261001000000",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	if n := built.Load(); n != 0 {
		t.Fatalf("the container built a database %d times; attach must read them through the extension", n)
	}
}

// A named database the extension doesn't run fails Attach, naming it, the
// same as the container path. In single-database mode the extension has no
// manager.
func TestAttachExtensionMissingNamedDatabase(t *testing.T) {
	main := openSQLite(t, "main.db")
	c, built := countingContainer(t, main, main)
	for name, mgr := range map[string]*dbManager{"single": nil, "multi": {dbs: map[string]*gv.DB{}}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{
				Witness: newWitness(t), Container: c,
				Config:    map[string]any{"databases": []any{"analytics"}},
				Extension: extensions(map[string]any{"grove": groveExt{db: main, mgr: mgr}}),
			})
			if !found || err == nil || !strings.Contains(err.Error(), `"analytics"`) {
				t.Fatalf("attach = %v, %v; want true and an error naming the database", found, err)
			}
			if n := built.Load(); n != 0 {
				t.Fatalf("the container built a database %d times", n)
			}
		})
	}
}

// An extension with no database yet means grove isn't ready: attach
// reports it absent and doesn't fall back to the container.
func TestAttachExtensionWithoutDatabase(t *testing.T) {
	main := openSQLite(t, "main.db")
	c, built := countingContainer(t, main, main)
	for name, x := range map[string]any{"nil db": groveExt{}, "other getter": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			w := newWitness(t)
			found, err := attach(context.Background(), adapter.Host{
				Witness: w, Container: c, Logger: slog.New(slog.DiscardHandler),
				Extension: extensions(map[string]any{"grove": x}),
			})
			if found || err != nil {
				t.Fatalf("attach = %v, %v; want false, nil", found, err)
			}
			if n := built.Load(); n != 0 {
				t.Fatalf("the container built a database %d times", n)
			}
			if taken(t, w, KeyMigrations) {
				t.Fatal("collectors were registered")
			}
		})
	}
}

func TestAttachFailingPartWayRegistersNothing(t *testing.T) {
	db := openSQLite(t, "app.db")
	standard(t, db)
	c := vessel.New()
	provide(t, c, "", db)
	w := newWitness(t)
	// The status snapshot is the last collector grove adds; its key is taken.
	if err := w.Population(collect.Population{Key: KeyStatus, Title: "squatter", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }}); err != nil {
		t.Fatal(err)
	}
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c})
	if !found || err == nil {
		t.Fatalf("attach = %v, %v; want true and the duplicate key's error", found, err)
	}
	if w.Remove(KeyMigrations) {
		t.Errorf("%s stayed registered after attach failed", KeyMigrations)
	}
	if !w.Remove(KeyStatus) {
		t.Error("attach removed a collector it didn't add")
	}
}

// The migrations population is evidence for Hallproof's migrations-recorded
// test; the status snapshot supports no test of its own.
func TestTestKeys(t *testing.T) {
	db := openSQLite(t, "keys.db")
	standard(t, db)
	c := collectorsOf(t, New(db))
	if got := c.pops[KeyMigrations].Tests; !reflect.DeepEqual(got, []string{"migrations-recorded"}) {
		t.Errorf("%s Tests = %v, want [migrations-recorded]", KeyMigrations, got)
	}
	if got := c.snaps[KeyStatus].Tests; len(got) != 0 {
		t.Errorf("%s Tests = %v, want none", KeyStatus, got)
	}
}
