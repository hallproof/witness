// Package grove sends evidence about your database schema migrations to
// Hallproof, read from github.com/xraph/grove.
//
// # Collectors
//
// grove.migrations is a population of every migration recorded as applied
// in each database you read. Each item has an id ("<database>/<group>/
// <version>"), the database label, the group (the module that owns the
// migration, such as "core" or "authsome"), the version, the migration's
// name, the time it was applied (RFC 3339, UTC, to the second) and seq, the
// row number in grove's migration table, which shows the order they ran
// in. It runs hourly, since it only changes when you deploy. No Hallproof
// test uses it yet.
//
// grove.migration-status is a snapshot with one entry per database: its
// driver ("pg", "sqlite", ...), how many migrations are applied, how many
// per group, and the latest one applied. It also runs hourly. It carries
// "pending_reported": false, because it can't tell you about pending
// migrations (see the gaps below).
//
// Both read grove's migration table through the driver's own executor:
// migrate.NewExecutorFor(db.Driver()) and then ListApplied, which is a
// plain SELECT. The adapter never creates the table, never takes the
// migration lock and never writes. A database nothing has migrated yet has
// no table, so its run fails and the heartbeat says so.
//
// Each driver gives the applied time as its own text. The adapter reads the
// Postgres, SQLite, Turso, MySQL, ClickHouse and Mongo forms and sends RFC
// 3339 in UTC. A time with no zone (SQLite, Turso, MySQL, ClickHouse) is
// taken as UTC. A time it can't read fails the run; it doesn't guess.
//
// The adapter never sends the SQL a migration runs or anything it writes
// (it doesn't see either), the developer comment on a migration, the DSN and
// driver config, the migration lock's holder (host and process ID), and
// anything from grove/audit, which records raw SQL and row data. This
// adapter doesn't read or wire grove/audit at all.
//
// Grove has no migration events, so there's no event proof and no
// event_proofs option.
//
// # Scope
//
// Migrations belong to the platform, not to a tenant, so the staff-only
// default has no rows to filter. What scope decides here is which
// databases you read. By default that's the default database only, the
// unnamed one. If you register a database per customer with grove, the
// adapter doesn't read them, since their names would show up as database
// labels. You add named databases one by one in Databases; all_tenants
// doesn't widen anything here.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.grove:
//
//	databases: [analytics]   # named grove databases to read as well
//
// A name that grove doesn't provide fails Attach with an error naming it.
// The default database listed again under its own name is read once.
//
// # With Forge
//
// Add the grove extension and the witness extension, blank import this
// package, and keep the blank import of your driver's migrate package
// (github.com/xraph/grove/drivers/pgdriver/pgmigrate for Postgres), which
// you already have if grove runs your migrations:
//
//	import (
//		_ "github.com/hallproof/witness/grove"
//		_ "github.com/xraph/grove/drivers/pgdriver/pgmigrate"
//	)
//
// Attach reads the databases through the grove extension (named "grove"):
// the default one from its DB getter, and each named one in databases from
// its Manager. It doesn't ask the container for them when that extension
// runs, because the extension registers them there with constructors, and
// the container starts whatever a constructor builds the first time anyone
// asks for it. If the extension is there but has no database yet, the
// adapter logs it and does nothing.
//
// Only when your app doesn't run the grove extension does Attach look in the
// container, for the unnamed *grove.DB and each named one. If you open the
// databases yourself, provide the finished values there
// (vessel.ProvideValue or forge.ProvideValue), not constructors. Without a
// *grove.DB the adapter does nothing.
//
// Run it in a process that imports your driver's migrate package, such as
// your API server. Replicas send the same evidence, and Hallproof drops the
// duplicates.
//
// # Without Forge
//
// Build it yourself and register it:
//
//	a := grove.New(db, grove.WithDatabase("analytics", analyticsDB))
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// Register fails when there's no database, two databases share a label, or
// a label is empty or holds a slash.
//
// # Library gaps
//
// Pending migrations aren't reported. Only the code knows which migrations
// are registered, and grove's way to compare them with the table is
// Orchestrator.Status, or forge.CentralMigrator.StatusAll on top of it.
// That interface lives in Forge, which this adapter doesn't import to stay
// light, and Status calls EnsureMigrationTable first, which on Postgres takes
// an advisory lock and runs CREATE TABLE IF NOT EXISTS on every call. A
// read-only status call in grove's migrate package (one that treats a
// missing table as nothing applied) would let the snapshot report pending
// migrations and their comments.
//
// Grove deletes the row when you roll a migration back, so there's no
// rollback history. Hallproof sees a rollback only as an item that
// disappears from the population.
//
// The table has no actor, checksum or duration. Evidence says which
// version was applied and when, not who ran it or whether what ran matches
// reviewed code. Pair it with your repository's branch protection and CI
// evidence.
//
// Named databases are read by the names you list. Listing them all needs
// grove/extension's DBManager, and that module brings all of Forge with it.
package grove
