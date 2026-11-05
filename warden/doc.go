// Package warden sends Hallproof evidence of who can do what in your app,
// read from a Warden engine (github.com/xraph/warden).
//
// # Using it
//
// In a Forge app with witness/forge, a blank import is all you need:
//
//	import _ "github.com/hallproof/witness/warden"
//
// The adapter looks for a *warden.Engine in the container. Warden's own
// Forge extension provides one. If you build the engine yourself, provide
// it with forge.ProvideValue(c, eng), or, when you build the witness config
// in Go, put it under the "engine" key of the adapter's section
// (ConfigEngine). The adapter doesn't import Authsome, so an engine you
// only reach through (*authsome.Engine).Warden() has to be provided one of
// those two ways. Without an engine the adapter stays quiet and the rest of
// witness carries on.
//
// Without Forge, build it yourself and register it before you start the
// witness:
//
//	a := warden.New(eng, warden.WithTenants("app_platform"))
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # What it collects
//
// warden.roles is a population of every role in the staff tenants: slug,
// name, description, parent role, the permissions it grants directly
// (sorted names, with namespace/ in front of a permission outside the
// tenant root) and whether it's privileged. Every 15 minutes, for the
// privileged-reviewed and review-signed-off tests.
//
// warden.assignments is who holds which role: the subject, the role, the
// resource it's scoped to, who granted it, when, and when it expires.
// Expired rows Warden hasn't swept yet are still listed; expires_at tells
// you which. Every 15 minutes, for privileged-reviewed, review-signed-off
// and no-active-leavers (Hallproof matches subject_id to its people list).
//
// warden.policies lists every allow and deny policy: effect, priority,
// whether it's active, its time window, version, the subjects, actions,
// resources and obligations it matches, and each condition's field and
// operator. Condition values never leave your app, since they can hold IP
// ranges, emails or attribute values. A SHA-256 of the full conditions
// (conditions_hash) shows you when one changes. Every 15 minutes, with no
// test key yet.
//
// warden.model is a snapshot with one entry per staff tenant: a SHA-256 of
// Warden's own canonical .warden rendering of the tenant's resource types,
// permissions, roles and policies, plus how many of each. Relation tuples
// are left out of the hash because they are data, not model. Hourly. It
// is drift evidence and has no test key yet.
//
// warden.relations, off by default, lists every relationship tuple. Object
// IDs name your product's resources and the list can be huge, so you turn
// it on yourself. It counts first and fails the run when there are more
// than max_relations tuples. Hourly, for review-signed-off.
//
// warden.access-change-proof, off by default, proves warden.assignment.*,
// warden.role.permissions_set and warden.permission.attached/detached
// events on the platform stream of your chain. Nothing records those
// events yet (see the gaps below), so it proves nothing until Warden has
// an audit bridge.
//
// No collector sends metadata, created_by or updated_by, permission
// descriptions, or anything from a resource type besides counts.
//
// # Scope
//
// Warden knows tenants, not staff and customers, so scope is a list of
// tenants. In a Forge app the default is the witness scope's app ID, which
// is the tenant Authsome keeps its platform roles in. Authsome gives every
// user of the platform app the platform-user role, and in a product like
// Loomplane every customer is one of those users, so the adapter drops
// assignments of platform-user by default. It reads assignments one kept
// role at a time, so it never reads the customers' rows at all.
//
// Roles named in the scope's staff roles (platform-owner and
// platform-admin unless you say otherwise) are marked privileged.
//
// With no tenants and no app ID in the scope, the adapter registers
// nothing and logs why.
//
// # Options
//
// The keys of the adapter's section, extensions.witness.adapters.warden:
//
//   - tenants: the staff tenants. Empty means the scope's app ID.
//   - all_tenants: widen roles, assignments, policies and relations to
//     every tenant, customers included. The scope's all_tenants does the
//     same. warden.model still covers only the listed tenants, because
//     Warden has no way to list tenants.
//   - exclude_role_slugs: roles whose assignments are dropped. Unset means
//     platform-user in staff scope and nothing with all_tenants. An empty
//     list drops nothing.
//   - privileged: role slugs marked privileged. Empty means the scope's
//     staff roles.
//   - relations: turn on warden.relations.
//   - max_relations: the most tuples it will send. Zero means 50,000, the
//     most Hallproof takes in one population.
//   - event_proofs: turn on warden.access-change-proof.
//
// New takes the same settings through WithTenants, WithAllTenants and the
// other With options.
//
// # Paging
//
// Warden's SQL stores return at most 1000 rows when a list call leaves
// Limit at zero, and they don't say so. Every list here asks for pages of
// 1000 and keeps going until a short page, drops rows it has seen (offset
// paging can repeat a row that shares a created_at), and fails the run
// once a list passes 50,000 rows. A failed run shows up in Hallproof as an
// unhealthy collector, which beats a list that quietly stops.
//
// # Gaps in Warden
//
// Warden has no audit bridge to Chronicle. Its events only reach a log
// line through plugin/auditlog, and they fire from the HTTP API handlers,
// not the engine or the store. Authsome and Loomplane write roles and
// assignments straight to the store, so nothing is emitted. A small
// plugin/audithook (a Recorder interface and a plugin that maps
// plugin.Event to it) plus an opt-in store decorator that emits on every
// write would let warden.access-change-proof prove something.
//
// The 1000-row cap on a zero Limit is silent, which also truncates callers
// such as Authsome's ListUsersWithRole once a role has more than 1000
// holders.
//
// No list filter takes an app ID; the tenant is the only scope key, and
// there is no call that lists tenants.
//
// Nothing records which .warden file was applied. warden.model hashes what
// is in force, which is better evidence anyway. dsl.BuildProgram also
// reads every relation tuple, which the adapter then throws away; a
// SkipRelations export option would make the snapshot cheap on a tenant
// with many tuples. BuildProgram gives up past 200,000 rows of any kind.
//
// Warden's root module lists the testcontainers modules as direct
// requirements, so every app that adds Warden carries Docker client
// packages in its go.sum.
package warden
