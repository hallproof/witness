// Package shield sends evidence about your AI safety setup to Hallproof,
// read from a github.com/xraph/shield engine.
//
// # Using it
//
// With Forge, import the package for its side effect and name the tenants
// to read. The witness extension finds *engine.Engine in the container,
// which shield's own Forge extension puts there:
//
//	import _ "github.com/hallproof/witness/shield"
//
// and in extensions.witness.adapters.shield:
//
//	app_id: loomplane         # the shield app ID, not your identity app
//	tenants: [org_...]        # your own company's organization
//
// Without Forge, build the adapter and register it before you start
// witness:
//
//	a := shield.New(eng,
//		shield.WithAppID("loomplane"),
//		shield.WithTenants("org_..."),
//	)
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # Collectors
//
// shield.engine is a snapshot of how the engine runs: the default profile,
// whether a block stops the later layers, the largest scan it takes, how
// long a compiled profile is cached (-1 when the cache is off), whether
// redacted text is stored with each scan, whether the model judge is on and
// its timeout, and what the engine supports (persistence, tool calls, the
// layers that can't run, and the names of its strategies, detectors,
// assessors, triggers and lexicons). It runs hourly and is on by default.
// store_redacted is worth an auditor's eye: true means redacted scan text is
// kept in the database.
//
// shield.profiles is a population of every safety profile in the tenants
// you name: its name, app, tenant, whether it's on, and the names of the
// instincts (with any sensitivity override), judgments (with any threshold
// override), awareness detectors, values, reflexes and boundaries it's built
// from. Hourly.
//
// shield.checks is a population of every primitive those profiles can use,
// one item per row, with an ID of "<kind>:<shield ID>". You get each
// instinct's category, sensitivity, action and strategy names; each
// awareness detector's focus, action and detector names (an empty list
// means every built-in detector for that focus); each judgment's domain,
// threshold, action and assessors (name, domain, weight); each values row's
// severity, action and rules (principle, threshold, categories); each
// reflex's priority, triggers (type, threshold, window), actions (type and
// a SHA-256 of the target) and whether any action escalates to a person;
// and each boundary's limits (scope, allowlist mode, and how many entries
// it denies and allows). It supports the high-risk-approved test. A reflex
// trigger of type on_context whose pattern is exactly
// risk_class=<lowercase word>, the form shield's InfraAgent preset uses,
// sends that risk class, so you can see which risk classes are set to need
// a person's approval. Cortex's checkpoint events show the approvals
// happened. Hourly.
//
// shield.policies is a population of the org-level policies of each tenant
// you name, plus the app-wide policies of your app when you set AppID. App
// policies apply to every tenant, so they're company configuration. Each
// rule goes as its check type, action, priority and a SHA-256 of its
// condition. The condition is a small expression language a host can write
// anything into, so its text never leaves. Hourly.
//
// shield.compliance-reports is a population of the compliance reports
// written for those same scopes: framework, scope, period, when it was
// generated, and the summary's top-level numbers and booleans. Strings and
// nested values in the summary are dropped. Shield never writes these
// reports itself; your app does, if it does at all. Loomplane writes none,
// so there this population is empty. Every 6 hours.
//
// shield.scan-outcomes is a snapshot of the previous complete UTC day's
// scans in the tenants you name: how many ran, how many were blocked,
// flagged and allowed, and counts by direction and decision. A whole day
// keeps the hash steady until the day turns, so it pushes once a day. It
// only counts scans the engine stores. Hourly, with no test key yet.
//
// shield.tenant-conformance is a snapshot you get only when you widen the
// scope (see Scope). shield.safety-actions is an event proof, off until you
// turn on event proofs (see Options).
//
// Never sent: scan text, redacted text, findings and their matched text,
// descriptions, any metadata, instinct strategy configs (a canary strategy
// keeps its canary token there), awareness detector patterns and configs,
// values guidelines and configs, judgment assessor configs, reflex trigger
// patterns (other than the risk class form above), reflex action targets
// (a redact action's target is the regex it redacts with, so a hash goes
// instead), reflex action values and fallback text, boundary deny and
// allow lists and canned responses, policy rule error messages, policy
// conditions (a hash goes instead), and report details. A reflex window
// that isn't a Go duration such as "1m" goes as an empty string.
//
// # Scope
//
// Shield keeps a tenant and an app on every row but has no idea which
// tenant is your own company. So you tell it. Tenants (config tenants) are
// the shield tenant IDs to read, usually your own organization. With none,
// the adapter reads no tenant at all: you get shield.engine, and the
// app-wide policies and reports when AppID is set. It never falls back to
// every tenant, since that would put your customers' safety setup in
// Hallproof.
//
// AppID (config app_id) is the shield app ID, such as "loomplane". It isn't
// taken from the witness scope, because a shield app ID is usually a
// product name while the witness scope holds your identity app. Empty reads
// every app within your tenants and skips the app-wide rows.
//
// AllTenants (config all_tenants, or the witness scope's AllTenants) widens
// the scope, but not by sending every tenant's rows. Shield can't list its
// tenants, and thousands of workspaces would blow past push.MaxItems
// anyway. What you get is shield.tenant-conformance: how many tenants run
// each distinct safety configuration, as a SHA-256 of the same fields the
// profiles, checks and policies populations send (minus IDs, times and the
// tenant itself) and a count per hash, with no tenant IDs. If every
// workspace runs the InfraAgent preset unchanged you see one hash and one
// count. The populations stay on the tenants you name. Widening needs a
// TenantSource, a func your app writes that lists every tenant ID. Pass it
// with WithTenantSource, or in a Forge app provide it in the container:
//
//	forge.ProvideValue(c, shield.TenantSource(listOrgIDs))
//
// Without one, Register returns ErrNoTenantSource, and in a Forge app the
// adapter logs a warning and doesn't widen. Each run reads every tenant's
// rows (eight list calls a tenant), which is why it runs every 6 hours.
//
// A scope that holds more than push.MaxItems rows in one population fails
// the run with ErrTooMany, and the heartbeat reports the collector
// unhealthy, because a truncated list would read as the full set.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.shield:
//
//	app_id: ""                # the shield app ID; empty means every app
//	tenants: []               # shield tenant IDs to read
//	all_tenants: false        # adds shield.tenant-conformance; needs a TenantSource
//	engine_snapshot: true     # false turns shield.engine off
//	event_proofs: false
//	proof_actions: []         # defaults to DefaultProofActions
//
// Outside Forge the same settings are Options: WithAppID, WithTenants,
// WithAllTenants, WithTenantSource, WithoutEngineSnapshot and
// WithEventProofs.
//
// Event proofs add shield.safety-actions, proving shield.scan.blocked,
// shield.boundary.enforced, shield.reflex.fired and shield.pii.redacted
// from the platform stream. It only proves something when your app wires
// shield's audit_hook plugin to the chain witness proves from, which
// Loomplane doesn't do today. Mind you, a proof carries every event in its
// range, and shield's audit_hook puts the error text of a failed scan in
// that event's reason and metadata, so turn it on knowing that.
//
// Don't add shield.policy.created to proof_actions. In shield v1.10.0 the
// audit_hook records that action every time a policy is evaluated, not when
// one is created, so citing it proves the wrong thing.
//
// # Library gaps
//
// These are things shield v1.10.0 doesn't do yet that would make this
// adapter cheaper or more accurate:
//
//   - There's no way to list tenants. Every primitive and profile read
//     needs one, which is why widening needs a TenantSource. A store
//     method such as ListTenants, or tenant-optional list filters behind
//     an explicit operator flag, would fix it.
//   - OnPolicyEvaluated records shield.policy.created, and
//     shield.policy.assigned and shield.compliance.generated are declared
//     but never emitted. The fix is a shield.policy.evaluated action, with
//     created and assigned emitted from the store paths.
//   - OnScanFailed records err.Error() as the event's reason and metadata,
//     and OnScanBlocked records the blocking reason. An error kind would
//     keep text out of the chain.
//   - The MongoDB store's ScanStats ignores From and To, so on MongoDB
//     shield.scan-outcomes counts every scan ever stored, not one day's.
//     The SQL stores compare created_at to the date strings as given.
//   - Lists page by offset over created_at, which can skip or repeat a row
//     when rows are created during a scan. The adapter drops repeats, and
//     a skipped row shows up on the next run.
//   - Metadata, strategy, detector and assessor configs, and report
//     summaries and details are free-form maps. The adapter allowlists
//     what it sends and never passes them through.
package shield
