// Package keysmith sends evidence about your API keys to Hallproof, read
// from a github.com/xraph/keysmith engine.
//
// # Collectors
//
// keysmith.api-keys is a population of every staff API key: its ID, tenant,
// app, name, prefix (the configured one, such as "sk", never key material),
// environment, state, policy, scope names, who created it, and when it was
// created, expires, was last rotated and was revoked. Last use goes as a
// day, not a time, because it changes on every request and a timestamp
// would make every run new evidence. It runs every 15 minutes and supports
// the keys-rotated and no-active-leavers tests. Hallproof joins created_by
// to its people list for the second one.
//
// keysmith.key-policies is a population of the policies those keys are held
// to: lifetime, rotation period, grace period, rate limits, quotas, allowed
// scope names, and how many IPs and origins a policy allows. It runs hourly.
//
// keysmith.rotation is a snapshot of totals: keys, active keys, the oldest
// rotation date among active keys (the rotation date, or the creation date
// for a key that was never rotated), and active keys with no expiry or no
// policy. You can derive it from the key population. It's there so the
// keys-rotated test still has an answer when that population fails.
//
// keysmith.key-lifecycle-proof is an event proof of keys being rotated,
// revoked or expiring, from the platform stream. It's off until you turn on
// event proofs, and it only proves something when the app records those
// events to the chain witness proves from.
//
// Never sent: key hashes, the key hint (the last characters of the raw
// key), descriptions, key and policy metadata (except the entries you
// allow), a policy's IP, origin, method and path lists (their counts go
// instead), and row versions and update times, which change without
// telling you anything about access.
//
// # Scope
//
// By default you get staff keys only. A staff key is one in a tenant you
// name in StaffTenants (config staff_tenants), usually your own company's
// organization, and in the app you name in AppID. If you name no tenants
// the adapter collects nothing at all. It won't fall back to every tenant,
// since that would put your customers' keys in Hallproof. Register returns
// ErrNoTenants in that case, and in a Forge app the adapter logs a warning
// and registers nothing.
//
// AllTenants (config all_tenants, or the witness scope's AllTenants) reads
// every tenant's keys and policies, your customers' included. AppID still
// applies when it's set. Hallproof shows that the scope was widened.
//
// A scope that holds more than push.MaxItems keys or policies fails the run
// with ErrTooMany, and the heartbeat reports the collector unhealthy, because
// a truncated list would read as the full set.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.keysmith:
//
//	app_id: ""                  # defaults to the witness scope's app ID
//	staff_tenants: [org_...]    # required unless all_tenants is on
//	all_tenants: false
//	metadata_keys: [kind]       # key metadata entries to send, plain values only
//	event_proofs: false
//	proof_actions: []           # defaults to DefaultProofActions
//
// Outside Forge the same settings are Options: WithAppID, WithStaffTenants,
// WithAllTenants, WithMetadataKeys and WithEventProofs.
//
// If your app records its own key events rather than using keysmith's
// audit_hook plugin, name its actions in proof_actions. Loomplane, for one,
// records api_key.created and api_key.revoked.
//
// # Using it
//
// With Forge, import the package for its side effect, and the witness
// extension finds *keysmith.Engine in the container:
//
//	import _ "github.com/hallproof/witness/keysmith"
//
// The engine has to be in the container by type. Keysmith's own Forge
// extension provides it. If you build the engine yourself, provide it with
// forge.ProvideValue(c, engine).
//
// Without Forge, build the adapter and register it before you start
// witness:
//
//	a := keysmith.New(engine,
//		keysmith.WithAppID("app_..."),
//		keysmith.WithStaffTenants("org_..."),
//	)
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # Library gaps
//
// These are things keysmith (v1.8.1 here, unchanged in v1.9.0) doesn't do
// yet that would make this adapter cheaper or more accurate:
//
//   - key.ListFilter and policy.ListFilter have no AppID, so the adapter
//     reads the other apps' rows in a tenant and drops them itself.
//   - key.Store.List leaves Scopes empty, so the adapter reads each key's
//     scopes with one more query (scope.Store.ListByKey). A batch read,
//     or List filling Scopes, would fix that.
//   - Lists page by offset over created_at, which can skip or repeat a
//     row when keys are created during a scan. The adapter drops repeats,
//     and a skipped key shows up on the next run. Keyset paging would fix
//     it properly.
//   - Who revoked a key and why isn't stored on the key. It only reaches
//     the OnKeyRevoked hook, so the audit event is the only record.
//   - The audit_hook plugin is opt-in, and keysmith's Forge extension
//     doesn't wire it to Chronicle, so keysmith.* events reach the chain
//     only when your app adds the plugin.
package keysmith
