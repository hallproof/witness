// Package relay sends evidence about your outgoing webhooks to Hallproof,
// read from a github.com/xraph/relay store.
//
// # Using it
//
// With Forge, import the package for its side effect and name your staff
// tenants in extensions.witness.adapters.relay:
//
//	import _ "github.com/hallproof/witness/relay"
//
// The adapter asks Relay's own Forge extension ("relay") for the
// *relay.Relay, through its Relay method. Only when your app doesn't run
// that extension does it look for a *relay.Relay in the container. The
// order matters: the extension registers the Relay with a constructor, and
// a container that builds it on request starts it again. An extension that
// has no Relay yet counts as no relay, and the adapter logs it. If you
// build Relay yourself, provide the finished value with
// forge.ProvideValue(c, r), not a constructor.
//
// If the store you gave Relay wraps the database store to encrypt signing
// secrets, also provide the raw database store as an endpoint.Store:
//
//	vessel.ProvideValue[endpoint.Store](c, relaypg.New(db))
//
// The adapter reads that store from the container whether or not Relay's
// extension runs. Relay's extension never provides one, so provide it as a
// value as shown.
//
// The adapter then reads endpoints through that store and never decrypts a
// secret. A wrapper that decrypts on every list fails the whole list when
// one secret won't decrypt, so one bad row would cost you the collector.
// The event catalog still comes from the Relay.
//
// Without Forge, build the adapter and register it before you start
// witness:
//
//	a := relay.New(r,
//		relay.WithStaffTenants("org_..."),
//		relay.WithEndpointStore(rawStore), // only if r's store decrypts secrets
//	)
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// NewFromStore(s) does the same from a bare endpoint store. It lists event
// types too when s is a full relay store.
//
// # Collectors
//
// relay.webhook-endpoints is a population of the webhook endpoints in
// scope. Each item has the endpoint's ID, tenant, scope app and org, the
// destination scheme and host, whether deliveries are signed, whether it's
// enabled, the event type patterns it subscribes to (sorted), its rate
// limit, the names of its custom headers (lowercased, sorted), and when it
// was created and last updated. The host is lowercased and keeps its port
// only when the port isn't the scheme's default. A URL that won't parse
// sends an empty scheme and host. It runs every 30 minutes.
//
// relay.webhook-posture is a snapshot of counts across every tenant:
// endpoints, enabled endpoints, unsigned ones, ones not on HTTPS, and how
// many tenants have an endpoint at all. It names no tenant and no host, so
// it's on by default even in the staff scope. In an app where every
// endpoint belongs to a customer, such as Loomplane, the staff population
// is empty and this snapshot is what shows you only deliver signed HTTPS
// webhooks. Hallproof should show it as a system-wide aggregate. It runs
// hourly. Turn it off with posture: false or WithoutPosture.
//
// relay.event-types is a population of the event types the system can send:
// name, group, version, schema version, the description the developer
// wrote in code, whether it's deprecated and since when, its scope app,
// and the SHA-256 of its JSON schema with whitespace removed, so you see a
// schema change without the schema itself. It runs every 6 hours, and
// only when the store has an event catalog. Turn it off with
// event_types: false or WithoutEventTypes.
//
// The endpoint and posture collectors name the tests webhooks-signed and
// webhooks-encrypted. Hallproof's test library doesn't have those yet, so
// until it does the evidence arrives and lands on no test.
//
// Never sent: the signing secret (plaintext or ciphertext; it is read only
// to tell whether one is set), the URL's path, query, fragment and
// userinfo (webhook URLs often carry a token there), header values, an
// endpoint's metadata and description, an event type's example payload,
// schema body and metadata, and anything from events, deliveries or the
// dead letter queue, which the adapter never reads.
//
// Signed means the stored secret isn't blank, the same test Relay's signer
// makes. Through a raw store that holds encrypted secrets, that's "a
// ciphertext is stored", so an encrypted empty secret would read as
// signed. Loomplane always generates the secret, so it can't happen there.
//
// # Scope
//
// Relay doesn't record which tenants are yours and which are your
// customers'. A tenant ID is whatever string your app passes, so you tell
// the adapter:
// StaffTenants (config staff_tenants) names the tenants whose endpoints
// are staff endpoints, usually your own company's organization.
//
// With no staff tenants the endpoint population isn't registered at all.
// It never falls back to every tenant, which in Relay is what an empty
// tenant ID means, because that would put your customers' webhook
// destinations in Hallproof. Register logs a warning and registers the
// posture and event type collectors. If those are off too, it registers
// nothing and returns ErrNoTenants, and in a Forge app the adapter logs it
// and moves on.
//
// AllTenants (config all_tenants, or the witness scope's AllTenants) lists
// every tenant's endpoints, with their tenant IDs and hosts. Paths,
// queries, header values and secrets stay out even then. Hallproof shows
// that the scope was widened: the endpoints description says every tenant,
// and when the adapter's own all_tenants is on it tells the witness so.
// The host reports its own scope.
//
// Lists are read 500 rows a page. A scope holding more than push.MaxItems
// endpoints or event types fails the run with ErrTooMany, and the
// heartbeat reports the collector unhealthy, because a truncated list
// would read as the full set. A store that ignores Offset also fails the
// run instead of looping.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.relay:
//
//	staff_tenants: [org_...]   # required for the endpoint population
//	all_tenants: false
//	posture: true              # the aggregate snapshot
//	event_types: true          # the event type catalog
//
// Outside Forge the same settings are WithStaffTenants, WithAllTenants,
// WithoutPosture and WithoutEventTypes, plus WithEndpointStore and
// WithLogger.
//
// There's no event_proofs option. Relay records no audit events, so there
// is nothing for an event proof to cite.
//
// # Library gaps
//
// These are things Relay (v1.8.1 here) doesn't do yet that would make this
// adapter more useful:
//
//   - No platform or customer notion on tenants. Scope has to come from
//     your config.
//   - No audit hook. Creating, updating, deleting, enabling, disabling an
//     endpoint and rotating its secret emit nothing, so webhook config
//     changes can't be proven from the chain. A Chronicle-shaped
//     audit_hook on endpoint.Service, like the other libraries have, would
//     fix it.
//   - Lists page by offset. The store contract asks for a total order, so
//     paging neither skips nor repeats while nothing changes, but an
//     endpoint created mid-scan can still shift a page. The adapter drops
//     repeats, and anything skipped shows up on the next run.
package relay
