// Package bastion sends evidence about your API gateway to Hallproof, read
// from a github.com/xraph/bastion gateway: which routes it serves, which of
// them need a login, how they're rate limited, where they forward to, and
// how the gateway itself is locked down.
//
// # Collectors
//
// bastion.routes is a population of every route in the gateway's live
// route table, every 15 minutes. Each item has the route's ID, path,
// methods, protocol, source (manual, farp or discovery), service name,
// priority, version and whether it's enabled. Then the parts you'd check in
// an audit: whether the route requires authentication (auth_required), the
// provider names that would be tried, the scope names it asks for, whether
// it opts out of auth (auth_skipped), and whether it forwards auth context
// upstream. You also get the global rate limit and the route's own one,
// whether the hop to the upstream uses TLS for all, some or none of the
// targets, and whether any target skips certificate checks. Request
// handling goes as the prefix and rewrite settings plus header names only,
// for the route's header rules and its transform. A traffic policy goes as
// its type, its rule count and, for mirroring, the origin traffic is copied
// to. Last come whether the response cache, retries and circuit breakers
// are on for the route, and when the route last changed. No Hallproof test
// uses it outright yet; it's the context behind tls-enforced on the
// upstream hop.
//
// For a manual route, targets is the list of upstreams, each as its origin
// (scheme, host and port), weight, tags, and whether per-target TLS, client
// certificates and a server name are set. Routes from service discovery or
// FARP send target_count and target_schemes in its place, because their
// targets change every time a pod moves.
//
// bastion.gateway is a snapshot of the gateway's settings, every 15
// minutes: auth (on or off, default policy, provider names), upstream TLS
// (minimum version, cipher suites, whether certificate checks are skipped,
// whether a client certificate is set, and the last reload), rate limiting,
// IP filtering as counts, CORS, the admin API (on or off, base path,
// whether a token or auth middleware guards it, and whether you've said
// it's fine unguarded), and the access log, discovery, route persistence,
// body size limit and route count. It supports no-open-admin-ports and
// tls-enforced, both only in part. Bastion runs inside your app's HTTP
// server, so it doesn't own the listener or terminate client TLS. Evidence
// that the public endpoint refuses plain HTTP has to come from whatever
// does: Forge's HTTP server or your load balancer.
//
// Never sent: header and transform values (they can put an Authorization
// header or API key on the upstream request), target URL users, passwords,
// paths and queries, traffic match values (cookie and header values),
// route and target metadata, CA, certificate and key file paths, the admin
// token, admin middleware, the IP allow and deny lists (they can hold staff
// home addresses, so only their counts go), and a target's live state:
// health, open connections, circuit state, request counts and latency.
// Those change on every run and say nothing about your controls. A target
// URL that doesn't parse to a scheme and host is sent as a null origin,
// never raw.
//
// # Scope
//
// Bastion has no tenants or users. Its routes and settings are your own
// system configuration, so everything on the gateway goes out. What makes a
// gateway a customer's is who it fronts. In a Forge app the adapter reads
// only the *bastion.Gateway in the app's container, the one your app
// registers for itself, and never a gateway you build by hand for a
// customer's workload. The witness scope's AllTenants changes nothing here.
// If you do want a customer-fronting gateway covered, register it yourself
// with New, and Hallproof should label that system as widened.
//
// The route table is read on every run, not when the adapter starts,
// because Bastion only builds it after the gateway registers. An enabled
// gateway with no route table fails the run with ErrNoRouteTable, and the
// heartbeat reports the collector unhealthy, so a gateway that was never
// wired doesn't read as one with no routes. A disabled gateway serves
// nothing and sends an empty population. More routes than push.MaxItems
// fails the run with ErrTooMany.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.bastion:
//
//	targets_summary: false   # send target counts for manual routes too
//
// Outside Forge the same setting is WithTargetsSummary. There are no event
// proofs, because Bastion records no audit events yet (see the gaps below).
//
// # Using it
//
// With Forge, import the package for its side effect, and the witness
// extension finds *bastion.Gateway in the container:
//
//	import _ "github.com/hallproof/witness/bastion"
//
// Bastion's Register provides the gateway by type, and only when the
// gateway is enabled, so a disabled gateway is skipped. gateway.New and
// extension.New both do this for you.
//
// Without Forge, build the adapter on your gateway and register it before
// you start witness:
//
//	a := bastion.New(gw)
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// Importing this package pulls in Bastion's root module, which is heavy
// (Forge and its discovery extension among others). Any app that runs
// Bastion already pays that, so it adds nothing for you.
//
// # Library gaps
//
// These are things Bastion (v1.4.1 here) doesn't do yet that would make
// this adapter more accurate:
//
//   - No audit events reach Chronicle. observability.AuditLogger defines
//     route.created, route.updated, route.deleted, route.toggled and
//     config.changed, but nothing builds it, and admin API writes only go to
//     the logger. An audit_hook package (a Recorder with Record(ctx, event))
//     fed from those writes would let this adapter add a bastion.route-changes
//     event proof.
//   - There's no read API for "does this route require auth". The adapter
//     copies the logic of security.(*Auth).Authenticate, which can drift. A
//     RouteAuth(route) (required bool, providers []string) next to
//     Authenticate would fix that.
//   - The proxy never uses the TLS manager. In v1.4.1 the engine is handed
//     it (SetTLSManager) but builds its own transport, so only
//     tls.insecure_skip_verify takes effect, for every target, even with
//     tls.enabled off. The CA, client certificate, minimum version and the
//     per-target TLS blocks are reported as configured, not as applied.
//   - A route's circuit breaker override isn't read by the proxy, and its
//     cache block only tunes TTL, methods and vary headers, so
//     circuit_breaker_enabled and cache_enabled are the gateway-wide
//     settings.
//   - TLSManager.LastReload reads a time the reload loop writes without a
//     lock, so it can race when tls.reload_interval is set.
//   - The extension reports its version as "1.0.0" whatever the tag, so
//     read the module version from build info if you need it.
//   - Hallproof has no test key for "public routes require authentication"
//     or "public routes are rate limited" yet, so bastion.routes has no
//     tests of its own.
package bastion
