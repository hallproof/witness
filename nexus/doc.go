// Package nexus sends evidence about your AI gateway to Hallproof, read from
// a github.com/xraph/nexus *nexus.Gateway: which AI providers you call, the
// models you actually used, your guardrails, your gateway keys and your AI
// budgets.
//
// # Collectors
//
// nexus.gateway is an hourly snapshot of the gateway's settings. You get
// each registered provider by name with its capability flags (chat,
// streaming, tools and so on), the model aliases with their provider and
// model targets in fallback order, the routing strategy, the guards by name
// and phase, and the gateway's own switches: require_api_key, enable_cache,
// enable_usage, global_rate_limit, default_max_retries and
// default_timeout_seconds. Alias weights and per-tenant alias overrides are
// left out. Weights change without meaning anything, and overrides are keyed
// by tenant.
//
// nexus.models-in-use is a population of every provider and model pair a
// provider answered in the last 30 days, across the whole gateway. It runs
// every 6 hours. Each item is just provider, model and an id of
// "provider/model". No counts, tokens or cost go with it, because they
// change on every run and would make every run new evidence. Requests that
// were blocked, refused, served from cache or failed at the provider don't
// count, so a model name a caller typed that never reached a provider
// doesn't show up. Treat this list as "providers called", not as your
// subprocessors: with bring-your-own-key, a customer's own OpenAI account is
// their processor, not yours, and the provider name looks the same.
//
// nexus.keys is a population of the Nexus API keys in scope, every 15
// minutes, for the keys-rotated test: ID, tenant, name, scopes, effective
// status (an active key past its expiry reads expired), created_at (also the
// rotation date, since Nexus rotates by creating a new key), expires_at,
// the day it was last used, and owner_id from the key metadata entry you
// name. Last use goes as a day because it changes on every request.
//
// nexus.budgets is an hourly population of the tenants in scope: slug,
// status, monthly_budget_usd as an exact decimal, rpm, tpm, daily_requests,
// max_tokens_per_req, the stream caps, allowed and blocked models, the
// default model, guardrail_policy and cache_enabled. Current spend isn't
// sent, since it changes all day.
//
// Never sent: prompts, completions, request and response bodies, usage
// record metadata, key hashes and key prefixes (the prefix holds 8
// characters of the raw key), provider credentials and server keys,
// provider base URLs (in a bring-your-own-key setup these can be a
// customer's own endpoint), guard internals such as patterns and word
// lists, tenant names, and tenant and key metadata other than the owner
// entry you name.
//
// There are no event proofs. Nexus's audit actions aren't namespaced
// (key.created, request.failed and so on), so in a Chronicle stream shared
// with keysmith or authsome they'd be ambiguous. Setting event_proofs
// changes nothing, and the adapter logs a warning saying so.
//
// # Scope
//
// The gateway-wide collectors, nexus.gateway and nexus.models-in-use, always
// run. They describe your own vendor relationships and carry no tenant IDs,
// counts or customer data.
//
// The key and budget collectors are tenant-keyed, so they only run for the
// tenants you name in Tenants (config tenants), by ID or by slug, usually
// your own company's tenant. A name that matches no tenant is skipped, so
// you can name a tenant before the gateway creates it. Name none and those
// two collectors aren't registered at all. They never fall back to every
// tenant, because that would put your customers' keys and budgets in
// Hallproof.
//
// AllTenants (config all_tenants, or the witness scope's AllTenants) reads
// every tenant's keys and budgets, your customers' included. Hallproof shows
// that the scope was widened.
//
// A scope holding more than push.MaxItems keys or tenants fails the run with
// ErrTooMany and the heartbeat reports the collector unhealthy, because a
// truncated list would read as the full set. The models-in-use run fails the
// same way if it would need more than 5000 usage queries. A collector that
// runs before the gateway is initialized fails with ErrNotReady.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.nexus:
//
//	tenants: [platform]   # tenant IDs or slugs whose keys and budgets you send
//	all_tenants: false
//	owner_key: owner_id   # key metadata entry sent as owner_id
//
// Outside Forge the same settings are WithTenants, WithAllTenants and
// WithOwnerKey.
//
// # Using it
//
// With Forge, import the package for its side effect. Nexus's own Forge
// extension puts *nexus.Gateway in the container, and the witness extension
// finds it there:
//
//	import _ "github.com/hallproof/witness/nexus"
//
// Without Forge, build the adapter and register it before you start
// witness:
//
//	a := nexus.New(gateway, nexus.WithTenants("platform"))
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # Library gaps
//
// These are things Nexus (v1.9.2 here) doesn't do yet that would make this
// adapter cheaper or more complete:
//
//   - There's no read for the provider and model pairs in use. The usage
//     summary keys models and providers separately, so the adapter confirms
//     each pair with a one-row usage query. A summary keyed by pair, or a
//     usage.Store method returning the distinct pairs since a time, would
//     make it one query.
//   - The "month" usage summary is the calendar month. The adapter adds the
//     last week's summary and the alias targets to its candidates, but a
//     model used only in the last calendar month, more than a week ago and
//     not named in an alias, drops out of the list a few days before its 30
//     days are up.
//   - The stream guard strategy set with WithStreamGuardStrategy has no
//     getter, so it isn't in nexus.gateway. Gateway.StreamGuardStrategy()
//     next to RoutingStrategy() would fix that.
//   - Audit actions aren't namespaced, so there are no event proofs (see
//     above). Prefixing them with "nexus." would fix it. The audit event
//     also has no outcome or severity, and OnRequestFailed and
//     OnStreamFailed put the provider's error text in Details, which can
//     echo parts of a request.
//   - A key's owner isn't a field, so it comes from a metadata convention.
package nexus
