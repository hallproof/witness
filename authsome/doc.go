// Package authsome sends Hallproof evidence about who can sign in to your
// platform and how, read from an Authsome engine
// (github.com/xraph/authsome, v1.9.1 or later).
//
// # Using it
//
// In a Forge app you only import it. Add witness/forge and a blank import,
// and the adapter finds your *authsome.Engine in the container by type:
//
//	import _ "github.com/hallproof/witness/authsome"
//
// Its options go under extensions.witness.adapters.authsome:
//
//	all_platform_users: false   # every platform-app user is staff
//	api_keys: false             # collect Authsome API keys without the apikey plugin
//	inactivity_enforced: false  # you mount Authsome's Forge middleware
//	event_proofs: false         # prove Authsome's audit events
//
// Without Forge, build the adapter yourself and register it before you
// start the witness:
//
//	a := authsome.New(engine, authsome.WithScope(adapter.Scope{AppID: appID}))
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # What it collects
//
// Every collector runs every 15 minutes.
//
//   - authsome.staff-users: each staff account with its email, name, ban and
//     deletion state, platform roles, organisation roles, whether it holds a
//     privileged role, its TOTP and other second factors, how many live
//     sessions it has and the day it was last seen.
//   - authsome.auth-policy: the platform app's MFA switches, the password
//     policy from the engine's Config, session lifetimes and binding, and
//     lockout, as Authsome enforces them.
//   - authsome.staff-sessions: every live session a staff account holds.
//   - authsome.service-accounts: non-human principals, agents included, that
//     staff own, or that belong to no organisation and have no owner.
//   - authsome.agent-grants: delegations staff gave to agents, plus
//     agentauth grants when that plugin is installed.
//   - authsome.agents: agents registered with agentauth. Only when the
//     plugin is installed.
//   - authsome.staff-api-keys: Authsome's own API keys held by staff or by
//     those service accounts. Only when the apikey plugin is installed or
//     you set api_keys. Keys you mint with Keysmith directly belong to
//     witness/keysmith.
//
// When the mfa plugin isn't installed, staff-users and auth-policy say so
// in mfa_plugin and report no second factors. Nothing fails.
//
// The adapter sends no secrets and no free text. Password hashes, tokens, token
// hashes, key hashes and key prefixes, MFA seeds, phone numbers, avatars,
// IP addresses, user agents, ban reasons, descriptions and metadata all
// stay behind. The auth-policy snapshot reads named fields one at a time,
// so the token encryption keys and API key pepper in Config never leave the
// engine. Staff emails and names do go: Hallproof joins accounts to your
// people list with them, to find leavers and shared accounts.
//
// # Who counts as staff
//
// By default a user is staff when they hold one of the scope's staff roles
// (platform-owner and platform-admin unless you name others) in the
// platform app. That is the safe rule for an app like Loomplane, where
// customers sign up to the platform app too and every one of them holds
// platform-user. The platform app is the scope's AppID, or the app Authsome
// bootstrapped when that's empty. A role held on one resource only (a
// Warden assignment with a resource type) doesn't count, just as Authsome's
// own role reads skip it.
//
// Turn on all_platform_users when your platform app is an operator console
// and customers live in other apps. Then every user of the platform app is
// staff. Scope.AllTenants does the same and also widens service accounts,
// grants and agents to every organisation in the app. Either way, in a
// single-app deployment your customers' accounts end up in Hallproof, and
// every collector that reads staff says in its description which rule was
// on. With all_platform_users on, the adapter also tells the witness it
// collects beyond staff, so Hallproof shows that too. Scope.AllTenants is
// the host's own setting, and the host reports it.
//
// Service accounts and agents are in scope when staff own them, or when
// they belong to no organisation and nobody owns them. An org-less account
// or agent a customer owns stays out. Grants are in scope when a staff user
// gave them or an in-scope principal holds them.
//
// The adapter pages every list it can and fails the run, so the heartbeat
// shows it unhealthy, when a list outgrows a population. It never sends a
// truncated list.
//
// # Event proofs
//
// With event_proofs on, four collectors prove Authsome's audit events from
// the platform stream: authsome.mfa-proof (sign-ins and MFA changes),
// authsome.access-change-proof (role and membership changes,
// impersonation), authsome.deprovision-proof (deletions, bans, revoked
// sessions) and authsome.agent-proof (delegations and agent sessions).
//
// They're off by default because Authsome records sign-in, MFA and role
// events under the app with no organisation. In a single-app deployment the
// platform stream carries every customer's sign-ins too, IP address and
// user agent included. Turn them on once your app routes staff
// events to their own Chronicle tenant.
//
// # Library gaps
//
// These are things Authsome can't tell the adapter yet. The adapter works
// around each one or reports less.
//
//   - ListUsersWithRole stops at Warden's default of 1000 holders without
//     saying so. The adapter reads Warden's assignments page by page
//     instead.
//   - The mfa plugin keeps its store private, so the adapter can't list a
//     user's factors. It reports Enrolled (verified TOTP) and HasMFA (TOTP
//     or SMS). Passkeys live in another plugin and aren't read.
//   - The password.min_length and password.require_special settings are
//     declared but nothing reads them. The snapshot reports Config.Password,
//     which is what sign-up and password changes enforce.
//   - Only Authsome's Forge extension middleware enforces the inactivity
//     timeout. The adapter can't see whether you mount it, so
//     session_inactivity_enforced is false unless you set
//     inactivity_enforced.
//   - ListPrincipals and ListDelegations have no cursor or order. The
//     adapter reads delegations per staff user and per in-scope principal,
//     which stays small.
//   - agentauth can list grants only by user, and it doesn't audit grant
//     creation or revocation. Only agent sessions reach the audit trail.
//   - Authsome stamps a grant's last use, not which scopes it used, so
//     grant-scopes-used is only partly supported.
//   - Users have no last sign-in time. last_seen_on comes from sessions, and
//     a deleted session takes it with it.
//   - There is no API key read by service account. Service account keys
//     come from one app-wide read, filtered here.
//   - Authsome has no audit read API. Event proofs don't need one, because
//     witness/chronicle reads Chronicle directly.
//
// Every staff user costs about eight reads a run. That's fine for tens of
// staff. A deployment with thousands of platform users and
// all_platform_users on needs batch reads in Authsome first.
package authsome
