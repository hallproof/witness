// Package vault sends evidence about Vault (github.com/xraph/vault) to
// Hallproof: secret names, versions and ages, encryption at rest, rotation
// policies, feature flags and runtime config. It never sends a secret value.
//
// # Collectors
//
//   - vault.secrets (population, source "secrets", tests keys-rotated and
//     storage-encrypted). One item per secret: app ID, key, version, whether
//     it's encrypted and with what, when it was created and last set, when
//     it expires, and the rotation policy's state when there is one.
//   - vault.encryption (snapshot, test storage-encrypted). Per app ID, how
//     many secrets exist, how many current values aren't encrypted, and how
//     many older versions are plaintext or were never classified. With a
//     *vault.Vault it also reports whether the engine encrypts new writes.
//   - vault.rotation-policies (population, source "rotation-policies", test
//     keys-rotated). Each policy, its interval, when it last ran and whether
//     it's overdue. An empty list is sent too: it shows no policy exists.
//   - vault.flags (population, source "feature-flags"). Each flag, its type,
//     whether it's on, its tags, and its targeting rules as counts. A bool
//     flag's default goes out; no other default does.
//   - vault.config (population, source "runtime-config"). Each config key,
//     its type, version and override count. Values go out only for keys you
//     list in config_allowlist.
//   - vault.rotation-events (event proof on the platform stream, test
//     keys-rotated, actions secret.rotated, rotation.policy_saved and
//     rotation.policy_deleted). Off unless you set event_proofs.
//
// Never sent: values, encrypted values, key IDs, metadata, descriptions,
// variant values, rule return values, the tenant and user IDs inside rules,
// tag rules, custom evaluator names and params, and override values. The
// adapter holds its store through an interface without GetSecret,
// GetSecretVersion or ListUnrecordedVersions, so it can't read secret bytes
// even by mistake. It reads every list in pages. A run that would pass
// push.MaxItems fails, and the heartbeat goes unhealthy, so you never get
// half a list.
//
// # Scope
//
// Vault knows app IDs and tenants inside each app ID, not platform and
// customer. It also can't list its app IDs, so you tell the adapter which
// ones are yours:
//
//	apps: the app IDs whose secrets, policies and encryption counts go out
//	tenants: tenants inside those apps whose secrets also go out (widening)
//	flag_config_apps: the app IDs whose flags and config go out
//	config_allowlist: config keys whose values go out
//	event_proofs: turn on vault.rotation-events
//
// With no apps configured, a bare store collects nothing and logs a warning
// saying so. It never falls back to every app. With a *vault.Vault, apps
// defaults to the engine's own app ID and flag_config_apps to apps. Only
// app-level secrets (no tenant) go out unless you name tenants. Vault can't
// list tenants either, so a host scope of all tenants only logs a reminder
// to name them.
//
// For Loomplane, which keeps customer credentials in their own Vault app
// IDs, name only the platform ones:
//
//	extensions:
//	  witness:
//	    adapters:
//	      vault:
//	        apps: [loomplane-platform-oauth-apps, loomplane-platform-cloud, loomplane-oidc-issuer]
//
// # Using it
//
// In a Forge app, import the package for its side effect and witness/forge
// finds Vault:
//
//	import _ "github.com/hallproof/witness/vault"
//
// It asks Vault's own Forge extension ("vault") first, for its *vault.Vault
// through the Vault method, or, when that is nil, its store through the
// Store method. An extension with neither yet counts as no Vault, and the
// adapter logs it. Only when your app doesn't run that extension does it
// look in the container, for a *vault.Vault first and then a store.Store.
// The order matters: the extension registers both with constructors, and a
// container that builds the vault on request starts it again.
//
// If you build Vault's services yourself, provide the finished store (or
// vault) as a value, not a constructor, so the adapter can find it:
//
//	vessel.ProvideValue[store.Store](app.Container(), vaultpg.New(db))
//
// Without Forge, build the adapter and register it before the witness
// starts:
//
//	a := vault.New(vaultStore, vault.WithApps("platform"), vault.WithConfigValues("max-upload-mb"))
//	if err := a.Register(w); err != nil { ... }
//
// or vault.NewFromVault(v) when you have the engine.
//
// # Library gaps
//
// These need changes in Vault (or the app) before the evidence is complete:
//
//   - Vault never wires its audit hook. audit.NewLogger is built without
//     audit.WithHook and no vault.Option sets one, so rotation events land
//     only in Vault's own audit table and never reach Chronicle. Until that
//     changes, vault.rotation-events proves nothing, which is why it's off.
//   - The emitted action names drift from the constants: secret.get and
//     secret.delete are emitted, while the constants say secret.accessed and
//     secret.deleted.
//   - A bare secret.Service with no WithOnMutate or WithOnAccess (what
//     Loomplane builds) writes no audit rows at all.
//   - There's no way to list app IDs or tenants, so scope has to be named.
//   - CountSecrets, CountSecretsUnencrypted and CountVersionEncryption count
//     every tenant of an app. The encryption snapshot for an app therefore
//     includes tenant rows, if any exist; a tenant-scoped count would fix it.
//   - Without rotation policies, keys-rotated rests on last_set_at, which
//     shows a secret's age, not that a rotation process ran.
//   - ListSecrets has no key prefix filter, so the adapter can't take one
//     organisation's keys out of a shared app ID without reading the rest.
package vault
