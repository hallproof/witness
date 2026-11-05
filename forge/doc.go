// Package forge is the witness extension for Forge apps. Import it as
// witnessforge.
//
// You add one extension and blank-import an adapter for each library your
// app runs. Once every extension has started, witness asks each adapter to
// find its library in the app's container, and the ones that find it add
// their collectors. Then witness starts pushing evidence to Hallproof.
//
//	import (
//		witnessforge "github.com/hallproof/witness/forge"
//		_ "github.com/hallproof/witness/keysmith"
//		_ "github.com/hallproof/witness/vault"
//	)
//
//	app := forge.New(forge.WithExtensions(
//		keysmithext.New(),
//		witnessforge.New(),
//	))
//
// # Config
//
// The extension reads extensions.witness from your config file (or the
// top-level witness key). Fields you set in code with WithConfig win over
// the file.
//
//	extensions:
//	  witness:
//	    endpoint: https://hallproof.example.com
//	    ingest_key_file: /run/secrets/hallproof-ingest-key
//	    scope:
//	      app_id: app_platform
//	      tenant_id: t_platform
//	    exclude: [nexus]
//	    adapters:
//	      vault:
//	        apps: [app_platform]
//
// With no endpoint, or with disabled: true, witness is off. It logs that once
// and does nothing else, so you can ship the extension in every build and turn
// it on per environment. A bad endpoint or key fails the app's start, since
// that's a deploy mistake you want to see.
//
// libraries limits witness to the adapters you name, and exclude leaves some
// out. A name in either list that no adapter registered is logged as a
// warning, because it usually means a missing blank import. adapters holds
// each adapter's own options under its name; the adapter's package doc lists
// them.
//
// # Scope
//
// Adapters collect staff evidence only by default: the people, keys and
// settings that run your platform, never your customers'. scope.app_id and
// scope.tenant_id name the platform, and scope.staff_roles the roles that make
// someone staff (platform-owner and platform-admin when empty). Set
// scope.all_tenants to widen collection to every tenant. Hallproof is told
// when you do.
//
// # What it pushes on its own
//
// Next to the adapters' evidence, witness pushes one snapshot, witness.coverage.
// It lists every registered adapter by name and module, whether witness found
// its library, and error: true when its Attach failed. It never carries the
// error's text; that stays in your logs. The snapshot also says the scope,
// staff or all_tenants. This is how Hallproof can tell you "this app runs
// Trove, and no Trove evidence is arriving".
//
// An adapter's own options can take it beyond staff too, such as an
// all_platform_users switch or extra Chronicle streams. The adapter reports
// that through Host.Widened, and its entry gets widened: true and
// widened_by, the config keys that did it. The snapshot then also carries
// any_widened: true. The scope stays staff or all_tenants, because it's
// still what you set; any_widened says that some adapter went further.
//
// # Discovery
//
// Chain adapters attach first, so the chain is bound before the rest attach.
// An adapter whose library isn't in the container is skipped and logged. One
// that returns an error, or panics, is logged and skipped too, and witness
// still starts with the others. Collectors an adapter added before it failed
// stay registered.
//
// # The chain
//
// Witness records and proves events on a chain. Until a chain adapter (such
// as github.com/hallproof/witness/chronicle) binds one, the chain answers
// chain.ErrNoChain, so you can mount the middleware during Register and it
// starts recording once the chain is bound. The first chain bound stays. A
// chain offered after witness starts is ignored with a log line. WithChain
// sets the chain in code and wins over any adapter.
//
// # Reaching the witness from your own code
//
// The container holds *witness.Witness only once the app has started. Forge's
// container (vessel) starts every value with a Start method when the
// container starts, which happens before the after-start hooks, and a witness
// started that early would refuse the adapters' collectors. So from an app
// extension's Register or Start, depend on Name and call (*Extension).Witness
// on the extension you created:
//
//	w := witnessExt.Witness() // nil when witness is off
//	if w != nil {
//		_ = w.Snapshot(collect.Snapshot{ /* ... */ })
//		router.Use(w.Middleware(httpmw.Options{}))
//	}
//
// From handlers and anything else that runs after start,
// forge.InjectType[*witness.Witness] works.
//
// # Ordering
//
// The extension starts after every registered adapter's After names and
// Config.After, and Forge skips names your app doesn't run. Forge orders
// extensions before any of them reads config, so after only changes the
// order when you set it in code with WithConfig. Discovery doesn't depend on
// the order anyway: it runs once every extension has started.
//
// # Stopping
//
// When the app stops, witness stops before any extension does, so engines are
// still up while it sends what is queued. It gets at most 10 seconds, and
// evidence it couldn't send is logged, never a shutdown error.
//
// # Without Forge
//
// You don't need this package outside Forge. Build a *witness.Witness with
// witness.New, call each adapter's New and Register on it, and call Start.
//
// # Gaps
//
// Because of the container behaviour above, *witness.Witness is provided at
// after-start, not during Register. A witness root change that lets
// collectors be added after Start, or that doesn't match vessel's Starter
// interface, would let Register provide it.
package forge
