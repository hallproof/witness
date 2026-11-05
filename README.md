# witness

Witness sends evidence from your Go app to Hallproof, so your SOC 2 controls get tested against what your system actually does, not a screenshot someone took in March.

You tell it, once, how to read a few things your app already knows: its auth settings, who has access, which keys exist. Witness collects them on a schedule and pushes them to Hallproof whenever they change. Nothing else in your code has to call it.

```sh
go get github.com/hallproof/witness
```

You'll need Go 1.25 or newer, and an ingest key for your system from Hallproof. The module has no dependencies outside the standard library.

## Quick start

```go
w, err := witness.New(witness.Options{
	Endpoint:  "https://hallproof.example.com",
	IngestKey: os.Getenv("HALLPROOF_INGEST_KEY"),
})
if err != nil {
	return err
}

// Your auth settings, every 15 minutes.
err = w.Snapshot(collect.Snapshot{
	Key:   "auth-settings",
	Title: "Authentication settings",
	Tests: []string{"mfa-enforced"},
	Every: 15 * time.Minute,
	Collect: func(ctx context.Context) (map[string]any, error) {
		return map[string]any{"mfa": cfg.MFA, "session_hours": cfg.SessionHours}, nil
	},
})

// Everyone with staff access, every hour.
err = w.Population(collect.Population{
	Key:    "staff-users",
	Title:  "Staff accounts",
	Source: "staff-users",
	Tests:  []string{"access-reviewed"},
	Every:  time.Hour,
	Collect: listStaff, // returns []map[string]any, each with a unique "id"
})

w.Start(ctx)
defer w.Stop(shutdownCtx)
```

`Tests` names the control tests in Hallproof that the evidence supports, which is how it lands in the right place. [`example_test.go`](example_test.go) has the whole thing, middleware included.

## What it sends

Metadata, never content. A snapshot is the settings map you return, and a population is the list of items you return, each with an `id`. Witness hashes both and pushes them on the first run, whenever the hash changes, and once a day so the newest evidence is never stale. In between, each collector sends a small heartbeat with its current hash, so Hallproof can tell a quiet collector from a dead one.

Return who has access and how things are configured. Don't return passwords, tokens, secret values, message bodies or documents: Hallproof doesn't need them, and an evidence tool that leaks customer data is worse than no evidence at all.

If you also mount the middleware, staff requests that change something (anything but GET, HEAD and OPTIONS) are recorded as events with the route pattern, the user, the outcome and the request ID. The path's values, the query string and the body are never recorded. Mount it inside your auth middleware and outside your router:

```go
handler := auth(w.Middleware(httpmw.Options{Actor: whoIsCalling})(mux))
```

Event recording needs a chain to write to. This release ships without one, so the middleware passes every request straight through and witness logs once at start-up that recording is off. The Chronicle adapter is next (see below).

## When Hallproof is down

Your app doesn't notice. Collectors run on their own goroutines, and pushes go through a queue that never blocks. If Hallproof can't be reached, messages wait in the queue and go out when it's back. When the queue fills up, heartbeats go first and then the oldest evidence, and witness counts every drop and logs them, at most once a minute. If it can't get through at all, it says so in the log once, not on every retry. `Stop` sends what's queued and gives up when your shutdown context runs out, telling you how many messages it left behind.

A collector that panics, errors or hangs past its interval is logged and marked unhealthy in its next heartbeat. The other collectors keep going.

## Defaults

| Setting | Default | Change it with |
|---|---|---|
| Collector interval | 15 minutes | `Every` on the collector |
| Spread between runs | ±10% of the interval | |
| First run after `Start` | within 30 seconds | |
| Heartbeat | every 10 minutes | `Options.HeartbeatEvery` |
| Queue | 1000 messages | `client.WithQueueSize` |
| Retry backoff | 1 second, doubling to 5 minutes | `client.WithBackoff` |
| HTTP timeout | 30 seconds | `Options.HTTPClient` |
| Kind Hallproof doesn't take yet | held back for an hour | `client.WithHoldBack` |

## Forge apps

If your app runs on Forge, you don't write collectors by hand. Add the witness extension and a blank import for each library you want covered:

```go
import (
	witnessforge "github.com/hallproof/witness/forge"
	_ "github.com/hallproof/witness/authsome"
	_ "github.com/hallproof/witness/chronicle"
	_ "github.com/hallproof/witness/keysmith"
)

app := forge.New(forge.WithExtensions(
	witnessforge.New(),
	// your other extensions
))
```

Then give it an endpoint and a key in your config:

```yaml
extensions:
  witness:
    endpoint: https://hallproof.example.com
    ingest_key_file: /run/secrets/hallproof-ingest-key
    scope:
      app_id: your-platform-app
      tenant_id: platform
```

Once your app has started, the extension looks in Forge's container for each library you imported. It collects from the ones it finds and skips the rest quietly, then pushes a `witness.coverage` snapshot so Hallproof can see what it found. With no endpoint it does nothing at all.

Each adapter is a module of its own, so you only download the libraries you use:

| Module | What it collects |
|--------|------------------|
| [`chronicle`](chronicle) | Proves signed segments of your Chronicle audit chain, and reports whether the platform stream's checkpoints keep up |
| [`authsome`](authsome) | Staff users and their roles, auth policy, sessions, service accounts, agents and their grants |
| [`warden`](warden) | Roles, role assignments, policies and a fingerprint of the access model |
| [`keysmith`](keysmith) | API keys, key policies and rotation |
| [`vault`](vault) | Secret names, versions and rotation (never values), flags and allowlisted config |
| [`bastion`](bastion) | The gateway's routes, whether each needs auth, and its admin settings |
| [`trove`](trove) | Object stores and the protections applied when objects are written |
| [`grove`](grove) | Applied database migrations |
| [`relay`](relay) | Webhook destinations, whether they're signed, and an overall posture |
| [`dispatch`](dispatch) | Scheduled jobs and their results, including your backups |
| [`cortex`](cortex) | AI agents, their owners and tools, and approvals waiting on a person |
| [`nexus`](nexus) | AI providers and models in use, keys and budgets |
| [`shield`](shield) | AI safety profiles, checks and policies |
| [`sentinel`](sentinel) | AI eval suites, latest scores and red-team runs |

Witness collects staff, not customers, by default: the people who run your platform, its service accounts and its keys. Some libraries can't tell those apart on their own, so their adapters need you to name the platform's tenants or apps, and each package's docs say which. A company whose audit covers customer access too can set `scope.all_tenants`, and Hallproof shows that the scope was widened. An adapter whose own options reach further, such as extra Chronicle streams, is marked widened in the coverage snapshot too.

Adapters send metadata, never content. No secret values, prompts, payloads, bodies or error text leave your app in a snapshot or population, and every adapter has a test that fails if one does. Event proofs are different. A proof carries every event in a signed segment of your Chronicle chain as it was recorded, with its reason, metadata, IP and user agent, because Hallproof needs the whole segment to check the hashes. That's why they're off by default, and why you should turn them on only for a stream that holds staff events and nothing else. Chronicle's [What it sends](https://pkg.go.dev/github.com/hallproof/witness/chronicle#hdr-What_it_sends) section lists every field.

Outside Forge, each adapter has a plain constructor that takes the library's engine, such as `keysmith.New(engine, keysmith.WithStaffTenants("acme"))`, and a `Register(w)` that adds its collectors to your witness. It adds all of them or none: if one fails, the ones it added before are taken out again.

## The packages

- [`push`](push) is the wire protocol: the batch and message types, the hashes and the limits.
- [`client`](client) sends batches, with `Send` for pushing by hand and a background queue for everything else.
- [`collect`](collect) has the collector types and the scheduler.
- [`chain`](chain) is the interface for recording and proving events.
- [`httpmw`](httpmw) is the `net/http` middleware.
- [`ingesttest`](ingesttest) is a fake Hallproof ingest API for your tests.
- [`adapter`](adapter) is the registry the library adapters join.

## Not on Go?

The protocol is written down in [`spec/protocol.md`](spec/protocol.md), with a JSON Schema for every message body and test vectors for the hashes, so you can push from any language.

## What's coming

We're building witness in steps, and v0.x means the API can still change.

- Enforcement: gates a developer declares in code and an admin switches on in Hallproof, starting in report-only mode, so Hallproof can block what a control forbids without ever doing it silently.
- A chain witness runs itself, for apps that don't use Chronicle.

## Licence

MIT. See [LICENSE](LICENSE).
