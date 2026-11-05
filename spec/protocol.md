# The Hallproof push protocol, version 1

This is everything you need to send evidence to Hallproof from any language. The Go types in [`push`](../push) are one implementation of it, but you should not have to read Go to follow along. If this page and the Go code ever disagree, that is a bug, and we would like to hear about it.

You'll need an ingest key for the system you're reporting on. Hallproof issues those per system, and they start with `hpk_`.

## Sending a batch

POST one JSON batch to `/api/v1/ingest`, with the ingest key as a bearer token:

```http
POST /api/v1/ingest HTTP/1.1
Host: hallproof.example.com
Authorization: Bearer hpk_...
Content-Type: application/json

{
  "version": 1,
  "messages": [
    {
      "id": "auth-settings:6f1e...",
      "kind": "config_snapshot",
      "collected_at": "2026-11-04T12:00:00Z",
      "body": { "title": "Auth settings", "tests": ["mfa-enforced"], "settings": { "mfa": "required" }, "hash": "sha256:..." }
    }
  ]
}
```

The key says which organisation and system the evidence belongs to, so nothing in the batch repeats that. Use HTTPS. A key sent in clear text over a network is a key you should revoke.

| Limit | Value |
|---|---|
| Messages in a batch | 100 |
| Encoded batch size | 8 MiB |
| Events in one event proof segment | 10 000 |
| Items in one population | 50 000 |

The batch is described by [`schema/batch.schema.json`](schema/batch.schema.json), and the answer by [`schema/response.schema.json`](schema/response.schema.json).

## Messages

Every message has an `id`, a `kind`, a `collected_at` time and a `body`.

The ID is 1 to 200 bytes of UTF-8 text with no NUL bytes. It can appear only once in a batch (send it twice and both copies are rejected), and it has to stay unique for its system for ever. It's your idempotency key: send the same ID with the same body again and Hallproof answers `duplicate`, pointing at the evidence it already stored. Send the same ID with a different body and it's rejected, because Hallproof can't tell which one you meant.

`collected_at` is when you collected the evidence, in RFC 3339. Every kind in this version needs it, and it can't be more than five minutes ahead of Hallproof's clock.

A message that breaks a rule is answered `rejected`, with the reason in its `error`. The rest of the batch carries on.

## Status codes

The HTTP status tells you what happened to the batch as a whole.

- `200`: Hallproof read the batch. The body has one result per message, in the same order. A 200 doesn't mean every message was accepted, so look at each `status`: `accepted`, `duplicate`, `rejected` or `unsupported`.
- `400`: the batch is malformed. It isn't one JSON batch, its version isn't one the server speaks, or it has more than 100 messages. Nothing was stored. Fix the batch before you send it again, because resending it unchanged will not help. Hallproof keeps a note of each refused batch or message (its ID, kind, status and reason, never the body) for 30 days, up to the newest 1000 per key, and you can read them at `GET /api/v1/ingest-rejections`.
- `401`: the bearer token is missing, malformed, unknown or revoked.
- `413`: the batch is over 8 MiB. Split it and send the halves.
- `500`: Hallproof failed while storing the batch. Send the whole batch again. Messages it stored before the failure come back `duplicate`, so a resend is always safe.

Retry 500, 502, 503, 504 and network errors with backoff. Retry 429 the same way, after the `Retry-After` header if there is one. Never retry a 400 or a 401 unchanged.

## The kinds

| Kind | Body | What it is |
|---|---|---|
| `config_snapshot` | [`config_snapshot.schema.json`](schema/config_snapshot.schema.json) | A system's settings at one moment |
| `population` | [`population.schema.json`](schema/population.schema.json) | A list of things, such as every staff user, each with a unique string `id` |
| `event_proof` | [`event_proof.schema.json`](schema/event_proof.schema.json) | A signed run of audit chain events, ending at a checkpoint, that backs up the cited events |
| `heartbeat` | [`heartbeat.schema.json`](schema/heartbeat.schema.json) | A collector saying it's still running. Not evidence |

Every evidence body carries a `title`, an optional `description`, and `tests`: the keys of the controls' tests it supports, such as `mfa-enforced`. That's how a piece of evidence lands on the right test in Hallproof.

An event proof's field names mirror [Chronicle](https://github.com/xraph/chronicle)'s `audit.Event` and `checkpoint.Checkpoint`. Hallproof checks the hash chain and the checkpoint's Ed25519 signature against a public key you pinned for the system, so a proof only counts if whoever signed the chain is someone you already trust.

## Canonical JSON and hashes

Snapshots and populations carry a `hash` of their content, so you and Hallproof can agree on what was collected without sharing code. Both hashes are `sha256:` followed by 64 lowercase hex digits, taken over a canonical JSON form:

- Object keys are sorted bytewise (so `"B"` sorts before `"a"`), at every level.
- There's no whitespace outside strings.
- Numbers are written exactly as the sender wrote them. `1.10` stays `1.10`, and `1e3` stays `1e3`. Don't parse them into floats and print them back.
- Strings are escaped the way JSON requires and no further: `<`, `>` and `&` stay as they are, and non-ASCII text stays UTF-8.
- Arrays keep their order.

A snapshot's hash is sha256 of the canonical form of `settings`.

A population's hash ignores item order. Write each item in canonical form, sort those lines bytewise, join them with a single `\n` (no trailing newline), and take sha256 of the result.

[`vectors.json`](vectors.json) has inputs with their canonical forms and hashes. For populations, `canonical` is the sorted, joined lines, which is exactly what gets hashed. If your implementation reproduces every vector, Hallproof will accept your hashes.

## Compatibility

The batch `version` changes only for a breaking change. A new kind, or a new optional field in an existing body, isn't breaking.

A receiver ignores fields it doesn't know, which is why every schema here allows extra properties. A receiver that gets a kind it doesn't know answers `unsupported` for that message alone and carries on with the rest. Read `unsupported` as "this server is older than I am". It isn't an error, and sending the same message again won't change the answer.

## Heartbeats

A heartbeat says a collector is still alive. Send one per collector on a fixed interval, whether or not anything changed, each with a fresh random ID. Put the interval in `every_seconds` so Hallproof can tell when one is late. Hallproof keeps the newest heartbeat per collector, so it can flag one that has gone quiet even when its evidence hasn't changed in weeks.

Leave the collector's error text out of a heartbeat. Set `healthy` to false and let `last_success` say how long it's been. Error messages can carry customer data, and Hallproof never needs it.

A Hallproof that predates heartbeats answers `unsupported`, and it notes every message it can't take. Hold heartbeats back for a while when that happens, instead of filling the server's notes with them.

## What witness does on top

None of this is part of the protocol, and Hallproof doesn't check it. It's how the Go SDK behaves, written down so SDKs in other languages can match it.

An evidence message's ID is the collector's key, a colon, and the hex sha256 of the body's canonical JSON, as in `auth-settings:6f1e...`. When several copies of an app collect the same state they build the same ID, so Hallproof keeps one copy and answers `duplicate` to the rest, and when a developer edits a collector's title or tests the body changes and the ID changes with it, which stops the new body being rejected as a reused ID. Heartbeat IDs are `hb:`, the key, a colon, and 32 random hex digits.

A collector's evidence goes out on its first run and after that only when its content hash changes. Heartbeats cover the quiet stretches.

After one `unsupported` answer, witness stops sending that kind for an hour.

Backoff starts at one second and doubles up to five minutes, with full jitter. A message bigger than a whole batch is rejected on the client and never sent.

Collector keys are 1 to 100 characters of lowercase letters, digits, `.`, `_` and `-`, and start with a letter or digit.
