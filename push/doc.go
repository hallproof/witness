// Package push is the wire protocol for sending evidence to Hallproof.
//
// A sender collects evidence from a system (a settings snapshot, a list of
// users, a signed slice of an audit chain) and posts it to Hallproof's ingest
// API as a Batch. Each Message in the batch carries one piece of evidence. The
// reply is a Response with one Result per message, in the same order.
//
// It is part of github.com/hallproof/witness, whose root module imports only
// the standard library. You don't need Go to push, though: everything a
// sender in another language has to get right is written down below, and in
// spec/protocol.md in the witness repository.
//
// # Sending a batch
//
// POST the batch as JSON to /api/v1/ingest with your system's ingest key as
// the bearer token:
//
//	Authorization: Bearer hpk_...
//
// The key says which organisation and system the evidence is for, so the
// request carries nothing else to say so. A batch is at most MaxBatchBytes
// (8 MiB) encoded and MaxMessages (100) messages.
//
// # Messages
//
// Every message needs an ID, a kind, and a body. The ID rules:
//
//   - It is 1 to 200 bytes of UTF-8 text with no NUL bytes.
//   - It appears once in its batch. Two messages with the same ID in one
//     batch are both rejected.
//   - It stays unique for its system for ever (see Compatibility).
//
// collected_at is the time you collected the evidence, in RFC 3339. It is
// required for every kind this version defines, and it can't be more than
// five minutes ahead of Hallproof's clock. A message that breaks any of
// these rules is answered "rejected", with the reason in its error, and the
// rest of the batch carries on. Hallproof keeps a note of every message it
// answers "rejected" or "unsupported", the same way it does for a refused
// batch (see Status codes).
//
// # Status codes
//
// The HTTP status tells you what happened to the batch as a whole:
//
//   - 200: Hallproof read the batch. Look at each message's Result to see
//     what happened to it; a 200 doesn't mean every message was accepted.
//   - 400: the batch is malformed. It isn't one JSON batch, its version isn't
//     one this server speaks, or it has more than MaxMessages messages.
//     No evidence was stored. Fix the batch before you send it again.
//     Hallproof keeps a note of each refused batch or message (its ID,
//     kind, status and reason, never the body) for 30 days, up to the
//     newest 1000 per key, and you can read them at
//     GET /api/v1/ingest-rejections.
//   - 401: the bearer token is missing, malformed, unknown or revoked.
//   - 413: the batch is over 8 MiB. Split it into smaller batches.
//   - 500: Hallproof failed while storing the batch. Send the whole batch
//     again. Messages it stored before the failure come back "duplicate",
//     with their evidence IDs, so a resend is always safe.
//
// # Compatibility
//
// The batch version changes only for a breaking change. Adding a new kind of
// message, or a new optional field to an existing body, is not breaking.
//
// A receiver ignores fields it does not know. If it gets a kind it does not
// know, it answers "unsupported" for that message alone and carries on with
// the rest of the batch.
//
// A sender that gets "unsupported" should read it as "this server is older
// than I am". It is not an error, and retrying will not help.
//
// A message ID is the sender's idempotency key. Sending the same ID again
// with the same content is safe and is answered "duplicate". An ID must stay
// unique for its system for ever, so never reuse one for different content.
//
// # Heartbeats
//
// A heartbeat says a collector is still running. Send one per collector on a
// fixed interval, whether or not anything changed, with a fresh random ID
// each time. A receiver keeps the latest one per collector and doesn't treat
// it as evidence, so a collector that goes quiet shows up even when its
// evidence hasn't changed in weeks.
//
// A receiver older than this kind answers "unsupported". A sender should then
// hold heartbeats back for a while rather than keep sending them: the
// receiver notes every message it can't take.
//
// # Hashes
//
// SnapshotHash and PopulationHash let a sender and Hallproof agree on what
// was collected without sharing code. Both are "sha256:" followed by hex, and
// both are computed over the canonical JSON form that Canonical produces:
// object keys sorted bytewise, no extra whitespace, numbers kept as the exact
// text the sender wrote.
package push
