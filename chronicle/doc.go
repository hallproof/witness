// Package chronicle gives witness a real chain: the Chronicle audit trail
// your app already runs. You import it as wchronicle.
//
// In a Forge app you only need the blank import next to witness/forge:
//
//	import _ "github.com/hallproof/witness/chronicle"
//
// The adapter registers itself as a chain adapter, so witness/forge
// attaches it before every other library. It looks for a
// *chronicle.Chronicle in the container first (an app that builds Chronicle
// itself provides that), then for the chronicle.Emitter that Chronicle's
// own Forge extension provides, which it type-asserts. If neither is
// there, witness starts without a chain and event recording stays off.
//
// Outside Forge, build the chain yourself and hand it to witness:
//
//	ch, err := wchronicle.New(trail, wchronicle.Scope{AppID: "platform", TenantID: "staff"})
//	if err != nil {
//		return err
//	}
//	w, err := witness.New(witness.Options{Endpoint: url, IngestKey: key, Chain: ch})
//	if err != nil {
//		return err
//	}
//	if err := ch.Register(w); err != nil { // the platform-stream snapshot
//		return err
//	}
//
// # Recording
//
// Record writes every event to the platform scope you give New, whatever
// the request's context says. Chronicle keeps one stream per app and
// tenant, and witness proves the platform's stream, so staff evidence has
// to land there. An event's own TenantID doesn't move it to a customer's
// stream; when it differs from the platform's, it's kept in the metadata
// under "tenant_id". Action, Resource and Category are required. Outcome
// defaults to "success" and Severity to "info".
//
// # Proving
//
// Prove takes the checkpoint after the one the scheduler last proved, or
// the newest checkpoint after a restart, and returns the segment Hallproof
// verifies: from the first cited event to the checkpoint's end, every event
// with its hash, and the signed checkpoint. Before it returns, it checks
// what Hallproof will check, so a broken chain is an error in your logs and
// not a rejected proof. A checkpoint that doesn't link to the one before it
// is an error too, since that means one was deleted or forged.
//
// Two limits decide which cited events make it into a proof. A segment
// holds at most WithMaxSegment events (2000 by default, at most 10000), so
// keep Chronicle's checkpoints at or below that size; Prove logs how many
// citations it had to drop. And Hallproof only checks chronicle/v4 digests,
// so events written under an older scheme, or under Chronicle's keyed v5
// scheme, can't be proven. Keep the platform stream on the default plain
// v4 digest: Chronicle won't let a stream go back once it's keyed.
//
// # What it sends
//
// Proofs carry Chronicle events as recorded: IDs, scope, user, IP, user
// agent, request and session IDs, action, resource, outcome, reason and
// metadata. That's why library adapters keep event proofs off by default.
// Record only what you'd show an auditor, and keep request bodies and
// other content out of the metadata.
//
// The chronicle.platform-stream snapshot (test audit-chain-verifies) sends
// the platform stream's ID, digest scheme and head sequence, and its newest
// checkpoint's ID, time, end sequence, key ID and algorithm, plus how many
// events were recorded after it. No event content.
//
// # Options
//
// WithStream names more streams Prove accepts besides Platform (a full
// Chronicle stream ID works too). WithMaxSegment sets the segment limit.
// WithSigner checks each checkpoint's signature with your app's own
// checkpoint.Signer before a proof leaves. WithLogger sets the logger.
// In Forge, the adapter's config section takes the first two:
//
//	extensions:
//	  witness:
//	    adapters:
//	      chronicle:
//	        max_segment: 2000
//	        streams:
//	          billing: {app_id: platform, tenant_id: billing-staff}
//
// # Gaps in Chronicle
//
// You don't need a Chronicle change for any of this, but three would help.
// The checkpoint scheduler is private to Chronicle's Forge extension, so an
// app that builds Chronicle itself has to write its own loop to seal
// checkpoints. audit.Query can't filter by stream and sequence range, so
// Prove reads every event in a checkpoint, a thousand at a time, to find
// the ones to cite. And the Forge extension provides only chronicle.Emitter,
// which is why the adapter type-asserts.
package chronicle
