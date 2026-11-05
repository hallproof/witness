package chronicle_test

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"

	"github.com/hallproof/witness/push"
)

// pinnedKey is the one checkpoint key a test pins, as Hallproof pins a
// system's keys.
type pinnedKey struct {
	id  string
	pub ed25519.PublicKey
}

// verifyProof mirrors Hallproof's evidence.VerifyProof, steps 1 to 6, after
// the round trip a proof takes on the wire: witness's canonical JSON, read
// back with json.Number the way Hallproof's ingest decodes it.
func verifyProof(ctx context.Context, sent *push.EventProof, key pinnedKey) error {
	if sent == nil {
		return fmt.Errorf("no proof")
	}
	body, err := push.Canonical(sent)
	if err != nil {
		return err
	}
	p, err := push.DecodeBody[push.EventProof](push.Message{Kind: push.KindEventProof, Body: body})
	if err != nil {
		return err
	}
	cp := p.Checkpoint

	// 1. checkKey.
	if cp.Algorithm != checkpoint.AlgorithmEd25519 {
		return fmt.Errorf("algorithm %q", cp.Algorithm)
	}
	if cp.SignKeyID != key.id || len(key.pub) != ed25519.PublicKeySize {
		return fmt.Errorf("key %q is not pinned", cp.SignKeyID)
	}

	// 2. checkSignature.
	if _, err = id.Parse(cp.ID); err != nil {
		return fmt.Errorf("checkpoint ID %q: %w", cp.ID, err)
	}
	streamID, err := id.Parse(cp.StreamID)
	if err != nil {
		return fmt.Errorf("stream ID %q: %w", cp.StreamID, err)
	}
	payload := checkpoint.CanonicalPayload(&checkpoint.Checkpoint{
		StreamID: streamID, AppID: cp.AppID, TenantID: cp.TenantID,
		FromSeq: cp.FromSeq, ToSeq: cp.ToSeq, FromHash: cp.FromHash, ToHash: cp.ToHash,
		EventCount: cp.EventCount, PrevCheckpoint: cp.PrevCheckpoint, CreatedAt: cp.CreatedAt,
	})
	if payload != cp.SignedPayload {
		return fmt.Errorf("the checkpoint's fields don't match its signed payload")
	}
	if !ed25519.Verify(key.pub, []byte(cp.SignedPayload), cp.Signature) {
		return fmt.Errorf("signature does not verify")
	}

	// 3. checkRetired: the test key is never retired.

	// 4. checkSegment.
	seg := p.Segment
	if len(seg) == 0 {
		return fmt.Errorf("the segment has no events")
	}
	if len(seg) > push.MaxSegment {
		return fmt.Errorf("the segment has %d events", len(seg))
	}
	if seg[0].Sequence < cp.FromSeq {
		return fmt.Errorf("the segment starts at %d, before %d", seg[0].Sequence, cp.FromSeq)
	}
	for i := 1; i < len(seg); i++ {
		if seg[i].Sequence != seg[i-1].Sequence+1 {
			return fmt.Errorf("not contiguous: %d follows %d", seg[i].Sequence, seg[i-1].Sequence)
		}
	}
	if last := seg[len(seg)-1].Sequence; last != cp.ToSeq {
		return fmt.Errorf("the segment ends at %d, not %d", last, cp.ToSeq)
	}
	for _, e := range seg {
		if e.StreamID != cp.StreamID || e.AppID != cp.AppID || e.TenantID != cp.TenantID {
			return fmt.Errorf("event %d is outside the checkpoint's stream", e.Sequence)
		}
	}

	// 5. checkChain.
	h, err := hash.NewChain(hash.SchemePlainV4, nil)
	if err != nil {
		return err
	}
	for i, e := range seg {
		if hash.Scheme(e.HashScheme) != hash.SchemePlainV4 {
			return fmt.Errorf("event %d has hash scheme %q", e.Sequence, e.HashScheme)
		}
		digest, _, err := h.Compute(ctx, e.PrevHash, &audit.Event{
			Timestamp: e.Timestamp, Sequence: e.Sequence, Hash: e.Hash, PrevHash: e.PrevHash,
			AppID: e.AppID, TenantID: e.TenantID, UserID: e.UserID, IP: e.IP,
			UserAgent: e.UserAgent, RequestID: e.RequestID, SessionID: e.SessionID,
			Action: e.Action, Resource: e.Resource, Category: e.Category, ResourceID: e.ResourceID,
			Metadata: e.Metadata, Outcome: e.Outcome, Severity: e.Severity, Reason: e.Reason,
			SubjectID: e.SubjectID, ExactMetadata: e.ExactMetadata,
			HashScheme: e.HashScheme, HashKeyID: e.HashKeyID,
		})
		if err != nil {
			return err
		}
		if digest != e.Hash {
			return fmt.Errorf("event %d does not hash to its recorded hash", e.Sequence)
		}
		if i > 0 && e.PrevHash != seg[i-1].Hash {
			return fmt.Errorf("event %d does not link to event %d", e.Sequence, seg[i-1].Sequence)
		}
	}
	if seg[len(seg)-1].Hash != cp.ToHash {
		return fmt.Errorf("the segment's last hash is not the checkpoint's")
	}
	if seg[0].Sequence == cp.FromSeq && seg[0].PrevHash != cp.FromHash {
		return fmt.Errorf("event %d does not link to the checkpoint's starting hash", seg[0].Sequence)
	}

	// 6. checkCited.
	if len(p.Cited) == 0 {
		return fmt.Errorf("the proof cites no event")
	}
	first, last := seg[0].Sequence, seg[len(seg)-1].Sequence
	seen := map[uint64]bool{}
	for _, n := range p.Cited {
		if seen[n] {
			return fmt.Errorf("event %d cited twice", n)
		}
		seen[n] = true
		if n < first || n > last {
			return fmt.Errorf("event %d is outside the segment", n)
		}
	}
	return nil
}
