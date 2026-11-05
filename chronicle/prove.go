package chronicle

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"

	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/push"
)

// page is how many events Prove reads from the store at a time.
const page = 1000

// Prove proves the checkpoint after r.From on r.Stream, or the stream's
// newest checkpoint when r.From is empty or unknown. r.Stream is Platform,
// a name WithStream added, or the Chronicle stream ID of one of those
// streams; any other stream is an error. Starting from the
// newest is deliberate: the scheduler forgets r.From on every restart,
// and the oldest would re-walk the whole history on each deploy.
//
// The proof cites the checkpoint's events with an action in r.Actions,
// and its segment runs from the first of those to the checkpoint's end,
// at most the chain's max segment long and only over chronicle/v4 events,
// the only digests Hallproof checks. A checkpoint with nothing to cite
// gives a proof with no Cited and no Segment, which moves the scheduler
// on without a push.
//
// Prove returns chain.ErrNothingNew when the stream has no events or no
// checkpoint after r.From. Any other error means the chain can't be proven
// as it stands: a checkpoint that doesn't link to the one before it, an
// event that no longer hashes to what was signed, or a gap.
func (c *Chain) Prove(ctx context.Context, r chain.ProofRequest) (*push.EventProof, error) {
	streamID, err := c.resolve(ctx, r.Stream)
	if err != nil {
		return nil, err
	}
	cp, err := c.next(ctx, streamID, r.From)
	if err != nil {
		return nil, err
	}
	if r.To != "" {
		to, err := c.checkpoint(ctx, r.To)
		if err != nil {
			return nil, fmt.Errorf("witness/chronicle: checkpoint %q: %w", r.To, err)
		}
		if cp.ToSeq > to.ToSeq {
			return nil, chain.ErrNothingNew
		}
	}
	if err := c.checkCheckpoint(ctx, cp); err != nil {
		return nil, err
	}

	actions := make(map[string]bool, len(r.Actions))
	for _, a := range r.Actions {
		actions[a] = true
	}
	// Only the last maxSegment events can go in a segment, so only they
	// are kept while the rest of the checkpoint is read for citations.
	keepFrom := cp.FromSeq
	n := uint64(c.maxSegment) // #nosec G115 -- maxSegment is between 1 and push.MaxSegment
	if cp.ToSeq >= n && cp.ToSeq-n+1 > keepFrom {
		keepFrom = cp.ToSeq - n + 1
	}
	var (
		cited     []uint64
		tail      []*audit.Event
		lastNonV4 uint64
	)
	for from := cp.FromSeq; from <= cp.ToSeq; {
		to := min(from+page-1, cp.ToSeq)
		evs, err := c.store.EventRange(ctx, streamID, from, to)
		if err != nil {
			return nil, fmt.Errorf("witness/chronicle: read events %d to %d: %w", from, to, err)
		}
		for _, e := range evs {
			if e.Sequence < from || e.Sequence > to {
				continue
			}
			if hash.Scheme(e.HashScheme) != hash.SchemePlainV4 {
				lastNonV4 = max(lastNonV4, e.Sequence)
			}
			if actions[e.Action] {
				cited = append(cited, e.Sequence)
			}
			if e.Sequence >= keepFrom {
				tail = append(tail, e)
			}
		}
		if to == cp.ToSeq {
			break
		}
		from = to + 1
	}

	lo := max(keepFrom, lastNonV4+1)
	slices.Sort(cited)
	cited = slices.Compact(cited)
	var provable []uint64
	for _, n := range cited {
		if n >= lo {
			provable = append(provable, n)
		}
	}
	if dropped := len(cited) - len(provable); dropped > 0 {
		c.log.Warn("witness/chronicle: cited events can't be proven from this checkpoint",
			"checkpoint", cp.ID.String(), "dropped", dropped, "first_provable", lo,
			"reason", "older than the max segment or not chronicle/v4")
	}
	pc := pushCheckpoint(cp)
	if len(provable) == 0 {
		return &push.EventProof{Checkpoint: pc}, nil
	}

	first := provable[0]
	var raw []*audit.Event
	for _, e := range tail {
		if e.Sequence >= first {
			raw = append(raw, e)
		}
	}
	slices.SortFunc(raw, func(a, b *audit.Event) int { return cmp.Compare(a.Sequence, b.Sequence) })
	if err := c.checkSegment(ctx, cp, first, raw); err != nil {
		return nil, err
	}
	seg := make([]push.ChainEvent, len(raw))
	for i, e := range raw {
		seg[i] = chainEvent(e)
	}
	return &push.EventProof{Cited: provable, Segment: seg, Checkpoint: pc}, nil
}

// resolve finds the stream ID for name: one of the chain's stream names
// (Platform and those WithStream added), or the Chronicle stream ID of one
// of those streams. Any other stream, a customer tenant's included, is an
// error that lists the names Prove takes. A named scope with no stream yet
// is chain.ErrNothingNew.
func (c *Chain) resolve(ctx context.Context, name string) (id.ID, error) {
	if s, ok := c.streams[name]; ok {
		st, err := c.store.GetStreamByScope(ctx, s.AppID, s.TenantID)
		if errors.Is(err, xchronicle.ErrStreamNotFound) {
			return id.ID{}, chain.ErrNothingNew
		}
		if err != nil {
			return id.ID{}, fmt.Errorf("witness/chronicle: stream %q: %w", name, err)
		}
		return st.ID, nil
	}
	streamID, err := id.ParseWithPrefix(name, id.PrefixStream)
	if err != nil {
		return id.ID{}, c.unknownStream(name)
	}
	for _, alias := range c.streamNames() {
		s := c.streams[alias]
		st, err := c.store.GetStreamByScope(ctx, s.AppID, s.TenantID)
		if errors.Is(err, xchronicle.ErrStreamNotFound) {
			continue
		}
		if err != nil {
			return id.ID{}, fmt.Errorf("witness/chronicle: stream %q: %w", alias, err)
		}
		if st.ID.String() == streamID.String() {
			return st.ID, nil
		}
	}
	return id.ID{}, c.unknownStream(name)
}

// streamNames are the chain's stream names, sorted.
func (c *Chain) streamNames() []string {
	names := make([]string, 0, len(c.streams))
	for n := range c.streams {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// unknownStream is the error for a stream Prove doesn't take.
func (c *Chain) unknownStream(name string) error {
	quoted := make([]string, 0, len(c.streams))
	for _, n := range c.streamNames() {
		quoted = append(quoted, strconv.Quote(n))
	}
	return fmt.Errorf("witness/chronicle: Prove doesn't take stream %q; it takes %s, or the Chronicle stream ID of one of those streams", name, strings.Join(quoted, ", "))
}

// checkpoint looks a checkpoint up by its ID text.
func (c *Chain) checkpoint(ctx context.Context, s string) (*checkpoint.Checkpoint, error) {
	cid, err := id.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %q isn't a Chronicle ID", checkpoint.ErrNotFound, s)
	}
	return c.checkpoints.GetCheckpoint(ctx, cid)
}

// next is the checkpoint to prove: the one after from, or the newest when
// from is empty or isn't one of the stream's.
func (c *Chain) next(ctx context.Context, streamID id.ID, from string) (*checkpoint.Checkpoint, error) {
	if from != "" {
		prev, err := c.checkpoint(ctx, from)
		switch {
		case errors.Is(err, checkpoint.ErrNotFound):
			c.log.Warn("witness/chronicle: the last proven checkpoint is gone; proving the newest", "checkpoint", from)
		case err != nil:
			return nil, fmt.Errorf("witness/chronicle: checkpoint %q: %w", from, err)
		case prev.StreamID.String() != streamID.String():
			c.log.Warn("witness/chronicle: the last proven checkpoint is in another stream; proving the newest",
				"checkpoint", from, "stream", streamID.String())
		default:
			return c.after(ctx, streamID, prev)
		}
	}
	cp, err := c.checkpoints.LatestCheckpoint(ctx, streamID)
	if errors.Is(err, checkpoint.ErrNotFound) {
		return nil, chain.ErrNothingNew
	}
	if err != nil {
		return nil, fmt.Errorf("witness/chronicle: newest checkpoint: %w", err)
	}
	return cp, nil
}

// after is the checkpoint that follows prev, which must link to it.
func (c *Chain) after(ctx context.Context, streamID id.ID, prev *checkpoint.Checkpoint) (*checkpoint.Checkpoint, error) {
	seq := prev.ToSeq + 1
	next, err := c.checkpoints.CheckpointsInRange(ctx, streamID, seq, seq)
	if err != nil {
		return nil, fmt.Errorf("witness/chronicle: checkpoints after %s: %w", prev.ID.String(), err)
	}
	if len(next) == 0 {
		return nil, chain.ErrNothingNew
	}
	cp := next[0]
	if cp.FromSeq != seq {
		return nil, fmt.Errorf("witness/chronicle: checkpoint %s starts at %d, not %d right after checkpoint %s; a checkpoint was deleted or forged",
			cp.ID.String(), cp.FromSeq, seq, prev.ID.String())
	}
	if want := checkpoint.Digest(prev.SignedPayload); cp.PrevCheckpoint != want {
		return nil, fmt.Errorf("witness/chronicle: checkpoint %s doesn't link to checkpoint %s before it; a checkpoint was deleted or forged",
			cp.ID.String(), prev.ID.String())
	}
	return cp, nil
}

// checkCheckpoint refuses a checkpoint Hallproof would refuse: one not
// signed with Ed25519, or whose fields don't say what was signed.
func (c *Chain) checkCheckpoint(ctx context.Context, cp *checkpoint.Checkpoint) error {
	if cp.Algorithm != checkpoint.AlgorithmEd25519 {
		return fmt.Errorf("witness/chronicle: checkpoint %s is signed with %q; Hallproof checks %s signatures",
			cp.ID.String(), cp.Algorithm, checkpoint.AlgorithmEd25519)
	}
	if checkpoint.CanonicalPayload(cp) != cp.SignedPayload {
		return fmt.Errorf("witness/chronicle: checkpoint %s's fields don't match its signed payload", cp.ID.String())
	}
	if c.signer != nil {
		if err := c.signer.Verify(ctx, []byte(cp.SignedPayload), cp.Signature, cp.SignKeyID); err != nil {
			return fmt.Errorf("witness/chronicle: checkpoint %s: %w", cp.ID.String(), err)
		}
	}
	return nil
}

// checkSegment checks seg the way Hallproof will: every event from first
// to the checkpoint's end, in its stream, linked, each hashing to what was
// recorded, and ending at the hash the checkpoint signed.
func (c *Chain) checkSegment(ctx context.Context, cp *checkpoint.Checkpoint, first uint64, seg []*audit.Event) error {
	if want := cp.ToSeq - first + 1; uint64(len(seg)) != want {
		return fmt.Errorf("witness/chronicle: stream %s has %d events from %d to %d, not %d; it has gaps",
			cp.StreamID.String(), len(seg), first, cp.ToSeq, want)
	}
	h, err := hash.NewChain(hash.SchemePlainV4, nil)
	if err != nil {
		return fmt.Errorf("witness/chronicle: %w", err)
	}
	for i, e := range seg {
		if e.Sequence != first+uint64(i) {
			return fmt.Errorf("witness/chronicle: event %d is where %d should be", e.Sequence, first+uint64(i))
		}
		if e.StreamID.String() != cp.StreamID.String() || e.AppID != cp.AppID || e.TenantID != cp.TenantID {
			return fmt.Errorf("witness/chronicle: event %d isn't in checkpoint %s's stream", e.Sequence, cp.ID.String())
		}
		if i > 0 && e.PrevHash != seg[i-1].Hash {
			return fmt.Errorf("witness/chronicle: event %d doesn't link to event %d", e.Sequence, seg[i-1].Sequence)
		}
		digest, _, err := h.Compute(ctx, e.PrevHash, e)
		if err != nil {
			return fmt.Errorf("witness/chronicle: hash event %d: %w", e.Sequence, err)
		}
		if digest != e.Hash {
			return fmt.Errorf("witness/chronicle: event %d no longer hashes to its recorded hash; it was changed after it was written", e.Sequence)
		}
	}
	if seg[len(seg)-1].Hash != cp.ToHash {
		return fmt.Errorf("witness/chronicle: event %d's hash isn't the one checkpoint %s signed", cp.ToSeq, cp.ID.String())
	}
	if first == cp.FromSeq && seg[0].PrevHash != cp.FromHash {
		return fmt.Errorf("witness/chronicle: event %d doesn't link to checkpoint %s's starting hash", first, cp.ID.String())
	}
	return nil
}

// chainEvent is e as Hallproof reads it: every field the digest covers,
// and the IDs. Erasure state and the encryption key ID are left out.
func chainEvent(e *audit.Event) push.ChainEvent {
	return push.ChainEvent{
		ID: e.ID.String(), Timestamp: e.Timestamp, Sequence: e.Sequence, Hash: e.Hash, PrevHash: e.PrevHash,
		StreamID: e.StreamID.String(), AppID: e.AppID, TenantID: e.TenantID, UserID: e.UserID, IP: e.IP,
		UserAgent: e.UserAgent, RequestID: e.RequestID, SessionID: e.SessionID,
		Action: e.Action, Resource: e.Resource, Category: e.Category, ResourceID: e.ResourceID,
		Metadata: e.Metadata, Outcome: e.Outcome, Severity: e.Severity, Reason: e.Reason,
		SubjectID: e.SubjectID, ExactMetadata: e.ExactMetadata, HashScheme: e.HashScheme, HashKeyID: e.HashKeyID,
	}
}

// pushCheckpoint is cp field for field.
func pushCheckpoint(cp *checkpoint.Checkpoint) push.Checkpoint {
	return push.Checkpoint{
		ID: cp.ID.String(), StreamID: cp.StreamID.String(), AppID: cp.AppID, TenantID: cp.TenantID,
		FromSeq: cp.FromSeq, ToSeq: cp.ToSeq, FromHash: cp.FromHash, ToHash: cp.ToHash,
		EventCount: cp.EventCount, PrevCheckpoint: cp.PrevCheckpoint, Algorithm: cp.Algorithm,
		SignKeyID: cp.SignKeyID, Signature: cp.Signature, SignedPayload: cp.SignedPayload, CreatedAt: cp.CreatedAt,
	}
}
