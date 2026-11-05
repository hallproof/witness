package chronicle_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"

	"github.com/hallproof/witness/chain"
	wchronicle "github.com/hallproof/witness/chronicle"
	"github.com/hallproof/witness/push"
)

func seqs(p *push.EventProof) []uint64 {
	out := make([]uint64, 0, len(p.Segment))
	for _, e := range p.Segment {
		out = append(out, e.Sequence)
	}
	return out
}

func span(from, to uint64) []uint64 {
	var out []uint64
	for n := from; n <= to; n++ {
		out = append(out, n)
	}
	return out
}

func TestProveVerifies(t *testing.T) {
	f := newFixture(t)
	f.record(3, "user.login", nil)
	f.record(2, "key.create", nil)
	f.record(1, "user.login", nil)
	cp := f.checkpoint()

	p := f.mustProve("", "user.login")
	if !slices.Equal(p.Cited, []uint64{1, 2, 3, 6}) {
		t.Fatalf("cited %v", p.Cited)
	}
	if !slices.Equal(seqs(p), span(1, 6)) {
		t.Fatalf("segment %v", seqs(p))
	}
	if p.Checkpoint.ID != cp.ID.String() || p.Checkpoint.ToHash != cp.ToHash || p.Checkpoint.SignKeyID != f.keyID {
		t.Fatalf("checkpoint %+v", p.Checkpoint)
	}
	if p.Title != "" || len(p.Tests) != 0 {
		t.Fatalf("Common should be left to the collector: %+v", p.Common)
	}
	f.mustVerify(p)

	// The in-test verifier isn't vacuous: a changed event, a cut link and a
	// stray citation all fail.
	tampered := *p
	tampered.Segment = slices.Clone(p.Segment)
	tampered.Segment[2].ResourceID = "sess-other"
	if f.verify(&tampered) == nil {
		t.Fatal("a changed event verified")
	}
	cut := *p
	cut.Segment = p.Segment[1:]
	cut.Cited = []uint64{2}
	cut.Segment = slices.Clone(cut.Segment)
	cut.Segment[0].PrevHash = "00"
	if f.verify(&cut) == nil {
		t.Fatal("a cut link verified")
	}
	stray := *p
	stray.Cited = []uint64{7}
	if f.verify(&stray) == nil {
		t.Fatal("a citation outside the segment verified")
	}
}

func TestProveCitesFromTheFirstCitedEvent(t *testing.T) {
	f := newFixture(t)
	f.record(4, "key.create", nil)
	f.record(1, "user.login", nil)
	f.record(2, "key.create", nil)
	f.checkpoint()

	p := f.mustProve("", "user.login")
	if !slices.Equal(p.Cited, []uint64{5}) || !slices.Equal(seqs(p), span(5, 7)) {
		t.Fatalf("cited %v, segment %v", p.Cited, seqs(p))
	}
	f.mustVerify(p)
}

func TestProveWalksCheckpointsInOrder(t *testing.T) {
	f := newFixture(t)
	f.record(2, "user.login", nil)
	cp1 := f.checkpoint()
	f.record(2, "user.login", nil)
	cp2 := f.checkpoint()
	f.record(2, "user.login", nil)
	cp3 := f.checkpoint()

	// From nothing, the newest: a restart doesn't re-walk history.
	p := f.mustProve("", "user.login")
	if p.Checkpoint.ID != cp3.ID.String() {
		t.Fatalf("from nothing: %s, want the newest %s", p.Checkpoint.ID, cp3.ID)
	}

	p = f.mustProve(cp1.ID.String(), "user.login")
	if p.Checkpoint.ID != cp2.ID.String() || !slices.Equal(p.Cited, []uint64{3, 4}) || !slices.Equal(seqs(p), span(3, 4)) {
		t.Fatalf("after cp1: checkpoint %s, cited %v, segment %v", p.Checkpoint.ID, p.Cited, seqs(p))
	}
	f.mustVerify(p)

	p = f.mustProve(cp2.ID.String(), "user.login")
	if p.Checkpoint.ID != cp3.ID.String() || !slices.Equal(seqs(p), span(5, 6)) {
		t.Fatalf("after cp2: checkpoint %s, segment %v", p.Checkpoint.ID, seqs(p))
	}
	f.mustVerify(p)

	if _, err := f.prove(cp3.ID.String(), "user.login"); !isNothingNew(err) {
		t.Fatalf("after cp3: %v, want ErrNothingNew", err)
	}

	// A checkpoint the store doesn't know, or that isn't an ID at all:
	// start again from the newest.
	for _, from := range []string{id.NewCheckpointID().String(), "not-an-id"} {
		p = f.mustProve(from, "user.login")
		if p.Checkpoint.ID != cp3.ID.String() {
			t.Fatalf("from %q: %s, want the newest", from, p.Checkpoint.ID)
		}
	}

	// To stops the walk.
	_, err := f.chain.Prove(context.Background(), chain.ProofRequest{
		Stream: wchronicle.Platform, From: cp1.ID.String(), To: cp1.ID.String(), Actions: []string{"user.login"},
	})
	if !isNothingNew(err) {
		t.Fatalf("past To: %v, want ErrNothingNew", err)
	}
	p, err = f.chain.Prove(context.Background(), chain.ProofRequest{
		Stream: wchronicle.Platform, From: cp1.ID.String(), To: cp2.ID.String(), Actions: []string{"user.login"},
	})
	if err != nil || p.Checkpoint.ID != cp2.ID.String() {
		t.Fatalf("up to To: %v, %v", p, err)
	}
}

func TestProveNothingNew(t *testing.T) {
	f := newFixture(t)
	if _, err := f.prove("", "user.login"); !isNothingNew(err) {
		t.Fatalf("no stream: %v", err)
	}
	f.record(2, "user.login", nil)
	if _, err := f.prove("", "user.login"); !isNothingNew(err) {
		t.Fatalf("no checkpoint: %v", err)
	}
	cp := f.checkpoint()
	f.mustProve("", "user.login")
	f.record(1, "user.login", nil) // recorded but not yet checkpointed
	if _, err := f.prove(cp.ID.String(), "user.login"); !isNothingNew(err) {
		t.Fatalf("nothing sealed after the last proof: %v", err)
	}
}

func TestProveNoCitedAdvances(t *testing.T) {
	f := newFixture(t)
	f.record(3, "user.login", nil)
	cp := f.checkpoint()

	for _, actions := range [][]string{{"key.create"}, nil} {
		p := f.mustProve("", actions...)
		if len(p.Cited) != 0 || len(p.Segment) != 0 {
			t.Fatalf("actions %v: cited %v, segment %v", actions, p.Cited, seqs(p))
		}
		if p.Checkpoint.ID != cp.ID.String() || p.Checkpoint.ToHash != cp.ToHash {
			t.Fatalf("actions %v: checkpoint %+v, want %s", actions, p.Checkpoint, cp.ID)
		}
	}
}

// forge appends a checkpoint over the platform stream's head that links to
// prev with the wrong digest, signed with the fixture's own key.
func (f *fixture) forge(prev *checkpoint.Checkpoint, prevDigest string) {
	f.t.Helper()
	st := f.stream()
	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), StreamID: st.ID, AppID: st.AppID, TenantID: st.TenantID,
		FromSeq: prev.ToSeq + 1, ToSeq: st.HeadSeq, FromHash: prev.ToHash, ToHash: st.HeadHash,
		EventCount: int64(st.HeadSeq - prev.ToSeq), PrevCheckpoint: prevDigest,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	sig, keyID, alg, err := f.signer.Sign(context.Background(), []byte(cp.SignedPayload))
	if err != nil {
		f.t.Fatal(err)
	}
	cp.Signature, cp.SignKeyID, cp.Algorithm = sig, keyID, alg
	if err := f.mem.AppendCheckpoint(context.Background(), cp); err != nil {
		f.t.Fatal(err)
	}
}

func TestProveRejectsBrokenLink(t *testing.T) {
	f := newFixture(t)
	f.record(2, "user.login", nil)
	cp1 := f.checkpoint()
	f.record(2, "user.login", nil)
	f.forge(cp1, strings.Repeat("0", 64))

	_, err := f.prove(cp1.ID.String(), "user.login")
	if err == nil || isNothingNew(err) {
		t.Fatalf("a checkpoint that doesn't link to the last one: %v, want an error", err)
	}
}

func TestProveRejectsTamperedEvent(t *testing.T) {
	f := newFixture(t)
	f.record(3, "user.login", nil)
	f.checkpoint()

	// The memory store hands out its own events, so this edits the stored
	// row the way someone with database access would.
	evs, err := f.mem.EventRange(context.Background(), f.stream().ID, 2, 2)
	if err != nil || len(evs) != 1 {
		t.Fatal(evs, err)
	}
	evs[0].UserID = "someone-else"

	if _, err := f.prove("", "user.login"); err == nil || isNothingNew(err) {
		t.Fatalf("a changed event: %v, want an error", err)
	}
}

func TestProveRespectsMaxSegment(t *testing.T) {
	f := newFixture(t, wchronicle.WithMaxSegment(5))
	f.record(12, "user.login", nil)
	f.checkpoint()

	p := f.mustProve("", "user.login")
	if !slices.Equal(seqs(p), span(8, 12)) || !slices.Equal(p.Cited, span(8, 12)) {
		t.Fatalf("segment %v, cited %v", seqs(p), p.Cited)
	}
	f.mustVerify(p)
}

func TestProveSkipsNonV4Prefix(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	store := f.trail.Store()

	// A stream that began under the retired chronicle/v2 scheme, then moved
	// to v4. Hallproof checks only v4 digests.
	st := &xchronicle.StreamInfo{ID: id.NewStreamID(), AppID: appID, TenantID: tenantID, Scheme: string(hash.SchemePlain), SchemeSince: 1}
	if err := store.CreateStreamInfo(ctx, st); err != nil {
		t.Fatal(err)
	}
	prev := ""
	for n := uint64(1); n <= 3; n++ {
		h := fmt.Sprintf("%064x", n)
		err := store.Append(ctx, &audit.Event{
			ID: id.NewAuditID(), Timestamp: time.Date(2026, 10, 1, 0, 0, int(n), 0, time.UTC), Sequence: n,
			Hash: h, PrevHash: prev, StreamID: st.ID, AppID: appID, TenantID: tenantID,
			Action: "user.login", Resource: "session", Category: "auth",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo, HashScheme: string(hash.SchemePlain),
		})
		if err != nil {
			t.Fatal(err)
		}
		prev = h
		if err := store.UpdateStreamHead(ctx, st.ID, h, n); err != nil {
			t.Fatal(err)
		}
	}
	f.record(3, "user.login", nil)
	cp := f.checkpoint()
	if cp.FromSeq != 1 || cp.ToSeq != 6 {
		t.Fatalf("checkpoint %d to %d", cp.FromSeq, cp.ToSeq)
	}

	p := f.mustProve("", "user.login")
	if !slices.Equal(seqs(p), span(4, 6)) || !slices.Equal(p.Cited, span(4, 6)) {
		t.Fatalf("segment %v, cited %v", seqs(p), p.Cited)
	}
	f.mustVerify(p)

	// A checkpoint with nothing provable cites nothing, so the scheduler
	// moves on.
	g := newFixture(t)
	st2 := &xchronicle.StreamInfo{ID: id.NewStreamID(), AppID: appID, TenantID: tenantID, Scheme: string(hash.SchemePlain), SchemeSince: 1}
	if err := g.trail.Store().CreateStreamInfo(ctx, st2); err != nil {
		t.Fatal(err)
	}
	if err := g.trail.Store().Append(ctx, &audit.Event{
		ID: id.NewAuditID(), Timestamp: time.Now().UTC(), Sequence: 1, Hash: fmt.Sprintf("%064x", 1),
		StreamID: st2.ID, AppID: appID, TenantID: tenantID, Action: "user.login", Resource: "session",
		Category: "auth", Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo, HashScheme: string(hash.SchemePlain),
	}); err != nil {
		t.Fatal(err)
	}
	if err := g.trail.Store().UpdateStreamHead(ctx, st2.ID, fmt.Sprintf("%064x", 1), 1); err != nil {
		t.Fatal(err)
	}
	g.checkpoint()
	if p := g.mustProve("", "user.login"); len(p.Cited) != 0 || len(p.Segment) != 0 {
		t.Fatalf("an all-v2 checkpoint: cited %v, segment %v", p.Cited, seqs(p))
	}
}

func TestProveMetadataRoundTrip(t *testing.T) {
	f := newFixture(t)
	f.record(1, "user.login", map[string]any{
		"count":  3,
		"ratio":  0.25,
		"big":    1e21,
		"neg":    -7,
		"html":   "<a&b>",
		"nested": map[string]any{"list": []any{1, "x", true, nil, 2.5}, "deep": map[string]any{"n": int64(1) << 53}},
	})

	// RecordOnce marks the event ExactMetadata, which the digest covers.
	_, err := f.trail.RecordOnce(context.Background(), acceptance.Request{
		Producer: "test", Installation: "chain", SourceKey: "event-exact", SourceFingerprint: "fp-exact", OrgID: tenantID,
		Event: &audit.Event{
			AppID: appID, TenantID: tenantID, Action: "user.login", Resource: "session", Category: "auth",
			Outcome: audit.OutcomeSuccess, Severity: audit.SeverityInfo, Timestamp: time.Date(2026, 11, 1, 10, 0, 0, 1, time.UTC),
			Metadata: map[string]any{"amount": json.Number("12.50"), "n": 4},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.checkpoint()

	p := f.mustProve("", "user.login")
	if len(p.Segment) != 2 || !p.Segment[1].ExactMetadata {
		t.Fatalf("segment %+v", p.Segment)
	}
	f.mustVerify(p)
}

func TestProveStreams(t *testing.T) {
	billing := wchronicle.Scope{AppID: appID, TenantID: "billing-staff"}
	f := newFixture(t, wchronicle.WithStream("billing", billing))
	ctx := context.Background()
	for range 2 {
		if err := f.trail.Info(ctx, "invoice.void", "invoice", "inv-1").Category("billing").
			AppID(billing.AppID).TenantID(billing.TenantID).Record(); err != nil {
			t.Fatal(err)
		}
	}
	st, err := f.trail.Store().GetStreamByScope(ctx, billing.AppID, billing.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cps.CheckpointStream(ctx, checkpoint.StreamHead{
		ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash,
	}); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"billing", st.ID.String()} {
		p, err := f.chain.Prove(ctx, chain.ProofRequest{Stream: name, Actions: []string{"invoice.void"}})
		if err != nil {
			t.Fatalf("stream %q: %v", name, err)
		}
		if !slices.Equal(p.Cited, []uint64{1, 2}) {
			t.Fatalf("stream %q: cited %v", name, p.Cited)
		}
		f.mustVerify(p)
	}

	if _, err := f.chain.Prove(ctx, chain.ProofRequest{Stream: "nope", Actions: []string{"x"}}); err == nil || isNothingNew(err) {
		t.Fatalf("an unknown stream name: %v, want an error", err)
	}
}

func TestProveChecksSignatureWithSigner(t *testing.T) {
	f := newFixture(t)
	f.record(2, "user.login", nil)
	f.checkpoint()

	// A signer that holds another key refuses the checkpoint.
	other := newFixture(t)
	c, err := wchronicle.New(f.trail, platform, wchronicle.WithSigner(other.signer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Prove(context.Background(), chain.ProofRequest{Stream: wchronicle.Platform, Actions: []string{"user.login"}}); err == nil || isNothingNew(err) {
		t.Fatalf("a signature the signer doesn't accept: %v, want an error", err)
	}

	c, err = wchronicle.New(f.trail, platform, wchronicle.WithSigner(f.signer))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Prove(context.Background(), chain.ProofRequest{Stream: wchronicle.Platform, Actions: []string{"user.login"}})
	if err != nil {
		t.Fatal(err)
	}
	f.mustVerify(p)
}

func TestProveRejectsGaps(t *testing.T) {
	f := newFixture(t)
	f.record(4, "user.login", nil)
	f.checkpoint()
	evs, err := f.mem.EventRange(context.Background(), f.stream().ID, 3, 3)
	if err != nil || len(evs) != 1 {
		t.Fatal(evs, err)
	}
	if _, err := f.mem.PurgeEvents(context.Background(), []id.ID{evs[0].ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.prove("", "user.login"); err == nil || isNothingNew(err) {
		t.Fatalf("a stream with a gap: %v, want an error", err)
	}
}

func TestProveFromAnotherStreamsCheckpoint(t *testing.T) {
	billing := wchronicle.Scope{AppID: appID, TenantID: "billing-staff"}
	f := newFixture(t, wchronicle.WithStream("billing", billing))
	ctx := context.Background()
	if err := f.trail.Info(ctx, "invoice.void", "invoice", "inv-1").Category("billing").
		AppID(billing.AppID).TenantID(billing.TenantID).Record(); err != nil {
		t.Fatal(err)
	}
	st, err := f.trail.Store().GetStreamByScope(ctx, billing.AppID, billing.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.cps.CheckpointStream(ctx, checkpoint.StreamHead{
		ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.record(2, "user.login", nil)
	cp := f.checkpoint()

	p := f.mustProve(other.ID.String(), "user.login")
	if p.Checkpoint.ID != cp.ID.String() {
		t.Fatalf("from another stream's checkpoint: %s, want the platform's newest %s", p.Checkpoint.ID, cp.ID)
	}
}
