package chronicle

import (
	"context"
	"errors"
	"fmt"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// SnapshotKey is the key of the platform stream's snapshot.
const SnapshotKey = "chronicle.platform-stream"

func init() {
	adapter.Register(adapter.Adapter{
		Name:   "chronicle",
		Module: "github.com/xraph/chronicle",
		After:  []string{"chronicle"},
		Chain:  true,
		Attach: attach,
	})
}

// Config is the adapter's config section, extensions.witness.adapters.chronicle
// in a Forge app.
type Config struct {
	// MaxSegment is WithMaxSegment's n. Zero keeps DefaultMaxSegment.
	MaxSegment int `json:"max_segment"`
	// Streams are more stream names for Prove, as WithStream gives.
	Streams map[string]Scope `json:"streams"`
}

// attach finds the app's Chronicle in the container, binds a Chain over
// it as witness's chain, and registers the platform stream's snapshot.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	trail := find(h.Container)
	if trail == nil {
		return false, nil
	}
	var cfg Config
	if err := adapter.Decode(h.Config, &cfg); err != nil {
		return true, err
	}
	opts := []Option{WithMaxSegment(cfg.MaxSegment), WithLogger(h.Logger)}
	for name, s := range cfg.Streams {
		opts = append(opts, WithStream(name, s))
	}
	c, err := New(trail, Scope{AppID: h.Scope.AppID, TenantID: h.Scope.TenantID}, opts...)
	if err != nil {
		return true, err
	}
	if h.SetChain == nil {
		return true, errors.New("witness/chronicle: the host can't bind a chain")
	}
	if h.Witness == nil {
		return true, errors.New("witness/chronicle: the host has no witness")
	}
	if len(cfg.Streams) > 0 {
		// Prove can now prove streams beyond the platform's, which can be
		// customer tenants' streams.
		h.Widened("streams")
	}
	h.SetChain(c)
	return true, c.Register(h.Witness)
}

// find returns the *chronicle.Chronicle in container, provided as itself
// (an app that builds Chronicle) or as chronicle.Emitter (Chronicle's own
// Forge extension), or nil.
func find(container any) *xchronicle.Chronicle {
	v, ok := container.(vessel.Vessel)
	if !ok || v == nil {
		return nil
	}
	if vessel.HasType[*xchronicle.Chronicle](v) {
		if trail, err := vessel.Inject[*xchronicle.Chronicle](v); err == nil && trail != nil {
			return trail
		}
	}
	if vessel.HasType[xchronicle.Emitter](v) {
		if em, err := vessel.Inject[xchronicle.Emitter](v); err == nil {
			if trail, ok := em.(*xchronicle.Chronicle); ok && trail != nil {
				return trail
			}
		}
	}
	return nil
}

// Register adds the chain's own collectors to w: the platform stream's
// snapshot. Call it before w.Start.
func (c *Chain) Register(w *witness.Witness) error {
	return w.Snapshot(c.PlatformSnapshot())
}

// PlatformSnapshot is a snapshot of the platform stream's posture: its ID
// and digest scheme, whether it has a signed checkpoint, the newest
// checkpoint's key and algorithm, and whether the events recorded since
// that checkpoint still fit in one proof segment. It backs
// audit-chain-verifies.
//
// It leaves out what moves with every event or checkpoint (the head
// sequence, the checkpoint's ID, time and end, the exact lag), so its hash
// changes only when the posture does and witness doesn't push it again on
// every run.
//
// When the chain has streams besides the platform's (WithStream, or the
// adapter's streams config), the description says how many, so Hallproof
// shows that Prove reaches beyond the platform stream. It never names them.
func (c *Chain) PlatformSnapshot() collect.Snapshot {
	desc := "The platform's Chronicle stream: its digest scheme, its checkpoint signing key and algorithm, and whether the events not yet checkpointed fit in one proof segment."
	// New always adds Platform itself; count the others.
	switch n := len(c.streams) - 1; {
	case n == 1:
		desc += " Event proofs can also come from 1 more stream, which may be a customer tenant's."
	case n > 1:
		desc += fmt.Sprintf(" Event proofs can also come from %d more streams, which may be customer tenants'.", n)
	}
	return collect.Snapshot{
		Key:         SnapshotKey,
		Title:       "Platform audit chain",
		Description: desc,
		Tests:       []string{"audit-chain-verifies"},
		Collect:     c.platformSettings,
	}
}

func (c *Chain) platformSettings(ctx context.Context) (map[string]any, error) {
	out := map[string]any{"app_id": c.platform.AppID, "tenant_id": c.platform.TenantID}
	st, err := c.store.GetStreamByScope(ctx, c.platform.AppID, c.platform.TenantID)
	if errors.Is(err, xchronicle.ErrStreamNotFound) {
		out["stream"] = "none"
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("witness/chronicle: platform stream: %w", err)
	}
	out["stream_id"] = st.ID.String()
	out["hash_scheme"] = st.Scheme
	cp, err := c.checkpoints.LatestCheckpoint(ctx, st.ID)
	if errors.Is(err, checkpoint.ErrNotFound) {
		out["checkpointed"] = false
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("witness/chronicle: platform stream's newest checkpoint: %w", err)
	}
	var lag uint64
	if st.HeadSeq > cp.ToSeq {
		lag = st.HeadSeq - cp.ToSeq
	}
	out["checkpointed"] = true
	out["sign_key_id"] = cp.SignKeyID
	out["algorithm"] = cp.Algorithm
	// A bucket, not the count: it flips only when checkpoints fall so far
	// behind that the waiting events no longer fit in one segment.
	out["lag_within_segment"] = lag <= uint64(c.maxSegment) // #nosec G115 -- maxSegment is between 1 and push.MaxSegment
	return out, nil
}
