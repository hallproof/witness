package chronicle

import (
	"context"
	"errors"
	"fmt"
	"time"

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

// PlatformSnapshot is a snapshot of the platform stream's state: its head
// sequence and digest scheme, its newest checkpoint (ID, time, end, key
// and algorithm), and how many events have been recorded since that
// checkpoint. It backs audit-chain-verifies.
func (c *Chain) PlatformSnapshot() collect.Snapshot {
	return collect.Snapshot{
		Key:         SnapshotKey,
		Title:       "Platform audit chain",
		Description: "The platform's Chronicle stream: its head, its newest signed checkpoint, and events not yet checkpointed.",
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
	out["head_sequence"] = st.HeadSeq
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
	out["last_checkpoint_id"] = cp.ID.String()
	out["last_checkpoint_at"] = cp.CreatedAt.UTC().Format(time.RFC3339Nano)
	out["last_checkpoint_to_sequence"] = cp.ToSeq
	out["lag_events"] = lag
	out["sign_key_id"] = cp.SignKeyID
	out["algorithm"] = cp.Algorithm
	return out, nil
}
