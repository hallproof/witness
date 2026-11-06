package chronicle_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/keys"
	chronstore "github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"

	"github.com/hallproof/witness/chain"
	wchronicle "github.com/hallproof/witness/chronicle"
	"github.com/hallproof/witness/push"
)

// The platform scope every fixture records under.
const (
	appID    = "platform-app"
	tenantID = "staff"
)

var platform = wchronicle.Scope{AppID: appID, TenantID: tenantID}

// quiet discards what the chain logs.
var quiet = slog.New(slog.DiscardHandler)

// keyProvider holds one Ed25519 checkpoint key.
type keyProvider struct {
	id   string
	priv ed25519.PrivateKey
}

func (p keyProvider) Current(context.Context, keys.Use) (key []byte, keyID string, err error) {
	return p.priv, p.id, nil
}

func (p keyProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != p.id {
		return nil, keys.ErrKeyNotFound
	}
	return p.priv, nil
}

// fixture is a Chronicle on a memory store, with a real Ed25519 signer and
// checkpointer, and a witness chain over it.
type fixture struct {
	t      *testing.T
	trail  *xchronicle.Chronicle
	mem    *memory.Store
	signer *checkpoint.Ed25519Signer
	cps    *checkpoint.Checkpointer
	pub    ed25519.PublicKey
	keyID  string
	chain  *wchronicle.Chain
	n      int
}

func newFixture(t *testing.T, opts ...wchronicle.Option) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := keyProvider{id: "ckpt-test-1", priv: priv}
	mem := memory.New()
	trail, err := xchronicle.New(xchronicle.WithStore(chronstore.NewAdapter(mem)))
	if err != nil {
		t.Fatal(err)
	}
	signer := checkpoint.NewEd25519Signer(provider)
	opts = append([]wchronicle.Option{wchronicle.WithLogger(quiet)}, opts...)
	c, err := wchronicle.New(trail, platform, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		t: t, trail: trail, mem: mem, signer: signer,
		cps: checkpoint.NewCheckpointer(mem, signer, nil),
		pub: pub, keyID: provider.id, chain: c,
	}
}

// record appends n events with action through the witness chain.
func (f *fixture) record(n int, action string, meta map[string]any) {
	f.t.Helper()
	for range n {
		f.n++
		err := f.chain.Record(context.Background(), chain.Event{
			Time:       time.Date(2026, 11, 1, 9, 0, f.n, 123456789, time.UTC),
			Action:     action,
			Resource:   "session",
			ResourceID: fmt.Sprintf("sess-%d", f.n),
			Category:   "auth",
			UserID:     "staff-1",
			IP:         "203.0.113.7",
			Metadata:   meta,
		})
		if err != nil {
			f.t.Fatal(err)
		}
	}
}

// stream is the platform stream.
func (f *fixture) stream() *xchronicle.StreamInfo {
	f.t.Helper()
	st, err := f.trail.Store().GetStreamByScope(context.Background(), appID, tenantID)
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

// checkpoint signs the platform stream up to its head.
func (f *fixture) checkpoint() *checkpoint.Checkpoint {
	f.t.Helper()
	st := f.stream()
	cp, err := f.cps.CheckpointStream(context.Background(), checkpoint.StreamHead{
		ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return cp
}

// prove proves the platform stream from from, citing actions.
func (f *fixture) prove(from string, actions ...string) (*push.EventProof, error) {
	f.t.Helper()
	return f.chain.Prove(context.Background(), chain.ProofRequest{Stream: wchronicle.Platform, From: from, Actions: actions})
}

// mustProve is prove that fails the test on an error.
func (f *fixture) mustProve(from string, actions ...string) *push.EventProof {
	f.t.Helper()
	p, err := f.prove(from, actions...)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// verify checks p the way Hallproof does, with this fixture's key pinned.
func (f *fixture) verify(p *push.EventProof) error {
	f.t.Helper()
	return verifyProof(context.Background(), p, pinnedKey{id: f.keyID, pub: f.pub})
}

// mustVerify is verify that fails the test on an error.
func (f *fixture) mustVerify(p *push.EventProof) {
	f.t.Helper()
	if err := f.verify(p); err != nil {
		f.t.Fatalf("proof doesn't verify: %v", err)
	}
}

// isNothingNew reports whether err is chain.ErrNothingNew.
func isNothingNew(err error) bool { return errors.Is(err, chain.ErrNothingNew) }
