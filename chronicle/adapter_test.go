package chronicle_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/chain"
	wchronicle "github.com/hallproof/witness/chronicle"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

func registered(t *testing.T) adapter.Adapter {
	t.Helper()
	for _, a := range adapter.Adapters() {
		if a.Name == "chronicle" {
			return a
		}
	}
	t.Fatal("the chronicle adapter isn't registered")
	return adapter.Adapter{}
}

func TestRegistered(t *testing.T) {
	a := registered(t)
	if !a.Chain || a.Module != "github.com/xraph/chronicle" || !slices.Equal(a.After, []string{"chronicle"}) || a.Attach == nil {
		t.Fatalf("%+v", a)
	}
}

// lazyChain is a host's chain before an adapter binds one, as witness/forge
// builds it.
type lazyChain struct {
	mu sync.Mutex
	c  chain.Chain
}

func (l *lazyChain) set(c chain.Chain) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.c = c
}

func (l *lazyChain) get() chain.Chain {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c == nil {
		return chain.Unconfigured{}
	}
	return l.c
}

func (l *lazyChain) Record(ctx context.Context, e chain.Event) error { return l.get().Record(ctx, e) }

func (l *lazyChain) Prove(ctx context.Context, r chain.ProofRequest) (*push.EventProof, error) {
	return l.get().Prove(ctx, r)
}

// host is an adapter.Host on a real witness pointed at an ingesttest
// server, with a lazy chain the adapter binds.
func host(t *testing.T, container any) (adapter.Host, *ingesttest.Server, *witness.Witness, *lazyChain) {
	t.Helper()
	s := ingesttest.New(t)
	lazy := &lazyChain{}
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key, Chain: lazy, HeartbeatEvery: time.Hour, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = w.Stop(ctx)
	})
	return adapter.Host{
		Witness: w, Scope: adapter.Scope{AppID: appID, TenantID: tenantID}, Container: container,
		SetChain: lazy.set, Logger: quiet,
	}, s, w, lazy
}

// fakeEmitter is a chronicle.Emitter that isn't a *chronicle.Chronicle.
type fakeEmitter struct{ xchronicle.Emitter }

func TestAttachSkipsMissingEngine(t *testing.T) {
	a := registered(t)
	emitterOnly := vessel.New()
	if err := vessel.ProvideValue[xchronicle.Emitter](emitterOnly, fakeEmitter{}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]any{
		"nil container":         nil,
		"not a vessel":          struct{}{},
		"empty vessel":          vessel.New(),
		"an emitter of another": emitterOnly,
	} {
		h, _, _, lazy := host(t, c)
		found, err := a.Attach(context.Background(), h)
		if found || err != nil {
			t.Fatalf("%s: found %v, err %v", name, found, err)
		}
		if _, off := lazy.get().(chain.Unconfigured); !off {
			t.Fatalf("%s: a chain was bound", name)
		}
	}
}

func TestAttachNeedsAnApp(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.trail); err != nil {
		t.Fatal(err)
	}
	h, _, _, _ := host(t, c)
	h.Scope.AppID = ""
	found, err := registered(t).Attach(context.Background(), h)
	if !found || err == nil {
		t.Fatalf("found %v, err %v", found, err)
	}
}

// eventually waits up to 3 seconds for cond.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stored returns the server's stored messages from collector key.
func stored(s *ingesttest.Server, key string) []push.Message {
	var out []push.Message
	for _, m := range s.Stored() {
		if strings.HasPrefix(m.ID, key+":") {
			out = append(out, m)
		}
	}
	return out
}

func TestAttach(t *testing.T) {
	for _, how := range []string{"chronicle", "emitter"} {
		t.Run(how, func(t *testing.T) {
			f := newFixture(t)
			c := vessel.New()
			var err error
			if how == "chronicle" {
				err = vessel.ProvideValue(c, f.trail)
			} else {
				err = vessel.ProvideValue[xchronicle.Emitter](c, f.trail)
			}
			if err != nil {
				t.Fatal(err)
			}
			h, s, w, lazy := host(t, c)
			h.Config = map[string]any{"max_segment": 2}

			found, err := registered(t).Attach(context.Background(), h)
			if !found || err != nil {
				t.Fatalf("found %v, err %v", found, err)
			}
			if _, ok := lazy.get().(*wchronicle.Chain); !ok {
				t.Fatalf("bound %T, want *Chain", lazy.get())
			}

			// The bound chain records to the platform stream and proves it,
			// through witness, the way a library adapter's collector does.
			for range 3 {
				if err = w.Chain().Record(context.Background(), chain.Event{Action: "user.login", Resource: "session", Category: "auth"}); err != nil {
					t.Fatal(err)
				}
			}
			f.checkpoint()
			// The platform-stream snapshot is registered: its key is taken.
			dup := collect.Snapshot{Key: wchronicle.SnapshotKey, Title: "dup", Collect: func(context.Context) (map[string]any, error) { return nil, nil }}
			if err = w.Snapshot(dup); err == nil || !strings.Contains(err.Error(), "already used") {
				t.Fatalf("the snapshot key is free: %v", err)
			}
			if err = w.EventProof(collect.EventProof{
				Key: "logins", Title: "Staff logins", Every: 20 * time.Millisecond, Stream: adapter.Platform, Actions: []string{"user.login"},
			}); err != nil {
				t.Fatal(err)
			}
			if err = w.Start(context.Background()); err != nil {
				t.Fatal(err)
			}

			eventually(t, "the proof", func() bool { return len(stored(s, "logins")) > 0 })
			p, err := push.DecodeBody[push.EventProof](stored(s, "logins")[0])
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(p.Cited, []uint64{2, 3}) {
				t.Fatalf("cited %v; max_segment from the config is 2", p.Cited)
			}
			f.mustVerify(&p)
		})
	}
}

// Extra streams let Prove reach streams beyond the platform's, so the
// adapter tells the host it widened, and the snapshot's description says so.
func TestAttachWidensForStreams(t *testing.T) {
	for _, streams := range []map[string]any{nil, {"billing": map[string]any{"app_id": appID, "tenant_id": "billing"}}} {
		f := newFixture(t)
		c := vessel.New()
		if err := vessel.ProvideValue(c, f.trail); err != nil {
			t.Fatal(err)
		}
		h, _, _, lazy := host(t, c)
		var widened []string
		h.Widen = func(r string) { widened = append(widened, r) }
		if streams != nil {
			h.Config = map[string]any{"streams": streams}
		}
		if found, err := registered(t).Attach(context.Background(), h); !found || err != nil {
			t.Fatalf("found %v, err %v", found, err)
		}
		bound, ok := lazy.get().(*wchronicle.Chain)
		if !ok {
			t.Fatalf("bound %T, want *Chain", lazy.get())
		}
		desc := bound.PlatformSnapshot().Description
		if streams == nil {
			if widened != nil || strings.Contains(desc, "streams") {
				t.Fatalf("no streams: widened %v, description %q", widened, desc)
			}
			continue
		}
		if !slices.Equal(widened, []string{"streams"}) {
			t.Fatalf("widened %v, want [streams]", widened)
		}
		if !strings.Contains(desc, "1 more stream") || strings.Contains(desc, "billing") {
			t.Fatalf("description %q should count the extra streams and name none", desc)
		}
	}
}

func TestPlatformStreamSnapshot(t *testing.T) {
	f := newFixture(t)
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key, Chain: f.chain})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.chain.Register(w); err != nil {
		t.Fatal(err)
	}
	snap := f.chain.PlatformSnapshot()
	if snap.Key != "chronicle.platform-stream" || !slices.Equal(snap.Tests, []string{"audit-chain-verifies"}) {
		t.Fatalf("%+v", snap)
	}

	settings, err := snap.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if settings["stream"] != "none" || settings["app_id"] != appID || settings["tenant_id"] != tenantID {
		t.Fatalf("no stream yet: %v", settings)
	}

	f.record(3, "user.login", nil)
	settings, err = snap.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if settings["checkpointed"] != false || settings["hash_scheme"] != "chronicle/v4" || len(settings) != 5 {
		t.Fatalf("no checkpoint yet: %v", settings)
	}

	f.checkpoint()
	f.record(2, "user.login", nil)
	settings, err = snap.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Posture only: nothing that moves with every event or checkpoint.
	want := map[string]any{
		"app_id": appID, "tenant_id": tenantID, "stream_id": f.stream().ID.String(), "hash_scheme": "chronicle/v4",
		"checkpointed": true, "sign_key_id": f.keyID, "algorithm": "ed25519", "lag_within_segment": true,
	}
	for k, v := range want {
		if settings[k] != v {
			t.Errorf("%s = %v (%T), want %v", k, settings[k], settings[k], v)
		}
	}
	if len(settings) != len(want) {
		t.Errorf("settings %v", settings)
	}
}

// settingsHash collects snap and returns the hash witness sends with it.
func settingsHash(t *testing.T, snap collect.Snapshot) string {
	t.Helper()
	settings, err := snap.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h, err := push.SnapshotHash(settings)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The snapshot changes only when the stream's posture does, not with every
// event or checkpoint, so witness doesn't push it again on every run.
func TestPlatformStreamSnapshotIsStable(t *testing.T) {
	f := newFixture(t, wchronicle.WithMaxSegment(5))
	snap := f.chain.PlatformSnapshot()
	f.record(3, "user.login", nil)
	f.checkpoint()
	f.record(2, "user.login", nil)
	first := settingsHash(t, snap)

	f.record(4, "user.login", nil)
	f.checkpoint()
	f.record(1, "user.login", nil)
	if got := settingsHash(t, snap); got != first {
		t.Fatal("new events and a new checkpoint changed the snapshot; posture didn't change")
	}

	// More events waiting than one segment holds.
	f.record(5, "user.login", nil)
	if got := settingsHash(t, snap); got == first {
		t.Fatal("6 events past the checkpoint, more than max_segment 5, didn't change the snapshot")
	}

	// A checkpoint signed with another key.
	f.checkpoint()
	first = settingsHash(t, snap)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := checkpoint.NewCheckpointer(f.mem, checkpoint.NewEd25519Signer(keyProvider{id: "ckpt-test-2", priv: priv}), nil)
	f.record(1, "user.login", nil)
	st := f.stream()
	if _, err = other.CheckpointStream(context.Background(), checkpoint.StreamHead{
		ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash,
	}); err != nil {
		t.Fatal(err)
	}
	if got := settingsHash(t, snap); got == first {
		t.Fatal("a checkpoint under a new key didn't change the snapshot")
	}
}
