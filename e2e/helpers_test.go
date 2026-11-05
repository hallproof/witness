package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	chronstore "github.com/xraph/chronicle/store"
	chronmem "github.com/xraph/chronicle/store/memory"
	"github.com/xraph/forge"
	forgetesting "github.com/xraph/forge/testing"
	ks "github.com/xraph/keysmith"
	"github.com/xraph/keysmith/key"
	ksmem "github.com/xraph/keysmith/store/memory"
	xvault "github.com/xraph/vault"
	vaultid "github.com/xraph/vault/id"
	"github.com/xraph/vault/secret"
	vaultstore "github.com/xraph/vault/store"
	vaultmem "github.com/xraph/vault/store/memory"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/chain"
	wchronicle "github.com/hallproof/witness/chronicle"
	witnessforge "github.com/hallproof/witness/forge"
	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

// The platform every test collects for. tenantID is the witness scope's
// tenant: the one staff events are recorded under.
const (
	appID    = "app-platform"
	tenantID = "platform"

	// Keysmith tenants: the company's own organization, and a customer's.
	staffOrg    = "org-staff"
	customerOrg = "org-customer"

	// secretKey names the one Vault secret, and secretValue is its value,
	// which must never leave the app.
	secretKey   = "stripe-api-key"
	secretValue = "CANARY-secret-value-e2e"
)

// waitTimeout bounds every wait. Witness spreads each collector's first run
// over its first 30 seconds (collect's maxFirstDelay), and nothing an app
// sets shortens that, so a wait for evidence can take that long.
const waitTimeout = 45 * time.Second

// logs collects what witness logs, to show when a test fails.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// newLogs returns a log sink that prints itself when t fails.
func newLogs(t *testing.T) *logs {
	t.Helper()
	l := &logs{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("witness logged:\n%s", l.String())
		}
	})
	return l
}

func (l *logs) option() witnessforge.Option {
	return witnessforge.WithWitnessOptions(func(o *witness.Options) {
		o.Logger = slog.New(slog.NewTextHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
}

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

// trail is a Chronicle on its memory store, with a real Ed25519 signer and
// checkpointer, as Chronicle's own tests and chronicle/'s build it.
type trail struct {
	t     *testing.T
	c     *xchronicle.Chronicle
	cps   *checkpoint.Checkpointer
	pub   ed25519.PublicKey
	keyID string
	n     int
}

func newTrail(t *testing.T) *trail {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider := keyProvider{id: "ckpt-e2e-1", priv: priv}
	mem := chronmem.New()
	c, err := xchronicle.New(xchronicle.WithStore(chronstore.NewAdapter(mem)))
	if err != nil {
		t.Fatal(err)
	}
	return &trail{
		t: t, c: c,
		cps: checkpoint.NewCheckpointer(mem, checkpoint.NewEd25519Signer(provider), nil),
		pub: pub, keyID: provider.id,
	}
}

// event is a staff event with action, for c.Record.
func (tr *trail) event(action string) chain.Event {
	tr.n++
	return chain.Event{
		Time:       time.Date(2026, 11, 1, 9, 0, tr.n, 0, time.UTC),
		Action:     action,
		Resource:   "api_key",
		ResourceID: fmt.Sprintf("key-%d", tr.n),
		Category:   "access",
		UserID:     "staff-1",
		IP:         "203.0.113.7",
		Metadata:   map[string]any{"via": "console"},
	}
}

// recordBefore records actions to the platform stream before the app
// starts, through a chain of the chronicle adapter's own over the same
// Chronicle. The chain witness binds exists only once the app has started,
// and an event proof collector may run any time in its first 30 seconds, so
// what it should prove has to be there first.
func (tr *trail) recordBefore(actions ...string) {
	tr.t.Helper()
	c, err := wchronicle.New(tr.c, wchronicle.Scope{AppID: appID, TenantID: tenantID},
		wchronicle.WithLogger(slog.New(slog.DiscardHandler)))
	if err != nil {
		tr.t.Fatal(err)
	}
	for _, a := range actions {
		if err := c.Record(context.Background(), tr.event(a)); err != nil {
			tr.t.Fatal(err)
		}
	}
}

// stream is the platform stream.
func (tr *trail) stream() *xchronicle.StreamInfo {
	tr.t.Helper()
	st, err := tr.c.Store().GetStreamByScope(context.Background(), appID, tenantID)
	if err != nil {
		tr.t.Fatal(err)
	}
	return st
}

// checkpoint signs the platform stream up to its head.
func (tr *trail) checkpoint() *checkpoint.Checkpoint {
	tr.t.Helper()
	st := tr.stream()
	cp, err := tr.cps.CheckpointStream(context.Background(), checkpoint.StreamHead{
		ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash,
	})
	if err != nil {
		tr.t.Fatal(err)
	}
	return cp
}

// keyring is a Keysmith engine on its memory store with one staff key and
// one customer key, made through the engine's own CreateKey.
type keyring struct {
	eng                 *ks.Engine
	staff, customer     *key.Key
	staffRaw, custRaw   string
	staffHint, custHint string
}

func newKeyring(t *testing.T) *keyring {
	t.Helper()
	eng, err := ks.NewEngine(ks.WithStore(ksmem.New()))
	if err != nil {
		t.Fatal(err)
	}
	create := func(org, name string) (*key.Key, string) {
		ctx := ks.WithTenant(context.Background(), appID, org)
		res, err := eng.CreateKey(ctx, &ks.CreateKeyInput{
			Name:        name,
			Description: "CANARY-description-" + org,
			Prefix:      "sk",
			Environment: key.EnvLive,
			CreatedBy:   "user-" + org,
		})
		if err != nil {
			t.Fatalf("CreateKey(%s): %v", org, err)
		}
		return res.Key, res.RawKey
	}
	k := &keyring{eng: eng}
	k.staff, k.staffRaw = create(staffOrg, "deploy bot")
	k.customer, k.custRaw = create(customerOrg, "customer integration")
	k.staffHint, k.custHint = k.staff.Hint, k.customer.Hint
	return k
}

// newVault is a Vault memory store holding one app-level secret.
func newVault(t *testing.T) vaultstore.Store {
	t.Helper()
	s := vaultmem.New()
	err := s.SetSecret(context.Background(), &secret.Secret{
		Entity:          xvault.NewEntity(),
		ID:              vaultid.NewSecretID(),
		Key:             secretKey,
		Value:           []byte(secretValue),
		EncryptedValue:  []byte("CANARY-encrypted-e2e"),
		EncryptionAlg:   "AES-256-GCM",
		EncryptionKeyID: "CANARY-keyid-e2e",
		AppID:           appID,
		Metadata:        map[string]string{"CANARY-meta-key": "CANARY-meta-value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// startApp builds a test-mode Forge app with ext, provides the engines in
// its container the way an app that builds them itself does, and starts it.
// The returned stop stops the app once; the test's cleanup calls it too.
func startApp(t *testing.T, ext *witnessforge.Extension, tr *trail, kr *keyring, vs vaultstore.Store) (stop func() error) {
	t.Helper()
	app := forgetesting.NewTestAppWithConfig(forge.AppConfig{
		Name:        "witness-e2e",
		Environment: "test",
		Extensions:  []forge.Extension{ext},
	})
	c := app.Container()
	if err := forge.ProvideValue(c, tr.c); err != nil {
		t.Fatal(err)
	}
	if err := forge.ProvideValue(c, kr.eng); err != nil {
		t.Fatal(err)
	}
	if err := forge.ProvideValue[vaultstore.Store](c, vs); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(t.Context()); err != nil {
		t.Fatalf("app.Start: %v", err)
	}
	var once sync.Once
	var stopErr error
	stop = func() error {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			stopErr = app.Stop(ctx)
		})
		return stopErr
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// collector is the collector key a stored message came from.
func collector(m push.Message) string { k, _, _ := strings.Cut(m.ID, ":"); return k }

// latest returns the newest stored message from the collector k.
func latest(s *ingesttest.Server, k string) (push.Message, bool) {
	stored := s.Stored()
	for i := len(stored) - 1; i >= 0; i-- {
		if collector(stored[i]) == k {
			return stored[i], true
		}
	}
	return push.Message{}, false
}

// waitForKeys waits until s has stored evidence from every collector in
// keys, and fails the test with what is missing when it times out.
func waitForKeys(t *testing.T, s *ingesttest.Server, keys ...string) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		var missing []string
		for _, k := range keys {
			if _, ok := latest(s, k); !ok {
				missing = append(missing, k)
			}
		}
		if len(missing) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %v, no evidence from %v; stored: %v", waitTimeout, missing, storedKeys(s))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func storedKeys(s *ingesttest.Server) []string {
	var out []string
	for _, m := range s.Stored() {
		if k := collector(m); !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// mustDecode decodes m's body as T.
func mustDecode[T any](t *testing.T, m push.Message) T {
	t.Helper()
	v, err := push.DecodeBody[T](m)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// everythingSent is every request body the server received, as JSON, for
// canary checks: what was stored, what was a duplicate, and heartbeats.
func everythingSent(t *testing.T, s *ingesttest.Server) string {
	t.Helper()
	var b strings.Builder
	for _, r := range s.Requests() {
		raw, err := json.Marshal(r.Batch)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String()
}

// verifyProof checks p the way Hallproof's evidence.VerifyProof does, steps
// 1 to 6, with the checkpoint key pub pinned as keyID. It is copied from
// chronicle/'s verify_test.go, which a test in another module can't import.
func verifyProof(ctx context.Context, p *push.EventProof, keyID string, pub ed25519.PublicKey) error {
	cp := p.Checkpoint

	// 1. checkKey.
	if cp.Algorithm != checkpoint.AlgorithmEd25519 {
		return fmt.Errorf("algorithm %q", cp.Algorithm)
	}
	if cp.SignKeyID != keyID || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("key %q is not pinned", cp.SignKeyID)
	}

	// 2. checkSignature.
	if _, err := id.Parse(cp.ID); err != nil {
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
	if !ed25519.Verify(pub, []byte(cp.SignedPayload), cp.Signature) {
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
