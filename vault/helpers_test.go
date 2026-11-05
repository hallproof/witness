package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	xvault "github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/id"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store"
	"github.com/xraph/vault/store/memory"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

var bg = context.Background()

// spyStore is a memory store that records any call to a method that hands
// back secret bytes. The adapter must never make one.
type spyStore struct {
	store.Store
	mu        sync.Mutex
	forbidden []string
}

func newSpy() *spyStore { return &spyStore{Store: memory.New()} }

func (s *spyStore) note(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forbidden = append(s.forbidden, name)
}

func (s *spyStore) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forbidden...)
}

func (s *spyStore) GetSecret(ctx context.Context, key, appID, tenantID string) (*secret.Secret, error) {
	s.note("GetSecret")
	return s.Store.GetSecret(ctx, key, appID, tenantID)
}

func (s *spyStore) GetSecretVersion(ctx context.Context, key, appID, tenantID string, v int64) (*secret.Secret, error) {
	s.note("GetSecretVersion")
	return s.Store.GetSecretVersion(ctx, key, appID, tenantID, v)
}

func (s *spyStore) ListSecretVersions(ctx context.Context, key, appID, tenantID string) ([]*secret.Version, error) {
	s.note("ListSecretVersions")
	return s.Store.ListSecretVersions(ctx, key, appID, tenantID)
}

func (s *spyStore) ListUnrecordedVersions(ctx context.Context, appID, after string, limit int) ([]*secret.Version, error) {
	s.note("ListUnrecordedVersions")
	return s.Store.ListUnrecordedVersions(ctx, appID, after, limit)
}

func (s *spyStore) GetConfigVersion(ctx context.Context, key, appID string, v int64) (*config.Entry, error) {
	s.note("GetConfigVersion")
	return s.Store.GetConfigVersion(ctx, key, appID, v)
}

func (s *spyStore) ListConfigVersions(ctx context.Context, key, appID string) ([]*config.EntryVersion, error) {
	s.note("ListConfigVersions")
	return s.Store.ListConfigVersions(ctx, key, appID)
}

func putSecret(t *testing.T, s store.Store, app, tenant, key, alg string) {
	t.Helper()
	err := s.SetSecret(bg, &secret.Secret{
		Entity:          xvault.NewEntity(),
		ID:              id.NewSecretID(),
		Key:             key,
		Value:           []byte("CANARY-value-" + key),
		EncryptedValue:  []byte("CANARY-encrypted-" + key),
		EncryptionAlg:   alg,
		EncryptionKeyID: "CANARY-keyid-" + key,
		AppID:           app,
		TenantID:        tenant,
		Metadata:        map[string]string{"CANARY-meta-key": "CANARY-meta-value"},
	})
	if err != nil {
		t.Fatalf("SetSecret(%s/%s/%s): %v", app, tenant, key, err)
	}
}

func putPolicy(t *testing.T, s store.Store, app, key string, enabled bool, interval time.Duration, last, next *time.Time) {
	t.Helper()
	err := s.SaveRotationPolicy(bg, &rotation.Policy{
		Entity:         xvault.NewEntity(),
		ID:             id.NewRotationID(),
		SecretKey:      key,
		AppID:          app,
		Interval:       interval,
		Enabled:        enabled,
		LastRotatedAt:  last,
		NextRotationAt: next,
	})
	if err != nil {
		t.Fatalf("SaveRotationPolicy: %v", err)
	}
}

func putFlag(t *testing.T, s store.Store, app, key string, typ flag.Type, def any) {
	t.Helper()
	err := s.DefineFlag(bg, &flag.Definition{
		Entity:       xvault.NewEntity(),
		ID:           id.NewFlagID(),
		Key:          key,
		Type:         typ,
		DefaultValue: def,
		Description:  "CANARY-flag-description",
		Tags:         []string{"billing"},
		Variants: []flag.Variant{
			{Value: "CANARY-variant-value", Description: "CANARY-variant-description"},
		},
		Enabled:  true,
		AppID:    app,
		Metadata: map[string]string{"CANARY-flag-meta-key": "CANARY-flag-meta-value"},
	})
	if err != nil {
		t.Fatalf("DefineFlag: %v", err)
	}
}

func putConfig(t *testing.T, s store.Store, app, key string, value any) {
	t.Helper()
	err := s.SetConfig(bg, &config.Entry{
		Entity:      xvault.NewEntity(),
		ID:          id.NewConfigID(),
		Key:         key,
		Value:       value,
		ValueType:   "string",
		Description: "CANARY-config-description",
		AppID:       app,
		Metadata:    map[string]string{"CANARY-config-meta-key": "CANARY-config-meta-value"},
	})
	if err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
}

func putOverride(t *testing.T, s store.Store, app, key, tenant string, value any) {
	t.Helper()
	err := s.SetOverride(bg, &override.Override{
		Entity:   xvault.NewEntity(),
		ID:       id.NewOverrideID(),
		Key:      key,
		Value:    value,
		AppID:    app,
		TenantID: tenant,
		Metadata: map[string]string{"CANARY-override-meta-key": "CANARY-override-meta-value"},
	})
	if err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
}

// collected is everything an adapter's collectors returned in one run.
type collected struct {
	snapshots   map[string]map[string]any
	populations map[string][]map[string]any
	proofs      []collect.EventProof
}

func run(t *testing.T, a *Adapter) collected {
	t.Helper()
	out := collected{snapshots: map[string]map[string]any{}, populations: map[string][]map[string]any{}}
	set := a.collectors()
	for _, s := range set.snapshots {
		got, err := s.Collect(bg)
		if err != nil {
			t.Fatalf("%s: %v", s.Key, err)
		}
		out.snapshots[s.Key] = got
	}
	for _, p := range set.populations {
		got, err := p.Collect(bg)
		if err != nil {
			t.Fatalf("%s: %v", p.Key, err)
		}
		seen := map[string]bool{}
		for _, it := range got {
			itemID, _ := it["id"].(string)
			if itemID == "" || seen[itemID] {
				t.Fatalf("%s: item id %q missing or repeated", p.Key, itemID)
			}
			seen[itemID] = true
		}
		out.populations[p.Key] = got
	}
	out.proofs = set.proofs
	return out
}

func byID(items []map[string]any) map[string]map[string]any {
	m := make(map[string]map[string]any, len(items))
	for _, it := range items {
		m[it["id"].(string)] = it
	}
	return m
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func bufferLogger() (*slog.Logger, *logBuffer) {
	b := &logBuffer{}
	return slog.New(slog.NewTextHandler(b, nil)), b
}

func keys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
