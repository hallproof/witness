package e2e_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hallproof/witness/adapter"
	wchronicle "github.com/hallproof/witness/chronicle"
	witnessforge "github.com/hallproof/witness/forge"
	"github.com/hallproof/witness/ingesttest"
	wkeysmith "github.com/hallproof/witness/keysmith"
	"github.com/hallproof/witness/push"

	// Every adapter, as an app that runs them all would import them. The
	// app in these tests runs only Chronicle, Keysmith and Vault, so the
	// rest have to report their library as not found.
	_ "github.com/hallproof/witness/authsome"
	_ "github.com/hallproof/witness/bastion"
	_ "github.com/hallproof/witness/grove"
	_ "github.com/hallproof/witness/relay"
	_ "github.com/hallproof/witness/trove"
	_ "github.com/hallproof/witness/vault"
	_ "github.com/hallproof/witness/warden"
)

// The vault adapter's secret population.
const vaultSecrets = "vault.secrets"

// running are the adapters whose library the test app runs.
var running = []string{"chronicle", "keysmith", "vault"}

// every names every adapter module in this repo.
var every = []string{"authsome", "bastion", "chronicle", "grove", "keysmith", "relay", "trove", "vault", "warden"}

// heartbeatEvery is short, so that a witness still running after Stop would
// show up as new requests within a second.
const heartbeatEvery = 200 * time.Millisecond

func TestForgeAppPushesEvidence(t *testing.T) {
	t.Parallel()
	s := ingesttest.New(t)
	s.Know(push.KindHeartbeat)
	l := newLogs(t)

	tr := newTrail(t)
	tr.recordBefore("api_key.created", "user.login")
	cp := tr.checkpoint()
	kr := newKeyring(t)
	vs := newVault(t)

	ext := witnessforge.New(witnessforge.WithConfig(witnessforge.Config{
		Endpoint:       s.URL,
		IngestKey:      s.Key,
		Scope:          witnessforge.ScopeConfig{AppID: appID, TenantID: tenantID},
		HeartbeatEvery: heartbeatEvery,
		Adapters: map[string]map[string]any{
			"keysmith": {"staff_tenants": []any{staffOrg}},
			"vault":    {"apps": []any{appID}},
		},
	}), l.option())
	stop := startApp(t, ext, tr, kr, vs)

	w := ext.Witness()
	if w == nil {
		t.Fatal("ext.Witness() is nil with an endpoint configured")
	}

	waitForKeys(t, s, witnessforge.CoverageKey, wkeysmith.KeyAPIKeys, vaultSecrets, wchronicle.SnapshotKey)

	t.Run("coverage", func(t *testing.T) {
		m, _ := latest(s, witnessforge.CoverageKey)
		snap := mustDecode[push.ConfigSnapshot](t, m)
		if got := snap.Settings["scope"]; got != "staff" {
			t.Errorf("scope = %v, want staff", got)
		}
		list, ok := snap.Settings["adapters"].([]any)
		if !ok {
			t.Fatalf("adapters is %T, want a list", snap.Settings["adapters"])
		}
		byName := map[string]map[string]any{}
		for _, a := range list {
			entry, ok := a.(map[string]any)
			if !ok {
				t.Fatalf("adapter entry is %T", a)
			}
			name, _ := entry["name"].(string)
			byName[name] = entry
		}
		// Every registered adapter is in the snapshot, found or not.
		for _, a := range adapter.Adapters() {
			entry, ok := byName[a.Name]
			if !ok {
				t.Errorf("coverage leaves out %s", a.Name)
				continue
			}
			if entry["module"] != a.Module {
				t.Errorf("%s: module = %v, want %s", a.Name, entry["module"], a.Module)
			}
			want := slices.Contains(running, a.Name)
			if entry["found"] != want {
				t.Errorf("%s: found = %v, want %v", a.Name, entry["found"], want)
			}
			if _, failed := entry["error"]; failed {
				t.Errorf("%s: Attach failed", a.Name)
			}
		}
		for _, name := range every {
			if _, ok := byName[name]; !ok {
				t.Errorf("%s is blank-imported but not in the coverage snapshot", name)
			}
		}
	})

	t.Run("keysmith staff keys only", func(t *testing.T) {
		m, _ := latest(s, wkeysmith.KeyAPIKeys)
		pop := mustDecode[push.Population](t, m)
		ids := make([]string, 0, len(pop.Items))
		for _, it := range pop.Items {
			ids = append(ids, it["id"].(string))
			if it["tenant_id"] != staffOrg {
				t.Errorf("key %v is in tenant %v, outside the staff tenant", it["id"], it["tenant_id"])
			}
		}
		if !slices.Contains(ids, kr.staff.ID.String()) {
			t.Errorf("the staff key %s is missing from %v", kr.staff.ID, ids)
		}
		if slices.Contains(ids, kr.customer.ID.String()) {
			t.Errorf("the customer key %s was sent", kr.customer.ID)
		}
	})

	t.Run("vault secrets without values", func(t *testing.T) {
		m, _ := latest(s, vaultSecrets)
		pop := mustDecode[push.Population](t, m)
		ids := make([]string, 0, len(pop.Items))
		for _, it := range pop.Items {
			ids = append(ids, it["id"].(string))
		}
		if want := appID + "/" + secretKey; !slices.Contains(ids, want) {
			t.Errorf("secret %s is missing from %v", want, ids)
		}
	})

	t.Run("chronicle platform stream", func(t *testing.T) {
		m, _ := latest(s, wchronicle.SnapshotKey)
		snap := mustDecode[push.ConfigSnapshot](t, m)
		st := snap.Settings
		if st["app_id"] != appID || st["tenant_id"] != tenantID {
			t.Errorf("snapshot is of %v/%v, want %s/%s", st["app_id"], st["tenant_id"], appID, tenantID)
		}
		if st["checkpointed"] != true {
			t.Fatalf("checkpointed = %v, want true; settings %v", st["checkpointed"], st)
		}
		if st["last_checkpoint_id"] != cp.ID.String() {
			t.Errorf("last_checkpoint_id = %v, want %s", st["last_checkpoint_id"], cp.ID)
		}
		if st["sign_key_id"] != tr.keyID {
			t.Errorf("sign_key_id = %v, want %s", st["sign_key_id"], tr.keyID)
		}
	})

	t.Run("nothing secret sent", func(t *testing.T) {
		sent := everythingSent(t, s)
		for name, canary := range map[string]string{
			"the secret value":     secretValue,
			"a CANARY- field":      "CANARY-",
			"the staff raw key":    kr.staffRaw,
			"the customer raw key": kr.custRaw,
			"the staff key's hash": kr.staff.KeyHash,
			"the customer tenant":  customerOrg,
		} {
			if strings.Contains(sent, canary) {
				t.Errorf("%s (%q) reached Hallproof", name, canary)
			}
		}
	})

	// Heartbeats only go out for collectors that have run, so by now they
	// arrive every heartbeatEvery; their stopping is what shows witness
	// stopped.
	waitFor(t, "a heartbeat", func() bool { return heartbeats(s) > 0 })

	if err := stop(); err != nil {
		t.Fatalf("app.Stop: %v", err)
	}
	if q := w.Client().Stats().Queued; q != 0 {
		t.Errorf("%d messages still queued after the app stopped", q)
	}
	before := len(s.Requests())
	time.Sleep(5 * heartbeatEvery)
	if after := len(s.Requests()); after != before {
		t.Errorf("witness sent %d requests after the app stopped", after-before)
	}
	if err := w.Start(context.Background()); err == nil {
		t.Error("witness started again after the app stopped")
	}
}

func TestEventProofThroughForge(t *testing.T) {
	t.Parallel()
	s := ingesttest.New(t)
	l := newLogs(t)

	const cited = "api_key.revoked"
	tr := newTrail(t)
	tr.recordBefore("api_key.created", cited, "user.login", cited)
	cp := tr.checkpoint()
	kr := newKeyring(t)
	vs := newVault(t)

	ext := witnessforge.New(witnessforge.WithConfig(witnessforge.Config{
		Endpoint:  s.URL,
		IngestKey: s.Key,
		Scope:     witnessforge.ScopeConfig{AppID: appID, TenantID: tenantID},
		Adapters: map[string]map[string]any{
			"keysmith": {
				"staff_tenants": []any{staffOrg},
				"event_proofs":  true,
				"proof_actions": []any{cited},
			},
			"vault": {"apps": []any{appID}},
		},
	}), l.option())
	startApp(t, ext, tr, kr, vs)

	w := ext.Witness()
	if w == nil {
		t.Fatal("ext.Witness() is nil with an endpoint configured")
	}

	// The extension bound the chronicle adapter's chain: recording through
	// witness's chain lands in the platform stream.
	head := tr.stream().HeadSeq
	if err := w.Chain().Record(context.Background(), tr.event(cited)); err != nil {
		t.Fatalf("Record through the bound chain: %v", err)
	}
	if got := tr.stream().HeadSeq; got != head+1 {
		t.Errorf("platform stream head = %d after Record, want %d", got, head+1)
	}

	waitForKeys(t, s, wkeysmith.KeyLifecycleProof)
	m, _ := latest(s, wkeysmith.KeyLifecycleProof)
	if m.Kind != push.KindEventProof {
		t.Fatalf("%s sent a %s, want an event proof", wkeysmith.KeyLifecycleProof, m.Kind)
	}
	p := mustDecode[push.EventProof](t, m)
	if err := verifyProof(context.Background(), &p, tr.keyID, tr.pub); err != nil {
		t.Fatalf("the proof Hallproof stored doesn't verify: %v", err)
	}
	if p.Checkpoint.ID != cp.ID.String() {
		t.Errorf("proved checkpoint %s, want %s", p.Checkpoint.ID, cp.ID)
	}
	if p.Checkpoint.AppID != appID || p.Checkpoint.TenantID != tenantID {
		t.Errorf("proved %s/%s, want the platform stream %s/%s", p.Checkpoint.AppID, p.Checkpoint.TenantID, appID, tenantID)
	}
	actions := map[uint64]string{}
	for _, e := range p.Segment {
		actions[e.Sequence] = e.Action
	}
	if len(p.Cited) != 2 {
		t.Errorf("cited %v, want the 2 %s events before the checkpoint", p.Cited, cited)
	}
	for _, n := range p.Cited {
		if actions[n] != cited {
			t.Errorf("cited event %d is %q, want %q", n, actions[n], cited)
		}
	}
}

// heartbeats counts the heartbeat messages s received.
func heartbeats(s *ingesttest.Server) int {
	n := 0
	for _, r := range s.Requests() {
		for _, m := range r.Batch.Messages {
			if m.Kind == push.KindHeartbeat {
				n++
			}
		}
	}
	return n
}

// waitFor polls cond until waitTimeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
