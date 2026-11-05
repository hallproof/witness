package collect_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

var at = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func mustOK[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestValidKey(t *testing.T) {
	for _, k := range []string{"auth-settings", "a", "staff.users_2", "0x", strings.Repeat("a", 100)} {
		if err := collect.ValidKey(k); err != nil {
			t.Errorf("ValidKey(%q): %v", k, err)
		}
	}
	for _, k := range []string{"", strings.Repeat("a", 101), "Auth", "-x", ".x", "a b", "a:b", "é"} {
		if collect.ValidKey(k) == nil {
			t.Errorf("ValidKey(%q) accepted", k)
		}
	}
}

func TestSnapshotMessage(t *testing.T) {
	s := collect.Snapshot{Key: "auth-settings", Title: "Auth settings", Description: "d", Tests: []string{"mfa-enforced"}}
	settings := map[string]any{"mfa": "required", "lockout": json.Number("5")}
	m, hash, err := collect.SnapshotMessage(s, settings, at)
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != push.KindConfigSnapshot || !m.CollectedAt.Equal(at) {
		t.Fatalf("kind %s at %v", m.Kind, m.CollectedAt)
	}
	body := mustOK(push.DecodeBody[push.ConfigSnapshot](m))
	if want := mustOK(push.SnapshotHash(settings)); body.Hash != want || hash != want {
		t.Fatalf("hash %s / %s, want %s", body.Hash, hash, want)
	}
	if body.Title != s.Title || body.Description != s.Description || !reflect.DeepEqual(body.Tests, s.Tests) {
		t.Fatalf("common %+v", body.Common)
	}
	canonical := mustOK(push.Canonical(body))
	if want := collect.MessageID("auth-settings", canonical, at); m.ID != want {
		t.Fatalf("id %s, want %s", m.ID, want)
	}
	if !strings.HasPrefix(m.ID, "auth-settings:") || len(m.ID) != len("auth-settings:")+64+len(":20261104") {
		t.Fatalf("id %q isn't key:hex:day", m.ID)
	}
}

func TestIDStableAcrossReplicas(t *testing.T) {
	s := collect.Snapshot{Key: "k", Title: "t"}
	a, _, _ := collect.SnapshotMessage(s, map[string]any{"x": 1}, at)
	b, _, _ := collect.SnapshotMessage(s, map[string]any{"x": 1}, at.Add(time.Hour))
	if a.ID != b.ID {
		t.Fatalf("%s != %s", a.ID, b.ID)
	}
	c, _, _ := collect.SnapshotMessage(s, map[string]any{"x": 2}, at)
	if c.ID == a.ID {
		t.Fatal("different settings gave the same id")
	}
}

// Review Focus 2: editing a collector's tests while the state stays the same.
func TestEditedTestsGetANewID(t *testing.T) {
	srv := ingesttest.New(t, ingesttest.WithNow(func() time.Time { return at }))
	settings := map[string]any{"mfa": "required"}
	before, _, _ := collect.SnapshotMessage(collect.Snapshot{Key: "k", Title: "t", Tests: []string{"a"}}, settings, at)
	after, _, _ := collect.SnapshotMessage(collect.Snapshot{Key: "k", Title: "t", Tests: []string{"a", "b"}}, settings, at)
	if before.ID == after.ID {
		t.Fatal("editing the tests kept the id")
	}
	for _, m := range []push.Message{before, after} {
		raw, _ := json.Marshal(push.Batch{Version: push.Version, Messages: []push.Message{m}})
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/ingest", strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer "+srv.Key)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out push.Response
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if out.Results[0].Status != push.StatusAccepted {
			t.Fatalf("%s: %+v, want accepted", m.ID, out.Results[0])
		}
	}
}

func TestPopulationMessageChecksItems(t *testing.T) {
	p := collect.Population{Key: "staff", Title: "Staff", Source: "staff-users"}
	m, hash, err := collect.PopulationMessage(p, []map[string]any{{"id": "u2"}, {"id": "u1", "role": "admin"}}, at)
	if err != nil {
		t.Fatal(err)
	}
	body := mustOK(push.DecodeBody[push.Population](m))
	if body.Source != "staff-users" || body.Hash != hash || m.Kind != push.KindPopulation {
		t.Fatalf("body %+v", body)
	}

	tooMany := make([]map[string]any, push.MaxItems+1)
	for i := range tooMany {
		tooMany[i] = map[string]any{"id": string(rune(i))}
	}
	bad := map[string][]map[string]any{
		"no id":         {{"name": "secret-name"}},
		"non-string id": {{"id": 7}},
		"empty id":      {{"id": ""}},
		"repeated id":   {{"id": "secret-u1"}, {"id": "secret-u1"}},
		"too many":      tooMany,
	}
	for name, items := range bad {
		_, _, err := collect.PopulationMessage(p, items, at)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: the error echoes item contents: %v", name, err)
		}
	}
}

func TestProofMessage(t *testing.T) {
	e := collect.EventProof{Key: "logins", Title: "Admin logins", Tests: []string{"mfa-enforced"}, Stream: "s1", Actions: []string{"login"}}
	proof := &push.EventProof{
		Common:     push.Common{Title: "ignored"},
		Cited:      []uint64{3},
		Segment:    []push.ChainEvent{{ID: "e3", Sequence: 3, Action: "login"}},
		Checkpoint: push.Checkpoint{ID: "c1", ToSeq: 3},
	}
	m, err := collect.ProofMessage(e, proof, at)
	if err != nil {
		t.Fatal(err)
	}
	body := mustOK(push.DecodeBody[push.EventProof](m))
	if body.Title != "Admin logins" || !reflect.DeepEqual(body.Tests, e.Tests) {
		t.Fatalf("common %+v", body.Common)
	}
	if !reflect.DeepEqual(body.Cited, []uint64{3}) || body.Checkpoint.ID != "c1" || body.Segment[0].ID != "e3" {
		t.Fatalf("proof %+v", body)
	}
	if proof.Title != "ignored" {
		t.Fatal("ProofMessage changed the caller's proof")
	}
	if !strings.HasPrefix(m.ID, "logins:") || m.Kind != push.KindEventProof {
		t.Fatalf("id %s kind %s", m.ID, m.Kind)
	}
}

func TestHeartbeatIDsDiffer(t *testing.T) {
	hb := push.Heartbeat{Collector: "auth-settings", Evidence: push.KindConfigSnapshot, EverySeconds: 600, Replica: "r", SDK: "s"}
	a := mustOK(collect.HeartbeatMessage(hb, at))
	b := mustOK(collect.HeartbeatMessage(hb, at))
	if a.ID == b.ID {
		t.Fatal("two heartbeats share an id")
	}
	for _, m := range []push.Message{a, b} {
		if !strings.HasPrefix(m.ID, "hb:auth-settings:") || len(m.ID) != len("hb:auth-settings:")+32 || m.Kind != push.KindHeartbeat {
			t.Fatalf("heartbeat %s %s", m.ID, m.Kind)
		}
	}
	if got := mustOK(push.DecodeBody[push.Heartbeat](a)); got != hb {
		t.Fatalf("body %+v, want %+v", got, hb)
	}
}

func TestIDsFitTheLimit(t *testing.T) {
	key := strings.Repeat("k", 100)
	snap, _, _ := collect.SnapshotMessage(collect.Snapshot{Key: key, Title: "t"}, map[string]any{}, at)
	pop, _, _ := collect.PopulationMessage(collect.Population{Key: key, Title: "t"}, nil, at)
	proof := mustOK(collect.ProofMessage(collect.EventProof{Key: key, Title: "t"}, &push.EventProof{}, at))
	hb := mustOK(collect.HeartbeatMessage(push.Heartbeat{Collector: key}, at))
	for _, m := range []push.Message{snap, pop, proof, hb} {
		if len(m.ID) > 200 {
			t.Errorf("%s id is %d bytes", m.Kind, len(m.ID))
		}
	}
}

func TestNilCollectionsAreEmpty(t *testing.T) {
	snap, _, err := collect.SnapshotMessage(collect.Snapshot{Key: "k", Title: "t"}, nil, at)
	if err != nil || !strings.Contains(string(snap.Body), `"settings":{}`) {
		t.Fatalf("nil settings: %s, %v", snap.Body, err)
	}
	pop, _, err := collect.PopulationMessage(collect.Population{Key: "k", Title: "t"}, nil, at)
	if err != nil || !strings.Contains(string(pop.Body), `"items":[]`) {
		t.Fatalf("nil items: %s, %v", pop.Body, err)
	}
}

// Review, Critical: a state that returns to an earlier value must reach
// Hallproof as new evidence, not as a duplicate of the old one.
func TestIDChangesDaily(t *testing.T) {
	s := collect.Snapshot{Key: "k", Title: "t"}
	late := time.Date(2026, 11, 4, 23, 59, 0, 0, time.UTC)
	a, _, _ := collect.SnapshotMessage(s, map[string]any{"x": 1}, late)
	b, _, _ := collect.SnapshotMessage(s, map[string]any{"x": 1}, late.Add(-23*time.Hour))
	c, _, _ := collect.SnapshotMessage(s, map[string]any{"x": 1}, late.Add(2*time.Minute))
	if a.ID != b.ID {
		t.Fatalf("same day, different ids: %s, %s", a.ID, b.ID)
	}
	if a.ID == c.ID {
		t.Fatal("the next day kept the id")
	}
	if !strings.HasSuffix(a.ID, ":20261104") || !strings.HasSuffix(c.ID, ":20261105") {
		t.Fatalf("ids %s and %s don't end in their UTC day", a.ID, c.ID)
	}
}

func TestReturnToEarlierStateIsNewEvidence(t *testing.T) {
	day := func(n int) time.Time { return at.AddDate(0, 0, n) }
	srv := ingesttest.New(t, ingesttest.WithNow(func() time.Time { return day(30) }))
	s := collect.Snapshot{Key: "auth", Title: "Auth"}
	off := map[string]any{"mfa": "optional"}
	on := map[string]any{"mfa": "required"}
	for _, step := range []struct {
		settings map[string]any
		at       time.Time
	}{{off, day(1)}, {on, day(2)}, {off, day(30)}} {
		m, _, _ := collect.SnapshotMessage(s, step.settings, step.at)
		raw, _ := json.Marshal(push.Batch{Version: push.Version, Messages: []push.Message{m}})
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/ingest", strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer "+srv.Key)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out push.Response
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if out.Results[0].Status != push.StatusAccepted {
			t.Fatalf("%v on %v: %+v, want accepted", step.settings, step.at, out.Results[0])
		}
	}
}
