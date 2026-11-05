package ingesttest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func newServer(t *testing.T) *ingesttest.Server {
	return ingesttest.New(t, ingesttest.WithNow(func() time.Time { return now }))
}

// post sends raw as the request body with key as the bearer token.
func post(t *testing.T, s *ingesttest.Server, key string, raw []byte) (int, push.Response) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+"/api/v1/ingest", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out push.Response
	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return res.StatusCode, out
}

func send(t *testing.T, s *ingesttest.Server, msgs ...push.Message) (int, push.Response) {
	t.Helper()
	raw, err := json.Marshal(push.Batch{Version: push.Version, Messages: msgs})
	if err != nil {
		t.Fatal(err)
	}
	return post(t, s, s.Key, raw)
}

func snapshot(id string, settings map[string]any) push.Message {
	h, err := push.SnapshotHash(settings)
	if err != nil {
		panic(err)
	}
	body, _ := json.Marshal(push.ConfigSnapshot{Common: push.Common{Title: "Auth settings"}, Settings: settings, Hash: h})
	return push.Message{ID: id, Kind: push.KindConfigSnapshot, CollectedAt: now, Body: body}
}

func population(id string, items []map[string]any, hash string) push.Message {
	if hash == "" {
		h, err := push.PopulationHash(items)
		if err != nil {
			panic(err)
		}
		hash = h
	}
	body, _ := json.Marshal(push.Population{Common: push.Common{Title: "Staff"}, Source: "staff-users", Items: items, Hash: hash})
	return push.Message{ID: id, Kind: push.KindPopulation, CollectedAt: now, Body: body}
}

func statuses(r push.Response) []push.Status {
	out := make([]push.Status, len(r.Results))
	for i, x := range r.Results {
		out[i] = x.Status
	}
	return out
}

func TestWrongVersionIs400(t *testing.T) {
	s := newServer(t)
	raw, _ := json.Marshal(push.Batch{Version: 2, Messages: []push.Message{snapshot("m1", map[string]any{"a": 1})}})
	if code, _ := post(t, s, s.Key, raw); code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", code)
	}
	if code, _ := post(t, s, s.Key, []byte(`not json`)); code != http.StatusBadRequest {
		t.Fatalf("status %d for a body that isn't JSON, want 400", code)
	}
	if n := len(s.Stored()); n != 0 {
		t.Fatalf("%d stored, want 0", n)
	}
}

func TestTooManyMessagesIs400(t *testing.T) {
	s := newServer(t)
	msgs := make([]push.Message, push.MaxMessages+1)
	for i := range msgs {
		msgs[i] = snapshot("m"+string(rune('a'+i%26))+strings.Repeat("x", i), map[string]any{"i": i})
	}
	if code, _ := send(t, s, msgs...); code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", code)
	}
}

func TestWrongOrMissingKeyIs401(t *testing.T) {
	s := newServer(t)
	raw, _ := json.Marshal(push.Batch{Version: push.Version, Messages: []push.Message{snapshot("m1", map[string]any{"a": 1})}})
	for _, key := range []string{"", "hpk_wrong"} {
		if code, _ := post(t, s, key, raw); code != http.StatusUnauthorized {
			t.Errorf("key %q: status %d, want 401", key, code)
		}
	}
}

func TestOverMaxBatchBytesIs413(t *testing.T) {
	s := newServer(t)
	big := snapshot("big", map[string]any{"blob": strings.Repeat("x", push.MaxBatchBytes)})
	if code, _ := send(t, s, big); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", code)
	}
}

func TestMessageRules(t *testing.T) {
	ok := snapshot("ok", map[string]any{"a": 1})
	with := func(f func(*push.Message)) push.Message {
		m := snapshot("x", map[string]any{"a": 2})
		f(&m)
		return m
	}
	cases := []struct {
		name string
		msgs []push.Message
		want []push.Status
	}{
		{"empty id", []push.Message{with(func(m *push.Message) { m.ID = "" })}, []push.Status{push.StatusRejected}},
		{"201-byte id", []push.Message{with(func(m *push.Message) { m.ID = strings.Repeat("a", 201) })}, []push.Status{push.StatusRejected}},
		{"200-byte id", []push.Message{with(func(m *push.Message) { m.ID = strings.Repeat("a", 200) })}, []push.Status{push.StatusAccepted}},
		{"id with NUL", []push.Message{with(func(m *push.Message) { m.ID = "a\x00b" })}, []push.Status{push.StatusRejected}},
		{"id twice in a batch", []push.Message{ok, ok}, []push.Status{push.StatusRejected, push.StatusRejected}},
		{"unknown kind", []push.Message{with(func(m *push.Message) { m.Kind = "route_map" })}, []push.Status{push.StatusUnsupported}},
		{"zero collected_at", []push.Message{with(func(m *push.Message) { m.CollectedAt = time.Time{} })}, []push.Status{push.StatusRejected}},
		{"6 minutes ahead", []push.Message{with(func(m *push.Message) { m.CollectedAt = now.Add(6 * time.Minute) })}, []push.Status{push.StatusRejected}},
		{"4 minutes ahead", []push.Message{with(func(m *push.Message) { m.CollectedAt = now.Add(4 * time.Minute) })}, []push.Status{push.StatusAccepted}},
		{"blank title", []push.Message{with(func(m *push.Message) {
			m.Body = []byte(`{"title":" ","settings":{"a":2},"hash":"` + mustHash(map[string]any{"a": 2}) + `"}`)
		})}, []push.Status{push.StatusRejected}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newServer(t)
			code, res := send(t, s, c.msgs...)
			if code != http.StatusOK {
				t.Fatalf("status %d, want 200", code)
			}
			if got := statuses(res); !equal(got, c.want) {
				t.Fatalf("statuses %v, want %v (%+v)", got, c.want, res.Results)
			}
			for _, r := range res.Results {
				if r.Status == push.StatusRejected && r.Error == "" {
					t.Errorf("rejected without a reason")
				}
			}
		})
	}
}

func mustHash(m map[string]any) string {
	h, err := push.SnapshotHash(m)
	if err != nil {
		panic(err)
	}
	return h
}

func equal(a, b []push.Status) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDuplicateAndReusedID(t *testing.T) {
	s := newServer(t)
	_, first := send(t, s, snapshot("m1", map[string]any{"a": 1}))
	if first.Results[0].Status != push.StatusAccepted || first.Results[0].EvidenceID == "" {
		t.Fatalf("first: %+v", first.Results[0])
	}
	_, again := send(t, s, snapshot("m1", map[string]any{"a": 1}))
	if r := again.Results[0]; r.Status != push.StatusDuplicate || r.EvidenceID != first.Results[0].EvidenceID {
		t.Fatalf("again: %+v, want duplicate of %s", r, first.Results[0].EvidenceID)
	}
	_, reused := send(t, s, snapshot("m1", map[string]any{"a": 2}))
	if r := reused.Results[0]; r.Status != push.StatusRejected {
		t.Fatalf("reused id with a new body: %+v, want rejected", r)
	}
	if n := len(s.Stored()); n != 1 {
		t.Fatalf("%d stored, want 1", n)
	}
}

func TestHashesAreChecked(t *testing.T) {
	s := newServer(t)
	bad := snapshot("s1", map[string]any{"a": 1})
	bad.Body = []byte(`{"title":"t","settings":{"a":1},"hash":"sha256:00"}`)
	items := []map[string]any{{"id": "u1"}, {"id": "u2"}}
	_, res := send(t, s,
		bad,
		population("p1", items, "sha256:00"),
		population("p2", []map[string]any{{"name": "no id"}}, ""),
		population("p3", []map[string]any{{"id": 7}}, ""),
		population("p4", []map[string]any{{"id": "u1"}, {"id": "u1"}}, ""),
		population("p5", items, ""),
	)
	want := []push.Status{push.StatusRejected, push.StatusRejected, push.StatusRejected, push.StatusRejected, push.StatusRejected, push.StatusAccepted}
	if got := statuses(res); !equal(got, want) {
		t.Fatalf("statuses %v, want %v (%+v)", got, want, res.Results)
	}
}

func TestFailNext(t *testing.T) {
	s := newServer(t)
	s.FailNext(2, http.StatusServiceUnavailable)
	for i, want := range []int{503, 503, 200} {
		if code, _ := send(t, s, snapshot("m1", map[string]any{"a": 1})); code != want {
			t.Fatalf("request %d: status %d, want %d", i, code, want)
		}
	}
	reqs := s.Requests()
	if len(reqs) != 3 || reqs[0].Status != 503 || reqs[2].Status != 200 {
		t.Fatalf("requests %+v", reqs)
	}
	if len(reqs[0].Batch.Messages) != 1 {
		t.Fatalf("a failed request should still record its batch")
	}
}

func TestFailAfterStoring(t *testing.T) {
	s := newServer(t)
	s.FailAfterStoring(1)
	if code, _ := send(t, s, snapshot("m1", map[string]any{"a": 1})); code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", code)
	}
	if n := len(s.Stored()); n != 1 {
		t.Fatalf("%d stored, want 1", n)
	}
	_, res := send(t, s, snapshot("m1", map[string]any{"a": 1}))
	if res.Results[0].Status != push.StatusDuplicate {
		t.Fatalf("resend: %+v, want duplicate", res.Results[0])
	}
}

func TestKnowHeartbeat(t *testing.T) {
	s := newServer(t)
	body, _ := json.Marshal(push.Heartbeat{Collector: "c", Evidence: push.KindConfigSnapshot, EverySeconds: 600, Replica: "r", SDK: "witness-go/test"})
	hb := push.Message{ID: "hb:c:1", Kind: push.KindHeartbeat, CollectedAt: now, Body: body}
	if _, res := send(t, s, hb); res.Results[0].Status != push.StatusUnsupported {
		t.Fatalf("before Know: %+v, want unsupported", res.Results[0])
	}
	s.Know(push.KindHeartbeat)
	hb.ID = "hb:c:2"
	if _, res := send(t, s, hb); res.Results[0].Status != push.StatusAccepted {
		t.Fatalf("after Know: %+v, want accepted", res.Results[0])
	}
	if n := len(s.Stored()); n != 0 {
		t.Fatalf("heartbeats are not evidence, but %d were stored", n)
	}
}

func TestSetKey(t *testing.T) {
	s := newServer(t)
	s.SetKey("hpk_new")
	raw, _ := json.Marshal(push.Batch{Version: push.Version, Messages: []push.Message{snapshot("m1", map[string]any{"a": 1})}})
	if code, _ := post(t, s, "hpk_test", raw); code != http.StatusUnauthorized {
		t.Fatalf("old key: status %d, want 401", code)
	}
	if code, _ := post(t, s, "hpk_new", raw); code != http.StatusOK {
		t.Fatalf("new key: status %d, want 200", code)
	}
}
