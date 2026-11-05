package push_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hallproof/witness/push"
)

func mustBody(t *testing.T, v any) json.RawMessage {
	t.Helper()
	return mustOK(json.Marshal(v))
}

// jsonEqual reports whether a and b hold the same JSON value.
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

func TestBatchRoundTrip(t *testing.T) {
	at := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	common := push.Common{Title: "t", Description: "d", Tests: []string{"mfa-enforced"}}
	batch := push.Batch{
		Version: push.Version,
		Messages: []push.Message{
			{ID: "m1", Kind: push.KindConfigSnapshot, CollectedAt: at, Body: mustBody(t, push.ConfigSnapshot{
				Common: common, Settings: map[string]any{"mfa": true}, Hash: "sha256:aa",
			})},
			{ID: "m2", Kind: push.KindPopulation, CollectedAt: at, Body: mustBody(t, push.Population{
				Common: common, Source: "users", Items: []map[string]any{{"id": "u1"}}, Hash: "sha256:bb",
			})},
			{ID: "m3", Kind: push.KindEventProof, CollectedAt: at, Body: mustBody(t, push.EventProof{
				Common: common,
				Cited:  []uint64{2},
				Segment: []push.ChainEvent{{
					ID: "evt_1", Timestamp: at, Sequence: 2, Hash: "h2", PrevHash: "h1",
					StreamID: "stream_1", AppID: "app", Action: "login", Resource: "user",
					Category: "auth", Outcome: "success", Severity: "info",
					Metadata: map[string]any{"k": "v"},
				}},
				Checkpoint: push.Checkpoint{
					ID: "cp_1", StreamID: "stream_1", AppID: "app", FromSeq: 1, ToSeq: 2,
					EventCount: 2, Algorithm: "ed25519", SignKeyID: "key1",
					Signature: []byte{1, 2, 3}, CreatedAt: at,
				},
			})},
		},
	}

	raw := mustOK(json.Marshal(batch))
	for _, want := range []string{`"collected_at"`, `"sign_key_id"`, `"prev_hash"`, `"signature":"AQID"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("encoded batch lacks %s", want)
		}
	}

	var back push.Batch
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Version != batch.Version {
		t.Fatalf("version %d, want %d", back.Version, batch.Version)
	}
	if len(back.Messages) != 3 {
		t.Fatalf("%d messages, want 3", len(back.Messages))
	}

	proof := mustOK(push.DecodeBody[push.EventProof](back.Messages[2]))
	if !reflect.DeepEqual(proof.Cited, []uint64{2}) {
		t.Errorf("cited %v", proof.Cited)
	}
	if !bytes.Equal(proof.Checkpoint.Signature, []byte{1, 2, 3}) {
		t.Errorf("signature %v", proof.Checkpoint.Signature)
	}
	if proof.Segment[0].PrevHash != "h1" {
		t.Errorf("prev_hash %q", proof.Segment[0].PrevHash)
	}
	if !proof.Segment[0].Timestamp.Equal(at) {
		t.Errorf("timestamp %v", proof.Segment[0].Timestamp)
	}
	if !reflect.DeepEqual(proof.Tests, []string{"mfa-enforced"}) {
		t.Errorf("tests %v", proof.Tests)
	}

	snap := mustOK(push.DecodeBody[push.ConfigSnapshot](back.Messages[0]))
	if snap.Settings["mfa"] != true {
		t.Errorf("settings %v", snap.Settings)
	}
}

func TestDecodeBodyIgnoresUnknownFields(t *testing.T) {
	m := push.Message{ID: "m", Kind: push.KindPopulation, Body: json.RawMessage(
		`{"title":"x","source":"users","items":[{"id":"u1","n":1.10}],"hash":"sha256:z","future_field":1}`)}
	p := mustOK(push.DecodeBody[push.Population](m))
	if p.Source != "users" {
		t.Errorf("source %q", p.Source)
	}
	if p.Items[0]["n"] != json.Number("1.10") {
		t.Errorf("n %#v, want json.Number 1.10", p.Items[0]["n"])
	}
}

func TestUnknownKindDecodes(t *testing.T) {
	raw := `{"version":1,"messages":[{"id":"m1","kind":"route_map","collected_at":"2026-11-03T10:00:00Z","body":{"routes":[1,2]}}]}`
	var b push.Batch
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatal(err)
	}
	if len(b.Messages) != 1 {
		t.Fatalf("%d messages, want 1", len(b.Messages))
	}
	if b.Messages[0].Kind != push.Kind("route_map") {
		t.Errorf("kind %q", b.Messages[0].Kind)
	}
	if !jsonEqual(t, b.Messages[0].Body, []byte(`{"routes":[1,2]}`)) {
		t.Errorf("body %s", b.Messages[0].Body)
	}
}

func TestStatusAndLimits(t *testing.T) {
	for name, c := range map[string][2]int{
		"Version":       {push.Version, 1},
		"MaxMessages":   {push.MaxMessages, 100},
		"MaxBatchBytes": {push.MaxBatchBytes, 8 << 20},
		"MaxSegment":    {push.MaxSegment, 10000},
		"MaxItems":      {push.MaxItems, 50000},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %d, want %d", name, c[0], c[1])
		}
	}
	raw := mustOK(json.Marshal(push.Result{ID: "m", Status: push.StatusAccepted}))
	if !jsonEqual(t, raw, []byte(`{"id":"m","status":"accepted"}`)) {
		t.Errorf("result %s", raw)
	}
}

func TestHeartbeatKind(t *testing.T) {
	if push.KindHeartbeat != "heartbeat" {
		t.Fatalf("KindHeartbeat = %q", push.KindHeartbeat)
	}
}

func TestHeartbeatJSON(t *testing.T) {
	hb := push.Heartbeat{
		Collector: "auth-settings", Evidence: push.KindConfigSnapshot,
		EverySeconds: 600, Replica: "web-1", SDK: "witness-go/0.1.0",
	}
	raw := mustOK(json.Marshal(hb))
	want := `{"collector":"auth-settings","evidence":"config_snapshot","healthy":false,"every_seconds":600,"replica":"web-1","sdk":"witness-go/0.1.0"}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}

	hb.Hash = "sha256:ab"
	hb.Healthy = true
	hb.LastSuccess = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	raw = mustOK(json.Marshal(hb))
	for _, part := range []string{`"hash":"sha256:ab"`, `"healthy":true`, `"last_success":"2026-11-04T12:00:00Z"`} {
		if !strings.Contains(string(raw), part) {
			t.Errorf("%s lacks %s", raw, part)
		}
	}
}
