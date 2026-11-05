package push_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hallproof/witness/push"
)

func jsonNum(s string) json.Number { return json.Number(s) }

// mustOK returns v, or panics on err, which fails the test with a trace.
func mustOK[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestPopulationHashIgnoresOrder(t *testing.T) {
	a := []map[string]any{{"id": "u1", "role": "admin"}, {"id": "u2", "role": "user"}}
	b := []map[string]any{{"id": "u2", "role": "user"}, {"id": "u1", "role": "admin"}}
	ha := mustOK(push.PopulationHash(a))
	hb := mustOK(push.PopulationHash(b))
	if ha != hb {
		t.Fatalf("order changed the hash: %s != %s", ha, hb)
	}

	c := []map[string]any{{"id": "u1", "role": "user"}, {"id": "u2", "role": "user"}}
	if hc := mustOK(push.PopulationHash(c)); hc == ha {
		t.Fatal("different items gave the same hash")
	}
}

func TestHashKeepsExactNumbers(t *testing.T) {
	h1 := mustOK(push.SnapshotHash(map[string]any{"n": jsonNum("1.10")}))
	h2 := mustOK(push.SnapshotHash(map[string]any{"n": jsonNum("1.1")}))
	if h1 == h2 {
		t.Fatal("1.10 and 1.1 hashed the same")
	}
	if !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("hash %q lacks the sha256: prefix", h1)
	}

	k1 := mustOK(push.SnapshotHash(map[string]any{"b": 1, "a": 2}))
	k2 := mustOK(push.SnapshotHash(map[string]any{"a": 2, "b": 1}))
	if k1 != k2 {
		t.Fatal("key order changed the hash")
	}
}

func TestCanonicalForm(t *testing.T) {
	out := mustOK(push.Canonical(map[string]any{"b": []any{1, "<x>"}, "a": map[string]any{"z": nil, "y": true}}))
	if want := `{"a":{"y":true,"z":null},"b":[1,"<x>"]}`; string(out) != want {
		t.Fatalf("got %s, want %s", out, want)
	}
}

func TestPopulationHashRoundTripsThroughDecode(t *testing.T) {
	items := []map[string]any{{"id": "u1", "n": jsonNum("2.50")}}
	want := mustOK(push.PopulationHash(items))
	p := mustOK(push.DecodeBody[push.Population](push.Message{Body: []byte(`{"items":[{"id":"u1","n":2.50}]}`)}))
	if got := mustOK(push.PopulationHash(p.Items)); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
