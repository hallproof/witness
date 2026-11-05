package push_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hallproof/witness/push"
)

const specDir = "../spec"

// jsonFields lists t's JSON names, with embedded structs flattened, and the
// ones a sender must always send (no omitempty or omitzero).
func jsonFields(t reflect.Type) (names, required []string) {
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			n, r := jsonFields(f.Type)
			names = append(names, n...)
			required = append(required, r...)
			continue
		}
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		names = append(names, name)
		if !strings.Contains(opts, "omitempty") && !strings.Contains(opts, "omitzero") {
			required = append(required, name)
		}
	}
	slices.Sort(names)
	slices.Sort(required)
	return names, required
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func stringsOf(v any) []string {
	xs := asSlice(v)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		s, _ := x.(string)
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// checkObject compares one object schema with a Go type.
func checkObject(t *testing.T, where string, schema map[string]any, typ reflect.Type) {
	t.Helper()
	if schema == nil {
		t.Errorf("%s: no schema", where)
		return
	}
	names, required := jsonFields(typ)
	if got := keysOf(asMap(schema["properties"])); !slices.Equal(got, names) {
		t.Errorf("%s: properties %v, want %v", where, got, names)
	}
	if got := stringsOf(schema["required"]); !slices.Equal(got, required) {
		t.Errorf("%s: required %v, want %v", where, got, required)
	}
}

// openObjects fails for any object schema that forbids unknown fields:
// receivers ignore fields they don't know, so schemas must allow them.
func openObjects(t *testing.T, where string, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		if x["type"] == "object" && x["additionalProperties"] != true {
			t.Errorf("%s: an object schema must set \"additionalProperties\": true", where)
		}
		for k, c := range x {
			openObjects(t, where+"/"+k, c)
		}
	case []any:
		for _, c := range x {
			openObjects(t, where, c)
		}
	}
}

func TestSchemasMatchTypes(t *testing.T) {
	type def struct {
		path string
		typ  reflect.Type
	}
	files := map[string][]def{
		"config_snapshot": {{"", reflect.TypeFor[push.ConfigSnapshot]()}},
		"population":      {{"", reflect.TypeFor[push.Population]()}},
		"heartbeat":       {{"", reflect.TypeFor[push.Heartbeat]()}},
		"event_proof": {
			{"", reflect.TypeFor[push.EventProof]()},
			{"chain_event", reflect.TypeFor[push.ChainEvent]()},
			{"checkpoint", reflect.TypeFor[push.Checkpoint]()},
		},
		"batch": {
			{"", reflect.TypeFor[push.Batch]()},
			{"message", reflect.TypeFor[push.Message]()},
		},
		"response": {
			{"", reflect.TypeFor[push.Response]()},
			{"result", reflect.TypeFor[push.Result]()},
		},
	}
	for file, defs := range files {
		path := filepath.Join(specDir, "schema", file+".schema.json")
		s := readJSON(t, path)
		openObjects(t, file, s)
		for _, d := range defs {
			schema, where := s, file
			if d.path != "" {
				schema, where = asMap(asMap(s["$defs"])[d.path]), file+"#/$defs/"+d.path
			}
			checkObject(t, where, schema, d.typ)
		}
	}
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(specDir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name      string          `json:"name"`
		Kind      string          `json:"kind"`
		Input     json.RawMessage `json:"input"`
		Canonical string          `json:"canonical"`
		Hash      string          `json:"hash"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 6 {
		t.Fatalf("%d vectors, want at least 6", len(vectors))
	}
	for _, v := range vectors {
		dec := json.NewDecoder(bytes.NewReader(v.Input))
		dec.UseNumber()
		var canon []byte
		var hash string
		switch v.Kind {
		case "snapshot":
			var in map[string]any
			if err := dec.Decode(&in); err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			canon, hash = mustOK(push.Canonical(in)), mustOK(push.SnapshotHash(in))
		case "population":
			var in []map[string]any
			if err := dec.Decode(&in); err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			lines := make([][]byte, len(in))
			for i, it := range in {
				lines[i] = mustOK(push.Canonical(it))
			}
			slices.SortFunc(lines, bytes.Compare)
			canon, hash = bytes.Join(lines, []byte("\n")), mustOK(push.PopulationHash(in))
		default:
			t.Fatalf("%s: unknown kind %q", v.Name, v.Kind)
		}
		if string(canon) != v.Canonical {
			t.Errorf("%s: canonical\n got %s\nwant %s", v.Name, canon, v.Canonical)
		}
		if hash != v.Hash {
			t.Errorf("%s: hash %s, want %s", v.Name, hash, v.Hash)
		}
	}
}
