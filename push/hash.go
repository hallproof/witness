package push

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonical returns v's canonical JSON: object keys sorted bytewise, no
// insignificant whitespace, numbers as their exact decimal text, strings
// escaped by encoding/json without HTML escaping, arrays in order.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("push: canonical: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("push: canonical: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool, json.Number:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Errorf("push: canonical: %w", err)
		}
		buf.Write(b)
	case string:
		return writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("push: canonical: unexpected type %T", v)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) error {
	var sb bytes.Buffer
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("push: canonical: %w", err)
	}
	buf.Write(bytes.TrimSuffix(sb.Bytes(), []byte("\n")))
	return nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SnapshotHash is the hash of a settings map: sha256 of its canonical JSON.
func SnapshotHash(settings map[string]any) (string, error) {
	b, err := Canonical(settings)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

// PopulationHash is the hash of a list of items. Each item is encoded
// canonically, the encodings are sorted bytewise and joined with a newline, so
// the order of items does not change the hash.
func PopulationHash(items []map[string]any) (string, error) {
	enc := make([][]byte, len(items))
	for i, it := range items {
		b, err := Canonical(it)
		if err != nil {
			return "", err
		}
		enc[i] = b
	}
	sort.Slice(enc, func(i, j int) bool { return bytes.Compare(enc[i], enc[j]) < 0 })
	return digest(bytes.Join(enc, []byte("\n"))), nil
}
