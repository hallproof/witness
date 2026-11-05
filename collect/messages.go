package collect

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hallproof/witness/push"
)

// MessageID is an evidence message's ID: the collector's key, a colon, and
// the hex sha256 of the body's canonical JSON.
//
// Copies of an app that collect the same state build the same ID, so
// Hallproof keeps one and answers the rest "duplicate". Changing anything in
// the body, the title and tests included, changes the ID, so Hallproof never
// sees one ID with two bodies.
func MessageID(key string, canonicalBody []byte) string {
	sum := sha256.Sum256(canonicalBody)
	return key + ":" + hex.EncodeToString(sum[:])
}

func common(title, description string, tests []string) push.Common {
	return push.Common{Title: title, Description: description, Tests: tests}
}

// evidence builds a message whose body is body's canonical JSON.
func evidence(key string, kind push.Kind, body any, at time.Time) (push.Message, error) {
	canonical, err := push.Canonical(body)
	if err != nil {
		return push.Message{}, fmt.Errorf("witness: collector %q: %w", key, err)
	}
	return push.Message{ID: MessageID(key, canonical), Kind: kind, CollectedAt: at, Body: canonical}, nil
}

// SnapshotMessage builds s's message for settings collected at at, and
// returns the settings' hash. Nil settings are sent as an empty object.
func SnapshotMessage(s Snapshot, settings map[string]any, at time.Time) (m push.Message, hash string, err error) {
	if settings == nil {
		settings = map[string]any{}
	}
	if hash, err = push.SnapshotHash(settings); err != nil {
		return push.Message{}, "", fmt.Errorf("witness: collector %q: %w", s.Key, err)
	}
	body := push.ConfigSnapshot{Common: common(s.Title, s.Description, s.Tests), Settings: settings, Hash: hash}
	m, err = evidence(s.Key, push.KindConfigSnapshot, body, at)
	return m, hash, err
}

// PopulationMessage builds p's message for items collected at at, and
// returns the items' hash. It checks every item has a unique, non-empty
// string "id", and that there are at most push.MaxItems. Its errors name
// item positions, never item contents.
func PopulationMessage(p Population, items []map[string]any, at time.Time) (m push.Message, hash string, err error) {
	if items == nil {
		items = []map[string]any{}
	}
	if len(items) > push.MaxItems {
		return push.Message{}, "", fmt.Errorf("witness: collector %q returned %d items, more than %d", p.Key, len(items), push.MaxItems)
	}
	seen := make(map[string]int, len(items))
	for i, it := range items {
		id, ok := it["id"].(string)
		if !ok || id == "" {
			return push.Message{}, "", fmt.Errorf("witness: collector %q: item %d has no string id", p.Key, i)
		}
		if j, dup := seen[id]; dup {
			return push.Message{}, "", fmt.Errorf("witness: collector %q: items %d and %d have the same id", p.Key, j, i)
		}
		seen[id] = i
	}
	if hash, err = push.PopulationHash(items); err != nil {
		return push.Message{}, "", fmt.Errorf("witness: collector %q: %w", p.Key, err)
	}
	body := push.Population{Common: common(p.Title, p.Description, p.Tests), Source: p.Source, Items: items, Hash: hash}
	m, err = evidence(p.Key, push.KindPopulation, body, at)
	return m, hash, err
}

// ProofMessage builds e's message for a proof from the chain. The proof's
// title, description and tests are replaced with e's; proof itself is not
// changed.
func ProofMessage(e EventProof, proof *push.EventProof, at time.Time) (push.Message, error) {
	body := *proof
	body.Common = common(e.Title, e.Description, e.Tests)
	return evidence(e.Key, push.KindEventProof, body, at)
}

// HeartbeatMessage builds a heartbeat message with a fresh random ID:
// "hb:", the collector's key, a colon, and 32 hex digits.
func HeartbeatMessage(hb push.Heartbeat, at time.Time) (push.Message, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return push.Message{}, fmt.Errorf("witness: heartbeat id: %w", err)
	}
	body, err := push.Canonical(hb)
	if err != nil {
		return push.Message{}, fmt.Errorf("witness: heartbeat: %w", err)
	}
	return push.Message{
		ID:          "hb:" + hb.Collector + ":" + hex.EncodeToString(nonce[:]),
		Kind:        push.KindHeartbeat,
		CollectedAt: at,
		Body:        body,
	}, nil
}
