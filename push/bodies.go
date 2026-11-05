package push

import "time"

// Common is embedded in every evidence body. A heartbeat is not evidence and has
// none.
type Common struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	// Tests lists the keys of the tests this evidence supports, such as "mfa-enforced".
	Tests []string `json:"tests,omitempty"`
}

// ConfigSnapshot is a system's settings at a point in time.
type ConfigSnapshot struct {
	Common
	Settings map[string]any `json:"settings"`
	Hash     string         `json:"hash"`
}

// Population is a list of items, such as every user. Every item has a
// non-empty string "id", unique within the population.
type Population struct {
	Common
	Source string           `json:"source"`
	Items  []map[string]any `json:"items"`
	Hash   string           `json:"hash"`
}

// EventProof is a signed slice of an audit chain that backs up the cited
// events.
type EventProof struct {
	Common
	Cited      []uint64     `json:"cited"`
	Segment    []ChainEvent `json:"segment"`
	Checkpoint Checkpoint   `json:"checkpoint"`
}

// ChainEvent mirrors Chronicle's audit.Event, with the same JSON names.
type ChainEvent struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	Sequence      uint64         `json:"sequence"`
	Hash          string         `json:"hash"`
	PrevHash      string         `json:"prev_hash"`
	StreamID      string         `json:"stream_id"`
	AppID         string         `json:"app_id"`
	TenantID      string         `json:"tenant_id,omitempty"`
	UserID        string         `json:"user_id,omitempty"`
	IP            string         `json:"ip,omitempty"`
	UserAgent     string         `json:"user_agent,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	Action        string         `json:"action"`
	Resource      string         `json:"resource"`
	Category      string         `json:"category"`
	ResourceID    string         `json:"resource_id,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	Outcome       string         `json:"outcome"`
	Severity      string         `json:"severity"`
	Reason        string         `json:"reason,omitempty"`
	SubjectID     string         `json:"subject_id,omitempty"`
	ExactMetadata bool           `json:"exact_metadata,omitempty"`
	HashScheme    string         `json:"hash_scheme,omitempty"`
	HashKeyID     string         `json:"hash_key_id,omitempty"`
}

// Checkpoint mirrors Chronicle's checkpoint.Checkpoint, with the same JSON
// names. Signature is base64 in JSON.
type Checkpoint struct {
	ID             string    `json:"id"`
	StreamID       string    `json:"stream_id"`
	AppID          string    `json:"app_id"`
	TenantID       string    `json:"tenant_id,omitempty"`
	FromSeq        uint64    `json:"from_seq"`
	ToSeq          uint64    `json:"to_seq"`
	FromHash       string    `json:"from_hash"`
	ToHash         string    `json:"to_hash"`
	EventCount     int64     `json:"event_count"`
	PrevCheckpoint string    `json:"prev_checkpoint,omitempty"`
	Algorithm      string    `json:"algorithm"`
	SignKeyID      string    `json:"sign_key_id"`
	Signature      []byte    `json:"signature"`
	SignedPayload  string    `json:"signed_payload"`
	CreatedAt      time.Time `json:"created_at"`
}

// Heartbeat says a collector is alive. It is not evidence and has no Common.
// A sender sends one per collector on a fixed interval, whether or not the
// collector's state changed, each with a fresh message ID.
type Heartbeat struct {
	// Collector is the collector's key.
	Collector string `json:"collector"`
	// Evidence is the kind of evidence the collector pushes.
	Evidence Kind `json:"evidence"`
	// Hash is the content hash from the collector's last good run.
	Hash string `json:"hash,omitempty"`
	// Healthy is false when the collector's last run failed.
	Healthy bool `json:"healthy"`
	// LastSuccess is when the collector's last good run finished.
	LastSuccess time.Time `json:"last_success,omitzero"`
	// EverySeconds is the heartbeat interval, so a receiver can tell when
	// one is late.
	EverySeconds int `json:"every_seconds"`
	// Replica says which copy of the app sent the heartbeat.
	Replica string `json:"replica"`
	// SDK names the sender and its version, such as "witness-go/0.1.0".
	SDK string `json:"sdk"`
}
