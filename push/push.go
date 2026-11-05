package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Version is the batch format version. It changes only for a breaking change.
const Version = 1

// Limits a receiver enforces.
const (
	MaxMessages   = 100     // messages in one batch
	MaxBatchBytes = 8 << 20 // encoded batch size
	MaxSegment    = 10000   // events in one event proof segment
	MaxItems      = 50000   // items in one population
)

// Kind names a type of message.
type Kind string

// The kinds of message this version of the protocol defines.
const (
	KindConfigSnapshot Kind = "config_snapshot"
	KindPopulation     Kind = "population"
	KindEventProof     Kind = "event_proof"
	// KindHeartbeat says a collector is alive. It is not evidence.
	KindHeartbeat Kind = "heartbeat"
)

// Status is the receiver's answer for one message.
type Status string

// The statuses a receiver can give.
const (
	StatusAccepted    Status = "accepted"
	StatusDuplicate   Status = "duplicate"
	StatusRejected    Status = "rejected"
	StatusUnsupported Status = "unsupported"
)

// Batch is what a sender posts.
type Batch struct {
	Version  int       `json:"version"`
	Messages []Message `json:"messages"`
}

// Message is one piece of evidence. Body holds the kind's body as raw JSON, so
// a message of a kind the receiver does not know still decodes.
type Message struct {
	ID          string          `json:"id"`
	Kind        Kind            `json:"kind"`
	CollectedAt time.Time       `json:"collected_at"`
	Body        json.RawMessage `json:"body"`
}

// Result is the answer for one message.
type Result struct {
	ID         string `json:"id"`
	Status     Status `json:"status"`
	EvidenceID string `json:"evidence_id,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Response is what the receiver returns: one Result per message, in order.
type Response struct {
	Version int      `json:"version"`
	Results []Result `json:"results"`
}

// DecodeBody decodes a message's body into T. Numbers decode as json.Number so
// their exact text survives, and fields T does not know are ignored.
func DecodeBody[T any](m Message) (T, error) {
	var v T
	dec := json.NewDecoder(bytes.NewReader(m.Body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("push: decode %s body: %w", m.Kind, err)
	}
	return v, nil
}
