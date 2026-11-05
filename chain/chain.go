// Package chain is where witness records what happens in an app, as a
// tamper-evident signed chain, and proves it to Hallproof.
//
// Chain is the interface. Witness ships only Unconfigured, which records
// nothing: event recording is off until the app gives witness a real chain.
// github.com/hallproof/witness/chronicle proves events from a Chronicle the
// app already runs, and a later release adds a chain witness runs itself.
// Either way the proofs are Chronicle segments with signed checkpoints, the
// form Hallproof verifies.
package chain

import (
	"context"
	"errors"
	"time"

	"github.com/hallproof/witness/push"
)

// Outcomes, as Chronicle's audit package names them.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Severities, as Chronicle's audit package names them.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

var (
	// ErrNoChain means no chain is configured, so nothing is recorded or
	// proven.
	ErrNoChain = errors.New("witness: no chain is configured")
	// ErrNothingNew means the chain has sealed no checkpoint since the one
	// a ProofRequest starts from.
	ErrNothingNew = errors.New("witness: no new checkpoint to prove")
)

// Event is one thing that happened, to append to the chain. Its fields
// mirror Chronicle's audit.Event. Metadata holds facts about the event,
// never request bodies or other content.
type Event struct {
	Time       time.Time
	Action     string
	Resource   string
	ResourceID string
	Category   string
	// Outcome is OutcomeSuccess, OutcomeFailure or OutcomeDenied.
	Outcome string
	// Severity is SeverityInfo, SeverityWarning or SeverityCritical.
	Severity  string
	Reason    string
	UserID    string
	TenantID  string
	SessionID string
	RequestID string
	IP        string
	UserAgent string
	Metadata  map[string]any
}

// ProofRequest asks for a signed segment of one stream.
type ProofRequest struct {
	// Stream names the chain stream, such as a Chronicle stream ID.
	Stream string
	// From is the last checkpoint already proven, or "" for the stream's
	// start. The segment begins after it.
	From string
	// To is the checkpoint the segment ends at, or "" for the newest one
	// the chain has sealed.
	To string
	// Actions are the actions to cite. The proof's Cited holds the
	// sequences of the segment's events with one of these actions.
	Actions []string
}

// Chain records events and proves segments of them.
type Chain interface {
	// Record appends one event.
	Record(ctx context.Context, e Event) error
	// Prove returns a signed segment, or ErrNothingNew when no checkpoint
	// was sealed after r.From.
	Prove(ctx context.Context, r ProofRequest) (*push.EventProof, error)
}

// Unconfigured is the chain witness uses when the app gives it none. Both
// methods return ErrNoChain.
type Unconfigured struct{}

// Record returns ErrNoChain.
func (Unconfigured) Record(context.Context, Event) error { return ErrNoChain }

// Prove returns ErrNoChain.
func (Unconfigured) Prove(context.Context, ProofRequest) (*push.EventProof, error) {
	return nil, ErrNoChain
}
