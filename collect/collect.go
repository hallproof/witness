// Package collect turns what an app knows about itself into evidence for
// Hallproof, on a schedule.
//
// A collector has a key, a title, the tests its evidence supports, an
// interval and a way to collect. The Scheduler runs each collector,
// pushes its evidence the first time and again whenever it changes, and
// sends a heartbeat for each one on a fixed interval so Hallproof knows
// it's still running.
//
// Collect only metadata: who has access, what is configured, what exists.
// Never return secret values, message bodies, prompts or documents.
package collect

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// DefaultEvery is how often a collector runs when its Every is zero.
const DefaultEvery = 15 * time.Minute

// Snapshot collects a system's settings, such as its authentication
// policy.
type Snapshot struct {
	Key         string
	Title       string
	Description string
	// Tests lists the keys of the tests this evidence supports, such as
	// "mfa-enforced".
	Tests []string
	// Every is how often to collect. Zero means DefaultEvery.
	Every time.Duration
	// Collect returns the settings. Numbers given as json.Number keep
	// their exact text.
	Collect func(context.Context) (map[string]any, error)
}

// Population collects a list of things, such as every staff user. Each
// item needs a non-empty string "id", unique within the list.
type Population struct {
	Key         string
	Title       string
	Description string
	// Source says what the items are, such as "staff-users".
	Source string
	Tests  []string
	Every  time.Duration
	// Collect returns the items.
	Collect func(context.Context) ([]map[string]any, error)
}

// EventProof proves, from the app's chain, the events with one of Actions
// on Stream.
type EventProof struct {
	Key         string
	Title       string
	Description string
	Tests       []string
	Every       time.Duration
	// Stream names the chain stream to prove.
	Stream string
	// Actions are the actions to cite.
	Actions []string
}

// ValidKey checks a collector key: 1 to 100 characters of lowercase
// letters, digits, ".", "_" and "-", starting with a letter or digit.
func ValidKey(key string) error {
	if key == "" || len(key) > 100 {
		return fmt.Errorf("witness: collector key %q must be 1 to 100 characters", key)
	}
	for i, r := range key {
		lowerOrDigit := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !lowerOrDigit && (i == 0 || !strings.ContainsRune("._-", r)) {
			return fmt.Errorf("witness: collector key %q may hold only a-z, 0-9, '.', '_' and '-', and must start with a letter or digit", key)
		}
	}
	return nil
}
