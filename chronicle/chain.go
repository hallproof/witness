package chronicle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/scope"

	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/push"
)

// Platform is the stream name event-proof collectors ask for: the platform
// scope New was given. It is adapter.Platform.
const Platform = adapter.Platform

// DefaultMaxSegment is how many events a proof carries at most when
// WithMaxSegment isn't given. It keeps a proof well inside a batch; keep
// your checkpoints at or below it (Chronicle's every_events).
const DefaultMaxSegment = 2000

// TenantKey is the metadata key Record keeps an event's own TenantID under,
// since the event itself stays on the platform stream.
const TenantKey = "tenant_id"

// Scope names one Chronicle stream: Chronicle keeps one stream per app and
// tenant.
type Scope struct {
	AppID    string `json:"app_id"`
	TenantID string `json:"tenant_id"`
}

// Chain is a chain.Chain over a Chronicle the app already runs. Record
// appends to the platform stream, and Prove proves any named stream from
// its signed checkpoints.
type Chain struct {
	trail       *xchronicle.Chronicle
	store       xchronicle.Storer
	checkpoints checkpoint.Store
	platform    Scope
	streams     map[string]Scope
	maxSegment  int
	signer      checkpoint.Signer
	log         *slog.Logger
	err         error
}

var _ chain.Chain = (*Chain)(nil)

// Option configures a Chain.
type Option func(*Chain)

// WithStream lets Prove take name for the stream of s, beside Platform.
func WithStream(name string, s Scope) Option {
	return func(c *Chain) {
		switch {
		case name == "":
			c.err = errors.Join(c.err, errors.New("witness/chronicle: WithStream needs a name"))
		case s.AppID == "":
			c.err = errors.Join(c.err, fmt.Errorf("witness/chronicle: stream %q needs an app ID", name))
		default:
			c.streams[name] = s
		}
	}
}

// WithMaxSegment sets the most events a proof carries, DefaultMaxSegment
// by default. Values above push.MaxSegment, the most Hallproof takes, are
// lowered to it; values below 1 keep the default. Cited events older than
// the last n events of a checkpoint can't be proven from it, and Prove
// logs how many it dropped.
func WithMaxSegment(n int) Option {
	return func(c *Chain) {
		switch {
		case n < 1:
			c.maxSegment = DefaultMaxSegment
		case n > push.MaxSegment:
			c.maxSegment = push.MaxSegment
		default:
			c.maxSegment = n
		}
	}
}

// WithSigner makes Prove check each checkpoint's signature with s, the
// app's own checkpoint signer, before it returns a proof, so a bad
// signature shows up as an error here and not as a rejection in Hallproof.
func WithSigner(s checkpoint.Signer) Option {
	return func(c *Chain) { c.signer = s }
}

// WithLogger sets where the chain logs. The default is slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *Chain) {
		if l != nil {
			c.log = l
		}
	}
}

// New returns a Chain over trail. platform is the stream Record writes to
// and the one the stream name Platform means. New fails when trail has no
// store, or its store keeps no checkpoints, since there is nothing to
// prove from.
func New(trail *xchronicle.Chronicle, platform Scope, opts ...Option) (*Chain, error) {
	if trail == nil {
		return nil, errors.New("witness/chronicle: New needs a Chronicle")
	}
	if platform.AppID == "" {
		return nil, errors.New("witness/chronicle: the platform scope needs an app ID")
	}
	store := trail.Store()
	if store == nil {
		return nil, errors.New("witness/chronicle: the Chronicle has no store")
	}
	cps, ok := store.(checkpoint.Store)
	if !ok {
		return nil, fmt.Errorf("witness/chronicle: the Chronicle's store (%T) keeps no checkpoints, so there is nothing to prove from", store)
	}
	c := &Chain{
		trail: trail, store: store, checkpoints: cps, platform: platform,
		streams: map[string]Scope{}, maxSegment: DefaultMaxSegment, log: slog.Default(),
	}
	for _, o := range opts {
		o(c)
	}
	if c.err != nil {
		return nil, c.err
	}
	c.streams[Platform] = platform
	return c, nil
}

// Record appends e to the platform stream. Action, Resource and Category
// are required. An empty Outcome is "success" and an empty Severity
// "info". e's TenantID doesn't pick a stream: the event stays on the
// platform stream, which is the one witness proves, and a TenantID other
// than the platform's is kept in the metadata under TenantKey.
func (c *Chain) Record(ctx context.Context, e chain.Event) error {
	var missing []string
	if e.Action == "" {
		missing = append(missing, "Action")
	}
	if e.Resource == "" {
		missing = append(missing, "Resource")
	}
	if e.Category == "" {
		missing = append(missing, "Category")
	}
	if len(missing) > 0 {
		return fmt.Errorf("witness/chronicle: an event needs %v", missing)
	}
	if e.Outcome == "" {
		e.Outcome = chain.OutcomeSuccess
	}
	if e.Severity == "" {
		e.Severity = chain.SeverityInfo
	}
	meta := e.Metadata
	if e.TenantID != "" && e.TenantID != c.platform.TenantID {
		if _, taken := meta[TenantKey]; !taken {
			meta = maps.Clone(meta)
			if meta == nil {
				meta = map[string]any{}
			}
			meta[TenantKey] = e.TenantID
		}
	}
	ev := &audit.Event{
		AppID: c.platform.AppID, TenantID: c.platform.TenantID,
		Action: e.Action, Resource: e.Resource, ResourceID: e.ResourceID, Category: e.Category,
		Outcome: e.Outcome, Severity: e.Severity, Reason: e.Reason,
		UserID: e.UserID, SessionID: e.SessionID, RequestID: e.RequestID, IP: e.IP, UserAgent: e.UserAgent,
		Metadata: meta,
	}
	if !e.Time.IsZero() {
		ev.Timestamp = e.Time.UTC()
	}
	// Chronicle fills an empty AppID or TenantID from the context's scope,
	// which would move a tenantless platform's event to a customer's
	// stream. Pin both in the context too.
	ctx = scope.WithTenantID(scope.WithAppID(ctx, c.platform.AppID), c.platform.TenantID)
	if err := c.trail.Record(ctx, ev); err != nil {
		return fmt.Errorf("witness/chronicle: record: %w", err)
	}
	return nil
}
