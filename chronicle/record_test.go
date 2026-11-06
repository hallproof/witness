package chronicle_test

import (
	"context"
	"errors"
	"testing"
	"time"

	xchronicle "github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/scope"
	chronstore "github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"

	"github.com/hallproof/witness/chain"
	wchronicle "github.com/hallproof/witness/chronicle"
)

// events reads back every event of the (app, tenant) stream.
func events(t *testing.T, trail *xchronicle.Chronicle, app, tenant string) []*audit.Event {
	t.Helper()
	ctx := context.Background()
	st, err := trail.Store().GetStreamByScope(ctx, app, tenant)
	if errors.Is(err, xchronicle.ErrStreamNotFound) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	evs, err := trail.Store().EventRange(ctx, st.ID, 1, st.HeadSeq)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestRecordDefaultsAndValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	for name, e := range map[string]chain.Event{
		"no action":   {Resource: "session", Category: "auth"},
		"no resource": {Action: "user.login", Category: "auth"},
		"no category": {Action: "user.login", Resource: "session"},
	} {
		if err := f.chain.Record(ctx, e); err == nil {
			t.Fatalf("%s: recorded", name)
		}
	}
	if evs := events(t, f.trail, appID, tenantID); len(evs) != 0 {
		t.Fatalf("invalid events reached Chronicle: %d", len(evs))
	}

	if err := f.chain.Record(ctx, chain.Event{Action: "user.login", Resource: "session", Category: "auth"}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 2, 10, 0, 0, 5, time.FixedZone("x", 3600))
	if err := f.chain.Record(ctx, chain.Event{
		Time: at, Action: "user.logout", Resource: "session", ResourceID: "s1", Category: "auth",
		Outcome: chain.OutcomeDenied, Severity: chain.SeverityCritical, Reason: "policy",
		UserID: "u1", SessionID: "sid", RequestID: "rid", IP: "203.0.113.9", UserAgent: "ua",
	}); err != nil {
		t.Fatal(err)
	}

	evs := events(t, f.trail, appID, tenantID)
	if len(evs) != 2 {
		t.Fatalf("%d events", len(evs))
	}
	if e := evs[0]; e.Outcome != audit.OutcomeSuccess || e.Severity != audit.SeverityInfo || e.Timestamp.IsZero() || e.AppID != appID {
		t.Fatalf("defaults: %+v", e)
	}
	e := evs[1]
	if e.Outcome != chain.OutcomeDenied || e.Severity != chain.SeverityCritical || e.Reason != "policy" ||
		e.UserID != "u1" || e.SessionID != "sid" || e.RequestID != "rid" || e.IP != "203.0.113.9" ||
		e.UserAgent != "ua" || e.ResourceID != "s1" || !e.Timestamp.Equal(at) {
		t.Fatalf("fields: %+v", e)
	}
}

func TestRecordGoesToPlatformStream(t *testing.T) {
	f := newFixture(t)
	// The request's own scope names a customer; the event names another.
	ctx := scope.WithInfo(context.Background(), scope.Info{AppID: "customer-app", TenantID: "cust-1", UserID: "ctx-user"})
	meta := map[string]any{"route": "/admin"}
	if err := f.chain.Record(ctx, chain.Event{Action: "admin.view", Resource: "page", Category: "admin", TenantID: "cust-2", Metadata: meta}); err != nil {
		t.Fatal(err)
	}

	evs := events(t, f.trail, appID, tenantID)
	if len(evs) != 1 {
		t.Fatalf("%d events on the platform stream", len(evs))
	}
	if evs[0].Metadata["tenant_id"] != "cust-2" || evs[0].Metadata["route"] != "/admin" {
		t.Fatalf("metadata %v", evs[0].Metadata)
	}
	if evs[0].UserID != "ctx-user" {
		t.Fatalf("user from the context: %q", evs[0].UserID)
	}
	if len(meta) != 1 {
		t.Fatalf("the caller's metadata changed: %v", meta)
	}
	for _, s := range [][2]string{{"customer-app", "cust-1"}, {appID, "cust-1"}, {appID, "cust-2"}} {
		if evs := events(t, f.trail, s[0], s[1]); len(evs) != 0 {
			t.Fatalf("an event reached stream %v", s)
		}
	}

	// A platform with no tenant stays on the tenantless stream, whatever
	// the context says.
	trail, err := xchronicle.New(xchronicle.WithStore(chronstore.NewAdapter(memory.New())))
	if err != nil {
		t.Fatal(err)
	}
	c, err := wchronicle.New(trail, wchronicle.Scope{AppID: appID})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Record(ctx, chain.Event{Action: "admin.view", Resource: "page", Category: "admin"}); err != nil {
		t.Fatal(err)
	}
	if len(events(t, trail, appID, "")) != 1 || len(events(t, trail, appID, "cust-1")) != 0 {
		t.Fatal("a tenantless platform's event went to the context's tenant")
	}
}

// noCheckpoints is a store that keeps no checkpoints.
type noCheckpoints struct{ xchronicle.Storer }

func TestNew(t *testing.T) {
	trail, err := xchronicle.New(xchronicle.WithStore(chronstore.NewAdapter(memory.New())))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wchronicle.New(nil, platform); err == nil {
		t.Fatal("nil Chronicle accepted")
	}
	if _, err = wchronicle.New(trail, wchronicle.Scope{TenantID: "staff"}); err == nil {
		t.Fatal("a platform with no app accepted")
	}
	bare, err := xchronicle.New(xchronicle.WithStore(noCheckpoints{chronstore.NewAdapter(memory.New())}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wchronicle.New(bare, platform); err == nil {
		t.Fatal("a store without checkpoints accepted")
	}
	noStore, err := xchronicle.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wchronicle.New(noStore, platform); err == nil {
		t.Fatal("a Chronicle without a store accepted")
	}
	if _, err := wchronicle.New(trail, platform, wchronicle.WithStream("", platform)); err == nil {
		t.Fatal("an empty stream name accepted")
	}
	if _, err := wchronicle.New(trail, platform, wchronicle.WithStream("other", wchronicle.Scope{})); err == nil {
		t.Fatal("a stream with no app accepted")
	}
	var _ chain.Chain = (*wchronicle.Chain)(nil)
}
