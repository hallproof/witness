package authsome

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	authsome "github.com/xraph/authsome"
	"github.com/xraph/authsome/appclientconfig"
	"github.com/xraph/authsome/id"
	"github.com/xraph/authsome/organization"
	"github.com/xraph/authsome/principal"
	"github.com/xraph/authsome/serviceaccount"
	"github.com/xraph/authsome/store"
	"github.com/xraph/authsome/store/memory"
	"github.com/xraph/authsome/user"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/ingesttest"
)

func TestRegistered(t *testing.T) {
	var found *adapter.Adapter
	for _, a := range adapter.Adapters() {
		if a.Name == "authsome" {
			found = &a
		}
	}
	if found == nil {
		t.Fatal("authsome adapter not registered")
	}
	if found.Module != "github.com/xraph/authsome" {
		t.Errorf("Module = %q", found.Module)
	}
	if !slices.Contains(found.After, "authsome") {
		t.Errorf("After = %v, want the authsome extension", found.After)
	}
	if found.Chain {
		t.Error("authsome is not a chain adapter")
	}
}

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	srv := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: srv.URL, IngestKey: srv.Key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	attach := registered(t).Attach
	for name, c := range map[string]any{"empty vessel": vessel.New(), "nil": nil, "not a vessel": struct{}{}} {
		found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c})
		if found || err != nil {
			t.Errorf("%s: found=%v err=%v, want false, nil", name, found, err)
		}
	}
}

func TestAttachFindsEngineAndDecodesConfig(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	found, err := registered(t).Attach(context.Background(), adapter.Host{
		Witness:   newWitness(t),
		Container: c,
		Config:    map[string]any{"event_proofs": true, "unknown": 1},
	})
	if !found || err != nil {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestAttachRejectsBadConfig(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	found, err := registered(t).Attach(context.Background(), adapter.Host{
		Witness: newWitness(t), Container: c, Config: map[string]any{"event_proofs": "yes"},
	})
	if !found || err == nil {
		t.Fatalf("found=%v err=%v, want found and an error", found, err)
	}
}

func registered(t *testing.T) adapter.Adapter {
	t.Helper()
	for _, a := range adapter.Adapters() {
		if a.Name == "authsome" {
			return a
		}
	}
	t.Fatal("authsome adapter not registered")
	return adapter.Adapter{}
}

func TestRegisterAddsCollectors(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	if err := New(f.eng).Register(newWitness(t)); err != nil {
		t.Fatal(err)
	}
	if err := New(nil).Register(newWitness(t)); err == nil {
		t.Error("Register with a nil engine should fail")
	}
}

func TestCollectorsWithoutPlugins(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	b := build(t, New(f.eng))
	want := []string{"authsome.agent-grants", "authsome.service-accounts", "authsome.staff-sessions", "authsome.staff-users"}
	if got := keys(b.pops); !slices.Equal(got, want) {
		t.Errorf("populations = %v, want %v", got, want)
	}
	if got := keys(b.snaps); !slices.Equal(got, []string{"authsome.auth-policy"}) {
		t.Errorf("snapshots = %v", got)
	}
	if len(b.proofs) != 0 {
		t.Errorf("event proofs on by default: %v", keys(b.proofs))
	}
}

func TestCollectorsWithPluginsAndOptions(t *testing.T) {
	f := newFixture(t, fixtureOpts{plugins: true})
	b := build(t, New(f.eng, WithAPIKeys(), WithEventProofs()))
	for _, k := range []string{"authsome.agents", "authsome.staff-api-keys"} {
		if _, ok := b.pops[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	want := []string{"authsome.access-change-proof", "authsome.agent-proof", "authsome.deprovision-proof", "authsome.mfa-proof"}
	if got := keys(b.proofs); !slices.Equal(got, want) {
		t.Errorf("event proofs = %v, want %v", got, want)
	}
	for _, e := range b.proofs {
		if e.Stream != adapter.Platform || len(e.Actions) == 0 || len(e.Tests) == 0 {
			t.Errorf("%s: stream %q, %d actions, tests %v", e.Key, e.Stream, len(e.Actions), e.Tests)
		}
	}
}

func keys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestStaffUsers(t *testing.T) {
	f := newFixture(t, fixtureOpts{plugins: true})
	owner := f.addUser("owner@example.com", "platform-owner")
	admin := f.addUser("admin@example.com", "platform-admin")
	f.addUser("customer@example.com")
	f.enrolTOTP(owner)
	org := f.addOrgMember(owner, organization.RoleOwner)
	f.addSession(owner, time.Now().Add(time.Hour))
	f.addSession(owner, time.Now().Add(-time.Hour)) // expired, not counted

	items := ids(population(t, New(f.eng), "authsome.staff-users"))
	if len(items) != 2 {
		t.Fatalf("got %d staff, want 2: %v", len(items), keys(items))
	}
	o := items[owner.String()]
	if o == nil {
		t.Fatal("owner missing")
	}
	checks := map[string]any{
		"email":           "owner@example.com",
		"name":            "Ada Staff",
		"app_id":          f.app.String(),
		"email_verified":  true,
		"banned":          false,
		"privileged":      true,
		"mfa_totp":        true,
		"mfa_any":         true,
		"mfa_plugin":      true,
		"active_sessions": 1,
		"last_seen_on":    time.Now().UTC().Format(time.DateOnly),
	}
	for k, want := range checks {
		if fmt.Sprint(o[k]) != fmt.Sprint(want) {
			t.Errorf("owner %s = %v, want %v", k, o[k], want)
		}
	}
	if got := fmt.Sprint(o["platform_roles"]); got != "[platform-owner platform-user]" {
		t.Errorf("platform_roles = %s", got)
	}
	if got := mustJSON(t, o["org_roles"]); got != fmt.Sprintf(`[{"org_id":%q,"role":"owner"}]`, org.String()) {
		t.Errorf("org_roles = %s", got)
	}
	a := items[admin.String()]
	if a["mfa_totp"] != false || a["active_sessions"] != 0 || a["last_seen_on"] != nil {
		t.Errorf("admin: %v", a)
	}
}

func TestStaffUsersWithoutMFAPlugin(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	uid := f.addUser("owner@example.com", "platform-owner")
	o := ids(population(t, New(f.eng), "authsome.staff-users"))[uid.String()]
	if o["mfa_plugin"] != false || o["mfa_totp"] != false || o["mfa_any"] != false {
		t.Errorf("without mfa: %v", o)
	}
}

func TestAuthPolicy(t *testing.T) {
	f := newFixture(t, fixtureOpts{config: func(c *authsome.Config) {
		c.Password.MinLength = 14
		c.Password.RequireDigit = true
		c.Lockout.MaxAttempts = 7
	}})
	on := true
	if err := f.store.SetAppClientConfig(f.ctx, &appclientconfig.Config{ID: id.NewAppClientConfigID(), AppID: f.app, MFARequired: &on, MFAMethods: []string{"totp"}}); err != nil {
		t.Fatal(err)
	}
	s := snapshot(t, New(f.eng, WithInactivityEnforced()), "authsome.auth-policy")
	checks := map[string]any{
		"app_id":                             f.app.String(),
		"mfa_plugin":                         false,
		"mfa_required":                       true,
		"mfa_enabled":                        nil,
		"mfa_methods":                        []string{"totp"},
		"password_min_length":                14,
		"password_require_digit":             true,
		"password_require_special":           false,
		"lockout_enabled":                    true,
		"lockout_max_attempts":               7,
		"lockout_duration_seconds":           900,
		"lockout_reset_after_seconds":        3600,
		"session_inactivity_enforced":        true,
		"session_absolute_lifetime_seconds":  2592000,
		"session_inactivity_timeout_seconds": 604800,
		"session_bind_to_ip":                 false,
	}
	for k, want := range checks {
		got, ok := s[k]
		if !ok {
			t.Errorf("missing %s", k)
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	for _, k := range []string{"session_token_ttl_seconds", "session_refresh_ttl_seconds", "session_max_active", "session_rotate_refresh", "session_bind_to_device", "require_email_verification", "password_algorithm", "password_check_breached", "password_history_count", "password_max_age_days", "password_require_uppercase", "password_require_lowercase"} {
		if _, ok := s[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if s := snapshot(t, New(f.eng), "authsome.auth-policy"); s["session_inactivity_enforced"] != false {
		t.Error("inactivity enforcement claimed without the option")
	}
}

func TestStaffSessions(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	owner := f.addUser("owner@example.com", "platform-owner")
	cust := f.addUser("customer@example.com")
	live := f.addSession(owner, time.Now().Add(time.Hour))
	f.addSession(owner, time.Now().Add(-time.Hour))
	f.addSession(cust, time.Now().Add(time.Hour))

	items := ids(population(t, New(f.eng), "authsome.staff-sessions"))
	if len(items) != 1 || items[live.String()] == nil {
		t.Fatalf("sessions = %v, want only %s", keys(items), live)
	}
	s := items[live.String()]
	if s["user_id"] != owner.String() || s["principal_kind"] != "user" || s["last_active_on"] != time.Now().UTC().Format(time.DateOnly) {
		t.Errorf("session: %v", s)
	}
}

func TestStaffAPIKeys(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	owner := f.addUser("owner@example.com", "platform-owner")
	cust := f.addUser("customer@example.com")
	mine := f.addAPIKey(owner, id.ServiceAccountID{})
	f.addAPIKey(cust, id.ServiceAccountID{})
	svc := f.addServiceAccount(owner, id.OrgID{}, principal.KindService)
	svcKey := f.addAPIKey(id.UserID{}, svc)
	custSvc := f.addServiceAccount(cust, id.NewOrgID(), principal.KindService)
	f.addAPIKey(id.UserID{}, custSvc)

	items := ids(population(t, New(f.eng, WithAPIKeys()), "authsome.staff-api-keys"))
	if len(items) != 2 || items[mine.String()] == nil || items[svcKey.String()] == nil {
		t.Fatalf("keys = %v, want %s and %s", keys(items), mine, svcKey)
	}
	k := items[mine.String()]
	if k["name"] != "deploy" || k["revoked"] != false || k["last_used_on"] == nil || k["user_id"] != owner.String() {
		t.Errorf("key: %v", k)
	}
	if items[svcKey.String()]["service_account_id"] != svc.String() {
		t.Errorf("service account key: %v", items[svcKey.String()])
	}
}

func TestServiceAccounts(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	owner := f.addUser("owner@example.com", "platform-owner")
	cust := f.addUser("customer@example.com")
	staffOwned := f.addServiceAccount(owner, id.NewOrgID(), principal.KindAgent)
	platform := f.addServiceAccount(id.UserID{}, id.OrgID{}, principal.KindWorkload)
	custOrg := f.addServiceAccount(cust, id.NewOrgID(), principal.KindAgent)

	items := ids(population(t, New(f.eng), "authsome.service-accounts"))
	if len(items) != 2 || items[staffOwned.String()] == nil || items[platform.String()] == nil {
		t.Fatalf("service accounts = %v", keys(items))
	}
	if items[custOrg.String()] != nil {
		t.Error("customer org service account collected")
	}
	s := items[staffOwned.String()]
	if s["kind"] != "agent" || s["owner_user_id"] != owner.String() || s["active"] != true {
		t.Errorf("service account: %v", s)
	}
	if items[platform.String()]["owner_user_id"] != nil {
		t.Errorf("unowned account has owner %v", items[platform.String()]["owner_user_id"])
	}
}

func TestAgentGrants(t *testing.T) {
	f := newFixture(t, fixtureOpts{plugins: true})
	owner := f.addUser("owner@example.com", "platform-owner")
	cust := f.addUser("customer@example.com")
	agent := f.addAgent(owner, id.OrgID{})
	g := f.addAgentGrant(agent, owner)
	f.addAgentGrant(agent, cust)
	bot := f.addServiceAccount(owner, id.OrgID{}, principal.KindAgent)
	botRef := principal.Ref{Kind: principal.KindAgent, ID: bot.String()}
	d1 := f.addDelegation(botRef, principal.UserRef(owner))
	other := f.addServiceAccount(id.UserID{}, id.OrgID{}, principal.KindAgent)
	d2 := f.addDelegation(principal.Ref{Kind: principal.KindAgent, ID: other.String()}, principal.UserRef(owner))
	custBot := f.addServiceAccount(cust, id.NewOrgID(), principal.KindAgent)
	f.addDelegation(principal.Ref{Kind: principal.KindAgent, ID: custBot.String()}, principal.UserRef(cust))
	// A staff-owned agent acting for a customer still belongs to staff.
	d3 := f.addDelegation(botRef, principal.UserRef(cust))

	items := ids(population(t, New(f.eng), "authsome.agent-grants"))
	want := []string{d1.String(), d2.String(), d3.String(), g.String()}
	sort.Strings(want)
	if got := keys(items); !slices.Equal(got, want) {
		t.Fatalf("grants = %v, want %v", got, want)
	}
	a := items[g.String()]
	if a["source"] != "agentauth" || a["agent_id"] != agent.String() || a["user_id"] != owner.String() || a["expires_at"] == nil || a["last_used_on"] == nil {
		t.Errorf("agentauth grant: %v", a)
	}
	d := items[d1.String()]
	if d["source"] != "delegation" || d["actor_kind"] != "agent" || d["actor_id"] != bot.String() || d["subject_id"] != owner.String() || d["grant_kind"] != "delegation" {
		t.Errorf("delegation: %v", d)
	}
}

func TestAgents(t *testing.T) {
	f := newFixture(t, fixtureOpts{plugins: true})
	owner := f.addUser("owner@example.com", "platform-owner")
	cust := f.addUser("customer@example.com")
	mine := f.addAgent(owner, id.NewOrgID())
	platform := f.addAgent(id.UserID{}, id.OrgID{})
	f.addAgent(cust, id.NewOrgID())

	items := ids(population(t, New(f.eng), "authsome.agents"))
	if len(items) != 2 || items[mine.String()] == nil || items[platform.String()] == nil {
		t.Fatalf("agents = %v", keys(items))
	}
	a := items[mine.String()]
	if a["status"] != "approved" || a["origin"] != "first_party" || a["created_by"] != owner.String() || !strings.HasPrefix(fmt.Sprint(a["name"]), "helper-") {
		t.Errorf("agent: %v", a)
	}
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t, fixtureOpts{plugins: true})
	owner := f.addUser("owner@example.com", "platform-owner")
	cust := f.addUser("customer@example.com")
	f.addSession(cust, time.Now().Add(time.Hour))
	f.addAPIKey(cust, id.ServiceAccountID{})
	custOrg := id.NewOrgID()
	custSvc := f.addServiceAccount(cust, custOrg, principal.KindAgent)
	f.addDelegation(principal.Ref{Kind: principal.KindAgent, ID: custSvc.String()}, principal.UserRef(cust))
	custAgent := f.addAgent(cust, custOrg)
	f.addAgentGrant(custAgent, cust)
	_ = owner

	collectAll := func(a *Adapter) string {
		var sb strings.Builder
		b := build(t, a)
		for _, k := range keys(b.pops) {
			sb.WriteString(mustJSON(t, population(t, a, k)))
		}
		return sb.String()
	}
	if out := collectAll(New(f.eng, WithAPIKeys())); strings.Contains(out, cust.String()) || strings.Contains(out, "customer@example.com") {
		t.Errorf("default scope collected the customer: %s", out)
	}
	for name, a := range map[string]*Adapter{
		"all tenants":        New(f.eng, WithAPIKeys(), WithScope(adapter.Scope{AllTenants: true})),
		"all platform users": New(f.eng, WithAPIKeys(), WithAllPlatformUsers()),
	} {
		out := collectAll(a)
		if !strings.Contains(out, "customer@example.com") {
			t.Errorf("%s: customer user missing", name)
		}
	}
	// Only all tenants brings in customer-org principals and agents.
	if out := collectAll(New(f.eng, WithScope(adapter.Scope{AllTenants: true}))); !strings.Contains(out, custSvc.String()) || !strings.Contains(out, custAgent.String()) {
		t.Error("all tenants: customer org service account or agent missing")
	}
}

func TestStaffRolesFromScope(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.addUser("owner@example.com", "platform-owner")
	admin := f.addUser("admin@example.com", "platform-admin")
	items := population(t, New(f.eng, WithScope(adapter.Scope{StaffRoles: []string{"platform-admin", "no-such-role"}})), "authsome.staff-users")
	if len(items) != 1 || items[0]["id"] != admin.String() {
		t.Errorf("staff = %v, want only the admin", items)
	}
}

func TestScopeAppID(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.addUser("owner@example.com", "platform-owner")
	items := population(t, New(f.eng, WithScope(adapter.Scope{AppID: id.NewAppID().String()})), "authsome.staff-users")
	if len(items) != 0 {
		t.Errorf("another app's scope found %d staff", len(items))
	}
	bad := New(f.eng, WithScope(adapter.Scope{AppID: "not-an-id"}))
	p := build(t, bad).pops["authsome.staff-users"]
	if _, err := p.Collect(context.Background()); err == nil {
		t.Error("a malformed scope app ID should fail the run")
	}
}

// pagingStore pages users and service accounts the way the SQL stores do,
// by id cursor, which the memory store doesn't.
type pagingStore struct {
	*memory.Store
	limits []int
	stuck  bool
}

func (s *pagingStore) ListUsers(ctx context.Context, q *user.Query) (*user.List, error) {
	all, err := s.Store.ListUsers(ctx, &user.Query{AppID: q.AppID})
	if err != nil {
		return nil, err
	}
	s.limits = append(s.limits, q.Limit)
	items := all.Users
	sort.Slice(items, func(i, j int) bool { return items[i].ID.String() > items[j].ID.String() })
	page, next := cut(items, q.Cursor, q.Limit, func(u *user.User) string { return u.ID.String() })
	if s.stuck {
		next = "stuck"
	}
	return &user.List{Users: page, NextCursor: next}, nil
}

func (s *pagingStore) ListServiceAccounts(ctx context.Context, q *serviceaccount.Query) (*serviceaccount.List, error) {
	all, err := s.Store.ListServiceAccounts(ctx, &serviceaccount.Query{AppID: q.AppID})
	if err != nil {
		return nil, err
	}
	items := all.ServiceAccounts
	sort.Slice(items, func(i, j int) bool { return items[i].ID.String() > items[j].ID.String() })
	page, next := cut(items, q.Cursor, q.Limit, func(x *serviceaccount.ServiceAccount) string { return x.ID.String() })
	return &serviceaccount.List{ServiceAccounts: page, NextCursor: next}, nil
}

func cut[T any](items []T, cursor string, limit int, idOf func(T) string) (page []T, next string) {
	if limit <= 0 {
		limit = 50
	}
	for _, it := range items {
		if cursor != "" && idOf(it) >= cursor {
			continue
		}
		page = append(page, it)
	}
	if len(page) > limit {
		page = page[:limit]
		next = idOf(page[len(page)-1])
	}
	return page, next
}

func TestPages(t *testing.T) {
	defer setPageSize(2)()
	var ps *pagingStore
	f := newFixture(t, fixtureOpts{store: func(m *memory.Store) store.Store {
		ps = &pagingStore{Store: m}
		return ps
	}})
	const n = 5
	owners := make([]id.UserID, 0, n)
	for i := range n {
		owners = append(owners, f.addUser(fmt.Sprintf("owner%d@example.com", i), "platform-owner"))
	}
	for range n {
		f.addSession(owners[0], time.Now().Add(time.Hour))
		f.addServiceAccount(owners[0], id.OrgID{}, principal.KindService)
	}
	if got := len(population(t, New(f.eng), "authsome.staff-users")); got != n {
		t.Errorf("staff by role over pages: %d, want %d", got, n)
	}
	if got := len(population(t, New(f.eng), "authsome.staff-sessions")); got != n {
		t.Errorf("sessions over pages: %d, want %d", got, n)
	}
	if got := len(population(t, New(f.eng), "authsome.service-accounts")); got != n {
		t.Errorf("service accounts over pages: %d, want %d", got, n)
	}
	if got := len(population(t, New(f.eng, WithAllPlatformUsers()), "authsome.staff-users")); got != n {
		t.Errorf("all platform users over pages: %d, want %d", got, n)
	}
	if !slices.Contains(ps.limits, 2) {
		t.Errorf("user list limits %v, want the page size", ps.limits)
	}
	ps.stuck = true
	p := build(t, New(f.eng, WithAllPlatformUsers())).pops["authsome.staff-users"]
	if _, err := p.Collect(context.Background()); err == nil {
		t.Error("a cursor that never ends should fail the run, not loop or truncate")
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	defer setMaxItems(3)()
	f := newFixture(t, fixtureOpts{})
	for i := range 4 {
		f.addUser(fmt.Sprintf("owner%d@example.com", i), "platform-owner")
	}
	p := build(t, New(f.eng)).pops["authsome.staff-users"]
	if _, err := p.Collect(context.Background()); err == nil {
		t.Error("more staff than a population holds should fail the run")
	}
}

func TestNeverSendsContent(t *testing.T) {
	f := newFixture(t, fixtureOpts{plugins: true, config: func(c *authsome.Config) { c.APIKeyPepper = canary }})
	on := true
	if err := f.store.SetAppClientConfig(f.ctx, &appclientconfig.Config{ID: id.NewAppClientConfigID(), AppID: f.app, MFARequired: &on, AppName: &[]string{canary}[0], LogoURL: &[]string{canary}[0]}); err != nil {
		t.Fatal(err)
	}
	owner := f.addUser("owner@example.com", "platform-owner")
	f.enrolTOTP(owner)
	f.addOrgMember(owner, organization.RoleAdmin)
	f.addSession(owner, time.Now().Add(time.Hour))
	f.addAPIKey(owner, id.ServiceAccountID{})
	svc := f.addServiceAccount(owner, id.OrgID{}, principal.KindAgent)
	f.addAPIKey(id.UserID{}, svc)
	f.addDelegation(principal.Ref{Kind: principal.KindAgent, ID: svc.String()}, principal.UserRef(owner))
	agent := f.addAgent(owner, id.OrgID{})
	f.addAgentGrant(agent, owner)

	a := New(f.eng, WithAPIKeys(), WithEventProofs(), WithScope(adapter.Scope{AllTenants: true}))
	b := build(t, a)
	var out strings.Builder
	for _, k := range keys(b.pops) {
		items := population(t, a, k)
		if len(items) == 0 {
			t.Errorf("%s collected nothing, so the canary check proves nothing", k)
		}
		out.WriteString(mustJSON(t, items))
	}
	for _, k := range keys(b.snaps) {
		out.WriteString(mustJSON(t, snapshot(t, a, k)))
	}
	out.WriteString(mustJSON(t, b.proofs))
	if strings.Contains(out.String(), "CANARY") {
		t.Fatalf("collected output carries a canary: %s", out.String())
	}
}
