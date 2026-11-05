package authsome

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	authsome "github.com/xraph/authsome"
	"github.com/xraph/authsome/apikey"
	"github.com/xraph/authsome/bridge"
	"github.com/xraph/authsome/id"
	"github.com/xraph/authsome/organization"
	"github.com/xraph/authsome/plugins/agentauth"
	"github.com/xraph/authsome/plugins/mfa"
	"github.com/xraph/authsome/principal"
	"github.com/xraph/authsome/rbac"
	"github.com/xraph/authsome/serviceaccount"
	"github.com/xraph/authsome/session"
	"github.com/xraph/authsome/store"
	"github.com/xraph/authsome/store/memory"
	"github.com/xraph/authsome/user"
	"github.com/xraph/warden"
	wardenmem "github.com/xraph/warden/store/memory"

	"github.com/hallproof/witness/collect"
)

// canary goes in every field the adapter must never send.
const canary = "CANARY-a1b2c3-never-send"

// fixture is an Authsome engine on the memory store, bootstrapped the way
// Loomplane does it: one platform app, default platform roles, no
// automatic owners.
type fixture struct {
	t       *testing.T
	ctx     context.Context
	eng     *authsome.Engine
	store   store.Store
	app     id.AppID
	mfa     mfa.Store
	agents  agentauth.Store
	plugins bool
}

type fixtureOpts struct {
	// plugins installs the mfa and agentauth plugins.
	plugins bool
	// store replaces the memory store, for paging tests.
	store func(*memory.Store) store.Store
	// password and lockout override the engine config.
	config func(*authsome.Config)
}

func newFixture(t *testing.T, o fixtureOpts) *fixture {
	t.Helper()
	ctx := context.Background()
	mem := memory.New()
	var st store.Store = mem
	if o.store != nil {
		st = o.store(mem)
	}
	w, err := warden.NewEngine(warden.WithStore(wardenmem.New()))
	if err != nil {
		t.Fatal(err)
	}
	cfg := authsome.DefaultConfig()
	if o.config != nil {
		o.config(&cfg)
	}
	f := &fixture{t: t, ctx: ctx, store: st, plugins: o.plugins}
	opts := []authsome.Option{
		authsome.WithStore(st),
		authsome.WithWarden(w),
		authsome.WithChronicle(bridge.NewMemoryChronicle()),
		authsome.WithDisableMigrate(),
		authsome.WithConfig(cfg),
		authsome.WithBootstrap(authsome.WithInitialOwnerCount(0), authsome.WithSkipDefaultEnvs()),
	}
	if o.plugins {
		ms := mfa.NewMemoryStore()
		mp := mfa.New()
		mp.SetStore(ms)
		as := agentauth.NewMemoryStore()
		f.mfa, f.agents = ms, as
		opts = append(opts, authsome.WithPlugin(mp), authsome.WithPlugin(agentauth.New(agentauth.WithStore(as))))
	}
	eng, err := authsome.NewEngine(opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Stop(ctx) })
	f.eng = eng
	f.app = eng.PlatformAppID()
	if f.app.IsNil() {
		t.Fatal("bootstrap left no platform app")
	}
	return f
}

// addUser creates a platform-app user holding roles, with every excluded
// field set to the canary.
func (f *fixture) addUser(email string, roles ...string) id.UserID {
	f.t.Helper()
	now := time.Now().UTC()
	u := &user.User{
		ID:              id.NewUserID(),
		AppID:           f.app,
		Email:           email,
		EmailVerified:   true,
		FirstName:       "Ada",
		LastName:        "Staff",
		Username:        "u" + id.NewUserID().String()[20:],
		DisplayUsername: canary,
		Phone:           canary,
		Image:           canary,
		PasswordHash:    canary,
		BanReason:       canary,
		Metadata:        user.Metadata{"note": canary},
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := f.store.CreateUser(f.ctx, u); err != nil {
		f.t.Fatal(err)
	}
	f.eng.EnsureDefaultRole(f.ctx, f.app, u.ID)
	for _, slug := range roles {
		r, err := f.eng.GetRoleBySlug(f.ctx, f.app, slug)
		if err != nil {
			f.t.Fatalf("role %s: %v", slug, err)
		}
		if err := f.eng.AssignUserRole(f.ctx, f.app, &rbac.UserRole{UserID: u.ID.String(), RoleID: r.ID}); err != nil {
			f.t.Fatal(err)
		}
	}
	return u.ID
}

func (f *fixture) addSession(uid id.UserID, expires time.Time) id.SessionID {
	f.t.Helper()
	now := time.Now().UTC()
	s := &session.Session{
		ID:                    id.NewSessionID(),
		AppID:                 f.app,
		UserID:                uid,
		Token:                 canary + "-token",
		RefreshToken:          canary + "-refresh",
		IPAddress:             canary,
		UserAgent:             canary,
		DeviceID:              id.NewDeviceID(),
		FamilyID:              id.NewSessionFamilyID(),
		LastActivityAt:        now,
		ExpiresAt:             expires,
		RefreshTokenExpiresAt: expires,
		CreatedAt:             now,
		Roles:                 []string{canary},
		Scopes:                []string{canary},
		Actors:                principal.Chain{{Kind: principal.KindUser, ID: canary}},
	}
	if err := f.store.CreateSession(f.ctx, s); err != nil {
		f.t.Fatal(err)
	}
	return s.ID
}

func (f *fixture) addOrgMember(uid id.UserID, role organization.MemberRole) id.OrgID {
	f.t.Helper()
	now := time.Now().UTC()
	o := &organization.Organization{ID: id.NewOrgID(), AppID: f.app, Name: "Org", Slug: "org-" + id.NewOrgID().String()[20:], CreatedBy: uid, CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateOrganization(f.ctx, o); err != nil {
		f.t.Fatal(err)
	}
	m := &organization.Member{ID: id.NewMemberID(), OrgID: o.ID, UserID: uid, Role: role, CreatedAt: now, UpdatedAt: now}
	if err := f.store.CreateMember(f.ctx, m); err != nil {
		f.t.Fatal(err)
	}
	return o.ID
}

func (f *fixture) addAPIKey(uid id.UserID, svc id.ServiceAccountID) id.APIKeyID {
	f.t.Helper()
	now := time.Now().UTC()
	k := &apikey.APIKey{
		ID:               id.NewAPIKeyID(),
		AppID:            f.app,
		UserID:           uid,
		ServiceAccountID: svc,
		Name:             "deploy",
		KeyHash:          canary,
		KeyPrefix:        canary,
		PublicKey:        canary,
		PublicKeyPrefix:  canary,
		Scopes:           []string{"read"},
		LastUsedAt:       &now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := f.store.CreateAPIKey(f.ctx, k); err != nil {
		f.t.Fatal(err)
	}
	return k.ID
}

func (f *fixture) addServiceAccount(owner id.UserID, org id.OrgID, kind principal.Kind) id.ServiceAccountID {
	f.t.Helper()
	now := time.Now().UTC()
	s := &serviceaccount.ServiceAccount{
		ID:          id.NewServiceAccountID(),
		AppID:       f.app,
		Name:        "bot-" + id.NewServiceAccountID().String()[20:],
		Description: canary,
		Scopes:      []string{"read"},
		Active:      true,
		Kind:        kind,
		OwnerUserID: owner,
		OrgID:       org,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := f.store.CreateServiceAccount(f.ctx, s); err != nil {
		f.t.Fatal(err)
	}
	return s.ID
}

func (f *fixture) addDelegation(actor, subject principal.Ref) id.DelegationID {
	f.t.Helper()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	d := &principal.Delegation{
		ID:        id.NewDelegationID(),
		AppID:     f.app,
		Actor:     actor,
		Subject:   subject,
		GrantKind: principal.GrantDelegation,
		Scopes:    []string{"read"},
		GrantedBy: subject,
		ExpiresAt: &exp,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := f.store.CreateDelegation(f.ctx, d); err != nil {
		f.t.Fatal(err)
	}
	return d.ID
}

func (f *fixture) addAgent(createdBy id.UserID, org id.OrgID) id.AgentID {
	f.t.Helper()
	now := time.Now().UTC()
	a := &agentauth.Agent{
		ID:          id.NewAgentID(),
		AppID:       f.app,
		OrgID:       org,
		ClientID:    "client-" + id.NewAgentID().String()[20:],
		Name:        "helper-" + id.NewAgentID().String()[20:],
		Description: canary,
		LogoURI:     canary,
		Origin:      agentauth.OriginFirstParty,
		Status:      agentauth.StatusApproved,
		CreatedBy:   createdBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := f.agents.CreateAgent(f.ctx, a); err != nil {
		f.t.Fatal(err)
	}
	return a.ID
}

func (f *fixture) addAgentGrant(agent id.AgentID, uid id.UserID) id.AgentGrantID {
	f.t.Helper()
	now := time.Now().UTC()
	g := &agentauth.AgentGrant{
		ID:         id.NewAgentGrantID(),
		AppID:      f.app,
		AgentID:    agent,
		UserID:     uid,
		Scopes:     []string{"read"},
		ConsentID:  id.NewConsentID(),
		ExpiresAt:  now.Add(time.Hour),
		LastUsedAt: &now,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := f.agents.CreateAgentGrant(f.ctx, g); err != nil {
		f.t.Fatal(err)
	}
	return g.ID
}

func (f *fixture) enrolTOTP(uid id.UserID) {
	f.t.Helper()
	now := time.Now().UTC()
	if err := f.mfa.CreateEnrollment(f.ctx, &mfa.Enrollment{
		ID: id.NewMFAID(), UserID: uid, Method: "totp", Secret: canary, Verified: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		f.t.Fatal(err)
	}
}

// built is what an adapter registers, by key.
type built struct {
	snaps  map[string]collect.Snapshot
	pops   map[string]collect.Population
	proofs map[string]collect.EventProof
}

func build(t *testing.T, a *Adapter) built {
	t.Helper()
	snaps, pops, proofs := a.collectors()
	b := built{snaps: map[string]collect.Snapshot{}, pops: map[string]collect.Population{}, proofs: map[string]collect.EventProof{}}
	for _, s := range snaps {
		b.snaps[s.Key] = s
	}
	for _, p := range pops {
		b.pops[p.Key] = p
	}
	for _, e := range proofs {
		b.proofs[e.Key] = e
	}
	return b
}

// population runs one population collector and checks witness accepts
// its output.
func population(t *testing.T, a *Adapter, key string) []map[string]any {
	t.Helper()
	p, ok := build(t, a).pops[key]
	if !ok {
		t.Fatalf("no population %s", key)
	}
	items, err := p.Collect(context.Background())
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	if _, _, err := collect.PopulationMessage(p, items, time.Now()); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return items
}

func snapshot(t *testing.T, a *Adapter, key string) map[string]any {
	t.Helper()
	s, ok := build(t, a).snaps[key]
	if !ok {
		t.Fatalf("no snapshot %s", key)
	}
	settings, err := s.Collect(context.Background())
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	if _, _, err := collect.SnapshotMessage(s, settings, time.Now()); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return settings
}

func ids(items []map[string]any) map[string]map[string]any {
	out := make(map[string]map[string]any, len(items))
	for _, it := range items {
		out[it["id"].(string)] = it
	}
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
