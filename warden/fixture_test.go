package warden

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/resourcetype"
	"github.com/xraph/warden/role"
	"github.com/xraph/warden/store/memory"

	"github.com/hallproof/witness/collect"
)

// The tenants the fixture seeds: the platform app, which holds staff
// roles, and one customer organization.
const (
	staffTenant    = "app_platform"
	customerTenant = "org_customer"
)

// canary is put in every field the adapter must never send.
const canary = "CANARY-7f3e"

// fixture is a Warden engine on the in-memory store, seeded with a staff
// tenant and a customer tenant.
type fixture struct {
	eng   *warden.Engine
	store *memory.Store
	roles map[string]*role.Role // by tenant + "/" + slug
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s := memory.New()
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return &fixture{eng: eng, store: s, roles: map[string]*role.Role{}}
}

// seed fills the fixture with staff and customer rows. Every field the
// adapter must not send carries canary.
func (f *fixture) seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	meta := map[string]any{"note": canary}

	for _, tenant := range []string{staffTenant, customerTenant} {
		must(t, f.store.CreateResourceType(ctx, &resourcetype.ResourceType{
			TenantID: tenant, Name: "project", Description: canary, Metadata: meta,
			Relations: []resourcetype.RelationDef{{Name: "owner", AllowedSubjects: []string{"user"}}},
		}))
		for _, p := range []struct{ name, res, act string }{
			{"user:*", "user", "*"},
			{"billing:read", "billing", "read"},
		} {
			must(t, f.store.CreatePermission(ctx, &permission.Permission{
				TenantID: tenant, Name: p.name, Resource: p.res, Action: p.act,
				Description: canary, Metadata: meta, CreatedBy: canary, UpdatedBy: canary,
			}))
		}
	}

	f.role(t, staffTenant, "platform-owner", "", "Owners of the platform", "user:*", "billing:read")
	f.role(t, staffTenant, "platform-admin", "platform-user", "Admins", "user:*")
	f.role(t, staffTenant, "platform-user", "", "Everyone", "billing:read")
	f.role(t, customerTenant, "org-admin", "", "Customer admins", "user:*")

	f.assign(t, staffTenant, "platform-owner", "usr_alice", "")
	f.assign(t, staffTenant, "platform-admin", "usr_bob", "usr_alice")
	f.assign(t, staffTenant, "platform-user", "usr_alice", "")
	f.assign(t, staffTenant, "platform-user", "usr_customer_carol", "")
	f.assign(t, customerTenant, "org-admin", "usr_customer_dave", "")

	for _, tenant := range []string{staffTenant, customerTenant} {
		must(t, f.store.CreatePolicy(ctx, &policy.Policy{
			TenantID: tenant, Name: "deny-outside-office-" + tenant, Description: "Deny outside the office",
			Effect: policy.EffectDeny, Priority: 10, IsActive: true, Version: 1,
			Subjects:    []policy.SubjectMatch{{Kind: "user", Role: "platform-admin"}},
			Actions:     []string{"*"},
			Resources:   []string{"billing:*"},
			Obligations: []string{"log"},
			Conditions: []policy.Condition{
				{Field: "context.ip", Operator: policy.OpIPInCIDR, Value: canary},
				{Field: "subject.email", Operator: policy.OpIn, Value: []any{canary + "@example.com"}},
			},
			Metadata: meta, CreatedBy: canary, UpdatedBy: canary,
		}))
		must(t, f.store.CreateRelation(ctx, &relation.Tuple{
			TenantID: tenant, ObjectType: "project", ObjectID: "prj_" + tenant, Relation: "owner",
			SubjectType: "user", SubjectID: "usr_" + tenant, Metadata: meta, CreatedBy: canary,
		}))
	}
}

func (f *fixture) role(t *testing.T, tenant, slug, parent, description string, perms ...string) {
	t.Helper()
	ctx := context.Background()
	r := &role.Role{
		TenantID: tenant, Slug: slug, Name: slug, Description: description, ParentSlug: parent,
		IsSystem: true, Metadata: map[string]any{"note": canary}, CreatedBy: canary, UpdatedBy: canary,
	}
	must(t, f.store.CreateRole(ctx, r))
	for _, p := range perms {
		must(t, f.store.AttachPermission(ctx, tenant, r.ID, permission.Ref{Name: p}))
	}
	f.roles[tenant+"/"+slug] = r
}

func (f *fixture) assign(t *testing.T, tenant, slug, subject, grantedBy string) {
	t.Helper()
	r := f.roles[tenant+"/"+slug]
	must(t, f.store.CreateAssignment(context.Background(), &assignment.Assignment{
		TenantID: tenant, RoleID: r.ID, SubjectKind: "user", SubjectID: subject,
		GrantedBy: grantedBy, Metadata: map[string]any{"note": canary},
	}))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// population runs the population collector with key and returns its items.
func population(t *testing.T, a *Adapter, key string) []map[string]any {
	t.Helper()
	_, pops, _ := a.collectors()
	for _, p := range pops {
		if p.Key == key {
			items, err := p.Collect(context.Background())
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			if err := checkPopulation(p, items); err != nil {
				t.Fatal(err)
			}
			return items
		}
	}
	t.Fatalf("no population collector %q", key)
	return nil
}

// model runs warden.model and returns its settings.
func model(t *testing.T, a *Adapter) map[string]any {
	t.Helper()
	const key = "warden.model"
	snaps, _, _ := a.collectors()
	for _, s := range snaps {
		if s.Key == key {
			settings, err := s.Collect(context.Background())
			if err != nil {
				t.Fatalf("%s: %v", key, err)
			}
			if _, _, err := collect.SnapshotMessage(s, settings, time.Now()); err != nil {
				t.Fatal(err)
			}
			return settings
		}
	}
	t.Fatalf("no snapshot collector %q", key)
	return nil
}

// checkPopulation builds the push message, which checks ids and limits the
// way the scheduler does.
func checkPopulation(p collect.Population, items []map[string]any) error {
	_, _, err := collect.PopulationMessage(p, items, time.Now())
	return err
}

// keys returns the collector keys a registers.
func keys(a *Adapter) []string {
	snaps, pops, proofs := a.collectors()
	out := make([]string, 0, len(snaps)+len(pops)+len(proofs))
	for _, s := range snaps {
		out = append(out, s.Key)
	}
	for _, p := range pops {
		out = append(out, p.Key)
	}
	for _, e := range proofs {
		out = append(out, e.Key)
	}
	return out
}

// byField indexes items by the string in field.
func byField(items []map[string]any, field string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, it := range items {
		s, _ := it[field].(string)
		out[s] = it
	}
	return out
}
