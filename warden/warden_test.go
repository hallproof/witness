package warden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/xraph/vessel"
	xwarden "github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module {
			t.Errorf("Module = %q, want %q", a.Module, Module)
		}
		if !slices.Equal(a.After, []string{"warden"}) {
			t.Errorf("After = %v, want [warden]", a.After)
		}
		if a.Chain {
			t.Error("warden is not a chain adapter")
		}
		return
	}
	t.Fatal("the warden adapter is not registered")
}

func host(t *testing.T, container any, cfg map[string]any) (adapter.Host, *witness.Witness) {
	t.Helper()
	srv := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: srv.URL, IngestKey: srv.Key})
	if err != nil {
		t.Fatal(err)
	}
	return adapter.Host{
		Witness:   w,
		Scope:     adapter.Scope{AppID: staffTenant, TenantID: "platform"},
		Logger:    slog.New(slog.DiscardHandler),
		Container: container,
		Config:    cfg,
	}, w
}

func attachRegistered(t *testing.T, h adapter.Host) (bool, error) {
	t.Helper()
	for _, a := range adapter.Adapters() {
		if a.Name == Name {
			return a.Attach(context.Background(), h)
		}
	}
	t.Fatal("the warden adapter is not registered")
	return false, nil
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"empty container": vessel.New(), "no container": nil, "not a container": "x"} {
		t.Run(name, func(t *testing.T) {
			h, _ := host(t, c, nil)
			found, err := attachRegistered(t, h)
			if found || err != nil {
				t.Fatalf("Attach = %v, %v; want false, nil", found, err)
			}
		})
	}
}

func TestAttachFindsEngineInContainer(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	h, w := host(t, c, nil)
	found, err := attachRegistered(t, h)
	if !found || err != nil {
		t.Fatalf("Attach = %v, %v; want true, nil", found, err)
	}
	for _, key := range []string{"warden.model", "warden.roles", "warden.assignments", "warden.policies"} {
		if !registered(w, key) {
			t.Errorf("%s is not registered", key)
		}
	}
	for _, key := range []string{"warden.relations", "warden.access-change-proof"} {
		if registered(w, key) {
			t.Errorf("%s is on by default", key)
		}
	}
}

func TestAttachTakesEngineFromConfig(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	cfg := map[string]any{ConfigEngine: f.eng, "relations": true, "event_proofs": true}
	h, w := host(t, vessel.New(), cfg)
	found, err := attachRegistered(t, h)
	if !found || err != nil {
		t.Fatalf("Attach = %v, %v; want true, nil", found, err)
	}
	for _, key := range []string{"warden.roles", "warden.relations", "warden.access-change-proof"} {
		if !registered(w, key) {
			t.Errorf("%s is not registered", key)
		}
	}
}

// registered reports whether w already has a collector with key.
func registered(w *witness.Witness, key string) bool {
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

func TestAttachWithoutTenantsRegistersNothing(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	h, w := host(t, c, nil)
	h.Scope = adapter.Scope{}
	found, err := attachRegistered(t, h)
	if !found || err != nil {
		t.Fatalf("Attach = %v, %v; want true, nil", found, err)
	}
	// Nothing was registered, so every key is still free.
	a := New(f.eng, WithTenants(staffTenant))
	if err := a.Register(w); err != nil {
		t.Fatalf("keys were taken: %v", err)
	}
}

func TestRegisterNeedsEngineAndScope(t *testing.T) {
	_, w := host(t, nil, nil)
	if err := New(nil, WithTenants(staffTenant)).Register(w); err == nil {
		t.Error("Register without an engine should fail")
	}
	f := newFixture(t)
	if err := New(f.eng).Register(w); err == nil {
		t.Error("Register without tenants should fail")
	}
}

func TestKeys(t *testing.T) {
	f := newFixture(t)
	got := keys(New(f.eng, WithTenants(staffTenant)))
	want := make([]string, 0, 6)
	want = append(want, "warden.model", "warden.roles", "warden.assignments", "warden.policies")
	if !slices.Equal(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
	got = keys(New(f.eng, WithTenants(staffTenant), WithRelations(0), WithEventProofs()))
	want = append(want, "warden.relations", "warden.access-change-proof")
	if !slices.Equal(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
}

func TestRoles(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	items := population(t, New(f.eng, WithTenants(staffTenant)), "warden.roles")
	roles := byField(items, "slug")
	if len(roles) != 3 {
		t.Fatalf("got %d roles, want 3 staff tenant roles: %v", len(roles), items)
	}
	owner := roles["platform-owner"]
	if owner["id"] != f.roles[staffTenant+"/platform-owner"].ID.String() {
		t.Errorf("id = %v", owner["id"])
	}
	if owner["tenant_id"] != staffTenant || owner["name"] != "platform-owner" || owner["description"] != "Owners of the platform" {
		t.Errorf("owner = %v", owner)
	}
	if !slices.Equal(owner["permissions"].([]string), []string{"billing:read", "user:*"}) {
		t.Errorf("permissions = %v", owner["permissions"])
	}
	if owner["privileged"] != true || roles["platform-admin"]["privileged"] != true || roles["platform-user"]["privileged"] != false {
		t.Errorf("privileged flags wrong: %v", items)
	}
	if roles["platform-admin"]["parent_slug"] != "platform-user" {
		t.Errorf("parent_slug = %v", roles["platform-admin"]["parent_slug"])
	}
	for _, k := range []string{"namespace_path", "app_id", "is_system", "is_default", "max_members", "created_at", "updated_at"} {
		if _, ok := owner[k]; !ok {
			t.Errorf("role is missing %q", k)
		}
	}
}

func TestAssignments(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	items := population(t, New(f.eng, WithTenants(staffTenant)), "warden.assignments")
	if len(items) != 2 {
		t.Fatalf("got %d assignments, want alice's owner and bob's admin: %v", len(items), items)
	}
	bySubject := byField(items, "subject_id")
	bob := bySubject["usr_bob"]
	if bob["role_slug"] != "platform-admin" || bob["privileged"] != true || bob["granted_by"] != "usr_alice" {
		t.Errorf("bob = %v", bob)
	}
	if bob["role_id"] != f.roles[staffTenant+"/platform-admin"].ID.String() {
		t.Errorf("role_id = %v", bob["role_id"])
	}
	for _, k := range []string{"id", "tenant_id", "namespace_path", "subject_kind", "resource_type", "resource_id", "expires_at", "created_at"} {
		if _, ok := bob[k]; !ok {
			t.Errorf("assignment is missing %q", k)
		}
	}
	for _, it := range items {
		if it["role_slug"] == "platform-user" {
			t.Errorf("the default platform-user assignment was sent: %v", it)
		}
	}
}

func TestAssignmentsExcludeIsConfigurable(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	items := population(t, New(f.eng, WithTenants(staffTenant), WithExcludeRoleSlugs()), "warden.assignments")
	if len(items) != 4 {
		t.Errorf("with no exclusions got %d assignments, want 4", len(items))
	}
	items = population(t, New(f.eng, WithTenants(staffTenant), WithExcludeRoleSlugs("platform-user", "platform-admin")), "warden.assignments")
	if len(items) != 1 || items[0]["subject_id"] != "usr_alice" {
		t.Errorf("got %v, want alice's owner assignment only", items)
	}
}

func TestPrivilegedIsConfigurable(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	items := population(t, New(f.eng, WithTenants(staffTenant), WithPrivileged("platform-owner")), "warden.roles")
	roles := byField(items, "slug")
	if roles["platform-owner"]["privileged"] != true || roles["platform-admin"]["privileged"] != false {
		t.Errorf("privileged flags wrong: %v", items)
	}
}

func TestPolicies(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	items := population(t, New(f.eng, WithTenants(staffTenant)), "warden.policies")
	if len(items) != 1 {
		t.Fatalf("got %d policies, want 1", len(items))
	}
	p := items[0]
	if p["name"] != "deny-outside-office-"+staffTenant || p["effect"] != "deny" || p["priority"] != 10 || p["is_active"] != true {
		t.Errorf("policy = %v", p)
	}
	conds, _ := p["conditions"].([]map[string]any)
	if len(conds) != 2 || conds[0]["field"] != "context.ip" || conds[0]["operator"] != "ip_in_cidr" {
		t.Errorf("conditions = %v", p["conditions"])
	}
	for _, c := range conds {
		if _, ok := c["value"]; ok {
			t.Errorf("a condition value was sent: %v", c)
		}
	}
	h, _ := p["conditions_hash"].(string)
	if len(h) != 64 {
		t.Errorf("conditions_hash = %q, want a SHA-256 hex digest", h)
	}
	subjects, _ := p["subjects"].([]map[string]any)
	if len(subjects) != 1 || subjects[0]["role"] != "platform-admin" {
		t.Errorf("subjects = %v", p["subjects"])
	}
	for _, k := range []string{"actions", "resources", "obligations", "not_before", "not_after", "version", "description", "created_at", "updated_at"} {
		if _, ok := p[k]; !ok {
			t.Errorf("policy is missing %q", k)
		}
	}

	// A changed condition value changes the hash.
	pol := mustPolicy(t, f, staffTenant)
	pol.Conditions[0].Value = "10.0.0.0/8"
	must(t, f.store.UpdatePolicy(context.Background(), pol))
	again := population(t, New(f.eng, WithTenants(staffTenant)), "warden.policies")
	if again[0]["conditions_hash"] == h {
		t.Error("conditions_hash did not change with a condition value")
	}
}

func mustPolicy(t *testing.T, f *fixture, tenant string) *policy.Policy {
	t.Helper()
	ps, err := f.store.ListPolicies(context.Background(), &policy.ListFilter{TenantID: tenant})
	if err != nil || len(ps) == 0 {
		t.Fatalf("ListPolicies: %v, %d", err, len(ps))
	}
	return ps[0]
}

func TestRelations(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	items := population(t, New(f.eng, WithTenants(staffTenant), WithRelations(0)), "warden.relations")
	if len(items) != 1 {
		t.Fatalf("got %d relations, want 1", len(items))
	}
	r := items[0]
	if r["object_type"] != "project" || r["object_id"] != "prj_"+staffTenant || r["relation"] != "owner" || r["subject_id"] != "usr_"+staffTenant {
		t.Errorf("relation = %v", r)
	}
	for _, k := range []string{"id", "tenant_id", "namespace_path", "subject_type", "subject_relation", "created_at"} {
		if _, ok := r[k]; !ok {
			t.Errorf("relation is missing %q", k)
		}
	}
}

func TestRelationsRefuseTooMany(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := range 5 {
		must(t, f.store.CreateRelation(ctx, &relation.Tuple{
			TenantID: staffTenant, ObjectType: "project", ObjectID: fmt.Sprintf("prj_%d", i),
			Relation: "owner", SubjectType: "user", SubjectID: "usr_alice",
		}))
	}
	_, pops, _ := New(f.eng, WithTenants(staffTenant), WithRelations(4)).collectors()
	for _, p := range pops {
		if p.Key != "warden.relations" {
			continue
		}
		if _, err := p.Collect(ctx); err == nil {
			t.Fatal("collected more relations than the limit instead of failing")
		}
		return
	}
	t.Fatal("no relations collector")
}

func TestModel(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	a := New(f.eng, WithTenants(staffTenant))
	settings := model(t, a)
	tenants, _ := settings["tenants"].([]map[string]any)
	if len(tenants) != 1 {
		t.Fatalf("tenants = %v", settings["tenants"])
	}
	m := tenants[0]
	if m["tenant_id"] != staffTenant || m["roles"] != 3 || m["permissions"] != 2 || m["resource_types"] != 1 || m["policies"] != 1 {
		t.Errorf("model = %v", m)
	}
	sum, _ := m["model_sha256"].(string)
	if len(sum) != 64 {
		t.Errorf("model_sha256 = %q", sum)
	}
	if again := model(t, a)["tenants"].([]map[string]any)[0]["model_sha256"]; again != sum {
		t.Error("model_sha256 is not stable across runs")
	}

	// Relations are data, not model: a new tuple leaves the hash alone.
	must(t, f.store.CreateRelation(context.Background(), &relation.Tuple{
		TenantID: staffTenant, ObjectType: "project", ObjectID: "prj_new", Relation: "owner", SubjectType: "user", SubjectID: "usr_x",
	}))
	if again := model(t, a)["tenants"].([]map[string]any)[0]["model_sha256"]; again != sum {
		t.Error("a relation changed model_sha256")
	}

	// A new permission on a role changes it.
	f.role(t, staffTenant, "auditor", "", "Auditors", "billing:read")
	if again := model(t, a)["tenants"].([]map[string]any)[0]["model_sha256"]; again == sum {
		t.Error("a new role did not change model_sha256")
	}
}

func TestEventProofs(t *testing.T) {
	f := newFixture(t)
	_, _, proofs := New(f.eng, WithTenants(staffTenant)).collectors()
	if len(proofs) != 0 {
		t.Fatal("event proofs are off by default")
	}
	_, _, proofs = New(f.eng, WithTenants(staffTenant), WithEventProofs()).collectors()
	if len(proofs) != 1 {
		t.Fatalf("got %d event proof collectors, want 1", len(proofs))
	}
	e := proofs[0]
	if e.Stream != adapter.Platform || !slices.Contains(e.Actions, "warden.assignment.created") {
		t.Errorf("event proof = %+v", e)
	}
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	customer := []string{customerTenant, "usr_customer_carol", "usr_customer_dave", "org-admin"}

	run := func(a *Adapter) string {
		var b strings.Builder
		_, pops, _ := a.collectors()
		for _, p := range pops {
			items, err := p.Collect(context.Background())
			if err != nil {
				t.Fatalf("%s: %v", p.Key, err)
			}
			raw, _ := json.Marshal(items)
			b.Write(raw)
		}
		return b.String()
	}

	out := run(New(f.eng, WithTenants(staffTenant), WithRelations(0)))
	for _, c := range customer {
		if strings.Contains(out, c) {
			t.Errorf("default scope sent customer data %q", c)
		}
	}

	wide := run(New(f.eng, WithTenants(staffTenant), WithAllTenants(), WithRelations(0)))
	for _, c := range customer {
		if !strings.Contains(wide, c) {
			t.Errorf("all_tenants scope is missing %q", c)
		}
	}

	listed := run(New(f.eng, WithTenants(staffTenant, customerTenant), WithRelations(0)))
	for _, c := range []string{customerTenant, "usr_customer_dave", "org-admin"} {
		if !strings.Contains(listed, c) {
			t.Errorf("listing the customer tenant is missing %q", c)
		}
	}
	if strings.Contains(listed, "usr_customer_carol") {
		t.Error("an explicit tenant list still drops the default platform-user assignment")
	}
}

func TestAttachScopeDefaults(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	o, ok := options(adapter.Host{Scope: adapter.Scope{AppID: staffTenant}}, Options{})
	if !ok || !slices.Equal(o.Tenants, []string{staffTenant}) {
		t.Errorf("tenants = %v, %v; want the platform app", o.Tenants, ok)
	}
	if !slices.Equal(o.Privileged, adapter.DefaultStaffRoles) {
		t.Errorf("privileged = %v", o.Privileged)
	}
	o, _ = options(adapter.Host{Scope: adapter.Scope{AppID: staffTenant, StaffRoles: []string{"root"}, AllTenants: true}}, Options{})
	if !slices.Equal(o.Privileged, []string{"root"}) || !o.AllTenants {
		t.Errorf("options = %+v", o)
	}
	o, _ = options(adapter.Host{Scope: adapter.Scope{AppID: staffTenant}}, Options{Tenants: []string{"t1"}, Privileged: []string{"p"}})
	if !slices.Equal(o.Tenants, []string{"t1"}) || !slices.Equal(o.Privileged, []string{"p"}) {
		t.Errorf("config should win over scope: %+v", o)
	}
	if _, ok := options(adapter.Host{}, Options{}); ok {
		t.Error("no tenants and no all_tenants should register nothing")
	}
}

func TestPages(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const n = 2500 // past Warden's silent 1000-row cap, twice
	admin := &role.Role{TenantID: staffTenant, Slug: "platform-admin", Name: "Admin"}
	must(t, f.store.CreateRole(ctx, admin))
	for i := range n {
		must(t, f.store.CreateRole(ctx, &role.Role{TenantID: staffTenant, Slug: fmt.Sprintf("r%04d", i), Name: "r"}))
		must(t, f.store.CreateAssignment(ctx, &assignment.Assignment{
			TenantID: staffTenant, RoleID: admin.ID, SubjectKind: "user", SubjectID: fmt.Sprintf("usr_%04d", i),
		}))
		must(t, f.store.CreateRelation(ctx, &relation.Tuple{
			TenantID: staffTenant, ObjectType: "project", ObjectID: fmt.Sprintf("prj_%04d", i),
			Relation: "owner", SubjectType: "user", SubjectID: "usr_alice",
		}))
	}
	a := New(f.eng, WithTenants(staffTenant), WithRelations(0))
	if got := len(population(t, a, "warden.roles")); got != n+1 {
		t.Errorf("roles: got %d, want %d", got, n+1)
	}
	if got := len(population(t, a, "warden.assignments")); got != n {
		t.Errorf("assignments: got %d, want %d", got, n)
	}
	if got := len(population(t, a, "warden.relations")); got != n {
		t.Errorf("relations: got %d, want %d", got, n)
	}
}

func TestPagesFailPastMaxItems(t *testing.T) {
	calls := 0
	endless := func(limit, offset int) ([]int, error) {
		calls++
		page := make([]int, limit)
		for i := range page {
			page[i] = offset + i
		}
		return page, nil
	}
	if _, err := pageAll(context.Background(), 1500, endless, func(i int) string { return fmt.Sprint(i) }); err == nil {
		t.Fatal("paging past the limit should fail, not truncate")
	}
	if calls != 2 {
		t.Errorf("paged %d times, want 2", calls)
	}

	calls = 0
	same := func(limit, _ int) ([]int, error) {
		calls++
		return make([]int, limit), nil
	}
	if _, err := pageAll(context.Background(), 1<<20, same, func(i int) string { return fmt.Sprint(i) }); err == nil {
		t.Fatal("a store that ignores the offset should fail the run")
	}
	if calls > 2 {
		t.Errorf("paged %d times over the same rows", calls)
	}
}

func TestNeverSendsContent(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	a := New(f.eng, WithTenants(staffTenant, customerTenant), WithAllTenants(), WithRelations(0), WithEventProofs())
	snaps, pops, proofs := a.collectors()
	out := make([]any, 0, 3*len(snaps)+3*len(pops)+len(proofs))
	for _, s := range snaps {
		settings, err := s.Collect(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", s.Key, err)
		}
		out = append(out, s.Title, s.Description, settings)
	}
	for _, p := range pops {
		items, err := p.Collect(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", p.Key, err)
		}
		if len(items) == 0 {
			t.Fatalf("%s collected nothing, so the canary test proves nothing", p.Key)
		}
		out = append(out, p.Title, p.Description, items)
	}
	for _, e := range proofs {
		out = append(out, e)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("a collector sent content: %s", raw)
	}
}

func TestAttachReportsWidening(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	for name, tc := range map[string]struct {
		cfg       map[string]any
		allTenant bool
		want      []string
	}{
		"default":                   {nil, false, nil},
		"host scope all tenants":    {nil, true, nil},
		"all tenants":               {map[string]any{"all_tenants": true}, false, []string{"all_tenants"}},
		"empty exclude list":        {map[string]any{"exclude_role_slugs": []any{}}, false, []string{"exclude_role_slugs"}},
		"exclude list without user": {map[string]any{"exclude_role_slugs": []any{"platform-admin"}}, false, []string{"exclude_role_slugs"}},
		"exclude list with user":    {map[string]any{"exclude_role_slugs": []any{"platform-user", "x"}}, false, nil},
	} {
		t.Run(name, func(t *testing.T) {
			c := vessel.New()
			if err := vessel.ProvideValue(c, f.eng); err != nil {
				t.Fatal(err)
			}
			h, _ := host(t, c, tc.cfg)
			h.Scope.AllTenants = tc.allTenant
			var got []string
			h.Widen = func(r string) { got = append(got, r) }
			found, err := attachRegistered(t, h)
			if !found || err != nil {
				t.Fatalf("Attach = %v, %v", found, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Widen got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWidenedDescriptions(t *testing.T) {
	f := newFixture(t)
	desc := func(a *Adapter) map[string]string {
		_, pops, _ := a.collectors()
		out := map[string]string{}
		for _, p := range pops {
			out[p.Key] = p.Description
		}
		return out
	}
	narrow := desc(New(f.eng, WithTenants(staffTenant), WithRelations(0)))
	wide := desc(New(f.eng, WithAllTenants(), WithRelations(0)))
	for _, k := range []string{"warden.roles", "warden.assignments", "warden.policies", "warden.relations"} {
		if !strings.Contains(wide[k], "every tenant, customers' included") {
			t.Errorf("%s with all_tenants: %q", k, wide[k])
		}
		if strings.Contains(narrow[k], "customers") {
			t.Errorf("%s by default: %q", k, narrow[k])
		}
	}
	kept := desc(New(f.eng, WithTenants(staffTenant), WithExcludeRoleSlugs()))["warden.assignments"]
	if !strings.Contains(kept, "exclude_role_slugs") || !strings.Contains(kept, "platform-user") {
		t.Errorf("assignments with an empty exclude list: %q", kept)
	}
}

func TestAttachReportsAnEngineThatWontResolve(t *testing.T) {
	c := vessel.New()
	if err := vessel.Provide(c, func() (*xwarden.Engine, error) { return nil, errors.New("boom") }); err != nil {
		t.Fatal(err)
	}
	h, _ := host(t, c, nil)
	found, err := attachRegistered(t, h)
	if !found || err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Attach = %v, %v; want true and the resolve error", found, err)
	}
}
