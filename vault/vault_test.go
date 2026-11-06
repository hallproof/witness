package vault

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xraph/vessel"

	xvault "github.com/xraph/vault"
	"github.com/xraph/vault/config"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store"
	"github.com/xraph/vault/store/memory"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/push"
)

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != "vault" {
			continue
		}
		if a.Module != "github.com/xraph/vault" {
			t.Errorf("Module = %q", a.Module)
		}
		if !slices.Equal(a.After, []string{"vault"}) {
			t.Errorf("After = %v, want [vault]", a.After)
		}
		if a.Chain {
			t.Error("vault is not a chain adapter")
		}
		return
	}
	t.Fatal("vault adapter is not registered")
}

func attachVault(t *testing.T, container any, cfg map[string]any, scope adapter.Scope) (bool, *logBuffer, error) {
	t.Helper()
	var a adapter.Adapter
	for _, x := range adapter.Adapters() {
		if x.Name == "vault" {
			a = x
		}
	}
	log, buf := bufferLogger()
	found, err := a.Attach(bg, adapter.Host{
		Witness:   newWitness(t),
		Scope:     scope,
		Logger:    log,
		Container: container,
		Config:    cfg,
	})
	return found, buf, err
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	found, _, err := attachVault(t, vessel.New(), nil, adapter.Scope{})
	if found || err != nil {
		t.Fatalf("empty container: found=%v err=%v, want false, nil", found, err)
	}
	found, _, err = attachVault(t, "not a container", nil, adapter.Scope{})
	if found || err != nil {
		t.Fatalf("no container: found=%v err=%v, want false, nil", found, err)
	}
}

func TestAttachFindsStore(t *testing.T) {
	c := vessel.New()
	if err := vessel.ProvideValue[store.Store](c, memory.New()); err != nil {
		t.Fatal(err)
	}
	found, buf, err := attachVault(t, c, map[string]any{"apps": []any{"platform"}}, adapter.Scope{})
	if !found || err != nil {
		t.Fatalf("found=%v err=%v, want true, nil", found, err)
	}
	if !strings.Contains(buf.String(), "platform") {
		t.Errorf("coverage log doesn't name the app: %s", buf)
	}
}

func TestAttachFindsVault(t *testing.T) {
	v, err := xvault.New(xvault.WithStore(memory.New()), xvault.WithAppID("platform"))
	if err != nil {
		t.Fatal(err)
	}
	c := vessel.New()
	if err = vessel.ProvideValue(c, v); err != nil {
		t.Fatal(err)
	}
	found, _, err := attachVault(t, c, nil, adapter.Scope{})
	if !found || err != nil {
		t.Fatalf("found=%v err=%v, want true, nil", found, err)
	}
}

func TestAttachBadConfig(t *testing.T) {
	c := vessel.New()
	if err := vessel.Provide(c, func() (store.Store, error) { return memory.New(), nil }); err != nil {
		t.Fatal(err)
	}
	found, _, err := attachVault(t, c, map[string]any{"apps": "platform"}, adapter.Scope{})
	if !found || err == nil {
		t.Fatalf("found=%v err=%v, want true and an error", found, err)
	}
}

func TestAttachAllTenantsNeedsTenantList(t *testing.T) {
	c := vessel.New()
	if err := vessel.Provide(c, func() (store.Store, error) { return memory.New(), nil }); err != nil {
		t.Fatal(err)
	}
	_, buf, err := attachVault(t, c, map[string]any{"apps": []any{"platform"}}, adapter.Scope{AllTenants: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "tenants") {
		t.Errorf("no log about naming tenants: %s", buf)
	}
}

func TestNoAppsCollectsNothing(t *testing.T) {
	log, buf := bufferLogger()
	s := memory.New()
	putSecret(t, s, "platform", "", "db-password", "AES-256-GCM")
	a := New(s, WithLogger(log))
	if err := a.Register(newWitness(t)); err != nil {
		t.Fatal(err)
	}
	set := a.collectors()
	if n := len(set.snapshots) + len(set.populations) + len(set.proofs); n != 0 {
		t.Fatalf("%d collectors with no apps configured, want 0", n)
	}
	if !strings.Contains(buf.String(), "no Vault app IDs") {
		t.Errorf("no coverage log saying nothing is collected: %s", buf)
	}

	v, err := xvault.New(xvault.WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	if set := NewFromVault(v).collectors(); len(set.snapshots)+len(set.populations) != 0 {
		t.Fatal("a vault with no app ID and no apps configured must collect nothing")
	}
}

func TestRegisterOnWitness(t *testing.T) {
	v, err := xvault.New(xvault.WithStore(memory.New()), xvault.WithAppID("platform"))
	if err != nil {
		t.Fatal(err)
	}
	a := NewFromVault(v, WithEventProofs(true))
	if err := a.Register(newWitness(t)); err != nil {
		t.Fatal(err)
	}
	set := a.collectors()
	got := make([]string, 0, len(set.snapshots)+len(set.populations)+len(set.proofs))
	for _, s := range set.snapshots {
		got = append(got, s.Key)
	}
	for _, p := range set.populations {
		got = append(got, p.Key)
	}
	for _, e := range set.proofs {
		got = append(got, e.Key)
	}
	slices.Sort(got)
	want := []string{"vault.config", "vault.encryption", "vault.flags", "vault.rotation-events", "vault.rotation-policies", "vault.secrets"}
	if !slices.Equal(got, want) {
		t.Fatalf("collectors = %v, want %v", got, want)
	}
	if err := New(nil, WithApps("x")).Register(newWitness(t)); err == nil {
		t.Fatal("Register with a nil store should fail")
	}
}

func TestEventProofsOffByDefault(t *testing.T) {
	a := New(memory.New(), WithApps("platform"))
	if n := len(a.collectors().proofs); n != 0 {
		t.Fatalf("%d event proof collectors by default, want 0", n)
	}
	a = New(memory.New(), WithOptions(Options{Apps: []string{"platform"}, EventProofs: true}))
	proofs := a.collectors().proofs
	if len(proofs) != 1 {
		t.Fatalf("%d event proof collectors, want 1", len(proofs))
	}
	p := proofs[0]
	if p.Stream != adapter.Platform || !slices.Equal(p.Tests, []string{"keys-rotated"}) {
		t.Errorf("proof = %+v", p)
	}
	if !slices.Equal(p.Actions, []string{"secret.rotated", "rotation.policy_saved", "rotation.policy_deleted"}) {
		t.Errorf("actions = %v", p.Actions)
	}
}

func TestSecrets(t *testing.T) {
	s := newSpy()
	putSecret(t, s, "platform", "", "db-password", "AES-256-GCM")
	putSecret(t, s, "platform", "", "db-password", "AES-256-GCM") // version 2
	putSecret(t, s, "platform", "", "legacy-token", "")
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	putSecret(t, s, "platform", "", "expiring", "AES-256-GCM")
	m := s.Store.(*memory.Store)
	sec, _ := m.GetSecret(bg, "expiring", "platform", "")
	sec.ExpiresAt = &expires
	if err := m.SetSecret(bg, sec); err != nil {
		t.Fatal(err)
	}
	last := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	next := last.Add(30 * 24 * time.Hour)
	putPolicy(t, s, "platform", "db-password", true, 30*24*time.Hour, &last, &next)

	out := run(t, New(s, WithApps("platform")))
	items := byID(out.populations["vault.secrets"])
	if len(items) != 3 {
		t.Fatalf("got %d secrets, want 3: %v", len(items), keys(items))
	}
	db := items["platform/db-password"]
	if db["version"] != int64(2) || db["encrypted"] != true || db["encryption_alg"] != "AES-256-GCM" {
		t.Errorf("db-password = %v", db)
	}
	if db["app_id"] != "platform" || db["key"] != "db-password" || db["vault_id"] == "" {
		t.Errorf("db-password identity = %v", db)
	}
	if _, ok := db["tenant_id"]; ok {
		t.Error("app-level secret has a tenant_id")
	}
	if db["rotation_enabled"] != true || db["rotation_interval_seconds"] != int64(30*24*3600) ||
		db["last_rotated_at"] != "2026-10-01T00:00:00Z" || db["next_rotation_at"] != "2026-10-31T00:00:00Z" {
		t.Errorf("rotation fields = %v", db)
	}
	if db["created_at"] == nil || db["last_set_at"] == nil {
		t.Errorf("timestamps missing: %v", db)
	}
	legacy := items["platform/legacy-token"]
	if legacy["encrypted"] != false {
		t.Errorf("legacy-token encrypted = %v, want false", legacy["encrypted"])
	}
	if _, ok := legacy["rotation_enabled"]; ok {
		t.Error("a secret without a policy has rotation fields")
	}
	if items["platform/expiring"]["expires_at"] != "2027-01-02T03:04:05Z" {
		t.Errorf("expires_at = %v", items["platform/expiring"]["expires_at"])
	}
	if c := s.calls(); len(c) != 0 {
		t.Fatalf("the adapter called %v", c)
	}
}

func TestEncryption(t *testing.T) {
	s := memory.New()
	putSecret(t, s, "platform", "", "a", "AES-256-GCM")
	putSecret(t, s, "platform", "", "b", "")
	putSecret(t, s, "platform", "", "b", "AES-256-GCM") // b's first version stays plaintext history

	out := run(t, New(s, WithApps("platform")))
	got := out.snapshots["vault.encryption"]
	if _, ok := got["engine_encryption_enabled"]; ok {
		t.Error("a bare store reports engine settings")
	}
	apps := got["apps"].(map[string]any)
	p := apps["platform"].(map[string]any)
	if p["secrets"] != int64(2) || p["unencrypted_current"] != int64(0) || p["plaintext_versions"] != int64(1) || p["unrecorded_versions"] != int64(0) {
		t.Errorf("platform counts = %v", p)
	}

	v, err := xvault.New(xvault.WithStore(s), xvault.WithAppID("platform"), xvault.WithEncryptionKey(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	got = run(t, NewFromVault(v)).snapshots["vault.encryption"]
	if got["engine_encryption_enabled"] != true || got["engine_encryption_algorithm"] != "AES-256-GCM" {
		t.Errorf("engine settings = %v", got)
	}
}

func TestRotationPolicies(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	last := now.Add(-31 * 24 * time.Hour)
	s := memory.New()
	putPolicy(t, s, "platform", "overdue", true, 30*24*time.Hour, &last, &past)
	putPolicy(t, s, "platform", "fine", true, 30*24*time.Hour, nil, &future)
	putPolicy(t, s, "platform", "off", false, time.Hour, nil, &past)

	a := New(s, WithApps("platform"))
	a.now = func() time.Time { return now }
	items := byID(run(t, a).populations["vault.rotation-policies"])
	if len(items) != 3 {
		t.Fatalf("got %d policies: %v", len(items), keys(items))
	}
	o := items["platform/overdue"]
	if o["overdue"] != true || o["enabled"] != true || o["interval_seconds"] != int64(30*24*3600) ||
		o["secret_key"] != "overdue" || o["app_id"] != "platform" || o["last_rotated_at"] == nil {
		t.Errorf("overdue = %v", o)
	}
	if items["platform/fine"]["overdue"] != false {
		t.Errorf("fine = %v", items["platform/fine"])
	}
	if _, ok := items["platform/fine"]["last_rotated_at"]; ok {
		t.Error("last_rotated_at set for a policy that never ran")
	}
	if items["platform/off"]["overdue"] != false {
		t.Error("a disabled policy is never overdue")
	}

	empty := run(t, New(memory.New(), WithApps("platform"))).populations["vault.rotation-policies"]
	if empty == nil || len(empty) != 0 {
		t.Errorf("no policies: got %v, want an empty list", empty)
	}
}

func TestFlags(t *testing.T) {
	s := memory.New()
	putFlag(t, s, "platform", "new-billing", flag.TypeBool, true)
	putFlag(t, s, "platform", "theme", flag.TypeString, "CANARY-default")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rules := []*flag.Rule{
		flag.WhenTenant("cust-1", "cust-2").Return(true),
		flag.Rollout(25).Return(true),
		flag.Schedule(start, start.Add(time.Hour)),
		flag.WhenUser("u1"),
	}
	for i, r := range rules {
		r.Priority = i
	}
	if err := s.SetFlagRules(bg, "new-billing", "platform", rules); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFlagTenantOverride(bg, "new-billing", "platform", "cust-9", false); err != nil {
		t.Fatal(err)
	}

	items := byID(run(t, New(s, WithFlagConfigApps("platform"))).populations["vault.flags"])
	if len(items) != 2 {
		t.Fatalf("got %d flags", len(items))
	}
	b := items["platform/new-billing"]
	if b["type"] != "bool" || b["enabled"] != true || b["default_value"] != true || b["variant_count"] != 1 ||
		b["tenant_override_count"] != 1 || b["key"] != "new-billing" || b["app_id"] != "platform" {
		t.Errorf("new-billing = %v", b)
	}
	if !slices.Equal(b["tags"].([]string), []string{"billing"}) {
		t.Errorf("tags = %v", b["tags"])
	}
	rs := b["rules"].([]map[string]any)
	if len(rs) != 4 {
		t.Fatalf("rules = %v", rs)
	}
	if rs[0]["type"] != "when_tenant" || rs[0]["tenant_count"] != 2 || rs[0]["priority"] != 0 {
		t.Errorf("rule 0 = %v", rs[0])
	}
	if rs[1]["percentage"] != 25 {
		t.Errorf("rule 1 = %v", rs[1])
	}
	if rs[2]["start_at"] != "2026-01-01T00:00:00Z" || rs[2]["end_at"] != "2026-01-01T01:00:00Z" {
		t.Errorf("rule 2 = %v", rs[2])
	}
	if rs[3]["user_count"] != 1 {
		t.Errorf("rule 3 = %v", rs[3])
	}
	if _, ok := items["platform/theme"]["default_value"]; ok {
		t.Error("a string flag's default value went out")
	}
}

func TestConfig(t *testing.T) {
	s := memory.New()
	putConfig(t, s, "platform", "max-upload-mb", "50")
	putConfig(t, s, "platform", "db-url", "CANARY-postgres://user:pass@host")
	putOverride(t, s, "platform", "db-url", "cust-1", "CANARY-override")

	items := byID(run(t, New(s, WithFlagConfigApps("platform"), WithConfigValues("max-upload-mb"))).populations["vault.config"])
	if len(items) != 2 {
		t.Fatalf("got %d entries", len(items))
	}
	m := items["platform/max-upload-mb"]
	if m["value"] != "50" || m["value_type"] != "string" || m["version"] != int64(1) || m["override_count"] != 0 || m["updated_at"] == nil {
		t.Errorf("max-upload-mb = %v", m)
	}
	d := items["platform/db-url"]
	if _, ok := d["value"]; ok {
		t.Error("a value not on the allowlist went out")
	}
	if d["override_count"] != 1 {
		t.Errorf("db-url override_count = %v", d["override_count"])
	}
}

func TestStaffScope(t *testing.T) {
	s := memory.New()
	putSecret(t, s, "platform", "", "staff-key", "AES-256-GCM")
	putSecret(t, s, "platform", "cust-1", "customer-key", "AES-256-GCM")
	putSecret(t, s, "customer-app", "", "org-1/var-1", "AES-256-GCM")
	putPolicy(t, s, "customer-app", "org-1/var-1", true, time.Hour, nil, nil)
	putFlag(t, s, "customer-app", "cust-flag", flag.TypeBool, true)
	putConfig(t, s, "customer-app", "cust-config", "x")

	out := run(t, New(s, WithApps("platform"), WithFlagConfigApps("platform")))
	all := marshal(t, out.populations) + marshal(t, out.snapshots)
	for _, bad := range []string{"cust-1", "customer-key", "customer-app", "org-1", "cust-flag", "cust-config"} {
		if strings.Contains(all, bad) {
			t.Errorf("default scope leaked %q", bad)
		}
	}
	if _, ok := byID(out.populations["vault.secrets"])["platform/staff-key"]; !ok {
		t.Error("staff secret missing")
	}

	wide := byID(run(t, New(s, WithApps("platform"), WithTenants("cust-1"))).populations["vault.secrets"])
	c, ok := wide["platform/cust-1/customer-key"]
	if !ok || c["tenant_id"] != "cust-1" {
		t.Errorf("named tenant's secret missing: %v", keys(wide))
	}
	if len(wide) != 2 {
		t.Errorf("widened to one tenant, got %v", keys(wide))
	}
}

func TestPages(t *testing.T) {
	s := memory.New()
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		putSecret(t, s, "platform", "", k, "AES-256-GCM")
		putFlag(t, s, "platform", k, flag.TypeBool, false)
		putConfig(t, s, "platform", k, "v")
	}
	a := New(s, WithApps("platform"), WithFlagConfigApps("platform"))
	a.pageSize = 2
	out := run(t, a)
	for _, key := range []string{"vault.secrets", "vault.flags", "vault.config"} {
		if n := len(out.populations[key]); n != 5 {
			t.Errorf("%s: %d items over pages of 2, want 5", key, n)
		}
	}
}

func TestRefusesOverMaxItems(t *testing.T) {
	s := memory.New()
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		putSecret(t, s, "platform", "", k, "AES-256-GCM")
		putFlag(t, s, "platform", k, flag.TypeBool, false)
		putConfig(t, s, "platform", k, "v")
		putPolicy(t, s, "platform", k, true, time.Hour, nil, nil)
	}
	a := New(s, WithApps("platform"), WithFlagConfigApps("platform"))
	a.pageSize, a.maxItems = 2, 4
	for _, p := range a.collectors().populations {
		if _, err := p.Collect(bg); err == nil {
			t.Errorf("%s: 5 items over a limit of 4 went out instead of failing", p.Key)
		}
	}
	if push.MaxItems != New(s).maxItems {
		t.Error("the default limit is not push.MaxItems")
	}
}

func TestCollectorErrorsFailTheRun(t *testing.T) {
	a := New(failing{memory.New()}, WithApps("platform"), WithFlagConfigApps("platform"))
	set := a.collectors()
	for _, p := range set.populations {
		if _, err := p.Collect(bg); err == nil {
			t.Errorf("%s: no error from a failing store", p.Key)
		}
	}
	for _, sn := range set.snapshots {
		if _, err := sn.Collect(bg); err == nil {
			t.Errorf("%s: no error from a failing store", sn.Key)
		}
	}
}

type failing struct{ store.Store }

var errDown = context.DeadlineExceeded

func (failing) ListSecrets(context.Context, string, secret.ListOpts) ([]*secret.Meta, error) {
	return nil, errDown
}

func (failing) CountSecrets(context.Context, string) (int64, error) { return 0, errDown }

func (failing) ListRotationPolicies(context.Context, string) ([]*rotation.Policy, error) {
	return nil, errDown
}

func (failing) ListFlagDefinitions(context.Context, string, flag.ListOpts) ([]*flag.Definition, error) {
	return nil, errDown
}

func (failing) ListConfig(context.Context, string, config.ListOpts) ([]*config.Entry, error) {
	return nil, errDown
}

func TestNeverSendsContent(t *testing.T) {
	s := newSpy()
	for _, tenant := range []string{"", "cust-1"} {
		putSecret(t, s, "platform", tenant, "db-password", "AES-256-GCM")
		putSecret(t, s, "platform", tenant, "db-password", "AES-256-GCM")
		putSecret(t, s, "platform", tenant, "plain", "")
	}
	putSecret(t, s, "customer-app", "", "org/x", "AES-256-GCM")
	putPolicy(t, s, "platform", "db-password", true, time.Hour, nil, nil)

	putFlag(t, s, "platform", "on", flag.TypeBool, true)
	for _, typ := range []flag.Type{flag.TypeString, flag.TypeInt, flag.TypeFloat, flag.TypeJSON} {
		putFlag(t, s, "platform", "flag-"+string(typ), typ, map[string]any{"x": "CANARY-default-" + string(typ)})
	}
	custom := &flag.Rule{Type: flag.RuleCustom, Config: flag.RuleConfig{
		Evaluator: "CANARY-evaluator",
		Params:    map[string]any{"CANARY-param-key": "CANARY-param-value"},
	}}
	rules := []*flag.Rule{
		flag.WhenTenant("CANARY-rule-tenant").Return("CANARY-return"),
		flag.WhenTenantTag("CANARY-tag-key", "CANARY-tag-value").Return("CANARY-return"),
		flag.WhenUser("CANARY-rule-user").Return("CANARY-return"),
		custom.Return("CANARY-return"),
	}
	for _, k := range []string{"on", "flag-string"} {
		if err := s.SetFlagRules(bg, k, "platform", rules); err != nil {
			t.Fatal(err)
		}
		if err := s.SetFlagTenantOverride(bg, k, "platform", "CANARY-override-tenant", "CANARY-override-value"); err != nil {
			t.Fatal(err)
		}
	}
	putConfig(t, s, "platform", "db-url", "CANARY-config-value")
	putConfig(t, s, "platform", "db-url", map[string]any{"dsn": "CANARY-config-value-2"})
	putOverride(t, s, "platform", "db-url", "CANARY-config-override-tenant", "CANARY-config-override-value")

	v, err := xvault.New(xvault.WithStore(s), xvault.WithAppID("platform"))
	if err != nil {
		t.Fatal(err)
	}
	a := NewFromVault(v, WithTenants("cust-1"), WithEventProofs(true))
	out := run(t, a)
	if len(out.populations["vault.secrets"]) != 4 || len(out.populations["vault.flags"]) != 5 || len(out.populations["vault.config"]) != 1 {
		t.Fatalf("collected too little to prove anything: %s", marshal(t, out.populations))
	}
	all := marshal(t, out.populations) + marshal(t, out.snapshots)
	if strings.Contains(all, "CANARY") {
		t.Fatalf("content went out: %s", all)
	}
	forbidden := []string{"metadata", "value", "return_value", "params", "tenant_ids", "user_ids", "description", "variants", "evaluator", "tag_key", "tag_value", "encrypted_value", "encryption_key_id"}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if slices.Contains(forbidden, k) {
					t.Errorf("%s has field %q", path, k)
				}
				walk(path+"."+k, val)
			}
		case []any:
			for _, val := range x {
				walk(path, val)
			}
		}
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(marshal(t, out.populations)), &generic); err != nil {
		t.Fatal(err)
	}
	walk("populations", generic)
	for _, f := range out.populations["vault.flags"] {
		if _, ok := f["default_value"]; ok && f["type"] != "bool" {
			t.Errorf("%v: a non-bool default value went out", f["id"])
		}
	}
	if c := s.calls(); len(c) != 0 {
		t.Fatalf("the adapter called %v", c)
	}
}

// vaultExt stands in for Vault's Forge extension: only its getters.
type vaultExt struct {
	v *xvault.Vault
	s store.Store
}

func (x vaultExt) Vault() *xvault.Vault { return x.v }
func (x vaultExt) Store() store.Store   { return x.s }

// attachExt attaches the adapter in an app that runs ext under Vault's
// extension name, with c as its container.
func attachExt(t *testing.T, c any, ext any, cfg map[string]any) (bool, *witness.Witness, *logBuffer, error) {
	t.Helper()
	var a adapter.Adapter
	for _, x := range adapter.Adapters() {
		if x.Name == "vault" {
			a = x
		}
	}
	w := newWitness(t)
	log, buf := bufferLogger()
	found, err := a.Attach(bg, adapter.Host{
		Witness:   w,
		Logger:    log,
		Container: c,
		Config:    cfg,
		Extension: func(name string) (any, bool) {
			if name == "vault" {
				return ext, true
			}
			return nil, false
		},
	})
	return found, w, buf, err
}

// countingContainer registers the vault and its store with constructors,
// as Vault's extension does, and counts how often the container builds
// either.
func countingContainer(t *testing.T, v *xvault.Vault) (vessel.Vessel, *int) {
	t.Helper()
	calls := new(int)
	c := vessel.New()
	if err := vessel.Provide(c, func() (*xvault.Vault, error) {
		*calls++
		return v, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := vessel.Provide(c, func() (store.Store, error) {
		*calls++
		return v.Store(), nil
	}); err != nil {
		t.Fatal(err)
	}
	return c, calls
}

func platformVault(t *testing.T) *xvault.Vault {
	t.Helper()
	v, err := xvault.New(xvault.WithStore(memory.New()), xvault.WithAppID("platform"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// taken reports whether a population key is already registered on w.
func taken(w *witness.Witness, key string) bool {
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

func TestAttachUsesTheExtensionNotTheContainer(t *testing.T) {
	v := platformVault(t)
	c, calls := countingContainer(t, v)
	found, w, _, err := attachExt(t, c, vaultExt{v: v, s: v.Store()}, nil)
	if !found || err != nil {
		t.Fatalf("found=%v err=%v, want true, nil", found, err)
	}
	if *calls != 0 {
		t.Fatalf("the container built the vault or its store %d times; want 0", *calls)
	}
	for _, k := range []string{"vault.secrets", "vault.flags"} {
		if !taken(w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
}

// An extension with a store but no vault yet still gives the store.
func TestAttachUsesTheExtensionStore(t *testing.T) {
	v := platformVault(t)
	c, calls := countingContainer(t, v)
	found, w, _, err := attachExt(t, c, vaultExt{s: v.Store()}, map[string]any{"apps": []any{"platform"}})
	if !found || err != nil {
		t.Fatalf("found=%v err=%v, want true, nil", found, err)
	}
	if *calls != 0 {
		t.Fatalf("the container built the vault or its store %d times; want 0", *calls)
	}
	if !taken(w, "vault.secrets") {
		t.Error("vault.secrets was not registered")
	}
}

func TestAttachExtensionWithoutVault(t *testing.T) {
	v := platformVault(t)
	c, calls := countingContainer(t, v)
	found, w, buf, err := attachExt(t, c, vaultExt{}, nil)
	if found || err != nil {
		t.Fatalf("found=%v err=%v, want false, nil", found, err)
	}
	if *calls != 0 {
		t.Fatalf("the container built the vault or its store %d times; want 0", *calls)
	}
	if taken(w, "vault.secrets") {
		t.Error("vault.secrets was registered with no vault")
	}
	if !strings.Contains(buf.String(), "extension") {
		t.Errorf("no log about the extension: %s", buf)
	}
}

func TestAttachExtensionWithoutGetterSkipsTheContainer(t *testing.T) {
	v := platformVault(t)
	c, calls := countingContainer(t, v)
	found, w, buf, err := attachExt(t, c, struct{}{}, map[string]any{"apps": []any{"platform"}})
	if found || err != nil {
		t.Fatalf("found=%v err=%v, want false, nil", found, err)
	}
	if *calls != 0 {
		t.Fatalf("the container built the vault or its store %d times; want 0", *calls)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "no Vault or Store getter") {
		t.Fatalf("no warning about the missing getters; logs:\n%s", buf)
	}
	if taken(w, "vault.secrets") {
		t.Error("vault.secrets was registered without the extension's vault")
	}
}
