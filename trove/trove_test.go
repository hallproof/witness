package trove

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	xtrove "github.com/xraph/trove"
	"github.com/xraph/trove/cas"
	"github.com/xraph/trove/drivers/memdriver"
	"github.com/xraph/trove/extension/model"
	"github.com/xraph/trove/extension/store"
	"github.com/xraph/trove/middleware"
	"github.com/xraph/trove/middleware/compress"
	"github.com/xraph/trove/middleware/encrypt"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness/adapter"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"trove"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatalf("adapter %q is not registered", Name)
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"nil": nil, "empty vessel": vessel.New(), "not a vessel": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c})
			if found || err != nil {
				t.Fatalf("attach = %v, %v; want false, nil", found, err)
			}
		})
	}
}

func TestAttachFindsManager(t *testing.T) {
	meta := newMeta()
	m := manager(t, "artifacts",
		map[string]*xtrove.Trove{
			"artifacts": open(t, memdriver.New(), xtrove.WithDefaultBucket("loomplane-artifacts")),
			"backups":   open(t, memdriver.New(), xtrove.WithDefaultBucket("loomplane-backups")),
		},
		map[string]store.Store{"artifacts": meta})
	c := vessel.New()
	if err := vessel.ProvideValue(c, m); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, key := range []string{KeyStores, KeyBuckets} {
		if !taken(t, w, key) {
			t.Errorf("%s is not registered", key)
		}
	}
}

func TestAttachFallsBackToOneStore(t *testing.T) {
	c := vessel.New()
	if err := vessel.ProvideValue(c, open(t, memdriver.New(), xtrove.WithDefaultBucket("files"))); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	if !taken(t, w, KeyStores) {
		t.Error("trove.stores is not registered")
	}
	if taken(t, w, KeyBuckets) {
		t.Error("trove.buckets is registered without a metadata store")
	}
}

func TestAttachBadConfig(t *testing.T) {
	c := vessel.New()
	if err := vessel.ProvideValue(c, open(t, memdriver.New())); err != nil {
		t.Fatal(err)
	}
	found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c, Config: map[string]any{"all_tenants": "yes"}})
	if !found || err == nil {
		t.Fatalf("attach = %v, %v; want true and a config error", found, err)
	}
}

func TestStores(t *testing.T) {
	artifacts := open(t, newCloud(),
		xtrove.WithDefaultBucket("loomplane-artifacts"),
		xtrove.WithMiddleware(encrypt.New(encrypt.WithKeyProvider(encrypt.NewStaticKeyProvider(testKey)))),
		xtrove.WithBackend("archive", memdriver.New()),
		xtrove.WithBackend("cold", newCloud()),
	)
	backups := open(t, memdriver.New(),
		xtrove.WithDefaultBucket("loomplane-backups"),
		xtrove.WithScopedMiddleware(&middleware.ScopeBucket{Buckets: []string{"loomplane-backups"}}, compress.New()),
		xtrove.WithCAS(cas.AlgSHA256),
		xtrove.WithChecksumAlgorithm(xtrove.Blake3),
	)
	// Registered for reads only: nothing is encrypted on write.
	readOnly := open(t, memdriver.New(), xtrove.WithReadMiddleware(encrypt.New()))
	a := NewManager(manager(t, "artifacts",
		map[string]*xtrove.Trove{"artifacts": artifacts, "backups": backups, "scratch": readOnly}, nil))

	items := run(t, a, KeyStores)
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3: %v", len(items), items)
	}
	if ids := []string{items[0]["id"].(string), items[1]["id"].(string), items[2]["id"].(string)}; !slices.Equal(ids, []string{"artifacts/loomplane-artifacts", "backups/loomplane-backups", "scratch"}) {
		t.Fatalf("ids = %v, want sorted by store", ids)
	}
	got := byID(items)

	art := got["artifacts/loomplane-artifacts"]
	want := map[string]any{
		"id":                            "artifacts/loomplane-artifacts",
		"store":                         "artifacts",
		"bucket":                        "loomplane-artifacts",
		"default_store":                 true,
		"driver":                        "cloud",
		"backends":                      []any{map[string]any{"name": "archive", "driver": "mem", "multipart": false}, map[string]any{"name": "cold", "driver": "cloud", "multipart": true}},
		"encryption_applied":            true,
		"encryption_global":             true,
		"encryption_scopes":             []any{"global"},
		"encryption_algorithm":          "aes-256-gcm",
		"backend_encryption":            "unknown",
		"compression_applied":           false,
		"scanning_applied":              false,
		"cas_enabled":                   false,
		"checksum_algorithm":            "sha256",
		"multipart":                     true,
		"presign":                       true,
		"versioning":                    false,
		"lifecycle":                     false,
		"multipart_bypasses_middleware": true,
	}
	if !reflect.DeepEqual(art, want) {
		t.Errorf("artifacts item =\n%v\nwant\n%v", art, want)
	}

	bk := got["backups/loomplane-backups"]
	for field, v := range map[string]any{
		"default_store":                 false,
		"driver":                        "mem",
		"backends":                      []any{},
		"encryption_applied":            false,
		"encryption_global":             false,
		"encryption_scopes":             []any{},
		"encryption_algorithm":          nil,
		"compression_applied":           true,
		"cas_enabled":                   true,
		"checksum_algorithm":            "blake3",
		"multipart":                     false,
		"presign":                       false,
		"multipart_bypasses_middleware": false,
	} {
		if !reflect.DeepEqual(bk[field], v) {
			t.Errorf("backups %s = %#v, want %#v", field, bk[field], v)
		}
	}

	sc := got["scratch"]
	if sc["bucket"] != "" || sc["encryption_applied"] != false || sc["encryption_algorithm"] != nil {
		t.Errorf("read-only encrypt reads as applied: %v", sc)
	}
}

func TestStoresScopedEncryption(t *testing.T) {
	scope := &middleware.ScopeFunc{Fn: func(context.Context, string, string) bool { return true }, Desc: "tenant files"}
	tr := open(t, memdriver.New(),
		xtrove.WithDefaultBucket("files"),
		xtrove.WithScopedWriteMiddleware(scope, encrypt.New()),
		xtrove.WithScopedWriteMiddleware(&middleware.ScopeBucket{Buckets: []string{"files"}}, encrypt.New()),
	)
	it := run(t, New(tr), KeyStores)[0]
	if it["store"] != DefaultStore || it["encryption_applied"] != true || it["encryption_global"] != false {
		t.Fatalf("item = %v", it)
	}
	if got := it["encryption_scopes"]; !reflect.DeepEqual(got, []any{"bucket(files)", "tenant files"}) {
		t.Errorf("encryption_scopes = %v", got)
	}
}

// customEncrypt is a middleware named encrypt that isn't Trove's own, so
// its algorithm is unknown.
type customEncrypt struct{ *encrypt.Encrypt }

func TestStoresUnknownEncryption(t *testing.T) {
	tr := open(t, memdriver.New())
	tr.UseMiddleware(middleware.Registration{Middleware: customEncrypt{encrypt.New()}})
	it := run(t, New(tr), KeyStores)[0]
	if it["encryption_applied"] != true || it["encryption_algorithm"] != "unknown" {
		t.Errorf("item = %v", it)
	}
}

func TestBuckets(t *testing.T) {
	shared := newMeta()
	bucket(t, shared, model.Bucket{
		ID: "bkt_1", Name: "loomplane-artifacts", Driver: "s3", Region: "eu-west-1",
		Versioning: true, CASEnabled: true, QuotaBytes: 1 << 30, QuotaObjects: 1000,
		Lifecycle: model.MarshalLifecycleRules([]model.LifecycleRule{{ID: "expire", Prefix: "tmp/", ExpirationDays: 30, AbortIncompleteDays: 7}}),
	})
	bucket(t, shared, model.Bucket{ID: "bkt_2", Name: "broken", Lifecycle: json.RawMessage(`{"not":"rules"`)})
	other := newMeta()
	bucket(t, other, model.Bucket{ID: "bkt_3", Name: "loomplane-backups", Driver: "local"})

	a := NewManager(manager(t, "artifacts", map[string]*xtrove.Trove{
		"artifacts": open(t, memdriver.New()),
		"backups":   open(t, memdriver.New()),
		"scratch":   open(t, memdriver.New()),
		"other":     open(t, memdriver.New()),
	}, map[string]store.Store{"artifacts": shared, "backups": shared, "other": other}))

	items := run(t, a, KeyBuckets)
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3: %v", len(items), items)
	}
	if ids := []string{items[0]["id"].(string), items[1]["id"].(string), items[2]["id"].(string)}; !slices.Equal(ids, []string{"bkt_1", "bkt_2", "bkt_3"}) {
		t.Fatalf("ids = %v, want sorted", ids)
	}
	got := byID(items)
	b1 := got["bkt_1"]
	stamp := b1["created_at"].(string)
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		t.Errorf("created_at %q: %v", stamp, err)
	}
	want := map[string]any{
		"id": "bkt_1", "stores": []any{"artifacts", "backups"}, "name": "loomplane-artifacts",
		"driver": "s3", "region": "eu-west-1", "versioning": true, "cas_enabled": true,
		"quota_bytes": float64(1 << 30), "quota_objects": float64(1000), "tenanted": false,
		"lifecycle": []any{map[string]any{
			"id": "expire", "prefix": "tmp/", "expiration_days": float64(30), "transition_days": float64(0),
			"transition_class": "", "noncurrent_days": float64(0), "abort_incomplete_days": float64(7),
		}},
		"lifecycle_unreadable": false,
		"created_at":           b1["created_at"], "updated_at": b1["updated_at"],
	}
	if !reflect.DeepEqual(b1, want) {
		t.Errorf("bkt_1 =\n%v\nwant\n%v", b1, want)
	}
	if b2 := got["bkt_2"]; b2["lifecycle_unreadable"] != true || !reflect.DeepEqual(b2["lifecycle"], []any{}) {
		t.Errorf("bkt_2 = %v, want an unreadable lifecycle", b2)
	}
	if b3 := got["bkt_3"]; !reflect.DeepEqual(b3["stores"], []any{"other"}) {
		t.Errorf("bkt_3 stores = %v", b3["stores"])
	}
}

func TestBucketsOneStore(t *testing.T) {
	meta := newMeta()
	bucket(t, meta, model.Bucket{ID: "bkt_1", Name: "files"})
	a := New(open(t, memdriver.New()), WithMetadataStore(meta))
	items := run(t, a, KeyBuckets)
	if len(items) != 1 || !reflect.DeepEqual(items[0]["stores"], []any{DefaultStore}) {
		t.Fatalf("items = %v", items)
	}
	if _, ok := populations(t, New(open(t, memdriver.New())))[KeyBuckets]; ok {
		t.Error("trove.buckets registered with no metadata store")
	}
}

func TestStaffScope(t *testing.T) {
	seed := func() store.Store {
		s := newMeta()
		bucket(t, s, model.Bucket{ID: "bkt_platform", Name: "platform"})
		bucket(t, s, model.Bucket{ID: "bkt_customer", Name: "customer-files", TenantKey: "org_customer"})
		return s
	}
	ids := func(items []map[string]any) []string {
		out := make([]string, 0, len(items))
		for _, it := range items {
			out = append(out, it["id"].(string))
		}
		return out
	}

	if got := ids(run(t, New(open(t, memdriver.New()), WithMetadataStore(seed())), KeyBuckets)); !slices.Equal(got, []string{"bkt_platform"}) {
		t.Errorf("default scope = %v, want the platform bucket only", got)
	}
	wide := run(t, New(open(t, memdriver.New()), WithMetadataStore(seed()), WithAllTenants()), KeyBuckets)
	if got := ids(wide); !slices.Equal(got, []string{"bkt_customer", "bkt_platform"}) {
		t.Errorf("all tenants = %v", got)
	}
	if it := byID(wide)["bkt_customer"]; it["tenanted"] != true {
		t.Errorf("customer bucket not marked tenanted: %v", it)
	}

	// Through attach, the host's scope and the config both widen it.
	for name, h := range map[string]adapter.Host{
		"scope":  {Scope: adapter.Scope{AllTenants: true}},
		"config": {Config: map[string]any{"all_tenants": true}},
		"none":   {},
	} {
		t.Run(name, func(t *testing.T) {
			m := manager(t, "files", map[string]*xtrove.Trove{"files": open(t, memdriver.New())}, map[string]store.Store{"files": seed()})
			c := vessel.New()
			if err := vessel.ProvideValue(c, m); err != nil {
				t.Fatal(err)
			}
			h.Container = c
			o, err := options(h)
			if err != nil {
				t.Fatal(err)
			}
			got := ids(run(t, newManager(m, o), KeyBuckets))
			wantN := 2
			if name == "none" {
				wantN = 1
			}
			if len(got) != wantN {
				t.Errorf("got %v", got)
			}
		})
	}
}

// all_tenants in the adapter's own config takes trove.buckets past staff,
// so attach tells the host. The witness scope's AllTenants is the host's
// own setting, which it already knows about.
func TestAttachReportsWidening(t *testing.T) {
	for name, tc := range map[string]struct {
		h    adapter.Host
		want []string
	}{
		"default":            {want: nil},
		"all tenants":        {h: adapter.Host{Config: map[string]any{"all_tenants": true}}, want: []string{"all_tenants"}},
		"global all tenants": {h: adapter.Host{Scope: adapter.Scope{AllTenants: true}}, want: nil},
	} {
		t.Run(name, func(t *testing.T) {
			c := vessel.New()
			if err := vessel.ProvideValue(c, open(t, memdriver.New())); err != nil {
				t.Fatal(err)
			}
			var got []string
			h := tc.h
			h.Witness, h.Container = newWitness(t), c
			h.Widen = func(reason string) { got = append(got, reason) }
			found, err := attach(context.Background(), h)
			if !found || err != nil {
				t.Fatalf("attach = %v, %v", found, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("widened = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWidenedDescription(t *testing.T) {
	desc := func(a *Adapter) string {
		for _, p := range a.populations() {
			if p.Key == KeyBuckets {
				return p.Description
			}
		}
		t.Fatal("trove.buckets is not registered")
		return ""
	}
	staff := desc(New(open(t, memdriver.New()), WithMetadataStore(newMeta())))
	wide := desc(New(open(t, memdriver.New()), WithMetadataStore(newMeta()), WithAllTenants()))
	if strings.Contains(staff, "customers'") {
		t.Errorf("staff description = %q", staff)
	}
	if !strings.Contains(wide, "customers'") {
		t.Errorf("widened description = %q", wide)
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	old := maxItems
	maxItems = 1
	t.Cleanup(func() { maxItems = old })

	meta := newMeta()
	bucket(t, meta, model.Bucket{ID: "bkt_1", Name: "a"})
	bucket(t, meta, model.Bucket{ID: "bkt_2", Name: "b"})
	p := populations(t, New(open(t, memdriver.New()), WithMetadataStore(meta)))[KeyBuckets]
	if _, err := p.Collect(context.Background()); !errors.Is(err, ErrTooMany) {
		t.Errorf("buckets: err = %v, want ErrTooMany", err)
	}

	m := manager(t, "a", map[string]*xtrove.Trove{"a": open(t, memdriver.New()), "b": open(t, memdriver.New())}, nil)
	p = populations(t, NewManager(m))[KeyStores]
	if _, err := p.Collect(context.Background()); !errors.Is(err, ErrTooMany) {
		t.Errorf("stores: err = %v, want ErrTooMany", err)
	}
}

func TestMetadataErrorFailsTheRun(t *testing.T) {
	a := New(open(t, memdriver.New()), WithMetadataStore(failingStore{newMeta()}))
	p := populations(t, a)[KeyBuckets]
	// Collector errors are only logged on your side, never sent, so the
	// store's own error is wrapped for the operator.
	items, err := p.Collect(context.Background())
	if !errors.Is(err, errDB) || items != nil {
		t.Fatalf("collect = %v, %v; want the store's error and no items", items, err)
	}
}

var errDB = errors.New("database is down")

type failingStore struct{ store.Store }

func (failingStore) ListBuckets(context.Context, string) ([]*model.Bucket, error) {
	return nil, errDB
}

func TestRegisterAddsCollectors(t *testing.T) {
	w := newWitness(t)
	if err := New(open(t, memdriver.New())).Register(w); err != nil {
		t.Fatal(err)
	}
	if !taken(t, w, KeyStores) || taken(t, w, KeyBuckets) {
		t.Error("Register added the wrong collectors")
	}
}

func TestNeverSendsContent(t *testing.T) {
	const canary = "CANARY"
	ctx := context.Background()

	// The encrypt key, a DSN handed to the driver, and an object with a key
	// and a body in the store.
	drv := newCloud()
	if err := drv.Open(ctx, "s3://CANARY-ACCESS:CANARY-SECRET@s3.example.com/bucket?region=CANARY"); err != nil {
		t.Fatal(err)
	}
	key := []byte("CANARY-KEY-0123456789abcdefghijk")
	scope := &middleware.ScopeFunc{Fn: func(context.Context, string, string) bool { return strings.Contains(canary, "C") }}
	tr := open(t, drv,
		xtrove.WithDefaultBucket("files"),
		xtrove.WithScopedMiddleware(scope, encrypt.New(encrypt.WithKeyProvider(encrypt.NewStaticKeyProvider(key)))),
		xtrove.WithRoute("CANARY-ROUTE/*", "archive"),
		xtrove.WithBackend("archive", memdriver.New()),
	)
	if err := tr.CreateBucket(ctx, "files"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Put(ctx, "files", "CANARY-OBJECT-KEY.txt", strings.NewReader("CANARY-BODY")); err != nil {
		t.Fatal(err)
	}

	// Bucket records with free-form metadata, a tenant bucket, and the
	// objects, uploads and CAS entries the collectors must never read.
	meta := newMeta()
	bucket(t, meta, model.Bucket{ID: "bkt_1", Name: "files", DefaultMeta: map[string]string{"owner": "CANARY-META"}})
	bucket(t, meta, model.Bucket{ID: "bkt_CANARY", Name: "CANARY-TENANT-BUCKET", TenantKey: "CANARY-TENANT-KEY"})
	if err := meta.CreateObject(ctx, &model.Object{ID: "obj_CANARY", BucketID: "bkt_1", Key: "CANARY-OBJECT", Metadata: map[string]string{"x": "CANARY"}}); err != nil {
		t.Fatal(err)
	}
	if err := meta.CreateUploadSession(ctx, &model.UploadSession{ID: "up_CANARY", BucketID: "bkt_1", ObjectKey: "CANARY-UPLOAD"}); err != nil {
		t.Fatal(err)
	}
	if err := meta.PutCASEntry(ctx, &model.CASEntry{Hash: "CANARY-HASH", BucketID: "bkt_1", Key: "CANARY-CAS"}); err != nil {
		t.Fatal(err)
	}

	m := manager(t, "files", map[string]*xtrove.Trove{"files": tr}, map[string]store.Store{"files": meta})
	a := NewManager(m)
	all := make([]map[string]any, 0, 2)
	for key := range populations(t, a) {
		all = append(all, run(t, a, key)...)
	}
	if len(all) != 2 {
		t.Fatalf("collected %d items, want one store and one bucket: %v", len(all), all)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("output carries a canary: %s", raw)
	}
	for _, field := range []string{"default_meta", "tenant_key", "metadata", "dsn", "url", "key"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Errorf("output has a %q field: %s", field, raw)
		}
	}
}
