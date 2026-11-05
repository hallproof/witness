package trove

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	xtrove "github.com/xraph/trove"
	"github.com/xraph/trove/driver"
	"github.com/xraph/trove/drivers/memdriver"
	"github.com/xraph/trove/extension"
	"github.com/xraph/trove/extension/model"
	"github.com/xraph/trove/extension/store"
	"github.com/xraph/trove/extension/store/memory"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

// cloudDriver stands in for a cloud driver such as s3: the memory driver
// plus native multipart and presigning.
type cloudDriver struct {
	*memdriver.MemDriver
}

func newCloud() *cloudDriver { return &cloudDriver{memdriver.New()} }

func (*cloudDriver) Name() string { return "cloud" }

func (*cloudDriver) InitiateMultipart(context.Context, string, string, ...driver.PutOption) (string, error) {
	return "", nil
}

func (*cloudDriver) UploadPart(context.Context, string, string, string, int, io.Reader) (*driver.PartInfo, error) {
	return nil, nil
}

func (*cloudDriver) CompleteMultipart(context.Context, string, string, string, []driver.PartInfo) (*driver.ObjectInfo, error) {
	return nil, nil
}

func (*cloudDriver) AbortMultipart(context.Context, string, string, string) error { return nil }

func (*cloudDriver) PresignGet(context.Context, string, string, time.Duration) (string, error) {
	return "", nil
}

func (*cloudDriver) PresignPut(context.Context, string, string, time.Duration) (string, error) {
	return "", nil
}

// open opens a Trove store or fails the test.
func open(t *testing.T, drv driver.Driver, opts ...xtrove.Option) *xtrove.Trove {
	t.Helper()
	tr, err := xtrove.Open(drv, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// manager builds a TroveManager from name, store and metadata store
// triples, with the first as default unless def names another.
func manager(t *testing.T, def string, stores map[string]*xtrove.Trove, meta map[string]store.Store) *extension.TroveManager {
	t.Helper()
	m := extension.NewTroveManager()
	for name, tr := range stores {
		m.Add(name, tr, meta[name])
	}
	if err := m.SetDefault(def); err != nil {
		t.Fatal(err)
	}
	return m
}

// bucket adds a bucket record to a metadata store.
func bucket(t *testing.T, s store.Store, b model.Bucket) {
	t.Helper()
	if err := s.CreateBucket(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
}

func newMeta() *memory.Store { return memory.New() }

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// taken reports whether a population key is already registered on w.
func taken(t *testing.T, w *witness.Witness, key string) bool {
	t.Helper()
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil
}

// populations returns the adapter's populations by key.
func populations(t *testing.T, a *Adapter) map[string]collect.Population {
	t.Helper()
	out := map[string]collect.Population{}
	for _, p := range a.populations() {
		out[p.Key] = p
	}
	return out
}

// run collects one population and round-trips it through JSON, the way it
// is sent.
func run(t *testing.T, a *Adapter, key string) []map[string]any {
	t.Helper()
	p, ok := populations(t, a)[key]
	if !ok {
		t.Fatalf("no population %q", key)
	}
	items, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// byID indexes items by their id field.
func byID(items []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, it := range items {
		id, _ := it["id"].(string)
		out[id] = it
	}
	return out
}
