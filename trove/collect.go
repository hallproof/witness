package trove

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/xraph/trove/driver"
	"github.com/xraph/trove/extension/model"
	"github.com/xraph/trove/middleware"
	"github.com/xraph/trove/middleware/encrypt"
)

// Middleware names, as Trove's own middleware reports them.
const (
	mwEncrypt  = "encrypt"
	mwCompress = "compress"
	mwScan     = "scan"
)

// sortedStores returns the stores to read, sorted by name.
func (a *Adapter) sortedStores() []storeRef {
	refs := a.stores()
	sort.Slice(refs, func(i, j int) bool { return refs[i].name < refs[j].name })
	return refs
}

// collectStores reads each store's configuration from memory. It makes no
// driver call, and never reads a DSN, a key, or any object.
func (a *Adapter) collectStores(_ context.Context) ([]map[string]any, error) {
	refs := a.sortedStores()
	if len(refs) > maxItems {
		return nil, fmt.Errorf("%w: %d stores, the limit is %d", ErrTooMany, len(refs), maxItems)
	}
	out := make([]map[string]any, 0, len(refs))
	for _, ref := range refs {
		out = append(out, storeItem(ref))
	}
	return out, nil
}

func storeItem(ref storeRef) map[string]any {
	t := ref.t
	cfg := t.Config()
	id := ref.name
	if cfg.DefaultBucket != "" {
		id += "/" + cfg.DefaultBucket
	}

	drv := t.Driver()
	multipart := isMultipart(drv)
	anyMultipart := multipart
	backends := []map[string]any{}
	for _, name := range t.Backends() {
		b, err := t.Backend(name)
		if err != nil {
			continue // only when the name is unknown, which Backends rules out
		}
		bd := b.Driver()
		mp := isMultipart(bd)
		anyMultipart = anyMultipart || mp
		backends = append(backends, map[string]any{"name": name, "driver": driverName(bd), "multipart": mp})
	}

	regs := t.Resolver().Registrations()
	enc := coverageOf(regs, mwEncrypt)
	var algorithm any
	if enc.applied {
		algorithm = "unknown"
		if onlyTroveEncrypt(regs) {
			algorithm = "aes-256-gcm"
		}
	}
	_, presign := drv.(driver.PresignDriver)
	_, versioning := drv.(driver.VersioningDriver)
	_, lifecycle := drv.(driver.LifecycleDriver)

	return map[string]any{
		"id":            id,
		"store":         ref.name,
		"bucket":        cfg.DefaultBucket,
		"default_store": ref.isDefault,
		"driver":        driverName(drv),
		"backends":      backends,

		"encryption_applied":   enc.applied,
		"encryption_global":    enc.global,
		"encryption_scopes":    enc.scopes,
		"encryption_algorithm": algorithm,
		// No driver reports server-side encryption yet; see the package doc.
		"backend_encryption": "unknown",

		"compression_applied": coverageOf(regs, mwCompress).applied,
		"scanning_applied":    coverageOf(regs, mwScan).applied,
		"cas_enabled":         t.CAS() != nil,
		"checksum_algorithm":  cfg.ChecksumAlgorithm.String(),

		"multipart":  multipart,
		"presign":    presign,
		"versioning": versioning,
		"lifecycle":  lifecycle,
		// Native multipart uploads skip Trove's middleware, so an object
		// written that way is not encrypted, compressed or scanned by it.
		"multipart_bypasses_middleware": anyMultipart && anyWriteMiddleware(regs),
	}
}

func driverName(d driver.Driver) string {
	if d == nil {
		return ""
	}
	return d.Name()
}

func isMultipart(d driver.Driver) bool {
	_, ok := d.(driver.MultipartDriver)
	return ok
}

// coverage is where one middleware runs on the write path.
type coverage struct {
	applied bool     // at least one registration runs when objects are written
	global  bool     // one of those has a global scope
	scopes  []string // distinct scopes of those registrations, sorted
}

// coverageOf reads where the middleware called name runs on write. It
// mirrors the Trove dashboard's own check: a registration counts only if
// its direction includes writes and it implements the write interface,
// which is what Trove's resolver requires before it runs it.
func coverageOf(regs []middleware.Registration, name string) coverage {
	c := coverage{scopes: []string{}}
	for _, r := range regs {
		if r.Middleware == nil || r.Middleware.Name() != name || !runsOnWrite(r) {
			continue
		}
		c.applied = true
		sc := r.Scope
		if sc == nil {
			sc = middleware.ScopeGlobal{}
		}
		if _, ok := sc.(middleware.ScopeGlobal); ok {
			c.global = true
		}
		// A scope's String is the description the developer wrote, never
		// its predicate.
		if s := sc.String(); !slices.Contains(c.scopes, s) {
			c.scopes = append(c.scopes, s)
		}
	}
	sort.Strings(c.scopes)
	return c
}

// onlyTroveEncrypt reports whether every encrypt registration that runs on
// write is Trove's own AES-256-GCM middleware, rather than a custom one
// that took the same name.
func onlyTroveEncrypt(regs []middleware.Registration) bool {
	for _, r := range regs {
		if r.Middleware == nil || r.Middleware.Name() != mwEncrypt || !runsOnWrite(r) {
			continue
		}
		if _, own := r.Middleware.(*encrypt.Encrypt); !own {
			return false
		}
	}
	return true
}

func runsOnWrite(r middleware.Registration) bool {
	dir := r.Direction
	if dir == 0 {
		dir = r.Middleware.Direction()
	}
	if dir&middleware.DirectionWrite == 0 {
		return false
	}
	_, ok := r.Middleware.(middleware.WriteMiddleware)
	return ok
}

// anyWriteMiddleware reports whether any middleware runs on write.
func anyWriteMiddleware(regs []middleware.Registration) bool {
	for _, r := range regs {
		if r.Middleware != nil && runsOnWrite(r) {
			return true
		}
	}
	return false
}

// bucketRecord is one metadata-store bucket and the stores whose metadata
// store holds it. Stores that share a database see the same records.
type bucketRecord struct {
	b      *model.Bucket
	stores []string
}

// collectBuckets reads bucket records from each store's metadata store.
// Records that belong to a tenant are left out unless AllTenants is on.
// Objects, uploads and CAS entries are never read.
func (a *Adapter) collectBuckets(ctx context.Context) ([]map[string]any, error) {
	byID := map[string]*bucketRecord{}
	var order []string
	for _, ref := range a.sortedStores() {
		if ref.meta == nil {
			continue
		}
		// An empty tenant key lists every tenant's buckets, so the filter
		// below decides scope.
		list, err := ref.meta.ListBuckets(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("witness/trove: list bucket records of store %q: %w", ref.name, err)
		}
		for _, b := range list {
			if b == nil || (b.TenantKey != "" && !a.o.AllTenants) {
				continue
			}
			if rec, ok := byID[b.ID]; ok {
				if !slices.Contains(rec.stores, ref.name) {
					rec.stores = append(rec.stores, ref.name)
				}
				continue
			}
			byID[b.ID] = &bucketRecord{b: b, stores: []string{ref.name}}
			order = append(order, b.ID)
			if len(order) > maxItems {
				return nil, fmt.Errorf("%w: more than %d bucket records", ErrTooMany, maxItems)
			}
		}
	}
	sort.Strings(order)
	out := make([]map[string]any, 0, len(order))
	for _, id := range order {
		out = append(out, bucketItem(byID[id]))
	}
	return out, nil
}

// lifecycleRule is the part of a lifecycle rule that is sent. Decoding
// into it drops any field Trove adds later until this adapter names it.
type lifecycleRule struct {
	ID                  string `json:"id"`
	Prefix              string `json:"prefix"`
	ExpirationDays      int    `json:"expiration_days"`
	TransitionDays      int    `json:"transition_days"`
	TransitionClass     string `json:"transition_class"`
	NoncurrentDays      int    `json:"noncurrent_days"`
	AbortIncompleteDays int    `json:"abort_incomplete_days"`
}

func bucketItem(rec *bucketRecord) map[string]any {
	b := rec.b
	rules := []lifecycleRule{}
	unreadable := false
	if len(b.Lifecycle) > 0 && string(b.Lifecycle) != "null" {
		if err := json.Unmarshal(b.Lifecycle, &rules); err != nil {
			rules, unreadable = []lifecycleRule{}, true
		}
	}
	if rules == nil {
		rules = []lifecycleRule{}
	}
	return map[string]any{
		"id":                   b.ID,
		"stores":               rec.stores,
		"name":                 b.Name,
		"driver":               b.Driver,
		"region":               b.Region,
		"versioning":           b.Versioning,
		"cas_enabled":          b.CASEnabled,
		"quota_bytes":          b.QuotaBytes,
		"quota_objects":        b.QuotaObjects,
		"lifecycle":            rules,
		"lifecycle_unreadable": unreadable,
		"tenanted":             b.TenantKey != "",
		"created_at":           stamp(b.CreatedAt),
		"updated_at":           stamp(b.UpdatedAt),
	}
}

func stamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}
