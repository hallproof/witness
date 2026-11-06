package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/xraph/relay/catalog"
	"github.com/xraph/relay/endpoint"

	"github.com/hallproof/witness/push"
)

// pageSize is how many rows each list call asks for.
const pageSize = 500

// maxItems is the most rows a population reads in scope before it fails
// the run. A variable so tests can lower it.
var maxItems = push.MaxItems

// errStuck is what a walk returns when a full page brings no row it hasn't
// seen, which means the store ignores Offset and paging would never end.
var errStuck = errors.New("witness/relay: the store returned a full page of rows already seen; does it honour Offset?")

// eachEndpoint pages through tenantID's endpoints ("" is every tenant) and
// calls fn once per endpoint. A row repeated on a later page (offset paging
// can repeat one when endpoints are created mid-scan) is skipped.
func (a *Adapter) eachEndpoint(ctx context.Context, tenantID string, seen map[string]bool, fn func(*endpoint.Endpoint) error) error {
	for off := 0; ; off += pageSize {
		page, err := a.eps.ListEndpoints(ctx, tenantID, endpoint.ListOpts{Offset: off, Limit: pageSize})
		if err != nil {
			return fmt.Errorf("witness/relay: list endpoints: %w", err)
		}
		fresh := 0
		for _, ep := range page {
			if ep == nil {
				continue
			}
			eid := ep.ID.String()
			if seen[eid] {
				continue
			}
			seen[eid] = true
			fresh++
			if err := fn(ep); err != nil {
				return err
			}
		}
		if len(page) < pageSize {
			return nil
		}
		if fresh == 0 {
			return errStuck
		}
	}
}

// scopeTenants are the tenant IDs the endpoint population lists: one empty
// ID, which relay reads as every tenant, when AllTenants is on, else the
// staff tenants.
func (a *Adapter) scopeTenants() []string {
	if a.o.AllTenants {
		return []string{""}
	}
	return a.tenants
}

func (a *Adapter) collectEndpoints(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	seen := map[string]bool{}
	for _, t := range a.scopeTenants() {
		err := a.eachEndpoint(ctx, t, seen, func(ep *endpoint.Endpoint) error {
			// Checked again after the store's own filter, so a store that
			// ignores the tenant can't widen the scope.
			if !a.o.AllTenants && !a.tenantIn[ep.TenantID] {
				return nil
			}
			if len(out) >= maxItems {
				return fmt.Errorf("%w: more than %d endpoints", ErrTooMany, maxItems)
			}
			out = append(out, endpointItem(ep))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// endpointItem maps the fields an endpoint may send, one by one. The
// secret is read only to say whether one is set; the URL gives its scheme
// and host only; headers give their names only.
func endpointItem(ep *endpoint.Endpoint) map[string]any {
	scheme, host := destination(ep.URL)
	events := slices.Clone(ep.EventTypes)
	if events == nil {
		events = []string{}
	}
	slices.Sort(events)
	names := make([]string, 0, len(ep.Headers))
	for name := range ep.Headers {
		if n := strings.ToLower(strings.TrimSpace(name)); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return map[string]any{
		"id":                  ep.ID.String(),
		"tenant_id":           ep.TenantID,
		"scope_app_id":        ep.ScopeAppID,
		"scope_org_id":        ep.ScopeOrgID,
		"destination_scheme":  scheme,
		"destination_host":    host,
		"signed":              signed(ep),
		"enabled":             ep.Enabled,
		"event_types":         events,
		"rate_limit":          ep.RateLimit,
		"custom_header_names": names,
		"created_at":          stamp(ep.CreatedAt),
		"updated_at":          stamp(ep.UpdatedAt),
	}
}

// signed is whether deliveries to ep are signed: the same test relay's
// signer makes before it signs.
func signed(ep *endpoint.Endpoint) bool { return strings.TrimSpace(ep.Secret) != "" }

// destination reduces a webhook URL to its scheme and host. The host is
// lowercased, with the port only when it isn't the scheme's default. The
// path, query, fragment and userinfo are dropped, since webhook URLs often
// carry a token there. A scheme other than http or https reads "other",
// and a URL that won't parse gives two empty strings.
func destination(raw string) (scheme, host string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return "", ""
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		scheme = "other"
	}
	host = strings.ToLower(u.Hostname())
	if host == "" {
		return scheme, ""
	}
	port := u.Port()
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		if strings.Contains(host, ":") {
			return scheme, "[" + host + "]"
		}
		return scheme, host
	}
	return scheme, net.JoinHostPort(host, port)
}

// collectPosture counts every tenant's endpoints. It sends counts only: no
// tenant IDs and no hosts, so it is safe in the staff-only scope.
func (a *Adapter) collectPosture(ctx context.Context) (map[string]any, error) {
	var total, enabled, unsigned, notHTTPS int
	tenants := map[string]bool{}
	err := a.eachEndpoint(ctx, "", map[string]bool{}, func(ep *endpoint.Endpoint) error {
		total++
		if ep.Enabled {
			enabled++
		}
		if !signed(ep) {
			unsigned++
		}
		if scheme, _ := destination(ep.URL); scheme != "https" {
			notHTTPS++
		}
		tenants[ep.TenantID] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"endpoints":              total,
		"enabled":                enabled,
		"unsigned":               unsigned,
		"not_https":              notHTTPS,
		"tenants_with_endpoints": len(tenants),
	}, nil
}

func (a *Adapter) collectEventTypes(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	seen := map[string]bool{}
	for off := 0; ; off += pageSize {
		page, err := a.cat.ListTypes(ctx, catalog.ListOpts{Offset: off, Limit: pageSize, IncludeDeprecated: true})
		if err != nil {
			return nil, fmt.Errorf("witness/relay: list event types: %w", err)
		}
		fresh := 0
		for _, et := range page {
			if et == nil || et.Definition.Name == "" || seen[et.Definition.Name] {
				continue
			}
			seen[et.Definition.Name] = true
			fresh++
			if len(out) >= maxItems {
				return nil, fmt.Errorf("%w: more than %d event types", ErrTooMany, maxItems)
			}
			out = append(out, eventTypeItem(et))
		}
		if len(page) < pageSize {
			return out, nil
		}
		if fresh == 0 {
			return nil, errStuck
		}
	}
}

// eventTypeItem maps an event type's fields one by one. The schema goes as
// a hash, so a change shows up without the schema itself; the example
// payload and metadata stay out.
func eventTypeItem(et *catalog.EventType) map[string]any {
	d := et.Definition
	var deprecatedAt, schemaSum any
	if et.DeprecatedAt != nil {
		deprecatedAt = stamp(*et.DeprecatedAt)
	}
	if len(bytes.TrimSpace(d.Schema)) > 0 {
		schemaSum = schemaHash(d.Schema)
	}
	return map[string]any{
		"id":             d.Name,
		"name":           d.Name,
		"group":          d.Group,
		"version":        d.Version,
		"schema_version": d.SchemaVersion,
		"description":    d.Description,
		"deprecated":     et.IsDeprecated,
		"deprecated_at":  deprecatedAt,
		"scope_app_id":   et.ScopeAppID,
		"schema_sha256":  schemaSum,
	}
}

// schemaHash is the hex SHA-256 of the schema with insignificant
// whitespace removed, so formatting alone doesn't change it.
func schemaHash(schema json.RawMessage) string {
	var buf bytes.Buffer
	b := []byte(schema)
	if json.Compact(&buf, schema) == nil {
		b = buf.Bytes()
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// stamp is t in UTC to the second. Stores keep different precisions, so
// whole seconds keep a row's hash steady across them.
func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }
