package warden

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/dsl"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/permission"
	"github.com/xraph/warden/policy"
	"github.com/xraph/warden/relation"
	"github.com/xraph/warden/role"

	"github.com/hallproof/witness/push"
)

// pageSize is the Limit of every list call. Warden's SQL stores cap a zero
// Limit at 1000 rows without saying so, so the adapter always asks for a
// page and keeps going until a short one.
const pageSize = 1000

// pageAll calls fetch with a growing offset until a short page, dropping
// rows it has already seen (offset paging can repeat a row that shares a
// created_at with another). It fails, rather than truncate, once it holds
// more than limit rows, and when a full page brings nothing new, which
// would otherwise loop forever.
func pageAll[T any](ctx context.Context, limit int, fetch func(limit, offset int) ([]T, error), key func(T) string) ([]T, error) {
	var out []T
	seen := map[string]struct{}{}
	for offset := 0; ; offset += pageSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := fetch(pageSize, offset)
		if err != nil {
			return nil, err
		}
		added := 0
		for _, v := range page {
			k := key(v)
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, v)
			added++
		}
		if len(out) > limit {
			return nil, fmt.Errorf("witness/warden: more than %d rows; narrow the scope rather than send a truncated list", limit)
		}
		if len(page) < pageSize {
			return out, nil
		}
		if added == 0 {
			return nil, errors.New("witness/warden: the store returned a full page with no new rows; stopping")
		}
	}
}

// scopeTenants are the tenant IDs each list call filters on. An empty
// tenant ID lists every tenant.
func (a *Adapter) scopeTenants() []string {
	if a.opts.AllTenants {
		return []string{""}
	}
	return a.opts.Tenants
}

// listRoles reads every role in scope.
func (a *Adapter) listRoles(ctx context.Context) ([]*role.Role, error) {
	s := a.eng.Store()
	var out []*role.Role
	for _, tenant := range a.scopeTenants() {
		rows, err := pageAll(ctx, push.MaxItems-len(out), func(limit, offset int) ([]*role.Role, error) {
			return s.ListRoles(ctx, &role.ListFilter{TenantID: tenant, Limit: limit, Offset: offset})
		}, func(r *role.Role) string { return r.ID.String() })
		if err != nil {
			return nil, fmt.Errorf("list roles: %w", err)
		}
		out = append(out, rows...)
	}
	return out, nil
}

func (a *Adapter) collectRoles(ctx context.Context) ([]map[string]any, error) {
	roles, err := a.listRoles(ctx)
	if err != nil {
		return nil, err
	}
	perms, err := a.rolePermissions(ctx, roles)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		items = append(items, map[string]any{
			"id":             r.ID.String(),
			"tenant_id":      r.TenantID,
			"namespace_path": r.NamespacePath,
			"app_id":         r.AppID,
			"slug":           r.Slug,
			"name":           r.Name,
			"description":    r.Description,
			"parent_slug":    r.ParentSlug,
			"is_system":      r.IsSystem,
			"is_default":     r.IsDefault,
			"max_members":    r.MaxMembers,
			"permissions":    perms[r.ID.String()],
			"privileged":     slices.Contains(a.opts.Privileged, r.Slug),
			"created_at":     stamp(r.CreatedAt),
			"updated_at":     stamp(r.UpdatedAt),
		})
	}
	return items, nil
}

// rolePermissions returns each role's directly granted permission names,
// sorted, by role ID. It asks once per tenant per page of roles.
func (a *Adapter) rolePermissions(ctx context.Context, roles []*role.Role) (map[string][]string, error) {
	byTenant := map[string][]id.RoleID{}
	var tenants []string
	for _, r := range roles {
		if _, ok := byTenant[r.TenantID]; !ok {
			tenants = append(tenants, r.TenantID)
		}
		byTenant[r.TenantID] = append(byTenant[r.TenantID], r.ID)
	}
	out := make(map[string][]string, len(roles))
	s := a.eng.Store()
	for _, tenant := range tenants {
		for chunk := range slices.Chunk(byTenant[tenant], pageSize) {
			grants, err := s.ListRolePermissionsForRoles(ctx, tenant, chunk)
			if err != nil {
				return nil, fmt.Errorf("list role permissions: %w", err)
			}
			for rid, ps := range grants {
				out[rid.String()] = permissionNames(ps)
			}
		}
	}
	for _, r := range roles {
		if out[r.ID.String()] == nil {
			out[r.ID.String()] = []string{}
		}
	}
	return out, nil
}

// permissionNames returns ps's names, sorted and without repeats. A
// permission outside the tenant root is named namespace/name.
func permissionNames(ps []*permission.Permission) []string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		n := p.Name
		if p.NamespacePath != "" {
			n = p.NamespacePath + "/" + p.Name
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return slices.Compact(names)
}

func (a *Adapter) collectAssignments(ctx context.Context) ([]map[string]any, error) {
	roles, err := a.listRoles(ctx)
	if err != nil {
		return nil, err
	}
	slugs := make(map[string]string, len(roles))
	for _, r := range roles {
		slugs[r.ID.String()] = r.Slug
	}
	rows, err := a.listAssignments(ctx, roles)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		slug := slugs[x.RoleID.String()]
		if slices.Contains(a.opts.ExcludeRoleSlugs, slug) {
			continue
		}
		items = append(items, map[string]any{
			"id":             x.ID.String(),
			"tenant_id":      x.TenantID,
			"namespace_path": x.NamespacePath,
			"role_id":        x.RoleID.String(),
			"role_slug":      slug,
			"subject_kind":   x.SubjectKind,
			"subject_id":     x.SubjectID,
			"resource_type":  x.ResourceType,
			"resource_id":    x.ResourceID,
			"expires_at":     stampPtr(x.ExpiresAt),
			"granted_by":     x.GrantedBy,
			"created_at":     stamp(x.CreatedAt),
			"privileged":     slices.Contains(a.opts.Privileged, slug),
		})
	}
	return items, nil
}

// listAssignments reads the assignments in scope. With roles to exclude,
// it reads only the other roles' assignments, one role at a time, so the
// default role every customer holds is never read at all.
func (a *Adapter) listAssignments(ctx context.Context, roles []*role.Role) ([]*assignment.Assignment, error) {
	s := a.eng.Store()
	key := func(x *assignment.Assignment) string { return x.ID.String() }
	var out []*assignment.Assignment
	read := func(f assignment.ListFilter) error {
		rows, err := pageAll(ctx, push.MaxItems-len(out), func(limit, offset int) ([]*assignment.Assignment, error) {
			f.Limit, f.Offset = limit, offset
			return s.ListAssignments(ctx, &f)
		}, key)
		if err != nil {
			return fmt.Errorf("list assignments: %w", err)
		}
		out = append(out, rows...)
		return nil
	}
	if len(a.opts.ExcludeRoleSlugs) == 0 {
		for _, tenant := range a.scopeTenants() {
			if err := read(assignment.ListFilter{TenantID: tenant}); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	for _, r := range roles {
		if slices.Contains(a.opts.ExcludeRoleSlugs, r.Slug) {
			continue
		}
		if err := read(assignment.ListFilter{TenantID: r.TenantID, RoleID: &r.ID}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (a *Adapter) collectPolicies(ctx context.Context) ([]map[string]any, error) {
	s := a.eng.Store()
	var rows []*policy.Policy
	for _, tenant := range a.scopeTenants() {
		page, err := pageAll(ctx, push.MaxItems-len(rows), func(limit, offset int) ([]*policy.Policy, error) {
			return s.ListPolicies(ctx, &policy.ListFilter{TenantID: tenant, Limit: limit, Offset: offset})
		}, func(p *policy.Policy) string { return p.ID.String() })
		if err != nil {
			return nil, fmt.Errorf("list policies: %w", err)
		}
		rows = append(rows, page...)
	}
	items := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		hash, err := conditionsHash(p.Conditions)
		if err != nil {
			return nil, err
		}
		items = append(items, map[string]any{
			"id":              p.ID.String(),
			"tenant_id":       p.TenantID,
			"namespace_path":  p.NamespacePath,
			"name":            p.Name,
			"description":     p.Description,
			"effect":          string(p.Effect),
			"priority":        p.Priority,
			"is_active":       p.IsActive,
			"not_before":      stampPtr(p.NotBefore),
			"not_after":       stampPtr(p.NotAfter),
			"version":         p.Version,
			"subjects":        subjects(p.Subjects),
			"actions":         orEmpty(p.Actions),
			"resources":       orEmpty(p.Resources),
			"obligations":     orEmpty(p.Obligations),
			"conditions":      conditions(p.Conditions),
			"conditions_hash": hash,
			"created_at":      stamp(p.CreatedAt),
			"updated_at":      stamp(p.UpdatedAt),
		})
	}
	return items, nil
}

func subjects(in []policy.SubjectMatch) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, s := range in {
		out = append(out, map[string]any{"kind": s.Kind, "id": s.ID, "role": s.Role})
	}
	return out
}

// conditions returns each condition's field and operator. Values stay
// home: they can hold IP ranges, emails or attribute values.
func conditions(in []policy.Condition) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, c := range in {
		out = append(out, map[string]any{"field": c.Field, "operator": string(c.Operator)})
	}
	return out
}

// conditionsHash is the SHA-256 of the conditions' canonical JSON, values
// included, so a changed value shows without being sent. Condition IDs are
// left out: they change when a policy is rewritten with the same rules.
func conditionsHash(in []policy.Condition) (string, error) {
	type cond struct {
		Field    string `json:"field"`
		Operator string `json:"operator"`
		Value    any    `json:"value"`
	}
	cs := make([]cond, 0, len(in))
	for _, c := range in {
		cs = append(cs, cond{Field: c.Field, Operator: string(c.Operator), Value: c.Value})
	}
	raw, err := json.Marshal(cs)
	if err != nil {
		return "", fmt.Errorf("witness/warden: hash policy conditions: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (a *Adapter) collectRelations(ctx context.Context) ([]map[string]any, error) {
	s := a.eng.Store()
	tenants := a.scopeTenants()
	var total int64
	for _, tenant := range tenants {
		n, err := s.CountRelations(ctx, &relation.ListFilter{TenantID: tenant})
		if err != nil {
			return nil, fmt.Errorf("count relations: %w", err)
		}
		total += n
	}
	if total > int64(a.opts.MaxRelations) {
		return nil, fmt.Errorf("witness/warden: %d relation tuples in scope, more than max_relations %d; narrow the tenants rather than send a truncated list", total, a.opts.MaxRelations)
	}
	var rows []*relation.Tuple
	for _, tenant := range tenants {
		page, err := pageAll(ctx, a.opts.MaxRelations-len(rows), func(limit, offset int) ([]*relation.Tuple, error) {
			return s.ListRelations(ctx, &relation.ListFilter{TenantID: tenant, Limit: limit, Offset: offset})
		}, func(t *relation.Tuple) string { return t.ID.String() })
		if err != nil {
			return nil, fmt.Errorf("list relations: %w", err)
		}
		rows = append(rows, page...)
	}
	items := make([]map[string]any, 0, len(rows))
	for _, t := range rows {
		items = append(items, map[string]any{
			"id":               t.ID.String(),
			"tenant_id":        t.TenantID,
			"namespace_path":   t.NamespacePath,
			"object_type":      t.ObjectType,
			"object_id":        t.ObjectID,
			"relation":         t.Relation,
			"subject_type":     t.SubjectType,
			"subject_id":       t.SubjectID,
			"subject_relation": t.SubjectRelation,
			"created_at":       stamp(t.CreatedAt),
		})
	}
	return items, nil
}

// collectModel fingerprints each staff tenant's model: Warden's own
// canonical .warden rendering of what is in force, without relation tuples
// (they are data, not model). Only the hash and counts leave the app; the
// text carries policy condition values.
func (a *Adapter) collectModel(ctx context.Context) (map[string]any, error) {
	tenants := make([]map[string]any, 0, len(a.opts.Tenants))
	for _, tenant := range a.opts.Tenants {
		prog, err := dsl.BuildProgram(ctx, a.eng, dsl.ExportOptions{TenantID: tenant})
		if err != nil {
			return nil, fmt.Errorf("witness/warden: read the model of tenant %q: %w", tenant, err)
		}
		prog.Relations = nil
		sum := sha256.Sum256(dsl.FormatBytes(prog))
		tenants = append(tenants, map[string]any{
			"tenant_id":      tenant,
			"model_sha256":   hex.EncodeToString(sum[:]),
			"resource_types": len(prog.ResourceTypes),
			"permissions":    len(prog.Permissions),
			"roles":          len(prog.Roles),
			"policies":       len(prog.Policies),
		})
	}
	return map[string]any{"tenants": tenants}, nil
}

// stamp formats t in UTC, so the same instant always reads the same.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func stampPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return stamp(*t)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
