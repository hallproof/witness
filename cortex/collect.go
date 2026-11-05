package cortex

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"time"

	cx "github.com/xraph/cortex"
	"github.com/xraph/cortex/agent"
	"github.com/xraph/cortex/checkpoint"
	"github.com/xraph/cortex/engine"
	"github.com/xraph/cortex/persona"
	"github.com/xraph/cortex/run"

	"github.com/hallproof/witness/push"
)

// pageSize is how many rows each list call asks for.
const pageSize = 500

// maxItems is the most rows a collector reads in scope before it fails the
// run. A variable so tests can lower it.
var maxItems = push.MaxItems

// rootOf is the configured scope that covers s, false when none does.
func (a *Adapter) rootOf(s cx.Scope) (cx.Scope, bool) {
	for _, root := range a.scopes {
		if root.Covers(s) {
			return root, true
		}
	}
	return cx.Scope{}, false
}

// inScope checks a row's scope again after the store's own filter, so a
// store that ignores the scope can't widen it.
func (a *Adapter) inScope(s cx.Scope) bool {
	_, ok := a.rootOf(s)
	return ok
}

// each pages through list under every configured scope and calls fn once
// per row in scope. It skips a row seen before (offset paging can repeat a
// row when rows are created mid-scan, and nested scopes overlap), and fails
// with ErrTooMany past maxItems rows. what names the rows in errors.
func each[T any](ctx context.Context, a *Adapter, what string,
	list func(ctx context.Context, limit, offset int) ([]T, error),
	key func(T) (string, cx.Scope),
	fn func(T) error,
) error {
	seen := map[string]bool{}
	for _, s := range a.scopes {
		sctx := cx.WithScope(ctx, s)
		for off := 0; ; off += pageSize {
			page, err := list(sctx, pageSize, off)
			if err != nil {
				return fmt.Errorf("witness/cortex: list %s: %w", what, err)
			}
			for _, row := range page {
				rid, rs := key(row)
				if !a.inScope(rs) || seen[rid] {
					continue
				}
				seen[rid] = true
				if len(seen) > maxItems {
					return fmt.Errorf("%w: more than %d %s", ErrTooMany, maxItems, what)
				}
				if err := fn(row); err != nil {
					return err
				}
			}
			if len(page) < pageSize {
				break
			}
		}
	}
	return nil
}

func (a *Adapter) collectAgents(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := each(ctx, a, "agents",
		func(ctx context.Context, limit, offset int) ([]*agent.Config, error) {
			return a.eng.ListAgents(ctx, &agent.ListFilter{Limit: limit, Offset: offset})
		},
		func(c *agent.Config) (string, cx.Scope) { return c.ID.String(), c.Scope },
		func(c *agent.Config) error {
			last, err := a.lastRun(ctx, c)
			if err != nil {
				return err
			}
			owner, principal := a.owner(c)
			out = append(out, map[string]any{
				"id":               c.ID.String(),
				"name":             c.Name,
				"scope":            c.Scope.Canonical(),
				"enabled":          c.Enabled,
				"model":            c.Model,
				"reasoning_loop":   c.ReasoningLoop,
				"max_steps":        c.MaxSteps,
				"tools":            sorted(c.Tools),
				"persona_ref":      c.PersonaRef,
				"inline_skills":    sorted(c.InlineSkills),
				"inline_traits":    sorted(c.InlineTraits),
				"inline_behaviors": sorted(c.InlineBehaviors),
				"guardrail_keys":   keys(c.Guardrails),
				"owner_id":         owner,
				"principal_id":     principal,
				"created_at":       stamp(c.CreatedAt),
				"updated_at":       stamp(c.UpdatedAt),
				// A day, not a time: an agent runs all day, and a
				// timestamp would make every run new evidence.
				"last_run_on": last,
			})
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// lastRun is the UTC day c's newest run was created, nil when it has none.
// The stores list runs newest first. It reads under the configured scope
// that holds c, not c's own, because a run can sit at a different level of
// the tree than its agent.
func (a *Adapter) lastRun(ctx context.Context, c *agent.Config) (any, error) {
	root, ok := a.rootOf(c.Scope)
	if !ok {
		return nil, nil
	}
	runs, err := a.eng.ListRuns(cx.WithScope(ctx, root), &run.ListFilter{AgentID: c.ID.String(), Limit: 1})
	if err != nil {
		return nil, fmt.Errorf("witness/cortex: list an agent's runs: %w", err)
	}
	if len(runs) == 0 || runs[0].AgentID != c.ID || !a.inScope(runs[0].Scope) {
		return nil, nil
	}
	return runs[0].CreatedAt.UTC().Format(time.DateOnly), nil
}

// owner is c's owner and principal ID: from the host's Owner func when
// set, else from the metadata keys, as strings only. Absent is "", so
// Hallproof sees an agent with no owner rather than a missing field.
func (a *Adapter) owner(c *agent.Config) (ownerID, principalID string) {
	if a.o.Owner != nil {
		return a.o.Owner(c)
	}
	return metaString(c.Metadata, a.ownerKey), metaString(c.Metadata, a.prinKey)
}

// metaString is m[k] when it is a string, else "".
func metaString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func (a *Adapter) collectPersonas(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := each(ctx, a, "personas",
		func(ctx context.Context, limit, offset int) ([]*persona.Persona, error) {
			return a.eng.ListPersonas(ctx, &persona.ListFilter{Limit: limit, Offset: offset})
		},
		func(p *persona.Persona) (string, cx.Scope) { return p.ID.String(), p.Scope },
		func(p *persona.Persona) error {
			skills := make([]string, 0, len(p.Skills))
			for _, s := range p.Skills {
				skills = append(skills, s.SkillName)
			}
			traits := make([]string, 0, len(p.Traits))
			for _, t := range p.Traits {
				traits = append(traits, t.TraitName)
			}
			out = append(out, map[string]any{
				"id":         p.ID.String(),
				"name":       p.Name,
				"scope":      p.Scope.Canonical(),
				"skills":     sorted(skills),
				"traits":     sorted(traits),
				"behaviors":  sorted(p.Behaviors),
				"created_at": stamp(p.CreatedAt),
				"updated_at": stamp(p.UpdatedAt),
			})
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Adapter) collectPending(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := each(ctx, a, "pending checkpoints",
		func(ctx context.Context, limit, offset int) ([]*checkpoint.Checkpoint, error) {
			return a.eng.ListPendingCheckpoints(ctx, &checkpoint.ListFilter{Limit: limit, Offset: offset})
		},
		func(cp *checkpoint.Checkpoint) (string, cx.Scope) { return cp.ID.String(), cp.Scope },
		func(cp *checkpoint.Checkpoint) error {
			out = append(out, map[string]any{
				"id":         cp.ID.String(),
				"run_id":     cp.RunID.String(),
				"agent_id":   cp.AgentID.String(),
				"scope":      cp.Scope.Canonical(),
				"state":      cp.State,
				"step_index": cp.StepIndex,
				"created_at": stamp(cp.CreatedAt),
			})
			return nil
		})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Adapter) collectTools(context.Context) (map[string]any, error) {
	infos := a.eng.Tools()
	slices.SortStableFunc(infos, func(x, y engine.ToolInfo) int { return cmp.Compare(x.Def.Name, y.Def.Name) })
	tools := make([]map[string]any, 0, len(infos))
	for _, t := range infos {
		it := map[string]any{
			"name":       t.Def.Name,
			"kind":       string(t.Kind),
			"retry_safe": t.RetrySafe,
		}
		if a.o.RiskClass != nil {
			it["risk"] = a.o.RiskClass(t.Def.Name)
		}
		tools = append(tools, it)
	}
	return map[string]any{
		"has_tool_authorizer": a.eng.HasToolAuthorizer(),
		"tools":               tools,
	}, nil
}

// sorted is a sorted copy of s, never nil, so an empty list goes as [].
func sorted(s []string) []string {
	out := make([]string, 0, len(s))
	out = append(out, s...)
	slices.Sort(out)
	return out
}

// keys is m's keys, sorted. The values are never read.
func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// stamp is t in UTC to the second. Stores keep different precisions, so
// whole seconds keep a row's hash steady across them.
func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }
