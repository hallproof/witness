package authsome

import (
	"context"
	"fmt"

	"github.com/xraph/authsome/id"
	"github.com/xraph/authsome/principal"
	"github.com/xraph/authsome/serviceaccount"

	"github.com/hallproof/witness/collect"
)

func (a *Adapter) serviceAccounts() collect.Population {
	return collect.Population{
		Key:         "authsome.service-accounts",
		Title:       "Service accounts",
		Description: "Every non-human principal in the platform app that staff own or that belongs to no organisation, with its kind, owner, scopes and expiry. Rows of kind agent are agent principals.",
		Source:      "service-accounts",
		Tests:       []string{"no-shared-accounts", "agent-has-owner", "agent-owner-active", "no-orphaned-agents"},
		Every:       every,
		Collect:     a.collectServiceAccounts,
	}
}

func (a *Adapter) collectServiceAccounts(ctx context.Context) ([]map[string]any, error) {
	st, err := a.staff(ctx)
	if err != nil {
		return nil, err
	}
	accounts, err := a.scopedServiceAccounts(ctx, st)
	if err != nil {
		return nil, err
	}
	items := make([]map[string]any, 0, len(accounts))
	for _, s := range accounts {
		items = append(items, map[string]any{
			"id":            s.ID.String(),
			"app_id":        optID(s.AppID),
			"org_id":        optID(s.OrgID),
			"env_id":        optID(s.EnvID),
			"kind":          string(kindOf(s)),
			"name":          s.Name,
			"scopes":        sorted(s.Scopes),
			"active":        s.Active,
			"owner_user_id": optID(s.OwnerUserID),
			"parent_id":     optID(s.ParentID),
			"expires_at":    stampPtr(s.ExpiresAt),
			"created_at":    stamp(s.CreatedAt),
			"updated_at":    stamp(s.UpdatedAt),
		})
	}
	return items, nil
}

// kindOf is a service account's principal kind. Rows from before the column
// existed read as a plain service account, as Authsome reads them.
func kindOf(s *serviceaccount.ServiceAccount) principal.Kind {
	if s.Kind == "" {
		return principal.KindService
	}
	return s.Kind
}

// scopedServiceAccounts are the platform app's service accounts that staff
// own or that belong to no organisation; every one of them under
// AllTenants.
func (a *Adapter) scopedServiceAccounts(ctx context.Context, st *staff) ([]*serviceaccount.ServiceAccount, error) {
	all, err := pages(func(cursor string) ([]*serviceaccount.ServiceAccount, string, error) {
		l, err := a.eng.Store().ListServiceAccounts(ctx, &serviceaccount.Query{AppID: st.app, Limit: pageSize, Cursor: cursor})
		if err != nil {
			return nil, "", fmt.Errorf("witness/authsome: list service accounts: %w", err)
		}
		return l.ServiceAccounts, l.NextCursor, nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]*serviceaccount.ServiceAccount, 0, len(all))
	seen := map[string]bool{}
	for _, s := range all {
		if seen[s.ID.String()] || s.AppID.String() != st.app.String() {
			continue
		}
		seen[s.ID.String()] = true
		if a.scope.AllTenants || st.has(s.OwnerUserID) || s.OrgID.IsNil() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (a *Adapter) agentGrants() collect.Population {
	desc := "Every grant a staff account has given an agent, from principal delegations"
	if a.agentauth() != nil {
		desc += " and from agentauth"
	}
	desc += ", with its scopes and expiry. Authsome records when a grant was last used, not which scopes were used, so grant-scopes-used is only partly supported."
	return collect.Population{
		Key:         "authsome.agent-grants",
		Title:       "Agent grants",
		Description: desc,
		Source:      "agent-grants",
		Tests:       []string{"grant-has-expiry", "grant-scopes-used", "agent-owner-active"},
		Every:       every,
		Collect:     a.collectAgentGrants,
	}
}

func (a *Adapter) collectAgentGrants(ctx context.Context) ([]map[string]any, error) {
	st, err := a.staff(ctx)
	if err != nil {
		return nil, err
	}
	var items []map[string]any
	seen := map[string]bool{}
	add := func(key string, item map[string]any) error {
		if seen[key] {
			return nil
		}
		seen[key] = true
		items = append(items, item)
		return bounded("agent grants", items)
	}

	if store := a.agentauth(); store != nil {
		for _, uid := range st.users {
			grants, gerr := store.ListGrantsByUser(ctx, uid)
			if gerr != nil {
				return nil, fmt.Errorf("witness/authsome: list a staff user's agent grants: %w", gerr)
			}
			for _, g := range grants {
				if !g.AppID.IsNil() && g.AppID.String() != st.app.String() {
					continue
				}
				if aerr := add(g.ID.String(), map[string]any{
					"id":              g.ID.String(),
					"source":          "agentauth",
					"app_id":          optID(g.AppID),
					"org_id":          optID(g.OrgID),
					"agent_id":        optID(g.AgentID),
					"user_id":         optID(g.UserID),
					"actor_kind":      string(principal.KindAgent),
					"actor_id":        optID(g.AgentID),
					"subject_kind":    string(principal.KindUser),
					"subject_id":      optID(g.UserID),
					"grant_kind":      string(principal.GrantDelegation),
					"scopes":          sorted(g.Scopes),
					"granted_by_kind": string(principal.KindUser),
					"granted_by":      optID(g.UserID),
					"expires_at":      stamp(g.ExpiresAt),
					"revoked_at":      stampPtr(g.RevokedAt),
					"created_at":      stamp(g.CreatedAt),
					"last_used_on":    dayPtr(g.LastUsedAt),
				}); aerr != nil {
					return nil, aerr
				}
			}
		}
	}

	// Delegations a staff user gave, and delegations held by a principal
	// in scope, whoever they act for.
	queries := make([]principal.DelegationQuery, 0, len(st.users))
	for _, uid := range st.users {
		subject := principal.UserRef(uid)
		queries = append(queries, principal.DelegationQuery{AppID: st.app, Subject: &subject})
	}
	accounts, err := a.scopedServiceAccounts(ctx, st)
	if err != nil {
		return nil, err
	}
	for _, s := range accounts {
		actor := principal.Ref{Kind: kindOf(s), ID: s.ID.String()}
		queries = append(queries, principal.DelegationQuery{AppID: st.app, Actor: &actor})
	}
	for i := range queries {
		ds, err := a.eng.Store().ListDelegations(ctx, &queries[i])
		if err != nil {
			return nil, fmt.Errorf("witness/authsome: list delegations: %w", err)
		}
		for _, d := range ds {
			if err := add(d.ID.String(), delegation(d)); err != nil {
				return nil, err
			}
		}
	}
	return items, nil
}

func delegation(d *principal.Delegation) map[string]any {
	item := map[string]any{
		"id":              d.ID.String(),
		"source":          "delegation",
		"app_id":          optID(d.AppID),
		"org_id":          optID(d.OrgID),
		"agent_id":        nil,
		"user_id":         nil,
		"actor_kind":      string(d.Actor.Kind),
		"actor_id":        optString(d.Actor.ID),
		"subject_kind":    string(d.Subject.Kind),
		"subject_id":      optString(d.Subject.ID),
		"grant_kind":      string(d.GrantKind),
		"scopes":          sorted(d.Scopes),
		"granted_by_kind": optString(string(d.GrantedBy.Kind)),
		"granted_by":      optString(d.GrantedBy.ID),
		"expires_at":      stampPtr(d.ExpiresAt),
		"revoked_at":      stampPtr(d.RevokedAt),
		"created_at":      stamp(d.CreatedAt),
		"last_used_on":    nil,
	}
	if d.Actor.Kind == principal.KindAgent {
		item["agent_id"] = optString(d.Actor.ID)
	}
	if d.Subject.Kind == principal.KindUser {
		item["user_id"] = optString(d.Subject.ID)
	}
	return item
}

func (a *Adapter) agents() collect.Population {
	return collect.Population{
		Key:         "authsome.agents",
		Title:       "Registered agents (agentauth)",
		Description: "Every agent registered with the platform app that staff registered or that belongs to no organisation, with its status and who registered it.",
		Source:      "agents",
		Tests:       []string{"agent-has-owner", "agent-owner-active", "no-orphaned-agents"},
		Every:       every,
		Collect:     a.collectAgents,
	}
}

func (a *Adapter) collectAgents(ctx context.Context) ([]map[string]any, error) {
	store := a.agentauth()
	if store == nil {
		return nil, nil
	}
	st, err := a.staff(ctx)
	if err != nil {
		return nil, err
	}
	all, err := store.ListAgents(ctx, st.app, id.OrgID{})
	if err != nil {
		return nil, fmt.Errorf("witness/authsome: list agents: %w", err)
	}
	items := make([]map[string]any, 0, len(all))
	for _, ag := range all {
		if !a.scope.AllTenants && !st.has(ag.CreatedBy) && !ag.OrgID.IsNil() {
			continue
		}
		items = append(items, map[string]any{
			"id":         ag.ID.String(),
			"app_id":     optID(ag.AppID),
			"org_id":     optID(ag.OrgID),
			"client_id":  ag.ClientID,
			"name":       ag.Name,
			"origin":     string(ag.Origin),
			"status":     string(ag.Status),
			"created_by": optID(ag.CreatedBy),
			"created_at": stamp(ag.CreatedAt),
			"updated_at": stamp(ag.UpdatedAt),
		})
	}
	return items, bounded("agents", items)
}
