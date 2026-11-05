package authsome

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xraph/authsome/apikey"
	"github.com/xraph/authsome/id"
	"github.com/xraph/authsome/organization"
	"github.com/xraph/authsome/page"
	"github.com/xraph/authsome/session"
	"github.com/xraph/authsome/store"
	"github.com/xraph/authsome/user"

	"github.com/hallproof/witness/collect"
)

func (a *Adapter) staffUsers() collect.Population {
	return collect.Population{
		Key:         "authsome.staff-users",
		Title:       "Staff accounts",
		Description: "Every staff account in the platform app, with its platform roles, organisation roles and second factors. Staff means " + a.staffRule() + ".",
		Source:      "staff-users",
		Tests:       []string{"no-shared-accounts", "no-active-leavers", "mfa-enforced", "privileged-reviewed", "review-signed-off"},
		Every:       every,
		Collect:     a.collectStaffUsers,
	}
}

func (a *Adapter) collectStaffUsers(ctx context.Context) ([]map[string]any, error) {
	st, err := a.staff(ctx)
	if err != nil {
		return nil, err
	}
	privileged := slices.Concat(a.scope.Roles(), privilegedRoles)
	mp := a.mfaPlugin()
	now := a.now()
	items := make([]map[string]any, 0, len(st.users))
	for _, uid := range st.users {
		u := st.records[uid.String()]
		if u == nil {
			u, err = a.eng.Store().GetUser(ctx, uid)
			if errors.Is(err, store.ErrNotFound) {
				continue // a role held by a user who no longer exists
			}
			if err != nil {
				return nil, fmt.Errorf("witness/authsome: read a staff user: %w", err)
			}
		}
		item, err := a.staffUser(ctx, st.app, u, privileged, now)
		if err != nil {
			return nil, err
		}
		if mp != nil {
			totp, err := mp.Enrolled(ctx, uid)
			if err != nil {
				return nil, fmt.Errorf("witness/authsome: read MFA enrolment: %w", err)
			}
			item["mfa_totp"] = totp
			item["mfa_any"] = totp || mp.HasMFA(ctx, uid)
		}
		items = append(items, item)
	}
	return items, nil
}

func (a *Adapter) staffUser(ctx context.Context, app id.AppID, u *user.User, privileged []string, now time.Time) (map[string]any, error) {
	roles, err := a.eng.ListUserRolesInApp(ctx, app, u.ID)
	if err != nil {
		return nil, fmt.Errorf("witness/authsome: read a staff user's roles: %w", err)
	}
	slugs := make([]string, 0, len(roles))
	isPrivileged := false
	for _, r := range roles {
		if !slices.Contains(slugs, r.Slug) {
			slugs = append(slugs, r.Slug)
		}
		isPrivileged = isPrivileged || slices.Contains(privileged, r.Slug)
	}
	slices.Sort(slugs)

	orgRoles, err := a.orgRoles(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	sessions, err := a.sessions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	live := 0
	var lastSeen time.Time
	for _, s := range sessions {
		if isLive(s, now) {
			live++
		}
		seen := s.LastActivityAt
		if seen.IsZero() {
			seen = s.CreatedAt
		}
		if seen.After(lastSeen) {
			lastSeen = seen
		}
	}
	return map[string]any{
		"id":                  u.ID.String(),
		"app_id":              optID(u.AppID),
		"env_id":              optID(u.EnvID),
		"email":               u.Email,
		"email_verified":      u.EmailVerified,
		"name":                u.Name(),
		"username":            optString(u.Username),
		"banned":              u.Banned,
		"ban_expires":         stampPtr(u.BanExpires),
		"deleted_at":          stampPtr(u.DeletedAt),
		"created_at":          stamp(u.CreatedAt),
		"password_changed_at": stampPtr(u.PasswordChangedAt),
		"platform_roles":      slugs,
		"privileged":          isPrivileged,
		"org_roles":           orgRoles,
		"mfa_plugin":          a.mfaPlugin() != nil,
		"mfa_totp":            false,
		"mfa_any":             false,
		"active_sessions":     live,
		"last_seen_on":        day(lastSeen),
	}, nil
}

// orgRoles are a user's organisation memberships, sorted by org ID.
func (a *Adapter) orgRoles(ctx context.Context, uid id.UserID) ([]map[string]any, error) {
	orgs, err := pages(func(cursor string) ([]*organization.Organization, string, error) {
		p, err := a.eng.Store().ListUserOrganizationsPage(ctx, uid, page.Opts{Limit: pageSize, Cursor: cursor})
		if err != nil {
			return nil, "", fmt.Errorf("witness/authsome: list a staff user's organisations: %w", err)
		}
		return p.Items, p.NextCursor, nil
	})
	if err != nil {
		return nil, err
	}
	type orgRole struct{ org, role string }
	held := make([]orgRole, 0, len(orgs))
	for _, o := range orgs {
		m, err := a.eng.Store().GetMemberByUserAndOrg(ctx, uid, o.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("witness/authsome: read a staff user's membership: %w", err)
		}
		held = append(held, orgRole{o.ID.String(), string(m.Role)})
	}
	slices.SortFunc(held, func(x, y orgRole) int { return strings.Compare(x.org, y.org) })
	out := make([]map[string]any, 0, len(held))
	for _, h := range held {
		out = append(out, map[string]any{"org_id": h.org, "role": h.role})
	}
	return out, nil
}

// sessions are every session a user holds, live or not.
func (a *Adapter) sessions(ctx context.Context, uid id.UserID) ([]*session.Session, error) {
	return pages(func(cursor string) ([]*session.Session, string, error) {
		p, err := a.eng.Store().ListUserSessionsPage(ctx, uid, page.Opts{Limit: pageSize, Cursor: cursor})
		if err != nil {
			return nil, "", fmt.Errorf("witness/authsome: list a staff user's sessions: %w", err)
		}
		return p.Items, p.NextCursor, nil
	})
}

// isLive reports whether s can still be used, directly or by refreshing.
func isLive(s *session.Session, now time.Time) bool {
	return s.ExpiresAt.After(now) || s.RefreshTokenExpiresAt.After(now)
}

func (a *Adapter) staffSessions() collect.Population {
	return collect.Population{
		Key:         "authsome.staff-sessions",
		Title:       "Staff sessions",
		Description: a.scoped("Every live session held by a staff account, so access that outlives a leaver shows up."),
		Source:      "staff-sessions",
		Tests:       []string{"no-active-leavers"},
		Every:       every,
		Collect:     a.collectStaffSessions,
	}
}

func (a *Adapter) collectStaffSessions(ctx context.Context) ([]map[string]any, error) {
	st, err := a.staff(ctx)
	if err != nil {
		return nil, err
	}
	now := a.now()
	var items []map[string]any
	for _, uid := range st.users {
		sessions, err := a.sessions(ctx, uid)
		if err != nil {
			return nil, err
		}
		for _, s := range sessions {
			if !isLive(s, now) {
				continue
			}
			kind := string(s.PrincipalKind)
			if kind == "" {
				kind = string(session.PrincipalKindUser)
			}
			items = append(items, map[string]any{
				"id":                 s.ID.String(),
				"user_id":            optID(s.UserID),
				"app_id":             optID(s.AppID),
				"org_id":             optID(s.OrgID),
				"principal_kind":     kind,
				"agent_id":           optID(s.AgentID),
				"grant_id":           optID(s.GrantID),
				"service_account_id": optID(s.ServiceAccountID),
				"created_at":         stamp(s.CreatedAt),
				"expires_at":         stamp(s.ExpiresAt),
				"refresh_expires_at": stamp(s.RefreshTokenExpiresAt),
				"last_active_on":     day(s.LastActivityAt),
			})
		}
		if err := bounded("staff sessions", items); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (a *Adapter) staffAPIKeys() collect.Population {
	return collect.Population{
		Key:         "authsome.staff-api-keys",
		Title:       "Staff API keys (Authsome)",
		Description: a.scoped("Authsome API keys owned by staff accounts or by the platform's service accounts."),
		Source:      "staff-api-keys",
		Tests:       []string{"keys-rotated", "no-active-leavers"},
		Every:       every,
		Collect:     a.collectStaffAPIKeys,
	}
}

func (a *Adapter) collectStaffAPIKeys(ctx context.Context) ([]map[string]any, error) {
	st, err := a.staff(ctx)
	if err != nil {
		return nil, err
	}
	var keys []*apikey.APIKey
	for _, uid := range st.users {
		mine, kerr := a.eng.APIKeyStore().ListAPIKeysByUser(ctx, st.app, uid)
		if kerr != nil {
			return nil, fmt.Errorf("witness/authsome: list a staff user's API keys: %w", kerr)
		}
		keys = append(keys, mine...)
		if berr := bounded("staff API keys", keys); berr != nil {
			return nil, berr
		}
	}
	// Service account keys live in Authsome's own store even when user keys
	// go to Keysmith, and there is no read by service account.
	accounts, err := a.scopedServiceAccounts(ctx, st)
	if err != nil {
		return nil, err
	}
	if len(accounts) > 0 {
		inScope := make(map[string]bool, len(accounts))
		for _, s := range accounts {
			inScope[s.ID.String()] = true
		}
		all, err := a.eng.Store().ListAPIKeysByApp(ctx, st.app)
		if err != nil {
			return nil, fmt.Errorf("witness/authsome: list API keys: %w", err)
		}
		for _, k := range all {
			if !k.ServiceAccountID.IsNil() && inScope[k.ServiceAccountID.String()] {
				keys = append(keys, k)
			}
		}
	}
	seen := map[string]bool{}
	items := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		if seen[k.ID.String()] {
			continue
		}
		seen[k.ID.String()] = true
		items = append(items, map[string]any{
			"id":                 k.ID.String(),
			"app_id":             optID(k.AppID),
			"env_id":             optID(k.EnvID),
			"user_id":            optID(k.UserID),
			"service_account_id": optID(k.ServiceAccountID),
			"name":               k.Name,
			"scopes":             sorted(k.Scopes),
			"created_at":         stamp(k.CreatedAt),
			"expires_at":         stampPtr(k.ExpiresAt),
			"revoked":            k.Revoked,
			"last_used_on":       dayPtr(k.LastUsedAt),
		})
	}
	return items, bounded("staff API keys", items)
}
