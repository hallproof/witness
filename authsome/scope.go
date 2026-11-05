package authsome

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/xraph/authsome/id"
	"github.com/xraph/authsome/user"
	"github.com/xraph/warden"
	wardenassign "github.com/xraph/warden/assignment"

	"github.com/hallproof/witness/push"
)

// pageSize is how many rows the adapter asks for at a time. 200 is the
// most Authsome's paged reads return.
var pageSize = 200

// maxItems is the most items one population may hold. A run that finds
// more fails rather than send a truncated list.
var maxItems = push.MaxItems

// roleNamespaces are the Warden namespaces Authsome keeps roles in, in the
// order Authsome's own GetRoleBySlug searches them.
var roleNamespaces = []string{"", "app", "platform"}

// privilegedRoles always count as privileged, whatever the staff roles are.
var privilegedRoles = []string{"platform-owner", "platform-admin", "super-admin"}

// staff is who counts as staff on one run.
type staff struct {
	app id.AppID
	// users are the staff user IDs, sorted.
	users []id.UserID
	set   map[string]bool
	// records holds the users already read, when the rule read them.
	records map[string]*user.User
}

func (s *staff) has(uid id.UserID) bool { return !uid.IsNil() && s.set[uid.String()] }

// allUsers reports whether every platform-app user is staff.
func (a *Adapter) allUsers() bool { return a.opts.AllPlatformUsers || a.scope.AllTenants }

// staffRule says, for logs and the package doc, who counts as staff.
func (a *Adapter) staffRule() string {
	if a.allUsers() {
		return "every platform-app user"
	}
	return "holds " + strings.Join(a.scope.Roles(), " or ")
}

// appID is the platform app: the scope's AppID when set, else the app
// Authsome bootstrapped, else the app the store marks as the platform.
func (a *Adapter) appID(ctx context.Context) (id.AppID, error) {
	if a.scope.AppID != "" {
		app, err := id.ParseAppID(a.scope.AppID)
		if err != nil {
			return id.AppID{}, fmt.Errorf("witness/authsome: scope app ID: %w", err)
		}
		return app, nil
	}
	if app := a.eng.PlatformAppID(); !app.IsNil() {
		return app, nil
	}
	app, err := a.eng.Store().GetPlatformApp(ctx)
	if err != nil {
		return id.AppID{}, fmt.Errorf("witness/authsome: find the platform app: %w", err)
	}
	return app.ID, nil
}

// staff works out who is staff this run.
func (a *Adapter) staff(ctx context.Context) (*staff, error) {
	app, err := a.appID(ctx)
	if err != nil {
		return nil, err
	}
	s := &staff{app: app, set: map[string]bool{}}
	if a.allUsers() {
		err = a.allPlatformUsers(ctx, s)
	} else {
		err = a.staffByRoles(ctx, s)
	}
	if err != nil {
		return nil, err
	}
	slices.SortFunc(s.users, func(x, y id.UserID) int { return strings.Compare(x.String(), y.String()) })
	return s, nil
}

func (s *staff) add(uid id.UserID) error {
	if uid.IsNil() || s.set[uid.String()] {
		return nil
	}
	s.set[uid.String()] = true
	s.users = append(s.users, uid)
	if len(s.users) > maxItems {
		return fmt.Errorf("witness/authsome: more than %d staff users", maxItems)
	}
	return nil
}

// allPlatformUsers reads every user of the platform app, page by page.
func (a *Adapter) allPlatformUsers(ctx context.Context, s *staff) error {
	s.records = map[string]*user.User{}
	users, err := pages(func(cursor string) ([]*user.User, string, error) {
		l, err := a.eng.Store().ListUsers(ctx, &user.Query{AppID: s.app, Cursor: cursor, Limit: pageSize})
		if err != nil {
			return nil, "", fmt.Errorf("witness/authsome: list users: %w", err)
		}
		return l.Users, l.NextCursor, nil
	})
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := s.add(u.ID); err != nil {
			return err
		}
		s.records[u.ID.String()] = u
	}
	return nil
}

// staffByRoles finds every user holding a staff role in the platform app.
// It reads Warden's assignments page by page: Authsome's ListUsersWithRole
// stops at Warden's default of 1000 rows without saying so.
func (a *Adapter) staffByRoles(ctx context.Context, s *staff) error {
	w := a.eng.Warden()
	if w == nil {
		return errors.New("witness/authsome: Authsome has no Warden engine, so staff can't be found by role")
	}
	now := a.now()
	for _, slug := range a.scope.Roles() {
		for _, ns := range roleNamespaces {
			r, err := w.Store().GetRoleBySlug(ctx, s.app.String(), ns, slug)
			if errors.Is(err, warden.ErrRoleNotFound) {
				continue
			}
			if err != nil {
				return fmt.Errorf("witness/authsome: role %q: %w", slug, err)
			}
			for offset := 0; ; {
				held, err := w.Store().ListAssignments(ctx, &wardenassign.ListFilter{
					TenantID:    s.app.String(),
					RoleID:      &r.ID,
					SubjectKind: "user",
					Limit:       pageSize,
					Offset:      offset,
				})
				if err != nil {
					return fmt.Errorf("witness/authsome: holders of %q: %w", slug, err)
				}
				for _, h := range held {
					if h.ExpiresAt != nil && !h.ExpiresAt.After(now) {
						continue
					}
					uid, err := id.ParseUserID(h.SubjectID)
					if err != nil {
						continue // not an Authsome user; Authsome skips these too
					}
					if err := s.add(uid); err != nil {
						return err
					}
				}
				// A store that ignores the limit has returned everything.
				if len(held) < pageSize || len(held) > pageSize {
					break
				}
				offset += len(held)
				if offset > maxItems {
					return fmt.Errorf("witness/authsome: more than %d holders of %q", maxItems, slug)
				}
			}
		}
	}
	return nil
}

// pages reads a cursor-paged list to the end. It fails, rather than loop
// or truncate, when a cursor repeats or the list outgrows a population.
func pages[T any](fetch func(cursor string) ([]T, string, error)) ([]T, error) {
	var all []T
	seen := map[string]bool{}
	cursor := ""
	for {
		items, next, err := fetch(cursor)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(all) > maxItems {
			return nil, fmt.Errorf("witness/authsome: more than %d rows", maxItems)
		}
		if next == "" {
			return all, nil
		}
		if seen[next] {
			return nil, errors.New("witness/authsome: a list's cursor repeated, so it would never end")
		}
		seen[next] = true
		cursor = next
	}
}

// bounded checks an unpaged list fits in a population.
func bounded[T any](what string, items []T) error {
	if len(items) > maxItems {
		return fmt.Errorf("witness/authsome: more than %d %s", maxItems, what)
	}
	return nil
}
