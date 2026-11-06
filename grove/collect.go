package grove

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xraph/grove/migrate"
)

// applied is one row of a database's migration table, with its time
// normalised.
type applied struct {
	seq                      int64
	group, version, name, at string
}

// read is one database's migration table.
type read struct {
	label, driver string
	rows          []applied
}

// readAll reads every database's migration table with the driver's own
// executor. ListApplied is a plain SELECT: the adapter never creates the
// table, takes the migration lock or writes anything.
func (a *Adapter) readAll(ctx context.Context) ([]read, error) {
	out := make([]read, 0, len(a.dbs))
	for _, d := range a.dbs {
		drv := d.db.Driver()
		if drv == nil {
			return nil, fmt.Errorf("witness/grove: database %q has no driver", d.label)
		}
		ex, err := migrate.NewExecutorFor(drv)
		if err != nil {
			return nil, fmt.Errorf("witness/grove: database %q: %w", d.label, err)
		}
		list, err := ex.ListApplied(ctx)
		if err != nil {
			return nil, fmt.Errorf("witness/grove: database %q: list applied migrations: %w", d.label, err)
		}
		r := read{label: d.label, driver: drv.Name(), rows: make([]applied, 0, len(list))}
		for _, m := range list {
			if m == nil {
				continue
			}
			at, err := appliedAt(m.MigratedAt)
			if err != nil {
				return nil, fmt.Errorf("witness/grove: database %q: migration %s/%s: %w", d.label, m.Group, m.Version, err)
			}
			r.rows = append(r.rows, applied{seq: m.ID, group: m.Group, version: m.Version, name: m.Name, at: at})
		}
		sort.SliceStable(r.rows, func(i, j int) bool { return r.rows[i].seq < r.rows[j].seq })
		out = append(out, r)
	}
	return out, nil
}

func (a *Adapter) collectMigrations(ctx context.Context) ([]map[string]any, error) {
	reads, err := a.readAll(ctx)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, r := range reads {
		n += len(r.rows)
	}
	items := make([]map[string]any, 0, n)
	for _, r := range reads {
		for _, m := range r.rows {
			items = append(items, map[string]any{
				"id":         r.label + "/" + m.group + "/" + m.version,
				"database":   r.label,
				"group":      m.group,
				"version":    m.version,
				"name":       m.name,
				"applied_at": m.at,
				"seq":        m.seq,
			})
		}
	}
	return items, nil
}

func (a *Adapter) collectStatus(ctx context.Context) (map[string]any, error) {
	reads, err := a.readAll(ctx)
	if err != nil {
		return nil, err
	}
	dbs := make(map[string]any, len(reads))
	for _, r := range reads {
		groups := map[string]any{}
		counts := map[string]int{}
		var latest *applied
		for i := range r.rows {
			m := &r.rows[i]
			counts[m.group]++
			if latest == nil || m.at > latest.at || (m.at == latest.at && m.seq > latest.seq) {
				latest = m
			}
		}
		for g, n := range counts {
			groups[g] = n
		}
		db := map[string]any{"driver": r.driver, "applied": len(r.rows), "groups": groups}
		if latest != nil {
			db["latest_applied"] = map[string]any{
				"group": latest.group, "version": latest.version, "name": latest.name, "applied_at": latest.at,
			}
		}
		dbs[r.label] = db
	}
	// The migration table only knows what ran, so pending migrations (those
	// registered in code but not applied) are not reported. See the package
	// doc.
	return map[string]any{"databases": dbs, "pending_reported": false}, nil
}

// timeLayouts are the forms grove's drivers give MigratedAt in. Go accepts a
// fractional second after the seconds field even when a layout doesn't show
// one.
var timeLayouts = []struct {
	layout string
	zone   bool // false: the text has no zone and is UTC
}{
	{time.RFC3339, true},                    // Mongo, and RFC 3339 generally
	{"2006-01-02 15:04:05Z07:00:00", true},  // Postgres ::text, offset with seconds
	{"2006-01-02 15:04:05Z07:00", true},     // Postgres ::text, offset with minutes
	{"2006-01-02 15:04:05Z07", true},        // Postgres ::text, "+00"
	{"2006-01-02 15:04:05 -0700 MST", true}, // time.Time.String
	{"2006-01-02 15:04:05", false},          // SQLite, Turso, MySQL, ClickHouse
	{"2006-01-02T15:04:05", false},
}

// appliedAt normalises a driver's MigratedAt text to RFC 3339 in UTC, to the
// second. Text with no zone is UTC: SQLite's DATETIME('now') is, and grove's
// MySQL and ClickHouse tables store the server clock without a zone, which
// this assumes is UTC.
func appliedAt(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("no applied time")
	}
	for _, l := range timeLayouts {
		var (
			t   time.Time
			err error
		)
		if l.zone {
			t, err = time.Parse(l.layout, s)
		} else {
			t, err = time.ParseInLocation(l.layout, s, time.UTC)
		}
		if err == nil {
			return t.UTC().Truncate(time.Second).Format(time.RFC3339), nil
		}
	}
	return "", errors.New("applied time is in a form the adapter doesn't know")
}
