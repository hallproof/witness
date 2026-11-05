package dispatch

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/xraph/dispatch/cron"
	"github.com/xraph/dispatch/job"

	"github.com/hallproof/witness/push"
)

// pageSize is how many jobs each list call asks for. Dispatch loads whole
// rows, payloads included, so pages stay small. A variable so tests can
// lower it.
var pageSize = 200

// maxItems is the most items a collector returns before it fails the run.
// A variable so tests can lower it.
var maxItems = push.MaxItems

// callTimeout bounds each job list call. Dispatch's name filter uses no
// index, so one call can walk a large table.
const callTimeout = 30 * time.Second

// everyAnchor and everySamples fix where expected_every_seconds is measured
// from: the same eight fires on every run, so the value never changes with
// the clock and a schedule's evidence only changes when the schedule does.
// The anchor is a Monday in UTC.
var everyAnchor = time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)

const everySamples = 8

func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// expectedEvery returns the fixed gap between a schedule's fires in
// seconds, or false when the gap varies (weekdays only, monthly, a minute
// step that doesn't divide the hour) or the schedule doesn't parse.
func expectedEvery(schedule string) (int64, bool) {
	fires, _, err := cron.NextFires(schedule, everyAnchor, everySamples)
	if err != nil || len(fires) < 2 {
		return 0, false
	}
	gap := fires[1].Sub(fires[0])
	for i := 2; i < len(fires); i++ {
		if fires[i].Sub(fires[i-1]) != gap {
			return 0, false
		}
	}
	if gap <= 0 {
		return 0, false
	}
	return int64(gap / time.Second), true
}

// staff reports whether a row's app and org scope is staff: no app or the
// platform's own app (AppID), and no org or one of StaffOrgs. Authsome
// gives a session with no org an app-only scope, and a background worker
// can enqueue a customer's job with no org at all, so an empty org alone
// isn't enough.
func (a *Adapter) staff(app, org string) bool {
	return (app == "" || app == a.appID) && (org == "" || a.staffOrg[org])
}

// inScope reports whether rows of an app and org are collected.
func (a *Adapter) inScope(app, org string) bool { return a.o.AllTenants || a.staff(app, org) }

// group is the key a row's runs are counted under: the org for staff rows
// ("" for no org) and for customer orgs, and "app:<app ID>" (plus "/<org>"
// when there is one) for another app's rows that have no org of their own
// or reuse a staff org, so they never land in a staff item.
func (a *Adapter) group(app, org string) string {
	if a.staff(app, org) || (org != "" && !a.staffOrg[org]) {
		return org
	}
	if org == "" {
		return "app:" + app
	}
	return "app:" + app + "/" + org
}

func entryName(e *cron.Entry) string {
	if e.Name != "" {
		return e.Name
	}
	return e.ID.String()
}

// entries returns the cron entries in scope, sorted by name. Dispatch lists
// every entry with no scope filter, so the adapter filters here.
func (a *Adapter) entries(ctx context.Context) ([]*cron.Entry, error) {
	all, err := a.crons.ListCrons(ctx)
	if err != nil {
		return nil, fmt.Errorf("witness/dispatch: list cron entries: %w", err)
	}
	out := make([]*cron.Entry, 0, len(all))
	for _, e := range all {
		if e != nil && a.inScope(e.ScopeAppID, e.ScopeOrgID) {
			out = append(out, e)
		}
	}
	if len(out) > maxItems {
		return nil, fmt.Errorf("%w: more than %d cron entries", ErrTooMany, maxItems)
	}
	sort.Slice(out, func(i, j int) bool { return entryName(out[i]) < entryName(out[j]) })
	return out, nil
}

func (a *Adapter) collectScheduled(ctx context.Context) ([]map[string]any, error) {
	entries, err := a.entries(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		it := map[string]any{
			"id":           entryName(e),
			"cron_id":      e.ID.String(),
			"schedule":     e.Schedule,
			"job_name":     e.JobName,
			"queue":        e.Queue,
			"enabled":      e.Enabled,
			"scope_app_id": e.ScopeAppID,
			"scope_org_id": e.ScopeOrgID,
			"created_at":   stamp(e.CreatedAt),
		}
		if s, ok := expectedEvery(e.Schedule); ok {
			it["expected_every_seconds"] = s
		}
		out = append(out, it)
	}
	return out, nil
}

func (a *Adapter) collectRuns(ctx context.Context) ([]map[string]any, error) {
	entries, err := a.entries(ctx)
	if err != nil {
		return nil, err
	}
	return a.runItems(ctx, entries, nil)
}

// collectBackups reports the entries whose name or job name is a backup
// name, and every backup name that matches no entry in scope, so a backup
// job with no schedule, or one that never ran, still shows up.
func (a *Adapter) collectBackups(ctx context.Context) ([]map[string]any, error) {
	entries, err := a.entries(ctx)
	if err != nil {
		return nil, err
	}
	var picked []*cron.Entry
	matched := map[string]bool{}
	for _, e := range entries {
		if slices.Contains(a.backups, e.Name) || slices.Contains(a.backups, e.JobName) {
			picked = append(picked, e)
			matched[e.Name], matched[e.JobName] = true, true
		}
	}
	var loose []string
	for _, n := range a.backups {
		if !matched[n] {
			loose = append(loose, n)
		}
	}
	return a.runItems(ctx, picked, loose)
}

// runItems builds one item per entry and per loose job name, plus one per
// other org or app that ran the job when the scope is wider than staff. It reads
// each job name once.
func (a *Adapter) runItems(ctx context.Context, entries []*cron.Entry, loose []string) ([]map[string]any, error) {
	scans := map[string]*scanResult{}
	scanOf := func(name string) (*scanResult, error) {
		if r, ok := scans[name]; ok {
			return r, nil
		}
		r, err := a.scan(ctx, name)
		if err != nil {
			return nil, err
		}
		scans[name] = r
		return r, nil
	}
	var out []map[string]any
	add := func(items []map[string]any) error {
		out = append(out, items...)
		if len(out) > maxItems {
			return fmt.Errorf("%w: more than %d job run summaries", ErrTooMany, maxItems)
		}
		return nil
	}
	for _, e := range entries {
		r, err := scanOf(e.JobName)
		if err != nil {
			return nil, err
		}
		if err := add(r.items(entryName(e), e.JobName, e)); err != nil {
			return nil, err
		}
	}
	for _, n := range loose {
		r, err := scanOf(n)
		if err != nil {
			return nil, err
		}
		if err := add(r.items(n, n, nil)); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]["id"]) < fmt.Sprint(out[j]["id"]) })
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

// runStats are one group's finished runs of one job name.
type runStats struct {
	org            string
	okAt, failAt   time.Time
	okID, failID   string
	ok24, fail24   int
	okSeen, failed bool
}

// scanResult is what one scan of a job name found, by the group (see
// group) of the scope that enqueued each job.
type scanResult struct {
	byGroup   map[string]*runStats
	truncated bool
}

func (r *scanResult) group(key, org string) *runStats {
	s, ok := r.byGroup[key]
	if !ok {
		s = &runStats{org: org}
		r.byGroup[key] = s
	}
	return s
}

// finishedAt is when a job finished. Dispatch sets CompletedAt only on
// success, so a failed job's time is its last update.
func finishedAt(j *job.Job) time.Time {
	if j.CompletedAt != nil {
		return *j.CompletedAt
	}
	return j.UpdatedAt
}

func (s *runStats) add(j *job.Job, windowStart time.Time) {
	at := finishedAt(j)
	inWindow := !at.Before(windowStart)
	switch j.State {
	case job.StateCompleted:
		if !s.okSeen || at.After(s.okAt) {
			s.okAt, s.okID, s.okSeen = at, j.ID.String(), true
		}
		if inWindow {
			s.ok24++
		}
	case job.StateFailed:
		if !s.failed || at.After(s.failAt) {
			s.failAt, s.failID, s.failed = at, j.ID.String(), true
		}
		if inWindow {
			s.fail24++
		}
	}
}

// items turns a scan into run summaries: one for the unscoped staff runs,
// under id, and one per other group, under id@group. e is the cron entry,
// nil for a backup name with no entry.
func (r *scanResult) items(id, jobName string, e *cron.Entry) []map[string]any {
	keys := make([]string, 0, len(r.byGroup)+1)
	keys = append(keys, "")
	for k := range r.byGroup {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys[1:])
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		s := r.byGroup[key]
		if s == nil {
			s = &runStats{}
		}
		it := map[string]any{
			"id":               id,
			"job_name":         jobName,
			"scope_org_id":     s.org,
			"succeeded_24h":    s.ok24,
			"failed_24h":       s.fail24,
			"window_truncated": r.truncated,
		}
		if key != "" {
			it["id"] = id + "@" + key
		}
		if e != nil {
			it["schedule"] = e.Schedule
			it["enabled"] = e.Enabled
			if e.LastRunAt != nil {
				it["last_fired_at"] = stamp(*e.LastRunAt)
			}
			if every, ok := expectedEvery(e.Schedule); ok {
				it["expected_every_seconds"] = every
			}
		}
		if s.okSeen {
			it["last_succeeded_at"] = stamp(s.okAt)
			it["last_succeeded_job_id"] = s.okID
		}
		if s.failed {
			it["last_failed_at"] = stamp(s.failAt)
			it["last_failed_job_id"] = s.failID
		}
		out = append(out, it)
	}
	return out
}

// scan reads the finished runs of one job name, succeeded and failed
// separately, so a job that rarely fails doesn't hide its last success.
func (a *Adapter) scan(ctx context.Context, name string) (*scanResult, error) {
	r := &scanResult{byGroup: map[string]*runStats{}}
	windowStart := a.now().Add(-Window)
	for _, st := range []job.State{job.StateCompleted, job.StateFailed} {
		truncated, err := a.scanState(ctx, name, st, windowStart, r)
		if err != nil {
			return nil, err
		}
		r.truncated = r.truncated || truncated
	}
	return r, nil
}

// scanState pages through jobs of one name and state, newest first. It
// stops at the end of the list, or once it has read past the window and
// found the latest staff run of this state, or when ScanBudget rows are
// read, which it reports as truncated.
func (a *Adapter) scanState(ctx context.Context, name string, state job.State, windowStart time.Time, r *scanResult) (bool, error) {
	read := 0
	cursor := ""
	found := false
	for {
		limit := min(pageSize, a.o.ScanBudget-read)
		page, err := a.list(ctx, job.ListJobsOpts{
			States:     []job.State{state},
			NamePrefix: name,
			Cursor:     cursor,
			Limit:      limit,
		})
		if err != nil {
			return false, err
		}
		// An empty page still costs one, so a backend that returns empty
		// partial pages can't loop forever.
		read += max(len(page.Jobs), 1)
		past := false
		for _, j := range page.Jobs {
			if j == nil {
				continue
			}
			if j.CreatedAt.Before(windowStart) {
				past = true
			}
			// NamePrefix matches "backup.verify" for "backup", and dispatch
			// treats an empty org filter as every org, so both are checked
			// here.
			if j.Name != name || j.State != state || !a.inScope(j.ScopeAppID, j.ScopeOrgID) {
				continue
			}
			r.group(a.group(j.ScopeAppID, j.ScopeOrgID), j.ScopeOrgID).add(j, windowStart)
			found = found || a.staff(j.ScopeAppID, j.ScopeOrgID)
		}
		if page.NextCursor == "" || (past && found) {
			return false, nil
		}
		if read >= a.o.ScanBudget {
			return true, nil
		}
		cursor = page.NextCursor
	}
}

func (a *Adapter) list(ctx context.Context, opts job.ListJobsOpts) (job.Page, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	page, err := a.jobs.ListJobs(ctx, opts)
	if err != nil {
		return job.Page{}, fmt.Errorf("witness/dispatch: list jobs: %w", err)
	}
	return page, nil
}
