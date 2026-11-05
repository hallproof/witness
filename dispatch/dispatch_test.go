package dispatch

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	dsp "github.com/xraph/dispatch"
	"github.com/xraph/dispatch/cron"
	"github.com/xraph/dispatch/engine"
	"github.com/xraph/dispatch/id"
	"github.com/xraph/dispatch/job"
	"github.com/xraph/dispatch/resource"
	"github.com/xraph/dispatch/store/memory"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/ingesttest"
)

const (
	staffOrg = "org-staff"
	customer = "org-customer"
)

// now is the clock every test adapter reads.
var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return now.Add(-d) }

type fixture struct {
	eng *engine.Engine
	st  *memory.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memory.New()
	d, err := dsp.New(dsp.WithStore(st))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.Build(d)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{eng: eng, st: st}
}

func (f *fixture) addCron(t *testing.T, e *cron.Entry) *cron.Entry {
	t.Helper()
	e.ID = id.NewCronID()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
		e.UpdatedAt = e.CreatedAt
	}
	if err := f.st.RegisterCron(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	return e
}

// addJob stores a finished job. Add jobs oldest first: dispatch lists by ID,
// and IDs sort by when they were minted.
func (f *fixture) addJob(t *testing.T, j *job.Job) *job.Job {
	t.Helper()
	j.ID = id.NewJobID()
	if j.State == "" {
		j.State = job.StateCompleted
	}
	if j.UpdatedAt.IsZero() {
		switch {
		case j.CompletedAt != nil:
			j.UpdatedAt = *j.CompletedAt
		default:
			j.UpdatedAt = j.CreatedAt.Add(time.Minute)
		}
	}
	if err := f.st.EnqueueJob(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	return j
}

// done returns a completed job created at c that finished a minute later.
func done(name string, c time.Time) *job.Job {
	fin := c.Add(time.Minute)
	return &job.Job{Name: name, State: job.StateCompleted, Entity: dsp.Entity{CreatedAt: c}, CompletedAt: &fin}
}

// failed returns a failed job created at c. Dispatch leaves CompletedAt
// empty on failure, and the store sets UpdatedAt.
func failed(name string, c time.Time) *job.Job {
	return &job.Job{Name: name, State: job.StateFailed, Entity: dsp.Entity{CreatedAt: c, UpdatedAt: c.Add(2 * time.Minute)}}
}

func (f *fixture) adapter(opts ...Option) *Adapter {
	a := New(f.eng, opts...)
	a.now = func() time.Time { return now }
	return a
}

type collectors struct {
	pops   map[string]collect.Population
	proofs map[string]collect.EventProof
}

func collectorsOf(t *testing.T, a *Adapter) collectors {
	t.Helper()
	pops, proofs, err := a.collectors()
	if err != nil {
		t.Fatal(err)
	}
	c := collectors{pops: map[string]collect.Population{}, proofs: map[string]collect.EventProof{}}
	for _, p := range pops {
		c.pops[p.Key] = p
	}
	for _, e := range proofs {
		c.proofs[e.Key] = e
	}
	return c
}

func run(t *testing.T, a *Adapter, key string) []map[string]any {
	t.Helper()
	p, ok := collectorsOf(t, a).pops[key]
	if !ok {
		t.Fatalf("%s is not registered", key)
	}
	items, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func byID(items []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, it := range items {
		out[it["id"].(string)] = it
	}
	return out
}

func ids(items []map[string]any) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it["id"].(string))
	}
	return out
}

func newWitness(t *testing.T) *witness.Witness {
	t.Helper()
	s := ingesttest.New(t)
	w, err := witness.New(witness.Options{Endpoint: s.URL, IngestKey: s.Key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// taken reports whether a collector key is already registered on w.
func taken(t *testing.T, w *witness.Witness, key string) bool {
	t.Helper()
	err := w.Population(collect.Population{Key: key, Title: "probe", Collect: func(context.Context) ([]map[string]any, error) { return nil, nil }})
	return err != nil && strings.Contains(err.Error(), "already used")
}

func TestRegistered(t *testing.T) {
	for _, a := range adapter.Adapters() {
		if a.Name != Name {
			continue
		}
		if a.Module != Module || !slices.Equal(a.After, []string{"dispatch"}) || a.Chain || a.Attach == nil {
			t.Fatalf("registered adapter = %+v", a)
		}
		return
	}
	t.Fatal("dispatch adapter is not registered")
}

func TestAttachSkipsMissingEngine(t *testing.T) {
	for name, c := range map[string]any{"nil": nil, "empty vessel": vessel.New(), "not a vessel": struct{}{}} {
		t.Run(name, func(t *testing.T) {
			found, err := attach(context.Background(), adapter.Host{Witness: newWitness(t), Container: c})
			if found || err != nil {
				t.Fatalf("attach = %v, %v; want false, nil", found, err)
			}
		})
	}
}

func TestAttachRegistersFromConfig(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{
		Witness:   w,
		Container: c,
		Config:    map[string]any{"backup_jobs": []any{"db.backup"}, "event_proofs": true},
	})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for _, k := range []string{KeyScheduledJobs, KeyJobRuns, KeyBackupRuns, KeyScheduleChanges} {
		if !taken(t, w, k) {
			t.Errorf("%s was not registered", k)
		}
	}
}

func TestAttachDefaults(t *testing.T) {
	f := newFixture(t)
	c := vessel.New()
	if err := vessel.ProvideValue(c, f.eng); err != nil {
		t.Fatal(err)
	}
	w := newWitness(t)
	found, err := attach(context.Background(), adapter.Host{Witness: w, Container: c})
	if !found || err != nil {
		t.Fatalf("attach = %v, %v; want true, nil", found, err)
	}
	for k, want := range map[string]bool{KeyScheduledJobs: true, KeyJobRuns: true, KeyBackupRuns: false, KeyScheduleChanges: false} {
		if got := taken(t, w, k); got != want {
			t.Errorf("%s registered = %v, want %v", k, got, want)
		}
	}
}

func TestRegisterNeedsEngine(t *testing.T) {
	if err := New(nil).Register(newWitness(t)); err == nil {
		t.Fatal("Register with no engine succeeded")
	}
}

func TestScheduledJobs(t *testing.T) {
	f := newFixture(t)
	nightly := f.addCron(t, &cron.Entry{Name: "nightly-backup", Schedule: "0 3 * * *", JobName: "db.backup", Queue: "ops", ScopeAppID: "app-platform", Enabled: true})
	weekday := f.addCron(t, &cron.Entry{Name: "weekday-report", Schedule: "0 9 * * 1-5", JobName: "report", Enabled: false})
	every := f.addCron(t, &cron.Entry{Name: "tick", Schedule: "@every 90s", JobName: "tick", Enabled: true})

	items := run(t, f.adapter(), KeyScheduledJobs)
	assertJSON(t, items, []map[string]any{
		{
			"id": "nightly-backup", "cron_id": nightly.ID.String(), "schedule": "0 3 * * *", "job_name": "db.backup",
			"queue": "ops", "enabled": true, "scope_app_id": "app-platform", "scope_org_id": "",
			"created_at": "2026-10-01T08:00:00Z", "expected_every_seconds": 86400,
		},
		{
			"id": "tick", "cron_id": every.ID.String(), "schedule": "@every 90s", "job_name": "tick",
			"queue": "", "enabled": true, "scope_app_id": "", "scope_org_id": "",
			"created_at": "2026-10-01T08:00:00Z", "expected_every_seconds": 90,
		},
		{
			"id": "weekday-report", "cron_id": weekday.ID.String(), "schedule": "0 9 * * 1-5", "job_name": "report",
			"queue": "", "enabled": false, "scope_app_id": "", "scope_org_id": "",
			"created_at": "2026-10-01T08:00:00Z",
		},
	})
}

func TestScheduledJobsAreStable(t *testing.T) {
	f := newFixture(t)
	e := f.addCron(t, &cron.Entry{Name: "weekday-report", Schedule: "0 9 * * 1-5", JobName: "report", Enabled: true})
	a := f.adapter()
	first := run(t, a, KeyScheduledJobs)
	// A fire moves LastRunAt, NextRunAt, the lock and UpdatedAt, and the
	// clock moves on. None of that is configuration.
	fired := ago(time.Minute)
	next := now.Add(24 * time.Hour)
	e.LastRunAt, e.NextRunAt, e.LockedUntil = &fired, &next, &next
	e.LockedBy = id.NewWorkerID().String()
	e.UpdatedAt = now
	a.now = func() time.Time { return now.Add(3 * 24 * time.Hour) }
	assertJSON(t, run(t, a, KeyScheduledJobs), first)
}

func TestJobRuns(t *testing.T) {
	f := newFixture(t)
	fired := ago(2 * time.Hour)
	f.addCron(t, &cron.Entry{Name: "nightly-backup", Schedule: "0 3 * * *", JobName: "db.backup", Enabled: true, LastRunAt: &fired})
	f.addCron(t, &cron.Entry{Name: "idle", Schedule: "0 4 * * *", JobName: "never.ran", Enabled: true})

	f.addJob(t, done("db.backup", ago(50*time.Hour)))
	f.addJob(t, failed("db.backup", ago(30*time.Hour)))
	f.addJob(t, done("db.backup", ago(26*time.Hour)))
	lastFail := f.addJob(t, failed("db.backup", ago(10*time.Hour)))
	f.addJob(t, done("db.backup", ago(5*time.Hour)))
	lastOK := f.addJob(t, done("db.backup", ago(3*time.Hour)))
	// Same prefix, other job: never counted.
	f.addJob(t, done("db.backup.verify", ago(time.Hour)))
	f.addJob(t, failed("db.backup.verify", ago(time.Hour)))
	// Not finished: never counted.
	f.addJob(t, &job.Job{Name: "db.backup", State: job.StateRunning, Entity: dsp.Entity{CreatedAt: ago(30 * time.Minute)}})
	f.addJob(t, &job.Job{Name: "db.backup", State: job.StateRetrying, Entity: dsp.Entity{CreatedAt: ago(20 * time.Minute)}})

	items := run(t, f.adapter(), KeyJobRuns)
	assertJSON(t, items, []map[string]any{
		{"id": "idle", "job_name": "never.ran", "schedule": "0 4 * * *", "enabled": true, "scope_org_id": "",
			"succeeded_24h": 0, "failed_24h": 0, "window_truncated": false, "expected_every_seconds": 86400},
		{
			"id": "nightly-backup", "job_name": "db.backup", "schedule": "0 3 * * *", "enabled": true, "scope_org_id": "",
			"last_fired_at":     "2026-11-05T10:00:00Z",
			"last_succeeded_at": "2026-11-05T09:01:00Z", "last_succeeded_job_id": lastOK.ID.String(),
			"last_failed_at": "2026-11-05T02:02:00Z", "last_failed_job_id": lastFail.ID.String(),
			"succeeded_24h": 2, "failed_24h": 1, "window_truncated": false, "expected_every_seconds": 86400,
		},
	})
}

func TestJobRunsFindLastResultsBeforeTheWindow(t *testing.T) {
	f := newFixture(t)
	f.addCron(t, &cron.Entry{Name: "weekly-backup", Schedule: "0 3 * * 0", JobName: "db.backup", Enabled: true})
	old := f.addJob(t, failed("db.backup", ago(20*24*time.Hour)))
	ok := f.addJob(t, done("db.backup", ago(3*24*time.Hour)))
	for i := range 5 {
		f.addJob(t, done("other", ago(time.Duration(10-i)*time.Hour)))
	}

	it := byID(run(t, f.adapter(), KeyJobRuns))["weekly-backup"]
	if it["last_succeeded_job_id"] != ok.ID.String() || it["last_failed_job_id"] != old.ID.String() {
		t.Fatalf("item = %v", it)
	}
	if it["succeeded_24h"] != 0 || it["failed_24h"] != 0 || it["window_truncated"] != false {
		t.Fatalf("item = %v", it)
	}
}

func TestBackupRuns(t *testing.T) {
	f := newFixture(t)
	f.addCron(t, &cron.Entry{Name: "nightly-backup", Schedule: "0 3 * * *", JobName: "db.backup", Enabled: true})
	f.addCron(t, &cron.Entry{Name: "archive", Schedule: "0 5 * * *", JobName: "archive.run", Enabled: true})
	f.addCron(t, &cron.Entry{Name: "report", Schedule: "0 6 * * *", JobName: "report", Enabled: true})
	ok := f.addJob(t, done("db.backup", ago(3*time.Hour)))
	f.addJob(t, done("archive.run", ago(2*time.Hour)))
	f.addJob(t, done("report", ago(time.Hour)))
	manual := f.addJob(t, done("offsite.copy", ago(4*time.Hour)))

	// db.backup names a job, archive names a cron entry, offsite.copy has
	// no schedule and missing.backup has never run.
	a := f.adapter(WithBackupJobs("db.backup", "archive", "offsite.copy", "missing.backup", " "))
	p := collectorsOf(t, a).pops[KeyBackupRuns]
	if !slices.Equal(p.Tests, []string{"backup-recent"}) || p.Source != "backup-job-runs" {
		t.Fatalf("collector = %+v", p)
	}
	items := run(t, a, KeyBackupRuns)
	if got := ids(items); !slices.Equal(got, []string{"archive", "missing.backup", "nightly-backup", "offsite.copy"}) {
		t.Fatalf("ids = %v", got)
	}
	m := byID(items)
	if m["nightly-backup"]["last_succeeded_job_id"] != ok.ID.String() || m["nightly-backup"]["succeeded_24h"] != 1 {
		t.Fatalf("nightly-backup = %v", m["nightly-backup"])
	}
	assertJSON(t, m["offsite.copy"], map[string]any{
		"id": "offsite.copy", "job_name": "offsite.copy", "scope_org_id": "",
		"last_succeeded_at": "2026-11-05T08:01:00Z", "last_succeeded_job_id": manual.ID.String(),
		"succeeded_24h": 1, "failed_24h": 0, "window_truncated": false,
	})
	assertJSON(t, m["missing.backup"], map[string]any{
		"id": "missing.backup", "job_name": "missing.backup", "scope_org_id": "",
		"succeeded_24h": 0, "failed_24h": 0, "window_truncated": false,
	})
}

func TestNoBackupJobsNoBackupCollector(t *testing.T) {
	f := newFixture(t)
	if _, ok := collectorsOf(t, f.adapter(WithBackupJobs(" ", ""))).pops[KeyBackupRuns]; ok {
		t.Fatal("backup-runs registered with no backup job names")
	}
}

func TestStaffScope(t *testing.T) {
	f := newFixture(t)
	f.addCron(t, &cron.Entry{Name: "nightly-backup", Schedule: "0 3 * * *", JobName: "db.backup", Enabled: true})
	f.addCron(t, &cron.Entry{Name: "staff-org-sync", Schedule: "0 * * * *", JobName: "sync", ScopeOrgID: staffOrg, Enabled: true})
	f.addCron(t, &cron.Entry{Name: "customer-export", Schedule: "0 1 * * *", JobName: "export", ScopeOrgID: customer, Enabled: true})

	f.addJob(t, done("db.backup", ago(5*time.Hour)))
	cust := done("db.backup", ago(4*time.Hour))
	cust.ScopeOrgID, cust.ScopeAppID = customer, "app-customer"
	f.addJob(t, cust)
	custFail := failed("db.backup", ago(3*time.Hour))
	custFail.ScopeOrgID = customer
	f.addJob(t, custFail)
	staffJob := done("db.backup", ago(2*time.Hour))
	staffJob.ScopeOrgID = staffOrg
	f.addJob(t, staffJob)

	t.Run("default", func(t *testing.T) {
		a := f.adapter(WithBackupJobs("db.backup"))
		if got := ids(run(t, a, KeyScheduledJobs)); !slices.Equal(got, []string{"nightly-backup"}) {
			t.Fatalf("scheduled ids = %v", got)
		}
		for _, k := range []string{KeyJobRuns, KeyBackupRuns} {
			items := run(t, a, k)
			if got := ids(items); !slices.Equal(got, []string{"nightly-backup"}) {
				t.Fatalf("%s ids = %v", k, got)
			}
			it := items[0]
			if it["succeeded_24h"] != 1 || it["failed_24h"] != 0 {
				t.Fatalf("%s counted a customer run: %v", k, it)
			}
		}
	})

	t.Run("staff orgs", func(t *testing.T) {
		a := f.adapter(WithStaffOrgs(staffOrg))
		if got := ids(run(t, a, KeyScheduledJobs)); !slices.Equal(got, []string{"nightly-backup", "staff-org-sync"}) {
			t.Fatalf("scheduled ids = %v", got)
		}
		m := byID(run(t, a, KeyJobRuns))
		if len(m) != 3 || m["nightly-backup"]["succeeded_24h"] != 1 || m["nightly-backup@"+staffOrg]["succeeded_24h"] != 1 {
			t.Fatalf("job runs = %v", m)
		}
		if m["nightly-backup@"+staffOrg]["scope_org_id"] != staffOrg {
			t.Fatalf("job runs = %v", m)
		}
	})

	t.Run("all tenants", func(t *testing.T) {
		a := f.adapter(WithAllTenants())
		if got := ids(run(t, a, KeyScheduledJobs)); !slices.Equal(got, []string{"customer-export", "nightly-backup", "staff-org-sync"}) {
			t.Fatalf("scheduled ids = %v", got)
		}
		m := byID(run(t, a, KeyJobRuns))
		c := m["nightly-backup@"+customer]
		if c == nil || c["succeeded_24h"] != 1 || c["failed_24h"] != 1 || c["scope_org_id"] != customer {
			t.Fatalf("job runs = %v", m)
		}
		if m["nightly-backup"]["succeeded_24h"] != 1 || m["nightly-backup"]["failed_24h"] != 0 {
			t.Fatalf("customer runs leaked into the staff item: %v", m["nightly-backup"])
		}
	})
}

func TestPages(t *testing.T) {
	defer func(n int) { pageSize = n }(pageSize)
	pageSize = 2
	f := newFixture(t)
	f.addCron(t, &cron.Entry{Name: "hourly", Schedule: "0 * * * *", JobName: "h", Enabled: true})
	for i := range 7 {
		f.addJob(t, done("h", ago(time.Duration(10-i)*time.Hour)))
	}
	for i := range 3 {
		f.addJob(t, failed("h", ago(time.Duration(9-i)*time.Hour)))
	}
	it := run(t, f.adapter(), KeyJobRuns)[0]
	if it["succeeded_24h"] != 7 || it["failed_24h"] != 3 || it["window_truncated"] != false {
		t.Fatalf("item = %v", it)
	}
}

func TestScanBudget(t *testing.T) {
	defer func(n int) { pageSize = n }(pageSize)
	pageSize = 2
	f := newFixture(t)
	f.addCron(t, &cron.Entry{Name: "hourly", Schedule: "0 * * * *", JobName: "h", Enabled: true})
	for i := range 7 {
		f.addJob(t, done("h", ago(time.Duration(10-i)*time.Hour)))
	}
	it := run(t, f.adapter(WithScanBudget(3)), KeyJobRuns)[0]
	if it["succeeded_24h"] != 3 || it["window_truncated"] != true || it["last_succeeded_at"] != "2026-11-05T08:01:00Z" {
		t.Fatalf("item = %v", it)
	}
}

func TestTooManyFailsTheRun(t *testing.T) {
	defer func(n int) { maxItems = n }(maxItems)
	maxItems = 1
	f := newFixture(t)
	f.addCron(t, &cron.Entry{Name: "a", Schedule: "0 * * * *", JobName: "a", Enabled: true})
	f.addCron(t, &cron.Entry{Name: "b", Schedule: "0 * * * *", JobName: "b", Enabled: true})
	for k, p := range collectorsOf(t, f.adapter(WithBackupJobs("a", "b"))).pops {
		if _, err := p.Collect(context.Background()); !errors.Is(err, ErrTooMany) {
			t.Errorf("%s: err = %v, want ErrTooMany", k, err)
		}
	}
}

type failingLister struct{}

func (failingLister) ListJobs(context.Context, job.ListJobsOpts) (job.Page, error) {
	return job.Page{}, errors.New("boom")
}

func TestListErrorFailsTheRun(t *testing.T) {
	f := newFixture(t)
	f.addCron(t, &cron.Entry{Name: "a", Schedule: "0 * * * *", JobName: "a", Enabled: true})
	a := f.adapter()
	a.jobs = failingLister{}
	if _, err := collectorsOf(t, a).pops[KeyJobRuns].Collect(context.Background()); err == nil {
		t.Fatal("a failing list did not fail the run")
	}
}

func TestEventProofs(t *testing.T) {
	f := newFixture(t)
	if c := collectorsOf(t, f.adapter()); len(c.proofs) != 0 {
		t.Fatalf("event proofs on by default: %v", c.proofs)
	}
	e, ok := collectorsOf(t, f.adapter(WithEventProofs())).proofs[KeyScheduleChanges]
	if !ok || e.Stream != adapter.Platform || !slices.Equal(e.Actions, DefaultProofActions) {
		t.Fatalf("proof = %+v", e)
	}
	e = collectorsOf(t, f.adapter(WithEventProofs("ops.cron_changed"))).proofs[KeyScheduleChanges]
	if !slices.Equal(e.Actions, []string{"ops.cron_changed"}) {
		t.Fatalf("actions = %v", e.Actions)
	}
}

func TestNeverSendsContent(t *testing.T) {
	const canary = "CANARY-5d1c"
	f := newFixture(t)
	worker := id.NewWorkerID()
	later := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	f.addCron(t, &cron.Entry{
		Name: "nightly-backup", Schedule: "0 3 * * *", JobName: "db.backup", Enabled: true,
		Payload:   []byte(`{"secret":"` + canary + `-cron-payload"}`),
		LockedBy:  canary + "-locked-by",
		NextRunAt: &later, LockedUntil: &later,
		Entity: dsp.Entity{CreatedAt: now.Add(-time.Hour), UpdatedAt: later},
	})
	for _, j := range []*job.Job{done("db.backup", ago(3*time.Hour)), failed("db.backup", ago(2*time.Hour))} {
		j.Payload = []byte(`{"secret":"` + canary + `-job-payload"}`)
		j.LastError = canary + "-last-error"
		j.PrimaryInputHash = canary + "-input-hash"
		j.ArtifactBindings = []byte(canary + "-bindings")
		j.ResourceClass = canary + "-class"
		j.Resources = resource.Set{canary + "-res": 1}
		j.ResourceLimits = resource.Set{canary + "-limit": 1}
		j.InputBytes = 4242424242
		j.WorkerID = worker
		j.HeartbeatAt, j.LeaseExpiresAt = &later, &later
		f.addJob(t, j)
	}

	c := collectorsOf(t, f.adapter(WithBackupJobs("db.backup"), WithEventProofs(), WithAllTenants()))
	out := make([]any, 0, len(c.pops)+len(c.proofs))
	for _, k := range []string{KeyScheduledJobs, KeyJobRuns, KeyBackupRuns} {
		p, ok := c.pops[k]
		if !ok {
			t.Fatalf("%s is not registered", k)
		}
		got, err := p.Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			t.Fatalf("%s collected nothing", k)
		}
		out = append(out, got)
	}
	for _, e := range c.proofs {
		out = append(out, e)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{canary, worker.String(), "4242424242", "2031-01-02"} {
		if strings.Contains(string(raw), bad) {
			t.Fatalf("output holds %q: %s", bad, raw)
		}
	}
}

func assertJSON(t *testing.T, got, want any) {
	t.Helper()
	norm := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var x any
		if uerr := json.Unmarshal(raw, &x); uerr != nil {
			t.Fatal(uerr)
		}
		out, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	if g, w := norm(got), norm(want); g != w {
		t.Fatalf("got  %s\nwant %s", g, w)
	}
}
