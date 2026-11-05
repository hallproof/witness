package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/xraph/dispatch/cron"
	"github.com/xraph/dispatch/engine"
	"github.com/xraph/dispatch/job"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "dispatch"

// Module is the library this adapter reads.
const Module = "github.com/xraph/dispatch"

// Collector keys.
const (
	KeyScheduledJobs   = "dispatch.scheduled-jobs"
	KeyJobRuns         = "dispatch.job-runs"
	KeyBackupRuns      = "dispatch.backup-runs"
	KeyScheduleChanges = "dispatch.schedule-changes"
)

// DefaultScanBudget is how many job rows the run collectors read, at most,
// for one job name and one outcome (succeeded or failed) in one run.
const DefaultScanBudget = 5000

// Window is how far back the run collectors count succeeded and failed
// runs.
const Window = 24 * time.Hour

// DefaultProofActions are the audit actions the schedule change proof cites
// when you turn event proofs on without naming any. Dispatch's audit_hook
// extension records them when an operator changes a cron entry.
var DefaultProofActions = []string{
	"operator.cron_enabled",
	"operator.cron_disabled",
	"operator.cron_deleted",
	"operator.cron_triggered",
}

// ErrTooMany is what a collector returns when the scope holds more items
// than one population can carry (push.MaxItems). The run fails, and its
// heartbeat says so, rather than sending a list that looks complete but
// isn't.
var ErrTooMany = errors.New("witness/dispatch: more items in scope than one population can carry")

// ErrNoLister is what Register returns when the engine's store can't list
// jobs (it doesn't implement job.Lister). Every store dispatch ships does.
var ErrNoLister = errors.New("witness/dispatch: the dispatch store can't list jobs")

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.dispatch.
type Options struct {
	// BackupJobs are the job names, or cron entry names, of your backup
	// jobs. They select what dispatch.backup-runs reports. Empty means that
	// collector isn't registered, because dispatch can't tell a backup job
	// from any other.
	BackupJobs []string `json:"backup_jobs"`
	// AppID is the platform's own app. A cron entry or job counts as staff
	// only when its app scope is empty or this app. In a Forge app it
	// defaults to the witness scope's AppID.
	AppID string `json:"app_id"`
	// StaffOrgs are org IDs whose cron entries and jobs count as staff, on
	// top of the ones with no org at all. Usually empty.
	StaffOrgs []string `json:"staff_orgs"`
	// AllTenants includes cron entries and jobs of every org, your
	// customers' included. In a Forge app the witness scope's AllTenants
	// turns it on too.
	AllTenants bool `json:"all_tenants"`
	// ScanBudget is the most job rows read for one job name and outcome in
	// one run. Zero means DefaultScanBudget.
	ScanBudget int `json:"scan_budget"`
	// EventProofs turns on the schedule change event proof. Off by
	// default.
	EventProofs bool `json:"event_proofs"`
	// ProofActions are the actions the event proof cites. Empty means
	// DefaultProofActions.
	ProofActions []string `json:"proof_actions"`
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithBackupJobs names your backup jobs, by job name or cron entry name.
func WithBackupJobs(names ...string) Option {
	return func(o *Options) { o.BackupJobs = append(o.BackupJobs, names...) }
}

// WithAppID sets the platform's own app. Cron entries and jobs scoped to
// another app aren't staff.
func WithAppID(appID string) Option { return func(o *Options) { o.AppID = appID } }

// WithStaffOrgs adds org IDs whose entries and jobs count as staff.
func WithStaffOrgs(orgIDs ...string) Option {
	return func(o *Options) { o.StaffOrgs = append(o.StaffOrgs, orgIDs...) }
}

// WithAllTenants includes every org's entries and jobs, customers'
// included.
func WithAllTenants() Option { return func(o *Options) { o.AllTenants = true } }

// WithScanBudget sets the most job rows read for one job name and outcome
// in one run.
func WithScanBudget(n int) Option { return func(o *Options) { o.ScanBudget = n } }

// WithEventProofs turns on the schedule change event proof, citing actions,
// or DefaultProofActions when you name none.
func WithEventProofs(actions ...string) Option {
	return func(o *Options) {
		o.EventProofs = true
		o.ProofActions = append(o.ProofActions, actions...)
	}
}

// cronLister is the one cron.Store read the adapter makes.
type cronLister interface {
	ListCrons(ctx context.Context) ([]*cron.Entry, error)
}

// Adapter collects dispatch evidence from one engine.
type Adapter struct {
	crons    cronLister
	jobs     job.Lister
	o        Options
	appID    string
	staffOrg map[string]bool
	backups  []string // trimmed, deduplicated backup names
	now      func() time.Time
}

// New returns an adapter that reads eng's cron entries and jobs.
func New(eng *engine.Engine, opts ...Option) *Adapter {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return newAdapter(eng, o)
}

func newAdapter(eng *engine.Engine, o Options) *Adapter {
	a := &Adapter{o: o, appID: strings.TrimSpace(o.AppID), staffOrg: map[string]bool{}, now: time.Now}
	if eng != nil {
		if cs := eng.CronStore(); cs != nil {
			a.crons = cs
		}
		if d := eng.Dispatcher(); d != nil {
			// Dispatcher.Store is typed as the small Storer interface, but
			// the value is the full store, which lists jobs.
			if l, ok := d.Store().(job.Lister); ok {
				a.jobs = l
			}
		}
	}
	for _, org := range o.StaffOrgs {
		if org = strings.TrimSpace(org); org != "" {
			a.staffOrg[org] = true
		}
	}
	for _, n := range o.BackupJobs {
		if n = strings.TrimSpace(n); n != "" && !slices.Contains(a.backups, n) {
			a.backups = append(a.backups, n)
		}
	}
	if a.o.ScanBudget <= 0 {
		a.o.ScanBudget = DefaultScanBudget
	}
	return a
}

// Register adds the adapter's collectors to w.
func (a *Adapter) Register(w *witness.Witness) error {
	pops, proofs, err := a.collectors()
	if err != nil {
		return err
	}
	for _, p := range pops {
		if err := w.Population(p); err != nil {
			return err
		}
	}
	for _, e := range proofs {
		if err := w.EventProof(e); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) collectors() ([]collect.Population, []collect.EventProof, error) {
	if a.crons == nil {
		return nil, nil, errors.New("witness/dispatch: no engine")
	}
	if a.jobs == nil {
		return nil, nil, ErrNoLister
	}
	pops := []collect.Population{
		{
			Key:         KeyScheduledJobs,
			Title:       "Scheduled jobs",
			Description: "Every cron schedule the system runs, with its schedule, the job it starts and whether it is enabled." + a.widened(),
			Source:      "cron-entries",
			Every:       time.Hour,
			Collect:     a.collectScheduled,
		},
		{
			Key:         KeyJobRuns,
			Title:       "Scheduled job results",
			Description: "For each scheduled job, when it last fired, last succeeded and last failed, and how many runs succeeded or failed in the last 24 hours." + a.widened(),
			Source:      "cron-job-runs",
			Every:       time.Hour,
			Collect:     a.collectRuns,
		},
	}
	if len(a.backups) > 0 {
		pops = append(pops, collect.Population{
			Key:         KeyBackupRuns,
			Title:       "Backup job results",
			Description: "When each backup job last succeeded and how often it is scheduled to run." + a.widened(),
			Source:      "backup-job-runs",
			Tests:       []string{"backup-recent"},
			Every:       time.Hour,
			Collect:     a.collectBackups,
		})
	}
	var proofs []collect.EventProof
	if a.o.EventProofs {
		actions := a.o.ProofActions
		if len(actions) == 0 {
			actions = DefaultProofActions
		}
		proofs = append(proofs, collect.EventProof{
			Key:         KeyScheduleChanges,
			Title:       "Schedule changes",
			Description: "Signed audit events for staff enabling, disabling, deleting or triggering a scheduled job.",
			Every:       15 * time.Minute,
			Stream:      adapter.Platform,
			Actions:     slices.Clone(actions),
		})
	}
	return pops, proofs, nil
}

// widened is the scope rule added to a collector's description when the
// scope reaches past staff, or "" when it doesn't.
func (a *Adapter) widened() string {
	if !a.o.AllTenants {
		return ""
	}
	return " Widened to every org and app, customers' included; each org's or app's runs get an item of their own."
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"dispatch"},
		Attach: attach,
	})
}

// attach finds the app's dispatch engine, through dispatch's extension or
// else the container, and registers the collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	a, found, err := fromHost(h)
	if !found || err != nil {
		return found, err
	}
	if len(a.backups) == 0 {
		logger(h).Info("witness: dispatch found, but no backup_jobs are set, so dispatch.backup-runs is off")
	}
	return true, a.Register(h.Witness)
}

// fromHost builds the adapter for the app's dispatch engine, and tells the
// host when the adapter's own all_tenants takes it past staff.
func fromHost(h adapter.Host) (*Adapter, bool, error) {
	eng, found, err := findEngine(h)
	if !found || err != nil {
		return nil, found, err
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return nil, true, err
	}
	if o.AllTenants {
		// The adapter's own config takes it past staff. The host already
		// knows about the witness scope's AllTenants.
		h.Widened("all_tenants")
	}
	o.AllTenants = o.AllTenants || h.Scope.AllTenants
	if strings.TrimSpace(o.AppID) == "" {
		o.AppID = h.Scope.AppID
	}
	return newAdapter(eng, o), true, nil
}

// extensionName is the name dispatch's own Forge extension registers under.
const extensionName = "dispatch"

// engineGetter is dispatch's Forge extension, read through its getter, so
// the adapter needn't import the extension package.
type engineGetter interface{ Engine() *engine.Engine }

// findEngine returns the app's dispatch engine. It asks dispatch's own
// extension first: the extension registers its engine in the container
// with a constructor, and the container starts whatever a constructor
// returns the first time anyone asks for it, so reading it there would
// start the extension's already running engine a second time. Only an app
// that doesn't run the extension is looked up in the container, where it
// should have provided its finished engine.
func findEngine(h adapter.Host) (*engine.Engine, bool, error) {
	if x, ok := h.Ext(extensionName); ok {
		g, ok := x.(engineGetter)
		if !ok {
			logger(h).Warn("witness: the dispatch extension has no Engine getter, so dispatch is skipped", "type", fmt.Sprintf("%T", x))
			return nil, false, nil
		}
		eng := g.Engine()
		if eng == nil {
			logger(h).Warn("witness: the dispatch extension has no engine yet, so dispatch is skipped")
			return nil, false, nil
		}
		return eng, true, nil
	}
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*engine.Engine](c) {
		return nil, false, nil
	}
	eng, err := vessel.Inject[*engine.Engine](c)
	if err != nil {
		return nil, true, fmt.Errorf("witness/dispatch: resolve the engine: %w", err)
	}
	return eng, true, nil
}

func logger(h adapter.Host) *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}
