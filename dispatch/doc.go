// Package dispatch sends evidence about your scheduled jobs to Hallproof,
// read from a github.com/xraph/dispatch engine. The one you'll care about
// most is proof that your backups ran.
//
// # Collectors
//
// dispatch.scheduled-jobs is a population of every cron entry: its name,
// cron ID, schedule, the job it starts, queue, whether it's enabled, its app
// and org scope, when it was created, and expected_every_seconds, the gap
// between fires. That gap is only sent for schedules that fire at a fixed
// interval, and it's measured from a fixed date, so a weekday-only or
// monthly schedule goes without it and the item doesn't change from one day
// to the next. It runs hourly.
//
// dispatch.job-runs is a population with one summary per scheduled job:
// when the schedule last fired, when the job last succeeded and last
// failed (with those jobs' IDs), how many runs succeeded or failed in the
// last 24 hours, and window_truncated, which is true when the scan budget
// ran out (see Options). It runs hourly, and since the counts move all the
// time, nearly every run sends new evidence. Keep it at an hour or longer.
//
// last_fired_at is when dispatch enqueued the job, not when it succeeded.
// The success time comes from the newest completed job. Dispatch doesn't
// store a failure time, so last_failed_at is the failed job's last update.
//
// dispatch.backup-runs has the same shape, but only for the jobs you name
// in BackupJobs, by job name or cron entry name. It supports the
// backup-recent test. A name that matches no cron entry still gets an item,
// built from the jobs with that exact name, so a backup that has no
// schedule, or has never run, shows up as exactly that. With no names set
// the collector isn't registered at all, because dispatch has no way to
// tell a backup job from any other.
//
// dispatch.schedule-changes is an event proof of staff enabling,
// disabling, deleting or triggering a cron entry, from the platform
// stream. It's off until you turn on event proofs, and it only proves
// something when your app records dispatch's audit_hook events to the
// chain witness proves from.
//
// Never sent: job and cron payloads, LastError (free text that often
// echoes arguments, SQL or customer data), artifact bindings, input hashes
// and sizes, worker IDs (a cron entry's LockedBy included), resource sets
// and lease fields. A cron entry's next run, lock times and update time
// aren't sent either, because they change on every fire without telling
// you anything about the schedule.
//
// # Scope
//
// By default you get staff evidence only: cron entries and jobs with no org
// scope, plus any org you name in StaffOrgs (config staff_orgs). Dispatch's
// own cron scheduler enqueues jobs with no scope, and RegisterCron never
// sets one, so this covers the schedules your app registers. Dispatch reads
// an empty org filter as "every org", so the adapter can't ask the store
// for unscoped jobs. It reads them all and drops the customer rows itself.
//
// AllTenants (config all_tenants, or the witness scope's AllTenants) adds
// every org's cron entries and jobs. Runs are never mixed across orgs: a
// customer's runs of a job get their own item, id "<cron name>@<org ID>",
// so a customer's success can't stand in for yours. Even then only counts,
// times and IDs go, never payloads or errors.
//
// A scope with more than push.MaxItems items fails the run with
// ErrTooMany, and the heartbeat reports the collector unhealthy.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.dispatch:
//
//	backup_jobs: [db.backup]   # job or cron entry names; empty turns backup-runs off
//	staff_orgs: []             # orgs that count as staff, on top of no org
//	all_tenants: false
//	scan_budget: 5000          # job rows read per job name and outcome per run
//	event_proofs: false
//	proof_actions: []          # defaults to DefaultProofActions
//
// Outside Forge the same settings are Options: WithBackupJobs,
// WithStaffOrgs, WithAllTenants, WithScanBudget and WithEventProofs.
//
// The scan budget is there because finding a job's runs is expensive (see
// the gaps below). For each job name the adapter reads completed jobs, then
// failed jobs, newest first, 200 at a time, each call capped at 30
// seconds. It stops once it has read past the 24 hour window and found the
// latest staff run, or at the end of the list, or after scan_budget rows.
// Hitting the budget sets window_truncated: the counts may then be low, and
// a last success or failure further back may be missing. A list call that
// errors or times out fails the run.
//
// # Using it
//
// With Forge, import the package for its side effect, and the witness
// extension finds *engine.Engine in the container. Dispatch's own Forge
// extension provides it.
//
//	import _ "github.com/hallproof/witness/dispatch"
//
// Without Forge, build the adapter and register it before you start
// witness:
//
//	a := dispatch.New(eng, dispatch.WithBackupJobs("db.backup"))
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # Library gaps
//
// These are things dispatch (v1.9.3 here) doesn't do yet that would make
// this adapter cheaper or more accurate:
//
//   - A job doesn't record the cron entry that enqueued it. The adapter
//     matches runs to schedules by job name, so a manual enqueue of the
//     same job counts as a run. A cron name on job.Job, filterable in
//     ListJobsOpts, would fix it. Today the exact link is only in the
//     cron.fired audit event.
//   - ListJobs filters names with no index on Postgres, SQLite or Mongo,
//     and dispatch never deletes finished jobs, so a rare job in a busy
//     table can mean walking most of it. An index on (name, id) would
//     help; a retention setting would help more.
//   - ListJobs loads whole rows, payloads included. Nothing from them is
//     sent, but the adapter pays to read them.
//   - A failed job has no failure time. CompletedAt is only set on
//     success, so the adapter uses UpdatedAt.
//   - ListJobsOpts treats an empty org as every org, so there's no way to
//     ask for unscoped jobs only.
//   - Dispatch's audit_hook is opt-in, and its Forge extension doesn't
//     wire it to Chronicle, so operator.cron_* events reach the chain only
//     when your app adds it with dispatchext.WithExtension.
//   - Citing backup runs from the chain (cron.fired plus job.completed for
//     the backup job) would need witness to filter event proofs by
//     metadata such as job_name. Without that it would cite every
//     job.completed on the stream, so the backup evidence comes from state.
package dispatch
