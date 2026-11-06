// Package sentinel sends evidence about how you test your AI agents to
// Hallproof, read from a github.com/xraph/sentinel engine: your evaluation
// suites, their latest scores against the current baseline, red-team
// results, and the thresholds runs are judged by.
//
// The evidence lands on Hallproof's AI testing checks. sentinel.suites and
// the eval-activity proof support ai-evals-current, sentinel.latest-scores
// supports ai-evals-current and ai-no-regression, and sentinel.redteam
// supports ai-redteam-recent. The settings snapshot supports no test of its
// own.
//
// # Collectors
//
// sentinel.suites is a population of your evaluation suites: ID, name, app,
// model, persona, how many cases the suite has, how many of those are
// red-team cases and of which attack types, whether it has a current
// baseline and which one, and when it was created and last changed. It runs
// hourly.
//
// sentinel.latest-scores is a population with one item per suite. Each item
// holds the suite's most recent completed run (model, completion time, case
// counts, pass rate, average score, scores per dimension) and how that run
// compares with the suite's current baseline: the baseline's pass rate and
// average score, the deltas, the dimensions the run didn't measure, the
// regression threshold, and whether the run regressed. A suite that never
// completed a run, or has no baseline, still gets an item, with those
// fields null. It runs hourly.
//
// The regressed flag is worked out from the run's and the baseline's
// aggregates only, with the same rule sentinel's own regression check uses
// (a fall of more than the threshold, and a baseline dimension the run
// didn't measure counts as a fall). Sentinel's check also compares each
// case, and that needs every result's output loaded. This adapter doesn't
// load outputs for it, so a run where one case collapsed while the averages
// held reads as not regressed here. regression_basis is "aggregate" to say
// so.
//
// sentinel.redteam is a population with one item per suite that has
// red-team cases: the latest completed run, how many attack cases it ran,
// how many got through (a result that failed or errored, meaning the scorer
// didn't see the defence hold), the bypass rate, and the same counts per
// attack type. Only sentinel's own attack types are sent (injection,
// jailbreak, leakage, hallucination, offtopic). A red-team case tagged with
// anything else counts as "other", because tags are free text. It runs every
// six hours, since it reads every case and result of the run.
//
// sentinel.settings is a snapshot of the pass threshold, the regression
// threshold and the default model. It runs hourly.
//
// sentinel.eval-activity is an event proof of runs completing and failing,
// regressions being found and baselines being saved, from the platform
// stream. It's off until you turn on event proofs, and it only proves
// something when the app records those events to the chain witness proves
// from.
//
// Never sent: system prompts, from suites or runs. Suite descriptions,
// temperatures and metadata. Case names, inputs, expected text, context,
// metadata and scorer config. Result names, outputs, scorer results, run
// traces and error text. Run config, run error text, token counts and
// costs. Baseline names and per-case baseline rows. Recorded production
// traffic isn't even read.
//
// # Scope
//
// Evaluations are your own QA of your own agents, so all suites in your
// app are in scope. AppID (config app_id) picks the app, and in a Forge app
// it defaults to the witness scope's app ID. With no AppID you get every
// app's suites.
//
// Runs are where customers can come in. A run can name a target tenant: the
// tenant whose agent it evaluated. By default a run counts only when it has
// no target tenant or targets one of StaffTenants (config staff_tenants;
// in a Forge app the witness scope's TenantID is added for you). A run
// against any other tenant is skipped, so a suite's "latest run" is its
// latest run against your own agent, and nothing about the customer's run
// is sent.
//
// AllTenants (config all_tenants, or the witness scope's AllTenants) counts
// runs against every tenant and sends each run's target_tenant_id with it.
// You'll rarely need it for SOC 2. It may matter under the EU AI Act if you
// have to show testing per deployment. The latest scores and red-team
// descriptions then say they cover every tenant. When it's this adapter's
// own all_tenants, attach tells the host through Host.Widened, so Hallproof
// shows the widening. The witness scope's AllTenants is the host's to
// report.
//
// A scope that holds more than push.MaxItems suites fails the run with
// ErrTooMany, and the heartbeat reports the collector unhealthy, because a
// truncated list would read as the full set.
//
// # Options
//
// In a Forge app these come from extensions.witness.adapters.sentinel:
//
//	app_id: ""            # defaults to the witness scope's app ID
//	staff_tenants: []     # target tenants whose runs count as yours
//	all_tenants: false
//	event_proofs: false
//	proof_actions: []     # defaults to DefaultProofActions
//
// Outside Forge the same settings are Options: WithAppID,
// WithStaffTenants, WithAllTenants and WithEventProofs.
//
// # Using it
//
// With Forge, import the package for its side effect:
//
//	import _ "github.com/hallproof/witness/sentinel"
//
// The adapter reads the engine through sentinel's own Forge extension
// ("sentinel", its Engine method), which already built and started it. If
// that extension is running but has no engine yet, sentinel counts as not
// found and the adapter logs why. Only when your app doesn't run
// sentinel's extension does the adapter look for *engine.Engine in the
// container. If you build the engine yourself, provide the finished value
// with forge.ProvideValue(c, eng), not a constructor: a container starts a
// value it builds from a constructor, and an engine started twice runs
// everything twice. If your app doesn't run Sentinel (Loomplane doesn't
// today, it only pulls Sentinel in through Cortex), the adapter finds
// nothing and registers nothing.
//
// Without Forge, build the adapter and register it before you start
// witness:
//
//	a := sentinel.New(eng, sentinel.WithAppID("app_..."))
//	if err := a.Register(w); err != nil {
//		return err
//	}
//
// # Library gaps
//
// These are things Sentinel (v1.10.0 here) doesn't do yet that would make
// this adapter cheaper or more accurate:
//
//   - A red-team run isn't a record. GenerateRedTeam writes tagged cases
//     into an ordinary suite, nothing builds or stores a redteam.Report,
//     and the engine never calls EmitRedTeamStarted or
//     EmitRedTeamCompleted, so red-team evidence can't come from events.
//     Emitting those with attack and bypass counts would fix the event
//     side.
//   - There is no per-tag result count, so the red-team collector loads
//     every case and result of the run to read IDs, tags and statuses.
//     GetResultStatsByTag(ctx, runID, tag), or a Tags filter on
//     GetResultStats, would avoid that.
//   - Regression against a baseline needs result outputs in memory. A
//     CheckRegression(ctx, runID) on the engine that runs
//     baseline.DetectRegression inside Sentinel would let this adapter
//     report per-case regressions as counts, without case names.
//   - ListCases and ListResults return inputs, expected text and outputs.
//     Witness never sends them but does read them. A projection read (IDs,
//     tags, status) would be cleaner.
//   - ListCases, ListResults and ListRunsBySuite are unpaged. The adapter
//     sends one item per suite, so push.MaxItems isn't at risk, but a very
//     large suite is read whole.
//   - Suites, runs and baselines are filtered by app only. There's no
//     tenant check on them, so the target tenant on a run is the only
//     scope signal.
//   - The audit_hook plugin writes err.Error() into an event's reason and
//     metadata for failed runs and cases, and model errors can quote
//     inputs. Keep that in mind before you send sentinel.eval.run.failed
//     events to a chain whose segments witness proves.
//   - Sentinel's root module is heavy (testcontainers sits in its main
//     requires) and pins older Forgery modules than its siblings, so this
//     module requires forge v1.13.2 and go-utils v1.5.0 to test against
//     what an app really resolves.
package sentinel
