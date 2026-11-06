package sentinel

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	sn "github.com/xraph/sentinel"
	"github.com/xraph/sentinel/baseline"
	"github.com/xraph/sentinel/evalrun"
	"github.com/xraph/sentinel/redteam"
	"github.com/xraph/sentinel/suite"
	"github.com/xraph/sentinel/testcase"

	"github.com/hallproof/witness/push"
)

// pageSize is how many suites each list call asks for.
const pageSize = 1000

// runPageSize is how many runs each list call asks for while looking for a
// suite's latest run in scope. The first page nearly always holds it.
const runPageSize = 100

// maxItems is the most suites a collector reads in scope before it fails
// the run. A variable so tests can lower it.
var maxItems = push.MaxItems

// redTeamTag is the tag sentinel's red-team generators put on every case
// they write.
const redTeamTag = "redteam"

// otherAttack is the attack type of a red-team case whose tags name none of
// sentinel's attack types. Tags are free text, so only known types are
// sent.
const otherAttack = "other"

// attackTypes are sentinel's own red-team attack types.
var attackTypes = []redteam.AttackType{
	redteam.AttackInjection,
	redteam.AttackJailbreak,
	redteam.AttackLeakage,
	redteam.AttackHallucination,
	redteam.AttackOfftopic,
}

// regressionEpsilon absorbs float64 rounding in a delta, as sentinel's own
// regression check does (baseline/regression.go), so a drop exactly equal
// to the threshold is not a regression here either.
const regressionEpsilon = 1e-9

func fellBelow(delta, threshold float64) bool { return delta < -threshold-regressionEpsilon }

// appIn checks a row's app against AppID again after the store's filter,
// so a store that ignores the filter can't widen the scope.
func (a *Adapter) appIn(appID string) bool { return a.o.AppID == "" || appID == a.o.AppID }

// runInScope reports whether a run evaluated your own agent: it has no
// target tenant, or one of the staff tenants, or AllTenants is on.
func (a *Adapter) runInScope(r *evalrun.Run) bool {
	return a.o.AllTenants || r.TargetTenantID == "" || a.tenantIn[r.TargetTenantID]
}

// eachSuite calls fn once for every suite in scope. It pages, skips a suite
// seen on an earlier page (offset paging can repeat a row when suites are
// created mid-scan), and fails with ErrTooMany past maxItems suites.
func (a *Adapter) eachSuite(ctx context.Context, fn func(*suite.Suite) error) error {
	seen := map[string]bool{}
	for off := 0; ; off += pageSize {
		page, err := a.eng.ListSuites(ctx, &suite.ListFilter{AppID: a.o.AppID, Limit: pageSize, Offset: off})
		if err != nil {
			return fmt.Errorf("witness/sentinel: list suites: %w", err)
		}
		for _, s := range page {
			sid := s.ID.String()
			if !a.appIn(s.AppID) || seen[sid] {
				continue
			}
			seen[sid] = true
			if len(seen) > maxItems {
				return fmt.Errorf("%w: more than %d suites", ErrTooMany, maxItems)
			}
			if err := fn(s); err != nil {
				return err
			}
		}
		if len(page) < pageSize {
			return nil
		}
	}
}

// latestRun is a suite's most recent completed run in scope, or nil when it
// has none. Runs come newest first; runs against other tenants are skipped.
func (a *Adapter) latestRun(ctx context.Context, s *suite.Suite) (*evalrun.Run, error) {
	sid := s.ID.String()
	for off := 0; ; off += runPageSize {
		page, err := a.eng.ListRuns(ctx, &evalrun.ListFilter{SuiteID: s.ID, AppID: a.o.AppID, State: evalrun.StateCompleted, Limit: runPageSize, Offset: off})
		if err != nil {
			return nil, fmt.Errorf("witness/sentinel: list runs: %w", err)
		}
		for _, r := range page {
			if r.State == evalrun.StateCompleted && r.SuiteID.String() == sid && a.appIn(r.AppID) && a.runInScope(r) {
				return r, nil
			}
		}
		if len(page) < runPageSize {
			return nil, nil
		}
	}
}

// currentBaseline is a suite's current baseline, or nil when it has none.
func (a *Adapter) currentBaseline(ctx context.Context, s *suite.Suite) (*baseline.Baseline, error) {
	b, err := a.eng.GetLatestBaseline(ctx, s.ID)
	if errors.Is(err, sn.ErrBaselineNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("witness/sentinel: get a suite's baseline: %w", err)
	}
	return b, nil
}

// redTeamCases maps the ID of each red-team case in s to its attack type.
// ListCases loads every case's input and expected text too. They stay in
// memory and are never sent.
func (a *Adapter) redTeamCases(ctx context.Context, s *suite.Suite) (total int, attacks map[string]string, err error) {
	cases, err := a.eng.ListCases(ctx, s.ID)
	if err != nil {
		return 0, nil, fmt.Errorf("witness/sentinel: list a suite's cases: %w", err)
	}
	attacks = map[string]string{}
	for _, c := range cases {
		if slices.Contains(c.Tags, redTeamTag) {
			attacks[c.ID.String()] = attackType(c)
		}
	}
	return len(cases), attacks, nil
}

// attackType is the first of a red-team case's tags that names one of
// sentinel's attack types, or otherAttack.
func attackType(c *testcase.Case) string {
	for _, t := range c.Tags {
		if slices.Contains(attackTypes, redteam.AttackType(t)) {
			return t
		}
	}
	return otherAttack
}

func (a *Adapter) collectSuites(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := a.eachSuite(ctx, func(s *suite.Suite) error {
		total, attacks, err := a.redTeamCases(ctx, s)
		if err != nil {
			return err
		}
		types := []string{}
		for _, t := range attacks {
			if !slices.Contains(types, t) {
				types = append(types, t)
			}
		}
		slices.Sort(types)
		b, err := a.currentBaseline(ctx, s)
		if err != nil {
			return err
		}
		var baselineID any
		if b != nil {
			baselineID = b.ID.String()
		}
		out = append(out, map[string]any{
			"id":                 s.ID.String(),
			"name":               s.Name,
			"app_id":             s.AppID,
			"model":              s.Model,
			"persona_ref":        s.PersonaRef,
			"case_count":         total,
			"redteam_case_count": len(attacks),
			"redteam_types":      types,
			"has_baseline":       b != nil,
			"baseline_id":        baselineID,
			"created_at":         stamp(s.CreatedAt),
			"updated_at":         stamp(s.UpdatedAt),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Adapter) collectLatestScores(ctx context.Context) ([]map[string]any, error) {
	threshold := a.eng.Config().RegressionThreshold
	out := []map[string]any{}
	err := a.eachSuite(ctx, func(s *suite.Suite) error {
		run, err := a.latestRun(ctx, s)
		if err != nil {
			return err
		}
		it := map[string]any{
			"id":                   s.ID.String(),
			"run_id":               nil,
			"model":                nil,
			"completed_at":         nil,
			"total_cases":          nil,
			"passed":               nil,
			"failed":               nil,
			"pass_rate":            nil,
			"avg_score":            nil,
			"dimension_scores":     nil,
			"baseline_id":          nil,
			"baseline_pass_rate":   nil,
			"baseline_avg_score":   nil,
			"pass_rate_delta":      nil,
			"avg_score_delta":      nil,
			"dimension_deltas":     nil,
			"missing_dimensions":   nil,
			"regression_threshold": threshold,
			"regressed":            nil,
			"regression_basis":     "aggregate",
		}
		a.addTarget(it, run)
		if run == nil {
			out = append(out, it)
			return nil
		}
		it["run_id"] = run.ID.String()
		it["model"] = run.Model
		it["completed_at"] = stampOf(run.CompletedAt)
		it["total_cases"] = run.TotalCases
		it["passed"] = run.Passed
		it["failed"] = run.Failed
		it["pass_rate"] = run.PassRate
		it["avg_score"] = run.AvgScore
		it["dimension_scores"] = scores(run.DimensionScores)

		b, err := a.currentBaseline(ctx, s)
		if err != nil {
			return err
		}
		if b != nil {
			compare(it, run, b, threshold)
		}
		out = append(out, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// compare fills it with how run compares with baseline b. It is
// baseline.DetectRegression on aggregates only: pass rate, average score
// and each dimension, with a baseline dimension the run didn't measure
// counting as regressed. Per-case regressions need each result's output
// loaded, so they are left out, and regression_basis says so.
func compare(it map[string]any, run *evalrun.Run, b *baseline.Baseline, threshold float64) {
	prd := run.PassRate - b.PassRate
	asd := run.AvgScore - b.AvgScore
	regressed := fellBelow(prd, threshold) || fellBelow(asd, threshold)
	deltas := map[string]float64{}
	missing := []string{}
	for dim, was := range b.DimensionScores {
		now, measured := run.DimensionScores[dim]
		if !measured {
			missing = append(missing, dim)
			regressed = true
			continue
		}
		d := now - was
		deltas[dim] = d
		if fellBelow(d, threshold) {
			regressed = true
		}
	}
	slices.Sort(missing)
	it["baseline_id"] = b.ID.String()
	it["baseline_pass_rate"] = b.PassRate
	it["baseline_avg_score"] = b.AvgScore
	it["pass_rate_delta"] = prd
	it["avg_score_delta"] = asd
	it["dimension_deltas"] = deltas
	it["missing_dimensions"] = missing
	it["regressed"] = regressed
}

// addTarget sends the run's target tenant when the scope is widened to
// every tenant. In the default scope it is always empty or a staff tenant,
// and is left out.
func (a *Adapter) addTarget(it map[string]any, run *evalrun.Run) {
	if !a.o.AllTenants {
		return
	}
	it["target_tenant_id"] = nil
	if run != nil && run.TargetTenantID != "" {
		it["target_tenant_id"] = run.TargetTenantID
	}
}

func (a *Adapter) collectRedTeam(ctx context.Context) ([]map[string]any, error) {
	out := []map[string]any{}
	err := a.eachSuite(ctx, func(s *suite.Suite) error {
		_, attacks, err := a.redTeamCases(ctx, s)
		if err != nil || len(attacks) == 0 {
			return err
		}
		run, err := a.latestRun(ctx, s)
		if err != nil {
			return err
		}
		it := map[string]any{
			"id":           s.ID.String(),
			"run_id":       nil,
			"completed_at": nil,
			"attacks":      0,
			"bypasses":     0,
			"bypass_rate":  nil,
			"by_type":      map[string]map[string]int{},
		}
		a.addTarget(it, run)
		if run == nil {
			out = append(out, it)
			return nil
		}
		// ListResults loads each result's output too. Only CaseID and
		// Status are read.
		results, err := a.eng.ListResults(ctx, run.ID)
		if err != nil {
			return fmt.Errorf("witness/sentinel: list a run's results: %w", err)
		}
		total, bypasses := 0, 0
		byType := map[string]map[string]int{}
		for _, r := range results {
			typ, ok := attacks[r.CaseID.String()]
			if !ok {
				continue
			}
			if byType[typ] == nil {
				byType[typ] = map[string]int{"total": 0, "bypasses": 0}
			}
			total++
			byType[typ]["total"]++
			// A failed or errored attack case is one where the scorer did
			// not see the defence hold.
			if r.Status == evalrun.StatusFail || r.Status == evalrun.StatusError {
				bypasses++
				byType[typ]["bypasses"]++
			}
		}
		it["run_id"] = run.ID.String()
		it["completed_at"] = stampOf(run.CompletedAt)
		it["attacks"] = total
		it["bypasses"] = bypasses
		if total > 0 {
			it["bypass_rate"] = float64(bypasses) / float64(total)
		}
		it["by_type"] = byType
		out = append(out, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (a *Adapter) collectSettings(context.Context) (map[string]any, error) {
	cfg := a.eng.Config()
	return map[string]any{
		"pass_threshold":       cfg.PassThreshold,
		"regression_threshold": cfg.RegressionThreshold,
		"default_model":        cfg.DefaultModel,
	}, nil
}

// scores copies m, so an empty or nil map goes as {}.
func scores(m map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	maps.Copy(out, m)
	return out
}

// stamp is t in UTC to the second. Stores keep different precisions, so
// whole seconds keep a row's hash steady across them.
func stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

func stampOf(t *time.Time) any {
	if t == nil {
		return nil
	}
	return stamp(*t)
}
