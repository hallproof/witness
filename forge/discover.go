package forge

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/xraph/forge"

	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/collect"
)

// CoverageKey is the key of the snapshot that tells Hallproof which
// libraries witness looked for, which it found, and the scope it collects.
const CoverageKey = "witness.coverage"

// Scope modes in the coverage snapshot.
const (
	scopeStaff      = "staff"
	scopeAllTenants = "all_tenants"
)

// discoverAndStart attaches every registered adapter the config allows,
// chain adapters first, registers the coverage snapshot and starts witness.
// It runs once every extension has started, and never fails the app: an
// adapter that errors or panics is logged and skipped.
func (e *Extension) discoverAndStart(ctx context.Context, container forge.Container) {
	e.mu.Lock()
	w, cfg, log := e.w, e.cfg, e.log
	e.mu.Unlock()
	if w == nil {
		return
	}

	// Provided only now, once the container has started: vessel starts
	// every value that has a Start method when the container starts, and
	// a witness started then would refuse the adapters' collectors.
	if err := forge.ProvideValue(container, w); err != nil {
		log.Error("witness: couldn't provide *witness.Witness in the container", "error", err)
	}

	all := adapter.Adapters()
	only, exclude := toSet(cfg.Libraries), toSet(cfg.Exclude)
	warnUnknown(log, all, "libraries", cfg.Libraries)
	warnUnknown(log, all, "exclude", cfg.Exclude)

	// Chain adapters first, so the chain is bound before the others attach;
	// each group stays in name order.
	ordered := make([]adapter.Adapter, 0, len(all))
	for _, a := range all {
		if a.Chain {
			ordered = append(ordered, a)
		}
	}
	for _, a := range all {
		if !a.Chain {
			ordered = append(ordered, a)
		}
	}

	scope := cfg.Scope.scope()
	results := make(map[string]map[string]any, len(all))
	anyWidened := false
	for _, a := range ordered {
		entry := map[string]any{"name": a.Name, "module": a.Module, "found": false}
		results[a.Name] = entry
		alog := log.With("adapter", a.Name)
		switch {
		case len(only) > 0 && !only[a.Name]:
			alog.Info("witness: skipped an adapter that libraries leaves out")
			continue
		case exclude[a.Name]:
			alog.Info("witness: skipped an excluded adapter")
			continue
		}
		wd := &widening{log: alog}
		found, err := attach(ctx, a, adapter.Host{
			Witness:   w,
			Scope:     scope,
			Logger:    alog,
			Container: container,
			Config:    cfg.Adapters[a.Name],
			SetChain:  e.setChain(a.Name, alog),
			Widen:     wd.widen,
		})
		entry["found"] = found
		if reasons := wd.close(); len(reasons) > 0 {
			entry["widened"] = true
			entry["widened_by"] = reasons
			anyWidened = true
			alog.Info("witness: an adapter's config takes it beyond staff", "widened_by", reasons)
		}
		switch {
		case err != nil:
			// The error text stays in the log; Hallproof only learns that
			// the adapter failed.
			entry["error"] = true
			alog.Error("witness: an adapter failed to attach, so its library is skipped", "error", err)
		case found:
			alog.Info("witness: found a library")
		default:
			alog.Info("witness: skipped an adapter whose library the app doesn't run")
		}
	}

	adapters := make([]any, 0, len(all))
	for _, a := range all {
		adapters = append(adapters, results[a.Name])
	}
	mode := scopeStaff
	if scope.AllTenants {
		mode = scopeAllTenants
	}
	settings := map[string]any{"scope": mode, "adapters": adapters}
	if anyWidened {
		// The scope stays what the host set; this says that an adapter's
		// own config went further, and its entry says how.
		settings["any_widened"] = true
	}
	if err := w.Snapshot(collect.Snapshot{
		Key:         CoverageKey,
		Title:       "Witness coverage",
		Description: "The libraries witness looks for in this app, which it found, and whose evidence it collects. An adapter whose own config collects beyond staff is marked widened, with the config keys that did it.",
		Every:       e.coverageEvery,
		Collect:     func(context.Context) (map[string]any, error) { return settings, nil },
	}); err != nil {
		log.Error("witness: couldn't add the coverage snapshot", "error", err)
	}

	if !e.chain.freeze() {
		log.Info("witness: no chain is bound, so event recording is off")
	}
	if err := w.Start(ctx); err != nil {
		log.Error("witness: couldn't start", "error", err)
	}
}

// attach calls a.Attach, turning a panic into an error so one broken
// adapter can't stop the app or the other adapters.
func attach(ctx context.Context, a adapter.Adapter, h adapter.Host) (found bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			found, err = false, fmt.Errorf("witness: adapter %q panicked: %v", a.Name, r)
		}
	}()
	return a.Attach(ctx, h)
}

// widening is one adapter's Host.Widen. It keeps each reason once, in the
// order the adapter gave them, and ignores calls after Attach returned,
// since the coverage snapshot is built by then.
type widening struct {
	log     *slog.Logger
	mu      sync.Mutex
	reasons []string
	closed  bool
}

func (wd *widening) widen(reason string) {
	wd.mu.Lock()
	defer wd.mu.Unlock()
	if wd.closed {
		wd.log.Warn("witness: ignored Widen after the adapter attached", "reason", reason)
		return
	}
	if reason == "" {
		reason = "unspecified"
	}
	if !slices.Contains(wd.reasons, reason) {
		wd.reasons = append(wd.reasons, reason)
	}
}

// close stops taking reasons and returns them.
func (wd *widening) close() []string {
	wd.mu.Lock()
	defer wd.mu.Unlock()
	wd.closed = true
	return wd.reasons
}

// setChain is the Host.SetChain for the adapter named by. A chain offered
// after witness starts, after another chain was bound, or a nil one is
// ignored with a log line.
func (e *Extension) setChain(by string, log *slog.Logger) func(chain.Chain) {
	return func(c chain.Chain) {
		if err := e.chain.bind(c, by); err != nil {
			log.Warn("witness: ignored SetChain", "reason", err.Error())
			return
		}
		log.Info("witness: bound the chain")
	}
}

func toSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// warnUnknown logs names in a config list that no adapter registered, which
// usually means a missing blank import.
func warnUnknown(log *slog.Logger, all []adapter.Adapter, field string, names []string) {
	known := make(map[string]bool, len(all))
	for _, a := range all {
		known[a.Name] = true
	}
	for _, n := range names {
		if !known[n] {
			log.Warn("witness: config names an adapter that isn't registered; blank-import its module",
				"field", field, "adapter", n)
		}
	}
}
