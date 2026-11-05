package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/push"
)

// Scheduler defaults.
const (
	DefaultHeartbeatEvery = 10 * time.Minute
	DefaultJitter         = 0.1
	// maxFirstDelay caps how long after Run a collector first runs.
	maxFirstDelay = 30 * time.Second
	// warnEvery limits warnings about a collector that keeps failing.
	warnEvery = time.Hour
)

// Sender takes messages to push. *client.Client is one.
type Sender interface {
	Enqueue(msgs ...push.Message)
}

// SchedulerOptions configures a Scheduler. Zero values take the defaults.
type SchedulerOptions struct {
	// Logger is where the scheduler logs. The default is slog.Default().
	Logger *slog.Logger
	// HeartbeatEvery is how often each collector's heartbeat is sent.
	// The default is 10 minutes.
	HeartbeatEvery time.Duration
	// Jitter spreads each collector's runs by up to this fraction of its
	// interval either way. The default is 0.1.
	Jitter float64
	// Replica and SDK go in every heartbeat.
	Replica, SDK string
	// Now is the clock. The default is time.Now.
	Now func() time.Time
}

// collector is one registered collector and what the scheduler remembers
// about it.
type collector struct {
	key   string
	kind  push.Kind
	every time.Duration
	// collect runs the collector once. It returns the message to push, if
	// any, and the hash to remember.
	collect func(ctx context.Context, s *Scheduler, c *collector, now time.Time) (*push.Message, string, error)

	ran         bool
	healthy     bool
	failures    int
	lastHash    string
	lastPushed  string
	lastSuccess time.Time
	lastWarn    time.Time
	from        string // event proofs: the last checkpoint proven
}

// Scheduler runs collectors and pushes what they find.
type Scheduler struct {
	send  Sender
	chain chain.Chain
	o     SchedulerOptions

	mu         sync.Mutex
	collectors map[string]*collector
	order      []string
	running    bool
}

// NewScheduler returns a Scheduler that pushes through s and proves events
// from c.
func NewScheduler(s Sender, c chain.Chain, o SchedulerOptions) *Scheduler {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.HeartbeatEvery <= 0 {
		o.HeartbeatEvery = DefaultHeartbeatEvery
	}
	if o.Jitter <= 0 || o.Jitter >= 1 {
		o.Jitter = DefaultJitter
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if c == nil {
		c = chain.Unconfigured{}
	}
	return &Scheduler{send: s, chain: c, o: o, collectors: map[string]*collector{}}
}

var errNoCollect = errors.New("witness: a collector needs a Collect function")

// validTitle checks a title the way Hallproof does: 1 to 200 bytes, not
// blank.
func validTitle(key, title string) error {
	if strings.TrimSpace(title) == "" || len(title) > 200 {
		return fmt.Errorf("witness: collector %q needs a title of 1 to 200 bytes", key)
	}
	return nil
}

func interval(key string, d time.Duration) (time.Duration, error) {
	switch {
	case d < 0:
		return 0, fmt.Errorf("witness: collector %q has a negative interval", key)
	case d == 0:
		return DefaultEvery, nil
	}
	return d, nil
}

func (s *Scheduler) add(key, title string, every time.Duration, c *collector) error {
	if err := ValidKey(key); err != nil {
		return err
	}
	if err := validTitle(key, title); err != nil {
		return err
	}
	d, err := interval(key, every)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return fmt.Errorf("witness: can't add collector %q after the scheduler started", key)
	}
	if _, dup := s.collectors[key]; dup {
		return fmt.Errorf("witness: collector key %q is already used", key)
	}
	c.key, c.every = key, d
	s.collectors[key] = c
	s.order = append(s.order, key)
	return nil
}

// AddSnapshot registers a settings collector.
func (s *Scheduler) AddSnapshot(sn Snapshot) error {
	if sn.Collect == nil {
		return errNoCollect
	}
	return s.add(sn.Key, sn.Title, sn.Every, &collector{
		kind: push.KindConfigSnapshot,
		collect: func(ctx context.Context, _ *Scheduler, _ *collector, now time.Time) (*push.Message, string, error) {
			settings, err := sn.Collect(ctx)
			if err != nil {
				return nil, "", err
			}
			m, hash, err := SnapshotMessage(sn, settings, now)
			return &m, hash, err
		},
	})
}

// AddPopulation registers a population collector.
func (s *Scheduler) AddPopulation(p Population) error {
	if p.Collect == nil {
		return errNoCollect
	}
	return s.add(p.Key, p.Title, p.Every, &collector{
		kind: push.KindPopulation,
		collect: func(ctx context.Context, _ *Scheduler, _ *collector, now time.Time) (*push.Message, string, error) {
			items, err := p.Collect(ctx)
			if err != nil {
				return nil, "", err
			}
			m, hash, err := PopulationMessage(p, items, now)
			return &m, hash, err
		},
	})
}

// errSkip ends a run that had nothing to do, without counting it.
var errSkip = errors.New("witness: nothing to do")

// AddEventProof registers an event proof collector. It proves nothing
// until the scheduler has a chain.
func (s *Scheduler) AddEventProof(e EventProof) error {
	if e.Stream == "" {
		return fmt.Errorf("witness: event proof collector %q needs a stream", e.Key)
	}
	return s.add(e.Key, e.Title, e.Every, &collector{
		kind: push.KindEventProof,
		collect: func(ctx context.Context, s *Scheduler, c *collector, now time.Time) (*push.Message, string, error) {
			s.mu.Lock()
			from, last := c.from, c.lastHash
			s.mu.Unlock()
			proof, err := s.chain.Prove(ctx, chain.ProofRequest{Stream: e.Stream, From: from, Actions: e.Actions})
			switch {
			case errors.Is(err, chain.ErrNoChain):
				return nil, "", errSkip
			case errors.Is(err, chain.ErrNothingNew):
				return nil, last, nil
			case err != nil:
				return nil, "", err
			case proof == nil || proof.Checkpoint.ID == "":
				return nil, "", errors.New("witness: the chain returned a proof without a checkpoint")
			}
			s.mu.Lock()
			c.from = proof.Checkpoint.ID
			s.mu.Unlock()
			if len(proof.Cited) == 0 {
				return nil, proof.Checkpoint.ToHash, nil
			}
			m, err := ProofMessage(e, proof, now)
			return &m, proof.Checkpoint.ToHash, err
		},
	})
}

func (s *Scheduler) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Run runs every collector on its interval, and the heartbeats on theirs,
// until ctx ends. It can run only once.
func (s *Scheduler) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("witness: the scheduler is already running")
	}
	s.running = true
	keys := append([]string(nil), s.order...)
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Go(func() { s.loop(ctx, k) })
	}
	wg.Go(func() {
		t := time.NewTicker(s.o.HeartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sendHeartbeats()
			}
		}
	})
	wg.Wait()
	return nil
}

func (s *Scheduler) loop(ctx context.Context, key string) {
	r := rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())) // #nosec G404 -- jitter, not a secret
	every := s.collectors[key].every
	wait := firstDelay(every, r)
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		s.runOnce(ctx, key)
		wait = nextDelay(every, s.o.Jitter, r)
	}
}

// nextDelay is every, moved by up to jitter of itself either way.
func nextDelay(every time.Duration, jitter float64, r *rand.Rand) time.Duration {
	return time.Duration(float64(every) * (1 + jitter*(2*r.Float64()-1)))
}

// firstDelay spreads collectors' first runs over min(every, 30s).
func firstDelay(every time.Duration, r *rand.Rand) time.Duration {
	return time.Duration(r.Int64N(int64(min(every, maxFirstDelay))))
}

// runOnce runs one collector, with its interval as the time limit, and
// pushes its evidence if it changed. A panic, an error or a timeout counts
// as a failed run.
func (s *Scheduler) runOnce(ctx context.Context, key string) {
	s.mu.Lock()
	c := s.collectors[key]
	s.mu.Unlock()

	runCtx, cancel := context.WithTimeout(ctx, c.every)
	defer cancel()
	type outcome struct {
		msg  *push.Message
		hash string
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.o.Logger.Error("witness: collector panicked", "collector", key, "panic", p, "stack", string(debug.Stack()))
				done <- outcome{err: fmt.Errorf("panic: %v", p)}
			}
		}()
		m, h, err := c.collect(runCtx, s, c, s.o.Now())
		done <- outcome{m, h, err}
	}()

	var out outcome
	select {
	case out = <-done:
	case <-runCtx.Done():
		// A collector that ignores its context keeps its goroutine until it
		// returns; the scheduler moves on.
		out.err = fmt.Errorf("timed out after %v", c.every)
	}
	if errors.Is(out.err, errSkip) {
		return
	}

	now := s.o.Now()
	s.mu.Lock()
	c.ran = true
	if out.err != nil {
		c.healthy = false
		c.failures++
		warn := now.Sub(c.lastWarn) >= warnEvery
		if warn {
			c.lastWarn = now
		}
		s.mu.Unlock()
		if warn {
			s.o.Logger.Warn("witness: collector failed", "collector", key, "error", out.err)
		}
		return
	}
	c.healthy, c.failures, c.lastWarn = true, 0, time.Time{}
	c.lastHash, c.lastSuccess = out.hash, now
	changed := out.msg != nil && out.hash != c.lastPushed
	if changed {
		c.lastPushed = out.hash
	}
	s.mu.Unlock()
	if changed {
		s.send.Enqueue(*out.msg)
	}
}

// sendHeartbeats sends one heartbeat for every collector that has run.
func (s *Scheduler) sendHeartbeats() {
	now := s.o.Now()
	s.mu.Lock()
	hbs := make([]push.Heartbeat, 0, len(s.order))
	for _, k := range s.order {
		c := s.collectors[k]
		if !c.ran {
			continue
		}
		hbs = append(hbs, push.Heartbeat{
			Collector:    k,
			Evidence:     c.kind,
			Hash:         c.lastHash,
			Healthy:      c.healthy,
			LastSuccess:  c.lastSuccess,
			EverySeconds: int(s.o.HeartbeatEvery / time.Second),
			Replica:      s.o.Replica,
			SDK:          s.o.SDK,
		})
	}
	s.mu.Unlock()

	msgs := make([]push.Message, 0, len(hbs))
	for _, hb := range hbs {
		m, err := HeartbeatMessage(hb, now)
		if err != nil {
			s.o.Logger.Warn("witness: heartbeat not sent", "collector", hb.Collector, "error", err)
			continue
		}
		msgs = append(msgs, m)
	}
	if len(msgs) > 0 {
		s.send.Enqueue(msgs...)
	}
}
