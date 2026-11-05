package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hallproof/witness/push"
)

// Defaults for the queue.
const (
	DefaultQueueSize = 1000
	DefaultHoldBack  = time.Hour
	// linger is how long the sender waits for more messages before it
	// sends a part-filled batch.
	linger = 100 * time.Millisecond
	// dropLogEvery limits how often dropped messages are logged.
	dropLogEvery = time.Minute
)

// WithQueueSize sets how many messages Enqueue holds before it drops the
// oldest. The default is 1000.
func WithQueueSize(n int) Option { return func(c *Client) { c.q.size = n } }

// WithHoldBack sets how long the client stops sending a kind of message
// after Hallproof answers "unsupported" to it. The default is an hour.
func WithHoldBack(d time.Duration) Option { return func(c *Client) { c.q.holdBack = d } }

// Stats counts what the client did since it was made.
type Stats struct {
	// Queued is how many messages are waiting to be sent.
	Queued int
	// Accepted, Duplicate, Rejected and Unsupported count Hallproof's
	// answers, plus the client's own for messages it refused to send.
	Accepted, Duplicate, Rejected, Unsupported uint64
	// Dropped counts messages pushed out of a full queue.
	Dropped uint64
	// HeldBack counts messages not sent because Hallproof had answered
	// "unsupported" to their kind.
	HeldBack uint64
}

type item struct {
	seq uint64
	msg push.Message
}

// queue is the client's background sender and the state Send shares with
// it: the hold-back list and the counters.
type queue struct {
	size     int
	holdBack time.Duration
	now      func() time.Time

	mu       sync.Mutex
	items    []item
	seq      uint64
	held     map[push.Kind]time.Time
	stats    Stats
	lastDrop time.Time
	dropped  uint64 // drops since the last log line

	notify   chan struct{}
	stopping chan struct{}
	done     chan struct{}
	cancel   context.CancelFunc
	start    sync.Once
	stop     sync.Once
}

func (q *queue) init() {
	q.size, q.holdBack, q.now = DefaultQueueSize, DefaultHoldBack, time.Now
	q.held = map[push.Kind]time.Time{}
	q.notify = make(chan struct{}, 1)
	q.stopping = make(chan struct{})
	q.done = make(chan struct{})
}

// Enqueue adds msgs to the queue and returns at once. When the queue is
// full the oldest message is dropped, counted and logged. Messages of a
// kind Hallproof recently answered "unsupported" are counted and not
// queued.
func (c *Client) Enqueue(msgs ...push.Message) {
	q := &c.q
	q.mu.Lock()
	now := q.now()
	for _, m := range msgs {
		if q.isHeld(m.Kind, now) {
			q.stats.HeldBack++
			continue
		}
		if len(q.items) >= q.size {
			q.items = q.items[1:]
			q.stats.Dropped++
			q.dropped++
		}
		q.seq++
		q.items = append(q.items, item{seq: q.seq, msg: m})
	}
	logDrops := q.dropped > 0 && now.Sub(q.lastDrop) >= dropLogEvery
	var n uint64
	if logDrops {
		n, q.dropped, q.lastDrop = q.dropped, 0, now
	}
	q.mu.Unlock()

	if logDrops {
		c.log.Warn("witness: the send queue is full; dropped the oldest messages",
			"dropped", n, "queue_size", q.size)
	}
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// Start starts the background sender. Calling it again does nothing.
func (c *Client) Start() {
	c.q.start.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		c.q.cancel = cancel
		go c.run(ctx)
	})
}

// Stop sends what is queued and stops the background sender. It gives up
// when ctx ends and returns an error that says how many messages it left
// behind. A Client that was never started is started first, so Stop always
// tries to flush.
func (c *Client) Stop(ctx context.Context) error {
	c.Start()
	c.q.stop.Do(func() { close(c.q.stopping) })
	select {
	case <-c.q.done:
	case <-ctx.Done():
		c.q.cancel()
		<-c.q.done
	}
	if n := c.Stats().Queued; n > 0 {
		return fmt.Errorf("witness: stopped with %d messages still queued: %w", n, context.Cause(ctx))
	}
	return nil
}

// Stats returns the client's counters.
func (c *Client) Stats() Stats {
	c.q.mu.Lock()
	defer c.q.mu.Unlock()
	s := c.q.stats
	s.Queued = len(c.q.items)
	return s
}

func (c *Client) run(ctx context.Context) {
	defer close(c.q.done)
	failures := 0
	for {
		batch := c.next(ctx)
		if batch == nil {
			return
		}
		err := c.deliver(ctx, batch)
		switch {
		case err == nil:
			failures = 0
		case ctx.Err() != nil:
			return
		default:
			failures++
			if failures == 1 {
				c.log.Warn("witness: hallproof is refusing pushes; messages stay queued", "error", err)
			}
			if c.wait(ctx, failures, err) != nil {
				return
			}
		}
	}
}

// next waits for messages and returns up to a batch's worth from the head
// of the queue, still queued. It returns nil when the client is stopping
// and the queue is empty, or ctx ends.
func (c *Client) next(ctx context.Context) []item {
	q := &c.q
	lingered := false
	for {
		q.mu.Lock()
		n := len(q.items)
		q.mu.Unlock()
		stopping := isClosed(q.stopping)

		switch {
		case n == 0 && stopping:
			return nil
		case n == 0:
			select {
			case <-q.notify:
			case <-q.stopping:
			case <-ctx.Done():
				return nil
			}
			continue
		case n < push.MaxMessages && !stopping && !lingered:
			lingered = true
			t := time.NewTimer(linger)
			select {
			case <-t.C:
			case <-q.stopping:
			case <-ctx.Done():
				t.Stop()
				return nil
			}
			t.Stop()
			continue
		}

		q.mu.Lock()
		take := q.items[:min(len(q.items), push.MaxMessages)]
		out := append([]item(nil), take...)
		q.mu.Unlock()
		return out
	}
}

// deliver sends items with no attempt limit and takes every answered one
// off the queue. Only ErrUnauthorized or the context end it early.
func (c *Client) deliver(ctx context.Context, items []item) error {
	msgs := make([]push.Message, len(items))
	for i, it := range items {
		msgs[i] = it.msg
	}
	results := make([]push.Result, len(msgs))
	var err error
	for _, b := range c.plan(msgs, results) {
		if err = c.sendBatch(ctx, msgs, b, results, 0); err != nil {
			break
		}
	}

	answered := make(map[uint64]bool, len(items))
	for i, r := range results {
		if r.Status != "" {
			answered[items[i].seq] = true
		}
	}
	c.account(msgs, results)

	q := &c.q
	q.mu.Lock()
	kept := q.items[:0]
	for _, it := range q.items {
		if !answered[it.seq] && !q.isHeld(it.msg.Kind, q.now()) {
			kept = append(kept, it)
		} else if !answered[it.seq] {
			q.stats.HeldBack++
		}
	}
	clear(q.items[len(kept):])
	q.items = kept
	q.mu.Unlock()
	return err
}

// account counts results and starts holding back any kind Hallproof
// answered "unsupported".
func (c *Client) account(msgs []push.Message, results []push.Result) {
	q := &c.q
	var newlyHeld []push.Kind
	q.mu.Lock()
	now := q.now()
	for i, r := range results {
		if heldLocally(r) {
			continue // counted as HeldBack already
		}
		switch r.Status {
		case push.StatusAccepted:
			q.stats.Accepted++
		case push.StatusDuplicate:
			q.stats.Duplicate++
		case push.StatusRejected:
			q.stats.Rejected++
		case push.StatusUnsupported:
			q.stats.Unsupported++
			k := msgs[i].Kind
			if !q.isHeld(k, now) && !heldLocally(r) {
				newlyHeld = append(newlyHeld, k)
			}
			q.held[k] = now.Add(q.holdBack)
		}
	}
	q.mu.Unlock()
	for _, k := range newlyHeld {
		c.log.Info("witness: hallproof doesn't take this kind of message yet; holding back messages of this kind",
			"kind", k, "for", q.holdBack)
	}
}

// holdBackError marks a result the client made itself for a held kind.
const holdBackError = "witness: hallproof doesn't take this kind of message yet; not sent"

func heldLocally(r push.Result) bool { return r.Error == holdBackError }

// isHeld reports whether kind k is being held back. q.mu must be held.
func (q *queue) isHeld(k push.Kind, now time.Time) bool {
	until, ok := q.held[k]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(q.held, k)
		return false
	}
	return true
}

// holdBackKinds answers, in results, every message of a held kind, so Send
// doesn't send it.
func (c *Client) holdBackKinds(msgs []push.Message, results []push.Result) {
	q := &c.q
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	for i, m := range msgs {
		if q.isHeld(m.Kind, now) {
			results[i] = push.Result{ID: m.ID, Status: push.StatusUnsupported, Error: holdBackError}
			q.stats.HeldBack++
		}
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
