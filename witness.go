package witness

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/client"
	"github.com/hallproof/witness/collect"
	"github.com/hallproof/witness/httpmw"
)

// Version is this SDK's version. It goes in the User-Agent header and in
// every heartbeat, as "witness-go/" + Version.
const Version = "0.1.0"

// sdk names this SDK on the wire.
const sdk = "witness-go/" + Version

// Options configures a Witness. Endpoint and IngestKey are required.
type Options struct {
	// Endpoint is your Hallproof's base URL, such as
	// "https://hallproof.example.com". It must be HTTPS, except to
	// localhost.
	Endpoint string
	// IngestKey is the system's ingest key, from Hallproof.
	IngestKey string
	// Chain records and proves events. Nil means chain.Unconfigured:
	// event recording is off.
	Chain chain.Chain
	// Logger is where witness logs. Nil means slog.Default().
	Logger *slog.Logger
	// HTTPClient is used to reach Hallproof. Nil means a client with a 30
	// second timeout.
	HTTPClient *http.Client
	// HeartbeatEvery is how often each collector's heartbeat is sent. The
	// default is 10 minutes, and New refuses more than a day, the longest
	// Hallproof takes.
	HeartbeatEvery time.Duration
	// Replica names this copy of the app in heartbeats. The default is the
	// host name plus 8 random hex digits.
	Replica string
	// ClientOptions are passed to client.New after witness's own.
	ClientOptions []client.Option
}

// Witness collects evidence from an app and pushes it to Hallproof.
//
// Register collectors, call Start once, and call Stop when the app shuts
// down. Nothing witness does blocks the app: collectors run on their own
// goroutines, pushes go through a bounded queue, and Hallproof being down
// only means evidence waits.
type Witness struct {
	chain  chain.Chain
	log    *slog.Logger
	client *client.Client
	sched  *collect.Scheduler

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// New checks o and returns a Witness. It doesn't contact Hallproof.
func New(o Options) (*Witness, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Chain == nil {
		o.Chain = chain.Unconfigured{}
	}
	if o.Replica == "" {
		o.Replica = defaultReplica()
	}
	if o.HeartbeatEvery > collect.MaxHeartbeatEvery {
		return nil, fmt.Errorf("witness: HeartbeatEvery is %v; Hallproof takes at most %v", o.HeartbeatEvery, collect.MaxHeartbeatEvery)
	}
	opts := []client.Option{client.WithUserAgent(sdk), client.WithLogger(o.Logger)}
	if o.HTTPClient != nil {
		opts = append(opts, client.WithHTTPClient(o.HTTPClient))
	}
	c, err := client.New(o.Endpoint, o.IngestKey, append(opts, o.ClientOptions...)...)
	if err != nil {
		return nil, err
	}
	return &Witness{
		chain:  o.Chain,
		log:    o.Logger,
		client: c,
		sched: collect.NewScheduler(c, o.Chain, collect.SchedulerOptions{
			Logger:         o.Logger,
			HeartbeatEvery: o.HeartbeatEvery,
			Replica:        o.Replica,
			SDK:            sdk,
		}),
	}, nil
}

func defaultReplica() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "app"
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return host
	}
	return host + "-" + hex.EncodeToString(b[:])
}

var errStarted = errors.New("witness: register collectors before Start")

// register runs add unless witness has started.
func (w *Witness) register(add func() error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return errStarted
	}
	return add()
}

// Snapshot registers a settings collector. Register collectors before
// Start.
func (w *Witness) Snapshot(s collect.Snapshot) error {
	return w.register(func() error { return w.sched.AddSnapshot(s) })
}

// Population registers a population collector.
func (w *Witness) Population(p collect.Population) error {
	return w.register(func() error { return w.sched.AddPopulation(p) })
}

// EventProof registers an event proof collector. It proves nothing while
// the chain is unconfigured.
func (w *Witness) EventProof(e collect.EventProof) error {
	return w.register(func() error { return w.sched.AddEventProof(e) })
}

// Chain returns the chain witness records to.
func (w *Witness) Chain() chain.Chain { return w.chain }

// Middleware returns httpmw's middleware, recording to witness's chain and
// logging to its logger unless o says otherwise.
func (w *Witness) Middleware(o httpmw.Options) func(http.Handler) http.Handler {
	if o.Chain == nil {
		o.Chain = w.chain
	}
	if o.Logger == nil {
		o.Logger = w.log
	}
	return httpmw.New(o)
}

// Client returns the client witness pushes with, for apps that also push
// by hand.
func (w *Witness) Client() *client.Client { return w.client }

// Start starts the collectors and the sender, and returns at once. They
// run until Stop. Start can be called once.
//
// ctx's values carry over, but its end doesn't stop witness: frameworks
// such as fx hand Start a context that ends once start-up is over.
func (w *Witness) Start(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return errors.New("witness: already started")
	}
	w.started = true
	if _, off := w.chain.(chain.Unconfigured); off {
		w.log.Info("witness: no chain is configured, so event recording is off")
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	w.cancel, w.done = cancel, make(chan struct{})
	w.client.Start()
	go func() {
		defer close(w.done)
		if err := w.sched.Run(runCtx); err != nil {
			w.log.Error("witness: the scheduler stopped", "error", err)
		}
	}()
	return nil
}

// Stop stops the collectors, then sends what is queued until ctx ends. Its
// error says how many messages were left unsent. Stop without Start does
// nothing.
func (w *Witness) Stop(ctx context.Context) error {
	w.mu.Lock()
	started, cancel, done := w.started, w.cancel, w.done
	w.mu.Unlock()
	if !started {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return w.client.Stop(ctx)
}
