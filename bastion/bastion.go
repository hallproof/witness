package bastion

import (
	"context"
	"errors"
	"fmt"
	"time"

	bst "github.com/xraph/bastion"
	"github.com/xraph/vessel"

	"github.com/hallproof/witness"
	"github.com/hallproof/witness/adapter"
	"github.com/hallproof/witness/collect"
)

// Name is the adapter's name: its config key and log name.
const Name = "bastion"

// Module is the library this adapter reads.
const Module = "github.com/xraph/bastion"

// Collector keys.
const (
	KeyRoutes  = "bastion.routes"
	KeyGateway = "bastion.gateway"
)

// ErrNoRouteTable is what the route collector returns when the gateway is
// enabled but has no route table yet. Bastion wires the table after the
// gateway registers (gateway.Wire), so this means the gateway was never
// wired. The run fails, and its heartbeat says so, rather than reporting a
// gateway with no routes.
var ErrNoRouteTable = errors.New("witness/bastion: the gateway has no route table; gateway.Wire has not run")

// ErrTooMany is what the route collector returns when the gateway serves
// more routes than one population can carry (push.MaxItems). The run fails
// rather than sending a list that looks complete but isn't.
var ErrTooMany = errors.New("witness/bastion: more routes than one population can carry")

// Options is the adapter's config. In a Forge app it is read from
// extensions.witness.adapters.bastion.
type Options struct {
	// TargetsSummary sends a target count and the target URL schemes for
	// every route instead of the list of upstream origins. Routes that
	// came from service discovery or FARP always get the summary, because
	// their targets change with every pod; this turns it on for manual
	// routes too.
	TargetsSummary bool `json:"targets_summary"`
}

// Option changes an adapter's Options.
type Option func(*Options)

// WithTargetsSummary sends a summary of each route's targets instead of
// the list, manual routes included.
func WithTargetsSummary() Option { return func(o *Options) { o.TargetsSummary = true } }

// Adapter collects evidence from one Bastion gateway.
type Adapter struct {
	gw *bst.Gateway
	o  Options
}

// New returns an adapter that reads gw. Register it only on a gateway that
// fronts your own platform. A gateway you run for a customer's workload is
// that customer's infrastructure, and Hallproof should show the scope as
// widened if you register on one.
func New(gw *bst.Gateway, opts ...Option) *Adapter {
	var o Options
	for _, opt := range opts {
		opt(&o)
	}
	return &Adapter{gw: gw, o: o}
}

// Register adds the adapter's collectors to w.
func (a *Adapter) Register(w *witness.Witness) error {
	pops, snaps, err := a.collectors()
	if err != nil {
		return err
	}
	for _, p := range pops {
		if err := w.Population(p); err != nil {
			return err
		}
	}
	for _, s := range snaps {
		if err := w.Snapshot(s); err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) collectors() ([]collect.Population, []collect.Snapshot, error) {
	if a.gw == nil {
		return nil, nil, errors.New("witness/bastion: no gateway")
	}
	pops := []collect.Population{{
		Key:         KeyRoutes,
		Title:       "Gateway routes",
		Description: "Every route the gateway serves, whether it requires authentication, its rate limit and the upstreams it forwards to.",
		Source:      "gateway-routes",
		Tests:       []string{},
		Every:       15 * time.Minute,
		Collect:     a.collectRoutes,
	}}
	snaps := []collect.Snapshot{{
		Key:         KeyGateway,
		Title:       "Gateway security settings",
		Description: "The gateway's authentication, upstream TLS, rate limiting, IP filtering, CORS and admin API settings.",
		Tests:       []string{"no-open-admin-ports", "tls-enforced"},
		Every:       15 * time.Minute,
		Collect:     a.collectGateway,
	}}
	return pops, snaps, nil
}

func init() {
	adapter.Register(adapter.Adapter{
		Name:   Name,
		Module: Module,
		After:  []string{"bastion"},
		Attach: attach,
	})
}

// attach finds the app's own *bastion.Gateway in the host's container and
// registers the collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	a, found, err := fromHost(h)
	if !found || err != nil {
		return found, err
	}
	return true, a.Register(h.Witness)
}

// fromHost builds the adapter for the gateway in h's container, the only
// gateway the adapter reads by default. Bastion has no tenants, so the
// witness scope changes nothing here.
func fromHost(h adapter.Host) (*Adapter, bool, error) {
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*bst.Gateway](c) {
		return nil, false, nil
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return nil, true, err
	}
	gw, err := vessel.Inject[*bst.Gateway](c)
	if err != nil {
		return nil, true, fmt.Errorf("witness/bastion: resolve the gateway: %w", err)
	}
	return &Adapter{gw: gw, o: o}, true, nil
}
