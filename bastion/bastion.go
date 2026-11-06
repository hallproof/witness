package bastion

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
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
// It adds them all or none: when one fails, the ones added before it
// are taken out again.
func (a *Adapter) Register(w *witness.Witness) error {
	pops, snaps, err := a.collectors()
	if err != nil {
		return err
	}
	var set adapter.Set
	set.Population(pops...)
	set.Snapshot(snaps...)
	return set.Register(w)
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

// attach finds the app's own *bastion.Gateway, through the bastion
// extension or else the container, and registers the collectors.
func attach(_ context.Context, h adapter.Host) (bool, error) {
	a, found, err := fromHost(h)
	if !found || err != nil {
		return found, err
	}
	return true, a.Register(h.Witness)
}

// fromHost builds the adapter for the app's own gateway, the only gateway
// the adapter reads by default. Bastion has no tenants, so the witness
// scope changes nothing here.
func fromHost(h adapter.Host) (*Adapter, bool, error) {
	gw, found, err := findGateway(h)
	if !found || err != nil {
		return nil, found, err
	}
	var o Options
	if err := adapter.Decode(h.Config, &o); err != nil {
		return nil, true, err
	}
	return &Adapter{gw: gw, o: o}, true, nil
}

// extensionName is the name every Bastion Forge extension registers under.
const extensionName = "bastion"

// gatewayGetter is bastion/extension's Extension, read through its getter,
// so the adapter needn't import that package.
type gatewayGetter interface{ Gateway() *bst.Gateway }

// findGateway returns the app's own gateway. It asks the bastion extension
// first, like every adapter, so that it never makes the container build and
// start an engine an extension already started. Bastion provides the
// finished gateway, so its container entry is safe either way, but reading
// the extension keeps the rule simple. Only an app that doesn't run a
// bastion extension is looked up in the container.
func findGateway(h adapter.Host) (*bst.Gateway, bool, error) {
	if x, ok := h.Ext(extensionName); ok {
		log := h.Logger
		if log == nil {
			log = slog.Default()
		}
		gw := gatewayOf(x)
		if gw == nil {
			log.Warn("witness: the bastion extension has no gateway, so bastion is skipped", "type", fmt.Sprintf("%T", x))
			return nil, false, nil
		}
		if !gw.Config().Enabled {
			// A disabled gateway isn't in the container either: Bastion
			// provides it only when enabled.
			return nil, false, nil
		}
		return gw, true, nil
	}
	c, ok := h.Container.(vessel.Vessel)
	if !ok || c == nil || !vessel.HasType[*bst.Gateway](c) {
		return nil, false, nil
	}
	gw, err := vessel.Inject[*bst.Gateway](c)
	if err != nil {
		return nil, true, fmt.Errorf("witness/bastion: resolve the gateway: %w", err)
	}
	return gw, true, nil
}

// gatewayOf returns the gateway of x, whichever Bastion extension it is:
// bastion/extension's has a Gateway getter, bastion.New returns the
// *bastion.Gateway itself, and bastion/gateway's embeds it. It returns nil
// for anything else.
func gatewayOf(x any) *bst.Gateway {
	switch v := x.(type) {
	case gatewayGetter:
		return v.Gateway()
	case *bst.Gateway:
		return v
	}
	rv := reflect.ValueOf(x)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}
	f, ok := rv.Type().FieldByName("Gateway")
	if !ok || !f.Anonymous || !f.IsExported() {
		return nil
	}
	if gw, ok := rv.FieldByIndex(f.Index).Interface().(*bst.Gateway); ok {
		return gw
	}
	return nil
}
