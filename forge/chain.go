package forge

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hallproof/witness/chain"
	"github.com/hallproof/witness/push"
)

// lazyChain is the chain witness is built with. It answers chain.ErrNoChain
// until a chain is bound, so the middleware can be mounted during Register
// and starts recording once a chain adapter binds a real chain.
//
// The first chain bound stays; a chain can't be bound once witness starts.
type lazyChain struct {
	mu     sync.RWMutex
	c      chain.Chain
	by     string
	frozen bool
}

var _ chain.Chain = (*lazyChain)(nil)

func (l *lazyChain) current() chain.Chain {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.c
}

// Record records e on the bound chain, or returns chain.ErrNoChain.
func (l *lazyChain) Record(ctx context.Context, e chain.Event) error {
	if c := l.current(); c != nil {
		return c.Record(ctx, e)
	}
	return chain.ErrNoChain
}

// Prove proves r on the bound chain, or returns chain.ErrNoChain.
func (l *lazyChain) Prove(ctx context.Context, r chain.ProofRequest) (*push.EventProof, error) {
	if c := l.current(); c != nil {
		return c.Prove(ctx, r)
	}
	return nil, chain.ErrNoChain
}

var errNilChain = errors.New("the chain is nil")

// bind binds c, which by names for log lines. It returns why it didn't.
func (l *lazyChain) bind(c chain.Chain, by string) error {
	if c == nil {
		return errNilChain
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.frozen:
		return errors.New("witness has already started")
	case l.c != nil:
		return fmt.Errorf("%s already bound a chain", l.by)
	}
	l.c, l.by = c, by
	return nil
}

// freeze stops later binds and reports whether a chain is bound.
func (l *lazyChain) freeze() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.frozen = true
	return l.c != nil
}
