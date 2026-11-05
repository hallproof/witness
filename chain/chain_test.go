package chain_test

import (
	"errors"
	"testing"

	"github.com/hallproof/witness/chain"
)

var _ chain.Chain = chain.Unconfigured{}

func TestUnconfigured(t *testing.T) {
	var c chain.Unconfigured
	if err := c.Record(t.Context(), chain.Event{Action: "x"}); !errors.Is(err, chain.ErrNoChain) {
		t.Fatalf("Record: %v, want ErrNoChain", err)
	}
	p, err := c.Prove(t.Context(), chain.ProofRequest{Stream: "s"})
	if p != nil || !errors.Is(err, chain.ErrNoChain) {
		t.Fatalf("Prove: %v, %v, want nil and ErrNoChain", p, err)
	}
}
