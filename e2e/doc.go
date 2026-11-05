// Package e2e holds witness's end-to-end tests. It isn't for import: it has
// no code of its own, only tests.
//
// The tests build a real Forge app with the witness extension, put real
// library engines in its container (Chronicle, Keysmith and Vault, each on
// its own memory store), blank-import every adapter, and check what reaches a
// fake Hallproof (ingesttest): the coverage snapshot, each adapter's
// evidence, an event proof that verifies the way Hallproof verifies it, and
// that witness stops with the app. Nothing here touches the network beyond
// a local test server, and nothing needs Docker.
//
// Each adapter's own tests check its collectors in detail. These tests check
// that the pieces fit: that the modules build into one binary, that the
// extension finds every engine it should, binds the chain before the other
// adapters attach, and pushes what they collect.
//
// Run them from this directory with go test -race ./... . They take up to
// about 30 seconds, because witness spreads each collector's first run over
// its first 30 seconds and an app can't shorten that.
package e2e
