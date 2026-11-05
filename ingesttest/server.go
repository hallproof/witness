// Package ingesttest runs a fake Hallproof ingest API for tests.
//
// The server checks what Hallproof checks: the bearer key, the batch's
// version, size and message count, each message's ID, kind and collection
// time, titles, and the hashes in snapshot and population bodies. It answers
// "duplicate" for a resent message and rejects an ID reused for a different
// body. It doesn't verify event proof signatures.
//
// Use it to test code that pushes evidence without a running Hallproof:
//
//	s := ingesttest.New(t)
//	c, _ := client.New(s.URL, s.Key)
//	// push, then look at s.Stored() and s.Requests()
package ingesttest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hallproof/witness/push"
)

// Hallproof's own limits, beyond the ones in push.
const (
	maxID    = 200
	maxTitle = 200
	maxAhead = 5 * time.Minute
)

// DefaultKey is the ingest key a new Server accepts.
const DefaultKey = "hpk_test"

// Request is one request the server received.
type Request struct {
	// Status is the HTTP status the server answered with.
	Status int
	// Batch is the request's batch, when its body decoded as one.
	Batch push.Batch
	// Header is a copy of the request's headers.
	Header http.Header
}

// Option changes a Server.
type Option func(*Server)

// WithNow sets the server's clock, which it uses to refuse evidence
// collected more than five minutes in the future.
func WithNow(now func() time.Time) Option { return func(s *Server) { s.now = now } }

type stored struct {
	hash       string
	evidenceID string
}

// Server is a fake Hallproof ingest API. Its methods are safe to call while
// requests are in flight.
type Server struct {
	// URL is the server's base URL. Push to URL + "/api/v1/ingest".
	URL string
	// Key is the ingest key the server started with. SetKey changes the
	// accepted key without changing this field.
	Key string

	now func() time.Time

	mu          sync.Mutex
	key         string
	known       map[push.Kind]bool
	failNext    int
	failStatus  int
	failStoring int
	requests    []Request
	byID        map[string]stored
	messages    []push.Message
	nextID      int
}

// New starts a Server and stops it when the test ends. It accepts the
// kinds Hallproof accepts today (config_snapshot, population and
// event_proof) and answers "unsupported" to the rest, heartbeats included,
// until Know says otherwise.
func New(t testing.TB, opts ...Option) *Server {
	t.Helper()
	s := &Server{
		Key:   DefaultKey,
		key:   DefaultKey,
		now:   time.Now,
		known: map[push.Kind]bool{push.KindConfigSnapshot: true, push.KindPopulation: true, push.KindEventProof: true},
		byID:  map[string]stored{},
	}
	for _, o := range opts {
		o(s)
	}
	hs := httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(hs.Close)
	s.URL = hs.URL
	return s
}

// Know makes the server accept messages of these kinds.
func (s *Server) Know(kinds ...push.Kind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range kinds {
		s.known[k] = true
	}
}

// SetKey changes the ingest key the server accepts.
func (s *Server) SetKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = key
}

// FailNext makes the next n requests answer status without storing
// anything, as an outage or an overloaded proxy would.
func (s *Server) FailNext(n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext, s.failStatus = n, status
}

// FailAfterStoring makes the next n requests store their batch as usual and
// then answer 500, as Hallproof does when a store fails part way.
func (s *Server) FailAfterStoring(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failStoring = n
}

// Requests returns every request so far, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Stored returns every message stored as evidence, in the order it was
// accepted. Heartbeats aren't evidence and never appear here.
func (s *Server) Stored() []push.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]push.Message(nil), s.messages...)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/ingest" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}

	raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, push.MaxBatchBytes))
	var b push.Batch
	decodeErr := json.Unmarshal(raw, &b)

	s.mu.Lock()
	defer s.mu.Unlock()
	answer := func(status int, v any) {
		s.requests = append(s.requests, Request{Status: status, Batch: b, Header: r.Header.Clone()})
		if v == nil {
			http.Error(w, http.StatusText(status), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		// The status is already sent, so a failed write has no one to tell.
		if err := json.NewEncoder(w).Encode(v); err != nil {
			return
		}
	}

	if s.failNext > 0 {
		s.failNext--
		answer(s.failStatus, nil)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.key {
		answer(http.StatusUnauthorized, nil)
		return
	}
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(readErr, &tooBig):
		answer(http.StatusRequestEntityTooLarge, nil)
		return
	case readErr != nil, decodeErr != nil, b.Version != push.Version, len(b.Messages) > push.MaxMessages:
		answer(http.StatusBadRequest, nil)
		return
	}

	uses := map[string]int{}
	for _, m := range b.Messages {
		uses[m.ID]++
	}
	resp := push.Response{Version: push.Version, Results: make([]push.Result, 0, len(b.Messages))}
	for _, m := range b.Messages {
		resp.Results = append(resp.Results, s.ingest(m, uses[m.ID] > 1))
	}

	if s.failStoring > 0 {
		s.failStoring--
		answer(http.StatusInternalServerError, nil)
		return
	}
	answer(http.StatusOK, resp)
}

func rejected(id, reason string) push.Result {
	return push.Result{ID: id, Status: push.StatusRejected, Error: reason}
}

// ingest handles one message, in the order Hallproof checks things.
func (s *Server) ingest(m push.Message, repeated bool) push.Result {
	switch {
	case m.ID == "" || len(m.ID) > maxID:
		return rejected(m.ID, fmt.Sprintf("the message id must be 1 to %d bytes", maxID))
	case !utf8.ValidString(m.ID) || strings.ContainsRune(m.ID, 0):
		return rejected(m.ID, "the message id must be UTF-8 text without NUL bytes")
	case repeated:
		return rejected(m.ID, "the message id appears more than once in the batch")
	case !s.known[m.Kind]:
		return push.Result{ID: m.ID, Status: push.StatusUnsupported, Error: fmt.Sprintf("this server doesn't take %q messages", m.Kind)}
	case m.CollectedAt.IsZero():
		return rejected(m.ID, "collected_at is required")
	case m.CollectedAt.After(s.now().Add(maxAhead)):
		return rejected(m.ID, "the evidence was collected in the future")
	}
	if err := checkBody(m); err != nil {
		return rejected(m.ID, err.Error())
	}
	if m.Kind == push.KindHeartbeat {
		return push.Result{ID: m.ID, Status: push.StatusAccepted}
	}

	hash, err := contentHash(m.Body)
	if err != nil {
		return rejected(m.ID, err.Error())
	}
	if prev, ok := s.byID[m.ID]; ok {
		if prev.hash != hash {
			return rejected(m.ID, "this message id was already used for different content")
		}
		return push.Result{ID: m.ID, Status: push.StatusDuplicate, EvidenceID: prev.evidenceID}
	}
	s.nextID++
	id := fmt.Sprintf("ev_%d", s.nextID)
	s.byID[m.ID] = stored{hash: hash, evidenceID: id}
	s.messages = append(s.messages, m)
	return push.Result{ID: m.ID, Status: push.StatusAccepted, EvidenceID: id}
}

func checkTitle(c push.Common) error {
	if strings.TrimSpace(c.Title) == "" || len(c.Title) > maxTitle {
		return fmt.Errorf("the title must be 1 to %d bytes", maxTitle)
	}
	return nil
}

func checkBody(m push.Message) error {
	switch m.Kind {
	case push.KindConfigSnapshot:
		b, err := push.DecodeBody[push.ConfigSnapshot](m)
		if err != nil {
			return err
		}
		if err := checkTitle(b.Common); err != nil {
			return err
		}
		if b.Settings == nil {
			return errors.New("a snapshot needs its settings")
		}
		if h, err := push.SnapshotHash(b.Settings); err != nil || h != b.Hash {
			return errors.New("snapshot hash does not match its settings")
		}
	case push.KindPopulation:
		b, err := push.DecodeBody[push.Population](m)
		if err != nil {
			return err
		}
		if err := checkTitle(b.Common); err != nil {
			return err
		}
		if b.Items == nil {
			return errors.New("a population needs its items")
		}
		if len(b.Items) > push.MaxItems {
			return fmt.Errorf("a population can have at most %d items", push.MaxItems)
		}
		seen := make(map[string]int, len(b.Items))
		for i, it := range b.Items {
			id, ok := it["id"].(string)
			if !ok || id == "" {
				return fmt.Errorf("population item %d has no string id", i)
			}
			if j, dup := seen[id]; dup {
				return fmt.Errorf("population items %d and %d have the same id", j, i)
			}
			seen[id] = i
		}
		if h, err := push.PopulationHash(b.Items); err != nil || h != b.Hash {
			return errors.New("population hash does not match its items")
		}
	case push.KindEventProof:
		b, err := push.DecodeBody[push.EventProof](m)
		if err != nil {
			return err
		}
		if err := checkTitle(b.Common); err != nil {
			return err
		}
		if len(b.Segment) > push.MaxSegment {
			return fmt.Errorf("a segment can have at most %d events", push.MaxSegment)
		}
	case push.KindHeartbeat:
		b, err := push.DecodeBody[push.Heartbeat](m)
		if err != nil {
			return err
		}
		if b.Collector == "" {
			return errors.New("a heartbeat needs its collector")
		}
	}
	return nil
}

// contentHash is sha256 of the body's canonical JSON, as Hallproof keys
// duplicates.
func contentHash(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", errors.New("the body isn't JSON")
	}
	c, err := push.Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
