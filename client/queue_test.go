package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hallproof/witness/client"
	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

func heartbeat(id string) push.Message {
	body, _ := json.Marshal(push.Heartbeat{Collector: "c", Evidence: push.KindConfigSnapshot, EverySeconds: 600, Replica: "r", SDK: "witness-go/test"})
	return push.Message{ID: id, Kind: push.KindHeartbeat, CollectedAt: time.Now(), Body: body}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func stop(t *testing.T, c *client.Client, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return c.Stop(ctx)
}

func storedIDs(s *ingesttest.Server) []string {
	stored := s.Stored()
	ids := make([]string, 0, len(stored))
	for _, m := range stored {
		ids = append(ids, m.ID)
	}
	return ids
}

// sentIDs lists every message ID the server was sent, in order, retries included.
func sentIDs(s *ingesttest.Server) []string {
	var ids []string
	for _, r := range s.Requests() {
		for _, m := range r.Batch.Messages {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

func count(ids []string, prefix string) int {
	n := 0
	for _, id := range ids {
		if strings.HasPrefix(id, prefix) {
			n++
		}
	}
	return n
}

// logBuffer is a concurrency-safe log sink.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestQueueDropsOldestWhenFull(t *testing.T) {
	s := ingesttest.New(t)
	c := newClient(t, s, client.WithQueueSize(3))
	for i := 1; i <= 5; i++ {
		c.Enqueue(snap(fmt.Sprint("m", i), fmt.Sprint(i)))
	}
	if st := c.Stats(); st.Dropped != 2 || st.Queued != 3 {
		t.Fatalf("stats %+v, want 2 dropped and 3 queued", st)
	}
	c.Start()
	if err := stop(t, c, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(storedIDs(s)); got != "[m3 m4 m5]" {
		t.Fatalf("stored %s, want [m3 m4 m5]", got)
	}
}

func TestStopFlushes(t *testing.T) {
	s := ingesttest.New(t)
	c := newClient(t, s)
	c.Start()
	c.Enqueue(snaps(10)...)
	if err := stop(t, c, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Stored()); n != 10 {
		t.Fatalf("%d stored, want 10", n)
	}
	if st := c.Stats(); st.Accepted != 10 || st.Queued != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// Review Focus 5: shutting down while Hallproof is down.
func TestStopReturnsAtDeadlineWhenServerDown(t *testing.T) {
	s := ingesttest.New(t)
	s.FailNext(1000, http.StatusServiceUnavailable)
	c := newClient(t, s)
	c.Enqueue(snaps(3)...)
	c.Start()
	start := time.Now()
	err := stop(t, c, 200*time.Millisecond)
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("Stop took %v", took)
	}
	if err == nil || !strings.Contains(err.Error(), "3 messages") {
		t.Fatalf("err %v, want one that says 3 messages are still queued", err)
	}
}

// Review Focus 1: heartbeats before Hallproof knows the kind.
func TestUnsupportedKindIsHeldBack(t *testing.T) {
	s := ingesttest.New(t) // doesn't know heartbeats
	logs := &logBuffer{}
	c := newClient(t, s,
		client.WithHoldBack(300*time.Millisecond),
		client.WithLogger(slog.New(slog.NewTextHandler(logs, nil))))
	c.Start()
	defer func() { _ = stop(t, c, time.Second) }()

	c.Enqueue(heartbeat("hb:1"))
	eventually(t, "the first heartbeat's answer", func() bool { return c.Stats().Unsupported == 1 })

	for i := 2; i <= 6; i++ {
		c.Enqueue(heartbeat(fmt.Sprint("hb:", i)))
	}
	c.Enqueue(snap("s1", "1"))
	eventually(t, "the snapshot", func() bool { return len(s.Stored()) == 1 })
	if n := count(sentIDs(s), "hb:"); n != 1 {
		t.Fatalf("%d heartbeats reached the server, want 1", n)
	}
	if st := c.Stats(); st.HeldBack != 5 {
		t.Fatalf("held back %d, want 5", st.HeldBack)
	}
	if n := strings.Count(logs.String(), "holding back"); n != 1 {
		t.Fatalf("%d hold-back log lines, want 1:\n%s", n, logs)
	}

	time.Sleep(350 * time.Millisecond)
	c.Enqueue(heartbeat("hb:7"))
	eventually(t, "a heartbeat after the hold-back", func() bool { return count(sentIDs(s), "hb:7") == 1 })
}

func TestSendHoldsBackToo(t *testing.T) {
	s := ingesttest.New(t)
	c := newClient(t, s)
	if res, _ := c.Send(t.Context(), heartbeat("hb:1")); res[0].Status != push.StatusUnsupported {
		t.Fatalf("first: %+v", res[0])
	}
	res, err := c.Send(t.Context(), heartbeat("hb:2"), snap("s1", "1"))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != push.StatusUnsupported || !strings.Contains(res[0].Error, "not sent") {
		t.Fatalf("held heartbeat: %+v", res[0])
	}
	if res[1].Status != push.StatusAccepted {
		t.Fatalf("snapshot: %+v", res[1])
	}
	if n := count(sentIDs(s), "hb:"); n != 1 {
		t.Fatalf("%d heartbeats sent, want 1", n)
	}
}

func TestUnauthorizedKeepsMessages(t *testing.T) {
	s := ingesttest.New(t)
	s.SetKey("hpk_someone_else")
	c := newClient(t, s)
	c.Enqueue(snaps(2)...)
	c.Start()
	eventually(t, "a 401", func() bool {
		for _, r := range s.Requests() {
			if r.Status == http.StatusUnauthorized {
				return true
			}
		}
		return false
	})
	s.SetKey(s.Key)
	if err := stop(t, c, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Stored()); n != 2 {
		t.Fatalf("%d stored, want 2", n)
	}
}

func TestRejectedAreNotRetried(t *testing.T) {
	s := ingesttest.New(t)
	c := newClient(t, s)
	c.Enqueue(push.Message{ID: "", Kind: push.KindConfigSnapshot, CollectedAt: time.Now(), Body: []byte(`{}`)}, snap("s1", "1"))
	c.Start()
	if err := stop(t, c, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if st := c.Stats(); st.Rejected != 1 || st.Accepted != 1 {
		t.Fatalf("stats %+v", st)
	}
	if n := len(s.Requests()); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
}

func TestEnqueueNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	hs := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select { // never answers while the test runs
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer hs.Close()
	defer close(release)
	c, err := client.New(hs.URL, "hpk_x", fast)
	if err != nil {
		t.Fatal(err)
	}
	c.Start()
	msg := snap("m", "1")
	start := time.Now()
	for range 10000 {
		c.Enqueue(msg)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("10 000 enqueues took %v", took)
	}
	_ = stop(t, c, 50*time.Millisecond)
}
