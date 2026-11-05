package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hallproof/witness/client"
	"github.com/hallproof/witness/ingesttest"
	"github.com/hallproof/witness/push"
)

// fast keeps retries quick in tests.
var fast = client.WithBackoff(time.Millisecond, 5*time.Millisecond)

func newClient(t *testing.T, s *ingesttest.Server, opts ...client.Option) *client.Client {
	t.Helper()
	c, err := client.New(s.URL, s.Key, append([]client.Option{fast}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// snap builds a valid snapshot message whose settings hold blob.
func snap(id, blob string) push.Message {
	settings := map[string]any{"blob": blob}
	h, err := push.SnapshotHash(settings)
	if err != nil {
		panic(err)
	}
	body, err := json.Marshal(push.ConfigSnapshot{Common: push.Common{Title: "t"}, Settings: settings, Hash: h})
	if err != nil {
		panic(err)
	}
	return push.Message{ID: id, Kind: push.KindConfigSnapshot, CollectedAt: time.Now(), Body: body}
}

func snaps(n int) []push.Message {
	out := make([]push.Message, n)
	for i := range out {
		out[i] = snap(fmt.Sprintf("m%03d", i), fmt.Sprint(i))
	}
	return out
}

func TestNewChecksEndpointAndKey(t *testing.T) {
	bad := []struct{ endpoint, key string }{
		{"", "hpk_x"},
		{"ftp://x", "hpk_x"},
		{"http://hallproof.example.com", "hpk_x"},
		{"https://", "hpk_x"},
		{"https://hallproof.example.com", ""},
		{"https://hallproof.example.com", "hpk x"},
		{"https://hallproof.example.com", "hpk_x\n"},
	}
	for _, b := range bad {
		if _, err := client.New(b.endpoint, b.key); err == nil {
			t.Errorf("New(%q, %q) accepted", b.endpoint, b.key)
		}
	}
	for _, ep := range []string{"https://hallproof.example.com", "https://hallproof.example.com/", "http://localhost:8080", "http://127.0.0.1", "http://[::1]:9000"} {
		if _, err := client.New(ep, "hpk_x"); err != nil {
			t.Errorf("New(%q): %v", ep, err)
		}
	}
}

func TestSendReturnsResultsInOrder(t *testing.T) {
	s := ingesttest.New(t)
	c := newClient(t, s)
	msgs := []push.Message{snap("b", "1"), snap("a", "2"), {ID: "", Kind: push.KindConfigSnapshot}, snap("c", "3")}
	res, err := c.Send(t.Context(), msgs...)
	if err != nil {
		t.Fatal(err)
	}
	want := []push.Status{push.StatusAccepted, push.StatusAccepted, push.StatusRejected, push.StatusAccepted}
	for i, r := range res {
		if r.Status != want[i] || r.ID != msgs[i].ID {
			t.Errorf("result %d: %+v, want %s for %q", i, r, want[i], msgs[i].ID)
		}
	}
}

func TestSendSplitsAtMaxMessages(t *testing.T) {
	s := ingesttest.New(t)
	res, err := newClient(t, s).Send(t.Context(), snaps(250)...)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 250 {
		t.Fatalf("%d results, want 250", len(res))
	}
	reqs := s.Requests()
	sizes := make([]int, 0, len(reqs))
	for _, r := range reqs {
		sizes = append(sizes, len(r.Batch.Messages))
	}
	if fmt.Sprint(sizes) != "[100 100 50]" {
		t.Fatalf("batch sizes %v, want [100 100 50]", sizes)
	}
}

func TestSendSplitsAtMaxBatchBytes(t *testing.T) {
	s := ingesttest.New(t)
	msgs := make([]push.Message, 3)
	for i := range msgs {
		msgs[i] = snap(fmt.Sprint("big", i), strings.Repeat("x", 3<<20))
	}
	res, err := newClient(t, s).Send(t.Context(), msgs...)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range res {
		if r.Status != push.StatusAccepted {
			t.Errorf("message %d: %+v", i, r)
		}
	}
	if n := len(s.Requests()); n != 2 {
		t.Fatalf("%d requests, want 2 (9 MiB doesn't fit in one batch)", n)
	}
	for i, r := range s.Requests() {
		raw, _ := json.Marshal(r.Batch)
		if len(raw) > push.MaxBatchBytes {
			t.Errorf("request %d is %d bytes, over the limit", i, len(raw))
		}
	}
}

// Review Focus 3: one message bigger than a whole batch.
func TestSendRejectsOversizeMessageLocally(t *testing.T) {
	s := ingesttest.New(t)
	big := snap("big", strings.Repeat("x", 9<<20))
	res, err := newClient(t, s).Send(t.Context(), big, snap("small", "1"))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != push.StatusRejected || !strings.Contains(res[0].Error, "larger than a batch") {
		t.Fatalf("big: %+v", res[0])
	}
	if res[1].Status != push.StatusAccepted {
		t.Fatalf("small: %+v", res[1])
	}
	for _, r := range s.Requests() {
		for _, m := range r.Batch.Messages {
			if m.ID == "big" {
				t.Fatal("the oversize message was sent")
			}
		}
	}
}

func TestSendSplitsOn413(t *testing.T) {
	// A server whose limit is lower than witness's: it takes one message at a time.
	var batches []int
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b push.Batch
		_ = json.NewDecoder(r.Body).Decode(&b)
		batches = append(batches, len(b.Messages))
		if len(b.Messages) > 1 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_ = json.NewEncoder(w).Encode(push.Response{Version: 1, Results: []push.Result{{ID: b.Messages[0].ID, Status: push.StatusAccepted}}})
	}))
	defer hs.Close()
	c, err := client.New(hs.URL, "hpk_x", fast)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Send(t.Context(), snaps(3)...)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range res {
		if r.Status != push.StatusAccepted {
			t.Errorf("message %d: %+v", i, r)
		}
	}
	if fmt.Sprint(batches) != "[3 1 2 1 1]" {
		t.Fatalf("batches %v, want [3 1 2 1 1]", batches)
	}
}

func TestSendRetries5xx(t *testing.T) {
	s := ingesttest.New(t)
	s.FailNext(2, http.StatusServiceUnavailable)
	res, err := newClient(t, s).Send(t.Context(), snap("m1", "1"))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != push.StatusAccepted || len(s.Requests()) != 3 {
		t.Fatalf("result %+v after %d requests, want accepted after 3", res[0], len(s.Requests()))
	}
}

func TestSendResendIsSafe(t *testing.T) {
	s := ingesttest.New(t)
	s.FailAfterStoring(1)
	res, err := newClient(t, s).Send(t.Context(), snap("m1", "1"))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != push.StatusDuplicate || res[0].EvidenceID == "" {
		t.Fatalf("result %+v, want duplicate with an evidence id", res[0])
	}
}

func TestSendDoesNotRetry400(t *testing.T) {
	s := ingesttest.New(t)
	s.FailNext(1, http.StatusBadRequest)
	res, err := newClient(t, s).Send(t.Context(), snap("m1", "1"), snap("m2", "2"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.Requests()); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
	for _, r := range res {
		if r.Status != push.StatusRejected || !strings.Contains(r.Error, "Bad Request") {
			t.Errorf("%+v, want rejected with the server's text", r)
		}
	}
}

func TestSendUnauthorized(t *testing.T) {
	s := ingesttest.New(t)
	c, err := client.New(s.URL, "hpk_wrong", fast)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(t.Context(), snap("m1", "1")); !errors.Is(err, client.ErrUnauthorized) {
		t.Fatalf("err %v, want ErrUnauthorized", err)
	}
	if n := len(s.Requests()); n != 1 {
		t.Fatalf("%d requests, want 1", n)
	}
}

func TestSendGivesUp(t *testing.T) {
	s := ingesttest.New(t)
	s.FailNext(10, http.StatusServiceUnavailable)
	_, err := newClient(t, s, client.WithMaxAttempts(3)).Send(t.Context(), snap("m1", "1"))
	if !errors.Is(err, client.ErrUnavailable) {
		t.Fatalf("err %v, want ErrUnavailable", err)
	}
	if n := len(s.Requests()); n != 3 {
		t.Fatalf("%d requests, want 3", n)
	}
}

func TestSendHonoursContext(t *testing.T) {
	s := ingesttest.New(t)
	s.FailNext(100, http.StatusServiceUnavailable)
	c, err := client.New(s.URL, s.Key, client.WithBackoff(time.Second, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Send(ctx, snap("m1", "1"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v, want the context's", err)
	}
	if took := time.Since(start); took > 80*time.Millisecond {
		t.Fatalf("Send took %v after its context ended", took)
	}
}

func TestHeaders(t *testing.T) {
	s := ingesttest.New(t)
	if _, err := newClient(t, s, client.WithUserAgent("witness-go/9.9.9")).Send(t.Context(), snap("m1", "1")); err != nil {
		t.Fatal(err)
	}
	h := s.Requests()[0].Header
	for k, want := range map[string]string{
		"Authorization": "Bearer " + s.Key,
		"Content-Type":  "application/json",
		"User-Agent":    "witness-go/9.9.9",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
}
