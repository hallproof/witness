package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hallproof/witness/push"
)

// envelope is the size of an empty batch, `{"version":1,"messages":[]}`.
const envelope = len(`{"version":1,"messages":[]}`)

// Send pushes msgs and returns one result per message, in the same order.
//
// It splits msgs into batches within Hallproof's limits. A message too big
// to fit in any batch is answered "rejected" without being sent. Network
// errors, 429 and 5xx are retried with backoff, up to the client's attempt
// limit. A 400 answers every message in that batch "rejected" with
// Hallproof's reason and isn't retried.
//
// A message of a kind Hallproof recently answered "unsupported" isn't sent:
// it gets an "unsupported" result straight away (see WithHoldBack).
//
// The error is ErrUnauthorized, ErrUnavailable or the context's. When it is
// set, the messages Send didn't get an answer for have an empty Status.
func (c *Client) Send(ctx context.Context, msgs ...push.Message) ([]push.Result, error) {
	results := make([]push.Result, len(msgs))
	c.holdBackKinds(msgs, results)
	var err error
	for _, b := range c.plan(msgs, results) {
		if err = c.sendBatch(ctx, msgs, b, results, c.maxAttempts); err != nil {
			break
		}
	}
	c.account(msgs, results)
	return results, err
}

// plan answers oversize messages in results and groups the rest, by index,
// into batches within MaxMessages and MaxBatchBytes. Messages that already
// have a result are skipped.
func (c *Client) plan(msgs []push.Message, results []push.Result) [][]int {
	var (
		batches [][]int
		cur     = make([]int, 0, min(len(msgs), push.MaxMessages))
		size    = envelope
	)
	for i, m := range msgs {
		if results[i].Status != "" {
			continue
		}
		n, err := encodedSize(m)
		switch {
		case err != nil:
			results[i] = push.Result{ID: m.ID, Status: push.StatusRejected, Error: "witness: the message can't be encoded: " + err.Error()}
			continue
		case envelope+n > push.MaxBatchBytes:
			results[i] = push.Result{ID: m.ID, Status: push.StatusRejected,
				Error: fmt.Sprintf("witness: the message is %d bytes, larger than a batch can be (%d)", n, push.MaxBatchBytes)}
			continue
		}
		extra := n
		if len(cur) > 0 {
			extra++ // the comma
		}
		if len(cur) == push.MaxMessages || size+extra > push.MaxBatchBytes {
			batches = append(batches, cur)
			cur, size, extra = make([]int, 0, min(len(msgs)-i, push.MaxMessages)), envelope, n
		}
		cur = append(cur, i)
		size += extra
	}
	if len(cur) > 0 {
		batches = append(batches, cur)
	}
	return batches
}

func encodedSize(m push.Message) (int, error) {
	b, err := json.Marshal(m)
	return len(b), err
}

// sendBatch sends the messages at idx as one batch and writes their results.
// attempts <= 0 means no limit. A 413 splits the batch in two.
func (c *Client) sendBatch(ctx context.Context, msgs []push.Message, idx []int, results []push.Result, attempts int) error {
	batch := push.Batch{Version: push.Version, Messages: make([]push.Message, len(idx))}
	for j, i := range idx {
		batch.Messages[j] = msgs[i]
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("witness: encode batch: %w", err)
	}

	var last error
	for attempt := 0; attempts <= 0 || attempt < attempts; attempt++ {
		if attempt > 0 {
			if attempts <= 0 && attempt == 1 {
				// The background sender retries without a limit, so say once
				// per streak that it isn't getting through.
				c.log.Warn("witness: can't push to hallproof; messages stay queued and retry", "error", last)
			}
			if err := c.wait(ctx, attempt, last); err != nil {
				return err
			}
		}
		out := c.post(ctx, body)
		switch {
		case out.err != nil:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			last = out
			continue
		case out.status == http.StatusOK:
			if err := matchResults(batch, out.resp); err != nil {
				last = err
				continue
			}
			for j, i := range idx {
				results[i] = out.resp.Results[j]
			}
			return nil
		case out.status == http.StatusBadRequest:
			reason := "hallproof refused the batch: " + out.text
			for _, i := range idx {
				results[i] = push.Result{ID: msgs[i].ID, Status: push.StatusRejected, Error: reason}
			}
			return nil
		case out.status == http.StatusUnauthorized:
			return ErrUnauthorized
		case out.status == http.StatusRequestEntityTooLarge:
			if len(idx) == 1 {
				results[idx[0]] = push.Result{ID: msgs[idx[0]].ID, Status: push.StatusRejected,
					Error: "witness: the message is larger than hallproof takes in one batch"}
				return nil
			}
			half := len(idx) / 2
			if err := c.sendBatch(ctx, msgs, idx[:half], results, attempts); err != nil {
				return err
			}
			return c.sendBatch(ctx, msgs, idx[half:], results, attempts)
		default:
			// 429, 5xx, or anything unexpected such as a proxy's 404:
			// the messages aren't at fault, so try again later.
			last = out
		}
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, last)
}

// outcome is one HTTP attempt. It is an error so a failed attempt can be
// carried as the reason Send gave up.
type outcome struct {
	status     int
	resp       push.Response
	text       string
	retryAfter time.Duration
	err        error
}

func (o outcome) Error() string {
	if o.err != nil {
		return o.err.Error()
	}
	if o.text != "" {
		return fmt.Sprintf("hallproof answered %d: %s", o.status, o.text)
	}
	return fmt.Sprintf("hallproof answered %d", o.status)
}

func (c *Client) post(ctx context.Context, body []byte) outcome {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return outcome{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	res, err := c.http.Do(req)
	if err != nil {
		return outcome{err: err}
	}
	defer res.Body.Close()

	out := outcome{status: res.StatusCode, retryAfter: retryAfter(res.Header.Get("Retry-After"))}
	if res.StatusCode == http.StatusOK {
		dec := json.NewDecoder(io.LimitReader(res.Body, 16<<20))
		if err := dec.Decode(&out.resp); err != nil {
			out.err = fmt.Errorf("witness: hallproof's answer isn't a response: %w", err)
		}
		return out
	}
	if text, err := io.ReadAll(io.LimitReader(res.Body, 1024)); err == nil {
		out.text = strings.TrimSpace(string(text))
	}
	return out
}

// matchResults checks Hallproof answered every message in the batch, in
// order.
func matchResults(b push.Batch, r push.Response) error {
	if len(r.Results) != len(b.Messages) {
		return fmt.Errorf("witness: hallproof answered %d results for %d messages", len(r.Results), len(b.Messages))
	}
	for i, res := range r.Results {
		if res.ID != b.Messages[i].ID {
			return fmt.Errorf("witness: result %d is for %q, not %q", i, res.ID, b.Messages[i].ID)
		}
	}
	return nil
}

// wait sleeps before attempt (1 or more): full jitter over an exponential
// ceiling, and no less than a Retry-After the server asked for, up to the
// maximum backoff.
func (c *Client) wait(ctx context.Context, attempt int, last error) error {
	d := c.backoff(attempt)
	var o outcome
	if errors.As(last, &o) && o.retryAfter > d {
		d = min(o.retryAfter, c.maxBackoff)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) backoff(attempt int) time.Duration {
	ceiling := c.maxBackoff
	if attempt < 31 {
		if d := c.minBackoff << (attempt - 1); d > 0 && d < ceiling {
			ceiling = d
		}
	}
	return time.Duration(rand.Int64N(int64(ceiling))) + 1 // #nosec G404 -- jitter, not a secret
}

// retryAfter reads a Retry-After header given in seconds. Dates are rare
// from an API and are ignored.
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}
