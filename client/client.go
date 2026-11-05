// Package client sends evidence to Hallproof's ingest API.
//
// Send pushes messages and waits for Hallproof's answers. Enqueue hands
// messages to a background sender that never blocks the caller, which is
// what witness's collectors use. Both batch messages within Hallproof's
// limits, retry what's worth retrying, and never retry what isn't.
package client

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// Errors Send returns. A message Hallproof refused is not an error: it comes
// back as a "rejected" or "unsupported" result.
var (
	// ErrUnauthorized means Hallproof refused the ingest key: it is wrong,
	// or someone revoked it.
	ErrUnauthorized = errors.New("witness: hallproof refused the ingest key")
	// ErrUnavailable means Hallproof couldn't be reached, or kept failing,
	// for every attempt Send was allowed.
	ErrUnavailable = errors.New("witness: hallproof is unavailable")
)

// Defaults for the options below.
const (
	DefaultMinBackoff  = time.Second
	DefaultMaxBackoff  = 5 * time.Minute
	DefaultMaxAttempts = 5
	DefaultTimeout     = 30 * time.Second
	DefaultUserAgent   = "witness-go"
)

// ingestPath is where Hallproof takes batches.
const ingestPath = "/api/v1/ingest"

// Option changes a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client. The default has a 30 second timeout.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithLogger sets where the client logs. The default is slog.Default().
func WithLogger(l *slog.Logger) Option { return func(c *Client) { c.log = l } }

// WithUserAgent sets the User-Agent header. The default is "witness-go".
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// WithBackoff sets the wait between attempts: it starts at minimum and
// doubles up to maximum, with full jitter. The defaults are 1s and 5m.
func WithBackoff(minimum, maximum time.Duration) Option {
	return func(c *Client) { c.minBackoff, c.maxBackoff = minimum, maximum }
}

// WithMaxAttempts sets how many times Send tries one batch before it gives
// up with ErrUnavailable. The default is 5. The background sender has no
// limit: its queue's size bounds it instead.
func WithMaxAttempts(n int) Option { return func(c *Client) { c.maxAttempts = n } }

// Client sends evidence to one Hallproof system, named by its ingest key.
// It is safe for concurrent use.
type Client struct {
	url        string
	key        string
	userAgent  string
	http       *http.Client
	log        *slog.Logger
	minBackoff time.Duration
	maxBackoff time.Duration

	maxAttempts int
}

// New returns a Client for the Hallproof at endpoint, such as
// "https://hallproof.example.com", pushing with ingestKey.
//
// The endpoint must be HTTPS. Plain HTTP is allowed only to a loopback
// address, for local development, so a key never crosses a network in
// clear text.
func New(endpoint, ingestKey string, opts ...Option) (*Client, error) {
	u, err := checkEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if ingestKey == "" || strings.IndexFunc(ingestKey, unicode.IsSpace) >= 0 {
		return nil, errors.New("witness: the ingest key must be set and contain no spaces")
	}
	c := &Client{
		url:         strings.TrimSuffix(u.String(), "/") + ingestPath,
		key:         ingestKey,
		userAgent:   DefaultUserAgent,
		http:        &http.Client{Timeout: DefaultTimeout},
		log:         slog.Default(),
		minBackoff:  DefaultMinBackoff,
		maxBackoff:  DefaultMaxBackoff,
		maxAttempts: DefaultMaxAttempts,
	}
	for _, o := range opts {
		o(c)
	}
	if c.minBackoff <= 0 || c.maxBackoff < c.minBackoff {
		return nil, fmt.Errorf("witness: backoff must be positive with max >= min, got %v and %v", c.minBackoff, c.maxBackoff)
	}
	if c.maxAttempts < 1 {
		return nil, errors.New("witness: max attempts must be at least 1")
	}
	return c, nil
}

func checkEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("witness: the endpoint %q isn't an absolute URL", endpoint)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if isLoopback(u.Hostname()) {
			return u, nil
		}
		return nil, fmt.Errorf("witness: the endpoint %q must use https (plain http is only for localhost)", endpoint)
	}
	return nil, fmt.Errorf("witness: the endpoint %q must use https", endpoint)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
