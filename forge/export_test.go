package forge

import "time"

// WithCoverageEvery sets how often the coverage snapshot runs, so a test
// sees it in milliseconds instead of up to 30 seconds.
func WithCoverageEvery(d time.Duration) Option {
	return func(e *Extension) { e.coverageEvery = d }
}
