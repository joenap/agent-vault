package oauth

import (
	"context"
	"sync"

	"golang.org/x/sync/singleflight"
)

// RefreshResult is the outcome of a single refresh attempt, shared across all
// concurrent callers for the same key via singleflight.
type RefreshResult struct {
	AccessToken string
	Refreshed   bool
	Err         error
}

// Refresher deduplicates concurrent token refreshes using singleflight so that
// multiple goroutines waiting on the same credential see one network call.
type Refresher struct {
	group singleflight.Group

	mu      sync.Mutex
	running int
	idle    chan struct{} // closed when running drops to 0
}

// NewRefresher returns a ready-to-use Refresher.
func NewRefresher() *Refresher {
	return &Refresher{}
}

// Do executes fn at most once for the given key at any point in time.
// Concurrent callers with the same key block until the first caller's fn
// returns, then all receive the same RefreshResult.
func (r *Refresher) Do(key string, fn func() RefreshResult) RefreshResult {
	v, _, _ := r.group.Do(key, func() (interface{}, error) {
		r.begin()
		defer r.end()
		res := fn()
		return res, nil
	})
	return v.(RefreshResult)
}

func (r *Refresher) begin() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running == 0 {
		r.idle = make(chan struct{})
	}
	r.running++
}

func (r *Refresher) end() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running--
	if r.running == 0 {
		close(r.idle)
	}
}

// Wait blocks until no refresh is running, or ctx ends. Shutdown calls it
// so a refresh the provider has already rotated gets stored before exit.
func (r *Refresher) Wait(ctx context.Context) error {
	r.mu.Lock()
	if r.running == 0 {
		r.mu.Unlock()
		return nil
	}
	idle := r.idle
	r.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
