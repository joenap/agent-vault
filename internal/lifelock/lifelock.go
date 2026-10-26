//go:build unix

// Package lifelock holds an exclusive lock on a file for a server's whole
// life. The kernel releases it when the process exits, however it exits,
// so unlike a PID file it never goes stale: a new server waits for the old
// one to be gone, never runs alongside it on the same data.
package lifelock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// ErrHeld means another process still holds the lock.
var ErrHeld = errors.New("another server holds the lock")

const retry = 50 * time.Millisecond

// Lock is a held lock.
type Lock struct{ f *os.File }

// Acquire takes the lock at path, waiting up to wait while another process
// holds it.
func Acquire(path string, wait time.Duration) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &Lock{f: f}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("locking %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrHeld
		}
		time.Sleep(retry)
	}
}

// Release drops the lock (exiting does too).
func (l *Lock) Release() { _ = l.f.Close() }
