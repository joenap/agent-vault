//go:build unix

package lifelock

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquire_TakesAFreeLockAtOnce(t *testing.T) {
	l, err := Acquire(filepath.Join(t.TempDir(), "server.lock"), time.Second)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	l.Release()
}

func TestAcquire_WaitsForTheHolderToRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.lock")
	held, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		held.Release()
	}()
	started := time.Now()
	l, err := Acquire(path, 5*time.Second)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer l.Release()
	if waited := time.Since(started); waited < 250*time.Millisecond {
		t.Fatalf("acquired after %v, while still held", waited)
	}
}

func TestAcquire_GivesUpAfterWaitWhileHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.lock")
	held, err := Acquire(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	started := time.Now()
	_, err = Acquire(path, 300*time.Millisecond)
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("Acquire: %v, want ErrHeld", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("gave up after %v", waited)
	}
}
