package server

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStart_ServesOnAnInjectedListenerAndStopsOnRequestWithoutAPIDFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".agent-vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// An address Start must not bind: the injected listener replaces it.
	srv := New("127.0.0.1:1", newMockStore(), make([]byte, 32), nil, true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))
	srv.SetPassedListeners(ln, nil)

	done := make(chan error, 1)
	go func() { done <- srv.Start() }()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health: %d", resp.StatusCode)
	}
	if _, err := os.Stat(filepath.Join(home, ".agent-vault", "agent-vault.pid")); !os.IsNotExist(err) {
		t.Fatalf("PID file written: %v", err)
	}

	srv.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Start: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Start didn't return after Stop")
	}
}
