//go:build unix

package cmd

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Infisical/agent-vault/internal/connpass"
	"github.com/Infisical/agent-vault/internal/lifelock"
	"github.com/Infisical/agent-vault/internal/server"
)

// controlLockWait bounds how long a server waits for the previous one to
// exit: its shutdown waits up to 35 s for a running OAuth refresh.
const controlLockWait = 40 * time.Second

// controlMode is `server --control-fd N`: the parent passes every API and
// proxy connection over the Unix socket on fd N (package connpass), so the
// server binds no port, and it stops when the parent's end closes, which
// the kernel does however the parent exits. A lifelock replaces the PID
// file: the next server waits for this one to be gone.
type controlMode struct {
	control    *net.UnixConn
	api, proxy *connpass.Listener
	lock       *lifelock.Lock
}

func openControlMode(fd int) (*controlMode, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolving home: %w", err)
	}
	dir := filepath.Join(home, ".agent-vault")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	lock, err := lifelock.Acquire(filepath.Join(dir, "agent-vault.lock"), controlLockWait)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "control")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		lock.Release()
		return nil, fmt.Errorf("--control-fd %d: %w", fd, err)
	}
	control, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		lock.Release()
		return nil, fmt.Errorf("--control-fd %d is not a Unix socket", fd)
	}
	return &controlMode{
		control: control,
		api:     connpass.NewListener("api"),
		proxy:   connpass.NewListener("proxy"),
		lock:    lock,
	}, nil
}

// attach makes srv serve passed connections and stop once the parent's
// end of the control socket closes.
func (m *controlMode) attach(srv *server.Server) {
	srv.SetPassedListeners(m.api, m.proxy)
	go func() {
		if err := connpass.Serve(m.control, m.api, m.proxy); err != nil {
			fmt.Fprintf(os.Stderr, "warning: control socket: %v\n", err)
		}
		srv.Stop()
	}()
}

func (m *controlMode) close() {
	_ = m.control.Close()
	m.lock.Release()
}
