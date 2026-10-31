//go:build unix

package cmd

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/connpass"
)

// passConn sends a fresh socket pair's far end over parent with tag and
// returns the near end.
func passConn(t *testing.T, parent *net.UnixConn, tag byte) net.Conn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parent.WriteMsgUnix([]byte{tag}, syscall.UnixRights(fds[1]), nil); err != nil {
		t.Fatal(err)
	}
	// macOS can flush an in-flight Unix socket whose sender already closed
	// its copy, so keep this copy until the server acks with the tag.
	ack := make([]byte, 1)
	_ = parent.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := parent.Read(ack); err != nil || ack[0] != tag {
		t.Fatalf("ack: %v, %v", ack, err)
	}
	_ = syscall.Close(fds[1])
	f := os.NewFile(uintptr(fds[0]), "near")
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// resetServerFlags undoes flag values a test set: cobra keeps them across
// in-process runs.
func resetServerFlags(t *testing.T) {
	t.Cleanup(func() {
		_ = serverCmd.Flags().Set("control-fd", "0")
		_ = serverCmd.Flags().Set("detach", "false")
	})
}

func TestServerCmd_ControlFdServesPassedConnectionsAndExitsWhenTheParentCloses(t *testing.T) {
	resetServerFlags(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "test-password")
	t.Setenv("AGENT_VAULT_TELEMETRY", "false")

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	pf := os.NewFile(uintptr(fds[0]), "parent")
	pc, err := net.FileConn(pf)
	_ = pf.Close()
	if err != nil {
		t.Fatal(err)
	}
	parent := pc.(*net.UnixConn)

	done := make(chan error, 1)
	go func() {
		_, err := executeCommand("server", "--control-fd", strconv.Itoa(fds[1]))
		done <- err
	}()

	conn := passConn(t, parent, connpass.TagAPI)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET /health HTTP/1.1\r\nHost: agent-vault\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("health over a passed connection: %q, %v", status, err)
	}
	_ = conn.Close()
	if _, err := os.Stat(filepath.Join(home, ".agent-vault", "agent-vault.pid")); !os.IsNotExist(err) {
		t.Fatalf("PID file written: %v", err)
	}

	_ = parent.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server still running after the parent's end closed")
	}
}

func TestServerCmd_ControlFdRefusesDetach(t *testing.T) {
	resetServerFlags(t)
	t.Setenv("HOME", t.TempDir())
	_, err := executeCommand("server", "--control-fd", "3", "--detach")
	if err == nil || !strings.Contains(err.Error(), "--detach") {
		t.Fatalf("got %v, want a refusal naming --detach", err)
	}
}
