//go:build unix

// Package connpass serves connections a parent process passes over a
// private control socket (SCM_RIGHTS), instead of listening on a port.
// Nothing on the machine can reach the server except through its parent,
// and the control socket's EOF says the parent is gone.
package connpass

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Each message on the control socket is one tag byte with one descriptor.
const (
	TagAPI   byte = 'A'
	TagProxy byte = 'P'
)

// Listener is a net.Listener fed by Serve.
type Listener struct {
	addr   addr
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func NewListener(name string) *Listener {
	return &Listener{
		addr:   addr(name),
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *Listener) Addr() net.Addr { return l.addr }

// deliver hands c to Accept, or closes it once the listener is closed.
func (l *Listener) deliver(c net.Conn) {
	select {
	case l.conns <- c:
	case <-l.closed:
		_ = c.Close()
	}
}

type addr string

func (a addr) Network() string { return "connpass" }
func (a addr) String() string  { return string(a) }

// Serve delivers each passed connection to api or proxy by its tag, until
// the parent's end of control closes (nil) or reading it fails.
func Serve(control *net.UnixConn, api, proxy *Listener) error {
	tag := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := control.ReadMsgUnix(tag, oob)
		if n == 0 && oobn == 0 {
			if err == nil || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		for _, f := range passedFiles(oob[:oobn]) {
			c := fileConn(f)
			switch {
			case n == 1 && tag[0] == TagAPI:
				go api.deliver(c)
			case n == 1 && tag[0] == TagProxy:
				go proxy.deliver(c)
			default:
				_ = c.Close()
			}
		}
	}
}

func passedFiles(oob []byte) []*os.File {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var files []*os.File
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			syscall.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "passed"))
		}
	}
	return files
}

// fileConn turns a passed descriptor into a net.Conn. net.FileConn knows
// TCP and Unix sockets; anything else (a vsock socket, a pipe) is served
// through the file itself.
func fileConn(f *os.File) net.Conn {
	if c, err := net.FileConn(f); err == nil {
		_ = f.Close()
		return c
	}
	return &osConn{File: f}
}

type osConn struct{ *os.File }

func (c *osConn) LocalAddr() net.Addr  { return addr("passed") }
func (c *osConn) RemoteAddr() net.Addr { return addr("passed") }

func (c *osConn) SetDeadline(t time.Time) error      { return c.File.SetDeadline(t) }
func (c *osConn) SetReadDeadline(t time.Time) error  { return c.File.SetReadDeadline(t) }
func (c *osConn) SetWriteDeadline(t time.Time) error { return c.File.SetWriteDeadline(t) }
