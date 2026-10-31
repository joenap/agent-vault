package mitm

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

const tunnelDialTimeout = 10 * time.Second

// tunnel splices an authenticated CONNECT to target without terminating
// TLS, so the client verifies the upstream's own certificate and no
// credential can be attached. Dial failures answer before the 200, while a
// status can still be sent. The dial goes through the same guarded dialer
// as forwarded requests. A tunnel counts against the proxy rate at open but
// holds no concurrency slot, since it may idle in a client's pool.
func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope) {
	start := time.Now()
	event := brokercore.ProxyEvent{
		Ingress: brokercore.IngressMITM,
		Method:  http.MethodConnect,
		Host:    target,
	}
	actorType, actorID := actorFromScope(scope)
	emit := func(status int, errCode string) {
		event.Emit(p.logger, start, status, errCode)
		p.logSink.Record(context.WithoutCancel(r.Context()), requestlog.FromEvent(event, scope.VaultID, actorType, actorID))
	}

	enf := p.rateLimit.EnforceProxy(r.Context(), scope.ActorID(), scope.VaultID)
	if !enf.Allowed {
		ratelimit.WriteDenial(w, enf.Decision, enf.Message)
		emit(http.StatusTooManyRequests, enf.ErrCode)
		return
	}
	enf.Release()

	dialCtx, cancel := context.WithTimeout(r.Context(), tunnelDialTimeout)
	defer cancel()
	upstream, err := p.upstream.DialContext(dialCtx, "tcp", target)
	if err != nil {
		p.logger.Warn("mitm tunnel dial failed", "target", target, "err", err.Error())
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "upstream_error")
		return
	}
	defer upstream.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		emit(http.StatusInternalServerError, "internal")
		return
	}
	client, buffered, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		emit(http.StatusInternalServerError, "internal")
		return
	}
	defer client.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		emit(http.StatusBadGateway, "client_error")
		return
	}

	// The client may have sent past the CONNECT request already.
	var fromClient io.Reader = client
	if n := buffered.Reader.Buffered(); n > 0 {
		fromClient = io.MultiReader(io.LimitReader(buffered.Reader, int64(n)), client)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, fromClient)
		closeWrite(upstream)
	}()
	_, _ = io.Copy(client, upstream)
	closeWrite(client)
	<-done
	emit(http.StatusOK, "")
}

// closeWrite passes one direction's EOF on while the other keeps flowing,
// falling back to a full close on a connection that can't half-close.
func closeWrite(c net.Conn) {
	if hc, ok := c.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
		return
	}
	_ = c.Close()
}
