package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// tunnelCredProvider is a fakeCredProvider that tunnels every host in tunnel.
type tunnelCredProvider struct {
	fakeCredProvider
	tunnel map[string]bool
}

func (f *tunnelCredProvider) ShouldTunnel(_ context.Context, _, host string, _ int) bool {
	return f.tunnel[host]
}

func tunnelScope() brokercore.SessionResolver {
	return validTokenResolver("av_sess_ok",
		&brokercore.ProxyScope{AgentID: "agent1", VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
}

// openConnect sends an authenticated CONNECT and returns the connection, its
// reader and the status.
func openConnect(t *testing.T, proxyURL *url.URL, target, token string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: http.Header{},
	}
	if token != "" {
		req.SetBasicAuth(token, "")
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	return conn, br, resp.StatusCode
}

// echoServer answers each connection by echoing it until the client's EOF,
// then closing.
func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().String()
}

func TestMITMTunnelShowsTheUpstreamsRealCertificate(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "real")
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	proxyURL, _, _ := setupProxy(t, tunnelScope(), &tunnelCredProvider{tunnel: map[string]bool{host: true}})

	// Trusts only the upstream's certificate, never the proxy's CA.
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	resp, err := newTrustingClient(proxyURL, url.User("av_sess_ok"), roots).Get(upstream.URL + "/x")
	if err != nil {
		t.Fatalf("client.Get through tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "real" {
		t.Fatalf("body = %q", body)
	}
}

func TestMITMTunnelCarriesBytesBothWaysAndPropagatesEOF(t *testing.T) {
	target := echoServer(t)
	host, _, _ := net.SplitHostPort(target)
	proxyURL, _, _ := setupProxy(t, tunnelScope(), &tunnelCredProvider{tunnel: map[string]bool{host: true}})

	conn, br, status := openConnect(t, proxyURL, target, "av_sess_ok")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	payload := strings.Repeat("crate", 200_000)
	go func() {
		_, _ = io.WriteString(conn, payload)
		_ = conn.(*net.TCPConn).CloseWrite()
	}()
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echoed %d bytes, want %d", len(got), len(payload))
	}
}

func TestMITMHostThatMustNotTunnelStaysReSigned(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	cp := &tunnelCredProvider{
		fakeCredProvider: fakeCredProvider{byHost: map[string]fakeInjectResult{
			host: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer real"}}},
		}},
	}
	proxyURL, clientRoots, p := setupProxy(t, tunnelScope(), cp)
	p.upstream.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // httptest upstream

	resp, err := newTrustingClient(proxyURL, url.User("av_sess_ok"), clientRoots).Get(upstream.URL + "/x")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Bearer real" {
		t.Fatalf("upstream saw %q, want the injected credential", body)
	}
}

func TestMITMTunnelNeedsProxyAuth(t *testing.T) {
	target := echoServer(t)
	host, _, _ := net.SplitHostPort(target)
	proxyURL, _, _ := setupProxy(t, tunnelScope(), &tunnelCredProvider{tunnel: map[string]bool{host: true}})

	if _, _, status := openConnect(t, proxyURL, target, ""); status != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", status)
	}
}

func TestMITMTunnelBlockedAddressAnswers502BeforeOpening(t *testing.T) {
	target := echoServer(t)
	host, _, _ := net.SplitHostPort(target)
	proxyURL, _, p := setupProxy(t, tunnelScope(), &tunnelCredProvider{tunnel: map[string]bool{host: true}})
	p.upstream.DialContext = netguard.SafeDialContext(false)

	if _, _, status := openConnect(t, proxyURL, target, "av_sess_ok"); status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", status)
	}
}

func TestMITMTunnelHonoursTheProxyRateLimit(t *testing.T) {
	target := echoServer(t)
	host, _, _ := net.SplitHostPort(target)
	proxyURL, _, p := setupProxy(t, tunnelScope(), &tunnelCredProvider{tunnel: map[string]bool{host: true}})
	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	cfg.Tiers[ratelimit.TierProxy].Rate = 0.001
	cfg.Tiers[ratelimit.TierProxy].Burst = 1
	p.rateLimit = ratelimit.New(cfg)

	if _, _, status := openConnect(t, proxyURL, target, "av_sess_ok"); status != http.StatusOK {
		t.Fatalf("first status = %d, want 200", status)
	}
	if _, _, status := openConnect(t, proxyURL, target, "av_sess_ok"); status != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", status)
	}
}

// An open tunnel may idle in a client's pool, so it mustn't hold a request
// slot the way an in-flight request does.
func TestMITMOpenTunnelsDoNotHoldProxyConcurrency(t *testing.T) {
	target := echoServer(t)
	host, _, _ := net.SplitHostPort(target)
	proxyURL, _, p := setupProxy(t, tunnelScope(), &tunnelCredProvider{tunnel: map[string]bool{host: true}})
	cfg := ratelimit.DefaultsFor(ratelimit.ProfileDefault)
	cfg.Tiers[ratelimit.TierProxy].Concurrency = 1
	p.rateLimit = ratelimit.New(cfg)

	for i := range 3 {
		if _, _, status := openConnect(t, proxyURL, target, "av_sess_ok"); status != http.StatusOK {
			t.Fatalf("tunnel %d status = %d, want 200", i, status)
		}
	}
}

func TestMITMTunnelEmitsARequestLogRow(t *testing.T) {
	target := echoServer(t)
	host, _, _ := net.SplitHostPort(target)
	sink := &recordingSink{}
	proxyURL, _, _ := setupProxy(t, tunnelScope(), &tunnelCredProvider{tunnel: map[string]bool{host: true}},
		func(o *Options) { o.LogSink = sink })

	conn, _, status := openConnect(t, proxyURL, target, "av_sess_ok")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	_ = conn.Close()

	row := sink.waitForRows(t, 1)[0]
	if row.Method != http.MethodConnect || row.Host != target || row.Status != http.StatusOK || row.ErrorCode != "" {
		t.Fatalf("row = %s", fmt.Sprintf("%+v", row))
	}
}
