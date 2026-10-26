package brokercore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

// fakeOAuthStore holds one OAuth credential and records token updates.
type fakeOAuthStore struct {
	mu        sync.Mutex
	cfg       store.CredentialOAuth
	updated   chan string // decrypted refresh token of each stored update
	updateErr []error     // the update's context error, per update
	key       []byte
}

func (f *fakeOAuthStore) GetCredentialOAuth(_ context.Context, _, _ string) (*store.CredentialOAuth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cfg := f.cfg
	return &cfg, nil
}

func (f *fakeOAuthStore) UpdateCredentialOAuthTokens(ctx context.Context, _, _ string, _, _, refreshCT, refreshNonce []byte, expiresAt *time.Time) error {
	if err := ctx.Err(); err != nil {
		f.mu.Lock()
		f.updateErr = append(f.updateErr, err)
		f.mu.Unlock()
		return err
	}
	refresh, err := crypto.Decrypt(refreshCT, refreshNonce, f.key)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.cfg.RefreshTokenCT, f.cfg.RefreshTokenNonce, f.cfg.TokenExpiresAt = refreshCT, refreshNonce, expiresAt
	f.mu.Unlock()
	f.updated <- string(refresh)
	return nil
}

func (f *fakeOAuthStore) UpdateCredentialOAuthError(_ context.Context, _, _ string, _ string) error {
	return nil
}

// newExpiredOAuth returns a store holding an expired credential whose
// refresh token is "old", refreshed at tokenURL.
func newExpiredOAuth(t *testing.T, key []byte, tokenURL string) *fakeOAuthStore {
	t.Helper()
	ct, nonce, err := crypto.Encrypt([]byte("old"), key)
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Minute)
	return &fakeOAuthStore{
		cfg: store.CredentialOAuth{
			TokenURL:          tokenURL,
			ClientID:          "client",
			RefreshTokenCT:    ct,
			RefreshTokenNonce: nonce,
			TokenExpiresAt:    &expired,
		},
		updated: make(chan string, 4),
		key:     key,
	}
}

// slowRotatingEndpoint answers every refresh with refresh token "rotated"
// after delay, signalling started when a request arrives.
func slowRotatingEndpoint(t *testing.T, delay time.Duration) (*httptest.Server, chan struct{}) {
	t.Helper()
	started := make(chan struct{}, 4)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": "rotated",
		})
	}))
	t.Cleanup(ts.Close)
	prev := oauth.TokenClient
	oauth.TokenClient = ts.Client()
	t.Cleanup(func() { oauth.TokenClient = prev })
	return ts, started
}

func TestMaybeRefreshOAuth_StoresTheRotatedTokenWhenTheRequestIsCancelledMidRefresh(t *testing.T) {
	key := make32(7)
	ts, started := slowRotatingEndpoint(t, 300*time.Millisecond)
	oauthStore := newExpiredOAuth(t, key, ts.URL)
	p := &StoreCredentialProvider{OAuthStore: oauthStore, EncKey: key, Refresher: oauth.NewRefresher()}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.maybeRefreshOAuth(ctx, "v", "K", "current")
	}()
	<-started
	cancel()

	select {
	case got := <-oauthStore.updated:
		if got != "rotated" {
			t.Fatalf("stored refresh token %q, want rotated", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("rotated token never stored (update context errors: %v)", oauthStore.updateErr)
	}
	<-done
}

func TestRefresher_WaitReturnsOnceRunningRefreshesFinish(t *testing.T) {
	key := make32(8)
	ts, started := slowRotatingEndpoint(t, 300*time.Millisecond)
	oauthStore := newExpiredOAuth(t, key, ts.URL)
	refresher := oauth.NewRefresher()
	p := &StoreCredentialProvider{OAuthStore: oauthStore, EncKey: key, Refresher: refresher}

	go func() { _, _ = p.maybeRefreshOAuth(context.Background(), "v", "K", "current") }()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := refresher.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	select {
	case <-oauthStore.updated:
	default:
		t.Fatal("Wait returned before the refresh stored its tokens")
	}
}

func TestRefresher_WaitReturnsAtOnceWithNothingRunning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := oauth.NewRefresher().Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}
