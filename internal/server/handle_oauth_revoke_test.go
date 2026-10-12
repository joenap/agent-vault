package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

// oauthMockStore keeps credential_oauth rows, and deleting a credential
// cascades to its row as the real schema does.
type oauthMockStore struct {
	*mockStore
	oauthRows map[string]*store.CredentialOAuth
}

func (m *oauthMockStore) GetCredentialOAuth(_ context.Context, vaultID, key string) (*store.CredentialOAuth, error) {
	return m.oauthRows[vaultID+":"+key], nil
}

func (m *oauthMockStore) DeleteCredential(ctx context.Context, vaultID, key string) error {
	if err := m.mockStore.DeleteCredential(ctx, vaultID, key); err != nil {
		return err
	}
	delete(m.oauthRows, vaultID+":"+key)
	return nil
}

type revokeFixture struct {
	store    *oauthMockStore
	srv      *Server
	token    string
	provider *httptest.Server
	revoked  []string
	status   int
}

// newRevokeFixture stores an OAuth credential CHATGPT_PLAN whose token
// endpoint is a TLS test provider that records revoked tokens.
func newRevokeFixture(t *testing.T) *revokeFixture {
	t.Helper()
	ms, token := setupMockStoreWithSession(t)
	f := &revokeFixture{
		store:  &oauthMockStore{mockStore: ms, oauthRows: map[string]*store.CredentialOAuth{}},
		token:  token,
		status: http.StatusOK,
	}
	f.provider = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		f.revoked = append(f.revoked, r.PostForm.Get("token"))
		w.WriteHeader(f.status)
	}))
	t.Cleanup(f.provider.Close)

	encKey := make([]byte, 32)
	f.srv = newTestServer(withStore(f.store), withEncKey(encKey))
	saved := oauth.TokenClient
	oauth.TokenClient = f.provider.Client()
	t.Cleanup(func() { oauth.TokenClient = saved })

	accessCT, accessNonce, _ := crypto.Encrypt([]byte("access"), encKey)
	refreshCT, refreshNonce, _ := crypto.Encrypt([]byte("refresh"), encKey)
	if _, err := ms.SetCredential(context.Background(), "root-ns-id", "CHATGPT_PLAN", accessCT, accessNonce); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	f.store.oauthRows["root-ns-id:CHATGPT_PLAN"] = &store.CredentialOAuth{
		VaultID: "root-ns-id", CredentialKey: "CHATGPT_PLAN",
		TokenURL: f.provider.URL + "/oauth/token", ClientID: "pub",
		RefreshTokenCT: refreshCT, RefreshTokenNonce: refreshNonce,
	}
	return f
}

func (f *revokeFixture) revoke(t *testing.T, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/credentials/oauth/revoke", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	f.srv.httpServer.Handler.ServeHTTP(rec, r)
	return rec
}

func (f *revokeFixture) body(key string) string {
	return `{"vault":"default","key":"` + key + `","revocation_url":"` + f.provider.URL + `/oauth/revoke"}`
}

func decodeRevoke(t *testing.T, rec *httptest.ResponseRecorder) oauthRevokeResponse {
	t.Helper()
	var resp oauthRevokeResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func (f *revokeFixture) stored() bool {
	_, ok := f.store.credentials["root-ns-id:CHATGPT_PLAN"]
	return ok || f.store.oauthRows["root-ns-id:CHATGPT_PLAN"] != nil
}

func TestOAuthRevokeRevokesThenDeletes(t *testing.T) {
	f := newRevokeFixture(t)
	rec := f.revoke(t, f.token, f.body("CHATGPT_PLAN"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if resp := decodeRevoke(t, rec); !resp.Revoked || resp.Error != nil {
		t.Fatalf("resp = %+v, want revoked", resp)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "refresh" {
		t.Fatalf("provider saw %q, want the refresh token once", f.revoked)
	}
	if f.stored() {
		t.Fatal("credential still stored after revoke")
	}
}

func TestOAuthRevokeDeletesEvenWhenTheProviderFails(t *testing.T) {
	f := newRevokeFixture(t)
	f.status = http.StatusServiceUnavailable
	rec := f.revoke(t, f.token, f.body("CHATGPT_PLAN"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	resp := decodeRevoke(t, rec)
	if resp.Revoked || resp.Error == nil || !strings.Contains(*resp.Error, "503") {
		t.Fatalf("resp = %+v, want not revoked with the provider's status", resp)
	}
	if f.stored() {
		t.Fatal("credential still stored after a failed revoke")
	}
}

func TestOAuthRevokeOfAMissingKeyIs404(t *testing.T) {
	f := newRevokeFixture(t)
	rec := f.revoke(t, f.token, f.body("NOT_THERE"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(f.revoked) != 0 {
		t.Fatal("provider was called for a missing key")
	}
}

func TestOAuthRevokeRefusesAURLOffTheTokenHost(t *testing.T) {
	for name, toURL := range map[string]func(provider string) string{
		"other host": func(string) string { return "https://evil.example/oauth/revoke" },
		"plain http": func(p string) string { return "http://" + strings.TrimPrefix(p, "https://") + "/oauth/revoke" },
		"missing":    func(string) string { return "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRevokeFixture(t)
			revocationURL := toURL(f.provider.URL)
			body := `{"vault":"default","key":"CHATGPT_PLAN","revocation_url":"` + revocationURL + `"}`
			rec := f.revoke(t, f.token, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if len(f.revoked) != 0 || !f.stored() {
				t.Fatal("a refused revoke must not call the provider or delete")
			}
		})
	}
}

func TestOAuthRevokeSkipsTheProviderForAManualCredential(t *testing.T) {
	f := newRevokeFixture(t)
	f.store.oauthRows["root-ns-id:CHATGPT_PLAN"].TokenURL = "manual"
	rec := f.revoke(t, f.token, `{"vault":"default","key":"CHATGPT_PLAN"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if resp := decodeRevoke(t, rec); resp.Revoked || resp.Error != nil {
		t.Fatalf("resp = %+v, want not revoked and no error", resp)
	}
	if len(f.revoked) != 0 || f.stored() {
		t.Fatal("a manual credential must be deleted without a provider call")
	}
}

func TestOAuthRevokeRefusesAProxyRoleUser(t *testing.T) {
	f := newRevokeFixture(t)
	f.store.users["proxy@test.com"] = &store.User{
		ID: "proxy-user-id", Email: "proxy@test.com", Role: "member", IsActive: true,
	}
	f.store.GrantVaultRole(context.Background(), "proxy-user-id", "user", "root-ns-id", "proxy")
	sess, err := f.store.CreateSession(context.Background(), "proxy-user-id", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	rec := f.revoke(t, sess.ID, f.body("CHATGPT_PLAN"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(f.revoked) != 0 || !f.stored() {
		t.Fatal("a refused revoke must not call the provider or delete")
	}
}
