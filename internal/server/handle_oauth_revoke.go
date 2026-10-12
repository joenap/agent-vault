package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

type oauthRevokeRequest struct {
	Vault         string `json:"vault"`
	Key           string `json:"key"`
	RevocationURL string `json:"revocation_url"`
}

type oauthRevokeResponse struct {
	Revoked bool    `json:"revoked"`
	Error   *string `json:"error,omitempty"`
}

// handleOAuthRevoke revokes an OAuth credential's refresh token at the
// provider (RFC 7009), then deletes the credential. The credential is
// deleted even when the provider call fails; the reply says whether the
// revoke succeeded.
func (s *Server) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	var req oauthRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Vault == "" {
		req.Vault = store.DefaultVault
	}
	if req.Key == "" {
		jsonError(w, http.StatusBadRequest, "\"key\" is required")
		return
	}

	ctx := r.Context()
	ns, err := s.store.GetVault(ctx, req.Vault)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", req.Vault))
		return
	}
	if _, err := s.requireVaultMember(w, r, ns.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, ctx, ns.ID, ns.Name) {
		return
	}

	oauthCfg, err := s.store.GetCredentialOAuth(ctx, ns.ID, req.Key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "Failed to read OAuth state")
		return
	}
	if oauthCfg == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("OAuth credential %q not found", req.Key))
		return
	}

	callProvider := oauthCfg.TokenURL != "manual" && len(oauthCfg.RefreshTokenCT) > 0
	if callProvider {
		if msg := checkRevocationURL(req.RevocationURL, oauthCfg.TokenURL); msg != "" {
			jsonError(w, http.StatusBadRequest, msg)
			return
		}
	}

	resp := oauthRevokeResponse{}
	if callProvider {
		// Shares the refresher's key so a revoke never races a refresh.
		res := s.oauthRefresher.Do(ns.ID+"|"+req.Key, func() oauth.RefreshResult {
			return oauth.RefreshResult{Err: s.revokeRefreshToken(ctx, oauthCfg, req.RevocationURL)}
		})
		if res.Err != nil {
			msg := res.Err.Error()
			resp.Error = &msg
		} else {
			resp.Revoked = true
		}
	}

	if err := s.store.DeleteCredential(ctx, ns.ID, req.Key); err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to delete credential")
		return
	}
	jsonOK(w, resp)
}

// checkRevocationURL returns why the URL can't receive the refresh token,
// or "" if it can: https, on the same host as the token endpoint.
func checkRevocationURL(revocationURL, tokenURL string) string {
	rev, err := url.Parse(revocationURL)
	if err != nil || rev.Scheme != "https" || rev.Host == "" {
		return "\"revocation_url\" must be an https URL"
	}
	tok, err := url.Parse(tokenURL)
	if err != nil || !strings.EqualFold(tok.Host, rev.Host) {
		return "\"revocation_url\" must be on the token endpoint's host"
	}
	return ""
}

func (s *Server) revokeRefreshToken(ctx context.Context, cfg *store.CredentialOAuth, revocationURL string) error {
	refreshToken, err := crypto.Decrypt(cfg.RefreshTokenCT, cfg.RefreshTokenNonce, s.encKey)
	if err != nil {
		return fmt.Errorf("decrypt refresh token: %w", err)
	}
	var clientSecret string
	if len(cfg.ClientSecretCT) > 0 {
		cs, err := crypto.Decrypt(cfg.ClientSecretCT, cfg.ClientSecretNonce, s.encKey)
		if err != nil {
			return fmt.Errorf("decrypt client secret: %w", err)
		}
		clientSecret = string(cs)
	}
	return oauth.Revoke(ctx, oauth.RevokeConfig{
		URL:             revocationURL,
		ClientID:        cfg.ClientID,
		ClientSecret:    clientSecret,
		Token:           string(refreshToken),
		TokenAuthMethod: cfg.TokenAuthMethod,
	})
}
