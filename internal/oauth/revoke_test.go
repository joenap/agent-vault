package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevoke_PublicClient(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		form := parseForm(t, r)
		if got := form.Get("token"); got != "ref" {
			t.Errorf("token = %q, want ref", got)
		}
		if got := form.Get("token_type_hint"); got != "refresh_token" {
			t.Errorf("token_type_hint = %q, want refresh_token", got)
		}
		if got := form.Get("client_id"); got != "pub" {
			t.Errorf("client_id = %q, want pub", got)
		}
		if form.Has("client_secret") {
			t.Errorf("client_secret sent for a public client")
		}
		// RFC 7009 §2.2: 200 with an empty body.
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	err := Revoke(context.Background(), RevokeConfig{URL: ts.URL, ClientID: "pub", Token: "ref"})
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
}

func TestRevoke_ClientSecretPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		form := parseForm(t, r)
		if got := form.Get("client_secret"); got != "sec" {
			t.Errorf("client_secret = %q, want sec", got)
		}
	}))
	defer ts.Close()

	err := Revoke(context.Background(), RevokeConfig{URL: ts.URL, ClientID: "c", ClientSecret: "sec", Token: "ref"})
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
}

func TestRevoke_ClientSecretBasic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "c" || pass != "sec" {
			t.Errorf("basic auth = %q %q %v, want c sec", user, pass, ok)
		}
		if form := parseForm(t, r); form.Has("client_secret") {
			t.Errorf("client_secret in body with client_secret_basic")
		}
	}))
	defer ts.Close()

	err := Revoke(context.Background(), RevokeConfig{
		URL: ts.URL, ClientID: "c", ClientSecret: "sec", Token: "ref", TokenAuthMethod: "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
}

func TestRevoke_ErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported_token_type"}`))
	}))
	defer ts.Close()

	err := Revoke(context.Background(), RevokeConfig{URL: ts.URL, ClientID: "c", Token: "ref"})
	var te *TokenError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want *TokenError", err)
	}
	if te.StatusCode != http.StatusBadRequest || !te.Permanent {
		t.Errorf("TokenError = %+v, want permanent 400", te)
	}
}
