package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bambuauth "printfarmhq/edge-agent/internal/bambu/auth"
)

func TestHTTPProviderLoginSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/user-service/user/login" {
			http.NotFound(w, r)
			return
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode login request failed: %v", err)
		}
		if req["account"] != "user@example.com" {
			t.Fatalf("unexpected account: %q", req["account"])
		}
		if req["apiError"] != "" {
			t.Fatalf("unexpected apiError: %q", req["apiError"])
		}
		if req["password"] != "secret" {
			t.Fatalf("unexpected password")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken":  "access-1",
			"refreshToken": "refresh-1",
			"expiresIn":    3600,
			"account": map[string]any{
				"email_masked": "u***@example.com",
			},
		})
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	session, err := provider.Login(context.Background(), bambuauth.LoginRequest{Username: "user@example.com", Password: "secret"})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if session.AccessToken != "access-1" {
		t.Fatalf("access token = %q, want access-1", session.AccessToken)
	}
	if session.RefreshToken != "refresh-1" {
		t.Fatalf("refresh token = %q, want refresh-1", session.RefreshToken)
	}
	if session.ExpiresAt.IsZero() {
		t.Fatalf("expires_at should not be zero")
	}
}

func TestHTTPProviderLoginMFARequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/user-service/user/login" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"","refreshToken":"","expiresIn":0,"loginType":"verifyCode"}`))
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	_, err := provider.Login(context.Background(), bambuauth.LoginRequest{Username: "user@example.com", Password: "secret"})
	if err == nil {
		t.Fatalf("expected MFA required error")
	}
	if !errors.Is(err, bambuauth.ErrMFARequired) {
		t.Fatalf("expected ErrMFARequired, got %v", err)
	}
}
