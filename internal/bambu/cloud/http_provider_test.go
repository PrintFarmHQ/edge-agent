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

func TestHTTPProviderListBoundDevicesSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "success",
			"devices": []map[string]any{
				{
					"dev_id":           "dev-1",
					"name":             "P1S Office",
					"dev_product_name": "P1S",
					"print_status":     "ACTIVE",
					"online":           true,
				},
				{
					"dev_id":           "dev-2",
					"name":             "X1C Garage",
					"dev_product_name": "X1C",
					"print_status":     "OFFLINE",
					"online":           false,
				},
			},
		})
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{
		AuthBaseURL: srv.URL,
		Client:      &http.Client{Timeout: 2 * time.Second},
	})
	devices, err := provider.ListBoundDevices(context.Background(), "access-1")
	if err != nil {
		t.Fatalf("ListBoundDevices failed: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("device count = %d, want 2", len(devices))
	}
	if devices[0].DeviceID != "dev-1" || devices[0].Name != "P1S Office" || !devices[0].Online {
		t.Fatalf("unexpected first device: %+v", devices[0])
	}
	if devices[1].DeviceID != "dev-2" || devices[1].Model != "X1C" || devices[1].Online {
		t.Fatalf("unexpected second device: %+v", devices[1])
	}
}

func TestHTTPProviderListBoundDevicesUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{
		AuthBaseURL: srv.URL,
		Client:      &http.Client{Timeout: 2 * time.Second},
	})
	_, err := provider.ListBoundDevices(context.Background(), "access-1")
	if err == nil {
		t.Fatalf("expected unauthorized error")
	}
	if !errors.Is(err, bambuauth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}
