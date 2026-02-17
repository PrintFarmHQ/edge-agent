package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bambuauth "printfarmhq/edge-agent/internal/bambu/auth"
	bambucloud "printfarmhq/edge-agent/internal/bambu/cloud"
	bambustore "printfarmhq/edge-agent/internal/store"
)

func newTestAgent(t *testing.T) *agent {
	t.Helper()
	baseDir := t.TempDir()
	return &agent{
		cfg: appConfig{
			BootstrapConfigPath:     filepath.Join(baseDir, "bootstrap", "config.json"),
			AuditLogPath:            filepath.Join(baseDir, "audit", "audit.log"),
			ArtifactStageDir:        filepath.Join(baseDir, "artifacts"),
			EnableKlipper:           true,
			EnableBambu:             true,
			BambuConnectURI:         "http://127.0.0.1:18091",
			MoonrakerRequestTimeout: 2 * time.Second,
			ArtifactUploadTimeout:   2 * time.Second,
			ArtifactDownloadTimeout: 2 * time.Second,
			CircuitBreakerCooldown:  2 * time.Second,
		},
		client:         &http.Client{Timeout: 2 * time.Second},
		desiredState:   make(map[int]desiredStateItem),
		bindings:       make(map[int]edgeBinding),
		currentState:   make(map[int]currentStateItem),
		actionQueue:    make(map[int][]action),
		deadLetters:    make(map[int][]action),
		queuedSince:    make(map[int]time.Time),
		recentEnqueue:  make(map[string]time.Time),
		breakerUntil:   make(map[int]time.Time),
		discoverySeeds: make(map[string]time.Time),
	}
}

type fakeBambuAuthProvider struct {
	loginFn   func(ctx context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error)
	refreshFn func(ctx context.Context, req bambuauth.RefreshRequest) (bambuauth.Session, error)
}

func (f *fakeBambuAuthProvider) Login(ctx context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error) {
	if f.loginFn == nil {
		return bambuauth.Session{}, errors.New("login not implemented")
	}
	return f.loginFn(ctx, req)
}

func (f *fakeBambuAuthProvider) Refresh(ctx context.Context, req bambuauth.RefreshRequest) (bambuauth.Session, error) {
	if f.refreshFn == nil {
		return bambuauth.Session{}, errors.New("refresh not implemented")
	}
	return f.refreshFn(ctx, req)
}

type memoryBambuCredentialsStore struct {
	loadErr error
	saveErr error
	loaded  bambustore.BambuCredentials
	last    bambustore.BambuCredentials
	saveCnt int
	loadCnt int
}

func (s *memoryBambuCredentialsStore) Save(_ context.Context, credentials bambustore.BambuCredentials) error {
	s.saveCnt++
	if s.saveErr != nil {
		return s.saveErr
	}
	s.last = credentials
	return nil
}

func (s *memoryBambuCredentialsStore) Load(_ context.Context) (bambustore.BambuCredentials, error) {
	s.loadCnt++
	if s.loadErr != nil {
		return bambustore.BambuCredentials{}, s.loadErr
	}
	return s.loaded, nil
}

func (s *memoryBambuCredentialsStore) Path() string {
	return ""
}

func TestParseRuntimeFlags(t *testing.T) {
	flags, err := parseRuntimeFlags([]string{
		"--klipper",
		"--control-plane-url=http://localhost:8000",
		"--api-key=test-key",
	})
	if err != nil {
		t.Fatalf("parseRuntimeFlags returned error: %v", err)
	}
	if flags.ControlPlaneURL != "http://localhost:8000" {
		t.Fatalf("ControlPlaneURL = %q, want %q", flags.ControlPlaneURL, "http://localhost:8000")
	}
	if flags.APIKey != "test-key" {
		t.Fatalf("APIKey = %q, want %q", flags.APIKey, "test-key")
	}
}

func TestParseRuntimeFlagsSaaSAPIKeyAlias(t *testing.T) {
	flags, err := parseRuntimeFlags([]string{"--klipper", "--saas-api-key=alias-key"})
	if err != nil {
		t.Fatalf("parseRuntimeFlags returned error: %v", err)
	}
	if flags.APIKey != "alias-key" {
		t.Fatalf("APIKey = %q, want %q", flags.APIKey, "alias-key")
	}
}

func TestParseRuntimeFlagsRequiresAtLeastOneAdapter(t *testing.T) {
	_, err := parseRuntimeFlags([]string{"--api-key=test-key"})
	if err == nil {
		t.Fatalf("expected parseRuntimeFlags to fail without adapter flags")
	}
}

func TestParseRuntimeFlagsBambuOnly(t *testing.T) {
	flags, err := parseRuntimeFlags([]string{"--bambu"})
	if err != nil {
		t.Fatalf("parseRuntimeFlags returned error: %v", err)
	}
	if !flags.EnableBambu {
		t.Fatalf("EnableBambu = false, want true")
	}
	if flags.EnableKlipper {
		t.Fatalf("EnableKlipper = true, want false")
	}
}

func TestParseRuntimeFlagsRejectsRemovedBambuConnectURIFlag(t *testing.T) {
	_, err := parseRuntimeFlags([]string{"--bambu", "--bambu-connect-uri=http://127.0.0.1:8088"})
	if err == nil {
		t.Fatalf("expected parseRuntimeFlags to reject removed --bambu-connect-uri flag")
	}
}

func TestParseRuntimeFlagsRejectsRemovedBambuMFAFlags(t *testing.T) {
	_, err := parseRuntimeFlags([]string{"--bambu", "--bambu-mfa-code=123456"})
	if err == nil {
		t.Fatalf("expected parseRuntimeFlags to reject removed --bambu-mfa-code flag")
	}

	_, err = parseRuntimeFlags([]string{"--bambu", "--bambu-mfa-code-cmd=printf 123456"})
	if err == nil {
		t.Fatalf("expected parseRuntimeFlags to reject removed --bambu-mfa-code-cmd flag")
	}
}

func TestParseRuntimeFlagsRejectsRemovedBambuCredentialFlags(t *testing.T) {
	_, err := parseRuntimeFlags([]string{"--bambu", "--bambu-username=user@example.com"})
	if err == nil {
		t.Fatalf("expected parseRuntimeFlags to reject removed --bambu-username flag")
	}
	if !strings.Contains(err.Error(), "bambu-username") {
		t.Fatalf("unexpected error for removed --bambu-username flag: %v", err)
	}

	_, err = parseRuntimeFlags([]string{"--bambu", "--bambu-password=secret"})
	if err == nil {
		t.Fatalf("expected parseRuntimeFlags to reject removed --bambu-password flag")
	}
	if !strings.Contains(err.Error(), "bambu-password") {
		t.Fatalf("unexpected error for removed --bambu-password flag: %v", err)
	}
}

func TestLoadConfigIgnoresEnableBambuSpikeAlias(t *testing.T) {
	t.Setenv("ENABLE_BAMBU", "")
	t.Setenv("ENABLE_BAMBU_SPIKE", "true")

	cfg := loadConfig()
	if cfg.EnableBambu {
		t.Fatalf("EnableBambu = true, want false when only ENABLE_BAMBU_SPIKE is set")
	}
}

func TestDefaultEdgeStateDirUsesPrintfarmhq(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	got := defaultEdgeStateDir()
	want := filepath.Join(homeDir, ".printfarmhq")
	if got != want {
		t.Fatalf("defaultEdgeStateDir() = %q, want %q", got, want)
	}
}

func TestLoadConfigDefaultPathsUsePrintfarmhq(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	cfg := loadConfig()
	wantRoot := filepath.Join(homeDir, ".printfarmhq")
	if cfg.BootstrapConfigPath != filepath.Join(wantRoot, "bootstrap", "config.json") {
		t.Fatalf("BootstrapConfigPath = %q, want %q", cfg.BootstrapConfigPath, filepath.Join(wantRoot, "bootstrap", "config.json"))
	}
	if cfg.AuditLogPath != filepath.Join(wantRoot, "logs", "audit.log") {
		t.Fatalf("AuditLogPath = %q, want %q", cfg.AuditLogPath, filepath.Join(wantRoot, "logs", "audit.log"))
	}
	if cfg.ArtifactStageDir != filepath.Join(wantRoot, "artifacts") {
		t.Fatalf("ArtifactStageDir = %q, want %q", cfg.ArtifactStageDir, filepath.Join(wantRoot, "artifacts"))
	}
}

func TestLoadConfigDefaultsDiscoveryInventoryIntervalToThirtySeconds(t *testing.T) {
	t.Setenv("DISCOVERY_INVENTORY_INTERVAL_MS", "")
	cfg := loadConfig()
	if cfg.DiscoveryInventoryInterval != 30*time.Second {
		t.Fatalf("DiscoveryInventoryInterval = %s, want 30s", cfg.DiscoveryInventoryInterval)
	}
}

func TestApplyRuntimeFlagsOverridesConfig(t *testing.T) {
	cfg := appConfig{
		StartupControlPlaneURL: "http://before",
		StartupSaaSAPIKey:      "before-key",
	}
	out := applyRuntimeFlags(cfg, runtimeFlags{
		ControlPlaneURL: "http://after",
		APIKey:          "after-key",
		EnableKlipper:   true,
		EnableBambu:     true,
	})
	if out.StartupControlPlaneURL != "http://after" {
		t.Fatalf("StartupControlPlaneURL = %q, want %q", out.StartupControlPlaneURL, "http://after")
	}
	if out.StartupSaaSAPIKey != "after-key" {
		t.Fatalf("StartupSaaSAPIKey = %q, want %q", out.StartupSaaSAPIKey, "after-key")
	}
	if !out.EnableKlipper || !out.EnableBambu {
		t.Fatalf("expected adapter flags to be enabled after runtime override")
	}
	if strings.Join(out.DiscoveryAllowedAdapters, ",") != "moonraker,bambu" {
		t.Fatalf("DiscoveryAllowedAdapters = %v, want [moonraker bambu]", out.DiscoveryAllowedAdapters)
	}
}

func TestBambuAuthStartupUsesStoredValidToken(t *testing.T) {
	a := newTestAgent(t)

	store := &memoryBambuCredentialsStore{
		loaded: bambustore.BambuCredentials{
			Username:           "saved@example.com",
			AccessToken:        "stored-access-token",
			RefreshToken:       "stored-refresh-token",
			ExpiresAt:          time.Now().UTC().Add(30 * time.Minute),
			MaskedEmail:        "s***@example.com",
			AccountDisplayName: "Saved User",
		},
	}
	a.bambuAuthStore = store

	loginCalled := false
	refreshCalled := false
	a.bambuAuthProvider = &fakeBambuAuthProvider{
		loginFn: func(_ context.Context, _ bambuauth.LoginRequest) (bambuauth.Session, error) {
			loginCalled = true
			return bambuauth.Session{}, errors.New("login should not be called for valid stored token")
		},
		refreshFn: func(_ context.Context, _ bambuauth.RefreshRequest) (bambuauth.Session, error) {
			refreshCalled = true
			return bambuauth.Session{}, errors.New("refresh should not be called for valid stored token")
		},
	}

	if err := a.initializeBambuAuth(context.Background()); err != nil {
		t.Fatalf("initializeBambuAuth failed: %v", err)
	}
	state := a.snapshotBambuAuthState()
	if !state.Ready {
		t.Fatalf("bambu auth should be ready")
	}
	if state.MaskedEmail != "s***@example.com" {
		t.Fatalf("masked email = %q, want s***@example.com", state.MaskedEmail)
	}
	if state.DisplayName != "Saved User" {
		t.Fatalf("display name = %q, want Saved User", state.DisplayName)
	}
	if loginCalled || refreshCalled {
		t.Fatalf("provider should not be called when stored token is still valid")
	}
	if store.saveCnt != 0 {
		t.Fatalf("store save count = %d, want 0", store.saveCnt)
	}
}

func setInteractiveBambuAuthTestInput(t *testing.T, input string, interactive bool) *bytes.Buffer {
	t.Helper()
	originalReader := bambuAuthInputReader
	originalWriter := bambuAuthOutputWriter
	originalInteractiveCheck := isBambuAuthInteractiveConsole

	output := &bytes.Buffer{}
	bambuAuthInputReader = strings.NewReader(input)
	bambuAuthOutputWriter = output
	isBambuAuthInteractiveConsole = func() bool {
		return interactive
	}

	t.Cleanup(func() {
		bambuAuthInputReader = originalReader
		bambuAuthOutputWriter = originalWriter
		isBambuAuthInteractiveConsole = originalInteractiveCheck
	})

	return output
}

func TestBambuAuthStartupRefreshesExpiredToken(t *testing.T) {
	a := newTestAgent(t)
	store := &memoryBambuCredentialsStore{
		loaded: bambustore.BambuCredentials{
			Username:     "saved@example.com",
			AccessToken:  "expired-access-token",
			RefreshToken: "stored-refresh-token",
			ExpiresAt:    time.Now().UTC().Add(-30 * time.Minute),
		},
	}
	a.bambuAuthStore = store
	setInteractiveBambuAuthTestInput(t, "", false)

	loginCalled := false
	refreshCalled := false
	a.bambuAuthProvider = &fakeBambuAuthProvider{
		loginFn: func(_ context.Context, _ bambuauth.LoginRequest) (bambuauth.Session, error) {
			loginCalled = true
			return bambuauth.Session{}, errors.New("interactive login should not run when refresh succeeds")
		},
		refreshFn: func(_ context.Context, req bambuauth.RefreshRequest) (bambuauth.Session, error) {
			refreshCalled = true
			if req.RefreshToken != "stored-refresh-token" {
				t.Fatalf("refresh token = %q, want stored-refresh-token", req.RefreshToken)
			}
			return bambuauth.Session{
				AccessToken:  "refreshed-access-token",
				RefreshToken: "",
				ExpiresAt:    time.Now().UTC().Add(2 * time.Hour),
			}, nil
		},
	}

	if err := a.initializeBambuAuth(context.Background()); err != nil {
		t.Fatalf("initializeBambuAuth failed: %v", err)
	}
	if !a.snapshotBambuAuthState().Ready {
		t.Fatalf("bambu auth should be ready")
	}
	if !refreshCalled {
		t.Fatalf("refresh should be called for expired token with refresh token")
	}
	if loginCalled {
		t.Fatalf("interactive login should not run when refresh succeeds")
	}
	if store.saveCnt != 1 {
		t.Fatalf("store save count = %d, want 1", store.saveCnt)
	}
	if store.last.AccessToken != "refreshed-access-token" {
		t.Fatalf("stored access token = %q, want refreshed-access-token", store.last.AccessToken)
	}
	if store.last.RefreshToken != "stored-refresh-token" {
		t.Fatalf("stored refresh token = %q, want stored-refresh-token", store.last.RefreshToken)
	}
	if store.last.Username != "saved@example.com" {
		t.Fatalf("stored username = %q, want saved@example.com", store.last.Username)
	}
}

func TestInitializeBambuAuthDoesNotPrintCloudDevicesToStdout(t *testing.T) {
	a := newTestAgent(t)
	store := &memoryBambuCredentialsStore{
		loaded: bambustore.BambuCredentials{
			Username:    "saved@example.com",
			AccessToken: "stored-access-token",
			ExpiresAt:   time.Now().UTC().Add(30 * time.Minute),
		},
	}
	a.bambuAuthStore = store
	output := &bytes.Buffer{}
	originalWriter := bambuAuthOutputWriter
	bambuAuthOutputWriter = output
	t.Cleanup(func() {
		bambuAuthOutputWriter = originalWriter
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer stored-access-token" {
			t.Fatalf("authorization header = %q, want Bearer stored-access-token", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"devices": []map[string]any{
				{
					"dev_id":           "dev-active",
					"name":             "P1S Office",
					"dev_product_name": "P1S",
					"print_status":     "ACTIVE",
					"online":           true,
				},
				{
					"dev_id":           "dev-offline",
					"name":             "X1C Garage",
					"dev_product_name": "X1C",
					"print_status":     "OFFLINE",
					"online":           false,
				},
			},
		})
	}))
	defer srv.Close()

	a.cfg.BambuCloudAuthBaseURL = srv.URL
	a.client = &http.Client{Timeout: 2 * time.Second}

	if err := a.initializeBambuAuth(context.Background()); err != nil {
		t.Fatalf("initializeBambuAuth failed: %v", err)
	}
	if !a.snapshotBambuAuthState().Ready {
		t.Fatalf("bambu auth should be ready")
	}

	stdout := output.String()
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("expected no cloud device stdout output, got %q", stdout)
	}
}

func TestBambuAuthRefreshFailureFallsBackToInteractiveLogin(t *testing.T) {
	a := newTestAgent(t)
	store := &memoryBambuCredentialsStore{
		loaded: bambustore.BambuCredentials{
			Username:     "saved@example.com",
			AccessToken:  "expired-access-token",
			RefreshToken: "stored-refresh-token",
			ExpiresAt:    time.Now().UTC().Add(-30 * time.Minute),
		},
	}
	a.bambuAuthStore = store
	promptOutput := setInteractiveBambuAuthTestInput(t, "\nsecret\n", true)

	loginCalled := false
	a.bambuAuthProvider = &fakeBambuAuthProvider{
		refreshFn: func(_ context.Context, _ bambuauth.RefreshRequest) (bambuauth.Session, error) {
			return bambuauth.Session{}, errors.New("refresh failed")
		},
		loginFn: func(_ context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error) {
			loginCalled = true
			if req.Username != "saved@example.com" {
				t.Fatalf("login username = %q, want saved@example.com", req.Username)
			}
			if req.Password != "secret" {
				t.Fatalf("login password mismatch")
			}
			return bambuauth.Session{
				AccessToken:  "interactive-access-token",
				RefreshToken: "interactive-refresh-token",
				ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
			}, nil
		},
	}

	if err := a.initializeBambuAuth(context.Background()); err != nil {
		t.Fatalf("initializeBambuAuth failed: %v", err)
	}
	if !loginCalled {
		t.Fatalf("interactive login should run when refresh fails")
	}
	if store.saveCnt != 1 {
		t.Fatalf("store save count = %d, want 1", store.saveCnt)
	}
	if store.last.Username != "saved@example.com" {
		t.Fatalf("stored username = %q, want saved@example.com", store.last.Username)
	}
	if !strings.Contains(promptOutput.String(), "Bambu username [saved@example.com]") {
		t.Fatalf("expected username prompt with default, got %q", promptOutput.String())
	}
	if !strings.Contains(promptOutput.String(), "Bambu password: ") {
		t.Fatalf("expected password prompt, got %q", promptOutput.String())
	}
	if strings.Contains(promptOutput.String(), "secret") {
		t.Fatalf("password should never be written to auth output: %q", promptOutput.String())
	}
}

func TestBambuAuthInteractiveLoginRequiresInteractiveConsole(t *testing.T) {
	a := newTestAgent(t)
	a.bambuAuthStore = &memoryBambuCredentialsStore{loadErr: os.ErrNotExist}
	setInteractiveBambuAuthTestInput(t, "user@example.com\nsecret\n", false)

	loginCalled := false
	a.bambuAuthProvider = &fakeBambuAuthProvider{
		loginFn: func(_ context.Context, _ bambuauth.LoginRequest) (bambuauth.Session, error) {
			loginCalled = true
			return bambuauth.Session{}, errors.New("login should not be called without interactive console")
		},
	}

	err := a.initializeBambuAuth(context.Background())
	if err == nil {
		t.Fatalf("expected initializeBambuAuth to fail when console is not interactive")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "interactive") {
		t.Fatalf("unexpected error: %v", err)
	}
	if loginCalled {
		t.Fatalf("login should not be called when interactive console is unavailable")
	}
	if a.snapshotBambuAuthState().Ready {
		t.Fatalf("bambu auth should not be ready")
	}
}

func TestBambuAuthMFAWithInteractiveCodeSucceeds(t *testing.T) {
	a := newTestAgent(t)
	a.bambuAuthStore = &memoryBambuCredentialsStore{loadErr: os.ErrNotExist}
	promptOutput := setInteractiveBambuAuthTestInput(t, "user@example.com\nsecret\n654321\n", true)

	loginCalls := 0
	a.bambuAuthProvider = &fakeBambuAuthProvider{
		loginFn: func(_ context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error) {
			loginCalls++
			if req.Username != "user@example.com" {
				t.Fatalf("login username = %q, want user@example.com", req.Username)
			}
			if loginCalls == 1 {
				if req.MFACode != "" {
					t.Fatalf("first login should not include MFA code")
				}
				if req.Password != "secret" {
					t.Fatalf("first login password mismatch")
				}
				return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrMFARequired, Message: "mfa required"}
			}
			if req.MFACode != "654321" {
				t.Fatalf("second login mfa code = %q, want 654321", req.MFACode)
			}
			return bambuauth.Session{
				AccessToken: "access-token",
				ExpiresAt:   time.Now().UTC().Add(1 * time.Hour),
			}, nil
		},
	}

	if err := a.initializeBambuAuth(context.Background()); err != nil {
		t.Fatalf("initializeBambuAuth failed: %v", err)
	}
	if !a.snapshotBambuAuthState().Ready {
		t.Fatalf("bambu auth should be ready")
	}
	if loginCalls != 2 {
		t.Fatalf("login call count = %d, want 2", loginCalls)
	}
	if !strings.Contains(promptOutput.String(), "Bambu username: ") {
		t.Fatalf("expected username prompt output, got %q", promptOutput.String())
	}
	if !strings.Contains(promptOutput.String(), "Bambu password: ") {
		t.Fatalf("expected password prompt output, got %q", promptOutput.String())
	}
	if !strings.Contains(promptOutput.String(), "Bambu MFA code required") {
		t.Fatalf("expected MFA prompt output, got %q", promptOutput.String())
	}
	if strings.Contains(promptOutput.String(), "secret") || strings.Contains(promptOutput.String(), "654321") {
		t.Fatalf("sensitive auth values should never be written to output: %q", promptOutput.String())
	}
	store := a.bambuAuthStore.(*memoryBambuCredentialsStore)
	if store.saveCnt != 1 {
		t.Fatalf("store save count = %d, want 1", store.saveCnt)
	}
	if store.last.Username != "user@example.com" {
		t.Fatalf("stored username = %q, want user@example.com", store.last.Username)
	}
}

func TestBambuAuthMFAWithEmptyInteractiveCodeFails(t *testing.T) {
	a := newTestAgent(t)
	a.bambuAuthStore = &memoryBambuCredentialsStore{loadErr: os.ErrNotExist}
	setInteractiveBambuAuthTestInput(t, "user@example.com\nsecret\n\n", true)

	loginCalls := 0
	a.bambuAuthProvider = &fakeBambuAuthProvider{
		loginFn: func(_ context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error) {
			loginCalls++
			if loginCalls == 1 {
				if req.MFACode != "" {
					t.Fatalf("first login should not include MFA code")
				}
				return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrMFARequired, Message: "mfa required"}
			}
			return bambuauth.Session{}, errors.New("unexpected second login")
		},
	}

	err := a.initializeBambuAuth(context.Background())
	if err == nil {
		t.Fatalf("expected initializeBambuAuth to fail for empty MFA code")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "cannot be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
	if loginCalls != 1 {
		t.Fatalf("login call count = %d, want 1", loginCalls)
	}
}

func TestBambuAuthMFAWrongCodeFails(t *testing.T) {
	a := newTestAgent(t)
	store := &memoryBambuCredentialsStore{loadErr: os.ErrNotExist}
	a.bambuAuthStore = store
	setInteractiveBambuAuthTestInput(t, "user@example.com\nsecret\n111111\n", true)

	loginCalls := 0
	a.bambuAuthProvider = &fakeBambuAuthProvider{
		loginFn: func(_ context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error) {
			loginCalls++
			if loginCalls == 1 {
				return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrMFARequired, Message: "mfa required"}
			}
			if req.MFACode != "111111" {
				t.Fatalf("second login mfa code = %q, want 111111", req.MFACode)
			}
			return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "incorrect MFA code"}
		},
	}

	err := a.initializeBambuAuth(context.Background())
	if err == nil {
		t.Fatalf("expected initializeBambuAuth to fail with wrong MFA code")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "incorrect mfa code") {
		t.Fatalf("unexpected error: %v", err)
	}
	if loginCalls != 2 {
		t.Fatalf("login call count = %d, want 2", loginCalls)
	}
	if store.saveCnt != 0 {
		t.Fatalf("store save count = %d, want 0", store.saveCnt)
	}
	if a.snapshotBambuAuthState().Ready {
		t.Fatalf("bambu auth should not be ready")
	}
}

func TestMapDesiredToAction(t *testing.T) {
	tests := []struct {
		name    string
		current string
		desired string
		want    string
	}{
		{name: "start print", current: "idle", desired: "printing", want: "print"},
		{name: "pause print", current: "printing", desired: "paused", want: "pause"},
		{name: "resume print", current: "paused", desired: "printing", want: "resume"},
		{name: "stop print", current: "printing", desired: "idle", want: "stop"},
		{name: "noop printing", current: "printing", desired: "printing", want: "noop"},
		{name: "invalid pause from idle", current: "idle", desired: "paused", want: "invalid"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapDesiredToAction(tc.current, tc.desired)
			if got != tc.want {
				t.Fatalf("mapDesiredToAction(%q, %q) = %q, want %q", tc.current, tc.desired, got, tc.want)
			}
		})
	}
}

func TestNormalizeAdapterFamily(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty defaults moonraker", in: "", want: "moonraker"},
		{name: "klipper alias", in: "klipper", want: "moonraker"},
		{name: "klipper alias mixed case", in: " KlIpPeR ", want: "moonraker"},
		{name: "moonraker passthrough", in: "moonraker", want: "moonraker"},
		{name: "bambu passthrough", in: "bambu", want: "bambu"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeAdapterFamily(tc.in)
			if got != tc.want {
				t.Fatalf("normalizeAdapterFamily(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestPruneQueueForIntent(t *testing.T) {
	queue := []action{
		{Kind: "print", Target: desiredStateItem{IntentVersion: 1}},
		{Kind: "pause", Target: desiredStateItem{IntentVersion: 2}},
		{Kind: "resume", Target: desiredStateItem{IntentVersion: 4}},
	}

	pruned := pruneQueueForIntentLocked(queue, 3)
	if len(pruned) != 1 {
		t.Fatalf("pruned queue length = %d, want 1", len(pruned))
	}
	if pruned[0].Kind != "resume" {
		t.Fatalf("remaining action kind = %q, want resume", pruned[0].Kind)
	}
}

func TestAllowEnqueueLockedThrottleWindow(t *testing.T) {
	now := time.Now().UTC()
	recent := map[string]time.Time{}
	desired := desiredStateItem{
		PrinterID:     1,
		IntentVersion: 10,
		JobID:         "job-1",
		PlateID:       2,
	}

	if !allowEnqueueLocked(recent, 1, "print", desired, now) {
		t.Fatalf("first enqueue should be allowed")
	}
	if allowEnqueueLocked(recent, 1, "print", desired, now.Add(1500*time.Millisecond)) {
		t.Fatalf("enqueue within 2s throttle window should be blocked")
	}
	if !allowEnqueueLocked(recent, 1, "print", desired, now.Add(2500*time.Millisecond)) {
		t.Fatalf("enqueue after 2s throttle window should be allowed")
	}
}

func TestReconcileQueuedStaleRequestsResync(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[1] = edgeBinding{PrinterID: 1, EndpointURL: "http://moonraker:7125"}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       7,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		ArtifactURL:         "http://example.invalid/plate.gcode",
		ChecksumSHA256:      "abc",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "queued",
		ReportedAt:          time.Now().UTC(),
	}
	a.queuedSince[1] = time.Now().UTC().Add(-31 * time.Second)

	a.reconcileOnce()

	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected no queued action while waiting in queued state")
	}
	current := a.currentState[1]
	if current.LastErrorCode != "queued_stale" {
		t.Fatalf("last error code = %q, want queued_stale", current.LastErrorCode)
	}
	if !a.consumeResyncRequest() {
		t.Fatalf("expected reconcile to request resync on stale queued state")
	}
	if a.consumeResyncRequest() {
		t.Fatalf("resync request should be one-shot")
	}
}

func TestReconcileThrottlePreventsImmediateReenqueueAfterDequeue(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[1] = edgeBinding{PrinterID: 1, EndpointURL: "http://moonraker:7125"}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       3,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		ArtifactURL:         "http://example.invalid/plate.gcode",
		ChecksumSHA256:      "abc",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		ReportedAt:          time.Now().UTC(),
	}

	a.reconcileOnce()
	if len(a.actionQueue[1]) != 1 {
		t.Fatalf("expected one queued action, got %d", len(a.actionQueue[1]))
	}

	_, _, ok := a.dequeueNextAction()
	if !ok {
		t.Fatalf("expected action dequeue to succeed")
	}
	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected queue to be empty after dequeue")
	}

	a.reconcileOnce()
	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected immediate duplicate re-enqueue to be throttled")
	}
}

func TestReconcileClearsQueuedActionsForRemovedDesiredPrinter(t *testing.T) {
	a := newTestAgent(t)
	a.actionQueue[1] = []action{
		{
			PrinterID: 1,
			Kind:      "print",
			Target: desiredStateItem{
				PrinterID:     1,
				IntentVersion: 1,
			},
		},
	}
	a.queuedSince[1] = time.Now().UTC().Add(-10 * time.Second)

	a.reconcileOnce()

	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected action queue for removed desired printer to be cleared")
	}
	if _, exists := a.queuedSince[1]; exists {
		t.Fatalf("expected queuedSince tracker to be cleared for removed desired printer")
	}
}

func TestClassifyActionError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantCode  string
		wantRetry bool
	}{
		{name: "artifact", err: errors.New("artifact_fetch_error: checksum mismatch"), wantCode: "artifact_fetch_error", wantRetry: false},
		{name: "validation", err: errors.New("validation failed"), wantCode: "validation_error", wantRetry: false},
		{name: "connectivity", err: errors.New("connection refused"), wantCode: "connectivity_error", wantRetry: true},
		{name: "deadline", err: errors.New("context deadline exceeded"), wantCode: "connectivity_error", wantRetry: true},
		{name: "unknown", err: errors.New("boom"), wantCode: "unknown_error", wantRetry: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, retryable := classifyActionError(tc.err)
			if code != tc.wantCode {
				t.Fatalf("code = %q, want %q", code, tc.wantCode)
			}
			if retryable != tc.wantRetry {
				t.Fatalf("retryable = %v, want %v", retryable, tc.wantRetry)
			}
		})
	}
}

func TestShouldLogAuditEventToStdout(t *testing.T) {
	tests := []struct {
		name  string
		event string
		want  bool
	}{
		{name: "error event", event: "state_push_error", want: true},
		{name: "failed event", event: "claim_failed", want: true},
		{name: "success event bindings", event: "bindings_updated", want: true},
		{name: "success event download", event: "artifact_downloaded", want: true},
		{name: "success event upload", event: "artifact_uploaded", want: true},
		{name: "success event print start", event: "print_start_requested", want: true},
		{name: "empty event", event: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldLogAuditEventToStdout(tc.event)
			if got != tc.want {
				t.Fatalf("shouldLogAuditEventToStdout(%q) = %v, want %v", tc.event, got, tc.want)
			}
		})
	}
}

func TestHandleActionFailureRetriesThenDeadLetters(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.ActionMaxAttempts = 2
	a.cfg.ActionRetryBaseInterval = 10 * time.Millisecond
	initial := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			IntentVersion:       1,
			DesiredPrinterState: "printing",
		},
	}

	a.handleActionFailure(initial, "connectivity_error", "connection refused", true)
	retries := a.actionQueue[1]
	if len(retries) != 1 {
		t.Fatalf("expected one retried action, got %d", len(retries))
	}
	if retries[0].Attempts != 1 {
		t.Fatalf("expected retry attempt=1, got %d", retries[0].Attempts)
	}

	a.handleActionFailure(action{
		PrinterID: 1,
		Kind:      "print",
		Attempts:  2,
		Target: desiredStateItem{
			PrinterID:           1,
			IntentVersion:       1,
			DesiredPrinterState: "printing",
		},
	}, "connectivity_error", "connection refused", true)

	if len(a.deadLetters[1]) != 1 {
		t.Fatalf("expected one dead-lettered action, got %d", len(a.deadLetters[1]))
	}
	cur := a.currentState[1]
	if cur.CurrentPrinterState != "error" {
		t.Fatalf("current state = %q, want error", cur.CurrentPrinterState)
	}
	if cur.LastErrorCode != "connectivity_error" {
		t.Fatalf("last error code = %q, want connectivity_error", cur.LastErrorCode)
	}
}

func TestMoveToDeadLetterConnectivityOpensCircuitBreaker(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.CircuitBreakerCooldown = 200 * time.Millisecond

	a.moveToDeadLetter(action{PrinterID: 1, Kind: "print"}, "connectivity_error", "connection refused")

	until, ok := a.breakerUntil[1]
	if !ok {
		t.Fatalf("expected breaker to be opened for printer 1")
	}
	if !until.After(time.Now().UTC()) {
		t.Fatalf("expected breaker_until in the future, got %s", until)
	}
}

func TestDequeueSkipsOpenCircuitBreaker(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[1] = edgeBinding{PrinterID: 1, EndpointURL: "http://moonraker:7125"}
	a.actionQueue[1] = []action{
		{
			PrinterID: 1,
			Kind:      "stop",
			Target: desiredStateItem{
				PrinterID:     1,
				IntentVersion: 1,
			},
		},
	}
	a.breakerUntil[1] = time.Now().UTC().Add(100 * time.Millisecond)

	_, _, ok := a.dequeueNextAction()
	if ok {
		t.Fatalf("expected dequeue to skip printer while breaker is open")
	}

	a.breakerUntil[1] = time.Now().UTC().Add(-1 * time.Millisecond)
	_, _, ok = a.dequeueNextAction()
	if !ok {
		t.Fatalf("expected dequeue to continue after breaker expiration")
	}
}

func TestBootstrapConfigSaveAndLoad(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_123",
		OrgID:           42,
		ClaimedAt:       time.Now().UTC().Truncate(time.Second),
	}
	a.claimed = true

	if err := a.saveBootstrapConfig(); err != nil {
		t.Fatalf("saveBootstrapConfig failed: %v", err)
	}

	info, err := os.Stat(a.cfg.BootstrapConfigPath)
	if err != nil {
		t.Fatalf("stat bootstrap config failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("bootstrap config file permissions = %o, want 600", perm)
	}

	loaded := newTestAgent(t)
	loaded.cfg.BootstrapConfigPath = a.cfg.BootstrapConfigPath
	if err := loaded.loadBootstrapConfig(); err != nil {
		t.Fatalf("loadBootstrapConfig failed: %v", err)
	}

	if loaded.bootstrap.AgentID != a.bootstrap.AgentID {
		t.Fatalf("loaded AgentID = %q, want %q", loaded.bootstrap.AgentID, a.bootstrap.AgentID)
	}
	if !loaded.claimed {
		t.Fatalf("expected loaded agent to be claimed")
	}
}

func TestLoadBootstrapConfigRepairsInsecureFilePermissions(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_123",
		OrgID:           42,
		ClaimedAt:       time.Now().UTC().Truncate(time.Second),
	}
	a.claimed = true
	if err := a.saveBootstrapConfig(); err != nil {
		t.Fatalf("saveBootstrapConfig failed: %v", err)
	}
	if err := os.Chmod(a.cfg.BootstrapConfigPath, 0o644); err != nil {
		t.Fatalf("chmod bootstrap config failed: %v", err)
	}

	loaded := newTestAgent(t)
	loaded.cfg.BootstrapConfigPath = a.cfg.BootstrapConfigPath
	if err := loaded.loadBootstrapConfig(); err != nil {
		t.Fatalf("loadBootstrapConfig failed: %v", err)
	}
	info, err := os.Stat(a.cfg.BootstrapConfigPath)
	if err != nil {
		t.Fatalf("stat bootstrap config failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("bootstrap config file permissions = %o, want 600", perm)
	}
}

func TestLoadBootstrapConfigRepairsInsecureDirectoryPermissions(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_123",
		OrgID:           42,
		ClaimedAt:       time.Now().UTC().Truncate(time.Second),
	}
	a.claimed = true
	if err := a.saveBootstrapConfig(); err != nil {
		t.Fatalf("saveBootstrapConfig failed: %v", err)
	}
	if err := os.Chmod(filepath.Dir(a.cfg.BootstrapConfigPath), 0o755); err != nil {
		t.Fatalf("chmod bootstrap dir failed: %v", err)
	}

	loaded := newTestAgent(t)
	loaded.cfg.BootstrapConfigPath = a.cfg.BootstrapConfigPath
	if err := loaded.loadBootstrapConfig(); err != nil {
		t.Fatalf("loadBootstrapConfig failed: %v", err)
	}
	info, err := os.Stat(filepath.Dir(a.cfg.BootstrapConfigPath))
	if err != nil {
		t.Fatalf("stat bootstrap dir failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("bootstrap config directory permissions = %o, want 700", perm)
	}
}

func TestClaimWithSaaSRejectsUnsupportedSchemaVersion(t *testing.T) {
	a := newTestAgent(t)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/agents/claim" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claimResponse{
			AgentID:                 "edge_1",
			OrgID:                   1,
			SchemaVersion:           3,
			SupportedSchemaVersions: []int{3},
		})
	}))
	defer saasSrv.Close()

	_, err := a.claimWithSaaS(saasSrv.URL, "edge_key")
	if err == nil {
		t.Fatalf("expected unsupported schema error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClaimWithSaaSSendsDiscoveryCapabilities(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryProfileMax = "aggressive"
	a.cfg.DiscoveryNetworkMode = "host"
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker", "bambu"}
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{Ready: true})

	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/agents/claim" {
			http.NotFound(w, r)
			return
		}
		var req claimRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode claim request failed: %v", err)
		}
		if req.Capabilities["discovery_profile_max"] != "aggressive" {
			t.Fatalf("unexpected discovery_profile_max: %q", req.Capabilities["discovery_profile_max"])
		}
		if req.Capabilities["discovery_network_mode"] != "host" {
			t.Fatalf("unexpected discovery_network_mode: %q", req.Capabilities["discovery_network_mode"])
		}
		if req.Capabilities["discovery_allowed_adapters"] != "moonraker,bambu" {
			t.Fatalf("unexpected discovery_allowed_adapters: %q", req.Capabilities["discovery_allowed_adapters"])
		}
		if req.Capabilities["bambu_enabled"] != "true" {
			t.Fatalf("unexpected bambu_enabled: %q", req.Capabilities["bambu_enabled"])
		}
		if req.Capabilities["bambu_auth_ready"] != "true" {
			t.Fatalf("unexpected bambu_auth_ready: %q", req.Capabilities["bambu_auth_ready"])
		}
		if _, exists := req.Capabilities["bambu_spike_enabled"]; exists {
			t.Fatalf("legacy capability bambu_spike_enabled should not be present")
		}
		writeJSON(w, http.StatusOK, claimResponse{
			AgentID:                 "edge_1",
			OrgID:                   1,
			SchemaVersion:           agentSchemaVersion,
			SupportedSchemaVersions: []int{1, agentSchemaVersion},
		})
	}))
	defer saasSrv.Close()

	claim, err := a.claimWithSaaS(saasSrv.URL, "edge_key")
	if err != nil {
		t.Fatalf("claimWithSaaS failed: %v", err)
	}
	if claim.AgentID != "edge_1" {
		t.Fatalf("agent_id = %q, want edge_1", claim.AgentID)
	}
}

func TestPollDiscoveryJobsOnceSubmitsMoonrakerResult(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker"}
	a.cfg.DiscoveryProfileMax = "hybrid"
	a.cfg.DiscoveryNetworkMode = "bridge"
	a.cfg.DiscoveryProbeTimeout = 2 * time.Second
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"status": map[string]any{
						"print_stats": map[string]any{"state": "printing"},
					},
				},
			})
		case "/machine/system_info":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"system_info": map[string]any{
						"product_info": map[string]any{
							"machine_type": "Voron 2.4",
							"device_name":  "Discovery Unit",
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	var (
		mu            sync.Mutex
		resultPayload discoveryJobResultRequest
		resultCalls   int
	)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-jobs"):
			writeJSON(w, http.StatusOK, discoveryJobsResponse{
				Jobs: []discoveryJobItem{
					{
						JobID:         "discover_1",
						Profile:       "hybrid",
						Adapters:      []string{"moonraker"},
						EndpointHints: []string{moonrakerSrv.URL},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-jobs/discover_1/result"):
			if err := json.NewDecoder(r.Body).Decode(&resultPayload); err != nil {
				t.Fatalf("decode discovery result failed: %v", err)
			}
			mu.Lock()
			resultCalls++
			mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = saasSrv.URL
	a.mu.Unlock()

	if err := a.pollDiscoveryJobsOnce(context.Background()); err != nil {
		t.Fatalf("pollDiscoveryJobsOnce failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if resultCalls != 1 {
		t.Fatalf("result submit calls = %d, want 1", resultCalls)
	}
	if resultPayload.JobStatus != "completed" {
		t.Fatalf("job_status = %q, want completed", resultPayload.JobStatus)
	}
	if resultPayload.Summary.CandidatesFound < 1 {
		t.Fatalf("candidates_found = %d, want >= 1", resultPayload.Summary.CandidatesFound)
	}
	if len(resultPayload.Candidates) < 1 {
		t.Fatalf("expected at least one discovery candidate")
	}
	if resultPayload.Candidates[0].Status != "reachable" {
		t.Fatalf("candidate status = %q, want reachable", resultPayload.Candidates[0].Status)
	}
}

func TestExecuteDiscoveryJobBridgeModeWithoutSeedsRejectsNoTargets(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker"}
	a.cfg.DiscoveryProfileMax = "hybrid"
	a.cfg.DiscoveryNetworkMode = "bridge"
	a.cfg.DiscoveryProbeTimeout = 1500 * time.Millisecond

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_1",
		Profile:  "hybrid",
		Adapters: []string{"moonraker"},
	})

	if result.JobStatus != "policy_rejected" {
		t.Fatalf("job_status = %q, want policy_rejected", result.JobStatus)
	}
	if result.Summary.HostsScanned != 0 {
		t.Fatalf("hosts_scanned = %d, want 0", result.Summary.HostsScanned)
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(result.Candidates))
	}
	if result.Candidates[0].RejectionReason != "no_targets" {
		t.Fatalf("rejection_reason = %q, want no_targets", result.Candidates[0].RejectionReason)
	}
}

func TestExecuteDiscoveryJobUsesBindingSeedTargets(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker"}
	a.cfg.DiscoveryProfileMax = "hybrid"
	a.cfg.DiscoveryNetworkMode = "bridge"
	a.cfg.DiscoveryProbeTimeout = 2 * time.Second

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"status": map[string]any{
						"print_stats": map[string]any{"state": "printing"},
					},
				},
			})
		case "/machine/system_info":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"system_info": map[string]any{
						"product_info": map[string]any{
							"machine_type": "Voron 2.4",
							"device_name":  "Seeded Unit",
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "moonraker",
		EndpointURL:   moonrakerSrv.URL,
	}

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_2",
		Profile:  "hybrid",
		Adapters: []string{"moonraker"},
	})

	if result.JobStatus != "completed" {
		t.Fatalf("job_status = %q, want completed", result.JobStatus)
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(result.Candidates))
	}
	candidate := result.Candidates[0]
	if candidate.Status != "reachable" {
		t.Fatalf("candidate status = %q, want reachable", candidate.Status)
	}
	discoverySource, _ := candidate.Evidence["discovery_source"].(string)
	if discoverySource != discoverySourceSeedManual {
		t.Fatalf("discovery_source = %q, want %q", discoverySource, discoverySourceSeedManual)
	}
}

func TestExecuteDiscoveryJobUsesHistorySeedTargets(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker"}
	a.cfg.DiscoveryProfileMax = "hybrid"
	a.cfg.DiscoveryNetworkMode = "bridge"
	a.cfg.DiscoveryProbeTimeout = 2 * time.Second

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"status": map[string]any{
						"print_stats": map[string]any{"state": "idle"},
					},
				},
			})
		case "/machine/system_info":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"system_info": map[string]any{
						"product_info": map[string]any{
							"machine_type": "Voron 0.2",
							"device_name":  "History Seed Unit",
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	a.discoverySeeds[normalizeDiscoveryEndpointHint(moonrakerSrv.URL)] = time.Now().UTC()

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_3",
		Profile:  "hybrid",
		Adapters: []string{"moonraker"},
	})

	if result.JobStatus != "completed" {
		t.Fatalf("job_status = %q, want completed", result.JobStatus)
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(result.Candidates))
	}
	candidate := result.Candidates[0]
	if candidate.Status != "reachable" {
		t.Fatalf("candidate status = %q, want reachable", candidate.Status)
	}
	discoverySource, _ := candidate.Evidence["discovery_source"].(string)
	if discoverySource != discoverySourceSeedHistory {
		t.Fatalf("discovery_source = %q, want %q", discoverySource, discoverySourceSeedHistory)
	}
}

func TestExecuteDiscoveryJobBambuCloudCandidates(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{Ready: true, AccessToken: "access-1"})
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}
	a.cfg.DiscoveryProbeTimeout = 2 * time.Second

	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("authorization header = %q, want Bearer access-1", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"devices": []map[string]any{
				{
					"dev_id":           "printer-1",
					"name":             "Bambu One",
					"dev_product_name": "X1C",
					"print_status":     "ACTIVE",
					"online":           true,
				},
				{
					"dev_id":           "printer-2",
					"name":             "Bambu Two",
					"dev_product_name": "P1S",
					"print_status":     "OFFLINE",
					"online":           false,
				},
			},
		})
	}))
	defer cloudSrv.Close()
	a.bambuAuthProvider = bambucloud.NewHTTPProvider(bambucloud.HTTPProviderConfig{
		AuthBaseURL: cloudSrv.URL,
		Client:      a.client,
	})

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_bambu_1",
		Profile:  "hybrid",
		Adapters: []string{"bambu"},
	})

	if result.JobStatus != "partial" {
		t.Fatalf("job_status = %q, want partial", result.JobStatus)
	}
	if len(result.Candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2", len(result.Candidates))
	}

	byEndpoint := map[string]discoveryCandidateResult{}
	for _, candidate := range result.Candidates {
		byEndpoint[candidate.EndpointURL] = candidate
	}

	online := byEndpoint["bambu://printer-1"]
	if online.Status != "reachable" {
		t.Fatalf("online candidate status = %q, want reachable", online.Status)
	}
	if online.CurrentPrinterState != "idle" {
		t.Fatalf("online current_printer_state = %q, want idle", online.CurrentPrinterState)
	}
	if online.CurrentJobState != "completed" {
		t.Fatalf("online current_job_state = %q, want completed", online.CurrentJobState)
	}
	if source, _ := online.Evidence["discovery_source"].(string); source != discoverySourceBambuCloud {
		t.Fatalf("online discovery_source = %q, want %q", source, discoverySourceBambuCloud)
	}
	if cloudOnline, ok := online.Evidence["cloud_online"].(bool); !ok || !cloudOnline {
		t.Fatalf("online cloud_online evidence = %v, want true", online.Evidence["cloud_online"])
	}

	offline := byEndpoint["bambu://printer-2"]
	if offline.Status != "unreachable" {
		t.Fatalf("offline candidate status = %q, want unreachable", offline.Status)
	}
	if offline.CurrentPrinterState != "" {
		t.Fatalf("offline current_printer_state = %q, want empty", offline.CurrentPrinterState)
	}
	if offline.CurrentJobState != "" {
		t.Fatalf("offline current_job_state = %q, want empty", offline.CurrentJobState)
	}
	if cloudOnline, ok := offline.Evidence["cloud_online"].(bool); !ok || cloudOnline {
		t.Fatalf("offline cloud_online evidence = %v, want false", offline.Evidence["cloud_online"])
	}
}

func TestExecuteDiscoveryJobBambuCloudUnreachable(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{Ready: true, AccessToken: "access-1"})
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}
	a.cfg.DiscoveryProbeTimeout = 150 * time.Millisecond
	a.bambuAuthProvider = bambucloud.NewHTTPProvider(bambucloud.HTTPProviderConfig{
		AuthBaseURL: "http://127.0.0.1:9",
		Client:      a.client,
	})

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_bambu_2",
		Profile:  "hybrid",
		Adapters: []string{"bambu"},
	})

	if len(result.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(result.Candidates))
	}
	candidate := result.Candidates[0]
	if candidate.Status != "unreachable" {
		t.Fatalf("candidate status = %q, want unreachable", candidate.Status)
	}
	if candidate.AdapterFamily != "bambu" {
		t.Fatalf("adapter_family = %q, want bambu", candidate.AdapterFamily)
	}
	if candidate.EndpointURL != "bambu://cloud" {
		t.Fatalf("endpoint_url = %q, want bambu://cloud", candidate.EndpointURL)
	}
}

func TestExecuteDiscoveryJobBambuCloudMissingTokenRejected(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{Ready: true})
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_bambu_3",
		Profile:  "hybrid",
		Adapters: []string{"bambu"},
	})

	if len(result.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(result.Candidates))
	}
	candidate := result.Candidates[0]
	if candidate.Status != "policy_rejected" {
		t.Fatalf("candidate status = %q, want policy_rejected", candidate.Status)
	}
	if candidate.RejectionReason != "auth_token_missing" {
		t.Fatalf("rejection_reason = %q, want auth_token_missing", candidate.RejectionReason)
	}
}

func TestMapBambuCloudStatesProducesSchemaCompatibleValues(t *testing.T) {
	printerAllowed := map[string]struct{}{
		"idle":     {},
		"queued":   {},
		"printing": {},
		"paused":   {},
		"error":    {},
	}
	jobAllowed := map[string]struct{}{
		"pending":   {},
		"printing":  {},
		"completed": {},
		"failed":    {},
		"canceled":  {},
	}

	cases := []struct {
		name        string
		online      bool
		printStatus string
	}{
		{name: "offline", online: false, printStatus: "OFFLINE"},
		{name: "active", online: true, printStatus: "ACTIVE"},
		{name: "paused", online: true, printStatus: "PAUSED"},
		{name: "error", online: true, printStatus: "ERROR"},
		{name: "unknown", online: true, printStatus: "MYSTERY"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			printerState, jobState := mapBambuCloudStates(tc.online, tc.printStatus)
			if _, ok := printerAllowed[printerState]; !ok {
				t.Fatalf("printer_state=%q is not schema-compatible", printerState)
			}
			if _, ok := jobAllowed[jobState]; !ok {
				t.Fatalf("job_state=%q is not schema-compatible", jobState)
			}
		})
	}
}

func TestMapBambuCloudStatesNormalizesActiveAndOfflineStates(t *testing.T) {
	tests := []struct {
		name        string
		online      bool
		printStatus string
		wantPrinter string
		wantJob     string
	}{
		{name: "active treated as idle", online: true, printStatus: "ACTIVE", wantPrinter: "idle", wantJob: "completed"},
		{name: "printing", online: true, printStatus: "PRINTING", wantPrinter: "printing", wantJob: "printing"},
		{name: "offline", online: false, printStatus: "OFFLINE", wantPrinter: "error", wantJob: "failed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			printerState, jobState := mapBambuCloudStates(tc.online, tc.printStatus)
			if printerState != tc.wantPrinter || jobState != tc.wantJob {
				t.Fatalf("mapBambuCloudStates(%t,%q)=(%q,%q), want (%q,%q)", tc.online, tc.printStatus, printerState, jobState, tc.wantPrinter, tc.wantJob)
			}
		})
	}
}

func TestPollDiscoveryScanRequestsOnceReturnsPendingRequest(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		if !strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-scan-requests") {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, discoveryScanRequestsResponse{
			Requests: []discoveryScanRequestItem{
				{
					RequestToken: "scan_req_1",
					RequestedAt:  edgeTimestamp{Time: time.Now().UTC()},
					ExpiresAt:    edgeTimestamp{Time: time.Now().UTC().Add(2 * time.Minute)},
				},
			},
		})
	}))
	defer saasSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = saasSrv.URL
	a.mu.Unlock()

	requests, err := a.pollDiscoveryScanRequestsOnce(context.Background())
	if err != nil {
		t.Fatalf("pollDiscoveryScanRequestsOnce failed: %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}
	if requests[0].RequestToken != "scan_req_1" {
		t.Fatalf("request token = %q, want scan_req_1", requests[0].RequestToken)
	}
}

func TestPollDiscoveryScanRequestsOnceAcceptsNaiveTimestamps(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		if !strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-scan-requests") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"requests":[{"request_token":"scan_req_2","requested_at":"2026-02-15T13:32:32.065292","expires_at":"2026-02-15T13:37:32.065292"}]}`)
	}))
	defer saasSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = saasSrv.URL
	a.mu.Unlock()

	requests, err := a.pollDiscoveryScanRequestsOnce(context.Background())
	if err != nil {
		t.Fatalf("pollDiscoveryScanRequestsOnce failed: %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("request count = %d, want 1", len(requests))
	}
	if requests[0].RequestToken != "scan_req_2" {
		t.Fatalf("request token = %q, want scan_req_2", requests[0].RequestToken)
	}
}

func TestSubmitDiscoveryInventoryPostsPayload(t *testing.T) {
	a := newTestAgent(t)
	bootstrap := bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}

	var (
		calls   int
		scanID  string
		entries int
	)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		if !strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-inventory") {
			http.NotFound(w, r)
			return
		}
		var payload discoveryInventoryReportRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		calls++
		scanID = payload.ScanID
		entries = len(payload.Entries)
		writeJSON(w, http.StatusOK, discoveryInventoryIngestResponse{
			ScanID:          payload.ScanID,
			AcceptedEntries: len(payload.Entries),
			MatchedEntries:  0,
			PendingEntries:  len(payload.Entries),
			GeneratedAt:     time.Now().UTC(),
		})
	}))
	defer saasSrv.Close()

	bootstrap.ControlPlaneURL = saasSrv.URL
	err := a.submitDiscoveryInventory(context.Background(), bootstrap, discoveryInventoryReportRequest{
		ScanID:       "scan_payload_1",
		ScanMode:     "manual",
		TriggerToken: "scan_req_1",
		StartedAt:    time.Now().UTC(),
		FinishedAt:   time.Now().UTC(),
		Summary: discoveryInventorySummary{
			HostsScanned:   1,
			HostsReachable: 1,
			EntriesCount:   1,
			ErrorsCount:    0,
		},
		Entries: []discoveryInventoryEntryReport{
			{
				AdapterFamily:       "moonraker",
				EndpointURL:         "http://192.168.1.55:7125",
				Status:              "reachable",
				DetectedPrinterName: "Discovery Unit",
				DetectedModelHint:   "Voron 2.4",
			},
		},
	})
	if err != nil {
		t.Fatalf("submitDiscoveryInventory failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("submit calls = %d, want 1", calls)
	}
	if scanID != "scan_payload_1" {
		t.Fatalf("scan_id = %q, want scan_payload_1", scanID)
	}
	if entries != 1 {
		t.Fatalf("entries = %d, want 1", entries)
	}
}

func TestRunAndSubmitDiscoveryInventoryScanIncludesBambuCloudDevices(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}
	a.cfg.DiscoveryProbeTimeout = 2 * time.Second
	a.setBambuAuthState(bambuAuthState{Ready: true, AccessToken: "access-1"})

	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("authorization header = %q, want Bearer access-1", got)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"devices": []map[string]any{
				{
					"dev_id":           "printer-online",
					"name":             "Bambu Online",
					"dev_product_name": "X1C",
					"print_status":     "ACTIVE",
					"online":           true,
				},
				{
					"dev_id":           "printer-offline",
					"name":             "Bambu Offline",
					"dev_product_name": "P1S",
					"print_status":     "OFFLINE",
					"online":           false,
				},
			},
		})
	}))
	defer cloudSrv.Close()
	a.bambuAuthProvider = bambucloud.NewHTTPProvider(bambucloud.HTTPProviderConfig{
		AuthBaseURL: cloudSrv.URL,
		Client:      a.client,
	})

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	var captured discoveryInventoryReportRequest
	var calls int
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-inventory") {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode discovery inventory payload failed: %v", err)
		}
		calls++
		writeJSON(w, http.StatusOK, discoveryInventoryIngestResponse{
			ScanID:          captured.ScanID,
			AcceptedEntries: len(captured.Entries),
			MatchedEntries:  0,
			PendingEntries:  len(captured.Entries),
			GeneratedAt:     time.Now().UTC(),
		})
	}))
	defer saasSrv.Close()
	a.bootstrap.ControlPlaneURL = saasSrv.URL

	if err := a.runAndSubmitDiscoveryInventoryScan(context.Background(), "manual", "scan_req_bambu", time.Time{}); err != nil {
		t.Fatalf("runAndSubmitDiscoveryInventoryScan failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("inventory submit calls = %d, want 1", calls)
	}
	if len(captured.Entries) != 2 {
		t.Fatalf("inventory entries = %d, want 2", len(captured.Entries))
	}
	entriesByEndpoint := map[string]discoveryInventoryEntryReport{}
	for _, entry := range captured.Entries {
		if entry.AdapterFamily != "bambu" {
			t.Fatalf("entry adapter_family = %q, want bambu", entry.AdapterFamily)
		}
		entriesByEndpoint[entry.EndpointURL] = entry
	}
	online, ok := entriesByEndpoint["bambu://printer-online"]
	if !ok {
		t.Fatalf("expected inventory entry for bambu://printer-online")
	}
	onlineFlag, ok := online.Evidence["cloud_online"].(bool)
	if !ok || !onlineFlag {
		t.Fatalf("online cloud_online evidence = %v, want true", online.Evidence["cloud_online"])
	}
	offline, ok := entriesByEndpoint["bambu://printer-offline"]
	if !ok {
		t.Fatalf("expected inventory entry for bambu://printer-offline")
	}
	if offline.Status != "unreachable" {
		t.Fatalf("offline status = %q, want unreachable", offline.Status)
	}
	if offline.CurrentPrinterState != "" {
		t.Fatalf("offline current_printer_state = %q, want empty", offline.CurrentPrinterState)
	}
	if offline.CurrentJobState != "" {
		t.Fatalf("offline current_job_state = %q, want empty", offline.CurrentJobState)
	}
	offlineFlag, ok := offline.Evidence["cloud_online"].(bool)
	if !ok || offlineFlag {
		t.Fatalf("offline cloud_online evidence = %v, want false", offline.Evidence["cloud_online"])
	}
}

func TestRunAndSubmitDiscoveryInventoryScanReportsReachableAndUnreachable(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker"}
	a.cfg.DiscoveryProfileMax = "hybrid"
	a.cfg.DiscoveryNetworkMode = "bridge"
	a.cfg.DiscoveryProbeTimeout = 150 * time.Millisecond

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"status": map[string]any{
						"print_stats": map[string]any{"state": "idle"},
					},
				},
			})
		case "/machine/system_info":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"system_info": map[string]any{
						"product_info": map[string]any{
							"machine_type": "Test Printer",
							"device_name":  "Reachable Unit",
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	a.cfg.DiscoveryEndpointHints = []string{
		moonrakerSrv.URL,
		"http://127.0.0.1:1", // unreachable by design
	}

	var captured discoveryInventoryReportRequest
	var calls int
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-inventory") {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode discovery inventory payload failed: %v", err)
		}
		calls++
		writeJSON(w, http.StatusOK, discoveryInventoryIngestResponse{
			ScanID:          captured.ScanID,
			AcceptedEntries: len(captured.Entries),
			MatchedEntries:  0,
			PendingEntries:  len(captured.Entries),
			GeneratedAt:     time.Now().UTC(),
		})
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	if err := a.runAndSubmitDiscoveryInventoryScan(context.Background(), "manual", "scan_req_test", time.Time{}); err != nil {
		t.Fatalf("runAndSubmitDiscoveryInventoryScan failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("inventory submit calls = %d, want 1", calls)
	}
	if len(captured.Entries) != 2 {
		t.Fatalf("inventory entries = %d, want 2 entries (reachable + unreachable)", len(captured.Entries))
	}
	entriesByEndpoint := map[string]discoveryInventoryEntryReport{}
	for _, entry := range captured.Entries {
		entriesByEndpoint[entry.EndpointURL] = entry
	}
	reachableEntry, ok := entriesByEndpoint[moonrakerSrv.URL]
	if !ok {
		t.Fatalf("expected reachable entry for %q", moonrakerSrv.URL)
	}
	if reachableEntry.Status != "reachable" {
		t.Fatalf("reachable entry status = %q, want reachable", reachableEntry.Status)
	}
	unreachableEntry, ok := entriesByEndpoint["http://127.0.0.1:1"]
	if !ok {
		t.Fatalf("expected unreachable entry for http://127.0.0.1:1")
	}
	if unreachableEntry.Status != "unreachable" {
		t.Fatalf("unreachable entry status = %q, want unreachable", unreachableEntry.Status)
	}
	if strings.TrimSpace(unreachableEntry.ConnectivityError) == "" {
		t.Fatalf("expected connectivity_error for unreachable entry")
	}
}

func TestRunAndSubmitDiscoveryInventoryScanManualBusyTimeoutEmitsFailedEvent(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true
	a.discoveryRunning = true

	var (
		mu     sync.Mutex
		events []discoveryScanEventRequest
	)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-scan-events"):
			var payload discoveryScanEventRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode discovery scan event failed: %v", err)
			}
			mu.Lock()
			events = append(events, payload)
			mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-inventory"):
			t.Fatalf("discovery inventory submit should not happen when lock wait times out")
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()
	a.bootstrap.ControlPlaneURL = saasSrv.URL

	manualExpiresAt := time.Now().UTC().Add(100 * time.Millisecond)
	err := a.runAndSubmitDiscoveryInventoryScan(context.Background(), "manual", "scan_req_busy_timeout", manualExpiresAt)
	if err == nil {
		t.Fatal("expected lock timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "discovery_scan_lock_busy_timeout") {
		t.Fatalf("unexpected error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	if events[0].Status != "failed" {
		t.Fatalf("event status = %q, want failed", events[0].Status)
	}
	if events[0].TriggerToken != "scan_req_busy_timeout" {
		t.Fatalf("trigger token = %q, want scan_req_busy_timeout", events[0].TriggerToken)
	}
}

func TestRunAndSubmitDiscoveryInventoryScanManualWaitsForBusyLock(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker"}
	a.cfg.DiscoveryProfileMax = "hybrid"
	a.cfg.DiscoveryNetworkMode = "bridge"
	a.cfg.DiscoveryProbeTimeout = 150 * time.Millisecond

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"status": map[string]any{
						"print_stats": map[string]any{"state": "idle"},
					},
				},
			})
		case "/machine/system_info":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"system_info": map[string]any{
						"product_info": map[string]any{
							"machine_type": "Test Printer",
							"device_name":  "Retry Unit",
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()
	a.cfg.DiscoveryEndpointHints = []string{moonrakerSrv.URL}

	var (
		mu             sync.Mutex
		inventoryCalls int
		eventStatuses  []string
	)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-scan-events"):
			var payload discoveryScanEventRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode discovery scan event failed: %v", err)
			}
			mu.Lock()
			eventStatuses = append(eventStatuses, payload.Status)
			mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/discovery-inventory"):
			var payload discoveryInventoryReportRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode discovery inventory payload failed: %v", err)
			}
			mu.Lock()
			inventoryCalls++
			mu.Unlock()
			writeJSON(w, http.StatusOK, discoveryInventoryIngestResponse{
				ScanID:          payload.ScanID,
				AcceptedEntries: len(payload.Entries),
				MatchedEntries:  0,
				PendingEntries:  len(payload.Entries),
				GeneratedAt:     time.Now().UTC(),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true
	a.discoveryRunning = true

	go func() {
		time.Sleep(50 * time.Millisecond)
		a.endDiscoveryRun()
	}()

	if err := a.runAndSubmitDiscoveryInventoryScan(
		context.Background(),
		"manual",
		"scan_req_wait",
		time.Now().UTC().Add(2*time.Second),
	); err != nil {
		t.Fatalf("runAndSubmitDiscoveryInventoryScan failed after lock released: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if inventoryCalls != 1 {
		t.Fatalf("inventory submit calls = %d, want 1", inventoryCalls)
	}
	if len(eventStatuses) < 2 {
		t.Fatalf("event statuses count = %d, want at least 2 (started/completed)", len(eventStatuses))
	}
	if eventStatuses[0] != "started" {
		t.Fatalf("first event status = %q, want started", eventStatuses[0])
	}
	last := eventStatuses[len(eventStatuses)-1]
	if last != "completed" && last != "failed" {
		t.Fatalf("last event status = %q, want completed/failed", last)
	}
}

func TestIsSupportedDiscoveryAdapter(t *testing.T) {
	tests := []struct {
		name           string
		adapter        string
		klipperEnabled bool
		bambuEnabled   bool
		want           bool
	}{
		{name: "moonraker supported", adapter: "moonraker", klipperEnabled: true, bambuEnabled: false, want: true},
		{name: "klipper alias supported", adapter: "klipper", klipperEnabled: true, bambuEnabled: false, want: true},
		{name: "moonraker disabled", adapter: "moonraker", klipperEnabled: false, bambuEnabled: true, want: false},
		{name: "bambu disabled", adapter: "bambu", klipperEnabled: true, bambuEnabled: false, want: false},
		{name: "bambu enabled", adapter: "bambu", klipperEnabled: true, bambuEnabled: true, want: true},
		{name: "unsupported adapter", adapter: "unknown", klipperEnabled: true, bambuEnabled: true, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isSupportedDiscoveryAdapter(tc.adapter, tc.klipperEnabled, tc.bambuEnabled)
			if got != tc.want {
				t.Fatalf(
					"isSupportedDiscoveryAdapter(%q, klipperEnabled=%t, bambuEnabled=%t)=%t, want %t",
					tc.adapter,
					tc.klipperEnabled,
					tc.bambuEnabled,
					got,
					tc.want,
				)
			}
		})
	}
}

func TestShouldSkipDiscoveryInterface(t *testing.T) {
	tests := []struct {
		name  string
		iface net.Interface
		want  bool
	}{
		{
			name:  "down interface",
			iface: net.Interface{Name: "en0", Flags: 0},
			want:  true,
		},
		{
			name:  "loopback interface",
			iface: net.Interface{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback},
			want:  true,
		},
		{
			name:  "point to point interface",
			iface: net.Interface{Name: "ppp0", Flags: net.FlagUp | net.FlagPointToPoint},
			want:  true,
		},
		{
			name:  "docker virtual interface",
			iface: net.Interface{Name: "docker0", Flags: net.FlagUp},
			want:  true,
		},
		{
			name:  "utun virtual interface",
			iface: net.Interface{Name: "utun3", Flags: net.FlagUp},
			want:  true,
		},
		{
			name:  "physical interface",
			iface: net.Interface{Name: "en0", Flags: net.FlagUp},
			want:  false,
		},
		{
			name:  "windows wifi interface",
			iface: net.Interface{Name: "Wi-Fi", Flags: net.FlagUp},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipDiscoveryInterface(tc.iface)
			if got != tc.want {
				t.Fatalf("shouldSkipDiscoveryInterface(%q) = %v, want %v", tc.iface.Name, got, tc.want)
			}
		})
	}
}

func TestPollDesiredStateOnceRejectsUnsupportedSchemaVersion(t *testing.T) {
	a := newTestAgent(t)
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       7,
		DesiredPrinterState: "printing",
	}

	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/desired-state") {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(desiredStateResponse{
			SchemaVersion: 99,
			States: []desiredStateItem{
				{
					PrinterID:           1,
					IntentVersion:       8,
					DesiredPrinterState: "idle",
				},
			},
		})
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	err := a.pollDesiredStateOnce(context.Background())
	if err == nil {
		t.Fatalf("expected unsupported schema error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.desiredState[1].IntentVersion != 7 {
		t.Fatalf("desired state should remain unchanged on schema validation failure")
	}
}

func TestPollBindingsOnceRevokedKeyDisablesAgent(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true
	a.actionQueue[1] = []action{{PrinterID: 1, Kind: "print"}}
	a.bindings[1] = edgeBinding{PrinterID: 1, EndpointURL: "http://printer"}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/bindings") {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Edge API key revoked", http.StatusForbidden)
	}))
	defer srv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = srv.URL
	a.mu.Unlock()

	err := a.pollBindingsOnce(context.Background())
	if err == nil {
		t.Fatalf("expected auth revocation error")
	}
	if !errors.Is(err, errEdgeAuthRevoked) {
		t.Fatalf("expected errEdgeAuthRevoked, got: %v", err)
	}
	if a.isClaimed() {
		t.Fatalf("expected agent to stop claimed mode after auth revocation")
	}
	if len(a.actionQueue) != 0 {
		t.Fatalf("expected action queue to be cleared after auth revocation")
	}
	if len(a.bindings) != 0 {
		t.Fatalf("expected bindings cache to be cleared after auth revocation")
	}
}

func TestPollBindingsOncePrunesStateForRemovedBindings(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true
	a.bindings[1] = edgeBinding{PrinterID: 1, EndpointURL: "http://printer-1"}
	a.bindings[2] = edgeBinding{PrinterID: 2, EndpointURL: "http://printer-2"}
	a.currentState[1] = currentStateItem{PrinterID: 1, CurrentPrinterState: "idle"}
	a.currentState[2] = currentStateItem{PrinterID: 2, CurrentPrinterState: "idle"}
	a.desiredState[2] = desiredStateItem{PrinterID: 2, IntentVersion: 1, DesiredPrinterState: "idle"}
	a.actionQueue[2] = []action{{PrinterID: 2, Kind: "stop"}}
	a.deadLetters[2] = []action{{PrinterID: 2, Kind: "print"}}
	a.queuedSince[2] = time.Now().UTC()
	a.breakerUntil[2] = time.Now().UTC().Add(time.Minute)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/bindings") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(bindingsResponse{
			AgentID: "edge_1",
			Bindings: []edgeBinding{
				{PrinterID: 1, AdapterFamily: "moonraker", EndpointURL: "http://printer-1"},
			},
		})
	}))
	defer srv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = srv.URL
	a.mu.Unlock()

	if err := a.pollBindingsOnce(context.Background()); err != nil {
		t.Fatalf("pollBindingsOnce failed: %v", err)
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	if _, exists := a.currentState[2]; exists {
		t.Fatalf("expected currentState for printer 2 to be pruned")
	}
	if _, exists := a.desiredState[2]; exists {
		t.Fatalf("expected desiredState for printer 2 to be pruned")
	}
	if _, exists := a.actionQueue[2]; exists {
		t.Fatalf("expected actionQueue for printer 2 to be pruned")
	}
	if _, exists := a.deadLetters[2]; exists {
		t.Fatalf("expected deadLetters for printer 2 to be pruned")
	}
	if _, exists := a.queuedSince[2]; exists {
		t.Fatalf("expected queuedSince for printer 2 to be pruned")
	}
	if _, exists := a.breakerUntil[2]; exists {
		t.Fatalf("expected breakerUntil for printer 2 to be pruned")
	}
}

func TestConvergeUpdatesCurrentStateAndQueue(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "moonraker",
		EndpointURL:   "http://moonraker:7125",
	}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       3,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-1",
		PlateID:             11,
		ArtifactURL:         "http://artifacts.local/plate.gcode",
		ChecksumSHA256:      "abc",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
	}

	a.reconcileOnce()

	cur := a.currentState[1]
	if cur.CurrentPrinterState != "idle" {
		t.Fatalf("current state after reconcile = %q, want idle before action execution", cur.CurrentPrinterState)
	}
	if cur.IntentVersionApplied != 0 {
		t.Fatalf("intent_version_applied = %d, want 0 before action execution", cur.IntentVersionApplied)
	}
	actions := a.actionQueue[1]
	if len(actions) != 1 {
		t.Fatalf("action queue length = %d, want 1", len(actions))
	}
	if actions[0].Kind != "print" {
		t.Fatalf("action kind = %q, want print", actions[0].Kind)
	}
	if actions[0].Target.IntentVersion != 3 {
		t.Fatalf("action intent version = %d, want 3", actions[0].Target.IntentVersion)
	}
}

func TestConvergeRequiresArtifactURLForPrinting(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "moonraker",
		EndpointURL:   "http://moonraker:7125",
	}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       1,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
	}

	a.reconcileOnce()

	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected no queued actions when artifact fields are missing")
	}
	cur := a.currentState[1]
	if cur.CurrentPrinterState != "error" {
		t.Fatalf("current state after reconcile = %q, want error", cur.CurrentPrinterState)
	}
	if cur.LastErrorCode != "artifact_fetch_error" {
		t.Fatalf("last error code = %q, want artifact_fetch_error", cur.LastErrorCode)
	}
}

func TestConvergeAllowsPrintingWithoutChecksum(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "moonraker",
		EndpointURL:   "http://moonraker:7125",
	}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       1,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		ArtifactURL:         "http://artifacts.local/plate.gcode",
		ChecksumSHA256:      "",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
	}

	a.reconcileOnce()

	if len(a.actionQueue[1]) != 1 {
		t.Fatalf("expected one queued print action when checksum is missing but artifact_url exists")
	}
	if a.actionQueue[1][0].Kind != "print" {
		t.Fatalf("action kind = %q, want print", a.actionQueue[1][0].Kind)
	}
}

func TestConvergeInvalidTransitionReportsOriginalSourceState(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "moonraker",
		EndpointURL:   "http://moonraker:7125",
	}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       1,
		DesiredPrinterState: "paused",
		DesiredJobState:     "printing",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
	}

	a.reconcileOnce()

	cur := a.currentState[1]
	if cur.CurrentPrinterState != "error" {
		t.Fatalf("current state after reconcile = %q, want error", cur.CurrentPrinterState)
	}
	if cur.LastErrorCode != "validation_error" {
		t.Fatalf("last error code = %q, want validation_error", cur.LastErrorCode)
	}
	if !strings.Contains(cur.LastErrorMessage, "from idle to desired paused") {
		t.Fatalf("unexpected validation message: %q", cur.LastErrorMessage)
	}
}

func TestDownloadArtifactChecksumMismatch(t *testing.T) {
	a := newTestAgent(t)
	artifactPath := filepath.Join(t.TempDir(), "plate.gcode")
	if err := os.WriteFile(artifactPath, []byte("G1 X10\n"), 0o600); err != nil {
		t.Fatalf("failed to write test artifact: %v", err)
	}

	srv := newFileServer(t, artifactPath)
	defer srv.Close()

	_, _, err := a.downloadArtifact(context.Background(), desiredStateItem{
		PrinterID:      1,
		PlateID:        99,
		ArtifactURL:    srv.URL,
		ChecksumSHA256: "deadbeef",
	})
	if err == nil {
		t.Fatalf("expected checksum mismatch error")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error, got: %v", err)
	}

	entries, readErr := os.ReadDir(a.cfg.ArtifactStageDir)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatalf("read artifact stage dir failed: %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no staged artifacts after checksum failure, found %d", len(entries))
	}
}

func TestDownloadArtifactHonorsTimeoutBudget(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.ArtifactDownloadTimeout = 20 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte("G1 X10\n"))
	}))
	defer srv.Close()

	_, _, err := a.downloadArtifact(context.Background(), desiredStateItem{
		PrinterID:      1,
		PlateID:        1,
		ArtifactURL:    srv.URL,
		ChecksumSHA256: "deadbeef",
	})
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") {
		t.Fatalf("expected deadline exceeded error, got: %v", err)
	}
}

func TestDownloadArtifactSucceedsWithoutChecksum(t *testing.T) {
	a := newTestAgent(t)
	artifactPath := filepath.Join(t.TempDir(), "plate.gcode")
	content := []byte("G1 X10\n")
	if err := os.WriteFile(artifactPath, content, 0o600); err != nil {
		t.Fatalf("failed to write test artifact: %v", err)
	}

	srv := newFileServer(t, artifactPath)
	defer srv.Close()

	readyPath, _, err := a.downloadArtifact(context.Background(), desiredStateItem{
		PrinterID:      1,
		PlateID:        99,
		ArtifactURL:    srv.URL,
		ChecksumSHA256: "",
	})
	if err != nil {
		t.Fatalf("expected download to succeed without checksum, got: %v", err)
	}
	defer a.cleanupArtifact(readyPath)

	data, readErr := os.ReadFile(readyPath)
	if readErr != nil {
		t.Fatalf("failed to read staged artifact: %v", readErr)
	}
	if string(data) != string(content) {
		t.Fatalf("staged artifact content mismatch")
	}
}

func TestDownloadArtifactResolvesRelativeURLWithControlPlaneAuth(t *testing.T) {
	a := newTestAgent(t)
	artifactBytes := []byte("G1 X9 Y9\n")
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/artifacts/plates/42" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if got := r.Header.Get("Authorization"); got == "" || !strings.HasPrefix(got, "Bearer ") {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get("X-Edge-Agent-Id"); got != "edge_test" {
			http.Error(w, "missing agent id", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(artifactBytes)
	}))
	defer artifactSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = artifactSrv.URL
	a.bootstrap.SaaSAPIKey = "edge-test-key"
	a.bootstrap.AgentID = "edge_test"
	a.claimed = true
	a.mu.Unlock()

	readyPath, _, err := a.downloadArtifact(context.Background(), desiredStateItem{
		PrinterID:      1,
		PlateID:        42,
		ArtifactURL:    "/edge/artifacts/plates/42",
		ChecksumSHA256: "",
	})
	if err != nil {
		t.Fatalf("downloadArtifact failed: %v", err)
	}
	defer a.cleanupArtifact(readyPath)

	data, readErr := os.ReadFile(readyPath)
	if readErr != nil {
		t.Fatalf("read staged artifact failed: %v", readErr)
	}
	if string(data) != string(artifactBytes) {
		t.Fatalf("staged artifact mismatch")
	}
}

func TestCleanupStagedArtifactsRemovesPartAndReadyFiles(t *testing.T) {
	a := newTestAgent(t)
	if err := os.MkdirAll(a.cfg.ArtifactStageDir, 0o755); err != nil {
		t.Fatalf("mkdir artifact stage dir failed: %v", err)
	}
	partPath := filepath.Join(a.cfg.ArtifactStageDir, "leftover.part")
	readyPath := filepath.Join(a.cfg.ArtifactStageDir, "leftover.ready")
	otherPath := filepath.Join(a.cfg.ArtifactStageDir, "keep.txt")
	if err := os.WriteFile(partPath, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write part file failed: %v", err)
	}
	if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("write ready file failed: %v", err)
	}
	if err := os.WriteFile(otherPath, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write keep file failed: %v", err)
	}

	if err := a.cleanupStagedArtifacts(); err != nil {
		t.Fatalf("cleanupStagedArtifacts failed: %v", err)
	}

	if _, err := os.Stat(partPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected .part file removed, stat err=%v", err)
	}
	if _, err := os.Stat(readyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected .ready file removed, stat err=%v", err)
	}
	if _, err := os.Stat(otherPath); err != nil {
		t.Fatalf("expected non-staged file to remain, stat err=%v", err)
	}
}

func newFileServer(t *testing.T, filePath string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filePath)
	}))
}

func TestExecutePrintActionUploadsAndStarts(t *testing.T) {
	a := newTestAgent(t)
	artifact := []byte("G1 X10 Y10\n")
	checksum := sha256.Sum256(artifact)

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	var (
		mu           sync.Mutex
		uploadCalls  int
		startCalls   int
		uploadedData []byte
	)
	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/files/upload":
			uploadCalls++
			if err := r.ParseMultipartForm(2 << 20); err != nil {
				t.Fatalf("parse multipart form failed: %v", err)
			}
			file, _, err := r.FormFile("file")
			if err != nil {
				t.Fatalf("missing file form field: %v", err)
			}
			defer file.Close()
			body, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("read uploaded file failed: %v", err)
			}
			mu.Lock()
			uploadedData = body
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/printer/print/start":
			startCalls++
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	act := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			PlateID:             7,
			IntentVersion:       9,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			ArtifactURL:         artifactSrv.URL,
			ChecksumSHA256:      hex.EncodeToString(checksum[:]),
		},
	}

	if err := a.executeAction(context.Background(), act, edgeBinding{PrinterID: 1, EndpointURL: moonrakerSrv.URL}); err != nil {
		t.Fatalf("executeAction(print) failed: %v", err)
	}

	if uploadCalls != 1 {
		t.Fatalf("upload calls = %d, want 1", uploadCalls)
	}
	if startCalls != 1 {
		t.Fatalf("start calls = %d, want 1", startCalls)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(uploadedData) != string(artifact) {
		t.Fatalf("uploaded artifact mismatch: got %q want %q", string(uploadedData), string(artifact))
	}
}

func TestExecuteControlActions(t *testing.T) {
	a := newTestAgent(t)
	hits := map[string]int{}
	var mu sync.Mutex

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer moonrakerSrv.Close()

	tests := []struct {
		kind string
		path string
	}{
		{kind: "pause", path: "/printer/print/pause"},
		{kind: "resume", path: "/printer/print/resume"},
		{kind: "stop", path: "/printer/print/cancel"},
	}
	for _, tc := range tests {
		if err := a.executeAction(context.Background(), action{PrinterID: 1, Kind: tc.kind}, edgeBinding{PrinterID: 1, EndpointURL: moonrakerSrv.URL}); err != nil {
			t.Fatalf("executeAction(%s) failed: %v", tc.kind, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for _, tc := range tests {
		if hits[tc.path] != 1 {
			t.Fatalf("path %s called %d times, want 1", tc.path, hits[tc.path])
		}
	}
}

func TestExecuteActionBambuDisabled(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = false

	err := a.executeAction(
		context.Background(),
		action{PrinterID: 1, Kind: "pause"},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err == nil {
		t.Fatalf("expected validation error for disabled bambu path")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "validation_error") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteActionBambuConnectRejected(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{Ready: true})

	err := a.executeAction(
		context.Background(),
		action{PrinterID: 1, Kind: "pause"},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err == nil {
		t.Fatalf("expected bambu connect action to be rejected in this phase")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not enabled via bambu connect bridge") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchBindingSnapshotBambuCloudEnabledWithoutConnectURI(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuConnectURI = "http://127.0.0.1:9"
	a.setBambuAuthState(bambuAuthState{Ready: true, AccessToken: "access-1"})

	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("authorization header = %q, want Bearer access-1", got)
		}
		_, _ = w.Write([]byte(`{"devices":[{"dev_id":"printer-123","name":"Bambu Unit","dev_product_name":"X1C","print_status":"ACTIVE","online":true}]}`))
	}))
	defer cloudSrv.Close()
	a.bambuAuthProvider = bambucloud.NewHTTPProvider(bambucloud.HTTPProviderConfig{
		AuthBaseURL: cloudSrv.URL,
		Client:      a.client,
	})

	state, job, err := a.fetchBindingSnapshot(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-123",
	})
	if err != nil {
		t.Fatalf("fetchBindingSnapshot failed: %v", err)
	}
	if state != "idle" || job != "completed" {
		t.Fatalf("snapshot = (%s,%s), want (idle,completed)", state, job)
	}
}

func TestFetchBindingSnapshotBambuCloudDeviceNotFoundReturnsError(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{Ready: true, AccessToken: "access-1"})

	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[{"dev_id":"different-printer","name":"Other Unit","dev_product_name":"X1C","print_status":"ACTIVE","online":true}]}`))
	}))
	defer cloudSrv.Close()
	a.bambuAuthProvider = bambucloud.NewHTTPProvider(bambucloud.HTTPProviderConfig{
		AuthBaseURL: cloudSrv.URL,
		Client:      a.client,
	})

	_, _, err := a.fetchBindingSnapshot(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-123",
	})
	if err == nil {
		t.Fatalf("expected snapshot error when cloud device is missing")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not bound") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchBindingSnapshotBambuCloudOfflineReturnsError(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{Ready: true, AccessToken: "access-1"})

	cloudSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"devices":[{"dev_id":"printer-123","name":"Bambu Unit","dev_product_name":"X1C","print_status":"OFFLINE","online":false}]}`))
	}))
	defer cloudSrv.Close()
	a.bambuAuthProvider = bambucloud.NewHTTPProvider(bambucloud.HTTPProviderConfig{
		AuthBaseURL: cloudSrv.URL,
		Client:      a.client,
	})

	_, _, err := a.fetchBindingSnapshot(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-123",
	})
	if err == nil {
		t.Fatalf("expected snapshot error for offline cloud device")
	}
	var offlineErr *bambuCloudDeviceOfflineError
	if !errors.As(err, &offlineErr) {
		t.Fatalf("expected bambuCloudDeviceOfflineError, got %T (%v)", err, err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "offline") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchBambuConnectSnapshotDefaultsJobState(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	connectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/printers/printer-abc/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"printer_id":"printer-abc","printer_state":"paused","printer_name":"Paused Unit","model":"P1S"}`))
	}))
	defer connectSrv.Close()
	a.cfg.BambuConnectURI = connectSrv.URL

	snapshot, err := a.fetchBambuConnectSnapshotByPrinterID(context.Background(), "printer-abc")
	if err != nil {
		t.Fatalf("fetchBambuConnectSnapshotByPrinterID failed: %v", err)
	}
	if snapshot.PrinterState != "paused" || snapshot.JobState != "printing" {
		t.Fatalf("snapshot = (%s,%s), want (paused,printing)", snapshot.PrinterState, snapshot.JobState)
	}
}

func TestFetchBindingSnapshotMoonrakerUnaffectedWhenBambuDisabled(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/printer/objects/query" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"paused"}}}}`))
	}))
	defer srv.Close()

	state, job, err := a.fetchBindingSnapshot(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "moonraker",
		EndpointURL:   srv.URL,
	})
	if err != nil {
		t.Fatalf("fetchBindingSnapshot failed: %v", err)
	}
	if state != "paused" || job != "printing" {
		t.Fatalf("snapshot = (%s,%s), want (paused,printing)", state, job)
	}
}

func TestCallMoonrakerPostHonorsTimeoutBudget(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.MoonrakerRequestTimeout = 20 * time.Millisecond

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer moonrakerSrv.Close()

	err := a.callMoonrakerPost(context.Background(), moonrakerSrv.URL, "/printer/print/pause", nil)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "deadline exceeded") {
		t.Fatalf("expected deadline exceeded error, got: %v", err)
	}
}

func TestFetchMoonrakerSnapshotMapping(t *testing.T) {
	a := newTestAgent(t)
	tests := []struct {
		name      string
		rawState  string
		wantState string
		wantJob   string
	}{
		{name: "printing", rawState: "printing", wantState: "printing", wantJob: "printing"},
		{name: "paused", rawState: "paused", wantState: "paused", wantJob: "printing"},
		{name: "canceled", rawState: "cancelled", wantState: "idle", wantJob: "canceled"},
		{name: "unknown", rawState: "ready", wantState: "idle", wantJob: "pending"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/printer/objects/query" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"` + tc.rawState + `"}}}}`))
			}))
			defer srv.Close()

			gotState, gotJob, err := a.fetchMoonrakerSnapshot(context.Background(), srv.URL)
			if err != nil {
				t.Fatalf("fetchMoonrakerSnapshot failed: %v", err)
			}
			if gotState != tc.wantState {
				t.Fatalf("state = %q, want %q", gotState, tc.wantState)
			}
			if gotJob != tc.wantJob {
				t.Fatalf("job state = %q, want %q", gotJob, tc.wantJob)
			}
		})
	}
}

func TestFetchMoonrakerSnapshotPrefersSubscribe(t *testing.T) {
	a := newTestAgent(t)

	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()

		switch r.URL.Path {
		case "/printer/objects/subscribe":
			if r.Method != http.MethodPost {
				t.Fatalf("subscribe method = %s, want POST", r.Method)
			}
			var reqBody struct {
				Objects map[string]any `json:"objects"`
			}
			if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
				t.Fatalf("decode subscribe body failed: %v", err)
			}
			if _, ok := reqBody.Objects["print_stats"]; !ok {
				t.Fatalf("subscribe payload missing print_stats object")
			}
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"paused"}}}}`))
		case "/printer/objects/query":
			t.Fatalf("query endpoint should not be called when subscribe succeeds")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	state, job, err := a.fetchMoonrakerSnapshot(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerSnapshot failed: %v", err)
	}
	if state != "paused" || job != "printing" {
		t.Fatalf("snapshot mapping = (%s,%s), want (paused,printing)", state, job)
	}

	mu.Lock()
	defer mu.Unlock()
	if hits["/printer/objects/subscribe"] != 1 {
		t.Fatalf("subscribe calls = %d, want 1", hits["/printer/objects/subscribe"])
	}
	if hits["/printer/objects/query"] != 0 {
		t.Fatalf("query calls = %d, want 0", hits["/printer/objects/query"])
	}
}

func TestFetchMoonrakerSnapshotFallsBackToQuery(t *testing.T) {
	a := newTestAgent(t)

	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()

		switch r.URL.Path {
		case "/printer/objects/subscribe":
			http.Error(w, "unsupported", http.StatusNotFound)
		case "/printer/objects/query":
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"printing"}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	state, job, err := a.fetchMoonrakerSnapshot(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerSnapshot failed: %v", err)
	}
	if state != "printing" || job != "printing" {
		t.Fatalf("snapshot mapping = (%s,%s), want (printing,printing)", state, job)
	}

	mu.Lock()
	defer mu.Unlock()
	if hits["/printer/objects/subscribe"] != 1 {
		t.Fatalf("subscribe calls = %d, want 1", hits["/printer/objects/subscribe"])
	}
	if hits["/printer/objects/query"] != 1 {
		t.Fatalf("query calls = %d, want 1", hits["/printer/objects/query"])
	}
}

func TestFetchMoonrakerTelemetryUsesFileMetadataEstimate(t *testing.T) {
	a := newTestAgent(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/query":
			_, _ = w.Write([]byte(`{
				"result": {
					"status": {
						"print_stats": {
							"state": "printing",
							"filename": "benchy.gcode",
							"print_duration": 60,
							"total_duration": 0
						},
						"display_status": {
							"progress": 0
						}
					}
				}
			}`))
		case "/server/files/metadata":
			if got := r.URL.Query().Get("filename"); got != "benchy.gcode" {
				t.Fatalf("filename query = %q, want benchy.gcode", got)
			}
			_, _ = w.Write([]byte(`{
				"result": {
					"estimated_time": 5400
				}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	progressPct, remainingSeconds, telemetrySource, manualIntervention, err := a.fetchMoonrakerTelemetry(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerTelemetry failed: %v", err)
	}
	if telemetrySource != "moonraker_metadata" {
		t.Fatalf("telemetry source = %q, want moonraker_metadata", telemetrySource)
	}
	if manualIntervention != "" {
		t.Fatalf("manual intervention = %q, want empty", manualIntervention)
	}
	if remainingSeconds == nil {
		t.Fatalf("remainingSeconds = nil, want value")
	}
	if got, want := *remainingSeconds, 5340.0; got < want-0.001 || got > want+0.001 {
		t.Fatalf("remainingSeconds = %v, want %v", got, want)
	}
	if progressPct == nil {
		t.Fatalf("progressPct = nil, want value")
	}
	if got, want := *progressPct, (60.0/5400.0)*100.0; got < want-0.001 || got > want+0.001 {
		t.Fatalf("progressPct = %v, want %v", got, want)
	}
}

func TestFetchMoonrakerTelemetryFallsBackWithoutMetadata(t *testing.T) {
	a := newTestAgent(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/query":
			_, _ = w.Write([]byte(`{
				"result": {
					"status": {
						"print_stats": {
							"state": "printing",
							"filename": "benchy.gcode",
							"print_duration": 120,
							"total_duration": 0
						},
						"display_status": {
							"progress": 0.1
						}
					}
				}
			}`))
		case "/server/files/metadata":
			http.Error(w, "not found", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	progressPct, remainingSeconds, telemetrySource, manualIntervention, err := a.fetchMoonrakerTelemetry(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerTelemetry failed: %v", err)
	}
	if telemetrySource != "moonraker" {
		t.Fatalf("telemetry source = %q, want moonraker", telemetrySource)
	}
	if manualIntervention != "" {
		t.Fatalf("manual intervention = %q, want empty", manualIntervention)
	}
	if progressPct == nil || *progressPct != 10 {
		t.Fatalf("progressPct = %v, want 10", progressPct)
	}
	if remainingSeconds == nil {
		t.Fatalf("remainingSeconds = nil, want value")
	}
	if got, want := *remainingSeconds, 1080.0; got < want-0.001 || got > want+0.001 {
		t.Fatalf("remainingSeconds = %v, want %v", got, want)
	}
}

func TestFetchMoonrakerProductInfo(t *testing.T) {
	a := newTestAgent(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/machine/system_info" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
			"result": {
				"system_info": {
					"product_info": {
						"machine_type": "Snapmaker U1",
						"device_name": "U1"
					}
				}
			}
		}`))
	}))
	defer srv.Close()

	name, modelHint, err := a.fetchMoonrakerProductInfo(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerProductInfo failed: %v", err)
	}
	if name != "U1" {
		t.Fatalf("detected name = %q, want U1", name)
	}
	if modelHint != "Snapmaker U1" {
		t.Fatalf("detected model hint = %q, want Snapmaker U1", modelHint)
	}
}

func TestFetchBindingSnapshotDetailedIncludesMoonrakerMetadata(t *testing.T) {
	a := newTestAgent(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"idle"}}}}`))
		case "/server/history/totals":
			_, _ = w.Write([]byte(`{"result":{"job_totals":{"total_print_time":7200}}}`))
		case "/machine/system_info":
			_, _ = w.Write([]byte(`{
				"result": {
					"system_info": {
						"product_info": {
							"machine_type": "Bambu Lab X1 Carbon",
							"device_name": "X1C-Farm-1"
						}
					}
				}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	snapshot, err := a.fetchBindingSnapshotDetailed(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "klipper",
		EndpointURL:   srv.URL,
	})
	if err != nil {
		t.Fatalf("fetchBindingSnapshotDetailed failed: %v", err)
	}
	if snapshot.DetectedName != "X1C-Farm-1" {
		t.Fatalf("detected name = %q, want X1C-Farm-1", snapshot.DetectedName)
	}
	if snapshot.DetectedModelHint != "Bambu Lab X1 Carbon" {
		t.Fatalf("detected model hint = %q, want Bambu Lab X1 Carbon", snapshot.DetectedModelHint)
	}
	if snapshot.TotalPrintSeconds == nil || *snapshot.TotalPrintSeconds != 7200 {
		t.Fatalf("total print seconds = %v, want 7200", snapshot.TotalPrintSeconds)
	}
}

func TestFetchBindingSnapshotDetailedMetadataFailureDoesNotFailSnapshot(t *testing.T) {
	a := newTestAgent(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"idle"}}}}`))
		case "/server/history/totals":
			_, _ = w.Write([]byte(`{"result":{"job_totals":{"total_print_time":3600}}}`))
		case "/machine/system_info":
			http.Error(w, "not supported", http.StatusNotFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	snapshot, err := a.fetchBindingSnapshotDetailed(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "klipper",
		EndpointURL:   srv.URL,
	})
	if err != nil {
		t.Fatalf("fetchBindingSnapshotDetailed should not fail when metadata endpoint fails: %v", err)
	}
	if snapshot.DetectedName != "" {
		t.Fatalf("detected name = %q, want empty", snapshot.DetectedName)
	}
	if snapshot.DetectedModelHint != "" {
		t.Fatalf("detected model hint = %q, want empty", snapshot.DetectedModelHint)
	}
}

func TestExecuteNextActionRetriesOnConnectivityError(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.ActionMaxAttempts = 3
	a.cfg.ActionRetryBaseInterval = 10 * time.Millisecond
	a.bindings[1] = edgeBinding{
		PrinterID:   1,
		EndpointURL: "http://127.0.0.1:1", // Expected connection refusal.
	}
	a.actionQueue[1] = []action{
		{
			PrinterID:  1,
			Kind:       "stop",
			EnqueuedAt: time.Now().UTC(),
			Target: desiredStateItem{
				PrinterID:           1,
				IntentVersion:       4,
				DesiredPrinterState: "idle",
			},
		},
	}

	if err := a.executeNextAction(context.Background()); err != nil {
		t.Fatalf("executeNextAction returned error: %v", err)
	}

	retries := a.actionQueue[1]
	if len(retries) != 1 {
		t.Fatalf("expected one retried action, got %d", len(retries))
	}
	if retries[0].Attempts != 1 {
		t.Fatalf("retry attempt = %d, want 1", retries[0].Attempts)
	}
	if retries[0].NextAttempt.Before(time.Now().UTC()) {
		t.Fatalf("next attempt should be in the future")
	}
	if len(a.deadLetters[1]) != 0 {
		t.Fatalf("expected no dead-lettered actions, got %d", len(a.deadLetters[1]))
	}
}

func TestExecuteNextActionRecoversUncertainPrintTimeoutViaSnapshot(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.MoonrakerRequestTimeout = 20 * time.Millisecond
	a.cfg.ArtifactDownloadTimeout = 1 * time.Second

	artifact := []byte("G1 X5 Y5\n")
	sum := sha256.Sum256(artifact)
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/files/upload":
			w.WriteHeader(http.StatusOK)
		case "/printer/print/start":
			time.Sleep(100 * time.Millisecond) // force timeout on start call
			w.WriteHeader(http.StatusOK)
		case "/printer/objects/subscribe":
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"printing"}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	a.bindings[1] = edgeBinding{
		PrinterID:   1,
		EndpointURL: moonrakerSrv.URL,
	}
	a.actionQueue[1] = []action{
		{
			PrinterID:  1,
			Kind:       "print",
			EnqueuedAt: time.Now().UTC(),
			Target: desiredStateItem{
				PrinterID:           1,
				IntentVersion:       9,
				DesiredPrinterState: "printing",
				DesiredJobState:     "printing",
				JobID:               "job-1",
				PlateID:             3,
				ArtifactURL:         artifactSrv.URL,
				ChecksumSHA256:      hex.EncodeToString(sum[:]),
			},
		},
	}

	if err := a.executeNextAction(context.Background()); err != nil {
		t.Fatalf("executeNextAction returned error: %v", err)
	}

	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected no retry queue entries after uncertain recovery")
	}
	if len(a.deadLetters[1]) != 0 {
		t.Fatalf("expected no dead-lettered actions after uncertain recovery")
	}
	current := a.currentState[1]
	if current.CurrentPrinterState != "printing" {
		t.Fatalf("current_printer_state = %q, want printing", current.CurrentPrinterState)
	}
	if current.IntentVersionApplied != 9 {
		t.Fatalf("intent_version_applied = %d, want 9", current.IntentVersionApplied)
	}
}

func TestExecuteNextActionDeadLettersOnArtifactFetchError(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.ActionMaxAttempts = 3

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer artifactSrv.Close()

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("moonraker should not be called when artifact download fails")
	}))
	defer moonrakerSrv.Close()

	a.bindings[1] = edgeBinding{
		PrinterID:   1,
		EndpointURL: moonrakerSrv.URL,
	}
	a.actionQueue[1] = []action{
		{
			PrinterID:  1,
			Kind:       "print",
			EnqueuedAt: time.Now().UTC(),
			Target: desiredStateItem{
				PrinterID:           1,
				IntentVersion:       2,
				DesiredPrinterState: "printing",
				ArtifactURL:         artifactSrv.URL,
				ChecksumSHA256:      "abc123",
			},
		},
	}

	if err := a.executeNextAction(context.Background()); err != nil {
		t.Fatalf("executeNextAction returned error: %v", err)
	}

	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected empty retry queue, got %d entries", len(a.actionQueue[1]))
	}
	if len(a.deadLetters[1]) != 1 {
		t.Fatalf("expected one dead-lettered action, got %d", len(a.deadLetters[1]))
	}
	current := a.currentState[1]
	if current.CurrentPrinterState != "error" {
		t.Fatalf("current_printer_state = %q, want error", current.CurrentPrinterState)
	}
	if current.LastErrorCode != "artifact_fetch_error" {
		t.Fatalf("last_error_code = %q, want artifact_fetch_error", current.LastErrorCode)
	}
}

func TestFunctionalSetupClaimViaHTTPEndpoint(t *testing.T) {
	a := newTestAgent(t)

	var (
		mu        sync.Mutex
		claimHits int
	)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer edge_key" {
			t.Fatalf("unexpected auth header: %q", got)
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/claim"):
			mu.Lock()
			claimHits++
			mu.Unlock()
			writeJSON(w, http.StatusOK, claimResponse{
				AgentID:                 "edge_1",
				OrgID:                   42,
				SchemaVersion:           agentSchemaVersion,
				SupportedSchemaVersions: []int{agentSchemaVersion},
			})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/bindings"):
			writeJSON(w, http.StatusOK, bindingsResponse{AgentID: "edge_1", Bindings: []edgeBinding{}})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/desired-state"):
			w.Header().Set("ETag", "etag-empty")
			writeJSON(w, http.StatusOK, desiredStateResponse{SchemaVersion: agentSchemaVersion, States: []desiredStateItem{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	payload := fmt.Sprintf(`{"control_plane_url":"%s","saas_api_key":"edge_key"}`, saasSrv.URL)
	req := httptest.NewRequest(http.MethodPost, "/setup/claim", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	a.handleSetupClaim(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d body=%s", resp.StatusCode, string(body))
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if body["status"] != "claimed" {
		t.Fatalf("status = %v, want claimed", body["status"])
	}
	if body["agent_id"] != "edge_1" {
		t.Fatalf("agent_id = %v, want edge_1", body["agent_id"])
	}

	mu.Lock()
	defer mu.Unlock()
	if claimHits != 1 {
		t.Fatalf("claim endpoint hits = %d, want 1", claimHits)
	}
	if !a.isClaimed() {
		t.Fatalf("expected agent to be claimed")
	}
	loaded := newTestAgent(t)
	loaded.cfg.BootstrapConfigPath = a.cfg.BootstrapConfigPath
	if err := loaded.loadBootstrapConfig(); err != nil {
		t.Fatalf("loadBootstrapConfig failed: %v", err)
	}
	if loaded.bootstrap.AgentID != "edge_1" {
		t.Fatalf("persisted agent_id = %q, want edge_1", loaded.bootstrap.AgentID)
	}
}

func TestFunctionalDesiredStateToActionAndStatePush(t *testing.T) {
	a := newTestAgent(t)
	artifact := []byte("G1 X1 Y1\n")
	sum := sha256.Sum256(artifact)

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	var moonrakerMu sync.Mutex
	moonrakerHits := map[string]int{}
	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		moonrakerMu.Lock()
		moonrakerHits[r.URL.Path]++
		moonrakerMu.Unlock()
		switch r.URL.Path {
		case "/server/files/upload":
			if err := r.ParseMultipartForm(2 << 20); err != nil {
				t.Fatalf("parse multipart form failed: %v", err)
			}
			file, _, err := r.FormFile("file")
			if err != nil {
				t.Fatalf("expected uploaded file form data: %v", err)
			}
			_, _ = io.Copy(io.Discard, file)
			_ = file.Close()
			w.WriteHeader(http.StatusOK)
		case "/printer/print/start":
			w.WriteHeader(http.StatusOK)
		case "/printer/objects/query":
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"printing"}}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	var (
		saasMu         sync.Mutex
		pushedStates   []currentStateItem
		statePushCount int
	)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer edge_key" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/bindings"):
			resp := bindingsResponse{
				AgentID: "edge_1",
				Bindings: []edgeBinding{
					{
						PrinterID:     1,
						AdapterFamily: "moonraker",
						EndpointURL:   moonrakerSrv.URL,
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case strings.HasSuffix(r.URL.Path, "/desired-state"):
			resp := desiredStateResponse{
				SchemaVersion: 1,
				States: []desiredStateItem{
					{
						PrinterID:           1,
						IntentVersion:       11,
						DesiredPrinterState: "printing",
						DesiredJobState:     "printing",
						JobID:               "job-1",
						PlateID:             3,
						ArtifactURL:         artifactSrv.URL,
						ChecksumSHA256:      hex.EncodeToString(sum[:]),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", "etag-11")
			_ = json.NewEncoder(w).Encode(resp)
		case strings.HasSuffix(r.URL.Path, "/state"):
			var req pushStateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode state push failed: %v", err)
			}
			if r.Header.Get("Idempotency-Key") == "" {
				t.Fatalf("expected Idempotency-Key header")
			}
			saasMu.Lock()
			pushedStates = append([]currentStateItem(nil), req.States...)
			statePushCount++
			saasMu.Unlock()
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"accepted":1,"deduplicated":false}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	ctx := context.Background()
	if err := a.pollBindingsOnce(ctx); err != nil {
		t.Fatalf("pollBindingsOnce failed: %v", err)
	}
	if err := a.pollDesiredStateOnce(ctx); err != nil {
		t.Fatalf("pollDesiredStateOnce failed: %v", err)
	}
	a.reconcileOnce()
	if err := a.executeNextAction(ctx); err != nil {
		t.Fatalf("executeNextAction failed: %v", err)
	}
	if err := a.pushStateOnce(ctx); err != nil {
		t.Fatalf("pushStateOnce failed: %v", err)
	}

	moonrakerMu.Lock()
	for _, path := range []string{"/server/files/upload", "/printer/print/start", "/printer/objects/query"} {
		if moonrakerHits[path] == 0 {
			t.Fatalf("expected moonraker path to be called: %s (hits: %+v)", path, moonrakerHits)
		}
	}
	moonrakerMu.Unlock()

	saasMu.Lock()
	defer saasMu.Unlock()
	if statePushCount == 0 {
		t.Fatalf("expected at least one state push")
	}
	if len(pushedStates) == 0 {
		t.Fatalf("expected pushed states payload")
	}
	if pushedStates[0].CurrentPrinterState != "printing" {
		t.Fatalf("pushed current_printer_state = %q, want printing", pushedStates[0].CurrentPrinterState)
	}
	if pushedStates[0].IntentVersionApplied != 11 {
		t.Fatalf("pushed intent_version_applied = %d, want 11", pushedStates[0].IntentVersionApplied)
	}
}

func TestPushStateOncePostsEmptyHeartbeatWhenNoPrinters(t *testing.T) {
	a := newTestAgent(t)

	var (
		mu         sync.Mutex
		callCount  int
		pushedBody pushStateRequest
	)

	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/state") {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("expected Idempotency-Key header")
		}
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&pushedBody); err != nil {
			t.Fatalf("decode state push failed: %v", err)
		}
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":0,"deduplicated":false}`))
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	ctx := context.Background()
	if err := a.pushStateOnce(ctx); err != nil {
		t.Fatalf("pushStateOnce failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Fatalf("state push calls = %d, want 1", callCount)
	}
	if len(pushedBody.States) != 0 {
		t.Fatalf("expected empty states heartbeat payload, got %d items", len(pushedBody.States))
	}
}

func TestNotifyShutdownPostsOfflineSignal(t *testing.T) {
	a := newTestAgent(t)

	var (
		mu        sync.Mutex
		callCount int
	)

	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/agents/edge_1/shutdown" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer edge_key" {
			t.Fatalf("unexpected auth header: %q", got)
		}
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"agent_id":"edge_1","status":"offline"}`))
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	if err := a.notifyShutdown(context.Background()); err != nil {
		t.Fatalf("notifyShutdown failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Fatalf("shutdown notify calls = %d, want 1", callCount)
	}
}

func TestNotifyShutdownReturnsErrorOnUnexpectedStatus(t *testing.T) {
	a := newTestAgent(t)
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/agents/edge_1/shutdown" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	err := a.notifyShutdown(context.Background())
	if err == nil {
		t.Fatalf("expected notifyShutdown to fail on non-2xx response")
	}
	if !strings.Contains(err.Error(), "shutdown notify returned 502") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLookupMACFromARPCommandLogsFailureOnce(t *testing.T) {
	origRunARPCommand := runARPCommand
	origLogARPCommandWarning := logARPCommandWarning
	defer func() {
		runARPCommand = origRunARPCommand
		logARPCommandWarning = origLogARPCommandWarning
		arpCommandWarningOnce = sync.Once{}
	}()

	var warningCount int
	runARPCommand = func(parts []string) ([]byte, error) {
		return nil, exec.ErrNotFound
	}
	logARPCommandWarning = func(_ string, _ ...any) {
		warningCount++
	}
	arpCommandWarningOnce = sync.Once{}

	if got := lookupMACFromARPCommand("192.168.1.50"); got != "" {
		t.Fatalf("lookupMACFromARPCommand returned %q, want empty", got)
	}
	if got := lookupMACFromARPCommand("192.168.1.60"); got != "" {
		t.Fatalf("lookupMACFromARPCommand returned %q, want empty on subsequent call", got)
	}
	if warningCount != 1 {
		t.Fatalf("warning count = %d, want 1", warningCount)
	}
}
