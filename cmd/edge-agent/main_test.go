package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
			BootstrapConfigPath:        filepath.Join(baseDir, "bootstrap", "config.json"),
			AuditLogPath:               filepath.Join(baseDir, "audit", "audit.log"),
			ArtifactStageDir:           filepath.Join(baseDir, "artifacts"),
			EnableKlipper:              true,
			EnableBambu:                true,
			BambuConnectURI:            "http://127.0.0.1:18091",
			ActionNonRetryableCooldown: 3 * time.Minute,
			MoonrakerRequestTimeout:    2 * time.Second,
			BambuLANRuntimeTimeout:     2 * time.Second,
			ArtifactUploadTimeout:      2 * time.Second,
			ArtifactDownloadTimeout:    2 * time.Second,
			CircuitBreakerCooldown:     2 * time.Second,
			LocalUIScanInterval:        15 * time.Second,
		},
		client:                 &http.Client{Timeout: 2 * time.Second},
		desiredState:           make(map[int]desiredStateItem),
		bindings:               make(map[int]edgeBinding),
		currentState:           make(map[int]currentStateItem),
		actionQueue:            make(map[int][]action),
		inflightActions:        make(map[int]action),
		deadLetters:            make(map[int][]action),
		queuedSince:            make(map[int]time.Time),
		recentEnqueue:          make(map[string]time.Time),
		suppressedUntil:        make(map[string]time.Time),
		breakerUntil:           make(map[int]time.Time),
		discoverySeeds:         make(map[string]time.Time),
		bambuLANRecords:        make(map[string]bambuLANDiscoveryRecord),
		bambuLANRuntimeRecords: make(map[string]*bambuLANRuntimeRecord),
		bambuLANFailures:       make(map[string]int),
		bambuLANRecoveryUntil:  make(map[int]time.Time),
		bambuLANProbeHosts:     make(map[string]time.Time),
		localObservations:      newLocalObservationStore(),
	}
}

func TestCameraStreamHTTPClientClonesBaseTransport(t *testing.T) {
	a := newTestAgent(t)
	baseTransport := &http.Transport{}
	a.client = &http.Client{Transport: baseTransport}

	cameraClient := a.cameraStreamHTTPClient()
	if cameraClient == nil {
		t.Fatalf("expected camera stream client")
	}
	clonedTransport, ok := cameraClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", cameraClient.Transport)
	}
	if clonedTransport == baseTransport {
		t.Fatalf("expected camera stream client to use a cloned transport")
	}
}

func readAuditLog(t *testing.T, a *agent) string {
	t.Helper()
	data, err := os.ReadFile(a.cfg.AuditLogPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read audit log failed: %v", err)
	}
	return string(data)
}

func newTestBambuLANDiscoveryResult(devices ...bambuLANDiscoveryDevice) bambuLANDiscoveryResult {
	return bambuLANDiscoveryResult{
		Devices:         append([]bambuLANDiscoveryDevice(nil), devices...),
		ListenPort:      bambuLANDiscoveryListenPort,
		ProbePorts:      append([]int(nil), bambuLANDiscoveryProbePorts...),
		PacketsReceived: len(devices),
		PacketsParsed:   len(devices),
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

type fakeBambuCloudActionProvider struct {
	loginFn         func(ctx context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error)
	refreshFn       func(ctx context.Context, req bambuauth.RefreshRequest) (bambuauth.Session, error)
	listDevicesFn   func(ctx context.Context, accessToken string) ([]bambucloud.CloudDevice, error)
	getUploadFn     func(ctx context.Context, accessToken, filename string, sizeBytes int64) (bambucloud.CloudUploadURLs, error)
	uploadSignedFn  func(ctx context.Context, uploadURLs bambucloud.CloudUploadURLs, fileBytes []byte) error
	confirmUploadFn func(ctx context.Context, accessToken string, uploadURLs bambucloud.CloudUploadURLs) error
	startPrintFn    func(ctx context.Context, accessToken string, req bambucloud.CloudPrintStartRequest) error
}

func (f *fakeBambuCloudActionProvider) Login(ctx context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error) {
	if f.loginFn == nil {
		return bambuauth.Session{}, errors.New("login not implemented")
	}
	return f.loginFn(ctx, req)
}

func (f *fakeBambuCloudActionProvider) Refresh(ctx context.Context, req bambuauth.RefreshRequest) (bambuauth.Session, error) {
	if f.refreshFn == nil {
		return bambuauth.Session{}, errors.New("refresh not implemented")
	}
	return f.refreshFn(ctx, req)
}

func (f *fakeBambuCloudActionProvider) ListBoundDevices(ctx context.Context, accessToken string) ([]bambucloud.CloudDevice, error) {
	if f.listDevicesFn == nil {
		return nil, errors.New("list devices not implemented")
	}
	return f.listDevicesFn(ctx, accessToken)
}

func (f *fakeBambuCloudActionProvider) GetUploadURLs(ctx context.Context, accessToken, filename string, sizeBytes int64) (bambucloud.CloudUploadURLs, error) {
	if f.getUploadFn == nil {
		return bambucloud.CloudUploadURLs{}, errors.New("get upload urls not implemented")
	}
	return f.getUploadFn(ctx, accessToken, filename, sizeBytes)
}

func (f *fakeBambuCloudActionProvider) UploadToSignedURLs(ctx context.Context, uploadURLs bambucloud.CloudUploadURLs, fileBytes []byte) error {
	if f.uploadSignedFn == nil {
		return errors.New("upload signed urls not implemented")
	}
	return f.uploadSignedFn(ctx, uploadURLs, fileBytes)
}

func (f *fakeBambuCloudActionProvider) ConfirmUpload(ctx context.Context, accessToken string, uploadURLs bambucloud.CloudUploadURLs) error {
	if f.confirmUploadFn == nil {
		return nil
	}
	return f.confirmUploadFn(ctx, accessToken, uploadURLs)
}

func (f *fakeBambuCloudActionProvider) StartPrintJob(ctx context.Context, accessToken string, req bambucloud.CloudPrintStartRequest) error {
	if f.startPrintFn == nil {
		return errors.New("start print not implemented")
	}
	return f.startPrintFn(ctx, accessToken, req)
}

type fakeBambuMQTTPublisher struct {
	mu       sync.Mutex
	requests []bambuMQTTCommandRequest
	publish  func(ctx context.Context, req bambuMQTTCommandRequest) error
}

func (f *fakeBambuMQTTPublisher) PublishPrintCommand(ctx context.Context, req bambuMQTTCommandRequest) error {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	if f.publish == nil {
		return nil
	}
	return f.publish(ctx, req)
}

type fakeBambuLANArtifactClient struct {
	loginErr             error
	setBinaryModeErr     error
	deleteErr            error
	sizeErr              error
	retrieveErr          error
	quitErr              error
	closeErr             error
	retrieveData         []byte
	sizeValue            int64
	storeErrs            []error
	storedRemoteNames    []string
	deletedRemoteNames   []string
	retrievedRemoteNames []string
}

func (f *fakeBambuLANArtifactClient) login(_ string, _ string) error {
	return f.loginErr
}

func (f *fakeBambuLANArtifactClient) setBinaryMode() error {
	return f.setBinaryModeErr
}

func (f *fakeBambuLANArtifactClient) store(remoteName string, _ []byte) error {
	f.storedRemoteNames = append(f.storedRemoteNames, remoteName)
	if len(f.storeErrs) == 0 {
		return nil
	}
	err := f.storeErrs[0]
	f.storeErrs = f.storeErrs[1:]
	return err
}

func (f *fakeBambuLANArtifactClient) delete(remoteName string) error {
	f.deletedRemoteNames = append(f.deletedRemoteNames, remoteName)
	return f.deleteErr
}

func (f *fakeBambuLANArtifactClient) size(_ string) (int64, error) {
	if f.sizeErr != nil {
		return 0, f.sizeErr
	}
	return f.sizeValue, nil
}

func (f *fakeBambuLANArtifactClient) retrieve(remoteName string, writer io.Writer) (int64, error) {
	f.retrievedRemoteNames = append(f.retrievedRemoteNames, remoteName)
	if f.retrieveErr != nil {
		return 0, f.retrieveErr
	}
	written, err := writer.Write(f.retrieveData)
	return int64(written), err
}

func (f *fakeBambuLANArtifactClient) quit() error {
	return f.quitErr
}

func (f *fakeBambuLANArtifactClient) close() error {
	return f.closeErr
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

func TestSummarizeBambuCloudStartDispatchErrorExtractsSanitizedFields(t *testing.T) {
	err := errors.New("bambu_start_rejected: task_variant_2: bambu print start POST https://api.bambulab.com/v1/user-service/my/task failed: status=403 body=")
	details := summarizeBambuCloudStartDispatchError(err)

	if details["dispatch_variant"] != "task_variant_2" {
		t.Fatalf("dispatch_variant = %v, want task_variant_2", details["dispatch_variant"])
	}
	if details["http_method"] != "POST" {
		t.Fatalf("http_method = %v, want POST", details["http_method"])
	}
	if details["endpoint"] != "https://api.bambulab.com/v1/user-service/my/task" {
		t.Fatalf("endpoint = %v, want https://api.bambulab.com/v1/user-service/my/task", details["endpoint"])
	}
	if details["http_status"] != 403 {
		t.Fatalf("http_status = %v, want 403", details["http_status"])
	}
	if details["response_body_present"] != false {
		t.Fatalf("response_body_present = %v, want false", details["response_body_present"])
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
		{name: "wait to pause while queued", current: "queued", desired: "paused", want: "noop"},
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

func TestBambuMQTTUsernameFromUploadURL(t *testing.T) {
	username := bambuMQTTUsernameFromUploadURL("https://s3.us-west-2.amazonaws.com/or-cloud-upload-prod/users/3911589060/filename/20260217183115.027/plate.gcode")
	if username != "3911589060" {
		t.Fatalf("username = %q, want 3911589060", username)
	}
}

func TestResolveBambuMQTTUsernameUsesTokenClaimOnly(t *testing.T) {
	a := newTestAgent(t)
	a.setBambuAuthState(bambuAuthState{
		Ready:       true,
		AccessToken: "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"claim-user"}`)) + ".sig",
	})

	username, source, err := a.resolveBambuMQTTUsername(context.Background(), "header."+base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"claim-user"}`))+".sig")
	if err != nil {
		t.Fatalf("resolveBambuMQTTUsername failed: %v", err)
	}
	if username != "claim-user" {
		t.Fatalf("username = %q, want claim-user", username)
	}
	if source != "token_claim" {
		t.Fatalf("source = %q, want token_claim", source)
	}
}

func TestResolveBambuMQTTUsernameFallsBackToAuthState(t *testing.T) {
	a := newTestAgent(t)
	a.setBambuAuthState(bambuAuthState{
		Ready:        true,
		AccessToken:  "opaque-access-token",
		MQTTUsername: "stale-user",
	})

	username, source, err := a.resolveBambuMQTTUsername(context.Background(), "opaque-access-token")
	if err != nil {
		t.Fatalf("resolveBambuMQTTUsername failed: %v", err)
	}
	if username != "stale-user" {
		t.Fatalf("username = %q, want stale-user", username)
	}
	if source != "auth_state" {
		t.Fatalf("source = %q, want auth_state", source)
	}
}

func TestResolveBambuMQTTUsernamePrefersAuthStateOverTokenClaim(t *testing.T) {
	a := newTestAgent(t)
	a.setBambuAuthState(bambuAuthState{
		Ready:        true,
		AccessToken:  "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"claim-user"}`)) + ".sig",
		MQTTUsername: "preferred-state-user",
	})

	username, source, err := a.resolveBambuMQTTUsername(context.Background(), "header."+base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"claim-user"}`))+".sig")
	if err != nil {
		t.Fatalf("resolveBambuMQTTUsername failed: %v", err)
	}
	if username != "preferred-state-user" {
		t.Fatalf("username = %q, want preferred-state-user", username)
	}
	if source != "auth_state" {
		t.Fatalf("source = %q, want auth_state", source)
	}
}

func TestResolveBambuMQTTUsernameRejectsInvalidTokenWithoutFallback(t *testing.T) {
	a := newTestAgent(t)
	a.setBambuAuthState(bambuAuthState{
		Ready:       true,
		AccessToken: "opaque-access-token",
	})

	_, _, err := a.resolveBambuMQTTUsername(context.Background(), "opaque-access-token")
	if err == nil {
		t.Fatalf("expected invalid token error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unable to resolve bambu mqtt username from access token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBambuActionVerificationTimeoutHasCloudFloor(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.MoonrakerRequestTimeout = 3 * time.Second
	if got := a.bambuActionVerificationTimeout(); got != 20*time.Second {
		t.Fatalf("bambuActionVerificationTimeout() = %s, want 20s", got)
	}

	a.cfg.MoonrakerRequestTimeout = 35 * time.Second
	if got := a.bambuActionVerificationTimeout(); got != 35*time.Second {
		t.Fatalf("bambuActionVerificationTimeout() = %s, want 35s", got)
	}
}

func TestBambuPrintStartVerificationTimeoutHasHigherFloor(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.MoonrakerRequestTimeout = 3 * time.Second
	if got := a.bambuPrintStartVerificationTimeout(); got != 90*time.Second {
		t.Fatalf("bambuPrintStartVerificationTimeout() = %s, want 90s", got)
	}

	a.cfg.MoonrakerRequestTimeout = 120 * time.Second
	if got := a.bambuPrintStartVerificationTimeout(); got != 120*time.Second {
		t.Fatalf("bambuPrintStartVerificationTimeout() = %s, want 120s", got)
	}
}

func TestHandleActionFailureSuppressesNonRetryableReenqueue(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.ActionNonRetryableCooldown = 2 * time.Minute
	desired := desiredStateItem{
		PrinterID:           1,
		IntentVersion:       7,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-1",
		PlateID:             3,
		ArtifactURL:         "http://example.invalid/plate.gcode",
	}
	a.bindings[1] = edgeBinding{PrinterID: 1, EndpointURL: "bambu://printer_1", AdapterFamily: "bambu"}
	a.desiredState[1] = desired
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		ReportedAt:          time.Now().UTC(),
	}

	failedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target:    desired,
	}
	a.handleActionFailure(failedAction, "validation_error", "validation failure", false)

	a.reconcileOnce()
	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected no immediate re-enqueue while action is suppressed")
	}

	key := actionThrottleKey(1, "print", desired)
	a.mu.Lock()
	a.suppressedUntil[key] = time.Now().UTC().Add(-1 * time.Second)
	a.mu.Unlock()

	a.reconcileOnce()
	if len(a.actionQueue[1]) != 1 {
		t.Fatalf("expected enqueue once suppression expires, got %d", len(a.actionQueue[1]))
	}
}

func TestHandleActionFailurePrunesQueuedDuplicateActionsForNonRetryableFailure(t *testing.T) {
	a := newTestAgent(t)
	desired := desiredStateItem{
		PrinterID:           1,
		IntentVersion:       7,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-1",
		PlateID:             3,
		ArtifactURL:         "http://example.invalid/plate.gcode",
	}
	a.actionQueue[1] = []action{
		{PrinterID: 1, Kind: "print", Target: desired},
		{PrinterID: 1, Kind: "pause", Target: desired},
		{PrinterID: 1, Kind: "print", Target: desired},
	}
	failedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target:    desired,
	}

	a.handleActionFailure(failedAction, "bambu_start_rejected", "cloud start unsupported", false)

	remaining := a.actionQueue[1]
	if len(remaining) != 1 {
		t.Fatalf("remaining queue length = %d, want 1 non-duplicate entry", len(remaining))
	}
	if remaining[0].Kind != "pause" {
		t.Fatalf("remaining queued action kind = %q, want pause", remaining[0].Kind)
	}
}

func TestHandleActionFailureAuthErrorInvalidatesBambuSession(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.setBambuAuthState(bambuAuthState{
		Ready:       true,
		AccessToken: "access-token",
		ExpiresAt:   time.Now().UTC().Add(1 * time.Hour),
		Username:    "operator@example.com",
	})

	desired := desiredStateItem{
		PrinterID:           1,
		IntentVersion:       21,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-1",
		PlateID:             3,
	}
	failedAction := action{PrinterID: 1, Kind: "print", Target: desired}
	a.handleActionFailure(failedAction, "auth_error", "bambu print start rejected access token", false)

	state := a.snapshotBambuAuthState()
	if state.Ready {
		t.Fatalf("expected bambu auth state to be invalidated")
	}
	if state.AccessToken != "" {
		t.Fatalf("expected access token cleared, got %q", state.AccessToken)
	}
	if state.LastError == "" {
		t.Fatalf("expected last error to be recorded")
	}
}

func TestHandleActionFailureMQTTAuthRejectDoesNotInvalidateBambuSession(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	expiresAt := time.Now().UTC().Add(1 * time.Hour)
	a.setBambuAuthState(bambuAuthState{
		Ready:       true,
		AccessToken: "access-token",
		ExpiresAt:   expiresAt,
		Username:    "operator@example.com",
	})

	desired := desiredStateItem{
		PrinterID:           1,
		IntentVersion:       22,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-1",
		PlateID:             3,
	}
	failedAction := action{PrinterID: 1, Kind: "print", Target: desired}
	a.handleActionFailure(failedAction, "auth_error", "bambu print start mqtt dispatch failed: bambu mqtt broker rejected connection return_code=5", false)

	state := a.snapshotBambuAuthState()
	if !state.Ready {
		t.Fatalf("expected bambu auth state to stay ready for mqtt auth reject")
	}
	if state.AccessToken != "access-token" {
		t.Fatalf("expected access token to remain unchanged, got %q", state.AccessToken)
	}
	if !state.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expected expires_at to remain unchanged")
	}
}

func TestReconcileSkipsEnqueueWhenEquivalentActionInflight(t *testing.T) {
	a := newTestAgent(t)
	desired := desiredStateItem{
		PrinterID:           1,
		IntentVersion:       3,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-1",
		PlateID:             2,
		ArtifactURL:         "http://example.invalid/plate.gcode",
		ChecksumSHA256:      "abc",
	}
	a.bindings[1] = edgeBinding{PrinterID: 1, EndpointURL: "http://moonraker:7125"}
	a.desiredState[1] = desired
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		ReportedAt:          time.Now().UTC(),
	}
	a.inflightActions[1] = action{
		PrinterID: 1,
		Kind:      "print",
		Target:    desired,
	}

	a.reconcileOnce()

	if len(a.actionQueue[1]) != 0 {
		t.Fatalf("expected no enqueue while equivalent action is in-flight, got %d", len(a.actionQueue[1]))
	}
}

func TestRefreshCurrentStateFromBindingsBambuLANMissMarksAuthError(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-1",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		CurrentJobState:     "completed",
		ReportedAt:          time.Now().UTC().Add(-1 * time.Minute),
	}

	a.refreshCurrentStateFromBindings(context.Background())

	current := a.currentState[1]
	if current.LastErrorCode != "auth_error" {
		t.Fatalf("last_error_code = %q, want auth_error", current.LastErrorCode)
	}
	if current.CurrentPrinterState != "idle" {
		t.Fatalf("current_printer_state = %q, want idle", current.CurrentPrinterState)
	}
	if !strings.Contains(strings.ToLower(current.LastErrorMessage), "bambu_lan_credentials_missing_local") {
		t.Fatalf("last_error_message = %q, want bambu_lan_credentials_missing_local", current.LastErrorMessage)
	}
}

func TestRefreshCurrentStateFromBindingsBambuIdleTransitionMarksCompletion(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-runtime",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "printing",
		CurrentJobState:     "printing",
		JobID:               "job-1",
		PlateID:             7,
		ReportedAt:          time.Now().UTC().Add(-1 * time.Minute),
	}

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState:     "idle",
			JobState:         "pending",
			TelemetrySource:  telemetrySourceBambuLANMQTT,
			RawPrinterStatus: "IDLE",
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	a.refreshCurrentStateFromBindings(context.Background())

	current := a.currentState[1]
	if current.CurrentPrinterState != "idle" {
		t.Fatalf("current_printer_state = %q, want idle", current.CurrentPrinterState)
	}
	if current.CurrentJobState != "completed" {
		t.Fatalf("current_job_state = %q, want completed", current.CurrentJobState)
	}
}

func TestFetchBambuLANRuntimeSnapshotByPrinterIDCoalescesConcurrentFetches(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuControlStatusPushInterval = time.Millisecond

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	var calls int
	var callsMu sync.Mutex
	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		time.Sleep(25 * time.Millisecond)
		return bindingSnapshot{
			PrinterState:     "idle",
			JobState:         "pending",
			TelemetrySource:  telemetrySourceBambuLANMQTT,
			RawPrinterStatus: "IDLE",
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snapshot, fetchErr := a.fetchBambuLANRuntimeSnapshotByPrinterID(context.Background(), "printer-lan-runtime")
			if fetchErr != nil {
				t.Errorf("fetchBambuLANRuntimeSnapshotByPrinterID failed: %v", fetchErr)
				return
			}
			if snapshot.PrinterState != "idle" {
				t.Errorf("snapshot.PrinterState = %q, want idle", snapshot.PrinterState)
			}
		}()
	}
	wg.Wait()

	callsMu.Lock()
	defer callsMu.Unlock()
	if calls != 1 {
		t.Fatalf("fetchBambuLANMQTTSnapshot calls = %d, want 1", calls)
	}
}

func TestRefreshCurrentStateFromBindingsBambuKeepsRecentRuntimeSnapshotReachableWithinGraceWindow(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuControlStatusPushInterval = time.Millisecond

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-runtime",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		CurrentJobState:     "pending",
		ReportedAt:          time.Now().UTC().Add(-1 * time.Minute),
	}
	a.recordBambuLANRuntimeSnapshot("printer-lan-runtime", "192.168.100.172", bindingSnapshot{
		PrinterState:     "idle",
		JobState:         "pending",
		TelemetrySource:  telemetrySourceBambuLANMQTT,
		RawPrinterStatus: "IDLE",
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		return bindingSnapshot{}, errors.New("bambu lan mqtt connection failed: dial tcp 192.168.100.172:8883: i/o timeout")
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	time.Sleep(2 * time.Millisecond)
	a.refreshCurrentStateFromBindings(context.Background())
	time.Sleep(2 * time.Millisecond)
	a.refreshCurrentStateFromBindings(context.Background())

	current := a.currentState[1]
	if current.LastErrorCode != "" {
		t.Fatalf("last_error_code = %q, want empty while recent runtime snapshot is still within grace", current.LastErrorCode)
	}
	if current.CurrentPrinterState != "idle" {
		t.Fatalf("current_printer_state = %q, want idle", current.CurrentPrinterState)
	}
}

func TestRefreshCurrentStateFromBindingsBambuReportsConnectivityErrorAfterGraceWindow(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuControlStatusPushInterval = time.Millisecond

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-runtime",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		CurrentJobState:     "pending",
		ReportedAt:          time.Now().UTC().Add(-1 * time.Minute),
	}
	a.recordBambuLANRuntimeSnapshot("printer-lan-runtime", "192.168.100.172", bindingSnapshot{
		PrinterState:     "idle",
		JobState:         "pending",
		TelemetrySource:  telemetrySourceBambuLANMQTT,
		RawPrinterStatus: "IDLE",
	})
	record := a.bambuLANRuntimeRecords["printer-lan-runtime"]
	record.LastSuccessAt = time.Now().UTC().Add(-1 * (bambuLANOfflineGraceWindow + time.Second))

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		return bindingSnapshot{}, errors.New("bambu lan mqtt connection failed: dial tcp 192.168.100.172:8883: i/o timeout")
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	time.Sleep(2 * time.Millisecond)
	a.refreshCurrentStateFromBindings(context.Background())

	current := a.currentState[1]
	if current.LastErrorCode != "connectivity_error" {
		t.Fatalf("last_error_code = %q, want connectivity_error after grace window expires", current.LastErrorCode)
	}
	if !strings.Contains(current.LastErrorMessage, "i/o timeout") {
		t.Fatalf("last_error_message = %q, want timeout", current.LastErrorMessage)
	}
}

func TestRefreshCurrentStateFromBindingsBambuInflightPrintSuppressesTransientConnectivityMisses(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-runtime",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		CurrentJobState:     "pending",
		ReportedAt:          time.Now().UTC().Add(-1 * time.Minute),
	}
	a.inflightActions[1] = action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			JobID:               "job-1",
			PlateID:             7,
			IntentVersion:       3,
		},
	}
	a.recordBambuLANRuntimeSnapshot("printer-lan-runtime", "192.168.100.172", bindingSnapshot{
		PrinterState:     "idle",
		JobState:         "pending",
		TelemetrySource:  telemetrySourceBambuLANMQTT,
		RawPrinterStatus: "IDLE",
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		return bindingSnapshot{}, errors.New("bambu lan mqtt read failed: read tcp 192.168.100.157:51394->192.168.100.172:8883: i/o timeout")
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	a.refreshCurrentStateFromBindings(context.Background())
	a.refreshCurrentStateFromBindings(context.Background())
	a.refreshCurrentStateFromBindings(context.Background())

	current := a.currentState[1]
	if current.LastErrorCode != "" {
		t.Fatalf("suppressed inflight failure last_error_code = %q, want empty", current.LastErrorCode)
	}
	if current.CurrentPrinterState != "idle" {
		t.Fatalf("suppressed inflight failure current_printer_state = %q, want idle", current.CurrentPrinterState)
	}
	if got := a.bambuLANFailures["printer-lan-runtime"]; got != 0 {
		t.Fatalf("failure counter = %d, want 0 while print start is inflight", got)
	}
}

func TestShouldSuppressBambuRuntimeConnectivityFailureForRuntimeCommandGraceWindow(t *testing.T) {
	a := newTestAgent(t)
	a.extendBambuRuntimeConnectivitySuppression(23, 5*time.Second)

	if !a.shouldSuppressBambuRuntimeConnectivityFailure(23, errors.New("read tcp: i/o timeout")) {
		t.Fatalf("expected runtime command suppression to be active")
	}
}

func TestShouldSuppressBambuRuntimeConnectivityFailureForQueuedRuntimeCommand(t *testing.T) {
	a := newTestAgent(t)
	a.actionQueue[23] = []action{
		{PrinterID: 23, Kind: "light_on"},
	}

	if !a.shouldSuppressBambuRuntimeConnectivityFailure(23, errors.New("read tcp: i/o timeout")) {
		t.Fatalf("expected queued runtime command suppression to be active")
	}
}

func TestFetchBambuLANRuntimeSnapshotByPrinterIDUsesConfiguredTimeout(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuLANRuntimeTimeout = 250 * time.Millisecond

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(ctx context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatalf("expected runtime snapshot context deadline")
		}
		remaining := time.Until(deadline)
		if remaining > 350*time.Millisecond || remaining < 100*time.Millisecond {
			t.Fatalf("remaining timeout = %v, want approximately 250ms", remaining)
		}
		return bindingSnapshot{
			PrinterState:     "idle",
			JobState:         "pending",
			TelemetrySource:  telemetrySourceBambuLANMQTT,
			RawPrinterStatus: "IDLE",
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	if _, err := a.fetchBambuLANRuntimeSnapshotByPrinterID(context.Background(), "printer-lan-runtime"); err != nil {
		t.Fatalf("fetchBambuLANRuntimeSnapshotByPrinterID failed: %v", err)
	}
}

func TestRefreshCurrentStateFromBindingsBambuRuntimeFailureCounterResetsAfterSuccess(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-runtime",
	}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		CurrentJobState:     "pending",
		ReportedAt:          time.Now().UTC().Add(-1 * time.Minute),
	}
	a.recordBambuLANRuntimeSnapshot("printer-lan-runtime", "192.168.100.172", bindingSnapshot{
		PrinterState:     "idle",
		JobState:         "pending",
		TelemetrySource:  telemetrySourceBambuLANMQTT,
		RawPrinterStatus: "IDLE",
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	callCount := 0
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		callCount++
		switch callCount {
		case 1, 3:
			return bindingSnapshot{}, errors.New("bambu lan mqtt connection failed: dial tcp 192.168.100.172:8883: i/o timeout")
		default:
			return bindingSnapshot{
				PrinterState:     "idle",
				JobState:         "pending",
				TelemetrySource:  telemetrySourceBambuLANMQTT,
				RawPrinterStatus: "IDLE",
			}, nil
		}
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	a.refreshCurrentStateFromBindings(context.Background())
	if got := a.currentState[1].LastErrorCode; got != "" {
		t.Fatalf("first failure last_error_code = %q, want empty", got)
	}

	a.refreshCurrentStateFromBindings(context.Background())
	if got := a.currentState[1].LastErrorCode; got != "" {
		t.Fatalf("success last_error_code = %q, want empty", got)
	}

	a.refreshCurrentStateFromBindings(context.Background())
	if got := a.currentState[1].LastErrorCode; got != "" {
		t.Fatalf("failure after reset last_error_code = %q, want empty", got)
	}
}

func TestRefreshCurrentStateFromBindingsHydratesBambuActiveIntentIdentity(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-runtime",
	}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       42,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-1",
		PlateID:             7,
	}

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState:     "printing",
			JobState:         "printing",
			TelemetrySource:  telemetrySourceBambuLANMQTT,
			RawPrinterStatus: "RUNNING",
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	a.refreshCurrentStateFromBindings(context.Background())

	current := a.currentState[1]
	if current.CurrentPrinterState != "printing" {
		t.Fatalf("current_printer_state = %q, want printing", current.CurrentPrinterState)
	}
	if current.JobID != "job-1" {
		t.Fatalf("job_id = %q, want job-1", current.JobID)
	}
	if current.PlateID != 7 {
		t.Fatalf("plate_id = %d, want 7", current.PlateID)
	}
	if current.IntentVersionApplied != 42 {
		t.Fatalf("intent_version_applied = %d, want 42", current.IntentVersionApplied)
	}
}

func TestRefreshCurrentStateFromBindingsHydratesMoonrakerActiveIntentIdentity(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = true
	a.bindings[1] = edgeBinding{
		PrinterID:     1,
		AdapterFamily: "moonraker",
		EndpointURL:   "http://moonraker.local:7125",
	}
	a.desiredState[1] = desiredStateItem{
		PrinterID:           1,
		IntentVersion:       43,
		DesiredPrinterState: "printing",
		DesiredJobState:     "printing",
		JobID:               "job-2",
		PlateID:             8,
	}

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"printing"}}}}`))
		case "/printer/objects/query":
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"printing","filename":"part.gcode","total_duration":1200,"print_duration":600},"display_status":{"progress":0.5}}}}`))
		case "/server/files/metadata":
			_, _ = w.Write([]byte(`{"result":{"estimated_time":1200}}`))
		case "/server/history/totals":
			_, _ = w.Write([]byte(`{"result":{"job_totals":{"total_print_time":600}}}`))
		case "/machine/system_info":
			_, _ = w.Write([]byte(`{"result":{"system_info":{"product_info":{"machine_type":"Voron","device_name":"Forge Moon"}}}}`))
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

	a.refreshCurrentStateFromBindings(context.Background())

	current := a.currentState[1]
	if current.CurrentPrinterState != "printing" {
		t.Fatalf("current_printer_state = %q, want printing", current.CurrentPrinterState)
	}
	if current.JobID != "job-2" {
		t.Fatalf("job_id = %q, want job-2", current.JobID)
	}
	if current.PlateID != 8 {
		t.Fatalf("plate_id = %d, want 8", current.PlateID)
	}
	if current.IntentVersionApplied != 43 {
		t.Fatalf("intent_version_applied = %d, want 43", current.IntentVersionApplied)
	}
	if current.ProgressPct == nil || *current.ProgressPct != 50 {
		t.Fatalf("progress_pct = %v, want 50", current.ProgressPct)
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
		{name: "bambu start unsupported sentinel", err: fmt.Errorf("wrapped: %w", bambucloud.ErrPrintStartUnsupported), wantCode: "bambu_start_rejected", wantRetry: false},
		{name: "bambu start rejected tagged", err: errors.New("bambu_start_rejected: cloud start unsupported"), wantCode: "bambu_start_rejected", wantRetry: false},
		{name: "bambu start metadata unresolved tagged", err: errors.New("bambu_start_metadata_unresolved: missing profileId"), wantCode: "bambu_start_metadata_unresolved", wantRetry: false},
		{name: "bambu auth invalid credentials sentinel", err: fmt.Errorf("wrapped: %w", bambuauth.ErrInvalidCredentials), wantCode: "auth_error", wantRetry: false},
		{name: "bambu auth rejected token", err: errors.New("bambu print start rejected access token"), wantCode: "auth_error", wantRetry: false},
		{name: "bambu mqtt auth reject", err: errors.New("bambu mqtt broker rejected connection return_code=5"), wantCode: "auth_error", wantRetry: false},
		{name: "bambu lan local credentials missing", err: errors.New("bambu_lan_credentials_missing_local: open lan_credentials.json: no such file or directory"), wantCode: "auth_error", wantRetry: false},
		{name: "bambu connect manual handoff required", err: errors.New("bambu_start_manual_handoff_required: Bambu Connect import dispatched but printer \"abc\" did not enter queued/printing state"), wantCode: "bambu_start_manual_handoff_required", wantRetry: false},
		{name: "bambu start verification timeout", err: errors.New("bambu_start_verification_timeout: connection error: bambu print start verification timeout after 20s"), wantCode: "bambu_start_verification_timeout", wantRetry: false},
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
		{name: "success event bambu unsupported", event: "bambu_cloud_start_unsupported", want: true},
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

func TestExecuteDiscoveryJobBambuLANCandidates(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}
	a.cfg.DiscoveryProbeTimeout = 2 * time.Second

	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, _ time.Duration, _ bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		return newTestBambuLANDiscoveryResult(
			bambuLANDiscoveryDevice{
				PrinterID:       "printer-1",
				Host:            "192.168.1.40",
				Name:            "Bambu One",
				Model:           "X1C",
				ConnectMode:     "lan",
				BindState:       "free",
				SecurityLink:    "secure",
				FirmwareVersion: "01.09.01.00",
				WiFiSignalDBM:   "-52",
			},
			bambuLANDiscoveryDevice{
				PrinterID: "printer-2",
				Host:      "192.168.1.41",
				Name:      "Bambu Two",
				Model:     "P1S",
			},
		), nil
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
	})

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_bambu_1",
		Profile:  "hybrid",
		Adapters: []string{"bambu"},
	})

	if result.JobStatus != "completed" {
		t.Fatalf("job_status = %q, want completed", result.JobStatus)
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
	if online.CurrentJobState != "pending" {
		t.Fatalf("online current_job_state = %q, want pending", online.CurrentJobState)
	}
	if source, _ := online.Evidence["discovery_source"].(string); source != discoverySourceBambuLAN {
		t.Fatalf("online discovery_source = %q, want %q", source, discoverySourceBambuLAN)
	}
	if gotIP, _ := online.Evidence["ip_address"].(string); gotIP != "192.168.1.40" {
		t.Fatalf("online ip_address = %q, want 192.168.1.40", gotIP)
	}
	if connectMode, _ := online.Evidence["dev_connect"].(string); connectMode != "lan" {
		t.Fatalf("online dev_connect = %q, want lan", connectMode)
	}
	if lanModeDetected, _ := online.Evidence["lan_mode_detected"].(bool); !lanModeDetected {
		t.Fatalf("online lan_mode_detected = %v, want true", online.Evidence["lan_mode_detected"])
	}
	if bindState, _ := online.Evidence["dev_bind"].(string); bindState != "free" {
		t.Fatalf("online dev_bind = %q, want free", bindState)
	}

	offline := byEndpoint["bambu://printer-2"]
	if offline.Status != "reachable" {
		t.Fatalf("offline candidate status = %q, want reachable", offline.Status)
	}
	if offline.CurrentPrinterState != "idle" {
		t.Fatalf("offline current_printer_state = %q, want idle", offline.CurrentPrinterState)
	}
	if offline.CurrentJobState != "pending" {
		t.Fatalf("offline current_job_state = %q, want pending", offline.CurrentJobState)
	}
	if gotIP, _ := offline.Evidence["ip_address"].(string); gotIP != "192.168.1.41" {
		t.Fatalf("offline ip_address = %q, want 192.168.1.41", gotIP)
	}
	auditLog := readAuditLog(t, a)
	if !strings.Contains(auditLog, `"event":"bambu_lan_discovery_candidates"`) {
		t.Fatalf("audit log missing bambu_lan_discovery_candidates event: %s", auditLog)
	}
	if !strings.Contains(auditLog, `"bambu://printer-1"`) || !strings.Contains(auditLog, `"bambu://printer-2"`) {
		t.Fatalf("audit log missing discovered bambu endpoints: %s", auditLog)
	}
}

func TestExecuteDiscoveryJobBambuLANDiscoveryError(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}
	a.cfg.DiscoveryProbeTimeout = 150 * time.Millisecond
	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, _ time.Duration, _ bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		return bambuLANDiscoveryResult{}, errors.New("lan ssdp probe failed")
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
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
	if source, _ := candidate.Evidence["discovery_source"].(string); source != discoverySourceBambuLAN {
		t.Fatalf("discovery_source = %q, want %q", source, discoverySourceBambuLAN)
	}
}

func TestExecuteDiscoveryJobBambuLANNoTargetsRejected(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}
	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, _ time.Duration, _ bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		return bambuLANDiscoveryResult{}, nil
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
	})

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
	if candidate.RejectionReason != "no_targets" {
		t.Fatalf("rejection_reason = %q, want no_targets", candidate.RejectionReason)
	}
	auditLog := readAuditLog(t, a)
	if !strings.Contains(auditLog, `"event":"bambu_lan_discovery_no_targets"`) {
		t.Fatalf("audit log missing bambu_lan_discovery_no_targets event: %s", auditLog)
	}
}

func TestBuildDiscoveryInventoryEntriesDropsCandidateWithoutEndpoint(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true

	entries := a.buildDiscoveryInventoryEntries([]discoveryCandidateResult{
		{
			AdapterFamily:     "bambu",
			Status:            "unreachable",
			ConnectivityError: "lan ssdp probe failed",
			Evidence: map[string]any{
				"source":           discoverySourceBambuLAN,
				"discovery_source": discoverySourceBambuLAN,
			},
		},
	})
	if len(entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(entries))
	}
	auditLog := readAuditLog(t, a)
	if !strings.Contains(auditLog, `"event":"discovery_inventory_candidate_dropped"`) {
		t.Fatalf("audit log missing discovery_inventory_candidate_dropped event: %s", auditLog)
	}
	if !strings.Contains(auditLog, `"drop_reason":"missing_endpoint_url"`) {
		t.Fatalf("audit log missing missing_endpoint_url drop reason: %s", auditLog)
	}
	if !strings.Contains(auditLog, `"discovery_source":"bambu_lan_ssdp"`) {
		t.Fatalf("audit log missing bambu discovery source: %s", auditLog)
	}
}

func TestShouldLogAuditEventToStdoutIncludesBambuLANDiagnostics(t *testing.T) {
	events := []string{
		"bambu_lan_discovery_candidates",
		"bambu_lan_discovery_probe_summary",
		"bambu_lan_discovery_no_targets",
		"bambu_lan_discovery_skipped_device",
		"discovery_inventory_candidate_dropped",
	}
	for _, event := range events {
		if !shouldLogAuditEventToStdout(event) {
			t.Fatalf("shouldLogAuditEventToStdout(%q) = false, want true", event)
		}
	}
}

func TestParseBambuLANDiscoveryResponseForge2Packet(t *testing.T) {
	payload := []byte(strings.Join([]string{
		"NOTIFY * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		"Server: UPnP/1.0",
		"Location: 192.168.100.175",
		"NT: urn:bambulab-com:device:3dprinter:1",
		"USN: 01P00C511601082",
		"Cache-Control: max-age=1800",
		"DevModel.bambu.com: C12",
		"DevName.bambu.com: Forge#2",
		"DevSignal.bambu.com: -52",
		"DevConnect.bambu.com: lan",
		"DevBind.bambu.com: free",
		"Devseclink.bambu.com: secure",
		"DevVersion.bambu.com: 01.09.01.00",
		"DevCap.bambu.com: 1",
		"",
		"",
	}, "\r\n"))

	device, ok := parseBambuLANDiscoveryResponse(payload, &net.UDPAddr{
		IP:   net.ParseIP("192.168.100.175"),
		Port: 1900,
	})
	if !ok {
		t.Fatalf("expected Forge#2 SSDP payload to parse")
	}
	if device.PrinterID != "01P00C511601082" {
		t.Fatalf("printer_id = %q, want 01P00C511601082", device.PrinterID)
	}
	if device.Host != "192.168.100.175" {
		t.Fatalf("host = %q, want 192.168.100.175", device.Host)
	}
	if device.Name != "Forge#2" {
		t.Fatalf("name = %q, want Forge#2", device.Name)
	}
	if device.Model != "C12" {
		t.Fatalf("model = %q, want C12", device.Model)
	}
	if device.ConnectMode != "lan" {
		t.Fatalf("connect_mode = %q, want lan", device.ConnectMode)
	}
	if device.BindState != "free" {
		t.Fatalf("bind_state = %q, want free", device.BindState)
	}
	if device.SecurityLink != "secure" {
		t.Fatalf("security_link = %q, want secure", device.SecurityLink)
	}
	if device.FirmwareVersion != "01.09.01.00" {
		t.Fatalf("firmware_version = %q, want 01.09.01.00", device.FirmwareVersion)
	}
	if device.WiFiSignalDBM != "-52" {
		t.Fatalf("wifi_signal_dbm = %q, want -52", device.WiFiSignalDBM)
	}
	if device.Capability != "1" {
		t.Fatalf("capability = %q, want 1", device.Capability)
	}
}

func TestExecuteDiscoveryJobBambuLANSkipsCloudDevices(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}

	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, _ time.Duration, _ bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		return newTestBambuLANDiscoveryResult(
			bambuLANDiscoveryDevice{
				PrinterID:   "printer-cloud",
				Host:        "192.168.1.50",
				Name:        "Cloud Forge",
				Model:       "X1C",
				ConnectMode: "cloud",
				BindState:   "occupied",
			},
			bambuLANDiscoveryDevice{
				PrinterID:   "printer-lan",
				Host:        "192.168.1.51",
				Name:        "LAN Forge",
				Model:       "P1S",
				ConnectMode: "lan",
				BindState:   "free",
			},
		), nil
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
	})

	result := a.executeDiscoveryJob(context.Background(), discoveryJobItem{
		JobID:    "scan_bambu_4",
		Profile:  "hybrid",
		Adapters: []string{"bambu"},
	})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(result.Candidates))
	}
	if got := result.Candidates[0].EndpointURL; got != "bambu://printer-lan" {
		t.Fatalf("endpoint_url = %q, want bambu://printer-lan", got)
	}
	auditLog := readAuditLog(t, a)
	if !strings.Contains(auditLog, `"event":"bambu_lan_discovery_skipped_device"`) {
		t.Fatalf("audit log missing bambu_lan_discovery_skipped_device event: %s", auditLog)
	}
	if !strings.Contains(auditLog, `"connect_mode":"cloud"`) {
		t.Fatalf("audit log missing skipped cloud connect mode: %s", auditLog)
	}
}

func TestExecuteBambuLANDiscoveryUsesCachedProbeHosts(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.bambuLANProbeHosts["192.168.100.175"] = time.Now().UTC()

	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, _ time.Duration, options bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		if len(options.PreferredHosts) == 0 || options.PreferredHosts[0] != "192.168.100.175" {
			t.Fatalf("preferred_hosts = %v, want first host 192.168.100.175", options.PreferredHosts)
		}
		return newTestBambuLANDiscoveryResult(
			bambuLANDiscoveryDevice{
				PrinterID:   "01P00C511601082",
				Host:        "192.168.100.175",
				Name:        "Forge#2",
				Model:       "C12",
				ConnectMode: "lan",
				BindState:   "free",
			},
		), nil
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
	})

	candidates, err := a.executeBambuLANDiscovery(context.Background(), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("executeBambuLANDiscovery returned error: %v", err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1", len(candidates))
	}
	if got := candidates[0].EndpointURL; got != "bambu://01P00C511601082" {
		t.Fatalf("endpoint_url = %q, want bambu://01P00C511601082", got)
	}
}

func TestExecuteBambuLANDiscoveryExtendsTimeoutForColdScan(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, timeout time.Duration, _ bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		if timeout < 15*time.Second {
			t.Fatalf("timeout = %s, want at least 15s", timeout)
		}
		return bambuLANDiscoveryResult{}, nil
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
	})

	if _, err := a.executeBambuLANDiscovery(context.Background(), 2500*time.Millisecond); err != nil {
		t.Fatalf("executeBambuLANDiscovery returned error: %v", err)
	}
}

func TestExecuteBambuLANDiscoveryUsesShorterTimeoutWithKnownHosts(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.bambuLANProbeHosts["192.168.100.175"] = time.Now().UTC()

	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, timeout time.Duration, _ bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		if timeout < 6*time.Second {
			t.Fatalf("timeout = %s, want at least 6s", timeout)
		}
		if timeout >= 15*time.Second {
			t.Fatalf("timeout = %s, want cached-host scan to stay below 15s", timeout)
		}
		return bambuLANDiscoveryResult{}, nil
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
	})

	if _, err := a.executeBambuLANDiscovery(context.Background(), 2500*time.Millisecond); err != nil {
		t.Fatalf("executeBambuLANDiscovery returned error: %v", err)
	}
}

func TestParseActivePrivateIPv4HostsFromARPFiltersIncompleteAndForeignNetworks(t *testing.T) {
	raw := strings.Join([]string{
		"? (192.168.100.175) at 94:a9:90:16:8c:18 on en0 ifscope [ethernet]",
		"? (192.168.100.172) at 3c:84:27:f0:ba:30 on en0 ifscope [ethernet]",
		"? (192.168.100.184) at (incomplete) on en0 ifscope [ethernet]",
		"? (192.168.64.11) at be:c1:62:02:d1:d1 on bridge100 ifscope [bridge]",
		"? (169.254.94.89) at e8:ea:6a:94:64:3a on en0 [ethernet]",
		"",
	}, "\n")

	hosts := parseActivePrivateIPv4HostsFromARP(raw, []string{"192.168.100.0/24"})
	want := []string{"192.168.100.172", "192.168.100.175"}
	if len(hosts) != len(want) {
		t.Fatalf("active hosts count = %d, want %d (%v)", len(hosts), len(want), hosts)
	}
	for idx := range want {
		if hosts[idx] != want[idx] {
			t.Fatalf("active hosts = %v, want %v", hosts, want)
		}
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

func TestPollConfigCommandsOnceUpsertsBambuLANCredentials(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	a.bambuLANStore = store

	var ackStatuses []configCommandAckRequest
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/config-commands"):
			writeJSON(w, http.StatusOK, configCommandsResponse{
				Commands: []configCommandItem{
					{
						CommandID:                42,
						CommandType:              "bambu_lan_credentials_upsert",
						TargetAdapterFamily:      "bambu",
						TargetEndpointNormalized: "bambu://01P00C511601082",
						Payload:                  json.RawMessage(`{"serial":"01P00C511601082","host":"192.168.100.175","access_code":"12345678","name":"Forge#2","model":"C12"}`),
						CreatedAt:                edgeTimestamp{Time: time.Now().UTC()},
						ExpiresAt:                edgeTimestamp{Time: time.Now().UTC().Add(5 * time.Minute)},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/config-commands/42/ack"):
			var ack configCommandAckRequest
			if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
				t.Fatalf("decode ack request failed: %v", err)
			}
			ackStatuses = append(ackStatuses, ack)
			writeJSON(w, http.StatusOK, configCommandAckResponse{Accepted: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = saasSrv.URL
	a.mu.Unlock()

	if err := a.pollConfigCommandsOnce(context.Background()); err != nil {
		t.Fatalf("pollConfigCommandsOnce failed: %v", err)
	}
	if len(ackStatuses) != 1 {
		t.Fatalf("ack count = %d, want 1", len(ackStatuses))
	}
	if ackStatuses[0].Status != "acknowledged" {
		t.Fatalf("ack status = %q, want acknowledged", ackStatuses[0].Status)
	}

	record, err := store.Get(context.Background(), "01P00C511601082")
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if record.Host != "192.168.100.175" {
		t.Fatalf("stored host = %q, want 192.168.100.175", record.Host)
	}
	if record.AccessCode != "12345678" {
		t.Fatalf("stored access code = %q, want 12345678", record.AccessCode)
	}
}

func TestPollConfigCommandsOnceAcknowledgesFailedApply(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	var ackStatuses []configCommandAckRequest
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Agent-Schema-Version"); got != schemaVersionHeaderValue() {
			t.Fatalf("unexpected schema header: %q", got)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/config-commands"):
			writeJSON(w, http.StatusOK, configCommandsResponse{
				Commands: []configCommandItem{
					{
						CommandID:                99,
						CommandType:              "bambu_lan_credentials_upsert",
						TargetAdapterFamily:      "bambu",
						TargetEndpointNormalized: "bambu://serial-missing-store",
						Payload:                  json.RawMessage(`{"serial":"serial-missing-store","host":"192.168.1.80","access_code":"12345678"}`),
						CreatedAt:                edgeTimestamp{Time: time.Now().UTC()},
						ExpiresAt:                edgeTimestamp{Time: time.Now().UTC().Add(5 * time.Minute)},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/config-commands/99/ack"):
			var ack configCommandAckRequest
			if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
				t.Fatalf("decode ack request failed: %v", err)
			}
			ackStatuses = append(ackStatuses, ack)
			writeJSON(w, http.StatusOK, configCommandAckResponse{Accepted: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = saasSrv.URL
	a.mu.Unlock()

	err := a.pollConfigCommandsOnce(context.Background())
	if err == nil {
		t.Fatalf("expected pollConfigCommandsOnce to fail when store is unavailable")
	}
	if len(ackStatuses) != 1 {
		t.Fatalf("ack count = %d, want 1", len(ackStatuses))
	}
	if ackStatuses[0].Status != "failed" {
		t.Fatalf("ack status = %q, want failed", ackStatuses[0].Status)
	}
	if !strings.Contains(ackStatuses[0].Error, "store is not configured") {
		t.Fatalf("ack error = %q, want store failure", ackStatuses[0].Error)
	}
}

func TestFetchMoonrakerCommandCapabilitiesDetectsPrimaryLightAndFilamentMacros(t *testing.T) {
	a := newTestAgent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/machine/device_power/devices":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"devices": []map[string]any{
						{"device": "chamber_light", "status": "off"},
						{"device": "psu", "status": "on"},
					},
				},
			})
		case "/printer/objects/list":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"objects": []string{
						"print_stats",
						"gcode_macro LOAD_FILAMENT",
						"gcode_macro UNLOAD_FILAMENT",
						"filament_switch_sensor toolhead_sensor",
					},
				},
			})
		case "/printer/objects/query":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"status": map[string]any{
						"filament_switch_sensor toolhead_sensor": map[string]any{
							"filament_detected": true,
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	capabilities, err := a.fetchMoonrakerCommandCapabilities(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerCommandCapabilities failed: %v", err)
	}

	led, ok := capabilities["led"].(map[string]any)
	if !ok || led["supported"] != true || led["state"] != "off" {
		t.Fatalf("led capability = %#v, want supported off state", capabilities["led"])
	}
	load, ok := capabilities["load_filament"].(map[string]any)
	if !ok || load["supported"] != true {
		t.Fatalf("load capability = %#v, want supported", capabilities["load_filament"])
	}
	unload, ok := capabilities["unload_filament"].(map[string]any)
	if !ok || unload["supported"] != true {
		t.Fatalf("unload capability = %#v, want supported", capabilities["unload_filament"])
	}
	filament, ok := capabilities["filament"].(map[string]any)
	if !ok || filament["state"] != "loaded" || filament["action_state"] != filamentActionStateIdle || filament["sensor_present"] != true {
		t.Fatalf("filament capability = %#v, want loaded idle with sensor", capabilities["filament"])
	}
}

func TestFetchMoonrakerCommandCapabilitiesTreatsMissingDevicePowerEndpointAsUnsupportedNotError(t *testing.T) {
	a := newTestAgent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/machine/device_power/devices":
			http.NotFound(w, r)
		case "/printer/objects/list":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"objects": []string{
						"gcode_macro LOAD_FILAMENT",
						"gcode_macro UNLOAD_FILAMENT",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	capabilities, err := a.fetchMoonrakerCommandCapabilities(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerCommandCapabilities should not fail on missing device_power endpoint: %v", err)
	}
	led, ok := capabilities["led"].(map[string]any)
	if !ok || led["supported"] != false {
		t.Fatalf("led capability = %#v, want unsupported", capabilities["led"])
	}
	load, ok := capabilities["load_filament"].(map[string]any)
	if !ok || load["supported"] != true {
		t.Fatalf("load capability = %#v, want supported", capabilities["load_filament"])
	}
}

func TestFetchMoonrakerCommandCapabilitiesFallsBackToLEDObjectWhenDevicePowerUnavailable(t *testing.T) {
	a := newTestAgent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/machine/device_power/devices":
			http.NotFound(w, r)
		case "/printer/objects/list":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"objects": []string{
						"led cavity_led",
					},
				},
			})
		case "/printer/objects/query":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"status": map[string]any{
						"led cavity_led": map[string]any{
							"color_data": []any{
								[]any{0.0, 0.0, 0.0, 0.0},
							},
						},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	capabilities, err := a.fetchMoonrakerCommandCapabilities(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerCommandCapabilities failed: %v", err)
	}
	led, ok := capabilities["led"].(map[string]any)
	if !ok || led["supported"] != true || led["state"] != "off" || led["device"] != "led cavity_led" {
		t.Fatalf("led capability = %#v, want supported off led object", capabilities["led"])
	}
	if led["mode"] != "klipper_led" {
		t.Fatalf("led mode = %#v, want klipper_led", led["mode"])
	}
}

func TestOpenSnapshotLoopReaderToleratesTransientSnapshotFailures(t *testing.T) {
	a := newTestAgent(t)
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount <= 2 {
			http.Error(w, "temporary camera error", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write([]byte{0xff, 0xd8, 0xff, 0xd9})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, contentType, err := a.openSnapshotLoopReader(ctx, srv.URL+"/monitor.jpg?ts={ts}")
	if err != nil {
		t.Fatalf("openSnapshotLoopReader failed: %v", err)
	}
	defer reader.Close()

	if contentType != "multipart/x-mixed-replace;boundary=frame" {
		t.Fatalf("contentType = %q, want multipart/x-mixed-replace;boundary=frame", contentType)
	}

	readResult := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		n, err := io.ReadAtLeast(reader, buf, 64)
		if err != nil {
			readErr <- err
			return
		}
		readResult <- append([]byte(nil), buf[:n]...)
	}()

	select {
	case err := <-readErr:
		t.Fatalf("snapshot loop reader failed before recovery: %v", err)
	case payload := <-readResult:
		if !bytes.Contains(payload, []byte("--frame")) {
			t.Fatalf("payload = %q, want multipart frame header", string(payload))
		}
		if !bytes.Contains(payload, []byte{0xff, 0xd8, 0xff, 0xd9}) {
			t.Fatalf("payload missing jpeg frame bytes: %v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for snapshot loop reader to recover")
	}
}

func TestSendMoonrakerCameraMonitorCommandDefaultSendsStartMonitorRPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	payloadCh := make(chan map[string]any, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		headers := make(http.Header)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				errCh <- readErr
				return
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "GET ") {
				continue
			}
			if trimmed == "" {
				break
			}
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		acceptKey := computeWebSocketAcceptKey(headers.Get("Sec-WebSocket-Key"))
		if _, err := io.WriteString(
			conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: "+acceptKey+"\r\n\r\n",
		); err != nil {
			errCh <- err
			return
		}

		header := make([]byte, 2)
		if _, err := io.ReadFull(reader, header); err != nil {
			errCh <- err
			return
		}
		payloadLen := int(header[1] & 0x7f)
		mask := make([]byte, 4)
		if _, err := io.ReadFull(reader, mask); err != nil {
			errCh <- err
			return
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			errCh <- err
			return
		}
		for idx := range payload {
			payload[idx] ^= mask[idx%len(mask)]
		}

		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			errCh <- err
			return
		}
		payloadCh <- decoded
	}()

	endpointURL := "http://" + listener.Addr().String()
	if err := sendMoonrakerCameraMonitorCommandDefault(context.Background(), endpointURL, false); err != nil {
		t.Fatalf("sendMoonrakerCameraMonitorCommandDefault failed: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("websocket capture failed: %v", err)
	case payload := <-payloadCh:
		if payload["method"] != "camera.start_monitor" {
			t.Fatalf("method = %v, want camera.start_monitor", payload["method"])
		}
		params, ok := payload["params"].(map[string]any)
		if !ok {
			t.Fatalf("params = %#v, want object", payload["params"])
		}
		if params["domain"] != "lan" {
			t.Fatalf("domain = %v, want lan", params["domain"])
		}
		if params["interval"] != float64(0) {
			t.Fatalf("interval = %v, want 0", params["interval"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for websocket payload")
	}
}

func TestStartMoonrakerCameraMonitorKeepaliveSkipsNonMonitorSnapshots(t *testing.T) {
	a := newTestAgent(t)
	original := sendMoonrakerCameraMonitorCommand
	defer func() {
		sendMoonrakerCameraMonitorCommand = original
	}()

	calls := make(chan string, 4)
	sendMoonrakerCameraMonitorCommand = func(ctx context.Context, endpointURL string, stop bool) error {
		if stop {
			calls <- "stop"
		} else {
			calls <- "start"
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.startMoonrakerCameraMonitorKeepalive(ctx, "http://moonraker.local", "http://moonraker.local/webcam/?action=snapshot")
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case call := <-calls:
		t.Fatalf("unexpected keepalive call for non-monitor snapshot: %s", call)
	default:
	}
}

func TestStartMoonrakerCameraMonitorKeepaliveTriggersMonitorCommands(t *testing.T) {
	a := newTestAgent(t)
	original := sendMoonrakerCameraMonitorCommand
	defer func() {
		sendMoonrakerCameraMonitorCommand = original
	}()

	calls := make(chan string, 4)
	sendMoonrakerCameraMonitorCommand = func(ctx context.Context, endpointURL string, stop bool) error {
		if stop {
			calls <- "stop"
		} else {
			calls <- "start"
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	a.startMoonrakerCameraMonitorKeepalive(ctx, "http://moonraker.local", "http://moonraker.local/server/files/camera/monitor.jpg?ts=1")

	select {
	case call := <-calls:
		if call != "start" {
			t.Fatalf("first keepalive call = %q, want start", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for start monitor call")
	}

	cancel()

	select {
	case call := <-calls:
		if call != "stop" {
			t.Fatalf("stop keepalive call = %q, want stop", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stop monitor call")
	}
}

func TestPollPrinterCommandsOnceQueuesCommandAction(t *testing.T) {
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
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/printer-commands"):
			writeJSON(w, http.StatusOK, printerCommandsResponse{
				Commands: []printerCommandItem{
					{
						CommandID:  77,
						PrinterID:  1,
						CommandKey: "load_filament",
						Payload:    json.RawMessage(`{}`),
						CreatedAt:  edgeTimestamp{Time: time.Now().UTC()},
						ExpiresAt:  edgeTimestamp{Time: time.Now().UTC().Add(5 * time.Minute)},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = saasSrv.URL
	a.mu.Unlock()

	if err := a.pollPrinterCommandsOnce(context.Background()); err != nil {
		t.Fatalf("pollPrinterCommandsOnce failed: %v", err)
	}

	queue := a.actionQueue[1]
	if len(queue) != 1 {
		t.Fatalf("queued action count = %d, want 1", len(queue))
	}
	if queue[0].Kind != "load_filament" {
		t.Fatalf("queued kind = %q, want load_filament", queue[0].Kind)
	}
	if queue[0].CommandRequestID != 77 {
		t.Fatalf("queued command request id = %d, want 77", queue[0].CommandRequestID)
	}
}

func TestExecuteNextActionAcknowledgesSuccessfulPrinterCommand(t *testing.T) {
	a := newTestAgent(t)
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true

	var ackStatuses []printerCommandAckRequest
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_1/printer-commands/55/ack"):
			var ack printerCommandAckRequest
			if err := json.NewDecoder(r.Body).Decode(&ack); err != nil {
				t.Fatalf("decode printer command ack failed: %v", err)
			}
			ackStatuses = append(ackStatuses, ack)
			writeJSON(w, http.StatusOK, printerCommandAckResponse{Accepted: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/machine/device_power/devices":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"devices": []map[string]any{
						{"device": "chamber_light", "status": "off"},
					},
				},
			})
		case "/machine/device_power/device":
			if r.URL.Query().Get("device") != "chamber_light" {
				t.Fatalf("device query = %q, want chamber_light", r.URL.Query().Get("device"))
			}
			if r.URL.Query().Get("action") != "on" {
				t.Fatalf("action query = %q, want on", r.URL.Query().Get("action"))
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	a.mu.Lock()
	a.bootstrap.ControlPlaneURL = saasSrv.URL
	a.bindings[1] = edgeBinding{PrinterID: 1, AdapterFamily: "moonraker", EndpointURL: moonrakerSrv.URL}
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		CurrentJobState:     "pending",
		CommandCapabilities: map[string]any{
			"led": map[string]any{"supported": true, "state": "off"},
		},
	}
	a.actionQueue[1] = []action{
		{
			PrinterID:        1,
			Kind:             "light_on",
			Reason:           "printer command light_on",
			CommandRequestID: 55,
			EnqueuedAt:       time.Now().UTC(),
			NextAttempt:      time.Now().UTC(),
		},
	}
	a.mu.Unlock()

	if err := a.executeNextAction(context.Background()); err != nil {
		t.Fatalf("executeNextAction failed: %v", err)
	}
	if len(ackStatuses) != 1 {
		t.Fatalf("ack count = %d, want 1", len(ackStatuses))
	}
	if ackStatuses[0].Status != "acknowledged" {
		t.Fatalf("ack status = %q, want acknowledged", ackStatuses[0].Status)
	}
	led, ok := a.currentState[1].CommandCapabilities["led"].(map[string]any)
	if !ok || led["state"] != "on" {
		t.Fatalf("led capability after success = %#v, want state on", a.currentState[1].CommandCapabilities["led"])
	}
}

func TestExecuteMoonrakerLightActionFallsBackToLEDObjectWhenDevicePowerUnavailable(t *testing.T) {
	a := newTestAgent(t)
	var receivedScript string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/machine/device_power/devices":
			http.NotFound(w, r)
		case "/printer/objects/list":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"objects": []string{
						"led cavity_led",
					},
				},
			})
		case "/printer/gcode/script":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode gcode script payload failed: %v", err)
			}
			receivedScript = payload["script"]
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	if err := a.executeMoonrakerLightAction(context.Background(), srv.URL, "light_on"); err != nil {
		t.Fatalf("executeMoonrakerLightAction failed: %v", err)
	}
	if receivedScript != "SET_LED LED=cavity_led WHITE=1 SYNC=0 TRANSMIT=1" {
		t.Fatalf("received script = %q, want cavity_led SET_LED on script", receivedScript)
	}
}

func TestParseBambuLANMQTTSnapshotPayloadMapsPushStatus(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "RUNNING",
			"mc_percent": 42,
			"mc_remaining_time": 5,
			"hms": []
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	if snapshot.PrinterState != "printing" {
		t.Fatalf("printer state = %q, want printing", snapshot.PrinterState)
	}
	if snapshot.JobState != "printing" {
		t.Fatalf("job state = %q, want printing", snapshot.JobState)
	}
	if snapshot.TelemetrySource != telemetrySourceBambuLANMQTT {
		t.Fatalf("telemetry source = %q, want %q", snapshot.TelemetrySource, telemetrySourceBambuLANMQTT)
	}
	if snapshot.ProgressPct == nil || *snapshot.ProgressPct != 42 {
		t.Fatalf("progress pct = %v, want 42", snapshot.ProgressPct)
	}
	if snapshot.RemainingSeconds == nil || *snapshot.RemainingSeconds != 300 {
		t.Fatalf("remaining seconds = %v, want 300", snapshot.RemainingSeconds)
	}
}

func TestParseBambuLANMQTTSnapshotPayloadTreatsIdleFailureSnapshotAsIdle(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "FAILED",
			"print_type": "idle",
			"task_id": "0",
			"gcode_file": "",
			"print_error": 0,
			"hms": [],
			"mc_remaining_time": 4.88
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	if snapshot.PrinterState != "idle" {
		t.Fatalf("printer state = %q, want idle", snapshot.PrinterState)
	}
	if snapshot.JobState != "pending" {
		t.Fatalf("job state = %q, want pending", snapshot.JobState)
	}
	if snapshot.ManualIntervention != "" {
		t.Fatalf("manual intervention = %q, want empty", snapshot.ManualIntervention)
	}
	if snapshot.RawPrinterStatus != "FAILED" {
		t.Fatalf("raw printer status = %q, want FAILED", snapshot.RawPrinterStatus)
	}
}

func TestParseBambuLANMQTTSnapshotPayloadKeepsActiveFailureAsError(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "FAILED",
			"print_type": "printing",
			"task_id": "123",
			"gcode_file": "plate.3mf",
			"print_error": 12,
			"hms": []
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	if snapshot.PrinterState != "error" {
		t.Fatalf("printer state = %q, want error", snapshot.PrinterState)
	}
	if snapshot.JobState != "failed" {
		t.Fatalf("job state = %q, want failed", snapshot.JobState)
	}
	if snapshot.ManualIntervention != "print_error" {
		t.Fatalf("manual intervention = %q, want print_error", snapshot.ManualIntervention)
	}
}

func TestParseBambuLANMQTTSnapshotPayloadTreatsFinishedAsCompleted(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "FINISHED",
			"print_type": "idle",
			"task_id": "0",
			"gcode_file": "",
			"print_error": 0,
			"hms": []
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	if snapshot.PrinterState != "idle" {
		t.Fatalf("printer state = %q, want idle", snapshot.PrinterState)
	}
	if snapshot.JobState != "completed" {
		t.Fatalf("job state = %q, want completed", snapshot.JobState)
	}
}

func TestParseBambuLANMQTTSnapshotPayloadCapturesLightCapabilities(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "IDLE",
			"print_type": "idle",
			"lights_report": [{"node":"chamber_light","mode":"on"}],
			"ams": {"tray_now":"254"},
			"vt_tray": {"tray_type":"PLA","tray_info_idx":"GFL99"}
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	led, ok := snapshot.CommandCapabilities["led"].(map[string]any)
	if !ok || led["supported"] != true || led["state"] != "on" {
		t.Fatalf("led capability = %#v, want supported on", snapshot.CommandCapabilities["led"])
	}
	load, ok := snapshot.CommandCapabilities["load_filament"].(map[string]any)
	if !ok || load["supported"] != true {
		t.Fatalf("load capability = %#v, want supported", snapshot.CommandCapabilities["load_filament"])
	}
	filament, ok := snapshot.CommandCapabilities["filament"].(map[string]any)
	if !ok || filament["state"] != "loaded" || filament["state_source"] != filamentStateSourceBambuActiveSource || filament["source_kind"] != filamentSourceKindExternalSpool {
		t.Fatalf("filament capability = %#v, want loaded external spool", snapshot.CommandCapabilities["filament"])
	}
	if _, exists := filament["action_state"]; exists {
		t.Fatalf("filament action_state = %#v, want omitted when idle", filament["action_state"])
	}
}

func TestMergeCommandCapabilitiesPreservesPreviousSupportedControlsAcrossUnsupportedFallback(t *testing.T) {
	previous := map[string]any{
		"led": map[string]any{
			"supported": true,
			"state":     "on",
		},
		"filament": map[string]any{
			"state":        "loaded",
			"action_state": filamentActionStateIdle,
			"state_source": filamentStateSourceBambuActiveSource,
			"confidence":   filamentConfidenceConfirmed,
		},
		"load_filament": map[string]any{
			"supported": true,
		},
		"unload_filament": map[string]any{
			"supported": true,
		},
	}

	merged := mergeCommandCapabilities(previous, unsupportedBambuCommandCapabilities())

	led, ok := merged["led"].(map[string]any)
	if !ok || led["supported"] != true || led["state"] != "on" {
		t.Fatalf("led capability = %#v, want supported on", merged["led"])
	}
	load, ok := merged["load_filament"].(map[string]any)
	if !ok || load["supported"] != true {
		t.Fatalf("load capability = %#v, want supported", merged["load_filament"])
	}
	unload, ok := merged["unload_filament"].(map[string]any)
	if !ok || unload["supported"] != true {
		t.Fatalf("unload capability = %#v, want supported", merged["unload_filament"])
	}
}

func TestFallbackBambuCommandCapabilitiesUsesLastRuntimeSnapshotRecord(t *testing.T) {
	a := newTestAgent(t)
	a.recordBambuLANRuntimeSnapshot(
		"printer-1",
		"192.168.1.20",
		bindingSnapshot{
			CommandCapabilities: map[string]any{
				"led": map[string]any{
					"supported": true,
					"state":     "off",
				},
				"load_filament": map[string]any{
					"supported": true,
				},
				"unload_filament": map[string]any{
					"supported": true,
				},
			},
		},
	)

	capabilities := a.fallbackBambuCommandCapabilities("printer-1")
	led, ok := capabilities["led"].(map[string]any)
	if !ok || led["supported"] != true || led["state"] != "off" {
		t.Fatalf("led capability = %#v, want supported off", capabilities["led"])
	}
	load, ok := capabilities["load_filament"].(map[string]any)
	if !ok || load["supported"] != true {
		t.Fatalf("load capability = %#v, want supported", capabilities["load_filament"])
	}
}

func TestParseBambuLANMQTTSnapshotPayloadDoesNotTreatVTTrayMetadataAloneAsLoaded(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "IDLE",
			"print_type": "idle",
			"vt_tray": {"tray_type":"PLA","tray_info_idx":"GFL99"}
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	filament, ok := snapshot.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["state"] != "unknown" {
		t.Fatalf("filament state = %v, want unknown", filament["state"])
	}
	if filament["source_kind"] != filamentSourceKindUnknown {
		t.Fatalf("filament source_kind = %v, want unknown", filament["source_kind"])
	}
}

func TestParseBambuLANMQTTSnapshotPayloadReportsAMSActiveSource(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "IDLE",
			"print_type": "idle",
			"ams": {"tray_now":"0"}
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	filament, ok := snapshot.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["state"] != "loaded" {
		t.Fatalf("filament state = %v, want loaded", filament["state"])
	}
	if filament["source_kind"] != filamentSourceKindAMS {
		t.Fatalf("filament source_kind = %v, want ams", filament["source_kind"])
	}
	if filament["source_label"] != "AMS 1 / Tray 1" {
		t.Fatalf("filament source_label = %v, want AMS 1 / Tray 1", filament["source_label"])
	}
}

func TestParseBambuLANMQTTSnapshotPayloadReportsNoActiveSourceAsUnloaded(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "IDLE",
			"print_type": "idle",
			"ams": {"tray_now":"255"}
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	filament, ok := snapshot.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["state"] != "unloaded" {
		t.Fatalf("filament state = %v, want unloaded", filament["state"])
	}
	if filament["source_kind"] != filamentSourceKindNone {
		t.Fatalf("filament source_kind = %v, want none", filament["source_kind"])
	}
}

func TestParseBambuLANMQTTSnapshotPayloadIncludesControlTemperaturesAndFans(t *testing.T) {
	snapshot, err := parseBambuLANMQTTSnapshotPayload([]byte(`{
		"print": {
			"gcode_state": "IDLE",
			"print_type": "idle",
			"nozzle_temper": "215.5",
			"nozzle_target_temper": "220",
			"bed_temper": "58.2",
			"bed_target_temper": "60",
			"chamber_temper": "31",
			"cooling_fan_speed": "15",
			"big_fan1_speed": "0",
			"big_fan2_speed": "1"
		}
	}`))
	if err != nil {
		t.Fatalf("parseBambuLANMQTTSnapshotPayload failed: %v", err)
	}
	if snapshot.ControlStatus == nil {
		t.Fatalf("missing control status")
	}
	if snapshot.ControlStatus.Nozzle.Current == nil || *snapshot.ControlStatus.Nozzle.Current != 215.5 {
		t.Fatalf("nozzle current = %#v, want 215.5", snapshot.ControlStatus.Nozzle.Current)
	}
	if snapshot.ControlStatus.Bed.Target == nil || *snapshot.ControlStatus.Bed.Target != 60 {
		t.Fatalf("bed target = %#v, want 60", snapshot.ControlStatus.Bed.Target)
	}
	if snapshot.ControlStatus.Chamber.Current == nil || *snapshot.ControlStatus.Chamber.Current != 31 {
		t.Fatalf("chamber current = %#v, want 31", snapshot.ControlStatus.Chamber.Current)
	}
	if fan := snapshot.ControlStatus.Fans["part_cooling"]; fan.State != "on" {
		t.Fatalf("part cooling state = %q, want on", fan.State)
	}
	if fan := snapshot.ControlStatus.Fans["auxiliary"]; fan.State != "off" {
		t.Fatalf("auxiliary state = %q, want off", fan.State)
	}
	if fan := snapshot.ControlStatus.Fans["chamber"]; fan.State != "on" {
		t.Fatalf("chamber state = %q, want on", fan.State)
	}
}

func TestFetchBambuLANRuntimeSnapshotByPrinterIDPreservesPreviousFanStateWhenTelemetryOmitsFans(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuControlStatusPushInterval = time.Millisecond

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-fans",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.recordBambuLANRuntimeSnapshot("printer-fans", "192.168.100.172", bindingSnapshot{
		PrinterState:     "idle",
		JobState:         "pending",
		TelemetrySource:  telemetrySourceBambuLANMQTT,
		RawPrinterStatus: "IDLE",
		ControlStatus: &printerControlStatusSnapshot{
			Fans: map[string]printerFanStatus{
				"part_cooling": {Supported: true, State: "on"},
				"chamber":      {Supported: true, State: "off"},
			},
			MotionSupported: true,
			HomeSupported:   true,
		},
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState:     "idle",
			JobState:         "pending",
			TelemetrySource:  telemetrySourceBambuLANMQTT,
			RawPrinterStatus: "IDLE",
			ControlStatus: &printerControlStatusSnapshot{
				Nozzle:          printerTemperatureStatus{},
				Bed:             printerTemperatureStatus{},
				Chamber:         printerTemperatureStatus{},
				Fans:            nil,
				MotionSupported: true,
				HomeSupported:   true,
			},
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	time.Sleep(2 * time.Millisecond)
	snapshot, err := a.fetchBambuLANRuntimeSnapshotByPrinterID(context.Background(), "printer-fans")
	if err != nil {
		t.Fatalf("fetchBambuLANRuntimeSnapshotByPrinterID failed: %v", err)
	}
	if snapshot.ControlStatus == nil {
		t.Fatalf("expected control status")
	}
	if fan := snapshot.ControlStatus.Fans["part_cooling"]; fan.State != "on" {
		t.Fatalf("part cooling state = %q, want preserved on", fan.State)
	}
	if fan := snapshot.ControlStatus.Fans["chamber"]; fan.State != "off" {
		t.Fatalf("chamber state = %q, want preserved off", fan.State)
	}
}

func TestMarkActionSuccessForFilamentCommandSetsActionStateNotFinalState(t *testing.T) {
	a := newTestAgent(t)
	a.currentState[1] = currentStateItem{
		PrinterID:           1,
		CurrentPrinterState: "idle",
		CommandCapabilities: map[string]any{},
	}

	a.markActionSuccess(action{PrinterID: 1, Kind: "load_filament", CommandRequestID: 10})
	filament, ok := a.currentState[1].CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability after success")
	}
	if filament["state"] != "unknown" {
		t.Fatalf("filament state = %v, want unknown", filament["state"])
	}
	if filament["action_state"] != filamentActionStateLoading {
		t.Fatalf("filament action_state = %v, want loading", filament["action_state"])
	}
}

func TestResolveRuntimeFilamentCapabilityMarksBambuUnloadCompleteWhenSourceClears(t *testing.T) {
	now := time.Now().UTC()
	previous := currentStateItem{
		PrinterID:  1,
		ReportedAt: now.Add(-2 * time.Second),
		CommandCapabilities: map[string]any{
			"filament": map[string]any{
				"state":             "unknown",
				"action_state":      filamentActionStateUnloading,
				"state_source":      filamentStateSourceCommandFallback,
				"confidence":        filamentConfidenceHeuristic,
				"source_kind":       filamentSourceKindExternalSpool,
				"source_label":      "External spool",
				"action_started_at": now.Add(-5 * time.Second).Format(time.RFC3339Nano),
			},
		},
	}
	current := previous
	current.CommandCapabilities = mergeCommandCapabilities(previous.CommandCapabilities, map[string]any{
		"filament": map[string]any{
			"state":        "unknown",
			"state_source": filamentStateSourceBambuActiveSource,
			"confidence":   filamentConfidenceConfirmed,
			"source_kind":  filamentSourceKindNone,
		},
	})

	resolveRuntimeFilamentCapability(edgeBinding{AdapterFamily: "bambu"}, &current, previous, bindingSnapshot{}, now)

	filament, ok := current.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["state"] != "unloaded" {
		t.Fatalf("filament state = %v, want unloaded", filament["state"])
	}
	if filament["action_state"] != filamentActionStateIdle {
		t.Fatalf("filament action_state = %v, want idle", filament["action_state"])
	}
	if filament["source_kind"] != filamentSourceKindExternalSpool {
		t.Fatalf("filament source_kind = %v, want external_spool", filament["source_kind"])
	}
}

func TestResolveRuntimeFilamentCapabilityTreatsIdleBambuNoSourceAsUnloaded(t *testing.T) {
	now := time.Now().UTC()
	previous := currentStateItem{
		PrinterID:  1,
		ReportedAt: now.Add(-2 * time.Second),
		CommandCapabilities: map[string]any{
			"filament": map[string]any{
				"state":        "loaded",
				"action_state": filamentActionStateIdle,
				"state_source": filamentStateSourceBambuActiveSource,
				"confidence":   filamentConfidenceConfirmed,
				"source_kind":  filamentSourceKindExternalSpool,
				"source_label": "External spool",
			},
		},
	}
	current := previous
	current.CommandCapabilities = mergeCommandCapabilities(previous.CommandCapabilities, map[string]any{
		"filament": map[string]any{
			"state":        "unloaded",
			"action_state": filamentActionStateIdle,
			"state_source": filamentStateSourceBambuActiveSource,
			"confidence":   filamentConfidenceConfirmed,
			"source_kind":  filamentSourceKindNone,
		},
	})

	resolveRuntimeFilamentCapability(edgeBinding{AdapterFamily: "bambu"}, &current, previous, bindingSnapshot{}, now)

	filament, ok := current.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["state"] != "unloaded" {
		t.Fatalf("filament state = %v, want unloaded", filament["state"])
	}
	if filament["action_state"] != filamentActionStateIdle {
		t.Fatalf("filament action_state = %v, want idle", filament["action_state"])
	}
	if filament["source_kind"] != filamentSourceKindNone {
		t.Fatalf("filament source_kind = %v, want none", filament["source_kind"])
	}
}

func TestResolveRuntimeFilamentCapabilityKeepsBambuLoadRunningUntilSourceReturns(t *testing.T) {
	now := time.Now().UTC()
	previous := currentStateItem{
		PrinterID:  1,
		ReportedAt: now.Add(-2 * time.Second),
		CommandCapabilities: map[string]any{
			"filament": map[string]any{
				"state":             "unknown",
				"action_state":      filamentActionStateLoading,
				"state_source":      filamentStateSourceCommandFallback,
				"confidence":        filamentConfidenceHeuristic,
				"source_kind":       filamentSourceKindExternalSpool,
				"source_label":      "External spool",
				"action_started_at": now.Add(-5 * time.Second).Format(time.RFC3339Nano),
			},
		},
	}
	current := previous
	current.CommandCapabilities = mergeCommandCapabilities(previous.CommandCapabilities, map[string]any{
		"filament": map[string]any{
			"state":        "unknown",
			"state_source": filamentStateSourceBambuActiveSource,
			"confidence":   filamentConfidenceConfirmed,
			"source_kind":  filamentSourceKindNone,
		},
	})

	resolveRuntimeFilamentCapability(edgeBinding{AdapterFamily: "bambu"}, &current, previous, bindingSnapshot{}, now)

	filament, ok := current.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["action_state"] != filamentActionStateLoading {
		t.Fatalf("filament action_state = %v, want loading", filament["action_state"])
	}
	if filament["source_kind"] != filamentSourceKindExternalSpool {
		t.Fatalf("filament source_kind = %v, want external_spool", filament["source_kind"])
	}
}

func TestResolveRuntimeFilamentCapabilitySeedsBambuLoadStartTimeWhenTelemetryOmitsIt(t *testing.T) {
	now := time.Now().UTC()
	previous := currentStateItem{
		PrinterID:  1,
		ReportedAt: now.Add(-2 * time.Second),
		CommandCapabilities: map[string]any{
			"filament": map[string]any{
				"state":        "unknown",
				"state_source": filamentStateSourceBambuActiveSource,
				"confidence":   filamentConfidenceConfirmed,
				"source_kind":  filamentSourceKindNone,
				"action_state": filamentActionStateLoading,
			},
		},
	}
	current := previous
	current.CommandCapabilities = mergeCommandCapabilities(previous.CommandCapabilities, map[string]any{
		"filament": map[string]any{
			"state":        "unknown",
			"state_source": filamentStateSourceBambuActiveSource,
			"confidence":   filamentConfidenceConfirmed,
			"source_kind":  filamentSourceKindNone,
			"action_state": filamentActionStateLoading,
		},
	})

	resolveRuntimeFilamentCapability(edgeBinding{AdapterFamily: "bambu"}, &current, previous, bindingSnapshot{}, now)

	filament, ok := current.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["action_state"] != filamentActionStateLoading {
		t.Fatalf("filament action_state = %v, want loading", filament["action_state"])
	}
	rawStartedAt := stringFromAny(filament["action_started_at"])
	if rawStartedAt == "" {
		t.Fatalf("expected action_started_at to be seeded")
	}
	parsed, err := time.Parse(time.RFC3339Nano, rawStartedAt)
	if err != nil {
		t.Fatalf("parse action_started_at failed: %v", err)
	}
	if parsed.IsZero() {
		t.Fatalf("expected non-zero action_started_at")
	}
}

func TestResolveRuntimeFilamentCapabilityMarksBambuLoadConfirmationRequiredAfterTimeout(t *testing.T) {
	now := time.Now().UTC()
	previous := currentStateItem{
		PrinterID:  1,
		ReportedAt: now.Add(-1 * time.Second),
		CommandCapabilities: map[string]any{
			"filament": map[string]any{
				"state":             "unknown",
				"action_state":      filamentActionStateLoading,
				"state_source":      filamentStateSourceCommandFallback,
				"confidence":        filamentConfidenceHeuristic,
				"source_kind":       filamentSourceKindExternalSpool,
				"source_label":      "External spool",
				"action_started_at": now.Add(-bambuFilamentActionTimeout - time.Second).Format(time.RFC3339Nano),
			},
		},
	}
	current := previous
	current.CommandCapabilities = mergeCommandCapabilities(previous.CommandCapabilities, map[string]any{
		"filament": map[string]any{
			"state":        "unknown",
			"state_source": filamentStateSourceBambuActiveSource,
			"confidence":   filamentConfidenceConfirmed,
			"source_kind":  filamentSourceKindNone,
		},
	})

	resolveRuntimeFilamentCapability(edgeBinding{AdapterFamily: "bambu"}, &current, previous, bindingSnapshot{}, now)

	filament, ok := current.CommandCapabilities["filament"].(map[string]any)
	if !ok {
		t.Fatalf("missing filament capability")
	}
	if filament["action_state"] != filamentActionStateNeedsUserConfirmation {
		t.Fatalf("filament action_state = %v, want needs_user_confirmation", filament["action_state"])
	}
	if filament["source_kind"] != filamentSourceKindExternalSpool {
		t.Fatalf("filament source_kind = %v, want external_spool", filament["source_kind"])
	}
}

func TestExecuteBambuLANPrinterCommandLightOnPublishesSystemLEDPayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var capturedPayload map[string]any
	previousPublish := publishBambuMQTTRawFunc
	publishBambuMQTTRawFunc = func(_ context.Context, brokerAddr, topic, username, password string, payload []byte, insecureSkipVerify bool) error {
		if brokerAddr != "192.168.100.172:8883" {
			t.Fatalf("brokerAddr = %q, want 192.168.100.172:8883", brokerAddr)
		}
		if topic != "device/printer_1/request" {
			t.Fatalf("topic = %q, want device/printer_1/request", topic)
		}
		if username != "bblp" || password != "12345678" || !insecureSkipVerify {
			t.Fatalf("unexpected mqtt auth payload")
		}
		if err := json.Unmarshal(payload, &capturedPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		return nil
	}
	t.Cleanup(func() {
		publishBambuMQTTRawFunc = previousPublish
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, _ string, _ string, _ string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState: "idle",
			JobState:     "pending",
			CommandCapabilities: map[string]any{
				"led": map[string]any{"supported": true, "state": "on"},
			},
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	err = a.executeBambuLANPrinterCommand(
		context.Background(),
		action{PrinterID: 1, Kind: "light_on"},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeBambuLANPrinterCommand(light_on) failed: %v", err)
	}
	if _, ok := capturedPayload["system"]; !ok {
		t.Fatalf("payload = %#v, want system envelope", capturedPayload)
	}
	systemPayload := capturedPayload["system"].(map[string]any)
	if systemPayload["command"] != "ledctrl" {
		t.Fatalf("command = %v, want ledctrl", systemPayload["command"])
	}
	if systemPayload["led_node"] != "chamber_light" {
		t.Fatalf("led_node = %v, want chamber_light", systemPayload["led_node"])
	}
	if systemPayload["led_mode"] != "on" {
		t.Fatalf("led_mode = %v, want on", systemPayload["led_mode"])
	}
}

func TestExecuteBambuLANPrinterCommandLoadFilamentPublishesChangeFilamentPayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var capturedPayload map[string]any
	previousPublish := publishBambuMQTTRawFunc
	publishBambuMQTTRawFunc = func(_ context.Context, _, _, _, _ string, payload []byte, _ bool) error {
		if err := json.Unmarshal(payload, &capturedPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		return nil
	}
	t.Cleanup(func() {
		publishBambuMQTTRawFunc = previousPublish
	})

	err = a.executeBambuLANPrinterCommand(
		context.Background(),
		action{PrinterID: 1, Kind: "load_filament"},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeBambuLANPrinterCommand(load_filament) failed: %v", err)
	}
	printPayload, ok := capturedPayload["print"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want print envelope", capturedPayload)
	}
	if printPayload["command"] != "ams_change_filament" {
		t.Fatalf("command = %v, want ams_change_filament", printPayload["command"])
	}
	if printPayload["target"] != float64(255) {
		t.Fatalf("target = %v, want 255", printPayload["target"])
	}
}

func TestExecuteBambuLANPrinterCommandHomeAxesPublishesGCodeLinePayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var capturedPayload map[string]any
	previousPublish := publishBambuMQTTRawFunc
	publishBambuMQTTRawFunc = func(_ context.Context, _, _, _, _ string, payload []byte, _ bool) error {
		if err := json.Unmarshal(payload, &capturedPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		return nil
	}
	t.Cleanup(func() {
		publishBambuMQTTRawFunc = previousPublish
	})

	err = a.executeBambuLANPrinterCommand(
		context.Background(),
		action{PrinterID: 1, Kind: "home_axes", Payload: map[string]any{"axes": []any{"x", "y", "z"}}},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeBambuLANPrinterCommand(home_axes) failed: %v", err)
	}
	printPayload, ok := capturedPayload["print"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want print envelope", capturedPayload)
	}
	if printPayload["command"] != "gcode_line" {
		t.Fatalf("command = %v, want gcode_line", printPayload["command"])
	}
	if param := fmt.Sprint(printPayload["param"]); !strings.Contains(param, "G28") {
		t.Fatalf("param = %q, want G28", param)
	}
}

func TestExecuteBambuLANPrinterCommandSetFanEnabledPublishesGCodeLinePayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var capturedPayload map[string]any
	previousPublish := publishBambuMQTTRawFunc
	publishBambuMQTTRawFunc = func(_ context.Context, _, _, _, _ string, payload []byte, _ bool) error {
		if err := json.Unmarshal(payload, &capturedPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		return nil
	}
	t.Cleanup(func() {
		publishBambuMQTTRawFunc = previousPublish
	})

	err = a.executeBambuLANPrinterCommand(
		context.Background(),
		action{PrinterID: 1, Kind: "set_fan_enabled", Payload: map[string]any{"fan": "chamber", "enabled": true}},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeBambuLANPrinterCommand(set_fan_enabled) failed: %v", err)
	}
	printPayload, ok := capturedPayload["print"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want print envelope", capturedPayload)
	}
	if printPayload["command"] != "gcode_line" {
		t.Fatalf("command = %v, want gcode_line", printPayload["command"])
	}
	if param := fmt.Sprint(printPayload["param"]); !strings.Contains(param, "M106 P3 S255") {
		t.Fatalf("param = %q, want chamber fan M106 command", param)
	}
}

func TestExecuteBambuLANPrinterCommandJogMotionBatchPublishesOrderedGCodeLinePayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var capturedPayload map[string]any
	previousPublish := publishBambuMQTTRawFunc
	publishBambuMQTTRawFunc = func(_ context.Context, _, _, _, _ string, payload []byte, _ bool) error {
		if err := json.Unmarshal(payload, &capturedPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		return nil
	}
	t.Cleanup(func() {
		publishBambuMQTTRawFunc = previousPublish
	})

	err = a.executeBambuLANPrinterCommand(
		context.Background(),
		action{
			PrinterID: 1,
			Kind:      "jog_motion_batch",
			Payload: map[string]any{
				"steps": []any{
					map[string]any{"axis": "x", "distance_mm": 1},
					map[string]any{"axis": "y", "distance_mm": -1},
					map[string]any{"axis": "z", "distance_mm": 10},
				},
			},
		},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeBambuLANPrinterCommand(jog_motion_batch) failed: %v", err)
	}
	printPayload, ok := capturedPayload["print"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want print envelope", capturedPayload)
	}
	if printPayload["command"] != "gcode_line" {
		t.Fatalf("command = %v, want gcode_line", printPayload["command"])
	}
	param := fmt.Sprint(printPayload["param"])
	if !strings.Contains(param, "G91") || !strings.Contains(param, "G90") {
		t.Fatalf("param = %q, want relative/absolute motion wrapper", param)
	}
	expectedLines := []string{
		"G0 X1 F6000",
		"G0 Y-1 F6000",
		"G0 Z10 F300",
	}
	for _, line := range expectedLines {
		if !strings.Contains(param, line) {
			t.Fatalf("param = %q, want %q", param, line)
		}
	}
	if strings.Index(param, expectedLines[0]) > strings.Index(param, expectedLines[1]) || strings.Index(param, expectedLines[1]) > strings.Index(param, expectedLines[2]) {
		t.Fatalf("param = %q, want ordered jog lines", param)
	}
}

func TestExecuteBambuLANPrinterCommandSetNozzleTemperaturePublishesGCodeLinePayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var capturedPayload map[string]any
	previousPublish := publishBambuMQTTRawFunc
	publishBambuMQTTRawFunc = func(_ context.Context, _, _, _, _ string, payload []byte, _ bool) error {
		if err := json.Unmarshal(payload, &capturedPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		return nil
	}
	t.Cleanup(func() {
		publishBambuMQTTRawFunc = previousPublish
	})

	err = a.executeBambuLANPrinterCommand(
		context.Background(),
		action{PrinterID: 1, Kind: "set_nozzle_temperature", Payload: map[string]any{"target_c": 235}},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeBambuLANPrinterCommand(set_nozzle_temperature) failed: %v", err)
	}
	printPayload, ok := capturedPayload["print"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want print envelope", capturedPayload)
	}
	if printPayload["command"] != "gcode_line" {
		t.Fatalf("command = %v, want gcode_line", printPayload["command"])
	}
	if param := fmt.Sprint(printPayload["param"]); !strings.Contains(param, "M104 S235") {
		t.Fatalf("param = %q, want nozzle temperature M104 command", param)
	}
}

func TestExecuteBambuLANPrinterCommandSetBedTemperaturePublishesGCodeLinePayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var capturedPayload map[string]any
	previousPublish := publishBambuMQTTRawFunc
	publishBambuMQTTRawFunc = func(_ context.Context, _, _, _, _ string, payload []byte, _ bool) error {
		if err := json.Unmarshal(payload, &capturedPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		return nil
	}
	t.Cleanup(func() {
		publishBambuMQTTRawFunc = previousPublish
	})

	err = a.executeBambuLANPrinterCommand(
		context.Background(),
		action{PrinterID: 1, Kind: "set_bed_temperature", Payload: map[string]any{"target_c": 65}},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeBambuLANPrinterCommand(set_bed_temperature) failed: %v", err)
	}
	printPayload, ok := capturedPayload["print"].(map[string]any)
	if !ok {
		t.Fatalf("payload = %#v, want print envelope", capturedPayload)
	}
	if printPayload["command"] != "gcode_line" {
		t.Fatalf("command = %v, want gcode_line", printPayload["command"])
	}
	if param := fmt.Sprint(printPayload["param"]); !strings.Contains(param, "M140 S65") {
		t.Fatalf("param = %q, want bed temperature M140 command", param)
	}
}

func TestFetchBambuVerificationSnapshotByPrinterIDUsesLANRuntimeWhenCredentialsAvailable(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuConnectURI = "http://127.0.0.1:1"

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-verify",
		Host:       "192.168.100.175",
		AccessCode: "12345678",
		Name:       "Forge#2",
		Model:      "C12",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		if host != "192.168.100.175" {
			t.Fatalf("host = %q, want 192.168.100.175", host)
		}
		if printerID != "printer-lan-verify" {
			t.Fatalf("printerID = %q, want printer-lan-verify", printerID)
		}
		if accessCode != "12345678" {
			t.Fatalf("access code = %q, want 12345678", accessCode)
		}
		return bindingSnapshot{
			PrinterState:    "paused",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	snapshot, err := a.fetchBambuVerificationSnapshotByPrinterID(context.Background(), "printer-lan-verify")
	if err != nil {
		t.Fatalf("fetchBambuVerificationSnapshotByPrinterID failed: %v", err)
	}
	if snapshot.PrinterState != "paused" {
		t.Fatalf("printer state = %q, want paused", snapshot.PrinterState)
	}
	if snapshot.TelemetrySource != telemetrySourceBambuLANMQTT {
		t.Fatalf("telemetry source = %q, want %q", snapshot.TelemetrySource, telemetrySourceBambuLANMQTT)
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

func TestRunAndSubmitDiscoveryInventoryScanIncludesBambuLANDevices(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.cfg.DiscoveryAllowedAdapters = []string{"bambu"}
	a.cfg.DiscoveryProbeTimeout = 2 * time.Second
	previousDiscover := discoverBambuLANPrinters
	discoverBambuLANPrinters = func(_ context.Context, _ time.Duration, _ bambuLANDiscoveryOptions) (bambuLANDiscoveryResult, error) {
		return newTestBambuLANDiscoveryResult(
			bambuLANDiscoveryDevice{
				PrinterID:   "printer-online",
				Host:        "192.168.1.90",
				Name:        "Bambu Online",
				Model:       "X1C",
				ConnectMode: "lan",
				BindState:   "free",
			},
			bambuLANDiscoveryDevice{
				PrinterID: "printer-offline",
				Host:      "192.168.1.91",
				Name:      "Bambu Offline",
				Model:     "P1S",
			},
		), nil
	}
	t.Cleanup(func() {
		discoverBambuLANPrinters = previousDiscover
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
	onlineIP, ok := online.Evidence["ip_address"].(string)
	if !ok || onlineIP != "192.168.1.90" {
		t.Fatalf("online ip_address evidence = %v, want 192.168.1.90", online.Evidence["ip_address"])
	}
	if connectMode, _ := online.Evidence["dev_connect"].(string); connectMode != "lan" {
		t.Fatalf("online dev_connect evidence = %q, want lan", connectMode)
	}
	offline, ok := entriesByEndpoint["bambu://printer-offline"]
	if !ok {
		t.Fatalf("expected inventory entry for bambu://printer-offline")
	}
	if offline.Status != "reachable" {
		t.Fatalf("offline status = %q, want reachable", offline.Status)
	}
	if offline.CurrentPrinterState != "idle" {
		t.Fatalf("offline current_printer_state = %q, want idle", offline.CurrentPrinterState)
	}
	if offline.CurrentJobState != "pending" {
		t.Fatalf("offline current_job_state = %q, want pending", offline.CurrentJobState)
	}
	offlineIP, ok := offline.Evidence["ip_address"].(string)
	if !ok || offlineIP != "192.168.1.91" {
		t.Fatalf("offline ip_address evidence = %v, want 192.168.1.91", offline.Evidence["ip_address"])
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

	_, err := a.downloadArtifact(context.Background(), desiredStateItem{
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

	_, err := a.downloadArtifact(context.Background(), desiredStateItem{
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

	artifact, err := a.downloadArtifact(context.Background(), desiredStateItem{
		PrinterID:      1,
		PlateID:        99,
		ArtifactURL:    srv.URL,
		ChecksumSHA256: "",
	})
	if err != nil {
		t.Fatalf("expected download to succeed without checksum, got: %v", err)
	}
	defer a.cleanupArtifact(artifact.LocalPath)

	data, readErr := os.ReadFile(artifact.LocalPath)
	if readErr != nil {
		t.Fatalf("failed to read staged artifact: %v", readErr)
	}
	if string(data) != string(content) {
		t.Fatalf("staged artifact content mismatch")
	}
}

func TestResolvePlateArtifactExtension(t *testing.T) {
	tests := []struct {
		name               string
		artifactURL        string
		contentDisposition string
		want               string
	}{
		{
			name:               "content disposition filename wins",
			artifactURL:        "https://example.invalid/edge/artifacts/42",
			contentDisposition: `attachment; filename="plate.3mf"`,
			want:               ".3mf",
		},
		{
			name:               "content disposition preserves gcode 3mf suffix",
			artifactURL:        "https://example.invalid/edge/artifacts/42",
			contentDisposition: `attachment; filename="plate.gcode.3mf"`,
			want:               ".gcode.3mf",
		},
		{
			name:               "url path extension fallback",
			artifactURL:        "https://example.invalid/uploads/plate.gc",
			contentDisposition: "",
			want:               ".gc",
		},
		{
			name:               "query filename fallback",
			artifactURL:        "https://example.invalid/download?filename=plate.ngc",
			contentDisposition: "",
			want:               ".ngc",
		},
		{
			name:               "query filename keeps compound suffix",
			artifactURL:        "https://example.invalid/download?filename=plate.gcode.3mf",
			contentDisposition: "",
			want:               ".gcode.3mf",
		},
		{
			name:               "unsupported extension defaults to gcode",
			artifactURL:        "https://example.invalid/uploads/plate.txt",
			contentDisposition: "",
			want:               ".gcode",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolvePlateArtifactExtension(tc.artifactURL, tc.contentDisposition)
			if got != tc.want {
				t.Fatalf("resolvePlateArtifactExtension() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDownloadArtifactUsesContentDispositionExtension(t *testing.T) {
	a := newTestAgent(t)
	content := []byte("3mf payload")
	sum := sha256.Sum256(content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="plate.gcode.3mf"`)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	artifact, err := a.downloadArtifact(context.Background(), desiredStateItem{
		PrinterID:      1,
		PlateID:        99,
		ArtifactURL:    srv.URL,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatalf("downloadArtifact failed: %v", err)
	}
	defer a.cleanupArtifact(artifact.LocalPath)

	if artifact.SourceFilename != "plate.gcode.3mf" {
		t.Fatalf("source filename = %q, want plate.gcode.3mf", artifact.SourceFilename)
	}
	if artifact.NormalizedExtension != ".gcode.3mf" {
		t.Fatalf("normalized extension = %q, want .gcode.3mf", artifact.NormalizedExtension)
	}
	wantRemoteName := "pfh-" + hex.EncodeToString(sum[:]) + ".gcode.3mf"
	if artifact.RemoteName != wantRemoteName {
		t.Fatalf("remoteName = %q, want %q", artifact.RemoteName, wantRemoteName)
	}
	if !strings.HasSuffix(filepath.Base(artifact.LocalPath), ".gcode.3mf.ready") {
		t.Fatalf("readyPath = %q, want .gcode.3mf.ready suffix", artifact.LocalPath)
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

	artifact, err := a.downloadArtifact(context.Background(), desiredStateItem{
		PrinterID:      1,
		PlateID:        42,
		ArtifactURL:    "/edge/artifacts/plates/42",
		ChecksumSHA256: "",
	})
	if err != nil {
		t.Fatalf("downloadArtifact failed: %v", err)
	}
	defer a.cleanupArtifact(artifact.LocalPath)

	data, readErr := os.ReadFile(artifact.LocalPath)
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
		mu               sync.Mutex
		uploadCalls      int
		startCalls       int
		uploadedData     []byte
		uploadedChecksum string
		uploadedFilename string
	)
	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/files/upload":
			uploadCalls++
			if err := r.ParseMultipartForm(2 << 20); err != nil {
				t.Fatalf("parse multipart form failed: %v", err)
			}
			file, header, err := r.FormFile("file")
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
			uploadedChecksum = r.FormValue("checksum")
			uploadedFilename = header.Filename
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
	if uploadedChecksum != hex.EncodeToString(checksum[:]) {
		t.Fatalf("uploaded checksum = %q, want %q", uploadedChecksum, hex.EncodeToString(checksum[:]))
	}
	if uploadedFilename != "pfh-"+hex.EncodeToString(checksum[:])+".gcode" {
		t.Fatalf("uploaded filename = %q, want canonical checksum filename", uploadedFilename)
	}
}

func TestExecutePrintActionReusesExistingMoonrakerArtifact(t *testing.T) {
	a := newTestAgent(t)
	artifact := []byte("G1 X20 Y20\n")
	checksum := sha256.Sum256(artifact)
	expectedRemoteName := "pfh-" + hex.EncodeToString(checksum[:]) + ".gcode"

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	var (
		metadataCalls int
		downloadCalls int
		uploadCalls   int
		startCalls    int
	)
	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/files/metadata":
			metadataCalls++
			if got := r.URL.Query().Get("filename"); got != expectedRemoteName {
				t.Fatalf("metadata filename = %q, want %q", got, expectedRemoteName)
			}
			writeJSON(w, http.StatusOK, map[string]any{"result": map[string]any{"size": len(artifact)}})
		case "/server/files/gcodes/" + expectedRemoteName:
			downloadCalls++
			_, _ = w.Write(artifact)
		case "/server/files/upload":
			uploadCalls++
			t.Fatalf("moonraker upload should be skipped when remote artifact matches")
		case "/printer/print/start":
			startCalls++
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode print start payload failed: %v", err)
			}
			if payload["filename"] != expectedRemoteName {
				t.Fatalf("start filename = %q, want %q", payload["filename"], expectedRemoteName)
			}
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
			PlateID:             8,
			IntentVersion:       10,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			ArtifactURL:         artifactSrv.URL + "/plate.gcode",
			ChecksumSHA256:      hex.EncodeToString(checksum[:]),
		},
	}

	if err := a.executeAction(context.Background(), act, edgeBinding{PrinterID: 1, EndpointURL: moonrakerSrv.URL}); err != nil {
		t.Fatalf("executeAction(print) failed: %v", err)
	}
	if metadataCalls != 1 {
		t.Fatalf("metadata calls = %d, want 1", metadataCalls)
	}
	if downloadCalls != 1 {
		t.Fatalf("download calls = %d, want 1", downloadCalls)
	}
	if uploadCalls != 0 {
		t.Fatalf("upload calls = %d, want 0", uploadCalls)
	}
	if startCalls != 1 {
		t.Fatalf("start calls = %d, want 1", startCalls)
	}
}

func TestExecutePrintActionUploadsWhenMoonrakerRemoteArtifactDiffers(t *testing.T) {
	a := newTestAgent(t)
	localArtifact := []byte("G1 X30 Y30\n")
	remoteArtifact := []byte("G1 X99 Y99\n")
	checksum := sha256.Sum256(localArtifact)
	expectedRemoteName := "pfh-" + hex.EncodeToString(checksum[:]) + ".gcode"

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(localArtifact)
	}))
	defer artifactSrv.Close()

	var uploadCalls int
	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/files/metadata":
			writeJSON(w, http.StatusOK, map[string]any{"result": map[string]any{"size": len(localArtifact)}})
		case "/server/files/gcodes/" + expectedRemoteName:
			_, _ = w.Write(remoteArtifact)
		case "/server/files/upload":
			uploadCalls++
			w.WriteHeader(http.StatusOK)
		case "/printer/print/start":
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
			PlateID:             9,
			IntentVersion:       11,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			ArtifactURL:         artifactSrv.URL + "/plate.gcode",
			ChecksumSHA256:      hex.EncodeToString(checksum[:]),
		},
	}

	if err := a.executeAction(context.Background(), act, edgeBinding{PrinterID: 1, EndpointURL: moonrakerSrv.URL}); err != nil {
		t.Fatalf("executeAction(print) failed: %v", err)
	}
	if uploadCalls != 1 {
		t.Fatalf("upload calls = %d, want 1", uploadCalls)
	}
}

func TestExecutePrintActionFallsBackToUploadWhenMoonrakerProbeFails(t *testing.T) {
	a := newTestAgent(t)
	artifact := []byte("G1 X40 Y40\n")
	checksum := sha256.Sum256(artifact)

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	var uploadCalls int
	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/files/metadata":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "/server/files/upload":
			uploadCalls++
			w.WriteHeader(http.StatusOK)
		case "/printer/print/start":
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
			PlateID:             10,
			IntentVersion:       12,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			ArtifactURL:         artifactSrv.URL + "/plate.gcode",
			ChecksumSHA256:      hex.EncodeToString(checksum[:]),
		},
	}

	if err := a.executeAction(context.Background(), act, edgeBinding{PrinterID: 1, EndpointURL: moonrakerSrv.URL}); err != nil {
		t.Fatalf("executeAction(print) failed: %v", err)
	}
	if uploadCalls != 1 {
		t.Fatalf("upload calls = %d, want 1", uploadCalls)
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

func TestExecuteBambuConnectPrintActionUsesBambuConnectURIHandoff(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	artifact := []byte("G1 X11 Y11\n")
	sum := sha256.Sum256(artifact)

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	connectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/printers/printer_1/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"printer_id":"printer_1","printer_state":"printing","job_state":"printing","printer_name":"Forge #2","model":"P1S"}`))
	}))
	defer connectSrv.Close()
	a.cfg.BambuConnectURI = connectSrv.URL

	var (
		gotCommand string
		gotArgs    []string
	)
	previousRunExternalCommand := runExternalCommand
	runExternalCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		gotCommand = name
		gotArgs = append([]string(nil), args...)
		return nil, nil
	}
	t.Cleanup(func() {
		runExternalCommand = previousRunExternalCommand
	})

	err := a.executeBambuConnectPrintAction(
		context.Background(),
		action{
			PrinterID: 1,
			Kind:      "print",
			Target: desiredStateItem{
				PrinterID:           1,
				PlateID:             22,
				IntentVersion:       7,
				DesiredPrinterState: "printing",
				DesiredJobState:     "printing",
				ArtifactURL:         artifactSrv.URL,
				ChecksumSHA256:      hex.EncodeToString(sum[:]),
			},
		},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("expected bambu print action success, got %v", err)
	}
	if gotCommand != "open" && gotCommand != "xdg-open" && gotCommand != "rundll32" {
		t.Fatalf("unexpected launcher command %q", gotCommand)
	}
	if len(gotArgs) == 0 {
		t.Fatalf("expected launcher arguments")
	}
	dispatchURI := gotArgs[len(gotArgs)-1]
	if !strings.HasPrefix(dispatchURI, "bambu-connect://import-file?path=") {
		t.Fatalf("unexpected dispatch uri %q", dispatchURI)
	}
}

func TestExecuteBambuConnectPrintActionFailsFastWhenBambuConnectUnavailable(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuConnectURI = "http://127.0.0.1:1"
	artifact := []byte("G1 X12 Y12\n")
	sum := sha256.Sum256(artifact)

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	previousRunExternalCommand := runExternalCommand
	runExternalCommand = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("launcher failed"), errors.New("exit status 1")
	}
	t.Cleanup(func() {
		runExternalCommand = previousRunExternalCommand
	})

	err := a.executeBambuConnectPrintAction(
		context.Background(),
		action{
			PrinterID: 1,
			Kind:      "print",
			Target: desiredStateItem{
				PrinterID:           1,
				PlateID:             22,
				IntentVersion:       8,
				DesiredPrinterState: "printing",
				DesiredJobState:     "printing",
				ArtifactURL:         artifactSrv.URL,
				ChecksumSHA256:      hex.EncodeToString(sum[:]),
			},
		},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err == nil {
		t.Fatalf("expected bambu print action to fail when bambu connect is unavailable")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "bambu_connect_dispatch_failed") {
		t.Fatalf("error = %v, want bambu_connect_dispatch_failed", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "launch") {
		t.Fatalf("error = %v, want launcher failure details", err)
	}
}

func TestExecuteActionBambuPrintUsesLANStartWhenCredentialsAvailable(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuConnectURI = ""
	artifact := []byte("3mf-bytes")
	sum := sha256.Sum256(artifact)

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
		Name:       "Forge#1",
		Model:      "C12",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	var (
		gotUploadRemoteName string
		gotUploadBytes      []byte
		gotProjectReq       bambuLANProjectFileRequest
	)
	previousUpload := uploadBambuLANArtifact
	uploadBambuLANArtifact = func(_ context.Context, credentials bambustore.BambuLANCredentials, remoteName string, fileBytes []byte) error {
		if credentials.Serial != "printer_1" {
			t.Fatalf("upload credentials serial = %q, want printer_1", credentials.Serial)
		}
		gotUploadRemoteName = remoteName
		gotUploadBytes = append([]byte(nil), fileBytes...)
		return nil
	}
	t.Cleanup(func() {
		uploadBambuLANArtifact = previousUpload
	})

	previousDispatch := dispatchBambuLANProjectFile
	dispatchBambuLANProjectFile = func(_ context.Context, credentials bambustore.BambuLANCredentials, req bambuLANProjectFileRequest) error {
		if credentials.Host != "192.168.100.172" {
			t.Fatalf("dispatch host = %q, want 192.168.100.172", credentials.Host)
		}
		gotProjectReq = req
		return nil
	}
	t.Cleanup(func() {
		dispatchBambuLANProjectFile = previousDispatch
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		if host != "192.168.100.172" {
			t.Fatalf("verify host = %q, want 192.168.100.172", host)
		}
		if printerID != "printer_1" {
			t.Fatalf("verify printerID = %q, want printer_1", printerID)
		}
		if accessCode != "12345678" {
			t.Fatalf("verify access code = %q, want 12345678", accessCode)
		}
		return bindingSnapshot{
			PrinterState:    "printing",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	err = a.executeAction(
		context.Background(),
		action{
			PrinterID: 1,
			Kind:      "print",
			Target: desiredStateItem{
				PrinterID:           1,
				PlateID:             23,
				IntentVersion:       9,
				DesiredPrinterState: "printing",
				DesiredJobState:     "printing",
				ArtifactURL:         artifactSrv.URL + "/plate.3mf",
				ChecksumSHA256:      hex.EncodeToString(sum[:]),
			},
		},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("expected bambu print action success via LAN path, got %v", err)
	}
	if gotUploadRemoteName == "" || !strings.HasSuffix(gotUploadRemoteName, ".gcode.3mf") {
		t.Fatalf("upload remote name = %q, want .gcode.3mf name", gotUploadRemoteName)
	}
	if string(gotUploadBytes) != string(artifact) {
		t.Fatalf("uploaded bytes mismatch")
	}
	if gotProjectReq.RemoteName != gotUploadRemoteName {
		t.Fatalf("project remote name = %q, want %q", gotProjectReq.RemoteName, gotUploadRemoteName)
	}
	if gotProjectReq.ProjectPath != "Metadata/plate_1.gcode" {
		t.Fatalf("project path = %q, want Metadata/plate_1.gcode", gotProjectReq.ProjectPath)
	}
	if gotProjectReq.FileMD5 == "" {
		t.Fatalf("expected project file md5")
	}
}

func TestRequestBambuLANCredentialRecoveryUsesAuthenticatedBoundRequest(t *testing.T) {
	a := newTestAgent(t)
	var (
		gotAuthHeader   string
		gotSchemaHeader string
		gotPayload      bambuCredentialRecoveryRequest
		callCount       int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		gotAuthHeader = r.Header.Get("Authorization")
		gotSchemaHeader = r.Header.Get("X-Agent-Schema-Version")
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/edge/agents/agent-1/bambu-credentials/recover" {
			t.Fatalf("path = %s, want /edge/agents/agent-1/bambu-credentials/recover", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload failed: %v", err)
		}
		_ = json.NewEncoder(w).Encode(bambuCredentialRecoveryResponse{
			Accepted:       true,
			RecoveryQueued: true,
			PrinterID:      22,
			AgentID:        "agent-1",
			EndpointURL:    "bambu://serial-1",
			CommandID:      9,
		})
	}))
	defer srv.Close()
	a.client = srv.Client()
	a.mu.Lock()
	a.claimed = true
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: srv.URL,
		SaaSAPIKey:      "pfh_edge_test",
		AgentID:         "agent-1",
	}
	a.mu.Unlock()

	queued, err := a.requestBambuLANCredentialRecovery(context.Background(), edgeBinding{
		PrinterID:     22,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://serial-1",
	})
	if err != nil {
		t.Fatalf("requestBambuLANCredentialRecovery failed: %v", err)
	}
	if !queued {
		t.Fatalf("expected recovery to be queued")
	}
	if callCount != 1 {
		t.Fatalf("call count = %d, want 1", callCount)
	}
	if gotAuthHeader != "Bearer pfh_edge_test" {
		t.Fatalf("Authorization = %q, want bearer api key", gotAuthHeader)
	}
	if gotSchemaHeader != schemaVersionHeaderValue() {
		t.Fatalf("X-Agent-Schema-Version = %q, want %q", gotSchemaHeader, schemaVersionHeaderValue())
	}
	if gotPayload.PrinterID != 22 {
		t.Fatalf("printer_id = %d, want 22", gotPayload.PrinterID)
	}
	if gotPayload.EndpointURL != "bambu://serial-1" {
		t.Fatalf("endpoint_url = %q, want bambu://serial-1", gotPayload.EndpointURL)
	}

	queued, err = a.requestBambuLANCredentialRecovery(context.Background(), edgeBinding{
		PrinterID:     22,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://serial-1",
	})
	if err != nil {
		t.Fatalf("second requestBambuLANCredentialRecovery failed: %v", err)
	}
	if queued {
		t.Fatalf("expected second recovery request to be suppressed by cooldown")
	}
	if callCount != 1 {
		t.Fatalf("call count after cooldown suppression = %d, want 1", callCount)
	}
}

func TestExecuteActionBambuPrintRequestsCredentialRecoveryWhenLocalCredentialsMissing(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path != "/edge/agents/agent-1/bambu-credentials/recover" {
			t.Fatalf("path = %s, want /edge/agents/agent-1/bambu-credentials/recover", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(bambuCredentialRecoveryResponse{
			Accepted:       true,
			RecoveryQueued: true,
			PrinterID:      1,
			AgentID:        "agent-1",
			EndpointURL:    "bambu://printer_1",
			CommandID:      11,
		})
	}))
	defer srv.Close()
	a.client = srv.Client()
	a.mu.Lock()
	a.claimed = true
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: srv.URL,
		SaaSAPIKey:      "pfh_edge_test",
		AgentID:         "agent-1",
	}
	a.mu.Unlock()

	err := a.executeAction(
		context.Background(),
		action{
			PrinterID: 1,
			Kind:      "print",
			Target: desiredStateItem{
				PrinterID:           1,
				PlateID:             24,
				IntentVersion:       10,
				DesiredPrinterState: "printing",
				DesiredJobState:     "printing",
			},
		},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err == nil {
		t.Fatalf("expected missing bambu lan credentials to fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "recovery requested") {
		t.Fatalf("error = %v, want recovery requested guidance", err)
	}
	if callCount != 1 {
		t.Fatalf("recovery request count = %d, want 1", callCount)
	}
}

func TestExecuteBambuLANPrintActionMarksQueuedBeforeVerificationCompletes(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	artifact := []byte("3mf-bytes")
	sum := sha256.Sum256(artifact)
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	previousUpload := uploadBambuLANArtifact
	uploadBambuLANArtifact = func(_ context.Context, _ bambustore.BambuLANCredentials, _ string, _ []byte) error {
		return nil
	}
	t.Cleanup(func() {
		uploadBambuLANArtifact = previousUpload
	})

	previousDispatch := dispatchBambuLANProjectFile
	dispatchBambuLANProjectFile = func(_ context.Context, _ bambustore.BambuLANCredentials, _ bambuLANProjectFileRequest) error {
		return nil
	}
	t.Cleanup(func() {
		dispatchBambuLANProjectFile = previousDispatch
	})

	verificationStarted := make(chan struct{}, 1)
	releaseVerification := make(chan struct{})
	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, _ string, _ string, _ string) (bindingSnapshot, error) {
		select {
		case verificationStarted <- struct{}{}:
		default:
		}
		<-releaseVerification
		return bindingSnapshot{
			PrinterState:    "printing",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	queuedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			PlateID:             23,
			IntentVersion:       9,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			JobID:               "job-123",
			ArtifactURL:         artifactSrv.URL + "/plate.3mf",
			ChecksumSHA256:      hex.EncodeToString(sum[:]),
		},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- a.executeBambuLANPrintAction(
			context.Background(),
			queuedAction,
			edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
		)
	}()

	select {
	case <-verificationStarted:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for verification to start")
	}

	current := a.currentState[1]
	if current.CurrentPrinterState != "queued" {
		t.Fatalf("current_printer_state = %q, want queued", current.CurrentPrinterState)
	}
	if current.CurrentJobState != "pending" {
		t.Fatalf("current_job_state = %q, want pending", current.CurrentJobState)
	}
	if current.JobID != "job-123" {
		t.Fatalf("job_id = %q, want job-123", current.JobID)
	}
	if current.PlateID != 23 {
		t.Fatalf("plate_id = %d, want 23", current.PlateID)
	}

	close(releaseVerification)
	if err := <-errCh; err != nil {
		t.Fatalf("executeBambuLANPrintAction failed: %v", err)
	}
}

func TestDefaultProbeBambuLANArtifactReusesMatchingRemoteFile(t *testing.T) {
	artifactBytes := []byte("3mf-bytes")
	md5Sum := md5.Sum(artifactBytes)
	fakeClient := &fakeBambuLANArtifactClient{
		sizeValue:    int64(len(artifactBytes)),
		retrieveData: artifactBytes,
	}

	previousDial := dialBambuLANArtifactClient
	dialBambuLANArtifactClient = func(context.Context, string) (bambuLANArtifactClient, error) {
		return fakeClient, nil
	}
	t.Cleanup(func() {
		dialBambuLANArtifactClient = previousDial
	})

	reused, reason, err := defaultProbeBambuLANArtifact(
		context.Background(),
		bambustore.BambuLANCredentials{Host: "192.168.0.10", AccessCode: "12345678"},
		"pfh-test.gcode.3mf",
		stagedArtifact{
			SizeBytes: int64(len(artifactBytes)),
			MD5:       hex.EncodeToString(md5Sum[:]),
		},
	)
	if err != nil {
		t.Fatalf("defaultProbeBambuLANArtifact failed: %v", err)
	}
	if !reused {
		t.Fatalf("expected probe to reuse matching remote artifact")
	}
	if reason != "md5_match" {
		t.Fatalf("reason = %q, want md5_match", reason)
	}
	if len(fakeClient.retrievedRemoteNames) != 1 || fakeClient.retrievedRemoteNames[0] != "pfh-test.gcode.3mf" {
		t.Fatalf("retrieved remote names = %#v, want probe target", fakeClient.retrievedRemoteNames)
	}
}

func TestDefaultUploadBambuLANArtifactDeletesThenRetriesOnOverwrite(t *testing.T) {
	fakeClient := &fakeBambuLANArtifactClient{
		storeErrs: []error{
			&bambuLANFTPSResponseError{Command: "STOR pfh-test.gcode.3mf", Code: 553, Message: "file exists"},
		},
	}

	previousDial := dialBambuLANArtifactClient
	dialBambuLANArtifactClient = func(context.Context, string) (bambuLANArtifactClient, error) {
		return fakeClient, nil
	}
	t.Cleanup(func() {
		dialBambuLANArtifactClient = previousDial
	})

	err := defaultUploadBambuLANArtifact(
		context.Background(),
		bambustore.BambuLANCredentials{Host: "192.168.0.10", AccessCode: "12345678"},
		"pfh-test.gcode.3mf",
		[]byte("3mf-bytes"),
	)
	if err != nil {
		t.Fatalf("defaultUploadBambuLANArtifact failed: %v", err)
	}
	if len(fakeClient.storedRemoteNames) != 2 {
		t.Fatalf("store calls = %d, want 2", len(fakeClient.storedRemoteNames))
	}
	if len(fakeClient.deletedRemoteNames) != 1 || fakeClient.deletedRemoteNames[0] != "pfh-test.gcode.3mf" {
		t.Fatalf("deleted remote names = %#v, want overwrite delete", fakeClient.deletedRemoteNames)
	}
}

func TestExecuteBambuLANPrintActionReusesExistingArtifact(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	artifact := []byte("3mf-bytes")
	sum := sha256.Sum256(artifact)
	md5Sum := md5.Sum(artifact)
	expectedRemoteName := "pfh-" + hex.EncodeToString(sum[:]) + ".gcode.3mf"
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	previousProbe := probeBambuLANArtifact
	probeBambuLANArtifact = func(_ context.Context, _ bambustore.BambuLANCredentials, remoteName string, artifact stagedArtifact) (bool, string, error) {
		if remoteName != expectedRemoteName {
			t.Fatalf("probe remoteName = %q, want %q", remoteName, expectedRemoteName)
		}
		if artifact.MD5 != hex.EncodeToString(md5Sum[:]) {
			t.Fatalf("artifact md5 = %q, want %q", artifact.MD5, hex.EncodeToString(md5Sum[:]))
		}
		return true, "md5_match", nil
	}
	t.Cleanup(func() {
		probeBambuLANArtifact = previousProbe
	})

	var uploadCalls int
	previousUpload := uploadBambuLANArtifact
	uploadBambuLANArtifact = func(_ context.Context, _ bambustore.BambuLANCredentials, _ string, _ []byte) error {
		uploadCalls++
		return nil
	}
	t.Cleanup(func() {
		uploadBambuLANArtifact = previousUpload
	})

	var dispatched bambuLANProjectFileRequest
	previousDispatch := dispatchBambuLANProjectFile
	dispatchBambuLANProjectFile = func(_ context.Context, _ bambustore.BambuLANCredentials, req bambuLANProjectFileRequest) error {
		dispatched = req
		return nil
	}
	t.Cleanup(func() {
		dispatchBambuLANProjectFile = previousDispatch
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, _ string, _ string, _ string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState:    "printing",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	queuedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			PlateID:             26,
			IntentVersion:       12,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			JobID:               "job-456",
			ArtifactURL:         artifactSrv.URL + "/plate.3mf",
			ChecksumSHA256:      hex.EncodeToString(sum[:]),
		},
	}

	if err := a.executeBambuLANPrintAction(
		context.Background(),
		queuedAction,
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	); err != nil {
		t.Fatalf("executeBambuLANPrintAction failed: %v", err)
	}
	if uploadCalls != 0 {
		t.Fatalf("upload calls = %d, want 0", uploadCalls)
	}
	if dispatched.RemoteName != expectedRemoteName {
		t.Fatalf("dispatch remote name = %q, want %q", dispatched.RemoteName, expectedRemoteName)
	}
	if dispatched.FileMD5 != strings.ToUpper(hex.EncodeToString(md5Sum[:])) {
		t.Fatalf("dispatch file md5 = %q, want uppercase MD5", dispatched.FileMD5)
	}
}

func TestExecuteBambuLANPrintActionUploadsOnProbeMismatch(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	artifact := []byte("3mf-bytes")
	sum := sha256.Sum256(artifact)
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	previousProbe := probeBambuLANArtifact
	probeBambuLANArtifact = func(context.Context, bambustore.BambuLANCredentials, string, stagedArtifact) (bool, string, error) {
		return false, "md5_mismatch", nil
	}
	t.Cleanup(func() {
		probeBambuLANArtifact = previousProbe
	})

	var uploadCalls int
	previousUpload := uploadBambuLANArtifact
	uploadBambuLANArtifact = func(_ context.Context, _ bambustore.BambuLANCredentials, _ string, _ []byte) error {
		uploadCalls++
		return nil
	}
	t.Cleanup(func() {
		uploadBambuLANArtifact = previousUpload
	})

	previousDispatch := dispatchBambuLANProjectFile
	dispatchBambuLANProjectFile = func(_ context.Context, _ bambustore.BambuLANCredentials, _ bambuLANProjectFileRequest) error {
		return nil
	}
	t.Cleanup(func() {
		dispatchBambuLANProjectFile = previousDispatch
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, _ string, _ string, _ string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState:    "printing",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	queuedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			PlateID:             27,
			IntentVersion:       13,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			JobID:               "job-789",
			ArtifactURL:         artifactSrv.URL + "/plate.3mf",
			ChecksumSHA256:      hex.EncodeToString(sum[:]),
		},
	}

	if err := a.executeBambuLANPrintAction(
		context.Background(),
		queuedAction,
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	); err != nil {
		t.Fatalf("executeBambuLANPrintAction failed: %v", err)
	}
	if uploadCalls != 1 {
		t.Fatalf("upload calls = %d, want 1", uploadCalls)
	}
}

func TestExecuteBambuLANPrintActionFallsBackToUploadOnProbeError(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	artifact := []byte("3mf-bytes")
	sum := sha256.Sum256(artifact)
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	previousProbe := probeBambuLANArtifact
	probeBambuLANArtifact = func(context.Context, bambustore.BambuLANCredentials, string, stagedArtifact) (bool, string, error) {
		return false, "size_probe_error", errors.New("probe timeout")
	}
	t.Cleanup(func() {
		probeBambuLANArtifact = previousProbe
	})

	var uploadCalls int
	previousUpload := uploadBambuLANArtifact
	uploadBambuLANArtifact = func(_ context.Context, _ bambustore.BambuLANCredentials, _ string, _ []byte) error {
		uploadCalls++
		return nil
	}
	t.Cleanup(func() {
		uploadBambuLANArtifact = previousUpload
	})

	previousDispatch := dispatchBambuLANProjectFile
	dispatchBambuLANProjectFile = func(_ context.Context, _ bambustore.BambuLANCredentials, _ bambuLANProjectFileRequest) error {
		return nil
	}
	t.Cleanup(func() {
		dispatchBambuLANProjectFile = previousDispatch
	})

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, _ string, _ string, _ string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState:    "printing",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	queuedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			PlateID:             28,
			IntentVersion:       14,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			JobID:               "job-999",
			ArtifactURL:         artifactSrv.URL + "/plate.3mf",
			ChecksumSHA256:      hex.EncodeToString(sum[:]),
		},
	}

	if err := a.executeBambuLANPrintAction(
		context.Background(),
		queuedAction,
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	); err != nil {
		t.Fatalf("executeBambuLANPrintAction failed: %v", err)
	}
	if uploadCalls != 1 {
		t.Fatalf("upload calls = %d, want 1", uploadCalls)
	}
}

func TestExecuteActionBambuPrintRejectsMissingLANCredentials(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	err := a.executeAction(
		context.Background(),
		action{
			PrinterID: 1,
			Kind:      "print",
			Target: desiredStateItem{
				PrinterID:           1,
				PlateID:             24,
				IntentVersion:       10,
				DesiredPrinterState: "printing",
				DesiredJobState:     "printing",
			},
		},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err == nil {
		t.Fatalf("expected missing bambu lan credentials to fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "bambu_lan_credentials_missing_local") {
		t.Fatalf("error = %v, want bambu_lan_credentials_missing_local", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "recovery") {
		t.Fatalf("error = %v, want recovery guidance", err)
	}
}

func TestExecuteActionBambuPrintRejectsNon3MFArtifact(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	artifact := []byte("G1 X13 Y13\n")
	sum := sha256.Sum256(artifact)

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	err = a.executeAction(
		context.Background(),
		action{
			PrinterID: 1,
			Kind:      "print",
			Target: desiredStateItem{
				PrinterID:           1,
				PlateID:             25,
				IntentVersion:       11,
				DesiredPrinterState: "printing",
				DesiredJobState:     "printing",
				ArtifactURL:         artifactSrv.URL + "/plate.gcode",
				ChecksumSHA256:      hex.EncodeToString(sum[:]),
			},
		},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err == nil {
		t.Fatalf("expected non-3mf bambu print action to fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), ".3mf") {
		t.Fatalf("error = %v, want .3mf guidance", err)
	}
}

func TestBuildBambuConnectImportURIEncodesPayload(t *testing.T) {
	dispatchURI := buildBambuConnectImportURI("/tmp/my plate.3mf", "my plate.3mf")
	if !strings.HasPrefix(dispatchURI, "bambu-connect://import-file?path=") {
		t.Fatalf("unexpected dispatch uri %q", dispatchURI)
	}
	parts := strings.SplitN(dispatchURI, "path=", 2)
	if len(parts) != 2 {
		t.Fatalf("expected path query in dispatch uri %q", dispatchURI)
	}
	inner, err := url.QueryUnescape(parts[1])
	if err != nil {
		t.Fatalf("failed to decode path query: %v", err)
	}
	if !strings.HasPrefix(inner, "?") {
		t.Fatalf("decoded inner payload = %q, want query string", inner)
	}
	values, err := url.ParseQuery(strings.TrimPrefix(inner, "?"))
	if err != nil {
		t.Fatalf("failed to parse inner query: %v", err)
	}
	if values.Get("version") != "v1.0.0" {
		t.Fatalf("version = %q, want v1.0.0", values.Get("version"))
	}
	if values.Get("path") != "/tmp/my plate.3mf" {
		t.Fatalf("path = %q, want /tmp/my plate.3mf", values.Get("path"))
	}
	if values.Get("name") != "my plate.3mf" {
		t.Fatalf("name = %q, want my plate.3mf", values.Get("name"))
	}
	if values.Get("fileName") != "my plate.3mf" {
		t.Fatalf("fileName = %q, want my plate.3mf", values.Get("fileName"))
	}
}

func TestBuildBambuLANProjectFilePayloadUsesFixedDefaults(t *testing.T) {
	payload := buildBambuLANProjectFilePayload(bambuLANProjectFileRequest{
		RemoteName:  "plate.gcode.3mf",
		FileMD5:     "ABC123",
		ProjectPath: "Metadata/plate_1.gcode",
	})

	if payload["command"] != "project_file" {
		t.Fatalf("command = %v, want project_file", payload["command"])
	}
	if payload["param"] != "Metadata/plate_1.gcode" {
		t.Fatalf("param = %v, want Metadata/plate_1.gcode", payload["param"])
	}
	if payload["url"] != "ftp:///plate.gcode.3mf" {
		t.Fatalf("url = %v, want ftp:///plate.gcode.3mf", payload["url"])
	}
	if payload["use_ams"] != false {
		t.Fatalf("use_ams = %v, want false", payload["use_ams"])
	}
	if payload["flow_cali"] != false {
		t.Fatalf("flow_cali = %v, want false", payload["flow_cali"])
	}
	if payload["layer_inspect"] != true {
		t.Fatalf("layer_inspect = %v, want true", payload["layer_inspect"])
	}
	if payload["plate_idx"] != bambuLANProjectFilePlateIdx {
		t.Fatalf("plate_idx = %v, want %d", payload["plate_idx"], bambuLANProjectFilePlateIdx)
	}
	if payload["project_id"] != "0" || payload["profile_id"] != "0" || payload["task_id"] != "0" || payload["subtask_id"] != "0" {
		t.Fatalf("expected zeroed ids, got project_id=%v profile_id=%v task_id=%v subtask_id=%v", payload["project_id"], payload["profile_id"], payload["task_id"], payload["subtask_id"])
	}
	if payload["ams_mapping"] != "" {
		t.Fatalf("ams_mapping = %v, want empty string", payload["ams_mapping"])
	}
	if payload["md5"] != "ABC123" {
		t.Fatalf("md5 = %v, want ABC123", payload["md5"])
	}
}

func TestPrepareBambuConnectImportPathRenamesReadyFile(t *testing.T) {
	stageDir := t.TempDir()
	readyPath := filepath.Join(stageDir, "printer_1_plate_1_1.3mf.ready")
	if err := os.WriteFile(readyPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write ready artifact failed: %v", err)
	}

	importPath, err := prepareBambuConnectImportPath(readyPath, "printer_1_plate_1_1.3mf")
	if err != nil {
		t.Fatalf("prepareBambuConnectImportPath failed: %v", err)
	}
	if strings.HasSuffix(importPath, ".ready") {
		t.Fatalf("importPath = %q, expected non-.ready path", importPath)
	}
	if _, statErr := os.Stat(importPath); statErr != nil {
		t.Fatalf("expected import path to exist, stat err: %v", statErr)
	}
	if _, statErr := os.Stat(readyPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected original .ready file removed, got stat err: %v", statErr)
	}
}

func TestExecuteActionBambuPauseUsesMQTT(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	var listCalls int
	provider := &fakeBambuCloudActionProvider{
		listDevicesFn: func(_ context.Context, _ string) ([]bambucloud.CloudDevice, error) {
			listCalls++
			printStatus := "PRINTING"
			if listCalls >= 2 {
				printStatus = "PAUSED"
			}
			return []bambucloud.CloudDevice{
				{
					DeviceID:    "printer_1",
					Name:        "P1S",
					PrintStatus: printStatus,
					Online:      true,
					AccessCode:  "dev-access-code",
				},
			}, nil
		},
		getUploadFn: func(_ context.Context, _, _ string, _ int64) (bambucloud.CloudUploadURLs, error) {
			return bambucloud.CloudUploadURLs{}, errors.New("not used")
		},
		uploadSignedFn: func(_ context.Context, _ bambucloud.CloudUploadURLs, _ []byte) error {
			return errors.New("not used")
		},
		startPrintFn: func(_ context.Context, _ string, _ bambucloud.CloudPrintStartRequest) error {
			return errors.New("not used")
		},
	}
	publisher := &fakeBambuMQTTPublisher{}
	a.bambuAuthProvider = provider
	a.bambuMQTTPublish = publisher
	a.setBambuAuthState(bambuAuthState{
		Ready:        true,
		AccessToken:  "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"user-1"}`)) + ".sig",
		MQTTUsername: "stale-user",
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
	})

	err := a.executeAction(
		context.Background(),
		action{PrinterID: 1, Kind: "pause"},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("expected bambu pause action success, got %v", err)
	}
	if listCalls < 2 {
		t.Fatalf("list device call count = %d, want at least 2", listCalls)
	}
	if len(publisher.requests) != 1 {
		t.Fatalf("mqtt publish requests = %d, want 1", len(publisher.requests))
	}
	if publisher.requests[0].Command != "pause" {
		t.Fatalf("mqtt command = %q, want pause", publisher.requests[0].Command)
	}
	if publisher.requests[0].Username != "u_stale-user" {
		t.Fatalf("mqtt username = %q, want u_stale-user", publisher.requests[0].Username)
	}
	if !strings.Contains(publisher.requests[0].Topic, "printer_1") {
		t.Fatalf("mqtt topic = %q, want printer_1 topic", publisher.requests[0].Topic)
	}
}

func TestExecuteActionBambuPauseUsesLANMQTTWhenCredentialsAvailable(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true
	a.cfg.BambuConnectURI = "http://127.0.0.1:1"

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer_1",
		Host:       "192.168.100.175",
		AccessCode: "12345678",
		Name:       "Forge#2",
		Model:      "C12",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	publisher := &fakeBambuMQTTPublisher{}
	a.bambuMQTTPublish = publisher

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		return bindingSnapshot{
			PrinterState:    "paused",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	err = a.executeAction(
		context.Background(),
		action{PrinterID: 1, Kind: "pause"},
		edgeBinding{PrinterID: 1, AdapterFamily: "bambu", EndpointURL: "bambu://printer_1"},
	)
	if err != nil {
		t.Fatalf("executeAction(pause) failed: %v", err)
	}
	if len(publisher.requests) != 1 {
		t.Fatalf("mqtt publish requests = %d, want 1", len(publisher.requests))
	}
	request := publisher.requests[0]
	if request.BrokerAddr != "192.168.100.175:8883" {
		t.Fatalf("broker addr = %q, want 192.168.100.175:8883", request.BrokerAddr)
	}
	if request.Topic != "device/printer_1/request" {
		t.Fatalf("topic = %q, want device/printer_1/request", request.Topic)
	}
	if request.Username != bambuLANMQTTUsername {
		t.Fatalf("mqtt username = %q, want %q", request.Username, bambuLANMQTTUsername)
	}
	if request.Password != "12345678" {
		t.Fatalf("mqtt password = %q, want access code", request.Password)
	}
	if request.Command != "pause" {
		t.Fatalf("mqtt command = %q, want pause", request.Command)
	}
	if !request.InsecureSkipVerify {
		t.Fatalf("InsecureSkipVerify = false, want true for local Bambu MQTT")
	}
}

func TestPublishBambuCloudMQTTCommandRetriesAlternateUsernameOnAuthReject(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableBambu = true

	provider := &fakeBambuCloudActionProvider{
		listDevicesFn: func(_ context.Context, _ string) ([]bambucloud.CloudDevice, error) {
			return []bambucloud.CloudDevice{
				{
					DeviceID:    "printer_1",
					Name:        "P1S",
					PrintStatus: "PRINTING",
					Online:      true,
					AccessCode:  "dev-access-code",
				},
			}, nil
		},
	}
	publisher := &fakeBambuMQTTPublisher{
		publish: func(_ context.Context, req bambuMQTTCommandRequest) error {
			if req.Username == "bad-user" || req.Username == "u_bad-user" {
				return errors.New("bambu mqtt broker rejected connection return_code=5")
			}
			return nil
		},
	}
	a.bambuAuthProvider = provider
	a.bambuMQTTPublish = publisher
	a.setBambuAuthState(bambuAuthState{
		Ready:        true,
		AccessToken:  "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"good-user"}`)) + ".sig",
		MQTTUsername: "bad-user",
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
	})

	err := a.publishBambuCloudMQTTCommand(
		context.Background(),
		provider,
		"header."+base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"good-user"}`))+".sig",
		"printer_1",
		"pause",
		nil,
	)
	if err != nil {
		t.Fatalf("publishBambuCloudMQTTCommand failed: %v", err)
	}
	if len(publisher.requests) < 5 {
		t.Fatalf("publish attempts = %d, want at least 5", len(publisher.requests))
	}
	if publisher.requests[0].Username != "u_bad-user" {
		t.Fatalf("first username = %q, want u_bad-user", publisher.requests[0].Username)
	}
	if publisher.requests[1].Username != "u_bad-user" {
		t.Fatalf("second username = %q, want u_bad-user (password fallback)", publisher.requests[1].Username)
	}
	if publisher.requests[2].Username != "bad-user" {
		t.Fatalf("third username = %q, want bad-user", publisher.requests[2].Username)
	}
	if publisher.requests[3].Username != "bad-user" {
		t.Fatalf("fourth username = %q, want bad-user (password fallback)", publisher.requests[3].Username)
	}
	if publisher.requests[4].Username != "u_good-user" {
		t.Fatalf("fifth username = %q, want u_good-user", publisher.requests[4].Username)
	}
	if authState := a.snapshotBambuAuthState(); authState.MQTTUsername != "u_good-user" {
		t.Fatalf("auth mqtt username = %q, want u_good-user", authState.MQTTUsername)
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
		{name: "ready treated as completed", rawState: "ready", wantState: "idle", wantJob: "completed"},
		{name: "unknown treated as completed", rawState: "mystery", wantState: "idle", wantJob: "completed"},
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

func TestFetchBindingSnapshotDetailedUsesBambuLANDiscoveryWithoutCloudAuth(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true
	a.bambuLANRecords["printer-lan-1"] = bambuLANDiscoveryRecord{
		Snapshot: bindingSnapshot{
			PrinterState:      "idle",
			JobState:          "pending",
			TelemetrySource:   telemetrySourceBambuLAN,
			DetectedName:      "Forge LAN",
			DetectedModelHint: "P1S",
		},
		Host:     "192.168.1.55",
		LastSeen: time.Now().UTC(),
	}

	snapshot, err := a.fetchBindingSnapshotDetailed(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-1",
	})
	if err != nil {
		t.Fatalf("fetchBindingSnapshotDetailed failed: %v", err)
	}
	if snapshot.TelemetrySource != telemetrySourceBambuLAN {
		t.Fatalf("telemetry source = %q, want %q", snapshot.TelemetrySource, telemetrySourceBambuLAN)
	}
	if snapshot.DetectedName != "Forge LAN" {
		t.Fatalf("detected name = %q, want Forge LAN", snapshot.DetectedName)
	}
	if snapshot.DetectedModelHint != "P1S" {
		t.Fatalf("detected model hint = %q, want P1S", snapshot.DetectedModelHint)
	}
}

func TestFetchBindingSnapshotDetailedUsesBambuLANMQTTSnapshotWhenCredentialsAvailable(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = true

	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "printer-lan-runtime",
		Host:       "192.168.100.175",
		AccessCode: "12345678",
		Name:       "Forge#2",
		Model:      "C12",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	previousFetch := fetchBambuLANMQTTSnapshot
	fetchBambuLANMQTTSnapshot = func(_ context.Context, host string, printerID string, accessCode string) (bindingSnapshot, error) {
		if host != "192.168.100.175" {
			t.Fatalf("host = %q, want 192.168.100.175", host)
		}
		if printerID != "printer-lan-runtime" {
			t.Fatalf("printerID = %q, want printer-lan-runtime", printerID)
		}
		if accessCode != "12345678" {
			t.Fatalf("access code = %q, want 12345678", accessCode)
		}
		return bindingSnapshot{
			PrinterState:    "printing",
			JobState:        "printing",
			TelemetrySource: telemetrySourceBambuLANMQTT,
		}, nil
	}
	t.Cleanup(func() {
		fetchBambuLANMQTTSnapshot = previousFetch
	})

	snapshot, err := a.fetchBindingSnapshotDetailed(context.Background(), edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-lan-runtime",
	})
	if err != nil {
		t.Fatalf("fetchBindingSnapshotDetailed failed: %v", err)
	}
	if snapshot.PrinterState != "printing" {
		t.Fatalf("printer state = %q, want printing", snapshot.PrinterState)
	}
	if snapshot.JobState != "printing" {
		t.Fatalf("job state = %q, want printing", snapshot.JobState)
	}
	if snapshot.TelemetrySource != telemetrySourceBambuLANMQTT {
		t.Fatalf("telemetry source = %q, want %q", snapshot.TelemetrySource, telemetrySourceBambuLANMQTT)
	}
	if snapshot.DetectedName != "Forge#2" {
		t.Fatalf("detected name = %q, want Forge#2", snapshot.DetectedName)
	}
	if snapshot.DetectedModelHint != "C12" {
		t.Fatalf("detected model hint = %q, want C12", snapshot.DetectedModelHint)
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

func TestExecuteBambuCloudPrintActionUsesCloudStartDispatch(t *testing.T) {
	a := newTestAgent(t)
	artifact := []byte("G1 X12 Y34\n")
	sum := sha256.Sum256(artifact)
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	var (
		startCalls  int
		gotStartReq bambucloud.CloudPrintStartRequest
	)

	a.bambuAuthProvider = &fakeBambuCloudActionProvider{
		listDevicesFn: func(_ context.Context, _ string) ([]bambucloud.CloudDevice, error) {
			return []bambucloud.CloudDevice{
				{
					DeviceID:    "printer-1",
					Online:      true,
					AccessCode:  "access-code-1",
					PrintStatus: "running",
				},
			}, nil
		},
		getUploadFn: func(_ context.Context, _ string, _ string, _ int64) (bambucloud.CloudUploadURLs, error) {
			return bambucloud.CloudUploadURLs{
				UploadFileURL: "https://s3.us-west-2.amazonaws.com/or-cloud-upload-prod/users/3911589060/filename/20260217183115.027/plate.gcode",
				UploadSizeURL: "https://s3.us-west-2.amazonaws.com/or-cloud-upload-prod/users/3911589060/filename/20260217183115.027/plate.gcode.size",
				FileURL:       "https://s3.us-west-2.amazonaws.com/or-cloud-upload-prod/users/3911589060/filename/20260217183115.027/plate.gcode",
				FileName:      "plate.gcode",
				FileID:        "file-1",
			}, nil
		},
		uploadSignedFn: func(_ context.Context, _ bambucloud.CloudUploadURLs, fileBytes []byte) error {
			if !bytes.Equal(fileBytes, artifact) {
				t.Fatalf("unexpected upload payload")
			}
			return nil
		},
		startPrintFn: func(_ context.Context, accessToken string, req bambucloud.CloudPrintStartRequest) error {
			if strings.TrimSpace(accessToken) == "" {
				t.Fatalf("expected non-empty access token for cloud start")
			}
			startCalls++
			gotStartReq = req
			return nil
		},
	}

	queuedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			IntentVersion:       11,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			JobID:               "job-1",
			PlateID:             7,
			ArtifactURL:         artifactSrv.URL,
			ChecksumSHA256:      hex.EncodeToString(sum[:]),
		},
	}
	binding := edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-1",
	}
	a.setBambuAuthState(bambuAuthState{
		Ready:       true,
		AccessToken: "opaque-token",
		ExpiresAt:   time.Now().UTC().Add(1 * time.Hour),
	})

	err := a.executeBambuCloudPrintAction(context.Background(), queuedAction, binding, "opaque-token")
	if err != nil {
		t.Fatalf("executeBambuCloudPrintAction failed: %v", err)
	}
	if startCalls != 1 {
		t.Fatalf("cloud start call count = %d, want 1", startCalls)
	}
	if gotStartReq.DeviceID != "printer-1" {
		t.Fatalf("start device_id = %q, want printer-1", gotStartReq.DeviceID)
	}
	if gotStartReq.FileName != "plate.gcode" {
		t.Fatalf("start file_name = %q, want plate.gcode", gotStartReq.FileName)
	}
	if gotStartReq.FileURL == "" {
		t.Fatalf("expected non-empty start file_url")
	}
	if gotStartReq.FileID != "file-1" {
		t.Fatalf("start file_id = %q, want file-1", gotStartReq.FileID)
	}
}

func TestExecuteBambuCloudPrintActionAllowsMissingFileURLOnCloudStart(t *testing.T) {
	a := newTestAgent(t)
	artifact := []byte("G1 X50 Y60\n")
	sum := sha256.Sum256(artifact)
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer artifactSrv.Close()

	var (
		startCalls  int
		gotStartReq bambucloud.CloudPrintStartRequest
	)

	a.bambuAuthProvider = &fakeBambuCloudActionProvider{
		getUploadFn: func(_ context.Context, _ string, _ string, _ int64) (bambucloud.CloudUploadURLs, error) {
			return bambucloud.CloudUploadURLs{
				UploadFileURL: "https://uploads.local/file",
				UploadSizeURL: "https://uploads.local/size",
				FileName:      "plate.gcode",
				FileID:        "file-2",
			}, nil
		},
		uploadSignedFn: func(_ context.Context, _ bambucloud.CloudUploadURLs, fileBytes []byte) error {
			if !bytes.Equal(fileBytes, artifact) {
				t.Fatalf("unexpected upload payload")
			}
			return nil
		},
		startPrintFn: func(_ context.Context, accessToken string, req bambucloud.CloudPrintStartRequest) error {
			if strings.TrimSpace(accessToken) == "" {
				t.Fatalf("expected non-empty access token for cloud start")
			}
			startCalls++
			gotStartReq = req
			return nil
		},
		listDevicesFn: func(_ context.Context, _ string) ([]bambucloud.CloudDevice, error) {
			return []bambucloud.CloudDevice{
				{
					DeviceID:    "printer-1",
					Online:      true,
					AccessCode:  "access-code-1",
					PrintStatus: "running",
				},
			}, nil
		},
	}

	queuedAction := action{
		PrinterID: 1,
		Kind:      "print",
		Target: desiredStateItem{
			PrinterID:           1,
			IntentVersion:       12,
			DesiredPrinterState: "printing",
			DesiredJobState:     "printing",
			JobID:               "job-2",
			PlateID:             8,
			ArtifactURL:         artifactSrv.URL,
			ChecksumSHA256:      hex.EncodeToString(sum[:]),
		},
	}
	binding := edgeBinding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://printer-1",
	}
	a.setBambuAuthState(bambuAuthState{
		Ready:        true,
		AccessToken:  "opaque-token",
		MQTTUsername: "user-1",
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
	})

	if err := a.executeBambuCloudPrintAction(context.Background(), queuedAction, binding, "opaque-token"); err != nil {
		t.Fatalf("executeBambuCloudPrintAction failed: %v", err)
	}
	if startCalls != 1 {
		t.Fatalf("cloud start call count = %d, want 1", startCalls)
	}
	if gotStartReq.DeviceID != "printer-1" {
		t.Fatalf("start device_id = %q, want printer-1", gotStartReq.DeviceID)
	}
	if gotStartReq.FileName != "plate.gcode" {
		t.Fatalf("start file_name = %q, want plate.gcode", gotStartReq.FileName)
	}
	if gotStartReq.FileURL != "" {
		t.Fatalf("start file_url = %q, want empty when upload response omits file_url", gotStartReq.FileURL)
	}
	if gotStartReq.FileID != "file-2" {
		t.Fatalf("start file_id = %q, want file-2", gotStartReq.FileID)
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

func TestPushStateOnceSkipsStaleCurrentStateWithoutBinding(t *testing.T) {
	a := newTestAgent(t)

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/printer/objects/subscribe":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"idle"}}}}`))
		case "/printer/objects/query":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"idle"},"display_status":{"progress":0}}}}`))
		case "/machine/update/status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"version_info":{"system":{"version":"1.0.0"}}}}`))
		case "/printer/objects/query?print_stats&display_status":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"idle","print_duration":0},"display_status":{"progress":0}}}}`))
		case "/printer/objects/query?print_stats":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"idle"}}}}`))
		case "/printer/info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"hostname":"moonraker"}}`))
		case "/server/files/metadata":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{}}`))
		case "/printer/objects/query?virtual_sdcard":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"result":{"status":{"virtual_sdcard":{"progress":0}}}}`))
		default:
			if strings.HasPrefix(r.URL.Path, "/printer/objects/query") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":{"status":{"print_stats":{"state":"idle"},"display_status":{"progress":0}}}}`))
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	var pushedBody pushStateRequest
	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/state") {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&pushedBody); err != nil {
			t.Fatalf("decode state push failed: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":1,"deduplicated":false}`))
	}))
	defer saasSrv.Close()

	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: saasSrv.URL,
		SaaSAPIKey:      "edge_key",
		AgentID:         "edge_1",
		OrgID:           1,
	}
	a.claimed = true
	a.bindings[22] = edgeBinding{PrinterID: 22, AdapterFamily: "moonraker", EndpointURL: moonrakerSrv.URL}
	a.currentState[21] = currentStateItem{PrinterID: 21, CurrentPrinterState: "error", LastErrorCode: "connectivity_error"}
	a.currentState[22] = currentStateItem{PrinterID: 22, CurrentPrinterState: "idle"}

	if err := a.pushStateOnce(context.Background()); err != nil {
		t.Fatalf("pushStateOnce failed: %v", err)
	}

	if len(pushedBody.States) != 1 {
		t.Fatalf("pushed state count = %d, want 1", len(pushedBody.States))
	}
	if pushedBody.States[0].PrinterID != 22 {
		t.Fatalf("pushed printer_id = %d, want 22", pushedBody.States[0].PrinterID)
	}
	if _, exists := a.currentState[21]; exists {
		t.Fatalf("expected stale current state for printer 21 to be pruned")
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
