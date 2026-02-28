package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	bambuauth "printfarmhq/edge-agent/internal/bambu/auth"
	bambucloud "printfarmhq/edge-agent/internal/bambu/cloud"
	bambustore "printfarmhq/edge-agent/internal/store"
)

const (
	agentVersion                 = "0.1.0"
	agentSchemaVersion           = 2
	discoverySeedRetention       = 24 * time.Hour
	discoverySeedMaxEntries      = 512
	discoveryManualLockRetry     = 250 * time.Millisecond
	discoveryManualLockWaitMax   = 10 * time.Second
	discoverySourceEndpointHint  = "endpoint_hint"
	discoverySourceSeedManual    = "seed_manual_binding"
	discoverySourceSeedHistory   = "seed_inventory_history"
	discoverySourceCIDRAllowlist = "cidr_allowlist"
	discoverySourceLocalSubnets  = "local_private_subnets"
	discoverySourceBambuConnect  = "bambu_connect"
	discoverySourceBambuCloud    = "bambu_cloud"
	telemetrySourceBambuCloud    = "bambu_cloud"
	telemetrySourceBambuConnect  = "bambu_connect"
	defaultBambuMQTTTopic        = "device/%s/request"
	defaultBambuMQTTBrokerGlobal = "us.mqtt.bambulab.com:8883"
	defaultBambuMQTTBrokerChina  = "cn.mqtt.bambulab.com:8883"
)

var agentSupportedSchemaVersions = []int{1, agentSchemaVersion}
var errEdgeAuthRevoked = errors.New("edge_api_key_revoked")
var errBambuAuthUnavailable = errors.New("validation_error: bambu auth is not ready")
var macAddressPattern = regexp.MustCompile(`([0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5})`)
var arpCommandWarningOnce sync.Once
var runARPCommand = func(parts []string) ([]byte, error) {
	cmd := exec.Command(parts[0], parts[1:]...)
	return cmd.Output()
}
var logARPCommandWarning = func(message string, args ...any) {
	log.Printf(message, args...)
}
var bambuAuthInputReader io.Reader = os.Stdin
var bambuAuthOutputWriter io.Writer = os.Stdout
var isBambuAuthInteractiveConsole = defaultIsBambuAuthInteractiveConsole

type bootstrapConfig struct {
	ControlPlaneURL string    `json:"control_plane_url"`
	SaaSAPIKey      string    `json:"saas_api_key"`
	AgentID         string    `json:"agent_id"`
	OrgID           int       `json:"org_id"`
	ClaimedAt       time.Time `json:"claimed_at"`
}

type claimRequest struct {
	Hostname     string            `json:"hostname"`
	Fingerprint  string            `json:"fingerprint"`
	AgentVersion string            `json:"agent_version"`
	Capabilities map[string]string `json:"capabilities"`
}

type claimResponse struct {
	AgentID                 string `json:"agent_id"`
	OrgID                   int    `json:"org_id"`
	SchemaVersion           int    `json:"schema_version"`
	SupportedSchemaVersions []int  `json:"supported_schema_versions"`
}

type desiredStateItem struct {
	PrinterID           int    `json:"printer_id"`
	IntentVersion       int    `json:"intent_version"`
	DesiredPrinterState string `json:"desired_printer_state"`
	DesiredJobState     string `json:"desired_job_state"`
	JobID               string `json:"job_id"`
	PlateID             int    `json:"plate_id"`
	ArtifactURL         string `json:"artifact_url"`
	ChecksumSHA256      string `json:"checksum_sha256"`
}

type desiredStateResponse struct {
	SchemaVersion int                `json:"schema_version"`
	States        []desiredStateItem `json:"states"`
}

type edgeBinding struct {
	PrinterID     int    `json:"printer_id"`
	AdapterFamily string `json:"adapter_family"`
	EndpointURL   string `json:"endpoint_url"`
}

type bindingsResponse struct {
	AgentID  string        `json:"agent_id"`
	Bindings []edgeBinding `json:"bindings"`
}

type currentStateItem struct {
	PrinterID            int       `json:"printer_id"`
	CurrentPrinterState  string    `json:"current_printer_state"`
	CurrentJobState      string    `json:"current_job_state,omitempty"`
	JobID                string    `json:"job_id,omitempty"`
	PlateID              int       `json:"plate_id,omitempty"`
	IntentVersionApplied int       `json:"intent_version_applied,omitempty"`
	IsPaused             bool      `json:"is_paused"`
	IsCanceled           bool      `json:"is_canceled"`
	LastErrorCode        string    `json:"last_error_code,omitempty"`
	LastErrorMessage     string    `json:"last_error_message,omitempty"`
	TotalPrintSeconds    *float64  `json:"total_print_seconds,omitempty"`
	ProgressPct          *float64  `json:"progress_pct,omitempty"`
	RemainingSeconds     *float64  `json:"remaining_seconds,omitempty"`
	TelemetrySource      string    `json:"telemetry_source,omitempty"`
	ManualIntervention   string    `json:"manual_intervention,omitempty"`
	ReportedAt           time.Time `json:"reported_at"`
}

type pushStateRequest struct {
	States []currentStateItem `json:"states"`
}

type printerProbeItem struct {
	ProbeID       string `json:"probe_id"`
	AdapterFamily string `json:"adapter_family"`
	EndpointURL   string `json:"endpoint_url"`
}

type printerProbesResponse struct {
	Probes []printerProbeItem `json:"probes"`
}

type printerProbeResultRequest struct {
	Status              string   `json:"status"`
	ConnectivityError   string   `json:"connectivity_error,omitempty"`
	CurrentPrinterState string   `json:"current_printer_state,omitempty"`
	CurrentJobState     string   `json:"current_job_state,omitempty"`
	TotalPrintSeconds   *float64 `json:"total_print_seconds,omitempty"`
	DetectedPrinterName string   `json:"detected_printer_name,omitempty"`
	DetectedModelHint   string   `json:"detected_model_hint,omitempty"`
}

type discoveryJobItem struct {
	JobID                string         `json:"job_id"`
	Profile              string         `json:"profile"`
	Adapters             []string       `json:"adapters"`
	EndpointHints        []string       `json:"endpoint_hints"`
	CIDRAllowlist        []string       `json:"cidr_allowlist"`
	RuntimeCapsOverrides map[string]int `json:"runtime_caps_overrides"`
	RequestedAt          edgeTimestamp  `json:"requested_at"`
	ExpiresAt            edgeTimestamp  `json:"expires_at"`
}

type discoveryJobsResponse struct {
	Jobs []discoveryJobItem `json:"jobs"`
}

type discoverySummary struct {
	HostsScanned    int `json:"hosts_scanned"`
	HostsReachable  int `json:"hosts_reachable"`
	CandidatesFound int `json:"candidates_found"`
	ErrorsCount     int `json:"errors_count"`
}

type discoveryCandidateResult struct {
	AdapterFamily       string         `json:"adapter_family"`
	EndpointURL         string         `json:"endpoint_url"`
	Status              string         `json:"status"`
	ConnectivityError   string         `json:"connectivity_error,omitempty"`
	RejectionReason     string         `json:"rejection_reason,omitempty"`
	CurrentPrinterState string         `json:"current_printer_state,omitempty"`
	CurrentJobState     string         `json:"current_job_state,omitempty"`
	DetectedPrinterName string         `json:"detected_printer_name,omitempty"`
	DetectedModelHint   string         `json:"detected_model_hint,omitempty"`
	Evidence            map[string]any `json:"evidence,omitempty"`
}

type discoveryProbeTarget struct {
	EndpointURL string
	Source      string
}

type discoveryJobResultRequest struct {
	JobStatus  string                     `json:"job_status"`
	StartedAt  time.Time                  `json:"started_at"`
	FinishedAt time.Time                  `json:"finished_at"`
	Summary    discoverySummary           `json:"summary"`
	Candidates []discoveryCandidateResult `json:"candidates"`
}

type discoveryScanRequestItem struct {
	RequestToken string        `json:"request_token"`
	RequestedAt  edgeTimestamp `json:"requested_at"`
	ExpiresAt    edgeTimestamp `json:"expires_at"`
}

type discoveryScanRequestsResponse struct {
	Requests []discoveryScanRequestItem `json:"requests"`
}

type edgeTimestamp struct {
	time.Time
}

func (ts *edgeTimestamp) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "null" || raw == `""` {
		ts.Time = time.Time{}
		return nil
	}
	unquoted, err := strconv.Unquote(raw)
	if err != nil {
		unquoted = raw
	}
	value := strings.TrimSpace(unquoted)
	if value == "" {
		ts.Time = time.Time{}
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		parsed, parseErr := time.Parse(layout, value)
		if parseErr == nil {
			ts.Time = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("unsupported timestamp format: %q", value)
}

func (ts edgeTimestamp) MarshalJSON() ([]byte, error) {
	if ts.Time.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(ts.Time.UTC().Format(time.RFC3339Nano))
}

type discoveryInventorySummary struct {
	HostsScanned   int `json:"hosts_scanned"`
	HostsReachable int `json:"hosts_reachable"`
	EntriesCount   int `json:"entries_count"`
	ErrorsCount    int `json:"errors_count"`
}

type discoveryInventoryEntryReport struct {
	AdapterFamily       string         `json:"adapter_family"`
	EndpointURL         string         `json:"endpoint_url"`
	Status              string         `json:"status"`
	ConnectivityError   string         `json:"connectivity_error,omitempty"`
	MacAddress          string         `json:"mac_address,omitempty"`
	DetectedPrinterName string         `json:"detected_printer_name,omitempty"`
	DetectedModelHint   string         `json:"detected_model_hint,omitempty"`
	CurrentPrinterState string         `json:"current_printer_state,omitempty"`
	CurrentJobState     string         `json:"current_job_state,omitempty"`
	Evidence            map[string]any `json:"evidence,omitempty"`
}

type discoveryInventoryReportRequest struct {
	ScanID       string                          `json:"scan_id"`
	ScanMode     string                          `json:"scan_mode"`
	TriggerToken string                          `json:"trigger_token,omitempty"`
	StartedAt    time.Time                       `json:"started_at"`
	FinishedAt   time.Time                       `json:"finished_at"`
	Summary      discoveryInventorySummary       `json:"summary"`
	Entries      []discoveryInventoryEntryReport `json:"entries"`
}

type discoveryScanEventRequest struct {
	ScanMode     string    `json:"scan_mode"`
	TriggerToken string    `json:"trigger_token,omitempty"`
	Status       string    `json:"status"`
	OccurredAt   time.Time `json:"occurred_at"`
	Error        string    `json:"error,omitempty"`
}

type discoveryScanEventResponse struct {
	Accepted bool `json:"accepted"`
}

type discoveryInventoryIngestResponse struct {
	ScanID          string    `json:"scan_id"`
	AcceptedEntries int       `json:"accepted_entries"`
	MatchedEntries  int       `json:"matched_entries"`
	PendingEntries  int       `json:"pending_entries"`
	GeneratedAt     time.Time `json:"generated_at"`
}

type setupClaimRequest struct {
	ControlPlaneURL string `json:"control_plane_url"`
	SaaSAPIKey      string `json:"saas_api_key"`
}

type action struct {
	PrinterID   int              `json:"printer_id"`
	Kind        string           `json:"kind"`
	Reason      string           `json:"reason"`
	Target      desiredStateItem `json:"target"`
	EnqueuedAt  time.Time        `json:"enqueued_at"`
	Attempts    int              `json:"attempts"`
	NextAttempt time.Time        `json:"next_attempt"`
}

type bindingSnapshot struct {
	PrinterState       string
	JobState           string
	TotalPrintSeconds  *float64
	ProgressPct        *float64
	RemainingSeconds   *float64
	TelemetrySource    string
	ManualIntervention string
	DetectedName       string
	DetectedModelHint  string
}

type bambuAuthState struct {
	Ready         bool
	AccessToken   string
	ExpiresAt     time.Time
	Username      string
	MQTTUsername  string
	MaskedEmail   string
	MaskedPhone   string
	DisplayName   string
	LastError     string
	LastAttemptAt time.Time
}

type appConfig struct {
	SetupBindAddr               string
	BootstrapConfigPath         string
	AuditLogPath                string
	ArtifactStageDir            string
	StartupControlPlaneURL      string
	StartupSaaSAPIKey           string
	EnableKlipper               bool
	EnableBambu                 bool
	BambuCloudAuthBaseURL       string
	BambuCloudUploadPath        string
	BambuCloudPrintPath         string
	BambuCloudMQTTBroker        string
	BambuCloudMQTTTopicTemplate string
	BambuConnectURI             string
	BindingsPollInterval        time.Duration
	DesiredStatePollInterval    time.Duration
	StatePushInterval           time.Duration
	ConvergenceTickInterval     time.Duration
	ActionExecInterval          time.Duration
	ActionRetryBaseInterval     time.Duration
	ActionMaxAttempts           int
	ActionNonRetryableCooldown  time.Duration
	MoonrakerRequestTimeout     time.Duration
	ArtifactUploadTimeout       time.Duration
	ArtifactDownloadTimeout     time.Duration
	CircuitBreakerCooldown      time.Duration
	ProbePollInterval           time.Duration
	DiscoveryPollInterval       time.Duration
	DiscoveryInventoryInterval  time.Duration
	DiscoveryManualPollInterval time.Duration
	DiscoveryProfileMax         string
	DiscoveryNetworkMode        string
	DiscoveryAllowedAdapters    []string
	DiscoveryEndpointHints      []string
	DiscoveryCIDRAllowlist      []string
	DiscoveryMaxTargets         int
	DiscoveryWorkerCount        int
	DiscoveryProbeTimeout       time.Duration
}

type runtimeFlags struct {
	ControlPlaneURL string
	APIKey          string
	EnableKlipper   bool
	EnableBambu     bool
}

type agent struct {
	cfg    appConfig
	client *http.Client

	bambuAuthProvider bambuauth.Provider
	bambuAuthStore    bambustore.BambuCredentialsStore
	bambuMQTTPublish  bambuPrintCommandPublisher
	bambuAuthMu       sync.RWMutex
	bambuAuth         bambuAuthState

	mu              sync.RWMutex
	bootstrap       bootstrapConfig
	claimed         bool
	lastETag        string
	desiredState    map[int]desiredStateItem
	bindings        map[int]edgeBinding
	currentState    map[int]currentStateItem
	actionQueue     map[int][]action
	deadLetters     map[int][]action
	queuedSince     map[int]time.Time
	recentEnqueue   map[string]time.Time
	suppressedUntil map[string]time.Time
	resyncRequested bool
	breakerUntil    map[int]time.Time

	discoveryStateMu sync.Mutex
	discoveryRunning bool
	discoverySeedMu  sync.Mutex
	discoverySeeds   map[string]time.Time

	auditMu sync.Mutex
}

func main() {
	flags, err := parseRuntimeFlags(os.Args[1:])
	if err != nil {
		log.Fatalf("failed to parse startup flags: %v", err)
	}

	cfg := loadConfig()
	cfg = applyRuntimeFlags(cfg, flags)
	app := &agent{
		cfg:             cfg,
		client:          &http.Client{Timeout: 15 * time.Second},
		desiredState:    make(map[int]desiredStateItem),
		bindings:        make(map[int]edgeBinding),
		currentState:    make(map[int]currentStateItem),
		actionQueue:     make(map[int][]action),
		deadLetters:     make(map[int][]action),
		queuedSince:     make(map[int]time.Time),
		recentEnqueue:   make(map[string]time.Time),
		suppressedUntil: make(map[string]time.Time),
		breakerUntil:    make(map[int]time.Time),
		discoverySeeds:  make(map[string]time.Time),
	}

	if err := app.loadBootstrapConfig(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("failed to load bootstrap config: %v", err)
	}
	if err := app.cleanupStagedArtifacts(); err != nil {
		log.Printf("artifact cleanup on startup failed: %v", err)
	}
	if err := app.bootstrapFromStartupCredentials(context.Background()); err != nil {
		log.Fatalf("failed to bootstrap from startup credentials: %v", err)
	}
	if err := app.initializeBambuAuth(context.Background()); err != nil {
		app.audit("bambu_auth_init_error", map[string]any{"error": err.Error()})
		log.Fatalf("failed to initialize bambu auth: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/setup/status", app.handleSetupStatus)
	mux.HandleFunc("/setup/claim", app.handleSetupClaim)

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	signalEvents := make(chan os.Signal, 1)
	signal.Notify(signalEvents, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signalEvents)

	// Attempt one bootstrap sync when restarting with persisted claim.
	if app.isClaimed() {
		app.bootstrapSync(rootCtx)
	}

	var wg sync.WaitGroup
	wg.Add(9)
	go app.bindingsPollLoop(rootCtx, &wg)
	go app.desiredStatePollLoop(rootCtx, &wg)
	go app.convergenceLoop(rootCtx, &wg)
	go app.actionExecLoop(rootCtx, &wg)
	go app.statePushLoop(rootCtx, &wg)
	go app.probePollLoop(rootCtx, &wg)
	go app.discoveryPollLoop(rootCtx, &wg)
	go app.discoveryInventoryLoop(rootCtx, &wg)
	go app.discoveryManualTriggerLoop(rootCtx, &wg)

	server := &http.Server{
		Addr:    cfg.SetupBindAddr,
		Handler: mux,
	}
	go func() {
		log.Printf("edge-agent listening on %s", cfg.SetupBindAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	<-rootCtx.Done()
	receivedSignal := "unknown"
	select {
	case sig := <-signalEvents:
		receivedSignal = strings.TrimSpace(sig.String())
	default:
	}
	app.audit("agent_shutdown", map[string]any{
		"reason": "signal",
		"kind":   receivedSignal,
	})

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.pushStateOnce(shutdownCtx); err != nil {
		app.audit("shutdown_state_push_error", map[string]any{"error": err.Error()})
	}
	if err := app.notifyShutdown(shutdownCtx); err != nil {
		app.audit("shutdown_notify_error", map[string]any{"error": err.Error()})
	}
	_ = server.Shutdown(shutdownCtx)
	wg.Wait()
}

func (a *agent) bootstrapSync(ctx context.Context) {
	if err := a.pollBindingsOnce(ctx); err != nil {
		a.audit("bootstrap_bindings_error", map[string]any{"error": err.Error()})
	}
	if err := a.pollDesiredStateOnce(ctx); err != nil {
		a.audit("bootstrap_desired_state_error", map[string]any{"error": err.Error()})
	}
	a.refreshCurrentStateFromBindings(ctx)
	a.reconcileOnce()
	if err := a.pushStateOnce(ctx); err != nil {
		a.audit("bootstrap_state_push_error", map[string]any{"error": err.Error()})
	}
}

func (a *agent) bootstrapFromStartupCredentials(ctx context.Context) error {
	apiKey := strings.TrimSpace(a.cfg.StartupSaaSAPIKey)
	if apiKey == "" {
		return nil
	}

	controlPlaneURL := strings.TrimSpace(a.cfg.StartupControlPlaneURL)
	if controlPlaneURL == "" {
		existing := a.snapshotBootstrap()
		controlPlaneURL = strings.TrimSpace(existing.ControlPlaneURL)
	}
	if controlPlaneURL == "" {
		return errors.New("control-plane-url is required when api key is provided")
	}

	existing := a.snapshotBootstrap()
	if a.isClaimed() &&
		strings.TrimSpace(existing.ControlPlaneURL) == controlPlaneURL &&
		strings.TrimSpace(existing.SaaSAPIKey) == apiKey {
		return nil
	}

	claim, err := a.claimWithSaaS(controlPlaneURL, apiKey)
	if err != nil {
		a.audit("claim_failed", map[string]any{"error": err.Error()})
		return fmt.Errorf("startup claim failed: %w", err)
	}

	a.mu.Lock()
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: controlPlaneURL,
		SaaSAPIKey:      apiKey,
		AgentID:         claim.AgentID,
		OrgID:           claim.OrgID,
		ClaimedAt:       time.Now().UTC(),
	}
	a.claimed = true
	a.lastETag = ""
	a.mu.Unlock()

	if err := a.saveBootstrapConfig(); err != nil {
		a.audit("bootstrap_persist_error", map[string]any{"error": err.Error()})
		log.Printf("warning: failed to persist bootstrap config: %v", err)
	}
	if err := a.pollBindingsOnce(ctx); err != nil {
		a.audit("bindings_initial_fetch_error", map[string]any{"error": err.Error()})
	}
	if err := a.pollDesiredStateOnce(ctx); err != nil {
		a.audit("desired_state_initial_fetch_error", map[string]any{"error": err.Error()})
	}

	a.audit("claimed", map[string]any{
		"agent_id":       claim.AgentID,
		"org_id":         claim.OrgID,
		"schema_version": claim.SchemaVersion,
		"source":         "startup_credentials",
	})
	return nil
}

func (a *agent) initializeBambuAuth(ctx context.Context) error {
	if !a.cfg.EnableBambu {
		a.setBambuAuthState(bambuAuthState{})
		return nil
	}

	state := bambuAuthState{LastAttemptAt: time.Now().UTC()}
	a.setBambuAuthState(state)
	a.audit("bambu_auth_start", map[string]any{
		"mode":             "token_reuse_with_interactive_fallback",
		"interactive_auth": true,
	})

	provider := a.bambuAuthProvider
	if provider == nil {
		provider = bambucloud.NewHTTPProvider(bambucloud.HTTPProviderConfig{
			AuthBaseURL: strings.TrimSpace(a.cfg.BambuCloudAuthBaseURL),
			Client:      a.client,
			UploadPath:  strings.TrimSpace(a.cfg.BambuCloudUploadPath),
			PrintPath:   strings.TrimSpace(a.cfg.BambuCloudPrintPath),
		})
		a.bambuAuthProvider = provider
	}

	credentialsStore := a.bambuAuthStore
	if credentialsStore == nil {
		store, err := bambustore.NewDefaultBambuCredentialsFileStore()
		if err != nil {
			state.LastError = fmt.Sprintf("bambu token store init failed: %v", err)
			a.setBambuAuthState(state)
			a.audit("bambu_auth_failure", map[string]any{"error": state.LastError})
			return err
		}
		credentialsStore = store
		a.bambuAuthStore = credentialsStore
	}

	session, username, shouldPersist, err := a.establishBambuSession(ctx, provider, credentialsStore)
	if err != nil {
		state.LastError = err.Error()
		a.setBambuAuthState(state)
		a.audit("bambu_auth_failure", map[string]any{"error": state.LastError})
		return err
	}

	if shouldPersist {
		credentials := bambustore.BambuCredentials{
			Username:           strings.TrimSpace(username),
			AccessToken:        session.AccessToken,
			RefreshToken:       session.RefreshToken,
			ExpiresAt:          session.ExpiresAt.UTC(),
			MaskedEmail:        session.MaskedEmail,
			MaskedPhone:        session.MaskedPhone,
			AccountDisplayName: session.AccountDisplayName,
			MQTTUsername:       strings.TrimSpace(session.MQTTUsername),
		}
		if err := credentialsStore.Save(ctx, credentials); err != nil {
			state.LastError = fmt.Sprintf("bambu token store write failed: %v", err)
			a.setBambuAuthState(state)
			a.audit("bambu_auth_persist_failure", map[string]any{"error": state.LastError})
			return err
		}
	}

	state = bambuAuthState{
		Ready:         true,
		AccessToken:   strings.TrimSpace(session.AccessToken),
		ExpiresAt:     session.ExpiresAt.UTC(),
		Username:      strings.TrimSpace(username),
		MQTTUsername:  strings.TrimSpace(session.MQTTUsername),
		MaskedEmail:   session.MaskedEmail,
		MaskedPhone:   session.MaskedPhone,
		DisplayName:   session.AccountDisplayName,
		LastAttemptAt: time.Now().UTC(),
	}
	a.setBambuAuthState(state)
	a.audit("bambu_auth_success", map[string]any{
		"expires_at":      state.ExpiresAt,
		"masked_email":    state.MaskedEmail,
		"masked_phone":    state.MaskedPhone,
		"display_name":    state.DisplayName,
		"mqtt_username":   state.MQTTUsername,
		"refresh_present": session.RefreshToken != "",
	})
	return nil
}

type bambuCloudDeviceLister interface {
	ListBoundDevices(ctx context.Context, accessToken string) ([]bambucloud.CloudDevice, error)
}

type bambuCloudActionProvider interface {
	bambuCloudDeviceLister
	GetUploadURLs(ctx context.Context, accessToken, filename string, sizeBytes int64) (bambucloud.CloudUploadURLs, error)
	UploadToSignedURLs(ctx context.Context, uploadURLs bambucloud.CloudUploadURLs, fileBytes []byte) error
	StartPrintJob(ctx context.Context, accessToken string, req bambucloud.CloudPrintStartRequest) error
}

type bambuMQTTCommandRequest struct {
	BrokerAddr string
	Topic      string
	Username   string
	Password   string
	Command    string
	Param      map[string]any
}

type bambuPrintCommandPublisher interface {
	PublishPrintCommand(ctx context.Context, req bambuMQTTCommandRequest) error
}

func (a *agent) establishBambuSession(
	ctx context.Context,
	provider bambuauth.Provider,
	store bambustore.BambuCredentialsStore,
) (bambuauth.Session, string, bool, error) {
	now := time.Now().UTC()
	storedCredentials, loadErr := store.Load(ctx)
	if loadErr == nil {
		storedUsername := strings.TrimSpace(storedCredentials.Username)
		if isStoredBambuTokenUsable(storedCredentials, now) {
			a.audit("bambu_auth_token_loaded", map[string]any{
				"expires_at": storedCredentials.ExpiresAt,
			})
			return sessionFromStoredBambuCredentials(storedCredentials), storedUsername, false, nil
		}

		refreshToken := strings.TrimSpace(storedCredentials.RefreshToken)
		if refreshToken != "" {
			a.audit("bambu_auth_token_refresh_attempt", map[string]any{
				"expires_at": storedCredentials.ExpiresAt,
			})
			refreshedSession, refreshErr := provider.Refresh(ctx, bambuauth.RefreshRequest{RefreshToken: refreshToken})
			if refreshErr == nil {
				if strings.TrimSpace(refreshedSession.RefreshToken) == "" {
					refreshedSession.RefreshToken = refreshToken
				}
				if strings.TrimSpace(refreshedSession.MQTTUsername) == "" {
					refreshedSession.MQTTUsername = strings.TrimSpace(storedCredentials.MQTTUsername)
				}
				a.audit("bambu_auth_token_refresh_success", map[string]any{
					"expires_at": refreshedSession.ExpiresAt,
				})
				return refreshedSession, storedUsername, true, nil
			}
			a.audit("bambu_auth_token_refresh_failure", map[string]any{
				"error": refreshErr.Error(),
			})
		}

		a.audit("bambu_auth_interactive_login_required", map[string]any{
			"reason": "stored_token_unusable",
		})
		session, promptedUsername, loginErr := loginBambuCloudInteractive(ctx, provider, storedUsername)
		if loginErr != nil {
			return bambuauth.Session{}, "", false, loginErr
		}
		return session, promptedUsername, true, nil
	}

	if !errors.Is(loadErr, os.ErrNotExist) {
		return bambuauth.Session{}, "", false, fmt.Errorf("load bambu credentials: %w", loadErr)
	}

	a.audit("bambu_auth_interactive_login_required", map[string]any{
		"reason": "missing_token",
	})
	session, promptedUsername, loginErr := loginBambuCloudInteractive(ctx, provider, "")
	if loginErr != nil {
		return bambuauth.Session{}, "", false, loginErr
	}
	return session, promptedUsername, true, nil
}

func loginBambuCloudInteractive(
	ctx context.Context,
	provider bambuauth.Provider,
	defaultUsername string,
) (bambuauth.Session, string, error) {
	reader := bufio.NewReader(bambuAuthInputReader)
	username, password, promptErr := promptForBambuCredentials(ctx, reader, defaultUsername)
	if promptErr != nil {
		return bambuauth.Session{}, "", promptErr
	}

	loginReq := bambuauth.LoginRequest{
		Username: username,
		Password: password,
	}
	session, err := provider.Login(ctx, loginReq)
	if err == nil {
		return session, username, nil
	}
	if !errors.Is(err, bambuauth.ErrMFARequired) {
		return bambuauth.Session{}, "", err
	}

	mfaCode, promptErr := promptForBambuMFACode(ctx, reader)
	if promptErr != nil {
		return bambuauth.Session{}, "", promptErr
	}
	loginReq.MFACode = mfaCode
	session, err = provider.Login(ctx, loginReq)
	if err != nil {
		return bambuauth.Session{}, "", err
	}
	return session, username, nil
}

func promptForBambuCredentials(
	ctx context.Context,
	reader *bufio.Reader,
	defaultUsername string,
) (username string, password string, err error) {
	if !isBambuAuthInteractiveConsole() {
		return "", "", errors.New("bambu login requires interactive console input, but no interactive console is available")
	}
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	default:
	}

	if reader == nil {
		reader = bufio.NewReader(bambuAuthInputReader)
	}
	trimmedDefaultUsername := strings.TrimSpace(defaultUsername)
	if trimmedDefaultUsername != "" {
		_, _ = io.WriteString(bambuAuthOutputWriter, fmt.Sprintf("Bambu username [%s]: ", trimmedDefaultUsername))
	} else {
		_, _ = io.WriteString(bambuAuthOutputWriter, "Bambu username: ")
	}
	rawUsername, readErr := readLineFromBambuAuthInput(reader)
	if readErr != nil {
		return "", "", fmt.Errorf("failed to read Bambu username: %w", readErr)
	}
	username = strings.TrimSpace(rawUsername)
	if username == "" {
		username = trimmedDefaultUsername
	}
	if username == "" {
		return "", "", errors.New("bambu username cannot be empty")
	}

	_, _ = io.WriteString(bambuAuthOutputWriter, "Bambu password: ")
	password, readErr = readBambuPasswordInput(reader)
	if readErr != nil {
		return "", "", fmt.Errorf("failed to read Bambu password: %w", readErr)
	}
	if password == "" {
		return "", "", errors.New("bambu password cannot be empty")
	}
	return username, password, nil
}

func promptForBambuMFACode(ctx context.Context, reader *bufio.Reader) (string, error) {
	if !isBambuAuthInteractiveConsole() {
		return "", errors.New("bambu cloud requires interactive MFA input, but no interactive console is available")
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	_, _ = io.WriteString(bambuAuthOutputWriter, "Bambu MFA code required. Enter code sent via email: ")
	if reader == nil {
		reader = bufio.NewReader(bambuAuthInputReader)
	}
	rawCode, readErr := readLineFromBambuAuthInput(reader)
	if readErr != nil {
		return "", fmt.Errorf("failed to read MFA code from console: %w", readErr)
	}
	code := strings.TrimSpace(trimTrailingLineBreak(rawCode))
	if code == "" {
		return "", errors.New("bambu MFA code cannot be empty")
	}
	return code, nil
}

func readLineFromBambuAuthInput(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && line == "" {
		return "", io.EOF
	}
	return line, nil
}

func readBambuPasswordInput(reader *bufio.Reader) (string, error) {
	if reader == nil {
		reader = bufio.NewReader(bambuAuthInputReader)
	}
	if shouldUseHiddenBambuPasswordInput() {
		return readBambuPasswordWithoutEcho()
	}

	rawPassword, err := readLineFromBambuAuthInput(reader)
	if err != nil {
		return "", err
	}
	return trimTrailingLineBreak(rawPassword), nil
}

func shouldUseHiddenBambuPasswordInput() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	if bambuAuthInputReader != os.Stdin {
		return false
	}
	return isBambuAuthInteractiveConsole()
}

func readBambuPasswordWithoutEcho() (string, error) {
	terminalState, err := readTerminalState()
	if err != nil {
		return "", err
	}
	if err := setTerminalState("-echo"); err != nil {
		return "", err
	}
	defer func() {
		_ = setTerminalState(terminalState)
		_, _ = io.WriteString(bambuAuthOutputWriter, "\n")
	}()

	reader := bufio.NewReader(os.Stdin)
	rawPassword, err := readLineFromBambuAuthInput(reader)
	if err != nil {
		return "", err
	}
	return trimTrailingLineBreak(rawPassword), nil
}

func readTerminalState() (string, error) {
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func setTerminalState(state string) error {
	cmd := exec.Command("stty", state)
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}

func trimTrailingLineBreak(raw string) string {
	return strings.TrimRight(strings.TrimRight(raw, "\n"), "\r")
}

func defaultIsBambuAuthInteractiveConsole() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func isStoredBambuTokenUsable(credentials bambustore.BambuCredentials, now time.Time) bool {
	if strings.TrimSpace(credentials.AccessToken) == "" {
		return false
	}
	expiresAt := credentials.ExpiresAt.UTC()
	if expiresAt.IsZero() {
		return false
	}
	return expiresAt.After(now.Add(60 * time.Second))
}

func sessionFromStoredBambuCredentials(credentials bambustore.BambuCredentials) bambuauth.Session {
	return bambuauth.Session{
		AccessToken:        strings.TrimSpace(credentials.AccessToken),
		RefreshToken:       strings.TrimSpace(credentials.RefreshToken),
		ExpiresAt:          credentials.ExpiresAt.UTC(),
		MaskedEmail:        strings.TrimSpace(credentials.MaskedEmail),
		MaskedPhone:        strings.TrimSpace(credentials.MaskedPhone),
		AccountDisplayName: strings.TrimSpace(credentials.AccountDisplayName),
		MQTTUsername:       strings.TrimSpace(credentials.MQTTUsername),
	}
}

func loadConfig() appConfig {
	defaultStateDir := defaultEdgeStateDir()
	bambuCloudAuthBaseURL := getEnvOrDefault("BAMBU_CLOUD_AUTH_BASE_URL", "https://api.bambulab.com")
	return appConfig{
		SetupBindAddr:               getEnvOrDefault("SETUP_BIND_ADDR", "0.0.0.0:8090"),
		BootstrapConfigPath:         getEnvOrDefault("BOOTSTRAP_CONFIG_PATH", filepath.Join(defaultStateDir, "bootstrap", "config.json")),
		AuditLogPath:                getEnvOrDefault("AUDIT_LOG_PATH", filepath.Join(defaultStateDir, "logs", "audit.log")),
		ArtifactStageDir:            getEnvOrDefault("ARTIFACT_STAGE_DIR", filepath.Join(defaultStateDir, "artifacts")),
		StartupControlPlaneURL:      getEnvOrDefault("CONTROL_PLANE_URL", ""),
		StartupSaaSAPIKey:           getEnvOrDefault("SAAS_API_KEY", getEnvOrDefault("EDGE_API_KEY", "")),
		EnableKlipper:               parseBoolEnv("ENABLE_KLIPPER", false),
		EnableBambu:                 parseBoolEnv("ENABLE_BAMBU", false),
		BambuCloudAuthBaseURL:       bambuCloudAuthBaseURL,
		BambuCloudUploadPath:        getEnvOrDefault("BAMBU_CLOUD_UPLOAD_PATH", "/v1/iot-service/api/user/upload"),
		BambuCloudPrintPath:         getEnvOrDefault("BAMBU_CLOUD_PRINT_PATH", "/v1/iot-service/api/user/print"),
		BambuCloudMQTTBroker:        getEnvOrDefault("BAMBU_CLOUD_MQTT_BROKER", defaultBambuCloudMQTTBroker(bambuCloudAuthBaseURL)),
		BambuCloudMQTTTopicTemplate: getEnvOrDefault("BAMBU_CLOUD_MQTT_TOPIC_TEMPLATE", defaultBambuMQTTTopic),
		BambuConnectURI:             getEnvOrDefault("BAMBU_CONNECT_URI", ""),
		BindingsPollInterval:        parseDurationMS("BINDINGS_POLL_INTERVAL_MS", 5000),
		DesiredStatePollInterval:    parseDurationMS("DESIRED_STATE_POLL_INTERVAL_MS", 3000),
		StatePushInterval:           parseDurationMS("STATE_PUSH_INTERVAL_MS", 3000),
		ConvergenceTickInterval:     parseDurationMS("CONVERGENCE_TICK_INTERVAL_MS", 500),
		ActionExecInterval:          parseDurationMS("ACTION_EXEC_INTERVAL_MS", 250),
		ActionRetryBaseInterval:     parseDurationMS("ACTION_RETRY_BASE_INTERVAL_MS", 1000),
		ActionMaxAttempts:           parsePositiveInt("ACTION_MAX_ATTEMPTS", 3),
		ActionNonRetryableCooldown:  parseDurationMS("ACTION_NON_RETRYABLE_COOLDOWN_MS", 180000),
		MoonrakerRequestTimeout:     parseDurationMS("MOONRAKER_REQUEST_TIMEOUT_MS", 8000),
		ArtifactUploadTimeout:       parseDurationMS("ARTIFACT_UPLOAD_TIMEOUT_MS", 90000),
		ArtifactDownloadTimeout:     parseDurationMS("ARTIFACT_DOWNLOAD_TIMEOUT_MS", 15000),
		CircuitBreakerCooldown:      parseDurationMS("CIRCUIT_BREAKER_COOLDOWN_MS", 15000),
		ProbePollInterval:           parseDurationMS("PROBE_POLL_INTERVAL_MS", 2000),
		DiscoveryPollInterval:       parseDurationMS("DISCOVERY_POLL_INTERVAL_MS", 4000),
		DiscoveryInventoryInterval:  parseDurationMS("DISCOVERY_INVENTORY_INTERVAL_MS", 30000),
		DiscoveryManualPollInterval: parseDurationMS("DISCOVERY_MANUAL_POLL_INTERVAL_MS", 5000),
		DiscoveryProfileMax:         parseDiscoveryProfile(getEnvOrDefault("DISCOVERY_PROFILE_MAX", "hybrid")),
		// Binary runtime should scan host LAN by default. Bridge mode remains opt-in.
		DiscoveryNetworkMode:     parseDiscoveryNetworkMode(getEnvOrDefault("DISCOVERY_NETWORK_MODE", "host")),
		DiscoveryAllowedAdapters: parseDiscoveryAdaptersEnv(getEnvOrDefault("DISCOVERY_ALLOWED_ADAPTERS", "moonraker,bambu")),
		DiscoveryEndpointHints:   parseDiscoveryHintsEnv(getEnvOrDefault("DISCOVERY_ENDPOINT_HINTS", "")),
		DiscoveryCIDRAllowlist:   parseDiscoveryCIDRsEnv(getEnvOrDefault("DISCOVERY_CIDR_ALLOWLIST", "")),
		DiscoveryMaxTargets:      parsePositiveInt("DISCOVERY_MAX_TARGETS", 256),
		DiscoveryWorkerCount:     parsePositiveInt("DISCOVERY_WORKER_COUNT", 64),
		DiscoveryProbeTimeout:    parseDurationMS("DISCOVERY_PROBE_TIMEOUT_MS", 2000),
	}
}

func defaultBambuCloudMQTTBroker(authBaseURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(authBaseURL))
	if err != nil {
		return defaultBambuMQTTBrokerGlobal
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if strings.HasSuffix(host, ".cn") {
		return defaultBambuMQTTBrokerChina
	}
	return defaultBambuMQTTBrokerGlobal
}

func defaultEdgeStateDir() string {
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".printfarmhq")
	}
	return filepath.Join(os.TempDir(), ".printfarmhq")
}

func parseRuntimeFlags(args []string) (runtimeFlags, error) {
	flagSet := flag.NewFlagSet("edge-agent", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)

	var out runtimeFlags
	var saasAPIKey string
	flagSet.StringVar(&out.ControlPlaneURL, "control-plane-url", "", "Control plane URL override")
	flagSet.StringVar(&out.APIKey, "api-key", "", "SaaS API key used for startup auto-claim")
	flagSet.StringVar(&saasAPIKey, "saas-api-key", "", "Alias for --api-key")
	flagSet.BoolVar(&out.EnableKlipper, "klipper", false, "Enable Klipper/Moonraker discovery and operations")
	flagSet.BoolVar(&out.EnableBambu, "bambu", false, "Enable Bambu cloud discovery and operations")

	if err := flagSet.Parse(args); err != nil {
		return runtimeFlags{}, err
	}
	if len(flagSet.Args()) > 0 {
		return runtimeFlags{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flagSet.Args(), " "))
	}

	out.ControlPlaneURL = strings.TrimSpace(out.ControlPlaneURL)
	out.APIKey = strings.TrimSpace(out.APIKey)
	if out.APIKey == "" {
		out.APIKey = strings.TrimSpace(saasAPIKey)
	}
	if !out.EnableKlipper && !out.EnableBambu {
		return runtimeFlags{}, errors.New("at least one adapter must be enabled via --klipper and/or --bambu")
	}
	return out, nil
}

func applyRuntimeFlags(cfg appConfig, flags runtimeFlags) appConfig {
	if flags.ControlPlaneURL != "" {
		cfg.StartupControlPlaneURL = flags.ControlPlaneURL
	}
	if flags.APIKey != "" {
		cfg.StartupSaaSAPIKey = flags.APIKey
	}
	cfg.EnableKlipper = flags.EnableKlipper
	cfg.EnableBambu = flags.EnableBambu
	cfg.DiscoveryAllowedAdapters = enabledDiscoveryAdapters(cfg.EnableKlipper, cfg.EnableBambu)
	return cfg
}

func enabledDiscoveryAdapters(enableKlipper bool, enableBambu bool) []string {
	adapters := make([]string, 0, 2)
	if enableKlipper {
		adapters = append(adapters, "moonraker")
	}
	if enableBambu {
		adapters = append(adapters, "bambu")
	}
	return adapters
}

func parseDurationMS(key string, fallback int) time.Duration {
	raw := getEnvOrDefault(key, strconv.Itoa(fallback))
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		v = fallback
	}
	return time.Duration(v) * time.Millisecond
}

func parsePositiveInt(key string, fallback int) int {
	raw := getEnvOrDefault(key, strconv.Itoa(fallback))
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func parseBoolEnv(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	case "":
		return fallback
	default:
		return fallback
	}
}

func parseDiscoveryProfile(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "aggressive" {
		return "aggressive"
	}
	return "hybrid"
}

func parseDiscoveryNetworkMode(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "host" {
		return "host"
	}
	return "bridge"
}

func parseDiscoveryAdaptersEnv(raw string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	for _, item := range strings.Split(raw, ",") {
		adapter := normalizeAdapterFamily(item)
		if adapter == "" {
			continue
		}
		if _, ok := seen[adapter]; ok {
			continue
		}
		seen[adapter] = struct{}{}
		out = append(out, adapter)
	}
	if len(out) == 0 {
		return []string{"moonraker"}
	}
	return out
}

func parseDiscoveryHintsEnv(raw string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 16)
	for _, item := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		canonical := normalizeDiscoveryEndpointHint(trimmed)
		if canonical == "" {
			continue
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}

func parseDiscoveryCIDRsEnv(raw string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 16)
	for _, item := range strings.Split(raw, ",") {
		cidr := strings.TrimSpace(item)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			continue
		}
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out
}

func getEnvOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func (a *agent) isClaimed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.claimed && a.bootstrap.AgentID != "" && a.bootstrap.SaaSAPIKey != "" && a.bootstrap.ControlPlaneURL != ""
}

func (a *agent) snapshotBootstrap() bootstrapConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.bootstrap
}

func (a *agent) setBambuAuthState(state bambuAuthState) {
	a.bambuAuthMu.Lock()
	defer a.bambuAuthMu.Unlock()
	a.bambuAuth = state
}

func (a *agent) snapshotBambuAuthState() bambuAuthState {
	a.bambuAuthMu.RLock()
	defer a.bambuAuthMu.RUnlock()
	return a.bambuAuth
}

func (a *agent) isBambuAuthReady() bool {
	if !a.cfg.EnableBambu {
		return false
	}
	state := a.snapshotBambuAuthState()
	return state.Ready
}

func (a *agent) isBambuOperational() bool {
	return a.cfg.EnableBambu && a.isBambuAuthReady()
}

func (a *agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bootstrap := a.snapshotBootstrap()
	a.mu.RLock()
	queueDepth := 0
	deadLetterCount := 0
	breakerCount := 0
	for _, actions := range a.actionQueue {
		queueDepth += len(actions)
	}
	for _, actions := range a.deadLetters {
		deadLetterCount += len(actions)
	}
	now := time.Now().UTC()
	for _, until := range a.breakerUntil {
		if until.After(now) {
			breakerCount++
		}
	}
	desiredCount := len(a.desiredState)
	currentCount := len(a.currentState)
	a.mu.RUnlock()
	claimed := a.isClaimed()
	bambuAuth := a.snapshotBambuAuthState()

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                "healthy",
		"version":               agentVersion,
		"claimed":               claimed,
		"agent_id":              bootstrap.AgentID,
		"desired_count":         desiredCount,
		"current_count":         currentCount,
		"queue_depth":           queueDepth,
		"dead_letters":          deadLetterCount,
		"breakers_open":         breakerCount,
		"klipper_enabled":       a.cfg.EnableKlipper,
		"bambu_enabled":         a.cfg.EnableBambu,
		"bambu_auth_ready":      bambuAuth.Ready,
		"bambu_auth_expires_at": bambuAuth.ExpiresAt,
		"bambu_auth_last_error": bambuAuth.LastError,
	})
}

func (a *agent) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	bootstrap := a.snapshotBootstrap()
	writeJSON(w, http.StatusOK, map[string]any{
		"claimed":           a.isClaimed(),
		"agent_id":          bootstrap.AgentID,
		"org_id":            bootstrap.OrgID,
		"control_plane_url": bootstrap.ControlPlaneURL,
		"claimed_at":        bootstrap.ClaimedAt,
	})
}

func (a *agent) handleSetupClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req setupClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}
	req.ControlPlaneURL = strings.TrimSpace(req.ControlPlaneURL)
	req.SaaSAPIKey = strings.TrimSpace(req.SaaSAPIKey)
	if req.ControlPlaneURL == "" || req.SaaSAPIKey == "" {
		http.Error(w, "control_plane_url and saas_api_key are required", http.StatusBadRequest)
		return
	}

	claim, err := a.claimWithSaaS(req.ControlPlaneURL, req.SaaSAPIKey)
	if err != nil {
		a.audit("claim_failed", map[string]any{"error": err.Error()})
		http.Error(w, fmt.Sprintf("claim failed: %v", err), http.StatusBadGateway)
		return
	}

	a.mu.Lock()
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: req.ControlPlaneURL,
		SaaSAPIKey:      req.SaaSAPIKey,
		AgentID:         claim.AgentID,
		OrgID:           claim.OrgID,
		ClaimedAt:       time.Now().UTC(),
	}
	a.claimed = true
	a.lastETag = ""
	a.mu.Unlock()

	if err := a.saveBootstrapConfig(); err != nil {
		http.Error(w, fmt.Sprintf("failed to persist bootstrap config: %v", err), http.StatusInternalServerError)
		return
	}
	if err := a.pollBindingsOnce(r.Context()); err != nil {
		a.audit("bindings_initial_fetch_error", map[string]any{"error": err.Error()})
	}
	if err := a.pollDesiredStateOnce(r.Context()); err != nil {
		a.audit("desired_state_initial_fetch_error", map[string]any{"error": err.Error()})
	}

	a.audit("claimed", map[string]any{
		"agent_id":       claim.AgentID,
		"org_id":         claim.OrgID,
		"schema_version": claim.SchemaVersion,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                    "claimed",
		"agent_id":                  claim.AgentID,
		"org_id":                    claim.OrgID,
		"schema_version":            claim.SchemaVersion,
		"supported_schema_versions": claim.SupportedSchemaVersions,
	})
}

func (a *agent) claimWithSaaS(controlPlaneURL, apiKey string) (claimResponse, error) {
	payload := claimRequest{
		Hostname:     hostnameOrUnknown(),
		Fingerprint:  hostnameOrUnknown(),
		AgentVersion: agentVersion,
		Capabilities: a.buildClaimCapabilities(),
	}

	var out claimResponse
	endpoint := strings.TrimSuffix(controlPlaneURL, "/") + "/edge/agents/claim"
	if err := doJSONRequest(a.client, http.MethodPost, endpoint, apiKey, "", payload, &out, map[string]string{
		"X-Agent-Schema-Version": schemaVersionHeaderValue(),
	}); err != nil {
		return claimResponse{}, err
	}
	if out.AgentID == "" {
		return claimResponse{}, errors.New("claim response missing agent_id")
	}
	if out.SchemaVersion <= 0 {
		return claimResponse{}, errors.New("claim response missing schema_version")
	}
	if len(out.SupportedSchemaVersions) == 0 {
		out.SupportedSchemaVersions = []int{out.SchemaVersion}
	}
	if !supportsSchemaVersion(agentSchemaVersion, out.SupportedSchemaVersions) {
		return claimResponse{}, fmt.Errorf(
			"agent schema_version=%d not supported by control-plane supported_schema_versions=%v",
			agentSchemaVersion,
			out.SupportedSchemaVersions,
		)
	}
	if !supportsSchemaVersion(out.SchemaVersion, out.SupportedSchemaVersions) {
		return claimResponse{}, fmt.Errorf(
			"claim response incompatible: schema_version=%d not in supported_schema_versions=%v",
			out.SchemaVersion,
			out.SupportedSchemaVersions,
		)
	}
	return out, nil
}

func (a *agent) buildClaimCapabilities() map[string]string {
	discoveryAllowedAdapters := a.cfg.DiscoveryAllowedAdapters
	if len(discoveryAllowedAdapters) == 0 {
		discoveryAllowedAdapters = []string{"moonraker"}
	}
	enabledAdapters := strings.Join(discoveryAllowedAdapters, ",")
	bambuAuthReady := a.isBambuAuthReady()
	return map[string]string{
		"adapter_family":             "klipper",
		"discovery_profile_max":      parseDiscoveryProfile(a.cfg.DiscoveryProfileMax),
		"discovery_network_mode":     parseDiscoveryNetworkMode(a.cfg.DiscoveryNetworkMode),
		"discovery_allowed_adapters": enabledAdapters,
		"enabled_adapters":           enabledAdapters,
		"bambu_enabled":              strconv.FormatBool(a.cfg.EnableBambu),
		"bambu_auth_ready":           strconv.FormatBool(bambuAuthReady),
	}
}

func hostnameOrUnknown() string {
	hn, err := os.Hostname()
	if err != nil || strings.TrimSpace(hn) == "" {
		return "unknown-host"
	}
	return hn
}

func (a *agent) bindingsPollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.cfg.BindingsPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.pollBindingsOnce(ctx); err != nil {
				a.audit("bindings_poll_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pollBindingsOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/bindings",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("bindings", resp.StatusCode, string(body))
			return fmt.Errorf("%w: bindings returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("bindings returned %d: %s", resp.StatusCode, string(body))
	}

	var payload bindingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	next := make(map[int]edgeBinding, len(payload.Bindings))
	for _, item := range payload.Bindings {
		next[item.PrinterID] = item
	}

	a.mu.Lock()
	a.bindings = next
	for printerID := range a.currentState {
		if _, exists := next[printerID]; exists {
			continue
		}
		delete(a.currentState, printerID)
		delete(a.desiredState, printerID)
		delete(a.actionQueue, printerID)
		delete(a.deadLetters, printerID)
		delete(a.queuedSince, printerID)
		delete(a.breakerUntil, printerID)
	}
	a.mu.Unlock()

	a.audit("bindings_updated", map[string]any{"binding_count": len(payload.Bindings)})
	return nil
}

func (a *agent) desiredStatePollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.cfg.DesiredStatePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.pollDesiredStateOnce(ctx); err != nil {
				a.audit("desired_state_poll_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pollDesiredStateOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/desired-state",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	a.mu.RLock()
	if a.lastETag != "" {
		req.Header.Set("If-None-Match", a.lastETag)
	}
	a.mu.RUnlock()

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("desired_state", resp.StatusCode, string(body))
			return fmt.Errorf("%w: desired-state returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("desired-state returned %d: %s", resp.StatusCode, string(body))
	}

	var payload desiredStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if !supportsSchemaVersion(payload.SchemaVersion, agentSupportedSchemaVersions) {
		return fmt.Errorf(
			"desired-state schema_version=%d unsupported by agent supported_schema_versions=%v",
			payload.SchemaVersion,
			agentSupportedSchemaVersions,
		)
	}

	next := make(map[int]desiredStateItem, len(payload.States))
	for _, item := range payload.States {
		next[item.PrinterID] = item
	}

	a.mu.Lock()
	a.desiredState = next
	if etag := strings.TrimSpace(resp.Header.Get("ETag")); etag != "" {
		a.lastETag = normalizeETag(etag)
	}
	a.mu.Unlock()

	a.audit("desired_state_updated", map[string]any{
		"state_count": len(payload.States),
		"etag":        strings.TrimSpace(resp.Header.Get("ETag")),
	})
	return nil
}

func (a *agent) convergenceLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.cfg.ConvergenceTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			a.reconcileOnce()
			if a.consumeResyncRequest() {
				if err := a.pollDesiredStateOnce(ctx); err != nil {
					a.audit("queued_stale_resync_desired_state_error", map[string]any{"error": err.Error()})
				}
				if err := a.pollBindingsOnce(ctx); err != nil {
					a.audit("queued_stale_resync_bindings_error", map[string]any{"error": err.Error()})
				}
				a.refreshCurrentStateFromBindings(ctx)
			}
		}
	}
}

func (a *agent) reconcileOnce() {
	var staleQueuedEvents []map[string]any
	a.mu.Lock()
	now := time.Now().UTC()
	pruneRecentEnqueueLocked(a.recentEnqueue, now)
	pruneSuppressedActionsLocked(a.suppressedUntil, now)
	for printerID := range a.actionQueue {
		if _, exists := a.desiredState[printerID]; exists {
			continue
		}
		delete(a.actionQueue, printerID)
		delete(a.queuedSince, printerID)
	}

	for printerID, desired := range a.desiredState {
		a.actionQueue[printerID] = pruneQueueForIntentLocked(a.actionQueue[printerID], desired.IntentVersion)

		current := a.currentState[printerID]
		if current.PrinterID == 0 {
			current.PrinterID = printerID
			current.CurrentPrinterState = "idle"
			current.ReportedAt = now
		}

		if current.CurrentPrinterState == desired.DesiredPrinterState && current.IntentVersionApplied >= desired.IntentVersion {
			continue
		}

		// Desired printing while printer reports queued is a wait-only state.
		if desired.DesiredPrinterState == "printing" && current.CurrentPrinterState == "queued" && current.LastErrorCode != "connectivity_error" {
			queuedSince, ok := a.queuedSince[printerID]
			if !ok {
				queuedSince = now
				a.queuedSince[printerID] = queuedSince
			}
			if now.Sub(queuedSince) > 30*time.Second {
				current.LastErrorCode = "queued_stale"
				current.LastErrorMessage = "queued state exceeded 30s without printing transition"
				current.ReportedAt = now
				a.currentState[printerID] = current
				a.resyncRequested = true
				staleQueuedEvents = append(staleQueuedEvents, map[string]any{
					"printer_id":      printerID,
					"intent_version":  desired.IntentVersion,
					"queued_since_at": queuedSince,
				})
			}
			continue
		}

		if desired.DesiredPrinterState == "printing" {
			if strings.TrimSpace(desired.ArtifactURL) == "" {
				current.CurrentPrinterState = "error"
				current.LastErrorCode = "artifact_fetch_error"
				current.LastErrorMessage = "missing artifact_url for printing intent"
				current.ReportedAt = now
				a.currentState[printerID] = current
				continue
			}
		}

		kind := mapDesiredToAction(current.CurrentPrinterState, desired.DesiredPrinterState)
		switch kind {
		case "noop":
			continue
		case "invalid":
			fromState := current.CurrentPrinterState
			current.CurrentPrinterState = "error"
			current.LastErrorCode = "validation_error"
			current.LastErrorMessage = fmt.Sprintf(
				"cannot converge from %s to desired %s",
				fromState,
				desired.DesiredPrinterState,
			)
			current.ReportedAt = now
			a.currentState[printerID] = current
			continue
		}

		if _, hasBinding := a.bindings[printerID]; !hasBinding {
			current.CurrentPrinterState = "error"
			current.LastErrorCode = "connectivity_error"
			current.LastErrorMessage = "missing printer binding for desired state"
			current.ReportedAt = now
			a.currentState[printerID] = current
			continue
		}

		if hasQueuedActionLocked(a.actionQueue[printerID], kind, desired.IntentVersion) {
			continue
		}
		if isBreakerOpenLocked(a.breakerUntil, printerID, now) {
			continue
		}
		suppressedKey := actionThrottleKey(printerID, kind, desired)
		if isActionSuppressedLocked(a.suppressedUntil, suppressedKey, now) {
			continue
		}
		if !allowEnqueueLocked(a.recentEnqueue, printerID, kind, desired, now) {
			continue
		}

		a.actionQueue[printerID] = append(a.actionQueue[printerID], action{
			PrinterID:   printerID,
			Kind:        kind,
			Reason:      fmt.Sprintf("converge %s -> %s", current.CurrentPrinterState, desired.DesiredPrinterState),
			Target:      desired,
			EnqueuedAt:  now,
			Attempts:    0,
			NextAttempt: now,
		})
	}

	a.mu.Unlock()
	for _, payload := range staleQueuedEvents {
		a.audit("queued_stale", payload)
	}
}

func mapDesiredToAction(current, desired string) string {
	switch desired {
	case "printing":
		switch current {
		case "paused":
			return "resume"
		case "printing", "queued":
			return "noop"
		default:
			return "print"
		}
	case "paused":
		switch current {
		case "printing":
			return "pause"
		case "paused":
			return "noop"
		default:
			return "invalid"
		}
	case "idle":
		switch current {
		case "printing", "paused", "queued":
			return "stop"
		default:
			return "noop"
		}
	default:
		return "invalid"
	}
}

func hasQueuedActionLocked(queue []action, kind string, intentVersion int) bool {
	for _, item := range queue {
		if item.Kind == kind && item.Target.IntentVersion == intentVersion {
			return true
		}
	}
	return false
}

func pruneQueueForIntentLocked(queue []action, minIntentVersion int) []action {
	if len(queue) == 0 {
		return queue
	}
	next := make([]action, 0, len(queue))
	for _, item := range queue {
		if item.Target.IntentVersion >= minIntentVersion {
			next = append(next, item)
		}
	}
	return next
}

func actionThrottleKey(printerID int, kind string, desired desiredStateItem) string {
	return fmt.Sprintf("%d:%s:%d:%s:%d", printerID, kind, desired.IntentVersion, desired.JobID, desired.PlateID)
}

func allowEnqueueLocked(recent map[string]time.Time, printerID int, kind string, desired desiredStateItem, now time.Time) bool {
	key := actionThrottleKey(printerID, kind, desired)
	if lastSeen, ok := recent[key]; ok && now.Sub(lastSeen) < 2*time.Second {
		return false
	}
	recent[key] = now
	return true
}

func pruneRecentEnqueueLocked(recent map[string]time.Time, now time.Time) {
	for key, enqueueAt := range recent {
		if now.Sub(enqueueAt) > 10*time.Second {
			delete(recent, key)
		}
	}
}

func isActionSuppressedLocked(suppressed map[string]time.Time, key string, now time.Time) bool {
	until, ok := suppressed[key]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(suppressed, key)
		return false
	}
	return true
}

func pruneSuppressedActionsLocked(suppressed map[string]time.Time, now time.Time) {
	for key, until := range suppressed {
		if now.After(until) {
			delete(suppressed, key)
		}
	}
}

func isBreakerOpenLocked(breakerUntil map[int]time.Time, printerID int, now time.Time) bool {
	until, ok := breakerUntil[printerID]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(breakerUntil, printerID)
		return false
	}
	return true
}

func (a *agent) actionExecLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.cfg.ActionExecInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.executeNextAction(ctx); err != nil {
				a.audit("action_exec_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) executeNextAction(ctx context.Context) error {
	queuedAction, binding, ok := a.dequeueNextAction()
	if !ok {
		return nil
	}

	if strings.TrimSpace(binding.EndpointURL) == "" {
		a.handleActionFailure(queuedAction, "connectivity_error", "missing endpoint_url in printer binding", true)
		return nil
	}

	if err := a.executeAction(ctx, queuedAction, binding); err != nil {
		code, retryable := classifyActionError(err)
		if code == "connectivity_error" {
			if a.tryRecoverUncertainConnectivityAction(ctx, queuedAction, binding) {
				return nil
			}
		}
		a.handleActionFailure(queuedAction, code, err.Error(), retryable)
		return nil
	}
	a.markActionSuccess(queuedAction)
	return nil
}

func (a *agent) tryRecoverUncertainConnectivityAction(ctx context.Context, queuedAction action, binding edgeBinding) bool {
	if queuedAction.Kind != "print" {
		return false
	}
	if strings.TrimSpace(binding.EndpointURL) == "" {
		return false
	}

	probeTimeout := a.cfg.MoonrakerRequestTimeout
	if probeTimeout < 250*time.Millisecond {
		probeTimeout = 250 * time.Millisecond
	}
	family := normalizeAdapterFamily(binding.AdapterFamily)
	var (
		printerState    string
		jobState        string
		telemetrySource string
		err             error
	)
	switch family {
	case "moonraker":
		printerState, jobState, err = a.fetchMoonrakerSnapshotWithTimeout(ctx, binding.EndpointURL, probeTimeout)
		telemetrySource = "moonraker"
	case "bambu":
		requestCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		snapshot, fetchErr := a.fetchBambuCloudSnapshotFromEndpoint(requestCtx, binding.EndpointURL)
		if fetchErr != nil {
			return false
		}
		printerState = snapshot.PrinterState
		jobState = snapshot.JobState
		telemetrySource = snapshot.TelemetrySource
	default:
		return false
	}
	if err != nil {
		return false
	}
	if printerState != "printing" && printerState != "queued" && printerState != "paused" {
		return false
	}
	if strings.TrimSpace(telemetrySource) == "" {
		telemetrySource = family
	}

	now := time.Now().UTC()
	a.mu.Lock()
	current := a.currentState[queuedAction.PrinterID]
	current.PrinterID = queuedAction.PrinterID
	current.CurrentPrinterState = printerState
	current.CurrentJobState = jobState
	current.JobID = queuedAction.Target.JobID
	current.PlateID = queuedAction.Target.PlateID
	current.IntentVersionApplied = queuedAction.Target.IntentVersion
	current.IsPaused = printerState == "paused"
	current.IsCanceled = jobState == "canceled"
	current.LastErrorCode = ""
	current.LastErrorMessage = ""
	current.ProgressPct = nil
	current.RemainingSeconds = nil
	current.TelemetrySource = telemetrySource
	current.ManualIntervention = ""
	current.ReportedAt = now
	a.currentState[queuedAction.PrinterID] = current
	if printerState == "queued" {
		if _, exists := a.queuedSince[queuedAction.PrinterID]; !exists {
			a.queuedSince[queuedAction.PrinterID] = now
		}
	} else {
		delete(a.queuedSince, queuedAction.PrinterID)
	}
	delete(a.breakerUntil, queuedAction.PrinterID)
	a.mu.Unlock()

	a.audit("uncertain_action_resolved", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"kind":           queuedAction.Kind,
		"resolved_state": printerState,
		"intent_version": queuedAction.Target.IntentVersion,
	})
	return true
}

func (a *agent) dequeueNextAction() (action, edgeBinding, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.actionQueue) == 0 {
		return action{}, edgeBinding{}, false
	}

	printerIDs := make([]int, 0, len(a.actionQueue))
	for printerID := range a.actionQueue {
		printerIDs = append(printerIDs, printerID)
	}
	sort.Ints(printerIDs)

	for _, printerID := range printerIDs {
		if isBreakerOpenLocked(a.breakerUntil, printerID, time.Now().UTC()) {
			continue
		}
		queue := a.actionQueue[printerID]
		if len(queue) == 0 {
			delete(a.actionQueue, printerID)
			continue
		}

		now := time.Now().UTC()
		idx := -1
		for i, candidate := range queue {
			if candidate.NextAttempt.IsZero() || !candidate.NextAttempt.After(now) {
				idx = i
				break
			}
		}
		if idx == -1 {
			continue
		}

		next := queue[idx]
		queue = append(queue[:idx], queue[idx+1:]...)
		if len(queue) == 0 {
			delete(a.actionQueue, printerID)
		} else {
			a.actionQueue[printerID] = queue
		}
		return next, a.bindings[printerID], true
	}

	return action{}, edgeBinding{}, false
}

func (a *agent) handleActionFailure(queuedAction action, errorCode, message string, retryable bool) {
	if retryable && queuedAction.Attempts < a.cfg.ActionMaxAttempts {
		a.requeueActionWithBackoff(queuedAction, errorCode, message)
		return
	}
	if !retryable {
		a.suppressActionReenqueue(queuedAction, errorCode, message)
	}
	a.moveToDeadLetter(queuedAction, errorCode, message)
	a.markActionFailure(queuedAction, errorCode, message)
}

func (a *agent) requeueActionWithBackoff(queuedAction action, errorCode, message string) {
	attempt := queuedAction.Attempts + 1
	backoff := a.cfg.ActionRetryBaseInterval
	for i := 1; i < attempt; i++ {
		backoff *= 2
	}
	queuedAction.Attempts = attempt
	queuedAction.NextAttempt = time.Now().UTC().Add(backoff)

	a.mu.Lock()
	a.actionQueue[queuedAction.PrinterID] = append([]action{queuedAction}, a.actionQueue[queuedAction.PrinterID]...)
	a.mu.Unlock()

	a.audit("action_retry_scheduled", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"kind":            queuedAction.Kind,
		"attempt":         queuedAction.Attempts,
		"next_attempt_at": queuedAction.NextAttempt,
		"error_code":      errorCode,
		"error_message":   message,
	})
}

func (a *agent) suppressActionReenqueue(queuedAction action, errorCode, message string) {
	cooldown := a.cfg.ActionNonRetryableCooldown
	if cooldown <= 0 {
		return
	}
	suppressedKey := actionThrottleKey(queuedAction.PrinterID, queuedAction.Kind, queuedAction.Target)
	suppressedUntil := time.Now().UTC().Add(cooldown)
	a.mu.Lock()
	currentUntil, exists := a.suppressedUntil[suppressedKey]
	if !exists || currentUntil.Before(suppressedUntil) {
		a.suppressedUntil[suppressedKey] = suppressedUntil
	}
	a.mu.Unlock()
	a.audit("action_reenqueue_suppressed", map[string]any{
		"printer_id":       queuedAction.PrinterID,
		"kind":             queuedAction.Kind,
		"intent_version":   queuedAction.Target.IntentVersion,
		"error_code":       errorCode,
		"error_message":    message,
		"suppressed_until": suppressedUntil,
	})
}

func (a *agent) moveToDeadLetter(queuedAction action, errorCode, message string) {
	a.mu.Lock()
	a.deadLetters[queuedAction.PrinterID] = append(a.deadLetters[queuedAction.PrinterID], queuedAction)
	if errorCode == "connectivity_error" || errorCode == "printer_busy" {
		a.breakerUntil[queuedAction.PrinterID] = time.Now().UTC().Add(a.cfg.CircuitBreakerCooldown)
	}
	a.mu.Unlock()
	a.audit("action_dead_lettered", map[string]any{
		"printer_id":    queuedAction.PrinterID,
		"kind":          queuedAction.Kind,
		"attempts":      queuedAction.Attempts,
		"error_code":    errorCode,
		"error_message": message,
		"breaker_until": a.snapshotBreakerUntil(queuedAction.PrinterID),
	})
}

func (a *agent) executeAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	family := normalizeAdapterFamily(binding.AdapterFamily)
	if family == "moonraker" && !a.cfg.EnableKlipper {
		return errors.New("validation_error: adapter_family moonraker is disabled (set --klipper to enable)")
	}
	if family == "bambu" && !a.cfg.EnableBambu {
		return errors.New("validation_error: adapter_family bambu is disabled (set --bambu to enable)")
	}

	switch family {
	case "moonraker":
		return a.executeMoonrakerAction(ctx, queuedAction, binding)
	case "bambu":
		return a.executeBambuCloudAction(ctx, queuedAction, binding)
	default:
		return fmt.Errorf("validation_error: unsupported adapter_family: %s", family)
	}
}

func normalizeAdapterFamily(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" || normalized == "klipper" {
		return "moonraker"
	}
	return normalized
}

func isSupportedDiscoveryAdapter(adapterFamily string, klipperEnabled bool, bambuEnabled bool) bool {
	switch normalizeAdapterFamily(adapterFamily) {
	case "moonraker":
		return klipperEnabled
	case "bambu":
		return bambuEnabled
	default:
		return false
	}
}

func (a *agent) executeMoonrakerAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	switch queuedAction.Kind {
	case "print":
		return a.executePrintAction(ctx, queuedAction, binding)
	case "pause":
		return a.callMoonrakerPost(ctx, binding.EndpointURL, "/printer/print/pause", nil)
	case "resume":
		return a.callMoonrakerPost(ctx, binding.EndpointURL, "/printer/print/resume", nil)
	case "stop":
		return a.callMoonrakerPost(ctx, binding.EndpointURL, "/printer/print/cancel", nil)
	default:
		return fmt.Errorf("unsupported action kind: %s", queuedAction.Kind)
	}
}

func (a *agent) executeBambuCloudAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	exec := func(token string) error {
		return a.executeBambuCloudActionWithToken(ctx, queuedAction, binding, token)
	}
	return a.executeWithBambuTokenRetry(ctx, exec)
}

func (a *agent) executeBambuCloudActionWithToken(ctx context.Context, queuedAction action, binding edgeBinding, accessToken string) error {
	switch queuedAction.Kind {
	case "print":
		return a.executeBambuCloudPrintAction(ctx, queuedAction, binding, accessToken)
	case "pause":
		return a.executeBambuCloudControlAction(ctx, queuedAction, binding, accessToken, "pause")
	case "resume":
		return a.executeBambuCloudControlAction(ctx, queuedAction, binding, accessToken, "resume")
	case "stop":
		return a.executeBambuCloudControlAction(ctx, queuedAction, binding, accessToken, "stop")
	default:
		return fmt.Errorf("unsupported action kind: %s", queuedAction.Kind)
	}
}

func (a *agent) executeWithBambuTokenRetry(ctx context.Context, op func(accessToken string) error) error {
	accessToken, err := a.ensureBambuAccessToken(ctx)
	if err != nil {
		return err
	}
	if err := op(accessToken); err != nil {
		if !errors.Is(err, bambuauth.ErrInvalidCredentials) {
			return err
		}
		if authErr := a.initializeBambuAuth(ctx); authErr != nil {
			return authErr
		}
		accessToken, tokenErr := a.ensureBambuAccessToken(ctx)
		if tokenErr != nil {
			return tokenErr
		}
		return op(accessToken)
	}
	return nil
}

func (a *agent) ensureBambuAccessToken(ctx context.Context) (string, error) {
	state := a.snapshotBambuAuthState()
	if strings.TrimSpace(state.AccessToken) != "" && state.Ready && state.ExpiresAt.After(time.Now().UTC().Add(60*time.Second)) {
		return strings.TrimSpace(state.AccessToken), nil
	}
	if err := a.initializeBambuAuth(ctx); err != nil {
		return "", err
	}
	state = a.snapshotBambuAuthState()
	if !state.Ready || strings.TrimSpace(state.AccessToken) == "" {
		return "", errBambuAuthUnavailable
	}
	return strings.TrimSpace(state.AccessToken), nil
}

func (a *agent) executeBambuCloudPrintAction(ctx context.Context, queuedAction action, binding edgeBinding, accessToken string) error {
	printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
	if err != nil {
		return err
	}
	provider, err := a.bambuCloudActionProvider()
	if err != nil {
		return err
	}

	localPath, remoteName, err := a.downloadArtifact(ctx, queuedAction.Target)
	if err != nil {
		return err
	}
	defer a.cleanupArtifact(localPath)

	fileBytes, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}

	a.audit("artifact_downloaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})

	uploadURLs, err := provider.GetUploadURLs(ctx, accessToken, remoteName, int64(len(fileBytes)))
	if err != nil {
		return err
	}
	if err := provider.UploadToSignedURLs(ctx, uploadURLs, fileBytes); err != nil {
		return err
	}

	a.audit("artifact_uploaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})

	fileURL := strings.TrimSpace(uploadURLs.FileURL)
	if fileURL == "" {
		return errors.New("validation_error: bambu upload response missing file_url")
	}
	fileName := strings.TrimSpace(uploadURLs.FileName)
	if fileName == "" {
		fileName = remoteName
	}
	startTransport := "cloud_http"
	startReq := bambucloud.CloudPrintStartRequest{
		DeviceID: strings.TrimSpace(printerID),
		FileName: fileName,
		FileURL:  fileURL,
		FileID:   strings.TrimSpace(uploadURLs.FileID),
	}
	if err := provider.StartPrintJob(ctx, accessToken, startReq); err != nil {
		if !errors.Is(err, bambucloud.ErrPrintStartUnsupported) {
			return err
		}
		startTransport = "mqtt_fallback"
		a.audit("bambu_print_start_http_unsupported", map[string]any{
			"printer_id":     queuedAction.PrinterID,
			"job_id":         queuedAction.Target.JobID,
			"plate_id":       queuedAction.Target.PlateID,
			"endpoint_url":   binding.EndpointURL,
			"print_path":     strings.TrimSpace(a.cfg.BambuCloudPrintPath),
			"error_message":  err.Error(),
			"adapter_family": "bambu",
		})
		mqttParam := map[string]any{
			"file_name": fileName,
			"file_url":  fileURL,
		}
		if fileID := strings.TrimSpace(uploadURLs.FileID); fileID != "" {
			mqttParam["file_id"] = fileID
		}
		if err := a.publishBambuCloudMQTTCommand(
			ctx,
			provider,
			accessToken,
			strings.TrimSpace(printerID),
			"start",
			mqttParam,
		); err != nil {
			return fmt.Errorf("bambu print start fallback mqtt failed: %w", err)
		}
	}
	a.audit("bambu_print_start_dispatch_attempt", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       fileName,
		"transport":      startTransport,
		"adapter_family": "bambu",
	})
	if err := a.verifyBambuPrintStart(ctx, strings.TrimSpace(printerID)); err != nil {
		return err
	}
	a.audit("bambu_print_start_verified", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       fileName,
		"transport":      startTransport,
		"adapter_family": "bambu",
	})

	a.audit("print_start_requested", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        fileName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
		"transport":       startTransport,
	})
	return nil
}

func (a *agent) executeBambuCloudControlAction(
	ctx context.Context,
	queuedAction action,
	binding edgeBinding,
	accessToken string,
	command string,
) error {
	printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
	if err != nil {
		return err
	}
	provider, err := a.bambuCloudActionProvider()
	if err != nil {
		return err
	}
	if err := a.publishBambuCloudMQTTCommand(ctx, provider, accessToken, strings.TrimSpace(printerID), command, nil); err != nil {
		return err
	}
	return a.verifyBambuControlAction(ctx, strings.TrimSpace(printerID), command)
}

func (a *agent) publishBambuCloudMQTTCommand(
	ctx context.Context,
	provider bambuCloudDeviceLister,
	accessToken string,
	printerID string,
	command string,
	param map[string]any,
) error {
	trimmedPrinterID := strings.TrimSpace(printerID)
	if trimmedPrinterID == "" {
		return errors.New("validation_error: missing bambu printer identifier")
	}
	if provider == nil {
		return errors.New("validation_error: bambu cloud provider does not support device listing")
	}

	devices, err := provider.ListBoundDevices(ctx, accessToken)
	if err != nil {
		return err
	}
	device, ok := findBambuCloudDeviceByID(devices, trimmedPrinterID)
	if !ok {
		return fmt.Errorf("bambu cloud device %q is not bound to this account", trimmedPrinterID)
	}
	if !device.Online {
		return fmt.Errorf("connection error: bambu cloud device %q is offline", trimmedPrinterID)
	}
	accessCode := strings.TrimSpace(device.AccessCode)
	if accessCode == "" {
		return fmt.Errorf("validation_error: bambu cloud device %q is missing access code", trimmedPrinterID)
	}

	username, usernameSource, err := a.resolveBambuMQTTUsername(accessToken)
	if err != nil {
		return err
	}
	a.audit("bambu_mqtt_username_resolved", map[string]any{
		"printer_id":     trimmedPrinterID,
		"command":        command,
		"source":         usernameSource,
		"adapter_family": "bambu",
	})
	a.updateBambuMQTTUsername(ctx, username)
	topic := strings.TrimSpace(a.cfg.BambuCloudMQTTTopicTemplate)
	if topic == "" {
		topic = defaultBambuMQTTTopic
	}
	if strings.Contains(topic, "%s") {
		topic = fmt.Sprintf(topic, trimmedPrinterID)
	}
	if strings.TrimSpace(topic) == "" {
		return errors.New("validation_error: bambu mqtt topic is empty")
	}

	brokerAddr := strings.TrimSpace(a.cfg.BambuCloudMQTTBroker)
	if brokerAddr == "" {
		brokerAddr = defaultBambuCloudMQTTBroker(a.cfg.BambuCloudAuthBaseURL)
	}
	publisher := a.bambuMQTTPublish
	if publisher == nil {
		publisher = defaultBambuPrintCommandPublisher{}
	}
	return publisher.PublishPrintCommand(ctx, bambuMQTTCommandRequest{
		BrokerAddr: brokerAddr,
		Topic:      topic,
		Username:   username,
		Password:   accessCode,
		Command:    command,
		Param:      param,
	})
}

func (a *agent) resolveBambuMQTTUsername(accessToken string) (string, string, error) {
	tokenUsername, tokenErr := bambuMQTTUsernameFromAccessToken(accessToken)
	if tokenErr != nil {
		return "", "", fmt.Errorf("validation_error: unable to resolve bambu mqtt username from access token (%v)", tokenErr)
	}
	return tokenUsername, "token_claim", nil
}

func (a *agent) updateBambuMQTTUsername(ctx context.Context, username string) {
	trimmedUsername := strings.TrimSpace(username)
	if trimmedUsername == "" {
		return
	}

	authState := a.snapshotBambuAuthState()
	if strings.EqualFold(strings.TrimSpace(authState.MQTTUsername), trimmedUsername) {
		return
	}
	authState.MQTTUsername = trimmedUsername
	a.setBambuAuthState(authState)

	if a.bambuAuthStore == nil {
		return
	}
	credentials, err := a.bambuAuthStore.Load(ctx)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		a.audit("bambu_mqtt_username_load_error", map[string]any{
			"error": err.Error(),
		})
		return
	}
	if errors.Is(err, os.ErrNotExist) {
		credentials = bambustore.BambuCredentials{}
	}
	if strings.EqualFold(strings.TrimSpace(credentials.MQTTUsername), trimmedUsername) {
		return
	}

	credentials.MQTTUsername = trimmedUsername
	if strings.TrimSpace(credentials.AccessToken) == "" {
		credentials.AccessToken = strings.TrimSpace(authState.AccessToken)
	}
	if credentials.ExpiresAt.IsZero() {
		credentials.ExpiresAt = authState.ExpiresAt
	}
	if strings.TrimSpace(credentials.Username) == "" {
		credentials.Username = strings.TrimSpace(authState.Username)
	}
	if strings.TrimSpace(credentials.MaskedEmail) == "" {
		credentials.MaskedEmail = strings.TrimSpace(authState.MaskedEmail)
	}
	if strings.TrimSpace(credentials.MaskedPhone) == "" {
		credentials.MaskedPhone = strings.TrimSpace(authState.MaskedPhone)
	}
	if strings.TrimSpace(credentials.AccountDisplayName) == "" {
		credentials.AccountDisplayName = strings.TrimSpace(authState.DisplayName)
	}
	if strings.TrimSpace(credentials.AccessToken) == "" || credentials.ExpiresAt.IsZero() {
		return
	}
	if err := a.bambuAuthStore.Save(ctx, credentials); err != nil {
		a.audit("bambu_mqtt_username_persist_error", map[string]any{
			"error": err.Error(),
		})
	}
}

func bambuMQTTUsernameFromUploadURLs(uploadURLs bambucloud.CloudUploadURLs) string {
	for _, rawURL := range []string{uploadURLs.UploadFileURL, uploadURLs.FileURL, uploadURLs.UploadSizeURL} {
		if username := bambuMQTTUsernameFromUploadURL(rawURL); username != "" {
			return username
		}
	}
	return ""
}

func bambuMQTTUsernameFromUploadURL(rawURL string) string {
	trimmedURL := strings.TrimSpace(rawURL)
	if trimmedURL == "" {
		return ""
	}
	parsed, err := url.Parse(trimmedURL)
	if err != nil {
		return ""
	}
	path := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	for i := 0; i < len(parts)-1; i++ {
		if !strings.EqualFold(strings.TrimSpace(parts[i]), "users") {
			continue
		}
		username := strings.TrimSpace(parts[i+1])
		if username != "" {
			return username
		}
	}
	return ""
}

func (a *agent) verifyBambuPrintStart(ctx context.Context, printerID string) error {
	timeout := a.cfg.MoonrakerRequestTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}
	deadline := time.Now().UTC().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().UTC().After(deadline) {
			return fmt.Errorf("connection error: bambu print start verification timeout after %s", timeout)
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		snapshot, err := a.fetchBambuCloudSnapshotByPrinterID(requestCtx, printerID)
		cancel()
		if err == nil && matchesBambuPrintStartExpectation(snapshot.PrinterState, snapshot.JobState) {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func matchesBambuPrintStartExpectation(printerState string, jobState string) bool {
	return printerState == "printing" || printerState == "queued" || (printerState == "paused" && jobState == "printing")
}

func (a *agent) verifyBambuControlAction(ctx context.Context, printerID string, command string) error {
	timeout := a.cfg.MoonrakerRequestTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}
	deadline := time.Now().UTC().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().UTC().After(deadline) {
			return fmt.Errorf("bambu command verification timeout after %s", timeout)
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		snapshot, err := a.fetchBambuCloudSnapshotByPrinterID(requestCtx, printerID)
		cancel()
		if err == nil && matchesBambuControlExpectation(snapshot.PrinterState, snapshot.JobState, command) {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func matchesBambuControlExpectation(printerState string, jobState string, command string) bool {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "pause":
		return printerState == "paused"
	case "resume":
		return printerState == "printing" || printerState == "queued"
	case "stop":
		return printerState == "idle" || jobState == "canceled"
	default:
		return false
	}
}

func findBambuCloudDeviceByID(devices []bambucloud.CloudDevice, printerID string) (bambucloud.CloudDevice, bool) {
	trimmedID := strings.TrimSpace(printerID)
	for _, device := range devices {
		if strings.EqualFold(strings.TrimSpace(device.DeviceID), trimmedID) {
			return device, true
		}
	}
	return bambucloud.CloudDevice{}, false
}

func bambuMQTTUsernameFromAccessToken(accessToken string) (string, error) {
	claims, err := parseJWTPayloadClaims(accessToken)
	if err != nil {
		return "", err
	}
	for _, key := range []string{"user_id", "uid", "sub"} {
		raw, ok := claims[key]
		if !ok {
			continue
		}
		value := strings.TrimSpace(claimValueToString(raw))
		if value != "" {
			return value, nil
		}
	}
	return "", errors.New("validation_error: bambu access token missing user identifier claim")
}

func parseJWTPayloadClaims(accessToken string) (map[string]any, error) {
	token := strings.TrimSpace(accessToken)
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("validation_error: invalid bambu access token format")
	}
	payload := strings.TrimSpace(parts[1])
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return nil, fmt.Errorf("validation_error: decode bambu access token payload: %w", err)
		}
	}
	claims := map[string]any{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("validation_error: parse bambu access token payload: %w", err)
	}
	return claims, nil
}

func claimValueToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	case float32:
		return strconv.FormatInt(int64(typed), 10)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

func (a *agent) executePrintAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	localPath, remoteName, err := a.downloadArtifact(ctx, queuedAction.Target)
	if err != nil {
		return err
	}
	defer a.cleanupArtifact(localPath)
	a.audit("artifact_downloaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteName,
		"adapter_family":  "moonraker",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})

	if err := a.uploadArtifact(ctx, binding.EndpointURL, localPath, remoteName); err != nil {
		return err
	}
	a.audit("artifact_uploaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteName,
		"adapter_family":  "moonraker",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})
	startPayload := map[string]string{"filename": remoteName}
	if err := a.callMoonrakerPost(ctx, binding.EndpointURL, "/printer/print/start", startPayload); err != nil {
		return err
	}
	a.audit("print_start_requested", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        remoteName,
		"adapter_family":  "moonraker",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})
	return nil
}

func (a *agent) callMoonrakerPost(ctx context.Context, endpointURL, path string, payload any) error {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	body := bytes.NewBuffer(nil)
	if payload != nil {
		if err := json.NewEncoder(body).Encode(payload); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, resolveURL(endpointURL, path), body)
	if err != nil {
		return err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("moonraker %s failed: status=%d body=%s", path, resp.StatusCode, string(msg))
	}
	return nil
}

func (a *agent) uploadArtifact(ctx context.Context, endpointURL, localPath, remoteName string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if err := writer.WriteField("root", "gcodes"); err != nil {
		return err
	}
	part, err := writer.CreateFormFile("file", remoteName)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, f); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	// Apply timeout only to network I/O; multipart encoding time should not consume request budget.
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.ArtifactUploadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodPost,
		resolveURL(endpointURL, "/server/files/upload"),
		bytes.NewReader(body.Bytes()),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := a.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("moonraker upload timeout after %s", a.cfg.ArtifactUploadTimeout)
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("moonraker upload failed: status=%d body=%s", resp.StatusCode, string(msg))
	}
	return nil
}

func (a *agent) downloadArtifact(ctx context.Context, desired desiredStateItem) (string, string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.ArtifactDownloadTimeout)
	defer cancel()

	artifactURL := strings.TrimSpace(desired.ArtifactURL)
	if artifactURL == "" {
		return "", "", errors.New("artifact_fetch_error: missing artifact_url")
	}
	bootstrap := a.snapshotBootstrap()
	if strings.HasPrefix(artifactURL, "/") {
		artifactURL = strings.TrimSuffix(bootstrap.ControlPlaneURL, "/") + artifactURL
	}
	if err := os.MkdirAll(a.cfg.ArtifactStageDir, 0o755); err != nil {
		return "", "", err
	}
	ok, err := hasMinFreeSpace(a.cfg.ArtifactStageDir, 1<<30)
	if err != nil {
		return "", "", err
	}
	if !ok {
		return "", "", errors.New("artifact_fetch_error: insufficient free staging disk space")
	}

	baseName := fmt.Sprintf("printer_%d_plate_%d_%d.gcode", desired.PrinterID, desired.PlateID, time.Now().UnixNano())
	partPath := filepath.Join(a.cfg.ArtifactStageDir, baseName+".part")
	readyPath := filepath.Join(a.cfg.ArtifactStageDir, baseName+".ready")
	cleanupPart := true
	defer func() {
		if !cleanupPart {
			return
		}
		if err := os.Remove(partPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.audit("artifact_cleanup_error", map[string]any{"path": partPath, "error": err.Error()})
		}
	}()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return "", "", err
	}
	artifactHost, artifactErr := url.Parse(artifactURL)
	controlHost, controlErr := url.Parse(strings.TrimSpace(bootstrap.ControlPlaneURL))
	if artifactErr == nil && controlErr == nil && artifactHost.Host != "" && artifactHost.Host == controlHost.Host && strings.TrimSpace(bootstrap.SaaSAPIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
		req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())
		if agentID := strings.TrimSpace(bootstrap.AgentID); agentID != "" {
			req.Header.Set("X-Edge-Agent-Id", agentID)
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", fmt.Errorf("artifact_fetch_error: download failed status=%d body=%s", resp.StatusCode, string(body))
	}

	out, err := os.Create(partPath)
	if err != nil {
		return "", "", err
	}

	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, hasher), resp.Body); err != nil {
		_ = out.Close()
		return "", "", err
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	expectedChecksum := strings.TrimSpace(desired.ChecksumSHA256)
	if expectedChecksum != "" {
		if !strings.EqualFold(sum, expectedChecksum) {
			_ = out.Close()
			return "", "", fmt.Errorf("artifact_fetch_error: checksum mismatch expected=%s actual=%s", desired.ChecksumSHA256, sum)
		}
	} else {
		a.audit("artifact_checksum_missing", map[string]any{
			"printer_id":    desired.PrinterID,
			"plate_id":      desired.PlateID,
			"artifact_url":  artifactURL,
			"actual_sha256": sum,
		})
	}
	if err := out.Close(); err != nil {
		return "", "", err
	}
	if err := os.Rename(partPath, readyPath); err != nil {
		return "", "", err
	}
	cleanupPart = false
	return readyPath, baseName, nil
}

func hasMinFreeSpace(dir string, minBytes uint64) (bool, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return false, err
	}
	free := stat.Bavail * uint64(stat.Bsize)
	return free >= minBytes, nil
}

func (a *agent) cleanupArtifact(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.audit("artifact_cleanup_error", map[string]any{"path": path, "error": err.Error()})
	}
}

func (a *agent) cleanupStagedArtifacts() error {
	patterns := []string{
		filepath.Join(a.cfg.ArtifactStageDir, "*.part"),
		filepath.Join(a.cfg.ArtifactStageDir, "*.ready"),
	}
	for _, pattern := range patterns {
		files, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}
		for _, file := range files {
			if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func (a *agent) markActionSuccess(queuedAction action) {
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	current := a.currentState[queuedAction.PrinterID]
	current.PrinterID = queuedAction.PrinterID
	current.CurrentPrinterState = queuedAction.Target.DesiredPrinterState
	current.CurrentJobState = queuedAction.Target.DesiredJobState
	current.JobID = queuedAction.Target.JobID
	current.PlateID = queuedAction.Target.PlateID
	current.IntentVersionApplied = queuedAction.Target.IntentVersion
	current.IsPaused = queuedAction.Kind == "pause"
	current.IsCanceled = queuedAction.Kind == "stop"
	current.LastErrorCode = ""
	current.LastErrorMessage = ""
	current.ProgressPct = nil
	current.RemainingSeconds = nil
	current.ManualIntervention = ""
	current.ReportedAt = now
	a.currentState[queuedAction.PrinterID] = current
	if current.CurrentPrinterState != "queued" {
		delete(a.queuedSince, queuedAction.PrinterID)
	}
	delete(a.breakerUntil, queuedAction.PrinterID)

	a.audit("action_executed", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"kind":            queuedAction.Kind,
		"intent_version":  queuedAction.Target.IntentVersion,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})
}

func (a *agent) markActionFailure(queuedAction action, errorCode, message string) {
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	current := a.currentState[queuedAction.PrinterID]
	current.PrinterID = queuedAction.PrinterID
	current.CurrentPrinterState = "error"
	current.CurrentJobState = queuedAction.Target.DesiredJobState
	current.JobID = queuedAction.Target.JobID
	current.PlateID = queuedAction.Target.PlateID
	current.LastErrorCode = errorCode
	current.LastErrorMessage = message
	current.ProgressPct = nil
	current.RemainingSeconds = nil
	current.ManualIntervention = ""
	current.ReportedAt = now
	a.currentState[queuedAction.PrinterID] = current
	delete(a.queuedSince, queuedAction.PrinterID)

	a.audit("action_failed", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"kind":            queuedAction.Kind,
		"intent_version":  queuedAction.Target.IntentVersion,
		"error_code":      errorCode,
		"error_message":   message,
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})
}

func classifyActionError(err error) (code string, retryable bool) {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "artifact_fetch_error"):
		return "artifact_fetch_error", false
	case strings.Contains(msg, "signaturedoesnotmatch"), strings.Contains(msg, "signature does not match"):
		return "validation_error", false
	case strings.Contains(msg, "validation"):
		return "validation_error", false
	case strings.Contains(msg, "timeout"),
		strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "connection"),
		strings.Contains(msg, "refused"),
		strings.Contains(msg, "offline"),
		strings.Contains(msg, "temporary failure"):
		return "connectivity_error", true
	case strings.Contains(msg, "status=5"):
		return "printer_busy", true
	default:
		return "unknown_error", false
	}
}

func (a *agent) consumeResyncRequest() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.resyncRequested {
		return false
	}
	a.resyncRequested = false
	return true
}

func (a *agent) snapshotBreakerUntil(printerID int) *time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	until, ok := a.breakerUntil[printerID]
	if !ok {
		return nil
	}
	copy := until
	return &copy
}

func (a *agent) statePushLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.cfg.StatePushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.pushStateOnce(ctx); err != nil {
				a.audit("state_push_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pushStateOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	a.refreshCurrentStateFromBindings(ctx)

	a.mu.RLock()
	states := make([]currentStateItem, 0, len(a.currentState))
	keys := make([]int, 0, len(a.currentState))
	for printerID := range a.currentState {
		keys = append(keys, printerID)
	}
	sort.Ints(keys)
	for _, printerID := range keys {
		s := a.currentState[printerID]
		s.ReportedAt = time.Now().UTC()
		states = append(states, s)
	}
	a.mu.RUnlock()

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/state",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)

	reqPayload := pushStateRequest{States: states}
	reqBody, err := json.Marshal(reqPayload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", randomKey("state"))
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("state_push", resp.StatusCode, string(body))
			return fmt.Errorf("%w: state push returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("state push returned %d: %s", resp.StatusCode, string(body))
	}
	a.audit("state_pushed", map[string]any{"count": len(states), "status_code": resp.StatusCode})
	return nil
}

func (a *agent) probePollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.cfg.ProbePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.pollPrinterProbesOnce(ctx); err != nil {
				a.audit("probe_poll_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pollPrinterProbesOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/printer-probes",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("probe_poll", resp.StatusCode, string(body))
			return fmt.Errorf("%w: probe poll returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("probe poll returned %d: %s", resp.StatusCode, string(body))
	}

	var payload printerProbesResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	for _, probe := range payload.Probes {
		snapshot, snapshotErr := a.fetchBindingSnapshotDetailed(
			ctx,
			edgeBinding{
				AdapterFamily: probe.AdapterFamily,
				EndpointURL:   probe.EndpointURL,
			},
		)
		if snapshotErr != nil {
			if err := a.submitPrinterProbeResult(
				ctx,
				bootstrap,
				probe.ProbeID,
				printerProbeResultRequest{
					Status:            "unreachable",
					ConnectivityError: snapshotErr.Error(),
				},
			); err != nil {
				a.audit("probe_result_submit_error", map[string]any{"probe_id": probe.ProbeID, "error": err.Error()})
			}
			continue
		}
		if err := a.submitPrinterProbeResult(
			ctx,
			bootstrap,
			probe.ProbeID,
			printerProbeResultRequest{
				Status:              "reachable",
				CurrentPrinterState: snapshot.PrinterState,
				CurrentJobState:     snapshot.JobState,
				TotalPrintSeconds:   snapshot.TotalPrintSeconds,
				DetectedPrinterName: snapshot.DetectedName,
				DetectedModelHint:   snapshot.DetectedModelHint,
			},
		); err != nil {
			a.audit("probe_result_submit_error", map[string]any{"probe_id": probe.ProbeID, "error": err.Error()})
		}
	}
	return nil
}

func (a *agent) submitPrinterProbeResult(
	ctx context.Context,
	bootstrap bootstrapConfig,
	probeID string,
	payload printerProbeResultRequest,
) error {
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/printer-probes/%s/result",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
		probeID,
	)
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("probe_result_submit", resp.StatusCode, string(body))
			return fmt.Errorf("%w: probe result submit returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("probe result submit returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (a *agent) discoveryPollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(a.cfg.DiscoveryPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.pollDiscoveryJobsOnce(ctx); err != nil {
				a.audit("discovery_poll_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) beginDiscoveryRun() bool {
	a.discoveryStateMu.Lock()
	defer a.discoveryStateMu.Unlock()
	if a.discoveryRunning {
		return false
	}
	a.discoveryRunning = true
	return true
}

func (a *agent) endDiscoveryRun() {
	a.discoveryStateMu.Lock()
	a.discoveryRunning = false
	a.discoveryStateMu.Unlock()
}

func (a *agent) discoveryInventoryLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	interval := a.cfg.DiscoveryInventoryInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.runAndSubmitDiscoveryInventoryScan(ctx, "periodic", "", time.Time{}); err != nil {
				a.audit("discovery_inventory_error", map[string]any{"mode": "periodic", "error": err.Error()})
			}
		}
	}
}

func (a *agent) discoveryManualTriggerLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	interval := a.cfg.DiscoveryManualPollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			requests, err := a.pollDiscoveryScanRequestsOnce(ctx)
			if err != nil {
				a.audit("discovery_manual_poll_error", map[string]any{"error": err.Error()})
				continue
			}
			for _, request := range requests {
				if err := a.runAndSubmitDiscoveryInventoryScan(ctx, "manual", request.RequestToken, request.ExpiresAt.Time); err != nil {
					a.audit("discovery_inventory_error", map[string]any{
						"mode":          "manual",
						"request_token": request.RequestToken,
						"error":         err.Error(),
					})
					continue
				}
			}
		}
	}
}

func (a *agent) pollDiscoveryScanRequestsOnce(ctx context.Context) ([]discoveryScanRequestItem, error) {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/discovery-scan-requests",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode == http.StatusUpgradeRequired {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		a.audit("discovery_schema_mismatch", map[string]any{"status_code": resp.StatusCode, "body": strings.TrimSpace(string(body))})
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("discovery_scan_requests", resp.StatusCode, string(body))
			return nil, fmt.Errorf("%w: discovery scan request poll returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("discovery scan request poll returned %d: %s", resp.StatusCode, string(body))
	}

	var payload discoveryScanRequestsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Requests, nil
}

func (a *agent) runAndSubmitDiscoveryInventoryScan(
	ctx context.Context,
	scanMode string,
	triggerToken string,
	manualExpiresAt time.Time,
) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}
	manualTriggerToken := strings.TrimSpace(triggerToken)
	emitManualScanEvent := func(status string, occurredAt time.Time, errMsg string) {
		if scanMode != "manual" || manualTriggerToken == "" {
			return
		}
		payload := discoveryScanEventRequest{
			ScanMode:     scanMode,
			TriggerToken: manualTriggerToken,
			Status:       status,
			OccurredAt:   occurredAt,
			Error:        strings.TrimSpace(errMsg),
		}
		if err := a.submitDiscoveryScanEvent(ctx, bootstrap, payload); err != nil {
			a.audit("discovery_scan_event_submit_error", map[string]any{
				"scan_mode":     scanMode,
				"trigger_token": manualTriggerToken,
				"status":        status,
				"error":         err.Error(),
			})
		}
	}

	acquired := a.beginDiscoveryRun()
	if !acquired {
		if scanMode != "manual" {
			return nil
		}

		waitDeadline := time.Now().UTC().Add(discoveryManualLockWaitMax)
		if !manualExpiresAt.IsZero() {
			manualDeadlineUTC := manualExpiresAt.UTC()
			if manualDeadlineUTC.Before(waitDeadline) {
				waitDeadline = manualDeadlineUTC
			}
		}

		retryTicker := time.NewTicker(discoveryManualLockRetry)
		defer retryTicker.Stop()
		for {
			now := time.Now().UTC()
			if !now.Before(waitDeadline) {
				lockErr := errors.New("discovery_scan_lock_busy_timeout")
				emitManualScanEvent("failed", now, lockErr.Error())
				return lockErr
			}
			select {
			case <-ctx.Done():
				cancelErr := ctx.Err()
				emitManualScanEvent("failed", time.Now().UTC(), cancelErr.Error())
				return cancelErr
			case <-retryTicker.C:
				if a.beginDiscoveryRun() {
					acquired = true
					break
				}
			}
			if acquired {
				break
			}
		}
	}

	defer a.endDiscoveryRun()

	startedAt := time.Now().UTC()
	job := discoveryJobItem{
		JobID:         randomKey("scan"),
		Profile:       parseDiscoveryProfile(a.cfg.DiscoveryProfileMax),
		Adapters:      append([]string(nil), a.cfg.DiscoveryAllowedAdapters...),
		EndpointHints: append([]string(nil), a.cfg.DiscoveryEndpointHints...),
		CIDRAllowlist: append([]string(nil), a.cfg.DiscoveryCIDRAllowlist...),
		RequestedAt:   edgeTimestamp{Time: startedAt},
		ExpiresAt:     edgeTimestamp{Time: startedAt.Add(30 * time.Second)},
	}
	a.audit("discovery_scan_started", map[string]any{
		"scan_mode":     scanMode,
		"trigger_token": manualTriggerToken,
		"adapters":      job.Adapters,
		"profile":       job.Profile,
	})
	emitManualScanEvent("started", startedAt, "")
	result := a.executeDiscoveryJob(ctx, job)
	sourceBreakdown := discoveryCandidateSourceBreakdown(result.Candidates)
	a.audit("discovery_scan_completed", map[string]any{
		"scan_mode":        scanMode,
		"trigger_token":    manualTriggerToken,
		"job_status":       result.JobStatus,
		"hosts_scanned":    result.Summary.HostsScanned,
		"hosts_reachable":  result.Summary.HostsReachable,
		"candidates":       result.Summary.CandidatesFound,
		"errors":           result.Summary.ErrorsCount,
		"source_breakdown": sourceBreakdown,
	})
	if result.Summary.CandidatesFound == 0 {
		a.audit("discovery_scan_zero_candidates", map[string]any{
			"scan_mode":        scanMode,
			"trigger_token":    manualTriggerToken,
			"hosts_scanned":    result.Summary.HostsScanned,
			"hosts_reachable":  result.Summary.HostsReachable,
			"errors":           result.Summary.ErrorsCount,
			"source_breakdown": sourceBreakdown,
		})
	}
	entries := make([]discoveryInventoryEntryReport, 0, len(result.Candidates))
	for _, candidate := range result.Candidates {
		candidateStatus := strings.ToLower(strings.TrimSpace(candidate.Status))
		switch candidateStatus {
		case "reachable", "unreachable", "lost":
		default:
			continue
		}
		adapterFamily := normalizeAdapterFamily(candidate.AdapterFamily)
		if !isSupportedDiscoveryAdapter(adapterFamily, a.cfg.EnableKlipper, a.isBambuOperational()) {
			continue
		}
		entry := discoveryInventoryEntryReport{
			AdapterFamily:       adapterFamily,
			EndpointURL:         strings.TrimSpace(candidate.EndpointURL),
			Status:              candidateStatus,
			ConnectivityError:   strings.TrimSpace(candidate.ConnectivityError),
			DetectedPrinterName: strings.TrimSpace(candidate.DetectedPrinterName),
			DetectedModelHint:   strings.TrimSpace(candidate.DetectedModelHint),
			CurrentPrinterState: strings.TrimSpace(candidate.CurrentPrinterState),
			CurrentJobState:     strings.TrimSpace(candidate.CurrentJobState),
			Evidence:            candidate.Evidence,
		}
		if entry.EndpointURL == "" || entry.AdapterFamily == "" {
			continue
		}
		entry.MacAddress = macAddressFromEvidence(candidate.Evidence)
		entries = append(entries, entry)
	}
	scanID := randomKey("scan")
	payload := discoveryInventoryReportRequest{
		ScanID:       scanID,
		ScanMode:     scanMode,
		TriggerToken: manualTriggerToken,
		StartedAt:    result.StartedAt,
		FinishedAt:   result.FinishedAt,
		Summary: discoveryInventorySummary{
			HostsScanned:   result.Summary.HostsScanned,
			HostsReachable: result.Summary.HostsReachable,
			EntriesCount:   len(entries),
			ErrorsCount:    result.Summary.ErrorsCount,
		},
		Entries: entries,
	}
	if err := a.submitDiscoveryInventory(ctx, bootstrap, payload); err != nil {
		a.audit("discovery_inventory_submit_error", map[string]any{
			"scan_id":       scanID,
			"scan_mode":     scanMode,
			"trigger_token": manualTriggerToken,
			"error":         err.Error(),
		})
		emitManualScanEvent("failed", time.Now().UTC(), err.Error())
		return err
	}
	a.audit("discovery_inventory_submit_ok", map[string]any{
		"scan_id":       scanID,
		"scan_mode":     scanMode,
		"trigger_token": manualTriggerToken,
		"entries":       len(entries),
	})
	a.audit("discovery_inventory_submitted", map[string]any{
		"scan_id":         scanID,
		"scan_mode":       scanMode,
		"trigger_token":   manualTriggerToken,
		"entries":         len(entries),
		"hosts_scanned":   result.Summary.HostsScanned,
		"hosts_reachable": result.Summary.HostsReachable,
		"errors":          result.Summary.ErrorsCount,
	})
	completionStatus := "completed"
	completionError := ""
	if result.JobStatus == "failed" {
		completionStatus = "failed"
		completionError = "discovery_scan_failed"
	}
	emitManualScanEvent(completionStatus, result.FinishedAt, completionError)
	return nil
}

func (a *agent) submitDiscoveryScanEvent(
	ctx context.Context,
	bootstrap bootstrapConfig,
	payload discoveryScanEventRequest,
) error {
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/discovery-scan-events",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("discovery_scan_event_submit", resp.StatusCode, string(body))
			return fmt.Errorf("%w: discovery scan event submit returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("discovery scan event submit returned %d: %s", resp.StatusCode, string(body))
	}
	var ack discoveryScanEventResponse
	_ = json.NewDecoder(resp.Body).Decode(&ack)
	return nil
}

func (a *agent) submitDiscoveryInventory(
	ctx context.Context,
	bootstrap bootstrapConfig,
	payload discoveryInventoryReportRequest,
) error {
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/discovery-inventory",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("discovery_inventory_submit", resp.StatusCode, string(body))
			return fmt.Errorf("%w: discovery inventory submit returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("discovery inventory submit returned %d: %s", resp.StatusCode, string(body))
	}
	var ack discoveryInventoryIngestResponse
	_ = json.NewDecoder(resp.Body).Decode(&ack)
	return nil
}

func (a *agent) pollDiscoveryJobsOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/discovery-jobs",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode == http.StatusUpgradeRequired {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		a.audit("discovery_schema_mismatch", map[string]any{"status_code": resp.StatusCode, "body": strings.TrimSpace(string(body))})
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("discovery_poll", resp.StatusCode, string(body))
			return fmt.Errorf("%w: discovery poll returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("discovery poll returned %d: %s", resp.StatusCode, string(body))
	}

	var payload discoveryJobsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	for _, job := range payload.Jobs {
		a.audit("discovery_job_started", map[string]any{
			"job_id":   job.JobID,
			"profile":  job.Profile,
			"adapters": job.Adapters,
		})
		result := a.executeDiscoveryJob(ctx, job)
		if err := a.submitDiscoveryJobResult(ctx, bootstrap, job.JobID, result); err != nil {
			a.audit("discovery_result_submit_error", map[string]any{"job_id": job.JobID, "error": err.Error()})
			continue
		}
		a.audit("discovery_job_submitted", map[string]any{
			"job_id":          job.JobID,
			"job_status":      result.JobStatus,
			"hosts_scanned":   result.Summary.HostsScanned,
			"hosts_reachable": result.Summary.HostsReachable,
			"candidates":      result.Summary.CandidatesFound,
			"errors":          result.Summary.ErrorsCount,
		})
	}
	return nil
}

func (a *agent) submitDiscoveryJobResult(
	ctx context.Context,
	bootstrap bootstrapConfig,
	jobID string,
	payload discoveryJobResultRequest,
) error {
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/discovery-jobs/%s/result",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
		jobID,
	)
	reqBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("discovery_result_submit", resp.StatusCode, string(body))
			return fmt.Errorf("%w: discovery result submit returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("discovery result submit returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (a *agent) executeDiscoveryJob(ctx context.Context, job discoveryJobItem) discoveryJobResultRequest {
	startedAt := time.Now().UTC()
	candidates := make([]discoveryCandidateResult, 0, 64)
	type discoveryProbeTask struct {
		adapterFamily   string
		endpointURL     string
		discoverySource string
	}
	bambuEnabled := a.isBambuOperational()
	allowedAdapters := map[string]struct{}{}
	for _, adapter := range a.cfg.DiscoveryAllowedAdapters {
		allowedAdapters[normalizeAdapterFamily(adapter)] = struct{}{}
	}
	if len(allowedAdapters) == 0 {
		for _, adapter := range enabledDiscoveryAdapters(a.cfg.EnableKlipper, bambuEnabled) {
			allowedAdapters[normalizeAdapterFamily(adapter)] = struct{}{}
		}
	}

	jobAdapters := make([]string, 0, len(job.Adapters))
	seenAdapter := map[string]struct{}{}
	for _, adapter := range job.Adapters {
		normalized := normalizeAdapterFamily(adapter)
		if normalized == "" {
			continue
		}
		if _, exists := seenAdapter[normalized]; exists {
			continue
		}
		seenAdapter[normalized] = struct{}{}
		jobAdapters = append(jobAdapters, normalized)
	}
	if len(jobAdapters) == 0 {
		jobAdapters = append(jobAdapters, enabledDiscoveryAdapters(a.cfg.EnableKlipper, bambuEnabled)...)
	}

	if strings.EqualFold(strings.TrimSpace(job.Profile), "aggressive") &&
		(parseDiscoveryProfile(a.cfg.DiscoveryProfileMax) != "aggressive" || parseDiscoveryNetworkMode(a.cfg.DiscoveryNetworkMode) != "host") {
		for _, adapter := range jobAdapters {
			candidates = append(candidates, discoveryCandidateResult{
				AdapterFamily:   adapter,
				Status:          "policy_rejected",
				RejectionReason: "profile_not_allowed",
			})
		}
		finishedAt := time.Now().UTC()
		return discoveryJobResultRequest{
			JobStatus:  "policy_rejected",
			StartedAt:  startedAt,
			FinishedAt: finishedAt,
			Summary: discoverySummary{
				HostsScanned:    0,
				HostsReachable:  0,
				CandidatesFound: 0,
				ErrorsCount:     len(candidates),
			},
			Candidates: candidates,
		}
	}

	moonrakerTargets := a.discoveryTargetsForJob(job)
	probeTimeout := a.discoveryProbeTimeout(job)
	tasks := make([]discoveryProbeTask, 0, len(jobAdapters)*len(moonrakerTargets))
	workerCount := a.cfg.DiscoveryWorkerCount
	if workerCount <= 0 {
		workerCount = 1
	}
	if len(moonrakerTargets) > 0 && workerCount > len(moonrakerTargets) {
		workerCount = len(moonrakerTargets)
	}
	if workerCount > 256 {
		workerCount = 256
	}
	a.audit("discovery_scan_plan", map[string]any{
		"profile":                strings.TrimSpace(job.Profile),
		"adapter_count":          len(jobAdapters),
		"moonraker_target_count": len(moonrakerTargets),
		"worker_count":           workerCount,
		"probe_timeout_ms":       int(probeTimeout / time.Millisecond),
	})

	for _, adapter := range jobAdapters {
		if _, ok := allowedAdapters[adapter]; !ok {
			candidates = append(candidates, discoveryCandidateResult{
				AdapterFamily:   adapter,
				Status:          "policy_rejected",
				RejectionReason: "adapter_not_allowed",
			})
			continue
		}
		switch adapter {
		case "moonraker":
			if !a.cfg.EnableKlipper {
				candidates = append(candidates, discoveryCandidateResult{
					AdapterFamily:   adapter,
					Status:          "policy_rejected",
					RejectionReason: "adapter_disabled",
				})
				continue
			}
			if len(moonrakerTargets) == 0 {
				candidates = append(candidates, discoveryCandidateResult{
					AdapterFamily:   adapter,
					Status:          "policy_rejected",
					RejectionReason: "no_targets",
				})
				continue
			}
			for _, target := range moonrakerTargets {
				tasks = append(tasks, discoveryProbeTask{
					adapterFamily:   adapter,
					endpointURL:     target.EndpointURL,
					discoverySource: target.Source,
				})
			}
		case "bambu":
			if !bambuEnabled {
				candidates = append(candidates, discoveryCandidateResult{
					AdapterFamily:   adapter,
					Status:          "policy_rejected",
					RejectionReason: "adapter_unavailable",
				})
				continue
			}
			bambuCandidates := a.executeBambuCloudDiscovery(ctx, probeTimeout)
			if len(bambuCandidates) == 0 {
				candidates = append(candidates, discoveryCandidateResult{
					AdapterFamily:   adapter,
					Status:          "policy_rejected",
					RejectionReason: "no_targets",
					Evidence: map[string]any{
						"source":           discoverySourceBambuCloud,
						"discovery_source": discoverySourceBambuCloud,
					},
				})
				continue
			}
			candidates = append(candidates, bambuCandidates...)
		default:
			candidates = append(candidates, discoveryCandidateResult{
				AdapterFamily:   adapter,
				Status:          "policy_rejected",
				RejectionReason: "unsupported_adapter",
			})
		}
	}

	if len(tasks) > 0 {
		if workerCount <= 0 {
			workerCount = 1
		}
		if workerCount > len(tasks) {
			workerCount = len(tasks)
		}

		taskCh := make(chan discoveryProbeTask)
		resultCh := make(chan discoveryCandidateResult, len(tasks))

		var workerWG sync.WaitGroup
		for i := 0; i < workerCount; i++ {
			workerWG.Add(1)
			go func() {
				defer workerWG.Done()
				for task := range taskCh {
					resultCh <- a.probeDiscoveryEndpoint(
						ctx,
						task.adapterFamily,
						task.endpointURL,
						probeTimeout,
						task.discoverySource,
					)
				}
			}()
		}

		for _, task := range tasks {
			taskCh <- task
		}
		close(taskCh)

		workerWG.Wait()
		close(resultCh)

		for result := range resultCh {
			candidates = append(candidates, result)
		}
	}

	a.recordDiscoverySeeds(candidates)

	scannedHosts := map[string]struct{}{}
	reachableHosts := map[string]struct{}{}
	candidatesFound := 0
	errorsCount := 0
	for _, item := range candidates {
		host := hostnameFromURL(item.EndpointURL)
		if host != "" {
			scannedHosts[host] = struct{}{}
		}
		if item.Status == "reachable" {
			candidatesFound++
			if host != "" {
				reachableHosts[host] = struct{}{}
			}
			continue
		}
		errorsCount++
	}

	jobStatus := "failed"
	if candidatesFound > 0 && errorsCount == 0 {
		jobStatus = "completed"
	} else if candidatesFound > 0 {
		jobStatus = "partial"
	} else if len(candidates) > 0 {
		allPolicyRejected := true
		for _, item := range candidates {
			if item.Status != "policy_rejected" {
				allPolicyRejected = false
				break
			}
		}
		if allPolicyRejected {
			jobStatus = "policy_rejected"
		}
	}

	return discoveryJobResultRequest{
		JobStatus:  jobStatus,
		StartedAt:  startedAt,
		FinishedAt: time.Now().UTC(),
		Summary: discoverySummary{
			HostsScanned:    len(scannedHosts),
			HostsReachable:  len(reachableHosts),
			CandidatesFound: candidatesFound,
			ErrorsCount:     errorsCount,
		},
		Candidates: candidates,
	}
}

func (a *agent) executeBambuCloudDiscovery(ctx context.Context, probeTimeout time.Duration) []discoveryCandidateResult {
	authState := a.snapshotBambuAuthState()
	accessToken := strings.TrimSpace(authState.AccessToken)
	if accessToken == "" {
		return []discoveryCandidateResult{
			{
				AdapterFamily:   "bambu",
				Status:          "policy_rejected",
				RejectionReason: "auth_token_missing",
				Evidence: map[string]any{
					"source":           discoverySourceBambuCloud,
					"discovery_source": discoverySourceBambuCloud,
				},
			},
		}
	}

	provider := a.bambuAuthProvider
	if provider == nil {
		return []discoveryCandidateResult{
			{
				AdapterFamily:   "bambu",
				Status:          "policy_rejected",
				RejectionReason: "auth_provider_missing",
				Evidence: map[string]any{
					"source":           discoverySourceBambuCloud,
					"discovery_source": discoverySourceBambuCloud,
				},
			},
		}
	}
	deviceProvider, ok := provider.(bambuCloudDeviceLister)
	if !ok {
		return []discoveryCandidateResult{
			{
				AdapterFamily:   "bambu",
				Status:          "policy_rejected",
				RejectionReason: "cloud_listing_unsupported",
				Evidence: map[string]any{
					"source":           discoverySourceBambuCloud,
					"discovery_source": discoverySourceBambuCloud,
				},
			},
		}
	}

	requestTimeout := probeTimeout
	if requestTimeout <= 0 {
		requestTimeout = a.cfg.MoonrakerRequestTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = 2 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	devices, err := deviceProvider.ListBoundDevices(requestCtx, accessToken)
	if err != nil {
		a.audit("bambu_cloud_discovery_error", map[string]any{"error": err.Error()})
		return []discoveryCandidateResult{
			{
				AdapterFamily:     "bambu",
				EndpointURL:       formatBambuPrinterEndpoint("cloud"),
				Status:            "unreachable",
				ConnectivityError: err.Error(),
				Evidence: map[string]any{
					"source":           discoverySourceBambuCloud,
					"discovery_source": discoverySourceBambuCloud,
				},
			},
		}
	}
	if len(devices) == 0 {
		return nil
	}

	out := make([]discoveryCandidateResult, 0, len(devices))
	for _, device := range devices {
		printerID := strings.TrimSpace(device.DeviceID)
		if printerID == "" {
			continue
		}
		printerState, jobState := mapBambuCloudStates(device.Online, device.PrintStatus)
		candidateStatus := "reachable"
		if !device.Online {
			candidateStatus = "unreachable"
			printerState = ""
			jobState = ""
		}
		detectedName := strings.TrimSpace(device.Name)
		if detectedName == "" {
			detectedName = printerID
		}
		modelHint := strings.TrimSpace(device.Model)

		evidence := map[string]any{
			"source":           discoverySourceBambuCloud,
			"discovery_source": discoverySourceBambuCloud,
			"cloud_online":     device.Online,
		}
		if status := strings.TrimSpace(device.PrintStatus); status != "" {
			evidence["cloud_print_status"] = status
		}
		if name := strings.TrimSpace(device.Name); name != "" {
			evidence["cloud_name"] = name
		}
		if modelHint != "" {
			evidence["cloud_model"] = modelHint
		}

		out = append(out, discoveryCandidateResult{
			AdapterFamily:       "bambu",
			EndpointURL:         formatBambuPrinterEndpoint(printerID),
			Status:              candidateStatus,
			CurrentPrinterState: printerState,
			CurrentJobState:     jobState,
			DetectedPrinterName: detectedName,
			DetectedModelHint:   modelHint,
			Evidence:            evidence,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.TrimSpace(out[i].EndpointURL)
		right := strings.TrimSpace(out[j].EndpointURL)
		return left < right
	})
	return out
}

func mapBambuCloudStates(online bool, rawPrintStatus string) (printerState string, jobState string) {
	if !online {
		return "error", "failed"
	}
	switch strings.ToLower(strings.TrimSpace(rawPrintStatus)) {
	case "printing", "running", "in_progress":
		return "printing", "printing"
	case "queued", "pending", "preparing", "starting", "heating", "slicing":
		return "queued", "pending"
	case "paused", "pausing":
		return "paused", "printing"
	case "error", "failed", "fault":
		return "error", "failed"
	case "canceled", "cancelled":
		return "idle", "canceled"
	case "idle", "ready", "standby", "finished", "completed", "active", "":
		return "idle", "completed"
	default:
		return "idle", "completed"
	}
}

func (a *agent) executeBambuConnectDiscovery(ctx context.Context, probeTimeout time.Duration) []discoveryCandidateResult {
	uri := strings.TrimSpace(a.cfg.BambuConnectURI)
	if uri == "" {
		return []discoveryCandidateResult{
			{
				AdapterFamily:   "bambu",
				Status:          "policy_rejected",
				RejectionReason: "missing_bambu_connect_uri",
				Evidence: map[string]any{
					"source":           discoverySourceBambuConnect,
					"discovery_source": discoverySourceBambuConnect,
				},
			},
		}
	}

	requestTimeout := probeTimeout
	if requestTimeout <= 0 {
		requestTimeout = a.cfg.MoonrakerRequestTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = 2 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	printers, err := a.fetchBambuConnectPrinters(requestCtx)
	if err != nil {
		a.audit("bambu_connect_discovery_error", map[string]any{
			"bambu_connect_uri": redactBambuConnectURI(uri),
			"error":             err.Error(),
		})
		return []discoveryCandidateResult{
			{
				AdapterFamily:     "bambu",
				EndpointURL:       formatBambuPrinterEndpoint("connect"),
				Status:            "unreachable",
				ConnectivityError: err.Error(),
				Evidence: map[string]any{
					"source":             discoverySourceBambuConnect,
					"discovery_source":   discoverySourceBambuConnect,
					"bambu_connect_host": redactBambuConnectURI(uri),
				},
			},
		}
	}
	if len(printers) == 0 {
		return nil
	}

	out := make([]discoveryCandidateResult, 0, len(printers))
	for _, printer := range printers {
		printerID := bambuConnectPrinterIdentifier(printer)
		if printerID == "" {
			continue
		}
		printerState, jobState := mapBambuConnectStates(printer.PrinterState, printer.JobState)
		detectedName := bambuConnectPrinterName(printer)
		if detectedName == "" {
			detectedName = printerID
		}
		out = append(out, discoveryCandidateResult{
			AdapterFamily:       "bambu",
			EndpointURL:         formatBambuPrinterEndpoint(printerID),
			Status:              "reachable",
			CurrentPrinterState: printerState,
			CurrentJobState:     jobState,
			DetectedPrinterName: detectedName,
			DetectedModelHint:   strings.TrimSpace(firstNonEmpty(printer.Model, printer.MachineType)),
			Evidence: map[string]any{
				"source":             discoverySourceBambuConnect,
				"discovery_source":   discoverySourceBambuConnect,
				"bambu_connect_host": redactBambuConnectURI(uri),
			},
		})
	}
	return out
}

func discoveryCandidateSourceBreakdown(candidates []discoveryCandidateResult) map[string]int {
	counts := map[string]int{}
	for _, candidate := range candidates {
		source := ""
		if candidate.Evidence != nil {
			if raw, ok := candidate.Evidence["discovery_source"].(string); ok {
				source = strings.TrimSpace(raw)
			}
		}
		if source == "" {
			source = "unspecified"
		}
		counts[source]++
	}
	return counts
}

func (a *agent) discoveryProbeTimeout(job discoveryJobItem) time.Duration {
	if job.RuntimeCapsOverrides != nil {
		if timeoutMS, ok := job.RuntimeCapsOverrides["probe_timeout_ms"]; ok && timeoutMS > 0 {
			return time.Duration(timeoutMS) * time.Millisecond
		}
		if timeoutMS, ok := job.RuntimeCapsOverrides["request_timeout_ms"]; ok && timeoutMS > 0 {
			return time.Duration(timeoutMS) * time.Millisecond
		}
	}
	if a.cfg.DiscoveryProbeTimeout > 0 {
		return a.cfg.DiscoveryProbeTimeout
	}
	if a.cfg.MoonrakerRequestTimeout > 0 {
		return a.cfg.MoonrakerRequestTimeout
	}
	return 2500 * time.Millisecond
}

func (a *agent) discoveryMaxTargets(job discoveryJobItem) int {
	maxTargets := a.cfg.DiscoveryMaxTargets
	if maxTargets <= 0 {
		maxTargets = 256
	}
	if job.RuntimeCapsOverrides != nil {
		if override, ok := job.RuntimeCapsOverrides["max_targets"]; ok && override > 0 {
			maxTargets = override
		}
	}
	if maxTargets > 4096 {
		maxTargets = 4096
	}
	return maxTargets
}

func (a *agent) discoveryTargetsForJob(job discoveryJobItem) []discoveryProbeTarget {
	maxTargets := a.discoveryMaxTargets(job)
	seen := map[string]struct{}{}
	targets := make([]discoveryProbeTarget, 0, maxTargets)
	appendTarget := func(raw string, source string) {
		if len(targets) >= maxTargets {
			return
		}
		canonical := normalizeDiscoveryEndpointHint(raw)
		if canonical == "" {
			return
		}
		if _, ok := seen[canonical]; ok {
			return
		}
		seen[canonical] = struct{}{}
		targets = append(targets, discoveryProbeTarget{
			EndpointURL: canonical,
			Source:      strings.TrimSpace(source),
		})
	}

	for _, hint := range job.EndpointHints {
		appendTarget(hint, discoverySourceEndpointHint)
	}
	for _, hint := range a.cfg.DiscoveryEndpointHints {
		appendTarget(hint, discoverySourceEndpointHint)
	}

	if len(targets) < maxTargets {
		for _, endpoint := range a.snapshotBindingDiscoveryEndpoints(maxTargets - len(targets)) {
			appendTarget(endpoint, discoverySourceSeedManual)
		}
	}

	if len(targets) < maxTargets {
		for _, endpoint := range a.snapshotDiscoverySeedEndpoints(maxTargets - len(targets)) {
			appendTarget(endpoint, discoverySourceSeedHistory)
		}
	}

	if len(targets) > 0 {
		return targets
	}

	jobCIDRs := normalizeDiscoveryCIDRList(job.CIDRAllowlist)
	cfgCIDRs := normalizeDiscoveryCIDRList(a.cfg.DiscoveryCIDRAllowlist)
	cidrs := jobCIDRs
	if len(cidrs) == 0 {
		cidrs = cfgCIDRs
	}
	cidrSource := discoverySourceCIDRAllowlist
	if len(cidrs) == 0 {
		if parseDiscoveryNetworkMode(a.cfg.DiscoveryNetworkMode) != "host" {
			a.audit("discovery_network_mode_fallback", map[string]any{
				"network_mode": parseDiscoveryNetworkMode(a.cfg.DiscoveryNetworkMode),
				"reason":       "bridge_requires_seeded_targets",
				"profile":      parseDiscoveryProfile(job.Profile),
			})
			return nil
		}
		cidrs = localPrivateIPv4CIDRs()
		cidrSource = discoverySourceLocalSubnets
	}

	for _, cidr := range cidrs {
		remaining := maxTargets - len(targets)
		if remaining <= 0 {
			break
		}
		for _, host := range enumerateCIDRHosts(cidr, remaining) {
			appendTarget("http://"+host+":7125", cidrSource)
			if len(targets) >= maxTargets {
				break
			}
		}
	}
	return targets
}

func normalizeDiscoveryCIDRList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, item := range values {
		cidr := strings.TrimSpace(item)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			continue
		}
		if _, exists := seen[cidr]; exists {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out
}

func (a *agent) snapshotBindingDiscoveryEndpoints(limit int) []string {
	if limit <= 0 {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	seen := map[string]struct{}{}
	out := make([]string, 0, limit)
	for _, binding := range a.bindings {
		if len(out) >= limit {
			break
		}
		canonical := normalizeDiscoveryEndpointHint(binding.EndpointURL)
		if canonical == "" {
			continue
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}

func (a *agent) snapshotDiscoverySeedEndpoints(limit int) []string {
	if limit <= 0 {
		return nil
	}
	now := time.Now().UTC()
	a.discoverySeedMu.Lock()
	defer a.discoverySeedMu.Unlock()
	if a.discoverySeeds == nil {
		a.discoverySeeds = make(map[string]time.Time)
	}
	a.pruneDiscoverySeedsLocked(now)
	out := make([]string, 0, limit)
	for endpoint := range a.discoverySeeds {
		out = append(out, endpoint)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (a *agent) recordDiscoverySeeds(candidates []discoveryCandidateResult) {
	now := time.Now().UTC()
	a.discoverySeedMu.Lock()
	defer a.discoverySeedMu.Unlock()
	if a.discoverySeeds == nil {
		a.discoverySeeds = make(map[string]time.Time)
	}
	for _, candidate := range candidates {
		if candidate.Status != "reachable" {
			continue
		}
		canonical := normalizeDiscoveryEndpointHint(candidate.EndpointURL)
		if canonical == "" {
			continue
		}
		a.discoverySeeds[canonical] = now
	}
	a.pruneDiscoverySeedsLocked(now)
}

func (a *agent) pruneDiscoverySeedsLocked(now time.Time) {
	if a.discoverySeeds == nil {
		a.discoverySeeds = make(map[string]time.Time)
	}
	for endpoint, seenAt := range a.discoverySeeds {
		if now.Sub(seenAt) > discoverySeedRetention {
			delete(a.discoverySeeds, endpoint)
		}
	}
	if len(a.discoverySeeds) <= discoverySeedMaxEntries {
		return
	}
	type seedEntry struct {
		endpoint string
		seenAt   time.Time
	}
	entries := make([]seedEntry, 0, len(a.discoverySeeds))
	for endpoint, seenAt := range a.discoverySeeds {
		entries = append(entries, seedEntry{endpoint: endpoint, seenAt: seenAt})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].seenAt.After(entries[j].seenAt)
	})
	keep := entries
	if len(keep) > discoverySeedMaxEntries {
		keep = keep[:discoverySeedMaxEntries]
	}
	allowed := map[string]struct{}{}
	for _, item := range keep {
		allowed[item.endpoint] = struct{}{}
	}
	for endpoint := range a.discoverySeeds {
		if _, exists := allowed[endpoint]; !exists {
			delete(a.discoverySeeds, endpoint)
		}
	}
}

func (a *agent) probeDiscoveryEndpoint(
	ctx context.Context,
	adapterFamily string,
	endpointURL string,
	probeTimeout time.Duration,
	discoverySource string,
) discoveryCandidateResult {
	adapter := normalizeAdapterFamily(adapterFamily)
	if adapter == "bambu" && !a.isBambuOperational() {
		return discoveryCandidateResult{
			AdapterFamily:   adapter,
			EndpointURL:     endpointURL,
			Status:          "policy_rejected",
			RejectionReason: "adapter_unavailable",
		}
	}

	switch adapter {
	case "moonraker":
		printerState, jobState, err := a.fetchMoonrakerSnapshotWithTimeout(ctx, endpointURL, probeTimeout)
		if err != nil {
			return discoveryCandidateResult{
				AdapterFamily:     adapter,
				EndpointURL:       endpointURL,
				Status:            "unreachable",
				ConnectivityError: err.Error(),
				Evidence: map[string]any{
					"source":           "moonraker",
					"discovery_source": strings.TrimSpace(discoverySource),
				},
			}
		}
		detectedName, detectedModelHint, _ := a.fetchMoonrakerProductInfo(ctx, endpointURL)
		evidence := map[string]any{
			"source":           "moonraker",
			"discovery_source": strings.TrimSpace(discoverySource),
		}
		if macAddress := discoverMACAddressForEndpoint(endpointURL); macAddress != "" {
			evidence["mac_address"] = macAddress
		}
		return discoveryCandidateResult{
			AdapterFamily:       adapter,
			EndpointURL:         endpointURL,
			Status:              "reachable",
			CurrentPrinterState: printerState,
			CurrentJobState:     jobState,
			DetectedPrinterName: detectedName,
			DetectedModelHint:   detectedModelHint,
			Evidence:            evidence,
		}
	case "bambu":
		snapshot, err := a.fetchBambuConnectSnapshotFromEndpoint(ctx, endpointURL)
		if err != nil {
			return discoveryCandidateResult{
				AdapterFamily:     adapter,
				EndpointURL:       endpointURL,
				Status:            "unreachable",
				ConnectivityError: err.Error(),
				Evidence: map[string]any{
					"source":           discoverySourceBambuConnect,
					"discovery_source": strings.TrimSpace(discoverySource),
				},
			}
		}
		return discoveryCandidateResult{
			AdapterFamily:       adapter,
			EndpointURL:         endpointURL,
			Status:              "reachable",
			CurrentPrinterState: snapshot.PrinterState,
			CurrentJobState:     snapshot.JobState,
			DetectedPrinterName: snapshot.DetectedName,
			DetectedModelHint:   snapshot.DetectedModelHint,
			Evidence: map[string]any{
				"source":           discoverySourceBambuConnect,
				"discovery_source": strings.TrimSpace(discoverySource),
			},
		}
	default:
		return discoveryCandidateResult{
			AdapterFamily:   adapter,
			EndpointURL:     endpointURL,
			Status:          "policy_rejected",
			RejectionReason: "unsupported_adapter",
		}
	}
}

func normalizeDiscoveryEndpointHint(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

func macAddressFromEvidence(evidence map[string]any) string {
	if evidence == nil {
		return ""
	}
	raw, ok := evidence["mac_address"]
	if !ok {
		return ""
	}
	value, ok := raw.(string)
	if !ok {
		return ""
	}
	return normalizeMACAddress(value)
}

func normalizeMACAddress(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return ""
	}
	compact := strings.ReplaceAll(strings.ReplaceAll(value, ":", ""), "-", "")
	if len(compact) != 12 {
		return ""
	}
	for _, ch := range compact {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return ""
		}
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < len(compact); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(compact[i : i+2])
	}
	return b.String()
}

func discoverMACAddressForEndpoint(endpointURL string) string {
	host := hostnameFromURL(endpointURL)
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil || ip.To4() == nil {
		return ""
	}
	ipv4 := ip.String()
	if mac := lookupMACFromProcARP(ipv4); mac != "" {
		return mac
	}
	return lookupMACFromARPCommand(ipv4)
}

func lookupMACFromProcARP(ipv4Host string) string {
	content, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if fields[0] != ipv4Host {
			continue
		}
		return normalizeMACAddress(fields[3])
	}
	return ""
}

func lookupMACFromARPCommand(ipv4Host string) string {
	commands := [][]string{
		{"arp", "-an", ipv4Host},
		{"arp", "-an"},
	}
	for _, parts := range commands {
		output, err := runARPCommand(parts)
		if err != nil {
			arpCommandWarningOnce.Do(func() {
				logARPCommandWarning("discovery mac lookup fallback failed; arp command unavailable or error=%v", err)
			})
			continue
		}
		text := strings.ToLower(string(output))
		if len(parts) == 3 && !strings.Contains(text, ipv4Host) {
			continue
		}
		raw := macAddressPattern.FindString(text)
		if raw == "" {
			continue
		}
		if normalized := normalizeMACAddress(raw); normalized != "" {
			return normalized
		}
	}
	return ""
}

func shouldSkipDiscoveryInterface(iface net.Interface) bool {
	if iface.Flags&net.FlagUp == 0 {
		return true
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return true
	}
	if iface.Flags&net.FlagPointToPoint != 0 {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(iface.Name))
	if name == "" {
		return true
	}
	virtualPrefixes := []string{
		"docker",
		"veth",
		"br-",
		"bridge",
		"virbr",
		"vmnet",
		"vboxnet",
		"utun",
		"awdl",
		"llw",
		"tailscale",
		"wg",
		"zt",
		"tun",
		"tap",
	}
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func localPrivateIPv4CIDRs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	for _, iface := range interfaces {
		if shouldSkipDiscoveryInterface(iface) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			_, ipNet, err := net.ParseCIDR(addr.String())
			if err != nil || ipNet == nil {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || !isPrivateIPv4(ip) {
				continue
			}
			cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
			if _, ok := seen[cidr]; ok {
				continue
			}
			seen[cidr] = struct{}{}
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	return out
}

func isPrivateIPv4(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	if ipv4[0] == 10 {
		return true
	}
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true
	}
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}
	return false
}

func enumerateCIDRHosts(cidr string, maxHosts int) []string {
	if maxHosts <= 0 {
		return nil
	}
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || ipNet == nil {
		return nil
	}
	start := ip.Mask(ipNet.Mask).To4()
	if start == nil {
		return nil
	}
	network := append(net.IP(nil), start...)
	broadcast := append(net.IP(nil), start...)
	for i := range broadcast {
		broadcast[i] |= ^ipNet.Mask[i]
	}

	out := make([]string, 0, maxHosts)
	cur := append(net.IP(nil), start...)
	incrementIPv4(cur)
	for ipNet.Contains(cur) && len(out) < maxHosts {
		if !cur.Equal(network) && !cur.Equal(broadcast) {
			out = append(out, cur.String())
		}
		incrementIPv4(cur)
	}
	return out
}

func incrementIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func (a *agent) handleControlPlaneAuthFailure(endpoint string, statusCode int, responseBody string) {
	a.mu.Lock()
	wasClaimed := a.claimed
	a.claimed = false
	a.desiredState = make(map[int]desiredStateItem)
	a.bindings = make(map[int]edgeBinding)
	a.actionQueue = make(map[int][]action)
	a.deadLetters = make(map[int][]action)
	a.queuedSince = make(map[int]time.Time)
	a.recentEnqueue = make(map[string]time.Time)
	a.suppressedUntil = make(map[string]time.Time)
	a.breakerUntil = make(map[int]time.Time)
	a.mu.Unlock()

	if !wasClaimed {
		return
	}
	a.audit("edge_auth_revoked_error", map[string]any{
		"endpoint":     endpoint,
		"status_code":  statusCode,
		"error":        "edge_api_key_revoked",
		"responseBody": strings.TrimSpace(responseBody),
	})
}

func (a *agent) notifyShutdown(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/shutdown",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("shutdown_notify", resp.StatusCode, string(body))
			return fmt.Errorf("%w: shutdown notify returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("shutdown notify returned %d: %s", resp.StatusCode, string(body))
	}
	a.audit("shutdown_notified", map[string]any{"status_code": resp.StatusCode})
	return nil
}

func (a *agent) refreshCurrentStateFromBindings(ctx context.Context) {
	type bindingState struct {
		printerID int
		binding   edgeBinding
	}

	a.mu.RLock()
	bindings := make([]bindingState, 0, len(a.bindings))
	for printerID, binding := range a.bindings {
		bindings = append(bindings, bindingState{printerID: printerID, binding: binding})
	}
	a.mu.RUnlock()
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].printerID < bindings[j].printerID
	})

	for _, item := range bindings {
		snapshot, err := a.fetchBindingSnapshotDetailed(ctx, item.binding)
		if err != nil {
			a.mu.Lock()
			current := a.currentState[item.printerID]
			current.PrinterID = item.printerID
			if current.CurrentPrinterState == "" {
				current.CurrentPrinterState = "error"
			}
			current.LastErrorCode = "connectivity_error"
			current.LastErrorMessage = err.Error()
			current.TotalPrintSeconds = nil
			current.ProgressPct = nil
			current.RemainingSeconds = nil
			current.TelemetrySource = ""
			current.ManualIntervention = ""
			current.ReportedAt = time.Now().UTC()
			a.currentState[item.printerID] = current
			a.mu.Unlock()
			continue
		}

		a.mu.Lock()
		current := a.currentState[item.printerID]
		prevState := current.CurrentPrinterState
		current.PrinterID = item.printerID
		current.CurrentPrinterState = snapshot.PrinterState
		current.CurrentJobState = snapshot.JobState
		current.LastErrorCode = ""
		current.LastErrorMessage = ""
		current.TotalPrintSeconds = snapshot.TotalPrintSeconds
		current.ProgressPct = snapshot.ProgressPct
		current.RemainingSeconds = snapshot.RemainingSeconds
		current.TelemetrySource = snapshot.TelemetrySource
		current.ManualIntervention = snapshot.ManualIntervention
		current.IsCanceled = snapshot.JobState == "canceled"
		current.ReportedAt = time.Now().UTC()
		if snapshot.PrinterState == "queued" {
			if prevState != "queued" {
				a.queuedSince[item.printerID] = current.ReportedAt
			}
		} else {
			delete(a.queuedSince, item.printerID)
		}
		if snapshot.PrinterState == "idle" {
			current.IsPaused = false
		}
		a.currentState[item.printerID] = current
		a.mu.Unlock()
	}
}

func (a *agent) fetchBindingSnapshot(ctx context.Context, binding edgeBinding) (printerState string, jobState string, err error) {
	snapshot, err := a.fetchBindingSnapshotDetailed(ctx, binding)
	if err != nil {
		return "", "", err
	}
	return snapshot.PrinterState, snapshot.JobState, nil
}

func (a *agent) fetchBindingSnapshotDetailed(ctx context.Context, binding edgeBinding) (bindingSnapshot, error) {
	family := normalizeAdapterFamily(binding.AdapterFamily)
	switch family {
	case "moonraker":
		printerState, jobState, err := a.fetchMoonrakerSnapshot(ctx, binding.EndpointURL)
		if err != nil {
			return bindingSnapshot{}, err
		}
		progressPct, remainingSeconds, telemetrySource, manualIntervention, telemetryErr := a.fetchMoonrakerTelemetry(ctx, binding.EndpointURL)
		if telemetryErr != nil {
			a.audit("moonraker_telemetry_fetch_error", map[string]any{
				"endpoint_url": binding.EndpointURL,
				"error":        telemetryErr.Error(),
			})
		}
		if strings.TrimSpace(telemetrySource) == "" {
			telemetrySource = "moonraker"
		}
		totalPrintSeconds, totalsErr := a.fetchMoonrakerTotalPrintSeconds(ctx, binding.EndpointURL)
		if totalsErr != nil {
			a.audit("moonraker_totals_fetch_error", map[string]any{
				"endpoint_url": binding.EndpointURL,
				"error":        totalsErr.Error(),
			})
		}
		detectedName, detectedModelHint, metadataErr := a.fetchMoonrakerProductInfo(ctx, binding.EndpointURL)
		if metadataErr != nil {
			a.audit("moonraker_metadata_fetch_error", map[string]any{
				"endpoint_url": binding.EndpointURL,
				"error":        metadataErr.Error(),
			})
		}
		return bindingSnapshot{
			PrinterState:       printerState,
			JobState:           jobState,
			TotalPrintSeconds:  totalPrintSeconds,
			ProgressPct:        progressPct,
			RemainingSeconds:   remainingSeconds,
			TelemetrySource:    telemetrySource,
			ManualIntervention: manualIntervention,
			DetectedName:       detectedName,
			DetectedModelHint:  detectedModelHint,
		}, nil
	case "bambu":
		if !a.cfg.EnableBambu {
			return bindingSnapshot{}, errors.New("validation_error: adapter_family bambu is disabled (set --bambu to enable)")
		}
		if !a.isBambuAuthReady() {
			return bindingSnapshot{}, errBambuAuthUnavailable
		}
		snapshot, err := a.fetchBambuCloudSnapshotFromEndpoint(ctx, binding.EndpointURL)
		if err != nil {
			var offlineErr *bambuCloudDeviceOfflineError
			if !errors.As(err, &offlineErr) {
				a.audit("bambu_cloud_snapshot_error", map[string]any{
					"endpoint_url": binding.EndpointURL,
					"error":        err.Error(),
				})
			}
			return bindingSnapshot{}, err
		}
		return snapshot, nil
	default:
		return bindingSnapshot{}, fmt.Errorf("validation_error: unsupported adapter_family: %s", family)
	}
}

func (a *agent) fetchBambuCloudSnapshotFromEndpoint(ctx context.Context, endpointURL string) (bindingSnapshot, error) {
	printerID, err := parseBambuPrinterEndpointID(endpointURL)
	if err != nil {
		return bindingSnapshot{}, err
	}
	return a.fetchBambuCloudSnapshotByPrinterID(ctx, printerID)
}

func (a *agent) fetchBambuCloudSnapshotByPrinterID(ctx context.Context, printerID string) (bindingSnapshot, error) {
	normalizedPrinterID := strings.TrimSpace(printerID)
	if normalizedPrinterID == "" {
		return bindingSnapshot{}, errors.New("validation_error: missing bambu printer identifier")
	}

	authState := a.snapshotBambuAuthState()
	accessToken := strings.TrimSpace(authState.AccessToken)
	if accessToken == "" {
		return bindingSnapshot{}, errBambuAuthUnavailable
	}

	deviceProvider, err := a.bambuCloudDeviceProvider()
	if err != nil {
		return bindingSnapshot{}, err
	}

	requestTimeout := a.cfg.MoonrakerRequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 8 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	devices, err := deviceProvider.ListBoundDevices(requestCtx, accessToken)
	if err != nil {
		return bindingSnapshot{}, err
	}

	var matched *bambucloud.CloudDevice
	for i := range devices {
		if strings.EqualFold(strings.TrimSpace(devices[i].DeviceID), normalizedPrinterID) {
			matched = &devices[i]
			break
		}
	}
	if matched == nil {
		return bindingSnapshot{}, fmt.Errorf("bambu cloud device %q is not bound to this account", normalizedPrinterID)
	}
	if !matched.Online {
		return bindingSnapshot{}, &bambuCloudDeviceOfflineError{PrinterID: normalizedPrinterID}
	}

	printerState, jobState := mapBambuCloudStates(matched.Online, matched.PrintStatus)
	detectedName := strings.TrimSpace(matched.Name)
	if detectedName == "" {
		detectedName = normalizedPrinterID
	}
	return bindingSnapshot{
		PrinterState:      printerState,
		JobState:          jobState,
		TelemetrySource:   telemetrySourceBambuCloud,
		DetectedName:      detectedName,
		DetectedModelHint: strings.TrimSpace(matched.Model),
	}, nil
}

type bambuCloudDeviceOfflineError struct {
	PrinterID string
}

func (e *bambuCloudDeviceOfflineError) Error() string {
	return fmt.Sprintf("bambu cloud device %q is offline", strings.TrimSpace(e.PrinterID))
}

func (a *agent) bambuCloudDeviceProvider() (bambuCloudDeviceLister, error) {
	provider := a.bambuAuthProvider
	if provider == nil {
		return nil, errors.New("validation_error: bambu cloud provider is not configured")
	}
	deviceProvider, ok := provider.(bambuCloudDeviceLister)
	if !ok {
		return nil, errors.New("validation_error: bambu cloud provider does not support device listing")
	}
	return deviceProvider, nil
}

func (a *agent) bambuCloudActionProvider() (bambuCloudActionProvider, error) {
	provider := a.bambuAuthProvider
	if provider == nil {
		return nil, errors.New("validation_error: bambu cloud provider is not configured")
	}
	actionProvider, ok := provider.(bambuCloudActionProvider)
	if !ok {
		return nil, errors.New("validation_error: bambu cloud provider does not support action execution")
	}
	return actionProvider, nil
}

type bambuConnectPrinterRecord struct {
	PrinterID    string `json:"printer_id"`
	ID           string `json:"id"`
	DeviceID     string `json:"device_id"`
	Serial       string `json:"serial"`
	Name         string `json:"name"`
	PrinterName  string `json:"printer_name"`
	DeviceName   string `json:"device_name"`
	Model        string `json:"model"`
	MachineType  string `json:"machine_type"`
	PrinterState string `json:"printer_state"`
	JobState     string `json:"job_state"`
}

func (a *agent) fetchBambuConnectSnapshotFromEndpoint(ctx context.Context, endpointURL string) (bindingSnapshot, error) {
	printerID, err := parseBambuPrinterEndpointID(endpointURL)
	if err != nil {
		return bindingSnapshot{}, err
	}
	return a.fetchBambuConnectSnapshotByPrinterID(ctx, printerID)
}

func (a *agent) fetchBambuConnectSnapshotByPrinterID(ctx context.Context, printerID string) (bindingSnapshot, error) {
	record, err := a.fetchBambuConnectPrinterStatus(ctx, printerID)
	if err != nil {
		return bindingSnapshot{}, err
	}
	canonicalID := strings.TrimSpace(printerID)
	if canonicalID == "" {
		canonicalID = bambuConnectPrinterIdentifier(record)
	}
	detectedName := bambuConnectPrinterName(record)
	if detectedName == "" {
		detectedName = canonicalID
	}
	printerState, jobState := mapBambuConnectStates(record.PrinterState, record.JobState)
	return bindingSnapshot{
		PrinterState:      printerState,
		JobState:          jobState,
		TelemetrySource:   telemetrySourceBambuConnect,
		DetectedName:      detectedName,
		DetectedModelHint: strings.TrimSpace(firstNonEmpty(record.Model, record.MachineType)),
	}, nil
}

func (a *agent) fetchBambuConnectPrinters(ctx context.Context) ([]bambuConnectPrinterRecord, error) {
	paths := []string{
		"/api/v1/printers",
		"/printers",
	}
	var lastErr error
	for _, path := range paths {
		printers, err := a.fetchBambuConnectPrinterListPath(ctx, path)
		if err == nil {
			return printers, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("bambu connect printer list failed")
	}
	return nil, lastErr
}

func (a *agent) fetchBambuConnectPrinterStatus(ctx context.Context, printerID string) (bambuConnectPrinterRecord, error) {
	normalizedPrinterID := strings.TrimSpace(printerID)
	if normalizedPrinterID == "" {
		return bambuConnectPrinterRecord{}, errors.New("validation_error: missing bambu printer identifier")
	}
	escaped := url.PathEscape(normalizedPrinterID)
	paths := []string{
		fmt.Sprintf("/api/v1/printers/%s/status", escaped),
		fmt.Sprintf("/api/v1/printers/%s", escaped),
	}
	var lastErr error
	for _, path := range paths {
		record, err := a.fetchBambuConnectPrinterRecordPath(ctx, path)
		if err == nil {
			if bambuConnectPrinterIdentifier(record) == "" {
				record.PrinterID = normalizedPrinterID
			}
			return record, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("bambu connect printer status failed")
	}
	return bambuConnectPrinterRecord{}, lastErr
}

func (a *agent) fetchBambuConnectPrinterListPath(ctx context.Context, path string) ([]bambuConnectPrinterRecord, error) {
	body, err := a.fetchBambuConnectBody(ctx, path)
	if err != nil {
		return nil, err
	}

	var direct []bambuConnectPrinterRecord
	if err := json.Unmarshal(body, &direct); err == nil {
		return normalizeBambuConnectPrinterList(direct), nil
	}

	var objectPayload struct {
		Printers []bambuConnectPrinterRecord `json:"printers"`
		Devices  []bambuConnectPrinterRecord `json:"devices"`
		Data     []bambuConnectPrinterRecord `json:"data"`
		Items    []bambuConnectPrinterRecord `json:"items"`
	}
	if err := json.Unmarshal(body, &objectPayload); err != nil {
		return nil, fmt.Errorf("bambu connect decode failed for %s: %w", path, err)
	}
	records := objectPayload.Printers
	if len(records) == 0 {
		records = objectPayload.Devices
	}
	if len(records) == 0 {
		records = objectPayload.Data
	}
	if len(records) == 0 {
		records = objectPayload.Items
	}
	return normalizeBambuConnectPrinterList(records), nil
}

func (a *agent) fetchBambuConnectPrinterRecordPath(ctx context.Context, path string) (bambuConnectPrinterRecord, error) {
	body, err := a.fetchBambuConnectBody(ctx, path)
	if err != nil {
		return bambuConnectPrinterRecord{}, err
	}

	var direct bambuConnectPrinterRecord
	if err := json.Unmarshal(body, &direct); err == nil {
		return direct, nil
	}

	var objectPayload struct {
		Printer bambuConnectPrinterRecord `json:"printer"`
		Data    bambuConnectPrinterRecord `json:"data"`
	}
	if err := json.Unmarshal(body, &objectPayload); err != nil {
		return bambuConnectPrinterRecord{}, fmt.Errorf("bambu connect status decode failed for %s: %w", path, err)
	}
	if bambuConnectPrinterIdentifier(objectPayload.Printer) != "" {
		return objectPayload.Printer, nil
	}
	return objectPayload.Data, nil
}

func (a *agent) fetchBambuConnectBody(ctx context.Context, path string) ([]byte, error) {
	baseURI := strings.TrimSpace(a.cfg.BambuConnectURI)
	if baseURI == "" {
		return nil, errors.New("validation_error: BAMBU_CONNECT_URI is required for bambu connect bridge")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolveURL(baseURI, path), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bambu connect request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("bambu connect %s returned %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func normalizeBambuConnectPrinterList(values []bambuConnectPrinterRecord) []bambuConnectPrinterRecord {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]bambuConnectPrinterRecord, 0, len(values))
	for _, item := range values {
		id := bambuConnectPrinterIdentifier(item)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, item)
	}
	return out
}

func parseBambuPrinterEndpointID(endpointURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpointURL))
	if err != nil {
		return "", fmt.Errorf("validation_error: invalid bambu endpoint_url: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(parsed.Scheme), "bambu") {
		return "", fmt.Errorf("validation_error: unsupported bambu endpoint_url scheme: %q", strings.TrimSpace(parsed.Scheme))
	}
	printerID := strings.TrimSpace(parsed.Host)
	if printerID == "" {
		rawPath := strings.Trim(strings.TrimSpace(parsed.EscapedPath()), "/")
		if rawPath != "" {
			unescaped, pathErr := url.PathUnescape(rawPath)
			if pathErr == nil {
				printerID = strings.TrimSpace(unescaped)
			} else {
				printerID = rawPath
			}
		}
	}
	if printerID == "" {
		return "", errors.New("validation_error: bambu endpoint_url missing printer identifier")
	}
	return printerID, nil
}

func formatBambuPrinterEndpoint(printerID string) string {
	return "bambu://" + strings.TrimSpace(printerID)
}

func redactBambuConnectURI(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme == "" {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s", scheme, strings.TrimSpace(parsed.Host))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func bambuConnectPrinterIdentifier(printer bambuConnectPrinterRecord) string {
	return firstNonEmpty(printer.PrinterID, printer.ID, printer.DeviceID, printer.Serial)
}

func bambuConnectPrinterName(printer bambuConnectPrinterRecord) string {
	return firstNonEmpty(printer.PrinterName, printer.Name, printer.DeviceName)
}

func mapBambuConnectStates(rawPrinterState string, rawJobState string) (printerState string, jobState string) {
	switch strings.ToLower(strings.TrimSpace(rawPrinterState)) {
	case "printing", "running":
		printerState = "printing"
	case "paused", "pause":
		printerState = "paused"
	case "error", "failed", "fault":
		printerState = "error"
	case "queued", "pending", "preparing", "starting", "heating":
		printerState = "queued"
	case "idle", "ready", "standby", "completed", "finished":
		printerState = "idle"
	default:
		printerState = "idle"
	}

	switch strings.ToLower(strings.TrimSpace(rawJobState)) {
	case "printing", "running", "started", "in_progress":
		jobState = "printing"
	case "paused", "pause":
		jobState = "printing"
	case "failed", "error":
		jobState = "failed"
	case "completed", "finished", "success":
		jobState = "completed"
	case "canceled", "cancelled":
		jobState = "canceled"
	case "queued", "pending", "preparing":
		jobState = "pending"
	}
	if jobState == "" {
		switch printerState {
		case "printing", "paused":
			jobState = "printing"
		case "error":
			jobState = "failed"
		case "queued":
			jobState = "pending"
		default:
			jobState = "pending"
		}
	}
	return printerState, jobState
}

func (a *agent) fetchMoonrakerSnapshot(ctx context.Context, endpointURL string) (printerState string, jobState string, err error) {
	return a.fetchMoonrakerSnapshotWithTimeout(ctx, endpointURL, a.cfg.MoonrakerRequestTimeout)
}

func (a *agent) fetchMoonrakerSnapshotWithTimeout(ctx context.Context, endpointURL string, requestTimeout time.Duration) (printerState string, jobState string, err error) {
	// Prefer subscribe snapshot when available and fall back to direct query for compatibility.
	state, err := a.fetchMoonrakerPrintStatsState(
		ctx,
		endpointURL,
		http.MethodPost,
		"/printer/objects/subscribe",
		map[string]any{"objects": map[string]any{"print_stats": nil}},
		requestTimeout,
	)
	if err != nil {
		state, err = a.fetchMoonrakerPrintStatsState(
			ctx,
			endpointURL,
			http.MethodGet,
			"/printer/objects/query?print_stats",
			nil,
			requestTimeout,
		)
		if err != nil {
			return "", "", err
		}
	}

	return mapMoonrakerPrintStatsState(state)
}

func (a *agent) fetchMoonrakerPrintStatsState(
	ctx context.Context,
	endpointURL string,
	method string,
	path string,
	payload any,
	requestTimeout time.Duration,
) (string, error) {
	if requestTimeout <= 0 {
		requestTimeout = a.cfg.MoonrakerRequestTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = 8 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(requestCtx, method, resolveURL(endpointURL, path), body)
	if err != nil {
		return "", err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("snapshot request %s failed: status=%d body=%s", path, resp.StatusCode, string(responseBody))
	}

	var snapshot struct {
		Result struct {
			Status struct {
				PrintStats struct {
					State string `json:"state"`
				} `json:"print_stats"`
			} `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&snapshot); err != nil {
		return "", err
	}
	state := strings.ToLower(strings.TrimSpace(snapshot.Result.Status.PrintStats.State))
	if state == "" {
		return "", fmt.Errorf("snapshot request %s returned empty print_stats.state", path)
	}
	return state, nil
}

func (a *agent) fetchMoonrakerTelemetry(ctx context.Context, endpointURL string) (*float64, *float64, string, string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/printer/objects/query?print_stats&display_status"),
		nil,
	)
	if err != nil {
		return nil, nil, "", "", err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, nil, "", "", fmt.Errorf("moonraker telemetry failed: status=%d body=%s", resp.StatusCode, string(responseBody))
	}

	var payload struct {
		Result struct {
			Status struct {
				PrintStats struct {
					State         string  `json:"state"`
					Filename      string  `json:"filename"`
					TotalDuration float64 `json:"total_duration"`
					PrintDuration float64 `json:"print_duration"`
				} `json:"print_stats"`
				DisplayStatus struct {
					Progress float64 `json:"progress"`
				} `json:"display_status"`
			} `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, nil, "", "", err
	}

	state := strings.ToLower(strings.TrimSpace(payload.Result.Status.PrintStats.State))
	manualIntervention := ""
	telemetrySource := "moonraker"
	if state == "cancelled" || state == "canceled" {
		manualIntervention = "canceled"
	}

	progressPct := (*float64)(nil)
	progress := payload.Result.Status.DisplayStatus.Progress
	if progress >= 0 && progress <= 1 {
		value := progress * 100
		if value < 0 {
			value = 0
		}
		if value > 100 {
			value = 100
		}
		progressPct = &value
	}

	remainingSeconds := (*float64)(nil)
	if state == "printing" || state == "paused" {
		printDuration := payload.Result.Status.PrintStats.PrintDuration
		if printDuration < 0 {
			printDuration = 0
		}
		totalDuration := payload.Result.Status.PrintStats.TotalDuration
		if progress > 0 && progress < 1 && printDuration >= 0 {
			estimatedTotal := printDuration / progress
			remaining := estimatedTotal - printDuration
			if remaining < 0 {
				remaining = 0
			}
			remainingSeconds = &remaining
		} else if totalDuration > 0 && printDuration >= 0 {
			remaining := totalDuration - printDuration
			if remaining < 0 {
				remaining = 0
			}
			remainingSeconds = &remaining
		}

		filename := strings.TrimSpace(payload.Result.Status.PrintStats.Filename)
		if filename != "" {
			estimatedSeconds, metadataErr := a.fetchMoonrakerFileEstimatedSeconds(ctx, endpointURL, filename)
			if metadataErr != nil {
				a.audit("moonraker_file_metadata_error", map[string]any{
					"endpoint_url": endpointURL,
					"filename":     filename,
					"error":        metadataErr.Error(),
				})
			} else if estimatedSeconds != nil && *estimatedSeconds > 0 {
				remaining := *estimatedSeconds - printDuration
				if remaining < 0 {
					remaining = 0
				}
				remainingSeconds = &remaining
				if progressPct == nil || progress <= 0 {
					value := (printDuration / *estimatedSeconds) * 100
					if value < 0 {
						value = 0
					}
					if value > 100 {
						value = 100
					}
					progressPct = &value
				}
				telemetrySource = "moonraker_metadata"
			}
		}
	}

	return progressPct, remainingSeconds, telemetrySource, manualIntervention, nil
}

func (a *agent) fetchMoonrakerFileEstimatedSeconds(ctx context.Context, endpointURL string, filename string) (*float64, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/server/files/metadata?filename="+url.QueryEscape(filename)),
		nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("moonraker file metadata failed: status=%d body=%s", resp.StatusCode, string(responseBody))
	}

	var payload struct {
		Result struct {
			EstimatedTime       *float64 `json:"estimated_time"`
			SlicerEstimatedTime *float64 `json:"slicer_estimated_time"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	candidates := []*float64{
		payload.Result.EstimatedTime,
		payload.Result.SlicerEstimatedTime,
	}
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if *candidate <= 0 {
			continue
		}
		value := *candidate
		return &value, nil
	}
	return nil, nil
}

func (a *agent) fetchMoonrakerTotalPrintSeconds(ctx context.Context, endpointURL string) (*float64, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/server/history/totals"),
		nil,
	)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("moonraker totals failed: status=%d body=%s", resp.StatusCode, string(responseBody))
	}

	var totals struct {
		Result struct {
			JobTotals struct {
				TotalPrintTime float64 `json:"total_print_time"`
			} `json:"job_totals"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&totals); err != nil {
		return nil, err
	}
	if totals.Result.JobTotals.TotalPrintTime < 0 {
		return nil, fmt.Errorf("moonraker totals returned negative total_print_time")
	}
	value := totals.Result.JobTotals.TotalPrintTime
	return &value, nil
}

func (a *agent) fetchMoonrakerProductInfo(ctx context.Context, endpointURL string) (detectedName string, detectedModelHint string, err error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/machine/system_info"),
		nil,
	)
	if err != nil {
		return "", "", err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", fmt.Errorf("moonraker system_info failed: status=%d body=%s", resp.StatusCode, string(responseBody))
	}

	var payload struct {
		Result struct {
			SystemInfo struct {
				ProductInfo struct {
					MachineType string `json:"machine_type"`
					DeviceName  string `json:"device_name"`
				} `json:"product_info"`
			} `json:"system_info"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", err
	}

	detectedModelHint = strings.TrimSpace(payload.Result.SystemInfo.ProductInfo.MachineType)
	detectedName = strings.TrimSpace(payload.Result.SystemInfo.ProductInfo.DeviceName)
	if detectedName == "" {
		detectedName = strings.TrimSpace(hostnameFromURL(endpointURL))
	}
	return detectedName, detectedModelHint, nil
}

func hostnameFromURL(endpointURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(endpointURL))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Hostname())
}

func mapMoonrakerPrintStatsState(state string) (printerState string, jobState string, err error) {
	switch state {
	case "printing":
		return "printing", "printing", nil
	case "paused":
		return "paused", "printing", nil
	case "cancelled", "canceled":
		return "idle", "canceled", nil
	case "error":
		return "error", "failed", nil
	case "queued":
		return "queued", "pending", nil
	default:
		return "idle", "pending", nil
	}
}

func randomKey(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(buf))
}

func normalizeETag(raw string) string {
	return strings.Trim(strings.TrimSpace(raw), "\"")
}

func schemaVersionHeaderValue() string {
	return strconv.Itoa(agentSchemaVersion)
}

func shouldLogAuditEventToStdout(event string) bool {
	e := strings.ToLower(strings.TrimSpace(event))
	if e == "" {
		return false
	}
	if strings.Contains(e, "error") || strings.Contains(e, "failed") {
		return true
	}
	// Keep successful operational events visible in stdout for manual runtime verification.
	switch e {
	case "action_executed",
		"action_reenqueue_suppressed",
		"artifact_downloaded",
		"artifact_uploaded",
		"bambu_print_start_http_unsupported",
		"bambu_print_start_dispatch_attempt",
		"bambu_print_start_verified",
		"print_start_requested",
		"uncertain_action_resolved",
		"state_pushed",
		"desired_state_updated",
		"bindings_updated",
		"discovery_scan_started",
		"discovery_scan_plan",
		"discovery_scan_completed",
		"discovery_scan_zero_candidates",
		"discovery_inventory_submitted",
		"discovery_inventory_submit_ok",
		"discovery_network_mode_fallback":
		return true
	default:
		return false
	}
}

func supportsSchemaVersion(version int, supported []int) bool {
	if version <= 0 {
		return false
	}
	for _, candidate := range supported {
		if candidate == version {
			return true
		}
	}
	return false
}

func resolveURL(baseURL, path string) string {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return strings.TrimSuffix(baseURL, "/") + path
	}
	ref, err := url.Parse(path)
	if err != nil {
		return strings.TrimSuffix(baseURL, "/") + path
	}
	return base.ResolveReference(ref).String()
}

func (a *agent) loadBootstrapConfig() error {
	info, err := os.Stat(a.cfg.BootstrapConfigPath)
	if err != nil {
		return err
	}
	if err := ensureSecretDirPermissions(filepath.Dir(a.cfg.BootstrapConfigPath)); err != nil {
		return err
	}
	if err := ensureSecretFilePermissions(a.cfg.BootstrapConfigPath, info.Mode()); err != nil {
		return err
	}

	data, err := os.ReadFile(a.cfg.BootstrapConfigPath)
	if err != nil {
		return err
	}
	var cfg bootstrapConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	a.mu.Lock()
	a.bootstrap = cfg
	a.claimed = cfg.AgentID != ""
	a.mu.Unlock()
	return nil
}

func ensureSecretFilePermissions(filePath string, mode os.FileMode) error {
	perms := mode.Perm()
	if perms != 0o600 {
		if err := os.Chmod(filePath, 0o600); err != nil {
			return fmt.Errorf("bootstrap config file permissions must be 0600, got %o: %w", perms, err)
		}
	}
	return nil
}

func ensureSecretDirPermissions(dirPath string) error {
	info, err := os.Stat(dirPath)
	if err != nil {
		return err
	}
	perms := info.Mode().Perm()
	// Directory must not be accessible by group/other.
	if perms&0o077 != 0 {
		if err := os.Chmod(dirPath, 0o700); err != nil {
			return fmt.Errorf("bootstrap config directory permissions must be 0700, got %o: %w", perms, err)
		}
	}
	return nil
}

func (a *agent) saveBootstrapConfig() error {
	a.mu.RLock()
	cfg := a.bootstrap
	a.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(a.cfg.BootstrapConfigPath), 0o700); err != nil {
		return err
	}

	tmpPath := a.cfg.BootstrapConfigPath + ".tmp"
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, a.cfg.BootstrapConfigPath); err != nil {
		return err
	}
	return os.Chmod(a.cfg.BootstrapConfigPath, 0o600)
}

func (a *agent) audit(event string, payload map[string]any) {
	a.auditMu.Lock()
	defer a.auditMu.Unlock()

	record := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"event": event,
	}
	for k, v := range payload {
		record[k] = v
	}

	line, err := json.Marshal(record)
	if err != nil {
		log.Printf("audit marshal failed: %v", err)
		return
	}

	if shouldLogAuditEventToStdout(event) {
		log.Printf("edge-event %s %s", event, string(line))
	}

	if err := os.MkdirAll(filepath.Dir(a.cfg.AuditLogPath), 0o755); err != nil {
		log.Printf("audit mkdir failed: %v", err)
		return
	}

	f, err := os.OpenFile(a.cfg.AuditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("audit open failed: %v", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		log.Printf("audit write failed: %v", err)
	}
}

func doJSONRequest(client *http.Client, method, url, apiKey, idempotencyKey string, reqBody any, out any, headers map[string]string) error {
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("request failed %d: %s", resp.StatusCode, string(body))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
