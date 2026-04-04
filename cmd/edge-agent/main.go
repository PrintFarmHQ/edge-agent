package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
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
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	bambuauth "printfarmhq/edge-agent/internal/bambu/auth"
	bambucamera "printfarmhq/edge-agent/internal/bambu/cameraruntime"
	bambucloud "printfarmhq/edge-agent/internal/bambu/cloud"
	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
	moonrakeradapter "printfarmhq/edge-agent/internal/printeradapter/moonraker"
	snapmakeru1 "printfarmhq/edge-agent/internal/printeradapter/moonraker/snapmaker_u1"
	bambustore "printfarmhq/edge-agent/internal/store"
)

const (
	agentVersion                 = "0.1.0"
	agentSchemaVersion           = 2
	bambuPluginStartupTimeout    = 60 * time.Second
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
	recoveryAppendCIDRTargetsKey = "append_cidr_targets"
	telemetrySourceBambuCloud    = "bambu_cloud"
	telemetrySourceBambuConnect  = "bambu_connect"
	defaultBambuMQTTTopic        = "device/%s/request"
	defaultBambuMQTTBrokerGlobal = "us.mqtt.bambulab.com:8883"
	defaultBambuMQTTBrokerChina  = "cn.mqtt.bambulab.com:8883"
	moonrakerCameraMonitorPath   = "/server/files/camera/monitor.jpg"
)

var agentSupportedSchemaVersions = []int{1, agentSchemaVersion}
var errEdgeAuthRevoked = errors.New("edge_api_key_revoked")
var errBambuAuthUnavailable = errors.New("validation_error: bambu auth is not ready")

const bambuLANCredentialRecoveryCooldown = 30 * time.Second

var macAddressPattern = regexp.MustCompile(`([0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5})`)
var cloudStartStatusPattern = regexp.MustCompile(`status=(\d{3})`)
var cloudStartMethodEndpointPattern = regexp.MustCompile(`\b(GET|POST|PUT|PATCH|DELETE)\s+(https?://\S+)`)
var cloudStartVariantPattern = regexp.MustCompile(`task_variant_(\d+)`)
var arpCommandWarningOnce sync.Once
var runARPCommand = func(parts []string) ([]byte, error) {
	cmd := exec.Command(parts[0], parts[1:]...)
	return cmd.Output()
}
var runExternalCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}
var logARPCommandWarning = func(message string, args ...any) {
	log.Printf(message, args...)
}
var bambuAuthInputReader io.Reader = os.Stdin
var bambuAuthOutputWriter io.Writer = os.Stdout
var isBambuAuthInteractiveConsole = defaultIsBambuAuthInteractiveConsole
var sendMoonrakerCameraMonitorCommand = sendMoonrakerCameraMonitorCommandDefault
var preflightBambuPluginBundleOnStartup = preflightBambuPluginBundleOnStartupDefault

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

type stagedArtifact struct {
	LocalPath           string
	SourceFilename      string
	NormalizedExtension string
	SizeBytes           int64
	SHA256              string
	MD5                 string
	RemoteName          string
}

func (a stagedArtifact) preferredSourceName() string {
	if source := strings.TrimSpace(a.SourceFilename); source != "" {
		return source
	}
	return strings.TrimSpace(a.RemoteName)
}

func (a stagedArtifact) moonrakerRemoteName() string {
	return strings.TrimSpace(a.RemoteName)
}

func (a stagedArtifact) bambuLANRemoteName() string {
	return normalizeBambuLANRemoteStartFilename(strings.TrimSpace(a.RemoteName))
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

type configCommandItem struct {
	CommandID                int             `json:"command_id"`
	CommandType              string          `json:"command_type"`
	TargetAdapterFamily      string          `json:"target_adapter_family"`
	TargetEndpointNormalized string          `json:"target_endpoint_normalized"`
	Payload                  json.RawMessage `json:"payload"`
	CreatedAt                edgeTimestamp   `json:"created_at"`
	ExpiresAt                edgeTimestamp   `json:"expires_at"`
}

type configCommandsResponse struct {
	Commands []configCommandItem `json:"commands"`
}

type printerCommandItem struct {
	CommandID  int             `json:"command_id"`
	PrinterID  int             `json:"printer_id"`
	CommandKey string          `json:"command_key"`
	Payload    json.RawMessage `json:"payload"`
	CreatedAt  edgeTimestamp   `json:"created_at"`
	ExpiresAt  edgeTimestamp   `json:"expires_at"`
}

type printerCommandsResponse struct {
	Commands []printerCommandItem `json:"commands"`
}

type cameraSessionItem struct {
	SessionID     string `json:"session_id"`
	PrinterID     int    `json:"printer_id"`
	AdapterFamily string `json:"adapter_family"`
	IngestURL     string `json:"ingest_url"`
	CloseURL      string `json:"close_url"`
}

type cameraSessionsResponse struct {
	Sessions []cameraSessionItem `json:"sessions"`
}

type cameraSessionCloseRequest struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type configCommandAckRequest struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type configCommandAckResponse struct {
	Accepted bool `json:"accepted"`
}

type printerCommandAckRequest struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type printerCommandAckResponse struct {
	Accepted bool `json:"accepted"`
}

type printerFileFingerprint struct {
	Path       string     `json:"path"`
	SizeBytes  *int64     `json:"size_bytes,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
}

type printerFileEntry struct {
	Path                string                 `json:"path"`
	DisplayPath         string                 `json:"display_path,omitempty"`
	DisplayName         string                 `json:"display_name"`
	SizeBytes           *int64                 `json:"size_bytes,omitempty"`
	ModifiedAt          *time.Time             `json:"modified_at,omitempty"`
	Format              string                 `json:"format,omitempty"`
	Origin              string                 `json:"origin,omitempty"`
	Kind                string                 `json:"kind,omitempty"`
	Location            string                 `json:"location,omitempty"`
	Startable           bool                   `json:"startable"`
	Deletable           bool                   `json:"deletable"`
	IsActiveFile        bool                   `json:"is_active_file"`
	StartDescriptor     map[string]any         `json:"start_descriptor,omitempty"`
	DeleteDescriptor    map[string]any         `json:"delete_descriptor,omitempty"`
	ExpectedFingerprint printerFileFingerprint `json:"expected_fingerprint"`
}

type printerFilesSnapshotItem struct {
	PrinterID     int                `json:"printer_id"`
	AdapterFamily string             `json:"adapter_family,omitempty"`
	Files         []printerFileEntry `json:"files"`
	ReportedAt    edgeTimestamp      `json:"reported_at"`
	Error         string             `json:"error,omitempty"`
}

type printerFilesReportRequest struct {
	Items []printerFilesSnapshotItem `json:"items"`
}

type printerFilesReportResponse struct {
	Accepted int `json:"accepted"`
}

type bambuCredentialRecoveryRequest struct {
	PrinterID   int    `json:"printer_id"`
	EndpointURL string `json:"endpoint_url"`
}

type bambuCredentialRecoveryResponse struct {
	Accepted       bool   `json:"accepted"`
	RecoveryQueued bool   `json:"recovery_queued"`
	PrinterID      int    `json:"printer_id"`
	AgentID        string `json:"agent_id"`
	EndpointURL    string `json:"endpoint_url"`
	CommandID      int    `json:"command_id"`
}

type bambuLANCredentialsUpsertPayload struct {
	Serial     string `json:"serial"`
	Host       string `json:"host"`
	AccessCode string `json:"access_code"`
	Name       string `json:"name,omitempty"`
	Model      string `json:"model,omitempty"`
}

type currentStateItem struct {
	PrinterID            int            `json:"printer_id"`
	CurrentPrinterState  string         `json:"current_printer_state"`
	CurrentJobState      string         `json:"current_job_state,omitempty"`
	JobID                string         `json:"job_id,omitempty"`
	PlateID              int            `json:"plate_id,omitempty"`
	IntentVersionApplied int            `json:"intent_version_applied,omitempty"`
	IsPaused             bool           `json:"is_paused"`
	IsCanceled           bool           `json:"is_canceled"`
	LastErrorCode        string         `json:"last_error_code,omitempty"`
	LastErrorMessage     string         `json:"last_error_message,omitempty"`
	TotalPrintSeconds    *float64       `json:"total_print_seconds,omitempty"`
	ProgressPct          *float64       `json:"progress_pct,omitempty"`
	RemainingSeconds     *float64       `json:"remaining_seconds,omitempty"`
	TelemetrySource      string         `json:"telemetry_source,omitempty"`
	ManualIntervention   string         `json:"manual_intervention,omitempty"`
	CommandCapabilities  map[string]any `json:"command_capabilities,omitempty"`
	ReportedAt           time.Time      `json:"reported_at"`
}

type printerTemperatureStatus struct {
	Available bool     `json:"available"`
	Current   *float64 `json:"current,omitempty"`
	Target    *float64 `json:"target,omitempty"`
}

type printerFanStatus struct {
	Label     string `json:"label,omitempty"`
	Supported bool   `json:"supported"`
	State     string `json:"state,omitempty"`
}

type printerControlStatusSnapshot struct {
	Nozzle          printerTemperatureStatus    `json:"nozzle"`
	Bed             printerTemperatureStatus    `json:"bed"`
	Chamber         printerTemperatureStatus    `json:"chamber"`
	Fans            map[string]printerFanStatus `json:"fans,omitempty"`
	MotionSupported bool                        `json:"motion_supported"`
	HomeSupported   bool                        `json:"home_supported"`
}

const (
	filamentActionStateIdle                  = "idle"
	filamentActionStateLoading               = "loading"
	filamentActionStateUnloading             = "unloading"
	filamentActionStateNeedsUserConfirmation = "needs_user_confirmation"
)

const (
	filamentStateSourceMoonrakerSensor    = "moonraker_sensor"
	filamentStateSourceBambuActiveSource  = "bambu_active_source"
	filamentStateSourceBambuCommandMemory = "bambu_command_memory"
	filamentStateSourceCommandFallback    = "command_fallback"
	filamentStateSourceUnknown            = "unknown"
)

const (
	filamentSourceKindExternalSpool = "external_spool"
	filamentSourceKindAMS           = "ams"
	filamentSourceKindNone          = "none"
	filamentSourceKindUnknown       = "unknown"
)

const (
	filamentConfidenceConfirmed = "confirmed"
	filamentConfidenceHeuristic = "heuristic"
)

const (
	moonrakerFilamentActionTimeout    = 20 * time.Second
	bambuFilamentActionTimeout        = 45 * time.Second
	bambuFilamentMemoryGrace          = 10 * time.Second
	bambuRuntimeCommandSuppressWindow = 8 * time.Second
)

type pushStateRequest struct {
	States []currentStateItem `json:"states"`
}

type printerControlStatusItem struct {
	PrinterID     int                          `json:"printer_id"`
	AdapterFamily string                       `json:"adapter_family,omitempty"`
	Status        printerControlStatusSnapshot `json:"status"`
	ReportedAt    time.Time                    `json:"reported_at"`
}

type pushPrinterControlStatusRequest struct {
	Items []printerControlStatusItem `json:"items"`
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
	PrinterID        int              `json:"printer_id"`
	Kind             string           `json:"kind"`
	Reason           string           `json:"reason"`
	Payload          map[string]any   `json:"payload,omitempty"`
	Target           desiredStateItem `json:"target"`
	CommandRequestID int              `json:"command_request_id,omitempty"`
	EnqueuedAt       time.Time        `json:"enqueued_at"`
	Attempts         int              `json:"attempts"`
	NextAttempt      time.Time        `json:"next_attempt"`
}

type bindingSnapshot struct {
	PrinterState        string
	JobState            string
	TotalPrintSeconds   *float64
	ProgressPct         *float64
	RemainingSeconds    *float64
	TelemetrySource     string
	RawPrinterStatus    string
	ActiveFilePath      string
	ManualIntervention  string
	CommandCapabilities map[string]any
	ControlStatus       *printerControlStatusSnapshot
	DetectedName        string
	DetectedModelHint   string
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
	SetupBindAddr                     string
	BootstrapConfigPath               string
	AuditLogPath                      string
	ArtifactStageDir                  string
	StartupControlPlaneURL            string
	StartupSaaSAPIKey                 string
	EnableKlipper                     bool
	EnableBambu                       bool
	BambuCloudAuthBaseURL             string
	BambuCloudUploadPath              string
	BambuCloudPrintPath               string
	BambuCloudMQTTBroker              string
	BambuCloudMQTTTopicTemplate       string
	BambuConnectURI                   string
	BambuCameraRuntimeDir             string
	BambuCameraHelperMJPEGURLTemplate string
	BambuCameraRTSPFallbackEnabled    bool
	BambuControlStatusPushInterval    time.Duration
	BindingsPollInterval              time.Duration
	ConfigCommandsPollInterval        time.Duration
	PrinterCommandsPollInterval       time.Duration
	DesiredStatePollInterval          time.Duration
	StatePushInterval                 time.Duration
	ConvergenceTickInterval           time.Duration
	ActionExecInterval                time.Duration
	ActionRetryBaseInterval           time.Duration
	ActionMaxAttempts                 int
	ActionNonRetryableCooldown        time.Duration
	MoonrakerRequestTimeout           time.Duration
	BambuLANRuntimeTimeout            time.Duration
	ArtifactUploadTimeout             time.Duration
	ArtifactDownloadTimeout           time.Duration
	CircuitBreakerCooldown            time.Duration
	ProbePollInterval                 time.Duration
	DiscoveryPollInterval             time.Duration
	DiscoveryInventoryInterval        time.Duration
	DiscoveryManualPollInterval       time.Duration
	LocalUIScanInterval               time.Duration
	LocalUIBindAddr                   string
	DiscoveryProfileMax               string
	DiscoveryNetworkMode              string
	DiscoveryAllowedAdapters          []string
	DiscoveryEndpointHints            []string
	DiscoveryCIDRAllowlist            []string
	DiscoveryMaxTargets               int
	DiscoveryWorkerCount              int
	DiscoveryProbeTimeout             time.Duration
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

	bambuAuthProvider  bambuauth.Provider
	bambuAuthStore     bambustore.BambuCredentialsStore
	bambuLANStore      bambustore.BambuLANCredentialsStore
	bambuCameraRuntime bambucamera.Runtime
	bambuMQTTPublish   bambuPrintCommandPublisher
	bambuAuthMu        sync.RWMutex
	bambuAuth          bambuAuthState
	controlPlaneMu     sync.RWMutex
	controlPlane       localControlPlaneState
	localWebUIMu       sync.RWMutex
	localWebUIURL      string

	mu                        sync.RWMutex
	bootstrap                 bootstrapConfig
	claimed                   bool
	lastETag                  string
	desiredState              map[int]desiredStateItem
	bindings                  map[int]edgeBinding
	currentState              map[int]currentStateItem
	actionQueue               map[int][]action
	inflightActions           map[int]action
	deadLetters               map[int][]action
	queuedSince               map[int]time.Time
	recentEnqueue             map[string]time.Time
	suppressedUntil           map[string]time.Time
	resyncRequested           bool
	breakerUntil              map[int]time.Time
	bambuRuntimeSuppressUntil map[int]time.Time

	discoveryStateMu       sync.Mutex
	discoveryRunning       bool
	discoverySeedMu        sync.Mutex
	discoverySeeds         map[string]time.Time
	bambuLANMu             sync.Mutex
	bambuLANRecords        map[string]bambuLANDiscoveryRecord
	bambuLANRuntimeRecords map[string]*bambuLANRuntimeRecord
	bambuLANFallbackUsed   map[string]bool
	bambuLANFailures       map[string]int
	bambuLANRecoveryUntil  map[int]time.Time
	bambuLANProbeHosts     map[string]time.Time

	localObservations    *localObservationStore
	activeCameraSessions map[string]context.CancelFunc
	auditMu              sync.Mutex
}

func main() {
	flags, err := parseRuntimeFlags(os.Args[1:])
	if err != nil {
		log.Fatalf("failed to parse startup flags: %v", err)
	}

	cfg := loadConfig()
	cfg = applyRuntimeFlags(cfg, flags)
	app := &agent{
		cfg:                       cfg,
		client:                    &http.Client{Timeout: 15 * time.Second},
		desiredState:              make(map[int]desiredStateItem),
		bindings:                  make(map[int]edgeBinding),
		currentState:              make(map[int]currentStateItem),
		actionQueue:               make(map[int][]action),
		inflightActions:           make(map[int]action),
		deadLetters:               make(map[int][]action),
		queuedSince:               make(map[int]time.Time),
		recentEnqueue:             make(map[string]time.Time),
		suppressedUntil:           make(map[string]time.Time),
		breakerUntil:              make(map[int]time.Time),
		bambuRuntimeSuppressUntil: make(map[int]time.Time),
		discoverySeeds:            make(map[string]time.Time),
		bambuLANRecords:           make(map[string]bambuLANDiscoveryRecord),
		bambuLANRuntimeRecords:    make(map[string]*bambuLANRuntimeRecord),
		bambuLANFallbackUsed:      make(map[string]bool),
		bambuLANFailures:          make(map[string]int),
		bambuLANRecoveryUntil:     make(map[int]time.Time),
		bambuLANProbeHosts:        make(map[string]time.Time),
		localObservations:         newLocalObservationStore(),
		activeCameraSessions:      make(map[string]context.CancelFunc),
	}
	if cfg.EnableBambu {
		bambuRuntime, err := prepareBambuRuntimeForStartup(cfg)
		if err != nil {
			log.Fatalf("failed to prepare Bambu runtime: %v", err)
		}
		app.bambuCameraRuntime = bambuRuntime
	}
	bambuLANStoreWarning := ""
	if cfg.EnableBambu {
		lanStore, storeErr := bambustore.NewDefaultBambuLANCredentialsFileStore()
		if storeErr != nil {
			bambuLANStoreWarning = storeErr.Error()
		} else {
			app.bambuLANStore = lanStore
		}
	}

	if err := app.loadBootstrapConfig(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("failed to load bootstrap config: %v", err)
	}
	if strings.TrimSpace(app.snapshotBootstrap().SaaSAPIKey) != "" {
		app.recordControlPlaneAPIKeySeen()
	}

	mux := http.NewServeMux()
	app.registerRoutes(mux)

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	signalEvents := make(chan os.Signal, 1)
	signal.Notify(signalEvents, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signalEvents)

	// Attempt one bootstrap sync when restarting with persisted claim.
	setupListener, err := net.Listen("tcp", cfg.SetupBindAddr)
	if err != nil {
		log.Fatalf("http server failed: %v", err)
	}
	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(setupListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	var localUIServer *http.Server
	localUIURL := ""
	localUIStartWarning := ""
	if startedServer, uiURL, _, err := app.startLocalWebUIServer(); err != nil {
		localUIStartWarning = err.Error()
	} else {
		localUIServer = startedServer
		app.setLocalWebUIURL(uiURL)
		localUIURL = uiURL
	}

	printStartupBanner(startupBannerInfo{
		DashboardURL:    localUIURL,
		EnabledAdapters: enabledDiscoveryAdapters(cfg.EnableKlipper, cfg.EnableBambu),
		ShowAlertOnly:   !app.isClaimed() && strings.TrimSpace(cfg.StartupSaaSAPIKey) == "",
		AlertMessage:    "Edge agent is NOT connected to control plane SaaS. Paste a valid API key in the dashboard.",
	})
	if bambuLANStoreWarning != "" {
		log.Printf("warning: failed to initialize bambu LAN credentials store: %v", bambuLANStoreWarning)
	}
	if localUIStartWarning != "" {
		log.Printf("warning: local web ui unavailable: %v", localUIStartWarning)
	}
	if err := app.cleanupStagedArtifacts(); err != nil {
		log.Printf("warning: artifact cleanup on startup failed: %v", err)
	}
	if err := app.bootstrapFromStartupCredentials(context.Background()); err != nil {
		log.Printf("warning: startup claim unavailable: %v", err)
	}

	// Attempt one bootstrap sync when restarting with persisted claim.
	if app.isClaimed() {
		app.bootstrapSync(rootCtx)
	}
	if localUIURL != "" {
		status, _, _, _ := app.localControlPlaneSnapshot(time.Now().UTC())
		if !isControlPlaneConnectedStatus(status) {
			app.openBrowserForLocalDashboard(localUIURL)
		}
	}

	var wg sync.WaitGroup
	wg.Add(14)
	go app.bindingsPollLoop(rootCtx, &wg)
	go app.configCommandsPollLoop(rootCtx, &wg)
	go app.printerCommandsPollLoop(rootCtx, &wg)
	go app.cameraSessionsPollLoop(rootCtx, &wg)
	go app.desiredStatePollLoop(rootCtx, &wg)
	go app.convergenceLoop(rootCtx, &wg)
	go app.actionExecLoop(rootCtx, &wg)
	go app.statePushLoop(rootCtx, &wg)
	go app.controlStatusPushLoop(rootCtx, &wg)
	go app.probePollLoop(rootCtx, &wg)
	go app.discoveryPollLoop(rootCtx, &wg)
	go app.discoveryInventoryLoop(rootCtx, &wg)
	go app.discoveryManualTriggerLoop(rootCtx, &wg)
	go app.localObservationScanLoop(rootCtx, &wg)

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
	if localUIServer != nil {
		_ = localUIServer.Shutdown(shutdownCtx)
	}
	wg.Wait()
}

func (a *agent) bootstrapSync(ctx context.Context) {
	if err := a.pollBindingsOnce(ctx); err != nil {
		a.audit("bootstrap_bindings_error", map[string]any{"error": err.Error()})
	}
	if err := a.pollConfigCommandsOnce(ctx); err != nil {
		a.audit("bootstrap_config_commands_error", map[string]any{"error": err.Error()})
	}
	if err := a.pollDesiredStateOnce(ctx); err != nil {
		a.audit("bootstrap_desired_state_error", map[string]any{"error": err.Error()})
	}
	a.refreshCurrentStateFromBindings(ctx)
	a.reconcileOnce()
	if err := a.pushStateOnce(ctx); err != nil {
		a.audit("bootstrap_state_push_error", map[string]any{"error": err.Error()})
	}
	if err := a.pushPrinterControlStatusOnce(ctx); err != nil {
		a.audit("bootstrap_control_status_push_error", map[string]any{"error": err.Error()})
	}
}

func preflightBambuPluginBundleOnStartupDefault(ctx context.Context, stateDir string) (bambucamera.PluginBundleStatus, error) {
	manager := bambucamera.NewManager(stateDir, runExternalCommand)
	return manager.PreflightPluginBundle(ctx)
}

func prepareBambuRuntimeForStartup(cfg appConfig) (bambucamera.Runtime, error) {
	if !cfg.EnableBambu {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), bambuPluginStartupTimeout)
	defer cancel()

	status, err := preflightBambuPluginBundleOnStartup(ctx, cfg.BambuCameraRuntimeDir)
	if err != nil {
		return nil, formatBambuPluginStartupError(status, err)
	}

	installState := "reused_cache"
	if status.Downloaded {
		installState = "downloaded_and_cached"
	}
	log.Printf(
		"Bambu native plugin bundle ready: version=%s cache_dir=%s source_library=%s install_state=%s",
		status.Version,
		status.CacheDir,
		status.SourceLibraryPath,
		installState,
	)

	return bambucamera.NewManager(cfg.BambuCameraRuntimeDir, runExternalCommand), nil
}

func formatBambuPluginStartupError(status bambucamera.PluginBundleStatus, err error) error {
	version := strings.TrimSpace(status.Version)
	if version == "" {
		version = "unknown"
	}
	cacheDir := strings.TrimSpace(status.CacheDir)
	if cacheDir == "" {
		cacheDir = filepath.Join("<unknown>", "plugins", runtime.GOOS, version)
	}

	failureClass := "bundle preparation failed"
	nextAction := "Verify that the cache directory is writable and that this machine can reach the pinned official Bambu plugin archive, then restart edge-agent with --bambu."
	switch {
	case errors.Is(err, bambucamera.ErrUnsupportedPlatform):
		failureClass = "unsupported platform"
		nextAction = "Use edge-agent without --bambu on this platform, or move Bambu mode to a supported OS."
	case errors.Is(err, context.DeadlineExceeded):
		failureClass = "startup preflight timed out"
		nextAction = "Verify network connectivity to the pinned official Bambu plugin archive and retry startup."
	case errors.Is(err, bambucamera.ErrCacheUnavailable):
		failureClass = "cache directory unavailable"
		nextAction = fmt.Sprintf("Verify that %s is writable by the current user, then restart edge-agent with --bambu.", cacheDir)
	case errors.Is(err, bambucamera.ErrChecksumMismatch):
		failureClass = "archive checksum mismatch"
		nextAction = "Retry later or inspect any proxy/cache in front of the official Bambu archive. edge-agent will not use an unverified bundle."
	case errors.Is(err, bambucamera.ErrDownloadFailed):
		failureClass = "pinned archive download failed"
		if strings.TrimSpace(status.ArchiveURL) != "" {
			nextAction = fmt.Sprintf("Verify that this machine can reach the pinned official Bambu plugin archive (%s) and retry startup.", status.ArchiveURL)
		} else {
			nextAction = "Verify that this machine can reach the pinned official Bambu plugin archive and retry startup."
		}
	case errors.Is(err, bambucamera.ErrIncompleteBundle):
		failureClass = "bundle extraction incomplete"
		nextAction = fmt.Sprintf("Delete the broken cache at %s if it still exists, then restart edge-agent with --bambu.", cacheDir)
	}

	return fmt.Errorf(
		"Bambu mode (--bambu) requires the pinned native plugin bundle version %s under %s. edge-agent could not prepare it automatically (%s): %w. %s",
		version,
		cacheDir,
		failureClass,
		err,
		nextAction,
	)
}

func (a *agent) bootstrapFromStartupCredentials(ctx context.Context) error {
	apiKey := strings.TrimSpace(a.cfg.StartupSaaSAPIKey)
	if apiKey == "" {
		return nil
	}
	a.recordControlPlaneAPIKeySeen()

	controlPlaneURL := strings.TrimSpace(a.cfg.StartupControlPlaneURL)
	if controlPlaneURL == "" {
		existing := a.snapshotBootstrap()
		controlPlaneURL = strings.TrimSpace(existing.ControlPlaneURL)
	}
	if controlPlaneURL == "" {
		a.clearClaimedState(controlPlaneURL)
		a.recordControlPlaneFailure("Control plane URL is missing. Paste a valid API key and reconnect from the dashboard.")
		return errors.New("control-plane-url is required when api key is provided")
	}

	existing := a.snapshotBootstrap()
	if a.isClaimed() &&
		strings.TrimSpace(existing.ControlPlaneURL) == controlPlaneURL &&
		strings.TrimSpace(existing.SaaSAPIKey) == apiKey {
		return nil
	}

	claim, err := a.applyClaim(ctx, controlPlaneURL, apiKey)
	if err != nil {
		a.audit("claim_failed", map[string]any{"error": err.Error()})
		a.clearClaimedState(controlPlaneURL)
		a.recordControlPlaneClaimFailure(err)
		return fmt.Errorf("startup claim failed: %w", err)
	}

	a.audit("claimed", map[string]any{
		"agent_id":       claim.AgentID,
		"org_id":         claim.OrgID,
		"schema_version": claim.SchemaVersion,
		"source":         "startup_credentials",
	})
	return nil
}

func (a *agent) applyClaim(ctx context.Context, controlPlaneURL string, apiKey string) (claimResponse, error) {
	normalizedControlPlaneURL := strings.TrimSpace(controlPlaneURL)
	normalizedAPIKey := strings.TrimSpace(apiKey)

	claim, err := a.claimWithSaaS(normalizedControlPlaneURL, normalizedAPIKey)
	if err != nil {
		return claimResponse{}, err
	}

	a.mu.Lock()
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: normalizedControlPlaneURL,
		SaaSAPIKey:      normalizedAPIKey,
		AgentID:         claim.AgentID,
		OrgID:           claim.OrgID,
		ClaimedAt:       time.Now().UTC(),
	}
	a.claimed = true
	a.lastETag = ""
	a.mu.Unlock()

	if err := a.saveBootstrapConfig(); err != nil {
		a.audit("bootstrap_persist_error", map[string]any{"error": err.Error()})
		return claimResponse{}, fmt.Errorf("failed to persist bootstrap config: %w", err)
	}
	if err := a.pollBindingsOnce(ctx); err != nil {
		a.audit("bindings_initial_fetch_error", map[string]any{"error": err.Error()})
	}
	if err := a.pollConfigCommandsOnce(ctx); err != nil {
		a.audit("config_commands_initial_fetch_error", map[string]any{"error": err.Error()})
	}
	if err := a.pollDesiredStateOnce(ctx); err != nil {
		a.audit("desired_state_initial_fetch_error", map[string]any{"error": err.Error()})
	}
	return claim, nil
}

func (a *agent) clearClaimedState(controlPlaneURL string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.claimed = false
	a.lastETag = ""
	a.bootstrap.ControlPlaneURL = firstNonEmpty(strings.TrimSpace(controlPlaneURL), strings.TrimSpace(a.bootstrap.ControlPlaneURL))
	a.bootstrap.SaaSAPIKey = ""
	a.bootstrap.AgentID = ""
	a.bootstrap.OrgID = 0
	a.bootstrap.ClaimedAt = time.Time{}
	a.desiredState = make(map[int]desiredStateItem)
	a.bindings = make(map[int]edgeBinding)
	a.actionQueue = make(map[int][]action)
	a.inflightActions = make(map[int]action)
	a.deadLetters = make(map[int][]action)
	a.queuedSince = make(map[int]time.Time)
	a.recentEnqueue = make(map[string]time.Time)
	a.suppressedUntil = make(map[string]time.Time)
	a.breakerUntil = make(map[int]time.Time)
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
	ConfirmUpload(ctx context.Context, accessToken string, uploadURLs bambucloud.CloudUploadURLs) error
	StartPrintJob(ctx context.Context, accessToken string, req bambucloud.CloudPrintStartRequest) error
}

type bambuMQTTCommandRequest struct {
	BrokerAddr         string
	Topic              string
	Username           string
	Password           string
	Command            string
	Param              any
	InsecureSkipVerify bool
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
		SetupBindAddr:                     getEnvOrDefault("SETUP_BIND_ADDR", "127.0.0.1:18090"),
		BootstrapConfigPath:               getEnvOrDefault("BOOTSTRAP_CONFIG_PATH", filepath.Join(defaultStateDir, "bootstrap", "config.json")),
		AuditLogPath:                      getEnvOrDefault("AUDIT_LOG_PATH", filepath.Join(defaultStateDir, "logs", "audit.log")),
		ArtifactStageDir:                  getEnvOrDefault("ARTIFACT_STAGE_DIR", filepath.Join(defaultStateDir, "artifacts")),
		StartupControlPlaneURL:            getEnvOrDefault("CONTROL_PLANE_URL", ""),
		StartupSaaSAPIKey:                 getEnvOrDefault("SAAS_API_KEY", getEnvOrDefault("EDGE_API_KEY", "")),
		EnableKlipper:                     parseBoolEnv("ENABLE_KLIPPER", false),
		EnableBambu:                       parseBoolEnv("ENABLE_BAMBU", false),
		BambuCloudAuthBaseURL:             bambuCloudAuthBaseURL,
		BambuCloudUploadPath:              getEnvOrDefault("BAMBU_CLOUD_UPLOAD_PATH", "/v1/iot-service/api/user/upload"),
		BambuCloudPrintPath:               getEnvOrDefault("BAMBU_CLOUD_PRINT_PATH", "/v1/iot-service/api/user/print"),
		BambuCloudMQTTBroker:              getEnvOrDefault("BAMBU_CLOUD_MQTT_BROKER", defaultBambuCloudMQTTBroker(bambuCloudAuthBaseURL)),
		BambuCloudMQTTTopicTemplate:       getEnvOrDefault("BAMBU_CLOUD_MQTT_TOPIC_TEMPLATE", defaultBambuMQTTTopic),
		BambuConnectURI:                   getEnvOrDefault("BAMBU_CONNECT_URI", ""),
		BambuCameraRuntimeDir:             getEnvOrDefault("BAMBU_CAMERA_RUNTIME_DIR", filepath.Join(defaultStateDir, "bambu", "camera_runtime")),
		BambuCameraHelperMJPEGURLTemplate: getEnvOrDefault("BAMBU_CAMERA_HELPER_MJPEG_URL_TEMPLATE", "http://127.0.0.1:1984/api/stream.mjpeg?src=p1s"),
		BambuCameraRTSPFallbackEnabled:    parseBoolEnv("BAMBU_CAMERA_RTSP_FALLBACK_ENABLED", false),
		BambuControlStatusPushInterval:    parseDurationMS("BAMBU_CONTROL_STATUS_PUSH_INTERVAL_MS", 1000),
		BindingsPollInterval:              parseDurationMS("BINDINGS_POLL_INTERVAL_MS", 5000),
		ConfigCommandsPollInterval:        parseDurationMS("CONFIG_COMMANDS_POLL_INTERVAL_MS", 5000),
		PrinterCommandsPollInterval:       parseDurationMS("PRINTER_COMMANDS_POLL_INTERVAL_MS", 1000),
		DesiredStatePollInterval:          parseDurationMS("DESIRED_STATE_POLL_INTERVAL_MS", 3000),
		StatePushInterval:                 parseDurationMS("STATE_PUSH_INTERVAL_MS", 3000),
		ConvergenceTickInterval:           parseDurationMS("CONVERGENCE_TICK_INTERVAL_MS", 500),
		ActionExecInterval:                parseDurationMS("ACTION_EXEC_INTERVAL_MS", 250),
		ActionRetryBaseInterval:           parseDurationMS("ACTION_RETRY_BASE_INTERVAL_MS", 1000),
		ActionMaxAttempts:                 parsePositiveInt("ACTION_MAX_ATTEMPTS", 3),
		ActionNonRetryableCooldown:        parseDurationMS("ACTION_NON_RETRYABLE_COOLDOWN_MS", 180000),
		MoonrakerRequestTimeout:           parseDurationMS("MOONRAKER_REQUEST_TIMEOUT_MS", 8000),
		BambuLANRuntimeTimeout:            parseDurationMS("BAMBU_LAN_RUNTIME_TIMEOUT_MS", 2000),
		ArtifactUploadTimeout:             parseDurationMS("ARTIFACT_UPLOAD_TIMEOUT_MS", 90000),
		ArtifactDownloadTimeout:           parseDurationMS("ARTIFACT_DOWNLOAD_TIMEOUT_MS", 15000),
		CircuitBreakerCooldown:            parseDurationMS("CIRCUIT_BREAKER_COOLDOWN_MS", 15000),
		ProbePollInterval:                 parseDurationMS("PROBE_POLL_INTERVAL_MS", 2000),
		DiscoveryPollInterval:             parseDurationMS("DISCOVERY_POLL_INTERVAL_MS", 4000),
		DiscoveryInventoryInterval:        parseDurationMS("DISCOVERY_INVENTORY_INTERVAL_MS", 30000),
		DiscoveryManualPollInterval:       parseDurationMS("DISCOVERY_MANUAL_POLL_INTERVAL_MS", 5000),
		LocalUIScanInterval:               parseDurationMS("LOCAL_UI_SCAN_INTERVAL_MS", 15000),
		LocalUIBindAddr:                   getEnvOrDefault("LOCAL_UI_BIND_ADDR", ""),
		DiscoveryProfileMax:               parseDiscoveryProfile(getEnvOrDefault("DISCOVERY_PROFILE_MAX", "hybrid")),
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
	flagSet.BoolVar(&out.EnableBambu, "bambu", false, "Enable Bambu LAN discovery and operations")

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
	return a.cfg.EnableBambu
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
		"local_web_ui_url":      a.localWebUIURLSnapshot(),
		"local_web_ui_port":     localWebUIPortFromURL(a.localWebUIURLSnapshot()),
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
		"control_plane_url": a.currentControlPlaneURL(),
		"claimed_at":        bootstrap.ClaimedAt,
		"local_web_ui_url":  a.localWebUIURLSnapshot(),
		"local_web_ui_port": localWebUIPortFromURL(a.localWebUIURLSnapshot()),
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
	a.recordControlPlaneAPIKeySeen()

	claim, err := a.applyClaim(r.Context(), req.ControlPlaneURL, req.SaaSAPIKey)
	if err != nil {
		a.audit("claim_failed", map[string]any{"error": err.Error()})
		a.clearClaimedState(req.ControlPlaneURL)
		a.recordControlPlaneClaimFailure(err)
		http.Error(w, fmt.Sprintf("claim failed: %v", err), http.StatusBadGateway)
		return
	}

	a.audit("claimed", map[string]any{
		"agent_id":       claim.AgentID,
		"org_id":         claim.OrgID,
		"schema_version": claim.SchemaVersion,
	})
	a.bootstrapSync(r.Context())

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
		a.recordControlPlaneClaimFailure(err)
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
	a.recordControlPlaneSuccess()
	return out, nil
}

func (a *agent) buildClaimCapabilities() map[string]string {
	discoveryAllowedAdapters := a.cfg.DiscoveryAllowedAdapters
	if len(discoveryAllowedAdapters) == 0 {
		discoveryAllowedAdapters = []string{"moonraker"}
	}
	enabledAdapters := strings.Join(discoveryAllowedAdapters, ",")
	bambuAuthReady := a.isBambuAuthReady()
	localWebUIURL := strings.TrimSpace(a.localWebUIURLSnapshot())
	localWebUIPort := localWebUIPortFromURL(localWebUIURL)
	_, ffmpegErr := exec.LookPath("ffmpeg")
	return map[string]string{
		"adapter_family":             "klipper",
		"discovery_profile_max":      parseDiscoveryProfile(a.cfg.DiscoveryProfileMax),
		"discovery_network_mode":     parseDiscoveryNetworkMode(a.cfg.DiscoveryNetworkMode),
		"discovery_allowed_adapters": enabledAdapters,
		"enabled_adapters":           enabledAdapters,
		"bambu_enabled":              strconv.FormatBool(a.cfg.EnableBambu),
		"bambu_auth_ready":           strconv.FormatBool(bambuAuthReady),
		"local_web_ui_url":           localWebUIURL,
		"local_web_ui_port":          localWebUIPort,
		"ffmpeg_available":           strconv.FormatBool(ffmpegErr == nil),
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
		a.recordControlPlaneFailure(err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("bindings", resp.StatusCode, string(body))
			return fmt.Errorf("%w: bindings returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		a.recordControlPlaneFailure(string(body))
		return fmt.Errorf("bindings returned %d: %s", resp.StatusCode, string(body))
	}

	var payload bindingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		a.recordControlPlaneFailure(err.Error())
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
	a.recordControlPlaneSuccess()
	return nil
}

func (a *agent) configCommandsPollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	interval := a.cfg.ConfigCommandsPollInterval
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
			if err := a.pollConfigCommandsOnce(ctx); err != nil {
				a.audit("config_commands_poll_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pollConfigCommandsOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/config-commands",
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
		a.audit("config_commands_schema_mismatch", map[string]any{
			"status_code": resp.StatusCode,
			"body":        strings.TrimSpace(string(body)),
		})
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("config_commands", resp.StatusCode, string(body))
			return fmt.Errorf("%w: config-commands returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("config-commands returned %d: %s", resp.StatusCode, string(body))
	}

	var payload configCommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if len(payload.Commands) == 0 {
		return nil
	}

	processedCount := 0
	var firstErr error
	for _, command := range payload.Commands {
		if err := a.processConfigCommand(ctx, bootstrap, command); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			a.audit("config_command_apply_error", map[string]any{
				"command_id":   command.CommandID,
				"command_type": strings.TrimSpace(command.CommandType),
				"error":        err.Error(),
			})
			continue
		}
		processedCount++
	}
	a.audit("config_commands_updated", map[string]any{
		"command_count":   len(payload.Commands),
		"processed_count": processedCount,
	})
	return firstErr
}

func (a *agent) processConfigCommand(ctx context.Context, bootstrap bootstrapConfig, command configCommandItem) error {
	normalizedType := strings.TrimSpace(command.CommandType)
	var applyErr error
	switch normalizedType {
	case "bambu_lan_credentials_upsert":
		applyErr = a.applyBambuLANCredentialsCommand(ctx, command)
	default:
		applyErr = fmt.Errorf("unsupported config command type: %s", normalizedType)
	}

	ackStatus := "acknowledged"
	ackError := ""
	if applyErr != nil {
		ackStatus = "failed"
		ackError = applyErr.Error()
	}
	if err := a.acknowledgeConfigCommand(ctx, bootstrap, command.CommandID, ackStatus, ackError); err != nil {
		a.audit("config_command_ack_failed", map[string]any{
			"command_id": command.CommandID,
			"status":     ackStatus,
			"error":      err.Error(),
		})
		if applyErr != nil {
			return fmt.Errorf("%v; acknowledge config command: %w", applyErr, err)
		}
		return fmt.Errorf("acknowledge config command: %w", err)
	}
	return applyErr
}

func (a *agent) applyBambuLANCredentialsCommand(ctx context.Context, command configCommandItem) error {
	if a.bambuLANStore == nil {
		return errors.New("bambu lan credentials store is not configured")
	}

	var payload bambuLANCredentialsUpsertPayload
	if len(command.Payload) == 0 {
		return errors.New("config command payload is empty")
	}
	if err := json.Unmarshal(command.Payload, &payload); err != nil {
		return fmt.Errorf("decode bambu lan config payload: %w", err)
	}

	serial := strings.TrimSpace(payload.Serial)
	host := strings.TrimSpace(payload.Host)
	accessCode := strings.TrimSpace(payload.AccessCode)
	if serial == "" {
		return errors.New("bambu lan config payload missing serial")
	}
	if host == "" {
		return errors.New("bambu lan config payload missing host")
	}
	if accessCode == "" {
		return errors.New("bambu lan config payload missing access_code")
	}

	if err := a.bambuLANStore.Upsert(ctx, bambustore.BambuLANCredentials{
		Serial:     serial,
		Host:       host,
		AccessCode: accessCode,
		Name:       strings.TrimSpace(payload.Name),
		Model:      strings.TrimSpace(payload.Model),
	}); err != nil {
		return err
	}

	a.audit("bambu_lan_credentials_upserted", map[string]any{
		"serial": serial,
		"host":   host,
	})
	if printerID := a.printerIDForEndpointNormalized(command.TargetEndpointNormalized); printerID != 0 {
		a.clearBambuLANCredentialRecoveryCooldown(printerID)
	}
	return nil
}

func (a *agent) printerIDForEndpointNormalized(endpointURL string) int {
	normalized := strings.TrimSpace(endpointURL)
	if normalized == "" {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for printerID, binding := range a.bindings {
		if strings.EqualFold(strings.TrimSpace(binding.EndpointURL), normalized) {
			return printerID
		}
	}
	return 0
}

func (a *agent) clearBambuLANCredentialRecoveryCooldown(printerID int) {
	if printerID == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.bambuLANRecoveryUntil, printerID)
}

func (a *agent) requestBambuLANCredentialRecovery(ctx context.Context, binding edgeBinding) (bool, error) {
	if binding.PrinterID == 0 {
		return false, errors.New("bambu_lan_credentials_missing_local: missing printer binding id")
	}
	if !a.isClaimed() {
		return false, errors.New("bambu_lan_credentials_missing_local: edge agent is not claimed")
	}

	now := time.Now().UTC()
	a.mu.Lock()
	if until, ok := a.bambuLANRecoveryUntil[binding.PrinterID]; ok && now.Before(until) {
		a.mu.Unlock()
		return false, nil
	}
	a.bambuLANRecoveryUntil[binding.PrinterID] = now.Add(bambuLANCredentialRecoveryCooldown)
	a.mu.Unlock()

	bootstrap := a.snapshotBootstrap()
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/bambu-credentials/recover",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	reqBody := bambuCredentialRecoveryRequest{
		PrinterID:   binding.PrinterID,
		EndpointURL: strings.TrimSpace(binding.EndpointURL),
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return false, fmt.Errorf("bambu_lan_credentials_missing_local: marshal recovery request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return false, fmt.Errorf("bambu_lan_credentials_missing_local: build recovery request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("bambu_lan_credentials_missing_local: recovery request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("bambu_credentials_recover", resp.StatusCode, string(body))
		}
		return false, fmt.Errorf("bambu_lan_credentials_missing_local: recovery request returned %d: %s", resp.StatusCode, string(body))
	}

	var payload bambuCredentialRecoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, fmt.Errorf("bambu_lan_credentials_missing_local: decode recovery response: %w", err)
	}
	a.audit("bambu_lan_credentials_recovery_requested", map[string]any{
		"printer_id":      binding.PrinterID,
		"endpoint_url":    strings.TrimSpace(binding.EndpointURL),
		"recovery_queued": payload.RecoveryQueued,
		"command_id":      payload.CommandID,
	})
	return payload.RecoveryQueued, nil
}

func (a *agent) acknowledgeConfigCommand(
	ctx context.Context,
	bootstrap bootstrapConfig,
	commandID int,
	statusValue string,
	errorValue string,
) error {
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/config-commands/%d/ack",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
		commandID,
	)

	reqBody := configCommandAckRequest{
		Status: strings.TrimSpace(statusValue),
		Error:  strings.TrimSpace(errorValue),
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
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
			a.handleControlPlaneAuthFailure("config_command_ack", resp.StatusCode, string(body))
			return fmt.Errorf("%w: config command ack returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("config command ack returned %d: %s", resp.StatusCode, string(body))
	}

	var ackResp configCommandAckResponse
	if err := json.NewDecoder(resp.Body).Decode(&ackResp); err != nil {
		return err
	}
	if !ackResp.Accepted {
		return errors.New("config command ack not accepted")
	}
	return nil
}

func (a *agent) printerCommandsPollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	interval := a.cfg.PrinterCommandsPollInterval
	if interval <= 0 {
		interval = 1 * time.Second
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
			if err := a.pollPrinterCommandsOnce(ctx); err != nil {
				a.audit("printer_commands_poll_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pollPrinterCommandsOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/printer-commands",
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
		a.audit("printer_commands_schema_mismatch", map[string]any{
			"status_code": resp.StatusCode,
			"body":        strings.TrimSpace(string(body)),
		})
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("printer_commands", resp.StatusCode, string(body))
			return fmt.Errorf("%w: printer-commands returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("printer-commands returned %d: %s", resp.StatusCode, string(body))
	}

	var payload printerCommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if len(payload.Commands) == 0 {
		return nil
	}

	queuedCount := 0
	var firstErr error
	for _, command := range payload.Commands {
		if err := a.enqueuePrinterCommand(command); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			a.audit("printer_command_enqueue_error", map[string]any{
				"command_id":  command.CommandID,
				"printer_id":  command.PrinterID,
				"command_key": strings.TrimSpace(command.CommandKey),
				"error":       err.Error(),
			})
			if ackErr := a.acknowledgePrinterCommand(ctx, bootstrap, command.CommandID, "failed", err.Error()); ackErr != nil && firstErr == nil {
				firstErr = ackErr
			}
			continue
		}
		queuedCount++
	}
	a.audit("printer_commands_updated", map[string]any{
		"command_count": len(payload.Commands),
		"queued_count":  queuedCount,
	})
	return firstErr
}

func (a *agent) enqueuePrinterCommand(command printerCommandItem) error {
	commandKey := strings.TrimSpace(command.CommandKey)
	if command.CommandID == 0 {
		return errors.New("validation_error: printer command is missing command_id")
	}
	if command.PrinterID == 0 {
		return errors.New("validation_error: printer command is missing printer_id")
	}
	switch commandKey {
	case "pause", "resume", "stop", "light_on", "light_off", "load_filament", "unload_filament", "home_axes", "jog_motion", "jog_motion_batch", "set_fan_enabled", "set_nozzle_temperature", "set_bed_temperature", "refresh_file_index", "start_existing_file", "delete_file", "delete_all_files":
	default:
		return fmt.Errorf("validation_error: unsupported printer command key %q", commandKey)
	}
	var payload map[string]any
	if len(command.Payload) > 0 {
		if err := json.Unmarshal(command.Payload, &payload); err != nil {
			return fmt.Errorf("validation_error: printer command payload is invalid JSON: %w", err)
		}
	}

	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	if hasQueuedPrinterCommandLocked(a.actionQueue[command.PrinterID], command.CommandID) {
		return nil
	}
	if inflight, ok := a.inflightActions[command.PrinterID]; ok && inflight.CommandRequestID == command.CommandID {
		return nil
	}
	a.actionQueue[command.PrinterID] = append(a.actionQueue[command.PrinterID], action{
		PrinterID:        command.PrinterID,
		Kind:             commandKey,
		Reason:           fmt.Sprintf("printer command %s", commandKey),
		Payload:          payload,
		CommandRequestID: command.CommandID,
		EnqueuedAt:       now,
		Attempts:         0,
		NextAttempt:      now,
	})
	return nil
}

func hasQueuedPrinterCommandLocked(queue []action, commandRequestID int) bool {
	for _, item := range queue {
		if item.CommandRequestID == commandRequestID && commandRequestID != 0 {
			return true
		}
	}
	return false
}

func (a *agent) acknowledgePrinterCommand(
	ctx context.Context,
	bootstrap bootstrapConfig,
	commandID int,
	statusValue string,
	errorValue string,
) error {
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/printer-commands/%d/ack",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
		commandID,
	)

	reqBody := printerCommandAckRequest{
		Status: strings.TrimSpace(statusValue),
		Error:  summarizePrinterCommandAckError(errorValue),
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
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
			a.handleControlPlaneAuthFailure("printer_command_ack", resp.StatusCode, string(body))
			return fmt.Errorf("%w: printer command ack returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("printer command ack returned %d: %s", resp.StatusCode, string(body))
	}

	var ackResp printerCommandAckResponse
	if err := json.NewDecoder(resp.Body).Decode(&ackResp); err != nil {
		return err
	}
	if !ackResp.Accepted {
		return errors.New("printer command ack not accepted")
	}
	return nil
}

func summarizePrinterCommandAckError(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	if match := regexp.MustCompile(`WebRequestError:\s*([^"{]+)`).FindStringSubmatch(trimmed); len(match) > 1 {
		return truncatePrinterCommandAckError(match[1])
	}
	if match := regexp.MustCompile(`"message"\s*:\s*"([^"]+)\"`).FindStringSubmatch(trimmed); len(match) > 1 {
		message := strings.TrimSpace(strings.ReplaceAll(match[1], `\"`, `"`))
		message = strings.TrimSpace(strings.TrimPrefix(message, "WebRequestError:"))
		return truncatePrinterCommandAckError(message)
	}
	if bodyIdx := strings.Index(trimmed, "body="); bodyIdx >= 0 {
		body := strings.TrimSpace(trimmed[bodyIdx+len("body="):])
		var payload struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err == nil {
			message := strings.TrimSpace(strings.TrimPrefix(payload.Error.Message, "WebRequestError:"))
			if message != "" {
				return truncatePrinterCommandAckError(message)
			}
		}
	}
	return truncatePrinterCommandAckError(trimmed)
}

func truncatePrinterCommandAckError(message string) string {
	trimmed := strings.TrimSpace(message)
	if len(trimmed) <= 1000 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:1000])
}

func summarizePrinterFacingActionError(raw string) string {
	trimmed := strings.TrimSpace(raw)
	lowered := strings.ToLower(trimmed)
	switch {
	case strings.Contains(lowered, "bambu print start verification timeout"):
		return "Bambu print start timed out waiting for the printer to confirm queued/printing state."
	case strings.Contains(lowered, "bambu command verification timeout"):
		return "Bambu command timed out waiting for the printer to confirm the requested state."
	default:
		return summarizePrinterCommandAckError(raw)
	}
}

func (a *agent) cameraSessionsPollLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !a.isClaimed() {
				continue
			}
			if err := a.pollCameraSessionsOnce(ctx); err != nil {
				a.audit("camera_sessions_poll_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pollCameraSessionsOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/camera-sessions",
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
		a.syncCameraSessionWorkers(ctx, bootstrap, nil)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("camera_sessions", resp.StatusCode, string(body))
			return fmt.Errorf("%w: camera-sessions returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("camera-sessions returned %d: %s", resp.StatusCode, string(body))
	}

	var payload cameraSessionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	a.syncCameraSessionWorkers(ctx, bootstrap, payload.Sessions)
	return nil
}

func (a *agent) syncCameraSessionWorkers(ctx context.Context, bootstrap bootstrapConfig, sessions []cameraSessionItem) {
	wanted := make(map[string]cameraSessionItem, len(sessions))
	for _, session := range sessions {
		if session.SessionID == "" || session.PrinterID == 0 {
			continue
		}
		wanted[session.SessionID] = session
	}

	type workerStart struct {
		session cameraSessionItem
		ctx     context.Context
	}
	toStart := make([]workerStart, 0)

	a.mu.Lock()
	for sessionID, cancel := range a.activeCameraSessions {
		if _, ok := wanted[sessionID]; ok {
			continue
		}
		cancel()
		delete(a.activeCameraSessions, sessionID)
	}
	for sessionID, session := range wanted {
		if _, ok := a.activeCameraSessions[sessionID]; ok {
			continue
		}
		workerCtx, cancel := context.WithCancel(ctx)
		a.activeCameraSessions[sessionID] = cancel
		toStart = append(toStart, workerStart{session: session, ctx: workerCtx})
	}
	a.mu.Unlock()

	for _, item := range toStart {
		go a.runCameraSessionWorker(item.ctx, bootstrap, item.session)
	}
}

func (a *agent) runCameraSessionWorker(ctx context.Context, bootstrap bootstrapConfig, session cameraSessionItem) {
	defer a.finishCameraSessionWorker(session.SessionID)

	binding, ok := a.snapshotBinding(session.PrinterID)
	if !ok {
		_ = a.closeCameraSessionRemote(ctx, bootstrap, session, "error", "missing printer binding for camera session")
		return
	}

	reader, contentType, err := a.openCameraSessionReader(ctx, binding)
	if err != nil {
		_ = a.closeCameraSessionRemote(ctx, bootstrap, session, "error", err.Error())
		return
	}
	defer reader.Close()

	if err := a.ingestCameraSession(ctx, bootstrap, session, contentType, reader); err != nil {
		if ctx.Err() == nil {
			_ = a.closeCameraSessionRemote(ctx, bootstrap, session, "error", err.Error())
		}
		return
	}
	if ctx.Err() == nil {
		_ = a.closeCameraSessionRemote(ctx, bootstrap, session, "closed", "")
	}
}

func (a *agent) finishCameraSessionWorker(sessionID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.activeCameraSessions[sessionID]; ok {
		delete(a.activeCameraSessions, sessionID)
	}
}

func (a *agent) openCameraSessionReader(ctx context.Context, binding edgeBinding) (io.ReadCloser, string, error) {
	switch normalizeAdapterFamily(binding.AdapterFamily) {
	case "moonraker":
		stream, err := a.moonrakerCameraAdapter().OpenCameraStream(ctx, printeradapter.Binding{
			PrinterID:     binding.PrinterID,
			AdapterFamily: binding.AdapterFamily,
			EndpointURL:   binding.EndpointURL,
		})
		if err != nil {
			return nil, "", err
		}
		return stream.Reader, stream.ContentType, nil
	case "bambu":
		return a.openBambuCameraReader(ctx, binding)
	default:
		return nil, "", fmt.Errorf("camera unsupported for adapter %s", strings.TrimSpace(binding.AdapterFamily))
	}
}

func (a *agent) openMoonrakerCameraReader(ctx context.Context, binding edgeBinding) (io.ReadCloser, string, error) {
	stream, err := a.moonrakerCameraAdapter().OpenCameraStream(ctx, printeradapter.Binding{
		PrinterID:     binding.PrinterID,
		AdapterFamily: binding.AdapterFamily,
		EndpointURL:   binding.EndpointURL,
	})
	if err != nil {
		return nil, "", err
	}
	return stream.Reader, stream.ContentType, nil
}

func (a *agent) startMoonrakerCameraMonitorKeepalive(ctx context.Context, endpointURL string, snapshotURL string) {
	a.moonrakerCameraAdapter().StartMonitorKeepalive(ctx, endpointURL, snapshotURL)
}

func (a *agent) openSnapshotLoopReader(ctx context.Context, snapshotURL string) (io.ReadCloser, string, error) {
	return a.moonrakerCameraAdapter().OpenSnapshotLoopReader(ctx, snapshotURL)
}

func (a *agent) fetchCameraSnapshotBytes(ctx context.Context, snapshotURL string) ([]byte, error) {
	return a.moonrakerCameraAdapter().FetchSnapshotBytes(ctx, snapshotURL)
}

func sendMoonrakerCameraMonitorCommandDefault(ctx context.Context, endpointURL string, stop bool) error {
	return moonrakeradapter.SendMonitorCommandDefault(ctx, endpointURL, stop)
}

func computeWebSocketAcceptKey(key string) string {
	return moonrakeradapter.ComputeWebSocketAcceptKey(key)
}

func (a *agent) moonrakerCameraAdapter() moonrakeradapter.CameraAdapter {
	return moonrakeradapter.CameraAdapter{
		HTTPClient:         a.client,
		StreamClient:       a.cameraStreamHTTPClient,
		RequestTimeout:     a.cfg.MoonrakerRequestTimeout,
		SendMonitorCommand: sendMoonrakerCameraMonitorCommand,
		Audit:              a.audit,
	}
}

type bambuCameraSource struct {
	URL  string
	Kind string
}

const (
	bambuCameraSourceKindHelper = "helper_mjpeg"
	bambuCameraSourceKindRTSP   = "rtsp"
)

var (
	bambuCameraHelperProber     = probeBambuCameraHelper
	bambuCameraCandidateProber  = probeBambuCameraCandidate
	openManagedBambuMJPEGReader = openManagedBambuMJPEGReaderDefault
	fetchManagedBambuSnapshot   = fetchManagedBambuSnapshotDefault
)

func (a *agent) openBambuCameraReader(ctx context.Context, binding edgeBinding) (io.ReadCloser, string, error) {
	printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
	if err != nil {
		return nil, "", err
	}
	if a.bambuCameraRuntime != nil {
		internalURL, urlErr := a.internalBambuCameraContractURL(printerID, "stream.mjpeg")
		if urlErr != nil {
			return nil, "", urlErr
		}
		return a.openCameraHTTPReader(ctx, internalURL, "multipart/x-mixed-replace;boundary=frame")
	}
	credentials, err := a.resolveBambuLANRuntimeCredentials(ctx, printerID)
	if err != nil {
		return nil, "", err
	}
	source, err := a.resolveBambuCameraSource(ctx, credentials)
	if err != nil {
		return nil, "", err
	}
	if source.Kind == bambuCameraSourceKindHelper {
		return a.openCameraHTTPReader(ctx, source.URL, "multipart/x-mixed-replace;boundary=frame")
	}

	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		return nil, "", errors.New("ffmpeg is required on the edge host for bambu camera streaming")
	}
	return openCameraFFmpegReader(ctx, ffmpegPath, source.URL)
}

func (a *agent) openCameraHTTPReader(ctx context.Context, targetURL string, defaultContentType string) (io.ReadCloser, string, error) {
	client := a.cameraStreamHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, "", fmt.Errorf("camera source returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if contentType == "" {
		contentType = defaultContentType
	}
	return resp.Body, contentType, nil
}

func openCameraFFmpegReader(ctx context.Context, ffmpegPath string, inputURL string) (io.ReadCloser, string, error) {
	pipeReader, pipeWriter := io.Pipe()
	args := []string{
		"-hide_banner",
		"-loglevel", "error",
		"-nostdin",
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(inputURL)), "rtsp") {
		args = append(args, "-rtsp_transport", "tcp")
	}
	args = append(args,
		"-i", inputURL,
		"-f", "mpjpeg",
		"-boundary_tag", "frame",
		"-q:v", "6",
		"-r", "5",
		"pipe:1",
	)

	cmd := exec.CommandContext(ctx, ffmpegPath, args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		pipeReader.Close()
		pipeWriter.Close()
		return nil, "", err
	}
	cmd.Stdout = pipeWriter
	if err := cmd.Start(); err != nil {
		pipeReader.Close()
		pipeWriter.Close()
		return nil, "", err
	}
	go func() {
		errMsg, _ := io.ReadAll(io.LimitReader(stderr, 4096))
		runErr := cmd.Wait()
		if runErr != nil {
			if trimmed := strings.TrimSpace(string(errMsg)); trimmed != "" {
				_ = pipeWriter.CloseWithError(fmt.Errorf("bambu ffmpeg stream failed: %s", trimmed))
				return
			}
			_ = pipeWriter.CloseWithError(runErr)
			return
		}
		_ = pipeWriter.Close()
	}()
	return pipeReader, "multipart/x-mixed-replace;boundary=frame", nil
}

func (a *agent) ensureBambuCameraHandle(ctx context.Context, printerID string) (bambucamera.Handle, error) {
	if a.bambuCameraRuntime == nil {
		return bambucamera.Handle{}, errors.New("bambu_camera_runtime_unavailable: internal runtime manager is not configured")
	}
	credentials, err := a.resolveBambuLANRuntimeCredentials(ctx, printerID)
	if err != nil {
		return bambucamera.Handle{}, err
	}
	return a.bambuCameraRuntime.Ensure(ctx, bambucamera.EnsureRequest{
		Serial:     strings.TrimSpace(printerID),
		Host:       strings.TrimSpace(credentials.Host),
		AccessCode: strings.TrimSpace(credentials.AccessCode),
		Model:      strings.TrimSpace(credentials.Model),
	})
}

func openManagedBambuMJPEGReaderDefault(ctx context.Context, handle bambucamera.Handle) (io.ReadCloser, error) {
	session, err := bambucamera.OpenSession(handle)
	if err != nil {
		return nil, err
	}
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		defer session.Close()

		for {
			frame, frameErr := bambucamera.ReadJPEGFrame(ctx, session)
			if frameErr != nil {
				switch {
				case errors.Is(frameErr, io.EOF):
					_ = pipeWriter.Close()
				default:
					_ = pipeWriter.CloseWithError(frameErr)
				}
				return
			}

			frameHeader := fmt.Sprintf("--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(frame))
			if _, err := pipeWriter.Write([]byte(frameHeader)); err != nil {
				return
			}
			if _, err := pipeWriter.Write(frame); err != nil {
				return
			}
			if _, err := pipeWriter.Write([]byte("\r\n")); err != nil {
				return
			}
		}
	}()
	return pipeReader, nil
}

func fetchManagedBambuSnapshotDefault(ctx context.Context, handle bambucamera.Handle) ([]byte, error) {
	session, err := bambucamera.OpenSession(handle)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	imageBytes, err := bambucamera.ReadJPEGFrame(ctx, session)
	if err != nil {
		return nil, err
	}
	if len(imageBytes) == 0 {
		return nil, errors.New("bambu snapshot failed: empty image output")
	}
	return imageBytes, nil
}

func (a *agent) resolveBambuCameraSource(ctx context.Context, credentials bambustore.BambuLANCredentials) (bambuCameraSource, error) {
	helperURL := a.bambuCameraHelperMJPEGURL(credentials)
	if helperURL == "" {
		if !a.cfg.BambuCameraRTSPFallbackEnabled {
			return bambuCameraSource{}, errors.New("bambu_camera_helper_required: configure BAMBU_CAMERA_HELPER_MJPEG_URL_TEMPLATE or enable BAMBU_CAMERA_RTSP_FALLBACK_ENABLED")
		}
		streamURL, err := resolveBambuCameraStreamURL(ctx, credentials)
		if err != nil {
			return bambuCameraSource{}, err
		}
		return bambuCameraSource{URL: streamURL, Kind: bambuCameraSourceKindRTSP}, nil
	}

	if err := bambuCameraHelperProber(ctx, helperURL); err == nil {
		return bambuCameraSource{URL: helperURL, Kind: bambuCameraSourceKindHelper}, nil
	} else if !a.cfg.BambuCameraRTSPFallbackEnabled {
		return bambuCameraSource{}, fmt.Errorf("bambu_camera_helper_unreachable: helper %s is not reachable: %v", sanitizeCameraURL(helperURL), err)
	}

	streamURL, err := resolveBambuCameraStreamURL(ctx, credentials)
	if err != nil {
		return bambuCameraSource{}, err
	}
	return bambuCameraSource{URL: streamURL, Kind: bambuCameraSourceKindRTSP}, nil
}

func resolveBambuCameraStreamURL(ctx context.Context, credentials bambustore.BambuLANCredentials) (string, error) {
	candidates, err := bambuCameraRTSPCandidates(credentials)
	if err != nil {
		return "", err
	}
	failures := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		probeErr := bambuCameraCandidateProber(ctx, candidate)
		if probeErr == nil {
			return candidate, nil
		}
		failures = append(failures, fmt.Sprintf("%s => %s", sanitizeCameraURL(candidate), strings.TrimSpace(probeErr.Error())))
	}
	if len(failures) == 0 {
		return "", errors.New("bambu_camera_rtsp_probe_failed: no RTSP candidates configured")
	}
	return "", fmt.Errorf("bambu_camera_rtsp_probe_failed: %s", strings.Join(failures, "; "))
}

func (a *agent) bambuCameraHelperMJPEGURL(credentials bambustore.BambuLANCredentials) string {
	template := strings.TrimSpace(a.cfg.BambuCameraHelperMJPEGURLTemplate)
	if template == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"{host}", strings.TrimSpace(credentials.Host),
		"{serial}", strings.TrimSpace(credentials.Serial),
		"{name}", url.QueryEscape(strings.TrimSpace(credentials.Name)),
		"{model}", url.QueryEscape(strings.TrimSpace(credentials.Model)),
	)
	return replacer.Replace(template)
}

func probeBambuCameraHelper(ctx context.Context, helperURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(helperURL))
	if err != nil {
		return err
	}
	address := strings.TrimSpace(parsed.Host)
	if address == "" {
		return errors.New("bambu camera helper probe missing host")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func bambuCameraRTSPCandidates(credentials bambustore.BambuLANCredentials) ([]string, error) {
	host := strings.TrimSpace(credentials.Host)
	accessCode := strings.TrimSpace(credentials.AccessCode)
	if host == "" {
		return nil, errors.New("bambu camera unavailable: missing bambu host")
	}
	if accessCode == "" {
		return nil, errors.New("bambu camera unavailable: missing bambu access code")
	}

	type candidateShape struct {
		scheme string
		port   string
		path   string
	}
	shapes := []candidateShape{
		{scheme: "rtsp", port: "6000", path: "/streaming/live/1"},
		{scheme: "rtsp", port: "6000", path: "/live"},
		{scheme: "rtsps", port: "6000", path: "/streaming/live/1"},
	}

	out := make([]string, 0, len(shapes))
	seen := make(map[string]struct{}, len(shapes))
	for _, shape := range shapes {
		candidate := (&url.URL{
			Scheme: shape.scheme,
			User:   url.UserPassword("bblp", accessCode),
			Host:   net.JoinHostPort(host, shape.port),
			Path:   shape.path,
		}).String()
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out, nil
}

func probeBambuCameraCandidate(ctx context.Context, candidate string) error {
	ffprobePath, err := exec.LookPath("ffprobe")
	if err == nil {
		requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(
			requestCtx,
			ffprobePath,
			"-v", "error",
			"-rtsp_transport", "tcp",
			"-rw_timeout", "3000000",
			"-i", candidate,
			"-show_streams",
			"-of", "compact",
		)
		output, probeErr := cmd.CombinedOutput()
		if probeErr == nil {
			return nil
		}
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return errors.New(trimmed)
		}
		return probeErr
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return err
	}
	address := strings.TrimSpace(parsed.Host)
	if address == "" {
		return errors.New("bambu camera candidate missing host")
	}
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func sanitizeCameraURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	if parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
	}
	return parsed.String()
}

func (a *agent) ingestCameraSession(ctx context.Context, bootstrap bootstrapConfig, session cameraSessionItem, contentType string, body io.ReadCloser) error {
	defer body.Close()
	endpoint := resolveURL(strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"), session.IngestURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bootstrap.SaaSAPIKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	client := a.cameraStreamHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("camera_ingest", resp.StatusCode, string(body))
			return fmt.Errorf("%w: camera ingest returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("camera ingest returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (a *agent) closeCameraSessionRemote(ctx context.Context, bootstrap bootstrapConfig, session cameraSessionItem, statusValue string, errorValue string) error {
	if strings.TrimSpace(session.CloseURL) == "" {
		return nil
	}
	endpoint := resolveURL(strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"), session.CloseURL)
	return doJSONRequest(
		a.client,
		http.MethodPost,
		endpoint,
		bootstrap.SaaSAPIKey,
		"",
		cameraSessionCloseRequest{Status: strings.TrimSpace(statusValue), Error: strings.TrimSpace(errorValue)},
		nil,
		map[string]string{"X-Agent-Schema-Version": schemaVersionHeaderValue()},
	)
}

func (a *agent) cameraStreamHTTPClient() *http.Client {
	transport := http.DefaultTransport
	if a.client != nil && a.client.Transport != nil {
		transport = a.client.Transport
	}
	if httpTransport, ok := transport.(*http.Transport); ok {
		return &http.Client{Transport: httpTransport.Clone()}
	}
	return &http.Client{Transport: transport}
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
		queue := a.actionQueue[printerID]
		kept := make([]action, 0, len(queue))
		for _, item := range queue {
			if isPrinterRuntimeCommandKind(item.Kind) {
				kept = append(kept, item)
			}
		}
		if len(kept) == 0 {
			delete(a.actionQueue, printerID)
		} else {
			a.actionQueue[printerID] = kept
		}
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
		if shouldSuppressConvergenceForAuthorityManualIntervention(current, desired) {
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
		if hasInflightActionLocked(a.inflightActions, printerID, kind, desired) {
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
		case "paused", "printing", "queued":
			return "noop"
		default:
			return "print"
		}
	case "paused", "idle":
		return "noop"
	default:
		return "invalid"
	}
}

func isPrinterRuntimeCommandKind(kind string) bool {
	switch strings.TrimSpace(kind) {
	case "light_on", "light_off", "load_filament", "unload_filament", "home_axes", "jog_motion", "jog_motion_batch", "set_fan_enabled", "set_nozzle_temperature", "set_bed_temperature", "refresh_file_index", "start_existing_file", "delete_file", "delete_all_files":
		return true
	default:
		return false
	}
}

func hasQueuedActionLocked(queue []action, kind string, intentVersion int) bool {
	for _, item := range queue {
		if isPrinterRuntimeCommandKind(item.Kind) {
			continue
		}
		if item.Kind == kind && item.Target.IntentVersion == intentVersion {
			return true
		}
	}
	return false
}

func actionIdentityMatches(item action, printerID int, kind string, desired desiredStateItem) bool {
	if item.PrinterID != printerID || item.Kind != kind {
		return false
	}
	if isPrinterRuntimeCommandKind(kind) {
		return item.CommandRequestID != 0 && item.CommandRequestID == desired.IntentVersion
	}
	if item.Target.IntentVersion != desired.IntentVersion {
		return false
	}
	if item.Target.JobID != desired.JobID {
		return false
	}
	if item.Target.PlateID != desired.PlateID {
		return false
	}
	return true
}

func hasInflightActionLocked(inflight map[int]action, printerID int, kind string, desired desiredStateItem) bool {
	item, ok := inflight[printerID]
	if !ok {
		return false
	}
	return actionIdentityMatches(item, printerID, kind, desired)
}

func pruneQueuedActionsByIdentityLocked(queue []action, printerID int, kind string, desired desiredStateItem) ([]action, int) {
	if len(queue) == 0 {
		return queue, 0
	}
	next := make([]action, 0, len(queue))
	dropped := 0
	for _, item := range queue {
		if actionIdentityMatches(item, printerID, kind, desired) {
			dropped++
			continue
		}
		next = append(next, item)
	}
	return next, dropped
}

func pruneQueueForIntentLocked(queue []action, minIntentVersion int) []action {
	if len(queue) == 0 {
		return queue
	}
	next := make([]action, 0, len(queue))
	for _, item := range queue {
		if isPrinterRuntimeCommandKind(item.Kind) {
			next = append(next, item)
			continue
		}
		if item.Target.IntentVersion >= minIntentVersion {
			next = append(next, item)
		}
	}
	return next
}

func actionThrottleKey(printerID int, kind string, desired desiredStateItem) string {
	if isPrinterRuntimeCommandKind(kind) {
		return fmt.Sprintf("%d:%s:%d", printerID, kind, desired.IntentVersion)
	}
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
	bootstrap := a.snapshotBootstrap()
	a.mu.Lock()
	a.inflightActions[queuedAction.PrinterID] = queuedAction
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.inflightActions, queuedAction.PrinterID)
		a.mu.Unlock()
	}()

	if normalizeAdapterFamily(binding.AdapterFamily) == "bambu" && isPrinterRuntimeCommandKind(queuedAction.Kind) {
		a.extendBambuRuntimeConnectivitySuppression(queuedAction.PrinterID, bambuRuntimeCommandSuppressWindow)
	}

	if strings.TrimSpace(binding.EndpointURL) == "" {
		a.handleActionFailure(queuedAction, "connectivity_error", "missing endpoint_url in printer binding", true)
		return nil
	}

	if err := a.executeAction(ctx, queuedAction, binding); err != nil {
		rawErrorMessage := strings.TrimSpace(err.Error())
		printerFacingErrorMessage := summarizePrinterFacingActionError(rawErrorMessage)
		code, retryable := classifyActionError(err)
		if code == "connectivity_error" {
			if a.tryRecoverUncertainConnectivityAction(ctx, queuedAction, binding) {
				if queuedAction.CommandRequestID != 0 {
					if ackErr := a.acknowledgePrinterCommand(ctx, bootstrap, queuedAction.CommandRequestID, "acknowledged", ""); ackErr != nil {
						return ackErr
					}
				}
				return nil
			}
		}
		if rawErrorMessage != "" && rawErrorMessage != printerFacingErrorMessage {
			a.audit("action_failure_raw", map[string]any{
				"printer_id":         queuedAction.PrinterID,
				"kind":               queuedAction.Kind,
				"command_request_id": queuedAction.CommandRequestID,
				"error_code":         code,
				"raw_error_message":  rawErrorMessage,
			})
		}
		terminalFailure := !retryable || queuedAction.Attempts >= a.cfg.ActionMaxAttempts
		a.handleActionFailure(queuedAction, code, printerFacingErrorMessage, retryable)
		if queuedAction.CommandRequestID != 0 && terminalFailure {
			if ackErr := a.acknowledgePrinterCommand(ctx, bootstrap, queuedAction.CommandRequestID, "failed", printerFacingErrorMessage); ackErr != nil {
				return ackErr
			}
		}
		return nil
	}
	a.markActionSuccess(queuedAction)
	if normalizeAdapterFamily(binding.AdapterFamily) == "bambu" && isPrinterRuntimeCommandKind(queuedAction.Kind) {
		a.extendBambuRuntimeConnectivitySuppression(queuedAction.PrinterID, bambuRuntimeCommandSuppressWindow)
	}
	if queuedAction.CommandRequestID != 0 {
		if ackErr := a.acknowledgePrinterCommand(ctx, bootstrap, queuedAction.CommandRequestID, "acknowledged", ""); ackErr != nil {
			return ackErr
		}
	}
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
		printerID, parseErr := parseBambuPrinterEndpointID(binding.EndpointURL)
		if parseErr != nil {
			return false
		}
		snapshot, fetchErr := a.fetchBambuVerificationSnapshotByPrinterID(requestCtx, printerID)
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
	if errorCode == "auth_error" && shouldInvalidateBambuAuthState(message) {
		state := a.snapshotBambuAuthState()
		state.Ready = false
		state.AccessToken = ""
		state.ExpiresAt = time.Time{}
		state.LastError = message
		state.LastAttemptAt = time.Now().UTC()
		a.setBambuAuthState(state)
		a.audit("bambu_auth_state_invalidated", map[string]any{
			"reason": message,
		})
	}

	if retryable && queuedAction.Attempts < a.cfg.ActionMaxAttempts {
		a.requeueActionWithBackoff(queuedAction, errorCode, message)
		return
	}
	if !retryable {
		a.suppressActionReenqueue(queuedAction, errorCode, message)
		dropped := a.pruneQueuedDuplicatesForAction(queuedAction)
		if dropped > 0 {
			a.audit("action_duplicate_queue_pruned", map[string]any{
				"printer_id":     queuedAction.PrinterID,
				"kind":           queuedAction.Kind,
				"intent_version": queuedAction.Target.IntentVersion,
				"job_id":         queuedAction.Target.JobID,
				"plate_id":       queuedAction.Target.PlateID,
				"dropped_count":  dropped,
			})
		}
	}
	a.moveToDeadLetter(queuedAction, errorCode, message)
	a.markActionFailure(queuedAction, errorCode, message)
}

func shouldInvalidateBambuAuthState(message string) bool {
	msg := strings.ToLower(strings.TrimSpace(message))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "rejected access token") ||
		strings.Contains(msg, "invalid credentials") ||
		strings.Contains(msg, "status=401") ||
		strings.Contains(msg, "unauthorized")
}

func (a *agent) pruneQueuedDuplicatesForAction(queuedAction action) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	queue := a.actionQueue[queuedAction.PrinterID]
	next, dropped := pruneQueuedActionsByIdentityLocked(queue, queuedAction.PrinterID, queuedAction.Kind, queuedAction.Target)
	if dropped == 0 {
		return 0
	}
	if len(next) == 0 {
		delete(a.actionQueue, queuedAction.PrinterID)
		return dropped
	}
	a.actionQueue[queuedAction.PrinterID] = next
	return dropped
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
		return a.executeBambuAction(ctx, queuedAction, binding)
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
	case "light_on", "light_off":
		return a.executeMoonrakerLightAction(ctx, binding.EndpointURL, queuedAction.Kind)
	case "load_filament":
		return a.executeMoonrakerGCodeMacroAction(ctx, binding.EndpointURL, "LOAD_FILAMENT")
	case "unload_filament":
		return a.executeMoonrakerGCodeMacroAction(ctx, binding.EndpointURL, "UNLOAD_FILAMENT")
	case "refresh_file_index":
		return a.refreshMoonrakerPrinterFiles(ctx, queuedAction, binding)
	case "start_existing_file":
		return a.executeMoonrakerStartExistingFile(ctx, queuedAction, binding)
	case "delete_file":
		return a.executeMoonrakerDeleteFile(ctx, queuedAction, binding)
	case "delete_all_files":
		return a.executeMoonrakerDeleteAllFiles(ctx, queuedAction, binding)
	case "home_axes", "jog_motion", "jog_motion_batch", "set_fan_enabled", "set_nozzle_temperature", "set_bed_temperature":
		return a.executeMoonrakerPrinterCommand(ctx, binding.EndpointURL, queuedAction)
	default:
		return fmt.Errorf("unsupported action kind: %s", queuedAction.Kind)
	}
}

func (a *agent) executeBambuAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	switch strings.ToLower(strings.TrimSpace(queuedAction.Kind)) {
	case "print":
		return a.executeBambuLANPrintAction(ctx, queuedAction, binding)
	case "pause", "resume", "stop":
		command := strings.ToLower(strings.TrimSpace(queuedAction.Kind))
		if err := a.executeBambuLANControlAction(ctx, queuedAction, binding, command); err == nil {
			return nil
		} else if !isBambuLANCredentialsUnavailable(err) {
			return err
		}
		return a.executeBambuCloudAction(ctx, queuedAction, binding)
	case "refresh_file_index":
		return a.refreshBambuPrinterFiles(ctx, queuedAction, binding)
	case "start_existing_file":
		return a.executeBambuLANStartExistingFile(ctx, queuedAction, binding)
	case "delete_file":
		return a.executeBambuLANDeleteFile(ctx, queuedAction, binding)
	case "delete_all_files":
		return a.executeBambuLANDeleteAllFiles(ctx, queuedAction, binding)
	case "light_on", "light_off", "load_filament", "unload_filament", "home_axes", "jog_motion", "jog_motion_batch", "set_fan_enabled", "set_nozzle_temperature", "set_bed_temperature":
		return a.executeBambuLANPrinterCommand(ctx, queuedAction, binding)
	default:
		return fmt.Errorf("unsupported action kind: %s", queuedAction.Kind)
	}
}

func (a *agent) executeBambuCloudAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	if strings.EqualFold(strings.TrimSpace(queuedAction.Kind), "print") {
		return a.executeBambuConnectPrintAction(ctx, queuedAction, binding)
	}
	exec := func(token string) error {
		return a.executeBambuCloudActionWithToken(ctx, queuedAction, binding, token)
	}
	return a.executeWithBambuTokenRetry(ctx, exec)
}

func (a *agent) executeBambuCloudActionWithToken(ctx context.Context, queuedAction action, binding edgeBinding, accessToken string) error {
	switch queuedAction.Kind {
	case "pause":
		return a.executeBambuCloudControlAction(ctx, queuedAction, binding, accessToken, "pause")
	case "resume":
		return a.executeBambuCloudControlAction(ctx, queuedAction, binding, accessToken, "resume")
	case "stop":
		return a.executeBambuCloudControlAction(ctx, queuedAction, binding, accessToken, "stop")
	case "print":
		return errors.New("bambu_connect_unavailable: print start requires Bambu Connect handoff")
	default:
		return fmt.Errorf("unsupported action kind: %s", queuedAction.Kind)
	}
}

func (a *agent) executeBambuConnectPrintAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
	if err != nil {
		return err
	}
	if strings.TrimSpace(a.cfg.BambuConnectURI) != "" {
		if _, statusErr := a.fetchBambuConnectPrinterStatus(ctx, printerID); statusErr != nil {
			a.audit("bambu_connect_preflight_warning", map[string]any{
				"printer_id":         queuedAction.PrinterID,
				"job_id":             queuedAction.Target.JobID,
				"plate_id":           queuedAction.Target.PlateID,
				"adapter_family":     "bambu",
				"connect_status_err": statusErr.Error(),
			})
		}
	}

	artifact, err := a.downloadArtifact(ctx, queuedAction.Target)
	if err != nil {
		return err
	}
	importDisplayName := artifact.preferredSourceName()
	importPath, err := prepareBambuConnectImportPath(artifact.LocalPath, importDisplayName)
	if err != nil {
		a.cleanupArtifact(artifact.LocalPath)
		return err
	}
	defer a.cleanupArtifact(importPath)

	a.audit("artifact_downloaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        importDisplayName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})

	dispatchURI := buildBambuConnectImportURI(importPath, importDisplayName)
	a.audit("bambu_connect_start_dispatch_attempt", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       importDisplayName,
		"dispatch_uri":   dispatchURI,
		"transport":      "bambu_connect_uri",
		"adapter_family": "bambu",
	})
	// Compatibility alias used by existing operator log filters.
	a.audit("bambu_print_start_dispatch_attempt", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       importDisplayName,
		"transport":      "bambu_connect_uri",
		"adapter_family": "bambu",
	})
	if err := launchBambuConnectURI(ctx, dispatchURI); err != nil {
		a.audit("bambu_connect_start_dispatch_failed", map[string]any{
			"printer_id":     queuedAction.PrinterID,
			"job_id":         queuedAction.Target.JobID,
			"plate_id":       queuedAction.Target.PlateID,
			"filename":       importDisplayName,
			"transport":      "bambu_connect_uri",
			"adapter_family": "bambu",
			"error":          err.Error(),
		})
		return fmt.Errorf("bambu_connect_dispatch_failed: %w", err)
	}
	a.audit("bambu_connect_start_dispatch_success", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       importDisplayName,
		"transport":      "bambu_connect_uri",
		"adapter_family": "bambu",
	})
	a.extendBambuRuntimeConnectivitySuppression(queuedAction.PrinterID, a.bambuPrintStartVerificationTimeout())

	if err := a.verifyBambuPrintStart(ctx, strings.TrimSpace(printerID)); err != nil {
		return fmt.Errorf(
			"bambu_start_manual_handoff_required: Bambu Connect import dispatched but printer %q did not enter queued/printing state within %s; open Bambu Connect and confirm Print on the target device: %w",
			strings.TrimSpace(printerID),
			a.bambuPrintStartVerificationTimeout(),
			err,
		)
	}

	a.audit("bambu_print_start_verified", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       importDisplayName,
		"transport":      "bambu_connect_uri",
		"adapter_family": "bambu",
	})

	a.audit("print_start_requested", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        importDisplayName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
		"transport":       "bambu_connect_uri",
	})
	return nil
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
		a.expireBambuAccessTokenForRetry(ctx, err.Error())
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

func (a *agent) expireBambuAccessTokenForRetry(ctx context.Context, reason string) {
	state := a.snapshotBambuAuthState()
	state.Ready = false
	state.AccessToken = ""
	state.ExpiresAt = time.Time{}
	state.LastError = strings.TrimSpace(reason)
	state.LastAttemptAt = time.Now().UTC()
	a.setBambuAuthState(state)

	store := a.bambuAuthStore
	if store == nil {
		return
	}
	credentials, err := store.Load(ctx)
	if err != nil {
		a.audit("bambu_auth_retry_token_expire_store_load_failed", map[string]any{"error": err.Error()})
		return
	}
	credentials.AccessToken = ""
	credentials.ExpiresAt = time.Time{}
	if err := store.Save(ctx, credentials); err != nil {
		a.audit("bambu_auth_retry_token_expire_store_save_failed", map[string]any{"error": err.Error()})
	}
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

	artifact, err := a.downloadArtifact(ctx, queuedAction.Target)
	if err != nil {
		return err
	}
	defer a.cleanupArtifact(artifact.LocalPath)

	fileBytes, err := os.ReadFile(artifact.LocalPath)
	if err != nil {
		return err
	}
	uploadName := artifact.preferredSourceName()

	a.audit("artifact_downloaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        uploadName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})

	uploadURLs, err := provider.GetUploadURLs(ctx, accessToken, uploadName, int64(len(fileBytes)))
	if err != nil {
		return err
	}
	if inferredMQTTUsername := strings.TrimSpace(bambuMQTTUsernameFromUploadURLs(uploadURLs)); inferredMQTTUsername != "" {
		a.updateBambuMQTTUsername(ctx, inferredMQTTUsername)
		a.audit("bambu_mqtt_username_inferred_from_upload_urls", map[string]any{
			"printer_id":     queuedAction.PrinterID,
			"job_id":         queuedAction.Target.JobID,
			"plate_id":       queuedAction.Target.PlateID,
			"source":         "upload_urls",
			"adapter_family": "bambu",
		})
	}
	if err := provider.UploadToSignedURLs(ctx, uploadURLs, fileBytes); err != nil {
		return err
	}
	if err := provider.ConfirmUpload(ctx, accessToken, uploadURLs); err != nil {
		return err
	}
	a.audit("artifact_upload_confirmed", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        uploadName,
		"file_id":         strings.TrimSpace(uploadURLs.FileID),
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})

	a.audit("artifact_uploaded", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        uploadName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	})

	fileURL := strings.TrimSpace(uploadURLs.FileURL)
	fileName := strings.TrimSpace(uploadURLs.FileName)
	if fileName == "" {
		fileName = uploadName
	}
	startReq := bambucloud.CloudPrintStartRequest{
		DeviceID: strings.TrimSpace(printerID),
		FileName: fileName,
		FileURL:  fileURL,
		FileID:   strings.TrimSpace(uploadURLs.FileID),
	}
	a.audit("bambu_print_start_dispatch_attempt", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       fileName,
		"transport":      "cloud_http_task",
		"adapter_family": "bambu",
		"has_file_url":   strings.TrimSpace(startReq.FileURL) != "",
		"has_file_id":    strings.TrimSpace(startReq.FileID) != "",
	})
	if err := provider.StartPrintJob(ctx, accessToken, startReq); err != nil {
		details := summarizeBambuCloudStartDispatchError(err)
		details["printer_id"] = queuedAction.PrinterID
		details["job_id"] = queuedAction.Target.JobID
		details["plate_id"] = queuedAction.Target.PlateID
		details["filename"] = fileName
		details["transport"] = "cloud_http_task"
		details["adapter_family"] = "bambu"
		a.audit("bambu_print_start_dispatch_failure", details)
		return fmt.Errorf("bambu print start cloud dispatch failed: %w", err)
	}
	a.extendBambuRuntimeConnectivitySuppression(queuedAction.PrinterID, a.bambuPrintStartVerificationTimeout())
	if err := a.verifyBambuPrintStart(ctx, strings.TrimSpace(printerID)); err != nil {
		return fmt.Errorf("bambu_start_verification_timeout: %w", err)
	}
	a.audit("bambu_print_start_verified", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"filename":       fileName,
		"transport":      "cloud_http_task",
		"adapter_family": "bambu",
	})

	a.audit("print_start_requested", map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        fileName,
		"adapter_family":  "bambu",
		"desired_printer": queuedAction.Target.DesiredPrinterState,
		"transport":       "cloud_http_task",
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
	if err := a.publishBambuCloudMQTTCommand(ctx, provider, accessToken, strings.TrimSpace(printerID), command, ""); err != nil {
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
	param any,
) error {
	type mqttUsernameCandidate struct {
		Username string
		Source   string
	}
	type mqttPasswordCandidate struct {
		Password string
		Source   string
	}
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
	trimmedAccessToken := strings.TrimSpace(accessToken)

	username, usernameSource, err := a.resolveBambuMQTTUsername(ctx, accessToken)
	if err != nil {
		return err
	}
	auditBase := map[string]any{
		"printer_id":     trimmedPrinterID,
		"command":        command,
		"adapter_family": "bambu",
	}
	a.audit("bambu_mqtt_username_resolved", map[string]any{
		"printer_id":     trimmedPrinterID,
		"command":        command,
		"source":         usernameSource,
		"adapter_family": "bambu",
	})

	candidates := []mqttUsernameCandidate{
		{Username: username, Source: usernameSource},
	}
	authStateUsername := strings.TrimSpace(a.snapshotBambuAuthState().MQTTUsername)
	if authStateUsername != "" {
		candidates = append(candidates, mqttUsernameCandidate{Username: authStateUsername, Source: "auth_state"})
	}
	if tokenUsername, tokenErr := bambuMQTTUsernameFromAccessToken(accessToken); tokenErr == nil && strings.TrimSpace(tokenUsername) != "" {
		candidates = append(candidates, mqttUsernameCandidate{Username: strings.TrimSpace(tokenUsername), Source: "token_claim"})
	}
	if a.bambuAuthStore != nil {
		credentials, loadErr := a.bambuAuthStore.Load(ctx)
		if loadErr == nil {
			storedUsername := strings.TrimSpace(credentials.MQTTUsername)
			if storedUsername != "" {
				candidates = append(candidates, mqttUsernameCandidate{Username: storedUsername, Source: "credentials_store"})
			}
		} else if !errors.Is(loadErr, os.ErrNotExist) {
			a.audit("bambu_mqtt_username_load_error", map[string]any{
				"error": loadErr.Error(),
			})
		}
	}

	uniqueCandidates := make([]mqttUsernameCandidate, 0, len(candidates)*2)
	seenCandidates := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		normalizedUsername := strings.TrimSpace(candidate.Username)
		if normalizedUsername == "" {
			continue
		}
		for _, cloudUsername := range cloudMQTTUsernameCandidates(normalizedUsername) {
			key := strings.ToLower(strings.TrimSpace(cloudUsername))
			if key == "" {
				continue
			}
			if _, exists := seenCandidates[key]; exists {
				continue
			}
			seenCandidates[key] = struct{}{}
			uniqueCandidates = append(uniqueCandidates, mqttUsernameCandidate{
				Username: strings.TrimSpace(cloudUsername),
				Source:   strings.TrimSpace(candidate.Source),
			})
		}
	}
	if len(uniqueCandidates) == 0 {
		return errors.New("validation_error: unable to resolve bambu mqtt username")
	}
	passwordCandidates := make([]mqttPasswordCandidate, 0, 2)
	if trimmedAccessToken != "" {
		passwordCandidates = append(passwordCandidates, mqttPasswordCandidate{
			Password: trimmedAccessToken,
			Source:   "access_token",
		})
	}
	if !strings.EqualFold(accessCode, trimmedAccessToken) {
		passwordCandidates = append(passwordCandidates, mqttPasswordCandidate{
			Password: accessCode,
			Source:   "device_access_code",
		})
	}

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

	var lastErr error
	for idx, candidate := range uniqueCandidates {
		for passwordIdx, passwordCandidate := range passwordCandidates {
			if idx > 0 || passwordIdx > 0 {
				attemptSequence := idx*len(passwordCandidates) + passwordIdx + 1
				totalCandidates := len(uniqueCandidates) * len(passwordCandidates)
				auditPayload := map[string]any{
					"printer_id":       auditBase["printer_id"],
					"command":          auditBase["command"],
					"adapter_family":   auditBase["adapter_family"],
					"candidate_source": candidate.Source,
					"attempt_sequence": attemptSequence,
					"total_candidates": totalCandidates,
				}
				if len(passwordCandidates) > 1 {
					auditPayload["password_source"] = passwordCandidate.Source
				}
				a.audit("bambu_mqtt_username_retry_attempt", auditPayload)
			}

			publishErr := publisher.PublishPrintCommand(ctx, bambuMQTTCommandRequest{
				BrokerAddr: brokerAddr,
				Topic:      topic,
				Username:   candidate.Username,
				Password:   passwordCandidate.Password,
				Command:    command,
				Param:      param,
			})
			if publishErr == nil {
				a.updateBambuMQTTUsername(ctx, candidate.Username)
				if idx > 0 || passwordIdx > 0 {
					auditPayload := map[string]any{
						"printer_id":       auditBase["printer_id"],
						"command":          auditBase["command"],
						"adapter_family":   auditBase["adapter_family"],
						"candidate_source": candidate.Source,
						"attempt_sequence": idx*len(passwordCandidates) + passwordIdx + 1,
					}
					if len(passwordCandidates) > 1 {
						auditPayload["password_source"] = passwordCandidate.Source
					}
					a.audit("bambu_mqtt_username_retry_success", auditPayload)
				}
				return nil
			}

			lastErr = publishErr
			if !isBambuMQTTAuthReject(publishErr) {
				return publishErr
			}
		}
	}
	return lastErr
}

func isBambuMQTTAuthReject(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "bambu mqtt broker rejected connection return_code=")
}

func cloudMQTTUsernameCandidates(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "u_") {
		base := strings.TrimSpace(trimmed[2:])
		if base == "" {
			return []string{trimmed}
		}
		return []string{trimmed, base}
	}
	return []string{"u_" + trimmed, trimmed}
}

func (a *agent) resolveBambuMQTTUsername(ctx context.Context, accessToken string) (string, string, error) {
	authStateUsername := strings.TrimSpace(a.snapshotBambuAuthState().MQTTUsername)
	if authStateUsername != "" {
		return authStateUsername, "auth_state", nil
	}

	if a.bambuAuthStore != nil {
		credentials, err := a.bambuAuthStore.Load(ctx)
		if err == nil {
			storedUsername := strings.TrimSpace(credentials.MQTTUsername)
			if storedUsername != "" {
				return storedUsername, "credentials_store", nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			a.audit("bambu_mqtt_username_load_error", map[string]any{
				"error": err.Error(),
			})
		}
	}

	tokenUsername, tokenErr := bambuMQTTUsernameFromAccessToken(accessToken)
	if tokenErr == nil {
		return tokenUsername, "token_claim", nil
	}

	return "", "", fmt.Errorf("validation_error: unable to resolve bambu mqtt username from access token (%v)", tokenErr)
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

func (a *agent) bambuActionVerificationTimeout() time.Duration {
	timeout := a.cfg.MoonrakerRequestTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	// Bambu cloud command dispatch + telemetry propagation can legitimately exceed
	// Moonraker-like LAN latencies; keep a floor to reduce false timeout failures.
	if timeout < 20*time.Second {
		timeout = 20 * time.Second
	}
	return timeout
}

func (a *agent) bambuPrintStartVerificationTimeout() time.Duration {
	timeout := a.bambuActionVerificationTimeout()
	// Cloud-start transitions can take significantly longer than command dispatch.
	// Keep a higher floor so we do not fail while the printer is still preparing.
	if timeout < 90*time.Second {
		timeout = 90 * time.Second
	}
	return timeout
}

func (a *agent) bambuVerificationSnapshotRequestTimeout() time.Duration {
	timeout := a.cfg.BambuLANRuntimeTimeout
	if timeout <= 0 {
		timeout = defaultBambuLANRuntimeTimeout
	}
	if timeout < 5*time.Second {
		timeout = 5 * time.Second
	}
	return timeout
}

func (a *agent) verifyBambuPrintStart(ctx context.Context, printerID string) error {
	timeout := a.bambuPrintStartVerificationTimeout()
	verificationSnapshotTimeout := a.bambuVerificationSnapshotRequestTimeout()
	deadline := time.Now().UTC().Add(timeout)
	lastPrinterState := ""
	lastJobState := ""
	lastRawStatus := ""
	lastErrMessage := ""
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().UTC().After(deadline) {
			if lastPrinterState != "" || lastJobState != "" {
				return fmt.Errorf(
					"bambu print start verification timeout after %s waiting for queued/printing state (last_printer_state=%s last_job_state=%s last_cloud_status=%s last_error=%s)",
					timeout,
					lastPrinterState,
					lastJobState,
					lastRawStatus,
					lastErrMessage,
				)
			}
			if lastErrMessage != "" {
				return fmt.Errorf("bambu print start verification timeout after %s waiting for queued/printing state (last_error=%s)", timeout, lastErrMessage)
			}
			return fmt.Errorf("bambu print start verification timeout after %s waiting for queued/printing state", timeout)
		}
		requestCtx, cancel := context.WithTimeout(ctx, verificationSnapshotTimeout)
		snapshot, err := a.fetchBambuVerificationSnapshotByPrinterIDWithLANTimeout(requestCtx, printerID, verificationSnapshotTimeout)
		cancel()
		if err == nil {
			lastPrinterState = snapshot.PrinterState
			lastJobState = snapshot.JobState
			lastRawStatus = strings.TrimSpace(snapshot.RawPrinterStatus)
			lastErrMessage = ""
			if matchesBambuPrintStartExpectation(snapshot.PrinterState, snapshot.JobState) {
				return nil
			}
		} else {
			lastErrMessage = strings.TrimSpace(err.Error())
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (a *agent) fetchBambuVerificationSnapshotByPrinterID(ctx context.Context, printerID string) (bindingSnapshot, error) {
	return a.fetchBambuVerificationSnapshotByPrinterIDWithLANTimeout(ctx, printerID, 0)
}

func (a *agent) fetchBambuVerificationSnapshotByPrinterIDWithLANTimeout(ctx context.Context, printerID string, lanRequestTimeout time.Duration) (bindingSnapshot, error) {
	lanSnapshot, lanErr := a.fetchBambuLANRuntimeSnapshotByPrinterIDWithTimeout(ctx, printerID, lanRequestTimeout)
	if lanErr == nil {
		return lanSnapshot, nil
	}
	if !isBambuLANCredentialsUnavailable(lanErr) {
		a.audit("bambu_lan_runtime_snapshot_error", map[string]any{
			"printer_id": strings.TrimSpace(printerID),
			"error":      lanErr.Error(),
		})
	}
	if strings.TrimSpace(a.cfg.BambuConnectURI) != "" {
		connectSnapshot, connectErr := a.fetchBambuConnectSnapshotByPrinterID(ctx, printerID)
		if connectErr == nil {
			return connectSnapshot, nil
		}
		if !a.isBambuAuthReady() {
			if !isBambuLANCredentialsUnavailable(lanErr) {
				return bindingSnapshot{}, fmt.Errorf("bambu lan runtime snapshot failed: %v; bambu connect snapshot failed: %w", lanErr, connectErr)
			}
			return bindingSnapshot{}, connectErr
		}
		cloudSnapshot, cloudErr := a.fetchBambuCloudSnapshotByPrinterID(ctx, printerID)
		if cloudErr == nil {
			return cloudSnapshot, nil
		}
		if !isBambuLANCredentialsUnavailable(lanErr) {
			return bindingSnapshot{}, fmt.Errorf("bambu lan runtime snapshot failed: %v; bambu connect snapshot failed: %v; cloud snapshot failed: %w", lanErr, connectErr, cloudErr)
		}
		return bindingSnapshot{}, fmt.Errorf("bambu connect snapshot failed: %v; cloud snapshot failed: %w", connectErr, cloudErr)
	}
	if a.isBambuAuthReady() {
		cloudSnapshot, cloudErr := a.fetchBambuCloudSnapshotByPrinterID(ctx, printerID)
		if cloudErr == nil {
			return cloudSnapshot, nil
		}
		if !isBambuLANCredentialsUnavailable(lanErr) {
			return bindingSnapshot{}, fmt.Errorf("bambu lan runtime snapshot failed: %v; cloud snapshot failed: %w", lanErr, cloudErr)
		}
		return bindingSnapshot{}, cloudErr
	}
	return bindingSnapshot{}, lanErr
}

func matchesBambuPrintStartExpectation(printerState string, jobState string) bool {
	return printerState == "printing" || printerState == "queued" || (printerState == "paused" && jobState == "printing")
}

func (a *agent) verifyBambuControlAction(ctx context.Context, printerID string, command string) error {
	timeout := a.bambuActionVerificationTimeout()
	verificationSnapshotTimeout := a.bambuVerificationSnapshotRequestTimeout()
	deadline := time.Now().UTC().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().UTC().After(deadline) {
			return fmt.Errorf("bambu command verification timeout after %s", timeout)
		}
		requestCtx, cancel := context.WithTimeout(ctx, verificationSnapshotTimeout)
		snapshot, err := a.fetchBambuVerificationSnapshotByPrinterIDWithLANTimeout(requestCtx, printerID, verificationSnapshotTimeout)
		cancel()
		if err == nil && matchesBambuControlExpectation(snapshot.PrinterState, snapshot.JobState, command) {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (a *agent) verifyBambuLEDState(ctx context.Context, printerID string, expectedState string) error {
	timeout := a.bambuActionVerificationTimeout()
	deadline := time.Now().UTC().Add(timeout)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().UTC().After(deadline) {
			return fmt.Errorf("bambu led verification timeout after %s", timeout)
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		snapshot, err := a.fetchBambuVerificationSnapshotByPrinterID(requestCtx, printerID)
		cancel()
		if err == nil {
			if capabilities := cloneCommandCapabilities(snapshot.CommandCapabilities); capabilities != nil {
				if led, ok := capabilities["led"].(map[string]any); ok {
					state := strings.ToLower(strings.TrimSpace(fmt.Sprint(led["state"])))
					if state == strings.ToLower(strings.TrimSpace(expectedState)) {
						return nil
					}
				}
			}
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

func artifactAuditFields(queuedAction action, adapterFamily, filename string) map[string]any {
	return map[string]any{
		"printer_id":      queuedAction.PrinterID,
		"job_id":          queuedAction.Target.JobID,
		"plate_id":        queuedAction.Target.PlateID,
		"filename":        filename,
		"adapter_family":  adapterFamily,
		"desired_printer": queuedAction.Target.DesiredPrinterState,
	}
}

func mergedAuditFields(base map[string]any, extra map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}

func (a *agent) executePrintAction(ctx context.Context, queuedAction action, binding edgeBinding) error {
	artifact, err := a.downloadArtifact(ctx, queuedAction.Target)
	if err != nil {
		return err
	}
	defer a.cleanupArtifact(artifact.LocalPath)
	remoteName := artifact.moonrakerRemoteName()
	baseAuditFields := artifactAuditFields(queuedAction, "moonraker", remoteName)
	a.audit("artifact_downloaded", mergedAuditFields(baseAuditFields, map[string]any{
		"source_filename": artifact.preferredSourceName(),
		"size_bytes":      artifact.SizeBytes,
	}))
	a.audit("artifact_reuse_probe_attempt", mergedAuditFields(baseAuditFields, map[string]any{
		"transport": "moonraker_file_manager",
	}))

	reused, reason, probeErr := a.probeMoonrakerArtifactReuse(ctx, binding.EndpointURL, artifact)
	switch {
	case probeErr != nil:
		a.audit("artifact_reuse_probe_fallback_upload", mergedAuditFields(baseAuditFields, map[string]any{
			"transport": "moonraker_file_manager",
			"reason":    reason,
			"error":     probeErr.Error(),
		}))
	case reused:
		a.audit("artifact_reused", mergedAuditFields(baseAuditFields, map[string]any{
			"transport": "moonraker_file_manager",
			"reason":    reason,
		}))
	case reason != "" && reason != "absent":
		a.audit("artifact_reuse_probe_mismatch", mergedAuditFields(baseAuditFields, map[string]any{
			"transport": "moonraker_file_manager",
			"reason":    reason,
		}))
	}

	if !reused {
		if err := a.uploadArtifact(ctx, binding.EndpointURL, artifact); err != nil {
			return err
		}
		a.audit("artifact_uploaded", mergedAuditFields(baseAuditFields, map[string]any{
			"transport": "moonraker_file_manager",
		}))
	}
	startPayload := map[string]string{"filename": remoteName}
	if err := a.callMoonrakerPost(ctx, binding.EndpointURL, "/printer/print/start", startPayload); err != nil {
		return err
	}
	a.audit("print_start_requested", baseAuditFields)
	return nil
}

func (a *agent) callMoonrakerPost(ctx context.Context, endpointURL, path string, payload any) error {
	return a.callMoonrakerPostWithTimeout(ctx, endpointURL, path, payload, a.cfg.MoonrakerRequestTimeout)
}

func (a *agent) callMoonrakerPostWithTimeout(
	ctx context.Context,
	endpointURL string,
	path string,
	payload any,
	timeout time.Duration,
) error {
	requestTimeout := timeout
	if requestTimeout <= 0 {
		requestTimeout = a.cfg.MoonrakerRequestTimeout
	}
	if requestTimeout <= 0 {
		requestTimeout = 8 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
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

func (a *agent) isSnapmakerU1Printer(printerID int) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	current, ok := a.currentState[printerID]
	if !ok || current.CommandCapabilities == nil {
		return false
	}
	rawSupport, ok := current.CommandCapabilities["printer_support"].(map[string]any)
	if !ok {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(stringFromAny(rawSupport["profile_key"])), snapmakeru1.ProfileKey)
}

type moonrakerPowerDevice struct {
	Device string
	Status string
}

func (a *agent) executeMoonrakerLightAction(ctx context.Context, endpointURL, commandKey string) error {
	devices, err := a.fetchMoonrakerDevicePowerDevices(ctx, endpointURL)
	if err != nil {
		return err
	}
	deviceName, _, ok := resolveMoonrakerPrimaryLightDevice(devices)
	action := "on"
	if strings.TrimSpace(commandKey) == "light_off" {
		action = "off"
	}
	if ok {
		return a.callMoonrakerPost(
			ctx,
			endpointURL,
			"/machine/device_power/device?device="+url.QueryEscape(deviceName)+"&action="+url.QueryEscape(action),
			nil,
		)
	}

	objects, err := a.fetchMoonrakerObjectList(ctx, endpointURL)
	if err != nil {
		return err
	}
	ledObjectName, ok := resolveMoonrakerPrimaryLEDObject(objects)
	if !ok {
		return errors.New("validation_error: moonraker primary light device is not configured")
	}
	ledConfigName := moonrakerLEDObjectConfigName(ledObjectName)
	if ledConfigName == "" {
		return errors.New("validation_error: moonraker led object is missing config name")
	}

	whiteValue := "1"
	if action == "off" {
		whiteValue = "0"
	}
	return a.callMoonrakerPost(
		ctx,
		endpointURL,
		"/printer/gcode/script",
		map[string]string{
			"script": fmt.Sprintf("SET_LED LED=%s WHITE=%s SYNC=0 TRANSMIT=1", ledConfigName, whiteValue),
		},
	)
}

func (a *agent) executeMoonrakerGCodeMacroAction(ctx context.Context, endpointURL, macroName string) error {
	return a.callMoonrakerPost(
		ctx,
		endpointURL,
		"/printer/gcode/script",
		map[string]string{"script": strings.TrimSpace(macroName)},
	)
}

func (a *agent) executeMoonrakerPrinterCommand(ctx context.Context, endpointURL string, queuedAction action) error {
	var (
		script         string
		err            error
		requestTimeout time.Duration
	)
	switch strings.TrimSpace(queuedAction.Kind) {
	case "home_axes":
		if a.isSnapmakerU1Printer(queuedAction.PrinterID) {
			script, err = buildSnapmakerU1HomeAxesScript(queuedAction.Payload)
		} else {
			script, err = buildMoonrakerHomeAxesScript(queuedAction.Payload)
		}
		requestTimeout = moonrakerHomeRequestTimeout(a.cfg.MoonrakerRequestTimeout)
	case "jog_motion":
		script, err = buildMoonrakerJogMotionProgram(queuedAction.Payload)
	case "jog_motion_batch":
		script, err = buildMoonrakerJogMotionBatchProgram(queuedAction.Payload)
	case "set_fan_enabled":
		script, err = buildMoonrakerFanControlGCode(queuedAction.Payload)
	case "set_nozzle_temperature":
		var heaterName string
		heaterName, err = a.fetchMoonrakerActiveExtruderName(ctx, endpointURL)
		if err == nil {
			script, err = buildMoonrakerHeaterTemperatureGCode(heaterName, queuedAction.Payload, "set_nozzle_temperature")
		}
	case "set_bed_temperature":
		script, err = buildMoonrakerHeaterTemperatureGCode("heater_bed", queuedAction.Payload, "set_bed_temperature")
	default:
		return fmt.Errorf("unsupported moonraker printer command kind: %s", queuedAction.Kind)
	}
	if err != nil {
		return err
	}
	if requestTimeout > 0 {
		return a.callMoonrakerPostWithTimeout(
			ctx,
			endpointURL,
			"/printer/gcode/script",
			map[string]string{"script": script},
			requestTimeout,
		)
	}
	return a.callMoonrakerPost(
		ctx,
		endpointURL,
		"/printer/gcode/script",
		map[string]string{"script": script},
	)
}

type moonrakerJogMotionStep struct {
	Axis     string
	Distance float64
	FeedRate int
}

const (
	moonrakerXYJogFeedRateMMPerMin = 6000
	moonrakerZJogFeedRateMMPerMin  = 300
)

func buildMoonrakerHomeAxesScript(payload map[string]any) (string, error) {
	axes := []string{"X", "Y", "Z"}
	if len(payload) > 0 {
		rawAxes, exists := payload["axes"]
		if exists {
			typedAxes, ok := rawAxes.([]any)
			if !ok || len(typedAxes) == 0 {
				return "", errors.New("validation_error: home_axes requires a non-empty axes array")
			}
			axes = axes[:0]
			seen := map[string]struct{}{}
			for _, rawAxis := range typedAxes {
				axis := strings.ToUpper(strings.TrimSpace(stringFromAny(rawAxis)))
				switch axis {
				case "X", "Y", "Z":
				default:
					return "", fmt.Errorf("validation_error: unsupported home axis %q", axis)
				}
				if _, exists := seen[axis]; exists {
					continue
				}
				seen[axis] = struct{}{}
				axes = append(axes, axis)
			}
			if len(axes) == 0 {
				return "", errors.New("validation_error: home_axes requires at least one valid axis")
			}
		}
	}
	if len(axes) == 3 {
		return "G28", nil
	}
	return "G28 " + strings.Join(axes, " "), nil
}

func buildSnapmakerU1HomeAxesScript(payload map[string]any) (string, error) {
	axes := []string{"X", "Y", "Z"}
	if len(payload) > 0 {
		rawAxes, exists := payload["axes"]
		if exists {
			typedAxes, ok := rawAxes.([]any)
			if !ok || len(typedAxes) == 0 {
				return "", errors.New("validation_error: home_axes requires a non-empty axes array")
			}
			axes = axes[:0]
			seen := map[string]struct{}{}
			for _, rawAxis := range typedAxes {
				axis := strings.ToUpper(strings.TrimSpace(stringFromAny(rawAxis)))
				switch axis {
				case "X", "Y", "Z":
				default:
					return "", fmt.Errorf("validation_error: unsupported home axis %q", axis)
				}
				if _, exists := seen[axis]; exists {
					continue
				}
				seen[axis] = struct{}{}
				axes = append(axes, axis)
			}
			if len(axes) == 0 {
				return "", errors.New("validation_error: home_axes requires at least one valid axis")
			}
		}
	}
	return snapmakeru1.BuildHomeScript(axes), nil
}

func buildMoonrakerJogMotionProgram(payload map[string]any) (string, error) {
	step, err := parseMoonrakerJogMotionStep(payload)
	if err != nil {
		return "", err
	}
	return buildMoonrakerJogMotionProgramFromSteps([]moonrakerJogMotionStep{step}), nil
}

func buildMoonrakerJogMotionBatchProgram(payload map[string]any) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("validation_error: jog_motion_batch requires payload")
	}
	rawSteps, exists := payload["steps"]
	if !exists {
		return "", errors.New("validation_error: jog_motion_batch requires steps")
	}
	typedSteps, ok := rawSteps.([]any)
	if !ok || len(typedSteps) == 0 {
		return "", errors.New("validation_error: jog_motion_batch requires a non-empty steps array")
	}
	steps := make([]moonrakerJogMotionStep, 0, len(typedSteps))
	for _, rawStep := range typedSteps {
		stepPayload, ok := rawStep.(map[string]any)
		if !ok {
			return "", errors.New("validation_error: jog_motion_batch steps must be objects")
		}
		step, err := parseMoonrakerJogMotionStep(stepPayload)
		if err != nil {
			return "", err
		}
		steps = append(steps, step)
	}
	return buildMoonrakerJogMotionProgramFromSteps(steps), nil
}

func parseMoonrakerJogMotionStep(payload map[string]any) (moonrakerJogMotionStep, error) {
	if len(payload) == 0 {
		return moonrakerJogMotionStep{}, errors.New("validation_error: jog_motion requires payload")
	}
	axis := strings.ToUpper(strings.TrimSpace(stringFromAny(payload["axis"])))
	switch axis {
	case "X", "Y", "Z":
	default:
		return moonrakerJogMotionStep{}, fmt.Errorf("validation_error: unsupported jog axis %q", axis)
	}
	distance, ok := moonrakerNumericValue(payload["distance_mm"])
	if !ok {
		return moonrakerJogMotionStep{}, errors.New("validation_error: jog_motion requires numeric distance_mm")
	}
	switch distance {
	case -10, -1, 1, 10:
	default:
		return moonrakerJogMotionStep{}, fmt.Errorf("validation_error: unsupported jog distance %.3f", distance)
	}
	feedRate := moonrakerXYJogFeedRateMMPerMin
	if axis == "Z" {
		feedRate = moonrakerZJogFeedRateMMPerMin
	}
	return moonrakerJogMotionStep{Axis: axis, Distance: distance, FeedRate: feedRate}, nil
}

func buildMoonrakerJogMotionProgramFromSteps(steps []moonrakerJogMotionStep) string {
	lines := make([]string, 0, len(steps)+4)
	lines = append(lines, "SAVE_GCODE_STATE NAME=pfh_motion")
	lines = append(lines, "G91")
	for _, step := range steps {
		lines = append(lines, fmt.Sprintf("G0 %s%g F%d", step.Axis, step.Distance, step.FeedRate))
	}
	lines = append(lines, "RESTORE_GCODE_STATE NAME=pfh_motion")
	return strings.Join(lines, "\n")
}

func buildMoonrakerFanControlGCode(payload map[string]any) (string, error) {
	if len(payload) == 0 {
		return "", errors.New("validation_error: set_fan_enabled requires payload")
	}
	fanName := strings.ToLower(strings.TrimSpace(stringFromAny(payload["fan"])))
	if fanName == "" {
		return "", errors.New("validation_error: set_fan_enabled requires fan")
	}
	enabled, err := parseMoonrakerBoolPayload(payload, "enabled")
	if err != nil {
		return "", err
	}
	switch fanName {
	case "fan":
		if enabled {
			return "M106 S255", nil
		}
		return "M107", nil
	default:
		if !strings.HasPrefix(fanName, "fan_generic ") {
			return "", fmt.Errorf("validation_error: unsupported moonraker fan %q", fanName)
		}
		configName := strings.TrimSpace(strings.TrimPrefix(fanName, "fan_generic "))
		if configName == "" {
			return "", fmt.Errorf("validation_error: invalid moonraker fan %q", fanName)
		}
		speed := 0
		if enabled {
			speed = 1
		}
		return fmt.Sprintf("SET_FAN_SPEED FAN=%s SPEED=%d", configName, speed), nil
	}
}

func buildMoonrakerHeaterTemperatureGCode(heaterName string, payload map[string]any, fieldName string) (string, error) {
	trimmedHeaterName := strings.TrimSpace(heaterName)
	if trimmedHeaterName == "" {
		return "", fmt.Errorf("validation_error: %s heater is not available", fieldName)
	}
	target, err := parseMoonrakerTargetTemperaturePayload(payload, fieldName)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("SET_HEATER_TEMPERATURE HEATER=%s TARGET=%d", trimmedHeaterName, target), nil
}

func parseMoonrakerBoolPayload(payload map[string]any, key string) (bool, error) {
	rawValue, exists := payload[key]
	if !exists {
		return false, fmt.Errorf("validation_error: missing %s", key)
	}
	typedValue, ok := rawValue.(bool)
	if !ok {
		return false, fmt.Errorf("validation_error: %s must be boolean", key)
	}
	return typedValue, nil
}

func parseMoonrakerTargetTemperaturePayload(payload map[string]any, fieldName string) (int, error) {
	if len(payload) == 0 {
		return 0, fmt.Errorf("validation_error: %s requires payload", fieldName)
	}
	rawTarget, exists := payload["target_c"]
	if !exists {
		return 0, fmt.Errorf("validation_error: %s requires target_c", fieldName)
	}
	target, ok := moonrakerNumericValue(rawTarget)
	if !ok {
		return 0, fmt.Errorf("validation_error: %s requires numeric target_c", fieldName)
	}
	if target < 0 {
		return 0, fmt.Errorf("validation_error: %s target_c must be >= 0", fieldName)
	}
	return int(target), nil
}

func moonrakerHomeRequestTimeout(defaultTimeout time.Duration) time.Duration {
	if defaultTimeout >= snapmakeru1.HomeRequestTimeout {
		return defaultTimeout
	}
	return snapmakeru1.HomeRequestTimeout
}

func moonrakerNumericValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		floatValue, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		return floatValue, true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		floatValue, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		return floatValue, true
	default:
		return 0, false
	}
}

func (a *agent) fetchMoonrakerCommandCapabilities(ctx context.Context, endpointURL string) (map[string]any, error) {
	capabilities := map[string]any{
		"led":             map[string]any{"supported": false},
		"load_filament":   map[string]any{"supported": false},
		"unload_filament": map[string]any{"supported": false},
	}
	var errs []string

	devices, err := a.fetchMoonrakerDevicePowerDevices(ctx, endpointURL)
	if err != nil {
		errs = append(errs, err.Error())
	}
	if deviceName, ledState, ok := resolveMoonrakerPrimaryLightDevice(devices); ok {
		capabilities["led"] = map[string]any{
			"supported": true,
			"device":    deviceName,
			"state":     normalizeMoonrakerPowerState(ledState),
		}
	}

	objects, err := a.fetchMoonrakerObjectList(ctx, endpointURL)
	if err != nil {
		errs = append(errs, err.Error())
	} else {
		sensorObjects := moonrakerFilamentSensorObjects(objects)
		if ledObjectName, ok := resolveMoonrakerPrimaryLEDObject(objects); ok {
			ledState, ledErr := a.fetchMoonrakerLEDObjectState(ctx, endpointURL, ledObjectName)
			if ledErr != nil {
				errs = append(errs, ledErr.Error())
			} else {
				capabilities["led"] = map[string]any{
					"supported": true,
					"device":    ledObjectName,
					"state":     ledState,
					"mode":      "klipper_led",
				}
			}
		}
		filamentState, filamentErr := a.fetchMoonrakerFilamentState(ctx, endpointURL, sensorObjects)
		if filamentErr != nil {
			errs = append(errs, filamentErr.Error())
		}
		capabilities["filament"] = map[string]any{
			"state":        firstNonEmpty(normalizeFilamentState(filamentState), "unknown"),
			"action_state": filamentActionStateIdle,
			"state_source": firstNonEmpty(func() string {
				if len(sensorObjects) > 0 {
					return filamentStateSourceMoonrakerSensor
				}
				return filamentStateSourceUnknown
			}(), filamentStateSourceUnknown),
			"confidence": func() string {
				if len(sensorObjects) > 0 {
					return filamentConfidenceConfirmed
				}
				return filamentConfidenceHeuristic
			}(),
			"sensor_present": len(sensorObjects) > 0,
		}
		capabilities["load_filament"] = map[string]any{
			"supported": moonrakerObjectListHasMacro(objects, "LOAD_FILAMENT"),
		}
		capabilities["unload_filament"] = map[string]any{
			"supported": moonrakerObjectListHasMacro(objects, "UNLOAD_FILAMENT"),
		}
	}

	if len(errs) > 0 {
		return capabilities, errors.New(strings.Join(errs, "; "))
	}
	return capabilities, nil
}

type moonrakerWritableFan struct {
	Key   string
	Label string
}

type moonrakerControlLayout struct {
	ToolheadPresent bool
	ExtruderObjects []string
	BedSupported    bool
	ChamberSensor   string
	Fans            []moonrakerWritableFan
}

func (a *agent) fetchMoonrakerControlStatus(ctx context.Context, endpointURL string) (printerControlStatusSnapshot, error) {
	objects, err := a.fetchMoonrakerObjectList(ctx, endpointURL)
	if err != nil {
		return printerControlStatusSnapshot{}, err
	}
	layout := buildMoonrakerControlLayout(objects)
	objectFields := map[string][]string{
		"toolhead": {"extruder"},
	}
	for _, extruderObject := range layout.ExtruderObjects {
		objectFields[extruderObject] = []string{"temperature", "target"}
	}
	if layout.BedSupported {
		objectFields["heater_bed"] = []string{"temperature", "target"}
	}
	if strings.TrimSpace(layout.ChamberSensor) != "" {
		objectFields[layout.ChamberSensor] = []string{"temperature"}
	}
	for _, fan := range layout.Fans {
		objectFields[fan.Key] = []string{"speed"}
	}

	statusByObject, err := a.fetchMoonrakerObjectStatus(ctx, endpointURL, objectFields)
	if err != nil {
		return printerControlStatusSnapshot{}, err
	}

	selectedExtruder := moonrakerSelectedExtruderName(statusByObject, layout.ExtruderObjects)
	fans := make(map[string]printerFanStatus, len(layout.Fans))
	for _, fan := range layout.Fans {
		fans[fan.Key] = moonrakerFanStatusFromObjectStatus(statusByObject[fan.Key], fan.Label)
	}

	return printerControlStatusSnapshot{
		Nozzle:          moonrakerTemperatureStatusFromObjectStatus(statusByObject[selectedExtruder], true),
		Bed:             moonrakerTemperatureStatusFromObjectStatus(statusByObject["heater_bed"], true),
		Chamber:         moonrakerTemperatureStatusFromObjectStatus(statusByObject[layout.ChamberSensor], false),
		Fans:            fans,
		MotionSupported: layout.ToolheadPresent,
		HomeSupported:   layout.ToolheadPresent,
	}, nil
}

func buildMoonrakerControlLayout(objects []string) moonrakerControlLayout {
	return moonrakerControlLayout{
		ToolheadPresent: moonrakerObjectListContains(objects, "toolhead"),
		ExtruderObjects: moonrakerExtruderObjects(objects),
		BedSupported:    moonrakerObjectListContains(objects, "heater_bed"),
		ChamberSensor:   resolveMoonrakerChamberTemperatureSensor(objects),
		Fans:            moonrakerWritableFanObjects(objects),
	}
}

func moonrakerObjectListContains(objects []string, want string) bool {
	normalizedWant := strings.ToLower(strings.TrimSpace(want))
	for _, objectName := range objects {
		if strings.ToLower(strings.TrimSpace(objectName)) == normalizedWant {
			return true
		}
	}
	return false
}

func moonrakerExtruderObjects(objects []string) []string {
	out := make([]string, 0)
	for _, objectName := range objects {
		trimmed := strings.TrimSpace(objectName)
		normalized := strings.ToLower(trimmed)
		if normalized == "extruder" {
			out = append(out, trimmed)
			continue
		}
		if strings.HasPrefix(normalized, "extruder") {
			suffix := strings.TrimPrefix(normalized, "extruder")
			if suffix != "" && strings.Trim(suffix, "0123456789") == "" {
				out = append(out, trimmed)
			}
		}
	}
	sort.Strings(out)
	return out
}

func resolveMoonrakerChamberTemperatureSensor(objects []string) string {
	priority := []string{
		"temperature_sensor chamber",
		"temperature_sensor chamber_temp",
		"temperature_sensor enclosure",
		"temperature_sensor enclosure_temp",
		"temperature_sensor cabinet",
		"temperature_sensor ambient",
	}
	byName := make(map[string]string, len(objects))
	for _, objectName := range objects {
		trimmed := strings.TrimSpace(objectName)
		if trimmed == "" {
			continue
		}
		byName[strings.ToLower(trimmed)] = trimmed
	}
	for _, candidate := range priority {
		if objectName, ok := byName[candidate]; ok {
			return objectName
		}
	}
	return ""
}

func moonrakerWritableFanObjects(objects []string) []moonrakerWritableFan {
	fans := make([]moonrakerWritableFan, 0)
	if moonrakerObjectListContains(objects, "fan") {
		fans = append(fans, moonrakerWritableFan{Key: "fan", Label: "Part Cooling"})
	}
	for _, objectName := range objects {
		trimmed := strings.TrimSpace(objectName)
		normalized := strings.ToLower(trimmed)
		if !strings.HasPrefix(normalized, "fan_generic ") {
			continue
		}
		configName := strings.TrimSpace(strings.TrimPrefix(trimmed, "fan_generic "))
		if configName == "" {
			continue
		}
		fans = append(fans, moonrakerWritableFan{
			Key:   strings.ToLower(trimmed),
			Label: moonrakerDisplayLabel(configName),
		})
	}
	sort.Slice(fans, func(i, j int) bool {
		return fans[i].Key < fans[j].Key
	})
	return fans
}

func moonrakerDisplayLabel(raw string) string {
	normalized := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, "_", " "), "-", " "))
	if normalized == "" {
		return ""
	}
	words := strings.Fields(normalized)
	for idx, word := range words {
		runes := []rune(strings.ToLower(word))
		if len(runes) == 0 {
			continue
		}
		runes[0] = unicode.ToUpper(runes[0])
		words[idx] = string(runes)
	}
	return strings.Join(words, " ")
}

func (a *agent) fetchMoonrakerObjectStatus(ctx context.Context, endpointURL string, objects map[string][]string) (map[string]map[string]any, error) {
	queryPath, err := buildMoonrakerObjectQueryPath(objects)
	if err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, resolveURL(endpointURL, queryPath), nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("moonraker object query failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Result struct {
			Status map[string]map[string]any `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Result.Status == nil {
		return map[string]map[string]any{}, nil
	}
	return payload.Result.Status, nil
}

func buildMoonrakerObjectQueryPath(objects map[string][]string) (string, error) {
	if len(objects) == 0 {
		return "", errors.New("validation_error: moonraker object query requires at least one object")
	}
	keys := make([]string, 0, len(objects))
	for key := range objects {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		keys = append(keys, trimmed)
	}
	if len(keys) == 0 {
		return "", errors.New("validation_error: moonraker object query requires at least one valid object")
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		fields := objects[key]
		if len(fields) == 0 {
			parts = append(parts, url.QueryEscape(key))
			continue
		}
		parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(strings.Join(fields, ",")))
	}
	return "/printer/objects/query?" + strings.Join(parts, "&"), nil
}

func moonrakerSelectedExtruderName(statusByObject map[string]map[string]any, extruderObjects []string) string {
	toolheadStatus := statusByObject["toolhead"]
	selected := strings.TrimSpace(stringFromAny(toolheadStatus["extruder"]))
	if selected != "" {
		for _, objectName := range extruderObjects {
			if strings.EqualFold(strings.TrimSpace(objectName), selected) {
				return objectName
			}
		}
	}
	if len(extruderObjects) > 0 {
		return extruderObjects[0]
	}
	return ""
}

func moonrakerTemperatureStatusFromObjectStatus(objectStatus map[string]any, includeTarget bool) printerTemperatureStatus {
	status := printerTemperatureStatus{}
	if len(objectStatus) == 0 {
		return status
	}
	if current, ok := moonrakerNumericValue(objectStatus["temperature"]); ok {
		value := current
		status.Current = &value
		status.Available = true
	}
	if includeTarget {
		if target, ok := moonrakerNumericValue(objectStatus["target"]); ok {
			value := target
			status.Target = &value
			status.Available = true
		}
	}
	return status
}

func moonrakerFanStatusFromObjectStatus(objectStatus map[string]any, label string) printerFanStatus {
	status := printerFanStatus{
		Label:     strings.TrimSpace(label),
		Supported: true,
		State:     "unknown",
	}
	if len(objectStatus) == 0 {
		return status
	}
	if speed, ok := moonrakerNumericValue(objectStatus["speed"]); ok {
		if speed > 0 {
			status.State = "on"
		} else {
			status.State = "off"
		}
	}
	return status
}

func (a *agent) fetchMoonrakerActiveExtruderName(ctx context.Context, endpointURL string) (string, error) {
	objects, err := a.fetchMoonrakerObjectList(ctx, endpointURL)
	if err != nil {
		return "", err
	}
	extruderObjects := moonrakerExtruderObjects(objects)
	if len(extruderObjects) == 0 {
		return "", errors.New("validation_error: moonraker extruder is not configured")
	}
	statusByObject, err := a.fetchMoonrakerObjectStatus(ctx, endpointURL, map[string][]string{
		"toolhead": {"extruder"},
	})
	if err != nil {
		if len(extruderObjects) == 1 {
			return extruderObjects[0], nil
		}
		return "", err
	}
	return moonrakerSelectedExtruderName(statusByObject, extruderObjects), nil
}

func (a *agent) fetchMoonrakerDevicePowerDevices(ctx context.Context, endpointURL string) ([]moonrakerPowerDevice, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/machine/device_power/devices"),
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
	if resp.StatusCode == http.StatusNotFound {
		return []moonrakerPowerDevice{}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("moonraker device_power devices failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	result, _ := payload["result"]
	return parseMoonrakerPowerDevices(result), nil
}

func parseMoonrakerPowerDevices(raw any) []moonrakerPowerDevice {
	result := make([]moonrakerPowerDevice, 0)
	appendDevice := func(deviceName string, statusValue any) {
		name := strings.TrimSpace(deviceName)
		if name == "" {
			return
		}
		status := strings.TrimSpace(fmt.Sprint(statusValue))
		result = append(result, moonrakerPowerDevice{Device: name, Status: status})
	}

	switch typed := raw.(type) {
	case map[string]any:
		if nested, ok := typed["devices"]; ok {
			return parseMoonrakerPowerDevices(nested)
		}
		for key, value := range typed {
			switch device := value.(type) {
			case map[string]any:
				name := strings.TrimSpace(firstNonEmpty(
					stringFromAny(device["device"]),
					stringFromAny(device["name"]),
					key,
				))
				appendDevice(name, firstNonEmpty(stringFromAny(device["status"]), stringFromAny(device["state"])))
			default:
				appendDevice(key, value)
			}
		}
	case []any:
		for _, item := range typed {
			switch device := item.(type) {
			case string:
				appendDevice(device, "")
			case map[string]any:
				name := strings.TrimSpace(firstNonEmpty(
					stringFromAny(device["device"]),
					stringFromAny(device["name"]),
				))
				appendDevice(name, firstNonEmpty(stringFromAny(device["status"]), stringFromAny(device["state"])))
			}
		}
	}
	return result
}

func resolveMoonrakerPrimaryLightDevice(devices []moonrakerPowerDevice) (string, string, bool) {
	if len(devices) == 0 {
		return "", "", false
	}
	priority := []string{"chamber_light", "caselight", "case_light", "work_light", "worklight", "light"}
	byName := make(map[string]moonrakerPowerDevice, len(devices))
	for _, device := range devices {
		normalizedName := strings.ToLower(strings.TrimSpace(device.Device))
		if normalizedName == "" {
			continue
		}
		byName[normalizedName] = device
	}
	for _, candidate := range priority {
		if device, ok := byName[candidate]; ok {
			return strings.TrimSpace(device.Device), strings.TrimSpace(device.Status), true
		}
	}

	matches := make([]moonrakerPowerDevice, 0)
	for _, device := range devices {
		normalizedName := strings.ToLower(strings.TrimSpace(device.Device))
		if strings.Contains(normalizedName, "light") || strings.Contains(normalizedName, "led") {
			matches = append(matches, device)
		}
	}
	if len(matches) == 1 {
		return strings.TrimSpace(matches[0].Device), strings.TrimSpace(matches[0].Status), true
	}
	return "", "", false
}

func normalizeMoonrakerPowerState(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "on", "true", "1":
		return "on"
	case "off", "false", "0":
		return "off"
	default:
		return ""
	}
}

func resolveMoonrakerPrimaryLEDObject(objects []string) (string, bool) {
	if len(objects) == 0 {
		return "", false
	}
	priority := []string{"led cavity_led", "led caselight", "led case_light", "led work_light", "led worklight", "led light"}
	byName := make(map[string]string, len(objects))
	for _, objectName := range objects {
		trimmed := strings.TrimSpace(objectName)
		normalized := strings.ToLower(trimmed)
		if !strings.HasPrefix(normalized, "led ") {
			continue
		}
		byName[normalized] = trimmed
	}
	for _, candidate := range priority {
		if objectName, ok := byName[candidate]; ok {
			return objectName, true
		}
	}

	matches := make([]string, 0)
	for normalized, objectName := range byName {
		if strings.Contains(normalized, "light") || strings.Contains(normalized, "led") {
			matches = append(matches, objectName)
		}
	}
	sort.Strings(matches)
	if len(matches) == 1 {
		return matches[0], true
	}
	return "", false
}

func moonrakerLEDObjectConfigName(objectName string) string {
	trimmed := strings.TrimSpace(objectName)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, " ") {
		return strings.TrimSpace(strings.SplitN(trimmed, " ", 2)[1])
	}
	return trimmed
}

func normalizeMoonrakerLEDColorState(raw any) string {
	switch typed := raw.(type) {
	case []any:
		hasSample := false
		for _, item := range typed {
			state := normalizeMoonrakerLEDColorState(item)
			switch state {
			case "on":
				return "on"
			case "off":
				hasSample = true
			}
		}
		if hasSample {
			return "off"
		}
	case []float64:
		if len(typed) == 0 {
			return ""
		}
		for _, value := range typed {
			if value > 0 {
				return "on"
			}
		}
		return "off"
	case float64:
		if typed > 0 {
			return "on"
		}
		return "off"
	case int:
		if typed > 0 {
			return "on"
		}
		return "off"
	}
	return ""
}

func normalizeFilamentState(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "loaded", "unloaded", "unknown":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func normalizeFilamentActionState(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case filamentActionStateIdle,
		filamentActionStateLoading,
		filamentActionStateUnloading,
		filamentActionStateNeedsUserConfirmation:
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func normalizeFilamentSourceKind(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case filamentSourceKindExternalSpool,
		filamentSourceKindAMS,
		filamentSourceKindNone,
		filamentSourceKindUnknown:
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func defaultFilamentSourceLabel(sourceKind string, rawLabel string) string {
	label := strings.TrimSpace(rawLabel)
	if label != "" {
		return label
	}
	switch normalizeFilamentSourceKind(sourceKind) {
	case filamentSourceKindExternalSpool:
		return "External spool"
	case filamentSourceKindAMS:
		return "AMS"
	default:
		return ""
	}
}

func (a *agent) fetchMoonrakerObjectList(ctx context.Context, endpointURL string) ([]string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/printer/objects/list"),
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("moonraker object list failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	result, _ := payload["result"]
	return parseMoonrakerObjectList(result), nil
}

func parseMoonrakerObjectList(raw any) []string {
	if typed, ok := raw.(map[string]any); ok {
		if nested, exists := typed["objects"]; exists {
			return parseMoonrakerObjectList(nested)
		}
	}
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	objects := make([]string, 0, len(items))
	for _, item := range items {
		name := strings.TrimSpace(fmt.Sprint(item))
		if name == "" {
			continue
		}
		objects = append(objects, name)
	}
	return objects
}

func moonrakerObjectListHasMacro(objects []string, macroName string) bool {
	want := strings.ToLower(strings.TrimSpace("gcode_macro " + macroName))
	for _, objectName := range objects {
		if strings.ToLower(strings.TrimSpace(objectName)) == want {
			return true
		}
	}
	return false
}

func moonrakerFilamentSensorObjects(objects []string) []string {
	out := make([]string, 0)
	for _, objectName := range objects {
		normalized := strings.ToLower(strings.TrimSpace(objectName))
		if strings.HasPrefix(normalized, "filament_switch_sensor ") || strings.HasPrefix(normalized, "filament_motion_sensor ") {
			out = append(out, strings.TrimSpace(objectName))
		}
	}
	sort.Strings(out)
	return out
}

func (a *agent) fetchMoonrakerLEDObjectState(ctx context.Context, endpointURL string, objectName string) (string, error) {
	trimmedObjectName := strings.TrimSpace(objectName)
	if trimmedObjectName == "" {
		return "", errors.New("validation_error: missing moonraker led object name")
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()
	queryPath := fmt.Sprintf(
		"/printer/objects/query?%s=color_data",
		url.QueryEscape(trimmedObjectName),
	)
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, queryPath),
		nil,
	)
	if err != nil {
		return "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("moonraker led object query failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var payload struct {
		Result struct {
			Status map[string]map[string]any `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	objectStatus := payload.Result.Status[trimmedObjectName]
	if len(objectStatus) == 0 {
		return "", fmt.Errorf("moonraker led object query returned no status for %s", trimmedObjectName)
	}
	state := normalizeMoonrakerLEDColorState(objectStatus["color_data"])
	if state == "" {
		return "", fmt.Errorf("moonraker led object %s reported unknown color_data", trimmedObjectName)
	}
	return state, nil
}

func (a *agent) fetchMoonrakerFilamentState(ctx context.Context, endpointURL string, sensorObjects []string) (string, error) {
	if len(sensorObjects) == 0 {
		return "", nil
	}
	detected := make([]bool, 0, len(sensorObjects))
	for _, objectName := range sensorObjects {
		state, ok, err := a.fetchMoonrakerFilamentSensorState(ctx, endpointURL, objectName)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		detected = append(detected, state)
	}
	if len(detected) == 0 {
		return "", nil
	}
	allTrue := true
	allFalse := true
	for _, state := range detected {
		if state {
			allFalse = false
		} else {
			allTrue = false
		}
	}
	switch {
	case allTrue:
		return "loaded", nil
	case allFalse:
		return "unloaded", nil
	default:
		return "unknown", nil
	}
}

func (a *agent) fetchMoonrakerFilamentSensorState(ctx context.Context, endpointURL, objectName string) (bool, bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/printer/objects/query?"+url.QueryEscape(objectName)),
		nil,
	)
	if err != nil {
		return false, false, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return false, false, fmt.Errorf("moonraker filament sensor query failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var payload struct {
		Result struct {
			Status map[string]map[string]any `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, false, err
	}
	sensorPayload, ok := payload.Result.Status[objectName]
	if !ok {
		return false, false, nil
	}
	rawDetected, exists := sensorPayload["filament_detected"]
	if !exists {
		return false, false, nil
	}
	switch typed := rawDetected.(type) {
	case bool:
		return typed, true, nil
	case string:
		normalized := strings.ToLower(strings.TrimSpace(typed))
		if normalized == "true" {
			return true, true, nil
		}
		if normalized == "false" {
			return false, true, nil
		}
	}
	return false, false, nil
}

func unsupportedBambuCommandCapabilities() map[string]any {
	return map[string]any{
		"led": map[string]any{"supported": false},
		"filament": map[string]any{
			"state":        "unknown",
			"action_state": filamentActionStateIdle,
			"state_source": filamentStateSourceUnknown,
			"confidence":   filamentConfidenceHeuristic,
			"source_kind":  filamentSourceKindUnknown,
		},
		"load_filament":   map[string]any{"supported": false},
		"unload_filament": map[string]any{"supported": false},
	}
}

func (a *agent) fallbackBambuCommandCapabilities(printerID string) map[string]any {
	snapshot, ok := a.lastBambuLANRuntimeSnapshot(printerID)
	if ok {
		if capabilities := cloneCommandCapabilities(snapshot.CommandCapabilities); capabilities != nil {
			return capabilities
		}
	}
	return unsupportedBambuCommandCapabilities()
}

func cloneCommandCapabilities(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func mergeCommandCapabilities(previous map[string]any, latest map[string]any) map[string]any {
	merged := cloneCommandCapabilities(latest)
	if merged == nil {
		merged = map[string]any{}
	}
	prev := cloneCommandCapabilities(previous)
	if prev == nil {
		return merged
	}

	prevFilament, _ := prev["filament"].(map[string]any)
	nextFilament, _ := merged["filament"].(map[string]any)
	if nextFilament == nil {
		nextFilament = map[string]any{}
	}
	if normalizeFilamentState(stringFromAny(nextFilament["state"])) == "" {
		if prevState := normalizeFilamentState(stringFromAny(prevFilament["state"])); prevState != "" {
			nextFilament["state"] = prevState
		}
	}
	if normalizeFilamentActionState(stringFromAny(nextFilament["action_state"])) == "" {
		if prevActionState := normalizeFilamentActionState(stringFromAny(prevFilament["action_state"])); prevActionState != "" {
			nextFilament["action_state"] = prevActionState
		}
	}
	if strings.TrimSpace(stringFromAny(nextFilament["state_source"])) == "" {
		if prevSource := strings.TrimSpace(stringFromAny(prevFilament["state_source"])); prevSource != "" {
			nextFilament["state_source"] = prevSource
		}
	}
	if strings.TrimSpace(stringFromAny(nextFilament["confidence"])) == "" {
		if prevConfidence := strings.TrimSpace(stringFromAny(prevFilament["confidence"])); prevConfidence != "" {
			nextFilament["confidence"] = prevConfidence
		}
	}
	if strings.TrimSpace(stringFromAny(nextFilament["action_started_at"])) == "" {
		if prevStartedAt := strings.TrimSpace(stringFromAny(prevFilament["action_started_at"])); prevStartedAt != "" {
			nextFilament["action_started_at"] = prevStartedAt
		}
	}
	if normalizeFilamentActionState(stringFromAny(nextFilament["action_state"])) == "" {
		nextFilament["action_state"] = filamentActionStateIdle
	}
	if len(nextFilament) > 0 {
		merged["filament"] = nextFilament
	}

	mergeSupportedCapabilityState(merged, prev, "led", true)
	mergeSupportedCapabilityState(merged, prev, "load_filament", false)
	mergeSupportedCapabilityState(merged, prev, "unload_filament", false)
	return merged
}

func mergeSupportedCapabilityState(merged map[string]any, previous map[string]any, key string, preserveState bool) {
	prevCapability, _ := previous[key].(map[string]any)
	if prevCapability == nil || !capabilitySupported(prevCapability) {
		return
	}

	nextCapability, _ := merged[key].(map[string]any)
	if nextCapability == nil {
		nextCapability = map[string]any{}
	}
	if capabilitySupported(nextCapability) {
		if preserveState && strings.TrimSpace(stringFromAny(nextCapability["state"])) == "" {
			if previousState := strings.TrimSpace(stringFromAny(prevCapability["state"])); previousState != "" {
				nextCapability["state"] = previousState
			}
		}
		merged[key] = nextCapability
		return
	}

	nextCapability["supported"] = true
	if preserveState {
		if previousState := strings.TrimSpace(stringFromAny(prevCapability["state"])); previousState != "" {
			nextCapability["state"] = previousState
		}
	}
	merged[key] = nextCapability
}

func capabilitySupported(capability map[string]any) bool {
	if capability == nil {
		return false
	}
	switch typed := capability["supported"].(type) {
	case bool:
		return typed
	case string:
		normalized := strings.TrimSpace(strings.ToLower(typed))
		return normalized == "true"
	default:
		return false
	}
}

func ensurePrinterSupportCapability(binding edgeBinding, snapshot bindingSnapshot, capabilities map[string]any) map[string]any {
	if capabilities == nil {
		capabilities = map[string]any{}
	}
	profile := printeradapter.ResolveProfile(
		printeradapter.Binding{
			PrinterID:     binding.PrinterID,
			AdapterFamily: binding.AdapterFamily,
			EndpointURL:   binding.EndpointURL,
		},
		printeradapter.RuntimeSnapshot{
			PrinterState:      snapshot.PrinterState,
			JobState:          snapshot.JobState,
			ProgressPct:       snapshot.ProgressPct,
			RemainingSeconds:  snapshot.RemainingSeconds,
			TelemetrySource:   snapshot.TelemetrySource,
			DetectedName:      snapshot.DetectedName,
			DetectedModelHint: snapshot.DetectedModelHint,
		},
	)
	panels := make([]string, 0, len(profile.SupportedPanels))
	for _, panel := range profile.SupportedPanels {
		panels = append(panels, string(panel))
	}
	capabilities["printer_support"] = map[string]any{
		"profile_key":        profile.Key,
		"profile_family":     profile.Family,
		"display_name":       profile.DisplayName,
		"support_tier":       string(profile.SupportTier),
		"panels":             panels,
		"unsupported_reason": strings.TrimSpace(profile.UnsupportedReason),
		"documentation_slug": strings.TrimSpace(profile.DocumentationSlug),
	}
	return capabilities
}

func filamentCapability(capabilities map[string]any) map[string]any {
	if capabilities == nil {
		return map[string]any{}
	}
	filament, _ := capabilities["filament"].(map[string]any)
	if filament == nil {
		filament = map[string]any{}
		capabilities["filament"] = filament
	}
	return filament
}

func filamentCapabilitySourceKind(capabilities map[string]any) string {
	filament := filamentCapability(capabilities)
	return normalizeFilamentSourceKind(stringFromAny(filament["source_kind"]))
}

func filamentCapabilitySourceLabel(capabilities map[string]any) string {
	filament := filamentCapability(capabilities)
	return defaultFilamentSourceLabel(
		normalizeFilamentSourceKind(stringFromAny(filament["source_kind"])),
		stringFromAny(filament["source_label"]),
	)
}

func setFilamentCapabilityState(
	capabilities map[string]any,
	state string,
	actionState string,
	stateSource string,
	confidence string,
	startedAt time.Time,
) {
	filament := filamentCapability(capabilities)
	if normalizedState := normalizeFilamentState(state); normalizedState != "" {
		filament["state"] = normalizedState
	}
	if normalizedActionState := normalizeFilamentActionState(actionState); normalizedActionState != "" {
		filament["action_state"] = normalizedActionState
	}
	if strings.TrimSpace(stateSource) != "" {
		filament["state_source"] = strings.TrimSpace(stateSource)
	}
	if strings.TrimSpace(confidence) != "" {
		filament["confidence"] = strings.TrimSpace(confidence)
	}
	if startedAt.IsZero() {
		delete(filament, "action_started_at")
	} else {
		filament["action_started_at"] = startedAt.UTC().Format(time.RFC3339Nano)
	}
	capabilities["filament"] = filament
}

func setFilamentCapabilitySource(capabilities map[string]any, sourceKind string, sourceLabel string) {
	filament := filamentCapability(capabilities)
	normalizedKind := normalizeFilamentSourceKind(sourceKind)
	if normalizedKind == "" {
		delete(filament, "source_kind")
		delete(filament, "source_label")
		capabilities["filament"] = filament
		return
	}
	filament["source_kind"] = normalizedKind
	normalizedLabel := defaultFilamentSourceLabel(normalizedKind, sourceLabel)
	if normalizedLabel == "" {
		delete(filament, "source_label")
	} else {
		filament["source_label"] = normalizedLabel
	}
	capabilities["filament"] = filament
}

func filamentCapabilityActionStartedAt(capabilities map[string]any) time.Time {
	filament := filamentCapability(capabilities)
	raw := strings.TrimSpace(stringFromAny(filament["action_started_at"]))
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func resolveRuntimeFilamentCapability(binding edgeBinding, current *currentStateItem, previous currentStateItem, snapshot bindingSnapshot, now time.Time) {
	if current == nil {
		return
	}
	if current.CommandCapabilities == nil {
		current.CommandCapabilities = map[string]any{}
	}
	filament := filamentCapability(current.CommandCapabilities)
	state := normalizeFilamentState(stringFromAny(filament["state"]))
	if state == "" {
		state = "unknown"
	}
	actionState := normalizeFilamentActionState(stringFromAny(filament["action_state"]))
	if actionState == "" {
		actionState = filamentActionStateIdle
	}
	stateSource := firstNonEmpty(strings.TrimSpace(stringFromAny(filament["state_source"])), filamentStateSourceUnknown)
	confidence := firstNonEmpty(strings.TrimSpace(stringFromAny(filament["confidence"])), filamentConfidenceHeuristic)
	startedAt := filamentCapabilityActionStartedAt(current.CommandCapabilities)
	sourceKind := firstNonEmpty(filamentCapabilitySourceKind(current.CommandCapabilities), filamentSourceKindUnknown)
	sourceLabel := filamentCapabilitySourceLabel(current.CommandCapabilities)
	previousCapabilities := cloneCommandCapabilities(previous.CommandCapabilities)
	prevState := normalizeFilamentState(stringFromAny(filamentCapability(previousCapabilities)["state"]))
	prevStateSource := firstNonEmpty(strings.TrimSpace(stringFromAny(filamentCapability(previousCapabilities)["state_source"])), filamentStateSourceUnknown)
	prevSourceKind := normalizeFilamentSourceKind(stringFromAny(filamentCapability(previousCapabilities)["source_kind"]))
	prevSourceLabel := filamentCapabilitySourceLabel(previousCapabilities)
	prevActionState := normalizeFilamentActionState(stringFromAny(filamentCapability(previousCapabilities)["action_state"]))
	prevStartedAt := filamentCapabilityActionStartedAt(previousCapabilities)

	if (actionState == filamentActionStateLoading || actionState == filamentActionStateUnloading) && startedAt.IsZero() {
		if prevActionState == actionState && !prevStartedAt.IsZero() {
			startedAt = prevStartedAt
		} else {
			startedAt = now
		}
	}

	setCurrent := func(nextState, nextActionState, nextStateSource, nextConfidence, nextSourceKind, nextSourceLabel string, nextStartedAt time.Time) {
		setFilamentCapabilityState(
			current.CommandCapabilities,
			nextState,
			nextActionState,
			nextStateSource,
			nextConfidence,
			nextStartedAt,
		)
		setFilamentCapabilitySource(current.CommandCapabilities, nextSourceKind, nextSourceLabel)
	}

	rememberedSourceKind := sourceKind
	rememberedSourceLabel := sourceLabel
	if rememberedSourceKind == filamentSourceKindUnknown || rememberedSourceKind == filamentSourceKindNone {
		if prevSourceKind == filamentSourceKindExternalSpool || prevSourceKind == filamentSourceKindAMS {
			rememberedSourceKind = prevSourceKind
			rememberedSourceLabel = prevSourceLabel
		}
	}

	switch normalizeAdapterFamily(binding.AdapterFamily) {
	case "moonraker":
		if sensorPresent, ok := filament["sensor_present"].(bool); !ok || !sensorPresent {
			setCurrent(
				"unknown",
				filamentActionStateIdle,
				filamentStateSourceUnknown,
				filamentConfidenceHeuristic,
				filamentSourceKindUnknown,
				"",
				time.Time{},
			)
			return
		}

		switch actionState {
		case filamentActionStateLoading:
			if state == "loaded" {
				setCurrent(state, filamentActionStateIdle, filamentStateSourceMoonrakerSensor, filamentConfidenceConfirmed, filamentSourceKindUnknown, "", time.Time{})
				return
			}
			if !startedAt.IsZero() && now.Sub(startedAt) > moonrakerFilamentActionTimeout {
				setCurrent("unknown", filamentActionStateIdle, filamentStateSourceUnknown, filamentConfidenceHeuristic, filamentSourceKindUnknown, "", time.Time{})
				return
			}
		case filamentActionStateUnloading:
			if state == "unloaded" {
				setCurrent(state, filamentActionStateIdle, filamentStateSourceMoonrakerSensor, filamentConfidenceConfirmed, filamentSourceKindUnknown, "", time.Time{})
				return
			}
			if !startedAt.IsZero() && now.Sub(startedAt) > moonrakerFilamentActionTimeout {
				setCurrent("unknown", filamentActionStateIdle, filamentStateSourceUnknown, filamentConfidenceHeuristic, filamentSourceKindUnknown, "", time.Time{})
				return
			}
		default:
			setCurrent(state, filamentActionStateIdle, filamentStateSourceMoonrakerSensor, filamentConfidenceConfirmed, filamentSourceKindUnknown, "", time.Time{})
			return
		}
		setCurrent(state, actionState, stateSource, confidence, filamentSourceKindUnknown, "", startedAt)
	case "bambu":
		switch actionState {
		case filamentActionStateLoading:
			if sourceKind == filamentSourceKindExternalSpool || sourceKind == filamentSourceKindAMS {
				setCurrent("loaded", filamentActionStateIdle, filamentStateSourceBambuActiveSource, filamentConfidenceConfirmed, sourceKind, sourceLabel, time.Time{})
				return
			}
			if !startedAt.IsZero() && now.Sub(startedAt) > bambuFilamentActionTimeout {
				setCurrent("unknown", filamentActionStateNeedsUserConfirmation, filamentStateSourceBambuCommandMemory, filamentConfidenceHeuristic, rememberedSourceKind, rememberedSourceLabel, time.Time{})
				return
			}
			setCurrent("unknown", filamentActionStateLoading, filamentStateSourceCommandFallback, filamentConfidenceHeuristic, rememberedSourceKind, rememberedSourceLabel, startedAt)
			return
		case filamentActionStateUnloading:
			if sourceKind == filamentSourceKindNone {
				setCurrent("unloaded", filamentActionStateIdle, filamentStateSourceBambuCommandMemory, filamentConfidenceHeuristic, rememberedSourceKind, rememberedSourceLabel, time.Time{})
				return
			}
			if !startedAt.IsZero() && now.Sub(startedAt) > bambuFilamentActionTimeout {
				setCurrent("unknown", filamentActionStateNeedsUserConfirmation, filamentStateSourceBambuCommandMemory, filamentConfidenceHeuristic, rememberedSourceKind, rememberedSourceLabel, time.Time{})
				return
			}
			setCurrent("unknown", filamentActionStateUnloading, filamentStateSourceCommandFallback, filamentConfidenceHeuristic, rememberedSourceKind, rememberedSourceLabel, startedAt)
			return
		case filamentActionStateNeedsUserConfirmation:
			if sourceKind == filamentSourceKindExternalSpool || sourceKind == filamentSourceKindAMS {
				setCurrent("loaded", filamentActionStateIdle, filamentStateSourceBambuActiveSource, filamentConfidenceConfirmed, sourceKind, sourceLabel, time.Time{})
				return
			}
			if sourceKind == filamentSourceKindNone && (rememberedSourceKind == filamentSourceKindExternalSpool || rememberedSourceKind == filamentSourceKindAMS) {
				setCurrent("unloaded", filamentActionStateIdle, filamentStateSourceBambuCommandMemory, filamentConfidenceHeuristic, rememberedSourceKind, rememberedSourceLabel, time.Time{})
				return
			}
			setCurrent("unknown", filamentActionStateNeedsUserConfirmation, filamentStateSourceBambuCommandMemory, filamentConfidenceHeuristic, rememberedSourceKind, rememberedSourceLabel, time.Time{})
			return
		default:
			if sourceKind == filamentSourceKindExternalSpool || sourceKind == filamentSourceKindAMS {
				setCurrent("loaded", filamentActionStateIdle, filamentStateSourceBambuActiveSource, filamentConfidenceConfirmed, sourceKind, sourceLabel, time.Time{})
				return
			}
			if sourceKind == filamentSourceKindNone {
				setCurrent("unloaded", filamentActionStateIdle, filamentStateSourceBambuActiveSource, filamentConfidenceConfirmed, filamentSourceKindNone, "", time.Time{})
				return
			}
			if now.Sub(previous.ReportedAt) <= bambuFilamentMemoryGrace &&
				(prevState == "loaded" || prevState == "unloaded") &&
				(prevStateSource == filamentStateSourceBambuCommandMemory || prevStateSource == filamentStateSourceBambuActiveSource) {
				setCurrent(prevState, filamentActionStateIdle, filamentStateSourceBambuCommandMemory, filamentConfidenceHeuristic, prevSourceKind, prevSourceLabel, time.Time{})
				return
			}
			setCurrent("unknown", filamentActionStateIdle, stateSource, confidence, sourceKind, sourceLabel, time.Time{})
			return
		}
	default:
		setCurrent(state, actionState, stateSource, confidence, sourceKind, sourceLabel, startedAt)
	}
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func (a *agent) probeMoonrakerArtifactReuse(ctx context.Context, endpointURL string, artifact stagedArtifact) (bool, string, error) {
	remoteName := artifact.moonrakerRemoteName()
	sizeBytes, exists, err := a.fetchMoonrakerRemoteFileSize(ctx, endpointURL, remoteName)
	if err != nil {
		return false, "metadata_probe_error", err
	}
	if !exists {
		return false, "absent", nil
	}
	if sizeBytes != artifact.SizeBytes {
		return false, "size_mismatch", nil
	}
	remoteSHA256, err := a.fetchMoonrakerRemoteFileSHA256(ctx, endpointURL, remoteName)
	if err != nil {
		return false, "hash_probe_error", err
	}
	if !strings.EqualFold(strings.TrimSpace(remoteSHA256), strings.TrimSpace(artifact.SHA256)) {
		return false, "sha256_mismatch", nil
	}
	return true, "sha256_match", nil
}

func (a *agent) fetchMoonrakerRemoteFileSize(ctx context.Context, endpointURL, filename string) (int64, bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/server/files/metadata?filename="+url.QueryEscape(filename)),
		nil,
	)
	if err != nil {
		return 0, false, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, false, fmt.Errorf("moonraker file metadata failed: status=%d body=%s", resp.StatusCode, string(responseBody))
	}

	var payload struct {
		Result struct {
			Size json.Number `json:"size"`
		} `json:"result"`
	}
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return 0, false, err
	}
	if strings.TrimSpace(payload.Result.Size.String()) == "" {
		return 0, true, errors.New("moonraker metadata missing size")
	}
	sizeBytes, err := payload.Result.Size.Int64()
	if err != nil {
		floatValue, floatErr := payload.Result.Size.Float64()
		if floatErr != nil {
			return 0, true, fmt.Errorf("moonraker metadata invalid size %q: %w", payload.Result.Size.String(), err)
		}
		sizeBytes = int64(floatValue)
	}
	return sizeBytes, true, nil
}

func (a *agent) fetchMoonrakerRemoteFileSHA256(ctx context.Context, endpointURL, filename string) (string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/server/files/gcodes/"+url.PathEscape(filename)),
		nil,
	)
	if err != nil {
		return "", err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("moonraker file download failed: status=%d body=%s", resp.StatusCode, string(responseBody))
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (a *agent) uploadArtifact(ctx context.Context, endpointURL string, artifact stagedArtifact) error {
	f, err := os.Open(artifact.LocalPath)
	if err != nil {
		return err
	}
	defer f.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if err := writer.WriteField("root", "gcodes"); err != nil {
		return err
	}
	if checksum := strings.TrimSpace(artifact.SHA256); checksum != "" {
		if err := writer.WriteField("checksum", checksum); err != nil {
			return err
		}
	}
	part, err := writer.CreateFormFile("file", artifact.moonrakerRemoteName())
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

func (a *agent) downloadArtifact(ctx context.Context, desired desiredStateItem) (stagedArtifact, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.ArtifactDownloadTimeout)
	defer cancel()

	artifactURL := strings.TrimSpace(desired.ArtifactURL)
	if artifactURL == "" {
		return stagedArtifact{}, errors.New("artifact_fetch_error: missing artifact_url")
	}
	bootstrap := a.snapshotBootstrap()
	if strings.HasPrefix(artifactURL, "/") {
		artifactURL = strings.TrimSuffix(bootstrap.ControlPlaneURL, "/") + artifactURL
	}
	if err := os.MkdirAll(a.cfg.ArtifactStageDir, 0o755); err != nil {
		return stagedArtifact{}, err
	}
	ok, err := hasMinFreeSpace(a.cfg.ArtifactStageDir, 1<<30)
	if err != nil {
		return stagedArtifact{}, err
	}
	if !ok {
		return stagedArtifact{}, errors.New("artifact_fetch_error: insufficient free staging disk space")
	}

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return stagedArtifact{}, err
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
		return stagedArtifact{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return stagedArtifact{}, fmt.Errorf("artifact_fetch_error: download failed status=%d body=%s", resp.StatusCode, string(body))
	}

	sourceFilename := resolvePlateArtifactSourceFilename(artifactURL, resp.Header.Get("Content-Disposition"))
	artifactExtension := resolvePlateArtifactExtension(artifactURL, resp.Header.Get("Content-Disposition"))
	baseName := fmt.Sprintf("printer_%d_plate_%d_%d%s", desired.PrinterID, desired.PlateID, time.Now().UnixNano(), artifactExtension)
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

	out, err := os.Create(partPath)
	if err != nil {
		return stagedArtifact{}, err
	}

	shaHasher := sha256.New()
	md5Hasher := md5.New()
	sizeBytes, err := io.Copy(io.MultiWriter(out, shaHasher, md5Hasher), resp.Body)
	if err != nil {
		_ = out.Close()
		return stagedArtifact{}, err
	}
	sum := hex.EncodeToString(shaHasher.Sum(nil))
	expectedChecksum := strings.TrimSpace(desired.ChecksumSHA256)
	if expectedChecksum != "" {
		if !strings.EqualFold(sum, expectedChecksum) {
			_ = out.Close()
			return stagedArtifact{}, fmt.Errorf("artifact_fetch_error: checksum mismatch expected=%s actual=%s", desired.ChecksumSHA256, sum)
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
		return stagedArtifact{}, err
	}
	if err := os.Rename(partPath, readyPath); err != nil {
		return stagedArtifact{}, err
	}
	cleanupPart = false
	return stagedArtifact{
		LocalPath:           readyPath,
		SourceFilename:      sourceFilename,
		NormalizedExtension: artifactExtension,
		SizeBytes:           sizeBytes,
		SHA256:              sum,
		MD5:                 hex.EncodeToString(md5Hasher.Sum(nil)),
		RemoteName:          buildCanonicalArtifactRemoteName(sum, artifactExtension),
	}, nil
}

func buildCanonicalArtifactRemoteName(checksumSHA256, normalizedExtension string) string {
	trimmedChecksum := strings.ToLower(strings.TrimSpace(checksumSHA256))
	trimmedExtension := normalizePlateArtifactExtension(normalizedExtension)
	if trimmedExtension == "" {
		trimmedExtension = ".gcode"
	}
	return "pfh-" + trimmedChecksum + trimmedExtension
}

func resolvePlateArtifactSourceFilename(artifactURL, contentDisposition string) string {
	if fromContentDisposition := extractFilenameFromContentDisposition(contentDisposition); fromContentDisposition != "" {
		return fromContentDisposition
	}
	parsedURL, err := url.Parse(strings.TrimSpace(artifactURL))
	if err != nil {
		return ""
	}
	for _, key := range []string{"filename", "file", "name"} {
		if queryValue := strings.TrimSpace(parsedURL.Query().Get(key)); queryValue != "" {
			return queryValue
		}
	}
	base := strings.TrimSpace(path.Base(parsedURL.Path))
	if base == "" || base == "." || base == "/" {
		return ""
	}
	if normalizePlateArtifactExtension(base) == "" {
		return ""
	}
	return base
}

func resolvePlateArtifactExtension(artifactURL, contentDisposition string) string {
	if sourceFilename := resolvePlateArtifactSourceFilename(artifactURL, contentDisposition); sourceFilename != "" {
		if normalized := normalizePlateArtifactExtension(sourceFilename); normalized != "" {
			return normalized
		}
	}
	parsedURL, err := url.Parse(strings.TrimSpace(artifactURL))
	if err == nil {
		if normalized := normalizePlateArtifactExtension(parsedURL.Path); normalized != "" {
			return normalized
		}
		for _, key := range []string{"filename", "file", "name"} {
			if queryValue := strings.TrimSpace(parsedURL.Query().Get(key)); queryValue != "" {
				if normalized := normalizePlateArtifactExtension(queryValue); normalized != "" {
					return normalized
				}
			}
		}
	} else {
		if normalized := normalizePlateArtifactExtension(artifactURL); normalized != "" {
			return normalized
		}
	}
	return ".gcode"
}

func extractFilenameFromContentDisposition(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(trimmed)
	if err != nil {
		return ""
	}
	if filename := strings.TrimSpace(params["filename"]); filename != "" {
		return filename
	}
	filenameStar := strings.TrimSpace(params["filename*"])
	if filenameStar == "" {
		return ""
	}
	if parts := strings.SplitN(filenameStar, "''", 2); len(parts) == 2 {
		decoded, decodeErr := url.QueryUnescape(parts[1])
		if decodeErr == nil && strings.TrimSpace(decoded) != "" {
			return strings.TrimSpace(decoded)
		}
		return strings.TrimSpace(parts[1])
	}
	return filenameStar
}

func normalizePlateArtifactExtension(rawExtension string) string {
	trimmed := strings.ToLower(strings.TrimSpace(rawExtension))
	if trimmed == "" {
		return ""
	}
	if strings.HasSuffix(trimmed, ".gcode.3mf") {
		return ".gcode.3mf"
	}
	if strings.Contains(trimmed, "/") || strings.Contains(trimmed, "\\") {
		trimmed = filepath.Ext(trimmed)
	} else if strings.Contains(trimmed, ".") && !strings.HasPrefix(trimmed, ".") {
		trimmed = filepath.Ext(trimmed)
	}
	if !strings.HasPrefix(trimmed, ".") {
		trimmed = "." + trimmed
	}
	switch trimmed {
	case ".gcode", ".gco", ".gc", ".ngc", ".3mf":
		return trimmed
	default:
		return ""
	}
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
	if isPrinterRuntimeCommandKind(queuedAction.Kind) {
		current.LastErrorCode = ""
		current.LastErrorMessage = ""
		current.ReportedAt = now
		if current.CommandCapabilities == nil {
			current.CommandCapabilities = map[string]any{}
		}
		binding := a.bindings[queuedAction.PrinterID]
		sourceKind := filamentCapabilitySourceKind(current.CommandCapabilities)
		sourceLabel := filamentCapabilitySourceLabel(current.CommandCapabilities)
		switch queuedAction.Kind {
		case "light_on":
			current.CommandCapabilities["led"] = map[string]any{"supported": true, "state": "on"}
		case "light_off":
			current.CommandCapabilities["led"] = map[string]any{"supported": true, "state": "off"}
		case "load_filament":
			if normalizeAdapterFamily(binding.AdapterFamily) == "bambu" && (sourceKind == "" || sourceKind == filamentSourceKindUnknown || sourceKind == filamentSourceKindNone) {
				sourceKind = filamentSourceKindExternalSpool
				sourceLabel = defaultFilamentSourceLabel(sourceKind, sourceLabel)
			}
			setFilamentCapabilityState(
				current.CommandCapabilities,
				"unknown",
				filamentActionStateLoading,
				filamentStateSourceCommandFallback,
				filamentConfidenceHeuristic,
				now,
			)
			setFilamentCapabilitySource(current.CommandCapabilities, sourceKind, sourceLabel)
		case "unload_filament":
			if normalizeAdapterFamily(binding.AdapterFamily) == "bambu" && (sourceKind == "" || sourceKind == filamentSourceKindUnknown || sourceKind == filamentSourceKindNone) {
				sourceKind = filamentSourceKindExternalSpool
				sourceLabel = defaultFilamentSourceLabel(sourceKind, sourceLabel)
			}
			setFilamentCapabilityState(
				current.CommandCapabilities,
				"unknown",
				filamentActionStateUnloading,
				filamentStateSourceCommandFallback,
				filamentConfidenceHeuristic,
				now,
			)
			setFilamentCapabilitySource(current.CommandCapabilities, sourceKind, sourceLabel)
		}
		a.currentState[queuedAction.PrinterID] = current
		delete(a.breakerUntil, queuedAction.PrinterID)
		a.audit("action_executed", map[string]any{
			"printer_id":         queuedAction.PrinterID,
			"kind":               queuedAction.Kind,
			"command_request_id": queuedAction.CommandRequestID,
		})
		return
	}
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

func (a *agent) markPrintStartInProgress(queuedAction action) {
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	current := a.currentState[queuedAction.PrinterID]
	current.PrinterID = queuedAction.PrinterID
	current.CurrentPrinterState = "queued"
	current.CurrentJobState = "pending"
	current.JobID = queuedAction.Target.JobID
	current.PlateID = queuedAction.Target.PlateID
	current.IntentVersionApplied = queuedAction.Target.IntentVersion
	current.IsPaused = false
	current.IsCanceled = false
	current.LastErrorCode = ""
	current.LastErrorMessage = ""
	current.ManualIntervention = ""
	current.ReportedAt = now
	a.currentState[queuedAction.PrinterID] = current
	if _, exists := a.queuedSince[queuedAction.PrinterID]; !exists {
		a.queuedSince[queuedAction.PrinterID] = now
	}

	a.audit("print_start_in_progress", map[string]any{
		"printer_id":     queuedAction.PrinterID,
		"intent_version": queuedAction.Target.IntentVersion,
		"job_id":         queuedAction.Target.JobID,
		"plate_id":       queuedAction.Target.PlateID,
		"reported_state": "queued",
	})
}

func (a *agent) markActionFailure(queuedAction action, errorCode, message string) {
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()

	current := a.currentState[queuedAction.PrinterID]
	current.PrinterID = queuedAction.PrinterID
	if isPrinterRuntimeCommandKind(queuedAction.Kind) {
		current.LastErrorCode = errorCode
		current.LastErrorMessage = message
		if current.CommandCapabilities == nil {
			current.CommandCapabilities = map[string]any{}
		}
		if queuedAction.Kind == "load_filament" || queuedAction.Kind == "unload_filament" {
			setFilamentCapabilityState(
				current.CommandCapabilities,
				"unknown",
				filamentActionStateIdle,
				filamentStateSourceUnknown,
				filamentConfidenceHeuristic,
				time.Time{},
			)
		}
		current.ReportedAt = now
		a.currentState[queuedAction.PrinterID] = current
		a.audit("action_failed", map[string]any{
			"printer_id":         queuedAction.PrinterID,
			"kind":               queuedAction.Kind,
			"command_request_id": queuedAction.CommandRequestID,
			"error_code":         errorCode,
			"error_message":      message,
		})
		return
	}
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

func summarizeBambuCloudStartDispatchError(err error) map[string]any {
	message := strings.TrimSpace(err.Error())
	out := map[string]any{
		"error_message": message,
	}
	if message == "" {
		return out
	}

	if match := cloudStartVariantPattern.FindStringSubmatch(strings.ToLower(message)); len(match) == 2 {
		out["dispatch_variant"] = "task_variant_" + strings.TrimSpace(match[1])
	}
	if match := cloudStartMethodEndpointPattern.FindStringSubmatch(message); len(match) == 3 {
		out["http_method"] = strings.ToUpper(strings.TrimSpace(match[1]))
		out["endpoint"] = strings.TrimSpace(match[2])
	}
	if match := cloudStartStatusPattern.FindStringSubmatch(strings.ToLower(message)); len(match) == 2 {
		if statusCode, convErr := strconv.Atoi(strings.TrimSpace(match[1])); convErr == nil {
			out["http_status"] = statusCode
		}
	}
	if idx := strings.Index(strings.ToLower(message), "allow="); idx >= 0 {
		allowPart := message[idx+len("allow="):]
		allowPart = strings.TrimSpace(allowPart)
		if splitIdx := strings.Index(strings.ToLower(allowPart), " body="); splitIdx >= 0 {
			allowPart = strings.TrimSpace(allowPart[:splitIdx])
		}
		if allowPart != "" {
			out["allow"] = allowPart
		}
	}
	if idx := strings.Index(strings.ToLower(message), "body="); idx >= 0 {
		bodyPart := strings.TrimSpace(message[idx+len("body="):])
		out["response_body_present"] = bodyPart != ""
	}
	return out
}

func classifyActionError(err error) (code string, retryable bool) {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "bambu_connect_unavailable"):
		return "bambu_connect_unavailable", false
	case strings.Contains(msg, "bambu_connect_dispatch_failed"):
		return "bambu_connect_dispatch_failed", false
	case strings.Contains(msg, "bambu_lan_upload_failed"):
		if strings.Contains(msg, "connection error") || strings.Contains(msg, "timeout") {
			return "connectivity_error", true
		}
		return "bambu_lan_upload_failed", false
	case strings.Contains(msg, "bambu_lan_credentials_missing_local"),
		strings.Contains(msg, "bambu_lan_credentials_store_unavailable"):
		return "auth_error", false
	case errors.Is(err, bambucloud.ErrPrintStartUnsupported), strings.Contains(msg, "bambu_start_rejected"):
		return "bambu_start_rejected", false
	case errors.Is(err, bambuauth.ErrInvalidCredentials),
		strings.Contains(msg, "rejected access token"),
		strings.Contains(msg, "invalid credentials"),
		strings.Contains(msg, "auth rejected"),
		strings.Contains(msg, "bambu ftps auth rejected"),
		strings.Contains(msg, "bambu mqtt broker rejected connection return_code=5"):
		return "auth_error", false
	case strings.Contains(msg, "bambu_start_metadata_unresolved"):
		return "bambu_start_metadata_unresolved", false
	case strings.Contains(msg, "bambu_start_manual_handoff_required"):
		return "bambu_start_manual_handoff_required", false
	case strings.Contains(msg, "bambu_start_verification_timeout"), strings.Contains(msg, "print start verification timeout"):
		return "bambu_start_verification_timeout", false
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

	a.mu.Lock()
	states := make([]currentStateItem, 0, len(a.currentState))
	keys := make([]int, 0, len(a.currentState))
	for printerID := range a.currentState {
		if _, exists := a.bindings[printerID]; !exists {
			delete(a.currentState, printerID)
			delete(a.queuedSince, printerID)
			delete(a.breakerUntil, printerID)
			continue
		}
		keys = append(keys, printerID)
	}
	sort.Ints(keys)
	for _, printerID := range keys {
		s := a.currentState[printerID]
		s.ReportedAt = time.Now().UTC()
		states = append(states, s)
	}
	a.mu.Unlock()

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

func (a *agent) controlStatusPushLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	interval := a.cfg.BambuControlStatusPushInterval
	if interval <= 0 {
		interval = time.Second
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
			if err := a.pushPrinterControlStatusOnce(ctx); err != nil {
				a.audit("control_status_push_error", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (a *agent) pushPrinterControlStatusOnce(ctx context.Context) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}

	type bindingState struct {
		printerID int
		binding   edgeBinding
	}

	a.mu.RLock()
	bindings := make([]bindingState, 0, len(a.bindings))
	for printerID, binding := range a.bindings {
		adapterFamily := normalizeAdapterFamily(binding.AdapterFamily)
		if adapterFamily != "bambu" && adapterFamily != "moonraker" {
			continue
		}
		bindings = append(bindings, bindingState{printerID: printerID, binding: binding})
	}
	a.mu.RUnlock()

	if len(bindings) == 0 {
		return nil
	}

	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].printerID < bindings[j].printerID
	})

	items := make([]printerControlStatusItem, 0, len(bindings))
	for _, item := range bindings {
		adapterFamily := normalizeAdapterFamily(item.binding.AdapterFamily)
		var controlStatus *printerControlStatusSnapshot
		switch adapterFamily {
		case "bambu":
			printerID, err := parseBambuPrinterEndpointID(item.binding.EndpointURL)
			if err != nil {
				a.audit("bambu_control_status_printer_id_error", map[string]any{
					"printer_id":   item.printerID,
					"endpoint_url": item.binding.EndpointURL,
					"error":        err.Error(),
				})
				continue
			}
			snapshot, err := a.fetchBambuLANRuntimeSnapshotByPrinterID(ctx, printerID)
			if err != nil {
				if a.shouldSuppressBambuRuntimeConnectivityFailure(item.printerID, err) {
					if previousSnapshot, ok := a.lastBambuLANRuntimeSnapshot(printerID); ok && previousSnapshot.ControlStatus != nil {
						controlStatus = previousSnapshot.ControlStatus
						break
					}
					continue
				}
				a.audit("bambu_control_status_snapshot_error", map[string]any{
					"printer_id":   item.printerID,
					"endpoint_url": item.binding.EndpointURL,
					"error":        err.Error(),
				})
				continue
			}
			if snapshot.ControlStatus == nil {
				continue
			}
			controlStatus = snapshot.ControlStatus
		case "moonraker":
			snapshot, err := a.fetchMoonrakerControlStatus(ctx, item.binding.EndpointURL)
			if err != nil {
				a.audit("moonraker_control_status_snapshot_error", map[string]any{
					"printer_id":   item.printerID,
					"endpoint_url": item.binding.EndpointURL,
					"error":        err.Error(),
				})
				continue
			}
			controlStatus = &snapshot
		default:
			continue
		}
		if controlStatus == nil {
			continue
		}
		items = append(items, printerControlStatusItem{
			PrinterID:     item.printerID,
			AdapterFamily: adapterFamily,
			Status:        *controlStatus,
			ReportedAt:    time.Now().UTC(),
		})
	}

	if len(items) == 0 {
		return nil
	}

	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/control-status",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)

	reqPayload := pushPrinterControlStatusRequest{Items: items}
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
	req.Header.Set("X-Agent-Schema-Version", schemaVersionHeaderValue())

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			a.handleControlPlaneAuthFailure("control_status_push", resp.StatusCode, string(body))
			return fmt.Errorf("%w: control status push returned %d: %s", errEdgeAuthRevoked, resp.StatusCode, string(body))
		}
		return fmt.Errorf("control status push returned %d: %s", resp.StatusCode, string(body))
	}
	a.audit("control_status_pushed", map[string]any{"count": len(items), "status_code": resp.StatusCode})
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
	scanSource := scanSourceForMode(scanMode)
	a.localObservations.markScanStarted(scanSource, startedAt)
	var runErr error
	defer func() {
		a.localObservations.markScanFinished(scanSource, time.Now().UTC(), runErr)
	}()

	emitManualScanEvent("started", startedAt, "")
	completed := a.executeDiscoveryScanLocked(ctx, scanMode, manualTriggerToken, startedAt)
	a.localObservations.upsertDiscoveryCandidates(completed.Result.Candidates, completed.Result.FinishedAt)
	scanID := randomKey("scan")
	payload := discoveryInventoryReportRequest{
		ScanID:       scanID,
		ScanMode:     scanMode,
		TriggerToken: manualTriggerToken,
		StartedAt:    completed.Result.StartedAt,
		FinishedAt:   completed.Result.FinishedAt,
		Summary: discoveryInventorySummary{
			HostsScanned:   completed.Result.Summary.HostsScanned,
			HostsReachable: completed.Result.Summary.HostsReachable,
			EntriesCount:   len(completed.Entries),
			ErrorsCount:    completed.Result.Summary.ErrorsCount,
		},
		Entries: completed.Entries,
	}
	if err := a.submitDiscoveryInventory(ctx, bootstrap, payload); err != nil {
		runErr = err
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
		"entries":       len(completed.Entries),
	})
	a.audit("discovery_inventory_submitted", map[string]any{
		"scan_id":         scanID,
		"scan_mode":       scanMode,
		"trigger_token":   manualTriggerToken,
		"entries":         len(completed.Entries),
		"hosts_scanned":   completed.Result.Summary.HostsScanned,
		"hosts_reachable": completed.Result.Summary.HostsReachable,
		"errors":          completed.Result.Summary.ErrorsCount,
	})
	completionStatus := "completed"
	completionError := ""
	if completed.Result.JobStatus == "failed" {
		completionStatus = "failed"
		completionError = "discovery_scan_failed"
	}
	emitManualScanEvent(completionStatus, completed.Result.FinishedAt, completionError)
	return nil
}

func (a *agent) buildDiscoveryInventoryEntries(candidates []discoveryCandidateResult) []discoveryInventoryEntryReport {
	entries := make([]discoveryInventoryEntryReport, 0, len(candidates))
	for _, candidate := range candidates {
		candidateStatus := strings.ToLower(strings.TrimSpace(candidate.Status))
		if candidateStatus != "reachable" && candidateStatus != "unreachable" && candidateStatus != "lost" {
			continue
		}
		adapterFamily := normalizeAdapterFamily(candidate.AdapterFamily)
		if !isSupportedDiscoveryAdapter(adapterFamily, a.cfg.EnableKlipper, a.isBambuOperational()) {
			a.audit("discovery_inventory_candidate_dropped", map[string]any{
				"adapter_family":   strings.TrimSpace(candidate.AdapterFamily),
				"status":           candidateStatus,
				"endpoint_url":     strings.TrimSpace(candidate.EndpointURL),
				"drop_reason":      "unsupported_adapter",
				"discovery_source": discoveryCandidateSource(candidate),
			})
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
		if entry.AdapterFamily == "" {
			a.audit("discovery_inventory_candidate_dropped", map[string]any{
				"adapter_family":   strings.TrimSpace(candidate.AdapterFamily),
				"status":           candidateStatus,
				"endpoint_url":     entry.EndpointURL,
				"drop_reason":      "missing_adapter_family",
				"discovery_source": discoveryCandidateSource(candidate),
			})
			continue
		}
		if entry.EndpointURL == "" {
			a.audit("discovery_inventory_candidate_dropped", map[string]any{
				"adapter_family":     entry.AdapterFamily,
				"status":             candidateStatus,
				"connectivity_error": entry.ConnectivityError,
				"drop_reason":        "missing_endpoint_url",
				"discovery_source":   discoveryCandidateSource(candidate),
			})
			continue
		}
		entry.MacAddress = macAddressFromEvidence(candidate.Evidence)
		entries = append(entries, entry)
	}
	return entries
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
	bambuEnabled := a.cfg.EnableBambu
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
			bambuCandidates, bambuErr := a.executeBambuLANDiscovery(ctx, probeTimeout)
			if bambuErr != nil {
				a.audit("bambu_lan_discovery_error", map[string]any{
					"error":          bambuErr.Error(),
					"adapter_family": adapter,
				})
				candidates = append(candidates, discoveryCandidateResult{
					AdapterFamily:     adapter,
					Status:            "unreachable",
					ConnectivityError: bambuErr.Error(),
					Evidence: map[string]any{
						"source":           discoverySourceBambuLAN,
						"discovery_source": discoverySourceBambuLAN,
					},
				})
				continue
			}
			if len(bambuCandidates) == 0 {
				a.audit("bambu_lan_discovery_no_targets", map[string]any{
					"adapter_family": adapter,
				})
				candidates = append(candidates, discoveryCandidateResult{
					AdapterFamily:   adapter,
					Status:          "policy_rejected",
					RejectionReason: "no_targets",
					Evidence: map[string]any{
						"source":           discoverySourceBambuLAN,
						"discovery_source": discoverySourceBambuLAN,
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
	status := strings.ToLower(strings.TrimSpace(rawPrintStatus))
	switch status {
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
		switch {
		case strings.Contains(status, "pause"):
			return "paused", "printing"
		case strings.Contains(status, "cancel"):
			return "idle", "canceled"
		case strings.Contains(status, "error"), strings.Contains(status, "fail"), strings.Contains(status, "fault"):
			return "error", "failed"
		case strings.Contains(status, "queue"),
			strings.Contains(status, "pend"),
			strings.Contains(status, "prepar"),
			strings.Contains(status, "start"),
			strings.Contains(status, "heat"),
			strings.Contains(status, "slice"),
			strings.Contains(status, "busy"):
			return "queued", "pending"
		case strings.Contains(status, "print"), strings.Contains(status, "run"):
			return "printing", "printing"
		case strings.Contains(status, "finish"), strings.Contains(status, "complet"), strings.Contains(status, "idle"), strings.Contains(status, "ready"):
			return "idle", "completed"
		default:
			return "idle", "completed"
		}
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
		source := discoveryCandidateSource(candidate)
		if source == "" {
			source = "unspecified"
		}
		counts[source]++
	}
	return counts
}

func discoveryCandidateSource(candidate discoveryCandidateResult) string {
	if candidate.Evidence == nil {
		return ""
	}
	raw, _ := candidate.Evidence["discovery_source"].(string)
	return strings.TrimSpace(raw)
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
	appendCIDRTargets := false
	if job.RuntimeCapsOverrides != nil {
		appendCIDRTargets = job.RuntimeCapsOverrides[recoveryAppendCIDRTargetsKey] > 0
	}
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

	if len(targets) > 0 && !appendCIDRTargets {
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
	a.recordControlPlaneAuthRevoked(strings.TrimSpace(responseBody))

	a.mu.Lock()
	wasClaimed := a.claimed
	a.claimed = false
	a.desiredState = make(map[int]desiredStateItem)
	a.bindings = make(map[int]edgeBinding)
	a.actionQueue = make(map[int][]action)
	a.inflightActions = make(map[int]action)
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
			observedAt := time.Now().UTC()
			a.mu.Lock()
			current := a.currentState[item.printerID]
			current.PrinterID = item.printerID
			if errors.Is(err, errBambuAuthUnavailable) {
				if current.CurrentPrinterState == "" {
					current.CurrentPrinterState = "idle"
					current.CurrentJobState = "completed"
				}
				current.LastErrorCode = "auth_error"
				current.LastErrorMessage = err.Error()
				current.ReportedAt = observedAt
				a.currentState[item.printerID] = current
				a.mu.Unlock()
				a.localObservations.upsertRuntimeFailure(item.binding, current, observedAt)
				continue
			}
			if isBambuLANCredentialsUnavailable(err) {
				if current.CurrentPrinterState == "" {
					current.CurrentPrinterState = "error"
				}
				current.LastErrorCode = "auth_error"
				current.LastErrorMessage = err.Error()
				current.TotalPrintSeconds = nil
				current.ProgressPct = nil
				current.RemainingSeconds = nil
				current.TelemetrySource = ""
				current.ManualIntervention = ""
				current.ReportedAt = observedAt
				a.currentState[item.printerID] = current
				a.mu.Unlock()
				a.localObservations.upsertRuntimeFailure(item.binding, current, observedAt)
				continue
			}
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
			current.ReportedAt = observedAt
			a.currentState[item.printerID] = current
			a.mu.Unlock()
			a.localObservations.upsertRuntimeFailure(item.binding, current, observedAt)
			continue
		}

		observedAt := time.Now().UTC()
		a.mu.Lock()
		current := a.currentState[item.printerID]
		previousCurrent := current
		prevState := current.CurrentPrinterState
		desired := a.desiredState[item.printerID]
		current.PrinterID = item.printerID
		current.CurrentPrinterState = snapshot.PrinterState
		current.CurrentJobState = snapshot.JobState
		hydrateActiveIntentIdentity(desired, &current, snapshot)
		detectedManualIntervention := detectExternalAuthorityManualIntervention(
			item.binding,
			desired,
			previousCurrent,
			snapshot,
			a.bambuPrintStartVerificationTimeout(),
		)
		if shouldMarkBambuIdleTransitionCompleted(item.binding, prevState, current, snapshot, detectedManualIntervention) {
			current.CurrentJobState = "completed"
		}
		current.LastErrorCode = ""
		current.LastErrorMessage = ""
		current.TotalPrintSeconds = snapshot.TotalPrintSeconds
		current.ProgressPct = snapshot.ProgressPct
		current.RemainingSeconds = snapshot.RemainingSeconds
		current.TelemetrySource = snapshot.TelemetrySource
		current.ManualIntervention = detectedManualIntervention
		current.CommandCapabilities = mergeCommandCapabilities(current.CommandCapabilities, snapshot.CommandCapabilities)
		resolveRuntimeFilamentCapability(item.binding, &current, previousCurrent, snapshot, observedAt)
		current.CommandCapabilities = ensurePrinterSupportCapability(item.binding, snapshot, current.CommandCapabilities)
		current.IsCanceled = snapshot.JobState == "canceled"
		current.ReportedAt = observedAt
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
		a.localObservations.upsertRuntimeSuccess(item.binding, snapshot, current, observedAt)
	}
}

func hydrateActiveIntentIdentity(desired desiredStateItem, current *currentStateItem, snapshot bindingSnapshot) {
	if current == nil {
		return
	}
	if snapshot.PrinterState != "queued" && snapshot.PrinterState != "printing" && snapshot.PrinterState != "paused" {
		return
	}
	if strings.TrimSpace(current.JobID) != "" && current.PlateID != 0 {
		return
	}
	if desired.DesiredPrinterState != "printing" || strings.TrimSpace(desired.JobID) == "" || desired.PlateID == 0 {
		return
	}
	current.JobID = desired.JobID
	current.PlateID = desired.PlateID
	current.IntentVersionApplied = desired.IntentVersion
}

func normalizeAuthorityManualIntervention(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pause", "paused":
		return "paused"
	case "stop", "stopped":
		return "stopped"
	case "cancel", "canceled", "cancelled":
		return "canceled"
	default:
		return ""
	}
}

func desiredOwnsActiveLifecycle(desired desiredStateItem) bool {
	return (desired.DesiredPrinterState == "printing" || desired.DesiredPrinterState == "paused") &&
		strings.TrimSpace(desired.JobID) != "" &&
		desired.PlateID != 0
}

func desiredIntentIsNewerThanCurrent(prev currentStateItem, desired desiredStateItem) bool {
	return desiredOwnsActiveLifecycle(desired) && desired.IntentVersion > prev.IntentVersionApplied
}

func previousCurrentMatchesDesiredTarget(prev currentStateItem, desired desiredStateItem) bool {
	if !desiredOwnsActiveLifecycle(desired) {
		return false
	}
	if strings.TrimSpace(prev.JobID) != "" && prev.PlateID != 0 {
		return prev.JobID == desired.JobID && prev.PlateID == desired.PlateID
	}
	return prev.IntentVersionApplied == desired.IntentVersion
}

func runtimeLookedActive(prev currentStateItem) bool {
	return prev.CurrentPrinterState == "queued" ||
		prev.CurrentPrinterState == "printing" ||
		prev.CurrentPrinterState == "paused" ||
		prev.CurrentJobState == "printing"
}

func shouldPersistPreviousAuthorityManualIntervention(
	prev currentStateItem,
	snapshot bindingSnapshot,
	desired desiredStateItem,
) bool {
	if desiredIntentIsNewerThanCurrent(prev, desired) {
		return false
	}
	switch normalizeAuthorityManualIntervention(prev.ManualIntervention) {
	case "paused":
		return snapshot.PrinterState == "paused"
	case "stopped", "canceled":
		return snapshot.PrinterState != "printing" &&
			snapshot.PrinterState != "queued" &&
			snapshot.PrinterState != "paused"
	default:
		return false
	}
}

func isBambuManagedStartIdlePendingSnapshot(
	binding edgeBinding,
	desired desiredStateItem,
	prev currentStateItem,
	snapshot bindingSnapshot,
	startWindow time.Duration,
	now time.Time,
) bool {
	if normalizeAdapterFamily(binding.AdapterFamily) != "bambu" {
		return false
	}
	if snapshot.PrinterState != "idle" || snapshot.JobState != "pending" {
		return false
	}
	if !desiredOwnsActiveLifecycle(desired) {
		return false
	}
	if !previousCurrentMatchesDesiredTarget(prev, desired) {
		return false
	}
	if prev.CurrentPrinterState != "queued" || prev.CurrentJobState != "pending" {
		return false
	}
	if startWindow <= 0 || prev.ReportedAt.IsZero() {
		return false
	}
	return now.UTC().Sub(prev.ReportedAt.UTC()) <= startWindow
}

func detectExternalAuthorityManualIntervention(
	binding edgeBinding,
	desired desiredStateItem,
	prev currentStateItem,
	snapshot bindingSnapshot,
	startWindow time.Duration,
) string {
	explicitAuthority := normalizeAuthorityManualIntervention(snapshot.ManualIntervention)
	if explicitAuthority != "" {
		if desiredIntentIsNewerThanCurrent(prev, desired) {
			return ""
		}
		return explicitAuthority
	}
	if raw := strings.ToLower(strings.TrimSpace(snapshot.ManualIntervention)); raw != "" {
		return raw
	}
	if desiredIntentIsNewerThanCurrent(prev, desired) {
		return ""
	}
	if isBambuManagedStartIdlePendingSnapshot(binding, desired, prev, snapshot, startWindow, time.Now().UTC()) {
		return ""
	}
	if shouldPersistPreviousAuthorityManualIntervention(prev, snapshot, desired) {
		return normalizeAuthorityManualIntervention(prev.ManualIntervention)
	}
	if !previousCurrentMatchesDesiredTarget(prev, desired) {
		return ""
	}
	if snapshot.PrinterState == "paused" && desired.DesiredPrinterState == "printing" {
		return "paused"
	}
	if snapshot.JobState == "canceled" {
		return "canceled"
	}
	if normalizeAdapterFamily(binding.AdapterFamily) == "bambu" &&
		snapshot.PrinterState == "idle" &&
		snapshot.JobState == "pending" &&
		runtimeLookedActive(prev) {
		return "stopped"
	}
	return ""
}

func shouldSuppressConvergenceForAuthorityManualIntervention(
	current currentStateItem,
	desired desiredStateItem,
) bool {
	intervention := normalizeAuthorityManualIntervention(current.ManualIntervention)
	if intervention == "" {
		return false
	}
	if desiredIntentIsNewerThanCurrent(current, desired) {
		return false
	}
	switch intervention {
	case "paused":
		return desired.DesiredPrinterState == "printing"
	case "stopped", "canceled":
		return desired.DesiredPrinterState == "printing" || desired.DesiredPrinterState == "paused"
	default:
		return false
	}
}

func shouldMarkBambuIdleTransitionCompleted(
	binding edgeBinding,
	prevPrinterState string,
	current currentStateItem,
	snapshot bindingSnapshot,
	manualIntervention string,
) bool {
	if normalizeAdapterFamily(binding.AdapterFamily) != "bambu" {
		return false
	}
	if snapshot.PrinterState != "idle" || snapshot.JobState != "pending" {
		return false
	}
	if strings.TrimSpace(manualIntervention) != "" {
		return false
	}
	if prev := strings.ToLower(strings.TrimSpace(prevPrinterState)); prev != "printing" && prev != "paused" && prev != "queued" {
		return false
	}
	if strings.TrimSpace(current.JobID) == "" || current.PlateID == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(snapshot.RawPrinterStatus), "idle")
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
		commandCapabilities, capabilityErr := a.fetchMoonrakerCommandCapabilities(ctx, binding.EndpointURL)
		if capabilityErr != nil {
			a.audit("moonraker_command_capabilities_fetch_error", map[string]any{
				"endpoint_url": binding.EndpointURL,
				"error":        capabilityErr.Error(),
			})
		}
		return bindingSnapshot{
			PrinterState:        printerState,
			JobState:            jobState,
			TotalPrintSeconds:   totalPrintSeconds,
			ProgressPct:         progressPct,
			RemainingSeconds:    remainingSeconds,
			TelemetrySource:     telemetrySource,
			ManualIntervention:  manualIntervention,
			CommandCapabilities: commandCapabilities,
			DetectedName:        detectedName,
			DetectedModelHint:   detectedModelHint,
		}, nil
	case "bambu":
		if !a.cfg.EnableBambu {
			return bindingSnapshot{}, errors.New("validation_error: adapter_family bambu is disabled (set --bambu to enable)")
		}
		printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
		if err != nil {
			return bindingSnapshot{}, err
		}
		hasSuccessfulRuntimeSnapshot := a.hasBambuLANSuccessfulRuntimeSnapshot(printerID)
		runtimeSnapshot, runtimeErr := a.fetchBambuLANRuntimeSnapshotByPrinterID(ctx, printerID)
		if runtimeErr == nil {
			a.clearBambuLANRuntimeFailure(printerID)
			return runtimeSnapshot, nil
		}
		decoratedRuntimeErr := runtimeErr
		if isBambuLANCredentialsUnavailable(runtimeErr) {
			decoratedRuntimeErr = a.decorateBambuLANCredentialsUnavailable(ctx, binding, runtimeErr)
		}
		runtimeFailureThresholdReached := false
		suppressRuntimeConnectivityFailure := a.shouldSuppressBambuRuntimeConnectivityFailure(binding.PrinterID, runtimeErr)
		if !isBambuLANCredentialsUnavailable(runtimeErr) {
			a.audit("bambu_lan_runtime_snapshot_error", map[string]any{
				"endpoint_url": binding.EndpointURL,
				"printer_id":   printerID,
				"error":        runtimeErr.Error(),
			})
			if suppressRuntimeConnectivityFailure {
				a.clearBambuLANRuntimeFailure(printerID)
				a.audit("bambu_lan_runtime_snapshot_error_suppressed", map[string]any{
					"endpoint_url": binding.EndpointURL,
					"printer_id":   printerID,
					"reason":       "inflight_bambu_print_start",
				})
			} else {
				runtimeFailureThresholdReached = a.recordBambuLANRuntimeFailure(printerID, runtimeErr)
			}
		}
		if hasSuccessfulRuntimeSnapshot {
			return bindingSnapshot{}, runtimeErr
		}
		lanSnapshot, lanErr := a.fetchBambuLANSnapshotFromEndpoint(ctx, binding.EndpointURL)
		if lanErr == nil && !runtimeFailureThresholdReached {
			lanSnapshot.CommandCapabilities = a.fallbackBambuCommandCapabilities(printerID)
			return lanSnapshot, nil
		}
		if runtimeFailureThresholdReached {
			return bindingSnapshot{}, runtimeErr
		}
		if a.isBambuAuthReady() {
			snapshot, err := a.fetchBambuCloudSnapshotFromEndpoint(ctx, binding.EndpointURL)
			if err == nil {
				snapshot.CommandCapabilities = a.fallbackBambuCommandCapabilities(printerID)
				return snapshot, nil
			}
			var offlineErr *bambuCloudDeviceOfflineError
			if !errors.As(err, &offlineErr) {
				a.audit("bambu_cloud_snapshot_error", map[string]any{
					"endpoint_url": binding.EndpointURL,
					"error":        err.Error(),
				})
			}
			if !isBambuLANCredentialsUnavailable(runtimeErr) {
				return bindingSnapshot{}, fmt.Errorf("bambu lan runtime snapshot failed: %v; cloud snapshot failed: %w", runtimeErr, err)
			}
			return bindingSnapshot{}, err
		}
		if !isBambuLANCredentialsUnavailable(runtimeErr) {
			return bindingSnapshot{}, runtimeErr
		}
		return bindingSnapshot{}, firstNonNilError(decoratedRuntimeErr, lanErr)
	default:
		return bindingSnapshot{}, fmt.Errorf("validation_error: unsupported adapter_family: %s", family)
	}
}

func firstNonNilError(primary error, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}

func (a *agent) decorateBambuLANCredentialsUnavailable(ctx context.Context, binding edgeBinding, cause error) error {
	if cause == nil {
		return nil
	}
	recoveryQueued, recoveryErr := a.requestBambuLANCredentialRecovery(ctx, binding)
	if recoveryErr != nil {
		a.audit("bambu_lan_credentials_recovery_error", map[string]any{
			"printer_id":   binding.PrinterID,
			"endpoint_url": strings.TrimSpace(binding.EndpointURL),
			"error":        recoveryErr.Error(),
		})
		return fmt.Errorf(
			"bambu_lan_credentials_missing_local: local Bambu access code missing on edge-agent and recovery failed: %v: %w",
			recoveryErr,
			cause,
		)
	}
	if recoveryQueued {
		return fmt.Errorf(
			"bambu_lan_credentials_missing_local: local Bambu access code missing on edge-agent; recovery requested from control plane: %w",
			cause,
		)
	}
	return fmt.Errorf(
		"bambu_lan_credentials_missing_local: local Bambu access code missing on edge-agent; recovery request already pending or cooling down: %w",
		cause,
	)
}

func (a *agent) shouldSuppressBambuRuntimeConnectivityFailure(printerID int, runtimeErr error) bool {
	if runtimeErr == nil {
		return false
	}
	code, _ := classifyActionError(runtimeErr)
	if code != "connectivity_error" {
		return false
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	if until, ok := a.bambuRuntimeSuppressUntil[printerID]; ok {
		if time.Now().UTC().Before(until) {
			return true
		}
	}
	if queue := a.actionQueue[printerID]; len(queue) > 0 {
		for _, queued := range queue {
			if isPrinterRuntimeCommandKind(queued.Kind) {
				return true
			}
		}
	}
	inflight, ok := a.inflightActions[printerID]
	if !ok {
		return false
	}
	if inflight.Kind == "print" && inflight.Target.DesiredPrinterState == "printing" {
		return true
	}
	return isPrinterRuntimeCommandKind(inflight.Kind)
}

func (a *agent) extendBambuRuntimeConnectivitySuppression(printerID int, duration time.Duration) {
	if printerID == 0 || duration <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.bambuRuntimeSuppressUntil == nil {
		a.bambuRuntimeSuppressUntil = make(map[int]time.Time)
	}
	until := time.Now().UTC().Add(duration)
	if existing, ok := a.bambuRuntimeSuppressUntil[printerID]; ok && existing.After(until) {
		return
	}
	a.bambuRuntimeSuppressUntil[printerID] = until
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
		RawPrinterStatus:  strings.TrimSpace(matched.PrintStatus),
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

func buildBambuConnectImportURI(localPath string, fileName string) string {
	normalizedPath := strings.TrimSpace(filepath.Clean(localPath))
	normalizedPath = strings.ReplaceAll(normalizedPath, "\\", "/")

	displayName := strings.TrimSpace(fileName)
	if displayName == "" {
		displayName = strings.TrimSpace(filepath.Base(localPath))
	}
	// Match Orca/Bambu Connect handoff contract: nested query payload
	// encoded once as the "path" value.
	innerPath := "?version=v1.0.0&path=" + normalizedPath + "&name=" + displayName + "&fileName=" + displayName
	return "bambu-connect://import-file?path=" + url.QueryEscape(innerPath)
}

func prepareBambuConnectImportPath(localPath string, remoteName string) (string, error) {
	stagedPath := strings.TrimSpace(localPath)
	if stagedPath == "" {
		return "", errors.New("artifact_fetch_error: missing local staged artifact path")
	}
	if !strings.HasSuffix(strings.ToLower(stagedPath), ".ready") {
		return stagedPath, nil
	}
	displayName := strings.TrimSpace(remoteName)
	if displayName == "" {
		displayName = strings.TrimSpace(filepath.Base(strings.TrimSuffix(stagedPath, ".ready")))
	}
	if displayName == "" {
		return "", errors.New("artifact_fetch_error: missing staged artifact filename for bambu connect import")
	}
	importPath := filepath.Join(filepath.Dir(stagedPath), displayName)
	if importPath == stagedPath {
		return stagedPath, nil
	}
	if err := os.Rename(stagedPath, importPath); err != nil {
		return "", fmt.Errorf("artifact_fetch_error: prepare bambu connect import path failed: %w", err)
	}
	return importPath, nil
}

func launchBambuConnectURI(ctx context.Context, rawURI string) error {
	targetURI := strings.TrimSpace(rawURI)
	if targetURI == "" {
		return errors.New("validation_error: missing bambu connect launch uri")
	}
	command, args, err := bambuConnectOpenCommand(targetURI)
	if err != nil {
		return err
	}
	output, execErr := runExternalCommand(ctx, command, args...)
	if execErr == nil {
		return nil
	}
	trimmedOutput := strings.TrimSpace(string(output))
	if trimmedOutput == "" {
		return fmt.Errorf("launch bambu connect uri failed: %w", execErr)
	}
	return fmt.Errorf("launch bambu connect uri failed: %w: %s", execErr, trimmedOutput)
}

func bambuConnectOpenCommand(rawURI string) (string, []string, error) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{rawURI}, nil
	case "linux":
		return "xdg-open", []string{rawURI}, nil
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", rawURI}, nil
	default:
		return "", nil, fmt.Errorf("validation_error: unsupported platform for bambu connect uri launch: %s", runtime.GOOS)
	}
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
	normalizedState := strings.ToLower(strings.TrimSpace(state))
	switch normalizedState {
	case "printing":
		return "printing", "printing", nil
	case "paused":
		return "paused", "printing", nil
	case "complete", "completed", "finished":
		return "idle", "completed", nil
	case "standby", "ready", "idle", "":
		// Idle-like Moonraker states should not imply that a job just completed.
		return "idle", "", nil
	case "cancelled", "canceled":
		return "idle", "canceled", nil
	case "error":
		return "error", "failed", nil
	case "queued":
		return "queued", "pending", nil
	default:
		return "idle", "", nil
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
		"action_duplicate_queue_pruned",
		"action_reenqueue_suppressed",
		"artifact_downloaded",
		"artifact_uploaded",
		"bambu_lan_upload_attempt",
		"bambu_lan_upload_success",
		"bambu_connect_start_dispatch_attempt",
		"bambu_connect_start_dispatch_success",
		"bambu_connect_start_dispatch_failed",
		"bambu_cloud_start_unsupported",
		"bambu_lan_discovery_candidates",
		"bambu_lan_credentials_upserted",
		"bambu_lan_discovery_probe_summary",
		"bambu_lan_discovery_no_targets",
		"bambu_lan_discovery_skipped_device",
		"bambu_mqtt_username_resolved",
		"bambu_mqtt_username_retry_attempt",
		"bambu_mqtt_username_retry_success",
		"bambu_print_start_dispatch_attempt",
		"bambu_print_start_dispatch_echo",
		"bambu_print_start_verified",
		"print_start_requested",
		"uncertain_action_resolved",
		"state_pushed",
		"desired_state_updated",
		"bindings_updated",
		"config_commands_updated",
		"discovery_scan_started",
		"discovery_scan_plan",
		"discovery_scan_completed",
		"discovery_scan_zero_candidates",
		"discovery_inventory_candidate_dropped",
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
