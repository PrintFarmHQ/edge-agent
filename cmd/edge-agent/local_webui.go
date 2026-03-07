package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	localControlPlaneStatusConnected    = "connected"
	localControlPlaneStatusNotConnected = "not_connected"
	localControlPlaneStatusRenewKey     = "renew_key"

	localObservationScanSourceBackground      = "local_background"
	localObservationScanSourceManual          = "local_manual"
	localObservationScanSourceControlPeriodic = "control_plane_periodic"
	localObservationScanSourceControlManual   = "control_plane_manual"

	localControlPlaneDegradedWindow = 2 * time.Minute
)

type localControlPlaneState struct {
	LastSuccessAt  time.Time
	LastFailureAt  time.Time
	LastFailureMsg string
	AuthRevoked    bool
	APIKeySeen     bool
}

type localScanTriggerResponse struct {
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at,omitempty"`
}

type localControlPlaneConnectRequest struct {
	SaaSAPIKey string `json:"saas_api_key"`
	APIKey     string `json:"api_key"`
}

type completedDiscoveryScan struct {
	Result  discoveryJobResultRequest
	Entries []discoveryInventoryEntryReport
}

func (a *agent) registerRoutes(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/setup/status", a.handleSetupStatus)
	mux.HandleFunc("/setup/claim", a.handleSetupClaim)
	mux.HandleFunc("/", a.handleLocalWebUIRedirect)
}

func (a *agent) registerLocalWebUIRoutes(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	mux.Handle("/assets/", a.loopbackOnly(http.StripPrefix("/assets/", http.FileServer(http.FS(localWebUIAssetsFS)))))
	mux.Handle("/api/local/observations", a.loopbackOnly(http.HandlerFunc(a.handleLocalObservations)))
	mux.Handle("/api/local/observations/scan", a.loopbackOnly(http.HandlerFunc(a.handleLocalObservationScan)))
	mux.Handle("/api/local/control-plane/connect", a.loopbackOnly(http.HandlerFunc(a.handleLocalControlPlaneConnect)))
	mux.Handle("/", a.loopbackOnly(http.HandlerFunc(a.handleLocalWebUIIndex)))
}

func (a *agent) handleLocalWebUIRedirect(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uiURL := a.localWebUIURLSnapshot()
	if strings.TrimSpace(uiURL) == "" {
		http.Error(w, "local web ui is starting", http.StatusServiceUnavailable)
		return
	}
	http.Redirect(w, r, uiURL, http.StatusTemporaryRedirect)
}

func (a *agent) handleLocalWebUIIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(localWebUIDistFS, "index.html")
	if err != nil {
		http.Error(w, "web ui asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (a *agent) handleLocalObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, a.buildLocalObservationsResponse())
}

func (a *agent) handleLocalObservationScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.beginDiscoveryRun() {
		writeJSON(w, http.StatusAccepted, localScanTriggerResponse{Status: "in_progress"})
		return
	}

	startedAt := time.Now().UTC()
	go func() {
		defer a.endDiscoveryRun()
		a.runLocalObservationScan(context.Background(), localObservationScanSourceManual, startedAt)
	}()

	writeJSON(w, http.StatusAccepted, localScanTriggerResponse{
		Status:    "started",
		StartedAt: startedAt,
	})
}

func (a *agent) handleLocalControlPlaneConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req localControlPlaneConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	apiKey := firstNonEmpty(strings.TrimSpace(req.SaaSAPIKey), strings.TrimSpace(req.APIKey))
	if apiKey == "" {
		http.Error(w, "saas_api_key is required", http.StatusBadRequest)
		return
	}

	controlPlaneURL := strings.TrimSpace(a.currentControlPlaneURL())
	if controlPlaneURL == "" {
		http.Error(w, "control plane url is not configured", http.StatusBadRequest)
		return
	}

	claim, err := a.applyClaim(r.Context(), controlPlaneURL, apiKey)
	if err != nil {
		a.audit("claim_failed", map[string]any{"error": err.Error()})
		a.clearClaimedState(controlPlaneURL)
		a.recordControlPlaneClaimFailure(err)
		http.Error(w, fmt.Sprintf("claim failed: %v", err), http.StatusBadGateway)
		return
	}

	a.audit("claimed", map[string]any{
		"agent_id":       claim.AgentID,
		"org_id":         claim.OrgID,
		"schema_version": claim.SchemaVersion,
		"source":         "local_dashboard",
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

const (
	localWebUIDefaultPort  = "18800"
	localWebUIFallbackPort = "18801"
)

func (a *agent) startLocalWebUIServer() (*http.Server, string, string, error) {
	bindAddr := strings.TrimSpace(a.cfg.LocalUIBindAddr)

	var listener net.Listener
	var err error

	if bindAddr != "" {
		// User explicitly set a bind address — respect it as-is, no cascade.
		listener, err = net.Listen("tcp", bindAddr)
		if err != nil {
			return nil, "", "", err
		}
	} else {
		// No explicit address: try stable ports, then fall back to random.
		for _, port := range []string{localWebUIDefaultPort, localWebUIFallbackPort, "0"} {
			listener, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, "", "", err
		}
	}

	server := &http.Server{
		Handler: a.localWebUIHandler(),
	}
	uiURL := localWebUIURLFromAddr(listener.Addr())
	uiPort := localWebUIPortFromAddr(listener.Addr())
	go func() {
		if err := server.Serve(listener); err != nil && !strings.Contains(err.Error(), "Server closed") && err != http.ErrServerClosed {
			log.Printf("warning: local web ui server failed: %v", err)
		}
	}()

	return server, uiURL, uiPort, nil
}

func (a *agent) localWebUIHandler() http.Handler {
	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)
	return mux
}

func (a *agent) loopbackOnly(next http.Handler) http.Handler {
	if next == nil {
		return http.NotFoundHandler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			http.Error(w, "local web ui is only available on loopback", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	host := strings.TrimSpace(remoteAddr)
	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func localWebUIURLFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return fmt.Sprintf("http://%s/", net.JoinHostPort(host, port))
}

func localWebUIPortFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(port)
}

func localWebUIPortFromURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Port())
}

func (a *agent) localObservationScanLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	interval := a.cfg.LocalUIScanInterval
	if interval <= 0 {
		interval = 15 * time.Second
	}

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if a.beginDiscoveryRun() {
				a.runLocalObservationScan(ctx, localObservationScanSourceBackground, time.Now().UTC())
				a.endDiscoveryRun()
			}
			timer.Reset(interval)
		}
	}
}

func (a *agent) runLocalObservationScan(ctx context.Context, scanSource string, startedAt time.Time) {
	a.localObservations.markScanStarted(scanSource, startedAt)
	var runErr error
	defer func() {
		a.localObservations.markScanFinished(scanSource, time.Now().UTC(), runErr)
	}()

	completed := a.executeDiscoveryScanLocked(ctx, scanSource, "", startedAt)
	a.localObservations.upsertDiscoveryCandidates(completed.Result.Candidates, completed.Result.FinishedAt)
}

func (a *agent) executeDiscoveryScanLocked(
	ctx context.Context,
	scanMode string,
	triggerToken string,
	startedAt time.Time,
) completedDiscoveryScan {
	job := a.newDefaultDiscoveryJob(startedAt)
	a.audit("discovery_scan_started", map[string]any{
		"scan_mode":     scanMode,
		"trigger_token": strings.TrimSpace(triggerToken),
		"adapters":      job.Adapters,
		"profile":       job.Profile,
	})

	result := a.executeDiscoveryJob(ctx, job)
	sourceBreakdown := discoveryCandidateSourceBreakdown(result.Candidates)
	entries := a.buildDiscoveryInventoryEntries(result.Candidates)

	a.audit("discovery_scan_completed", map[string]any{
		"scan_mode":         scanMode,
		"trigger_token":     strings.TrimSpace(triggerToken),
		"job_status":        result.JobStatus,
		"hosts_scanned":     result.Summary.HostsScanned,
		"hosts_reachable":   result.Summary.HostsReachable,
		"candidates":        result.Summary.CandidatesFound,
		"raw_candidates":    len(result.Candidates),
		"inventory_entries": len(entries),
		"errors":            result.Summary.ErrorsCount,
		"source_breakdown":  sourceBreakdown,
	})
	if result.Summary.CandidatesFound == 0 {
		a.audit("discovery_scan_zero_candidates", map[string]any{
			"scan_mode":         scanMode,
			"trigger_token":     strings.TrimSpace(triggerToken),
			"hosts_scanned":     result.Summary.HostsScanned,
			"hosts_reachable":   result.Summary.HostsReachable,
			"raw_candidates":    len(result.Candidates),
			"inventory_entries": len(entries),
			"errors":            result.Summary.ErrorsCount,
			"source_breakdown":  sourceBreakdown,
		})
	}

	return completedDiscoveryScan{
		Result:  result,
		Entries: entries,
	}
}

func (a *agent) newDefaultDiscoveryJob(startedAt time.Time) discoveryJobItem {
	return discoveryJobItem{
		JobID:         randomKey("scan"),
		Profile:       parseDiscoveryProfile(a.cfg.DiscoveryProfileMax),
		Adapters:      append([]string(nil), a.cfg.DiscoveryAllowedAdapters...),
		EndpointHints: append([]string(nil), a.cfg.DiscoveryEndpointHints...),
		CIDRAllowlist: append([]string(nil), a.cfg.DiscoveryCIDRAllowlist...),
		RequestedAt:   edgeTimestamp{Time: startedAt.UTC()},
		ExpiresAt:     edgeTimestamp{Time: startedAt.UTC().Add(30 * time.Second)},
	}
}

func scanSourceForMode(scanMode string) string {
	switch strings.TrimSpace(scanMode) {
	case "manual":
		return localObservationScanSourceControlManual
	case "periodic":
		return localObservationScanSourceControlPeriodic
	default:
		return strings.TrimSpace(scanMode)
	}
}

func (a *agent) buildLocalObservationsResponse() localObservationsResponse {
	scan := localScanStatus{}
	if a.localObservations != nil {
		scan = a.localObservations.scanStatus()
	}
	agentStatus := localAgentStatus{
		Version:                   agentVersion,
		Claimed:                   a.isClaimed(),
		ControlPlaneStatus:        localControlPlaneStatusNotConnected,
		ControlPlaneMessage:       "Edge agent is NOT connected to control plane SaaS. Paste a valid API key to continue.",
		LastControlPlaneSuccessAt: time.Time{},
		LastControlPlaneFailureAt: time.Time{},
		ControlPlaneURL:           a.currentControlPlaneURL(),
		Scan:                      scan,
	}

	status, message, lastSuccessAt, lastFailureAt := a.localControlPlaneSnapshot(time.Now().UTC())
	agentStatus.ControlPlaneStatus = status
	agentStatus.ControlPlaneMessage = message
	agentStatus.LastControlPlaneSuccessAt = lastSuccessAt
	agentStatus.LastControlPlaneFailureAt = lastFailureAt

	return a.localObservations.snapshot(agentStatus, time.Now().UTC())
}

func (a *agent) setLocalWebUIURL(rawURL string) {
	a.localWebUIMu.Lock()
	defer a.localWebUIMu.Unlock()
	a.localWebUIURL = strings.TrimSpace(rawURL)
}

func (a *agent) localWebUIURLSnapshot() string {
	a.localWebUIMu.RLock()
	defer a.localWebUIMu.RUnlock()
	return strings.TrimSpace(a.localWebUIURL)
}

func (a *agent) recordControlPlaneSuccess() {
	if a == nil {
		return
	}
	a.controlPlaneMu.Lock()
	defer a.controlPlaneMu.Unlock()
	a.controlPlane.LastSuccessAt = time.Now().UTC()
	a.controlPlane.LastFailureMsg = ""
	a.controlPlane.AuthRevoked = false
	a.controlPlane.APIKeySeen = true
}

func (a *agent) recordControlPlaneFailure(message string) {
	if a == nil {
		return
	}
	a.controlPlaneMu.Lock()
	defer a.controlPlaneMu.Unlock()
	a.controlPlane.LastFailureAt = time.Now().UTC()
	a.controlPlane.LastFailureMsg = strings.TrimSpace(message)
	a.controlPlane.AuthRevoked = false
}

func (a *agent) recordControlPlaneAuthRevoked(message string) {
	if a == nil {
		return
	}
	a.controlPlaneMu.Lock()
	defer a.controlPlaneMu.Unlock()
	a.controlPlane.LastFailureAt = time.Now().UTC()
	a.controlPlane.LastFailureMsg = strings.TrimSpace(message)
	a.controlPlane.AuthRevoked = true
	a.controlPlane.APIKeySeen = true
}

func (a *agent) recordControlPlaneAPIKeySeen() {
	if a == nil {
		return
	}
	a.controlPlaneMu.Lock()
	defer a.controlPlaneMu.Unlock()
	a.controlPlane.APIKeySeen = true
}

func (a *agent) recordControlPlaneClaimFailure(err error) {
	if err == nil {
		return
	}
	if isControlPlaneAuthError(err) {
		a.recordControlPlaneAuthRevoked("The current API key was rejected. Paste a new key to reconnect.")
		return
	}
	a.recordControlPlaneFailure("Edge agent is not connected to PrintFarmHQ SaaS. Check connectivity or paste a valid API key.")
}

func (a *agent) localControlPlaneSnapshot(now time.Time) (string, string, time.Time, time.Time) {
	a.controlPlaneMu.RLock()
	state := a.controlPlane
	a.controlPlaneMu.RUnlock()

	if a.isClaimed() {
		if !state.LastFailureAt.IsZero() &&
			(state.LastSuccessAt.IsZero() || state.LastFailureAt.After(state.LastSuccessAt)) &&
			now.Sub(state.LastFailureAt) <= localControlPlaneDegradedWindow {
			message := firstNonEmpty(state.LastFailureMsg, "Edge agent is not connected to PrintFarmHQ SaaS.")
			return localControlPlaneStatusNotConnected, message, state.LastSuccessAt, state.LastFailureAt
		}
		return localControlPlaneStatusConnected, "Connected to PrintFarmHQ SaaS.", state.LastSuccessAt, state.LastFailureAt
	}

	if state.AuthRevoked {
		return localControlPlaneStatusRenewKey, firstNonEmpty(
			state.LastFailureMsg,
			"The current API key was rejected. Paste a new key to reconnect.",
		), state.LastSuccessAt, state.LastFailureAt
	}

	if state.APIKeySeen {
		return localControlPlaneStatusNotConnected, firstNonEmpty(
			state.LastFailureMsg,
			"Edge agent is not connected to PrintFarmHQ SaaS. Check connectivity or paste a valid API key.",
		), state.LastSuccessAt, state.LastFailureAt
	}

	return localControlPlaneStatusNotConnected, "Edge agent is NOT connected to control plane SaaS. Paste a valid API key to continue.", state.LastSuccessAt, state.LastFailureAt
}

func (a *agent) currentControlPlaneURL() string {
	bootstrap := a.snapshotBootstrap()
	return firstNonEmpty(strings.TrimSpace(bootstrap.ControlPlaneURL), strings.TrimSpace(a.cfg.StartupControlPlaneURL))
}

func isControlPlaneConnectedStatus(status string) bool {
	return strings.TrimSpace(status) == localControlPlaneStatusConnected
}

func isControlPlaneAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errEdgeAuthRevoked) {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "request failed 401") ||
		strings.Contains(msg, "request failed 403") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden")
}
