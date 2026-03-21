package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bambucamera "printfarmhq/edge-agent/internal/bambu/cameraruntime"
	bambustore "printfarmhq/edge-agent/internal/store"
)

type fakeBambuCameraRuntime struct {
	ensureFn func(ctx context.Context, req bambucamera.EnsureRequest) (bambucamera.Handle, error)
}

func (f fakeBambuCameraRuntime) Ensure(ctx context.Context, req bambucamera.EnsureRequest) (bambucamera.Handle, error) {
	if f.ensureFn == nil {
		return bambucamera.Handle{}, errors.New("ensure not implemented")
	}
	return f.ensureFn(ctx, req)
}

func TestLocalObservationsEndpointReturnsNotConnectedPayload(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.StartupControlPlaneURL = "http://localhost:8000"
	a.localObservations.upsertDiscoveryCandidates([]discoveryCandidateResult{
		{
			AdapterFamily:       "moonraker",
			EndpointURL:         "http://192.168.1.44:7125",
			Status:              "reachable",
			CurrentPrinterState: "idle",
			CurrentJobState:     "pending",
			DetectedPrinterName: "Forge 44",
			DetectedModelHint:   "Voron",
			Evidence: map[string]any{
				"discovery_source": "moonraker",
			},
		},
	}, time.Now().UTC())

	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/local/observations", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload localObservationsResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}

	if payload.Agent.ControlPlaneStatus != localControlPlaneStatusNotConnected {
		t.Fatalf("control_plane_status = %q, want %q", payload.Agent.ControlPlaneStatus, localControlPlaneStatusNotConnected)
	}
	if payload.Agent.ControlPlaneURL != "http://localhost:8000" {
		t.Fatalf("control_plane_url = %q, want http://localhost:8000", payload.Agent.ControlPlaneURL)
	}
	if len(payload.Printers) != 1 {
		t.Fatalf("printer count = %d, want 1", len(payload.Printers))
	}
	if payload.Printers[0].Group != localObservationGroupAvailable {
		t.Fatalf("group = %q, want %q", payload.Printers[0].Group, localObservationGroupAvailable)
	}
}

func TestLocalControlPlaneSnapshotReturnsRenewKeyWhenAuthRevoked(t *testing.T) {
	a := newTestAgent(t)
	a.recordControlPlaneAPIKeySeen()
	a.recordControlPlaneAuthRevoked("Paste a new API key.")

	status, message, _, _ := a.localControlPlaneSnapshot(time.Now().UTC())
	if status != localControlPlaneStatusRenewKey {
		t.Fatalf("status = %q, want %q", status, localControlPlaneStatusRenewKey)
	}
	if !strings.Contains(message, "API key") {
		t.Fatalf("message = %q, want api key guidance", message)
	}
}

func TestLocalControlPlaneSnapshotReturnsConnectedAfterSuccess(t *testing.T) {
	a := newTestAgent(t)
	a.mu.Lock()
	a.claimed = true
	a.bootstrap = bootstrapConfig{
		ControlPlaneURL: "http://localhost:8000",
		SaaSAPIKey:      "pfh_edge_123",
		AgentID:         "edge_123",
	}
	a.mu.Unlock()
	a.recordControlPlaneSuccess()

	status, _, _, _ := a.localControlPlaneSnapshot(time.Now().UTC())
	if status != localControlPlaneStatusConnected {
		t.Fatalf("status = %q, want %q", status, localControlPlaneStatusConnected)
	}
}

func TestLocalObservationRoutesRejectNonLoopback(t *testing.T) {
	a := newTestAgent(t)
	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/local/observations", nil)
	req.RemoteAddr = "192.0.2.9:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestLocalWebUIRootServesHTML(t *testing.T) {
	a := newTestAgent(t)
	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("content-type = %q, want html", got)
	}
	if !strings.Contains(rec.Body.String(), "PrintFarmHQ Edge Agent") {
		t.Fatalf("body missing web ui title")
	}
}

func TestLocalObservationScanEndpointReturnsInProgressWhenBusy(t *testing.T) {
	a := newTestAgent(t)
	if !a.beginDiscoveryRun() {
		t.Fatalf("expected discovery lock acquisition")
	}
	defer a.endDiscoveryRun()

	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/local/observations/scan", strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	var payload localScanTriggerResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if payload.Status != "in_progress" {
		t.Fatalf("status = %q, want in_progress", payload.Status)
	}
}

func TestLocalObservationScanEndpointReturnsStartedWhenIdle(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.EnableKlipper = false
	a.cfg.EnableBambu = false
	a.cfg.DiscoveryAllowedAdapters = nil

	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/local/observations/scan", strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	var payload localScanTriggerResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if payload.Status != "started" {
		t.Fatalf("status = %q, want started", payload.Status)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := a.localObservations.scanStatus()
		if !status.LastStartedAt.IsZero() && !status.LastFinishedAt.IsZero() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected scan to start and finish")
}

func TestLocalControlPlaneConnectEndpointClaimsAgent(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.StartupControlPlaneURL = "http://placeholder"

	saasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/edge/agents/claim"):
			writeJSON(w, http.StatusOK, claimResponse{
				AgentID:                 "edge_ui_1",
				OrgID:                   7,
				SchemaVersion:           agentSchemaVersion,
				SupportedSchemaVersions: []int{agentSchemaVersion},
			})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_ui_1/bindings"):
			writeJSON(w, http.StatusOK, bindingsResponse{AgentID: "edge_ui_1", Bindings: []edgeBinding{}})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_ui_1/config-commands"):
			writeJSON(w, http.StatusOK, configCommandsResponse{Commands: []configCommandItem{}})
		case strings.HasSuffix(r.URL.Path, "/edge/agents/edge_ui_1/desired-state"):
			w.Header().Set("ETag", "etag-empty")
			writeJSON(w, http.StatusOK, desiredStateResponse{SchemaVersion: agentSchemaVersion, States: []desiredStateItem{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer saasSrv.Close()
	a.cfg.StartupControlPlaneURL = saasSrv.URL

	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/local/control-plane/connect", strings.NewReader(`{"api_key":"pfh_edge_test"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	if !a.isClaimed() {
		t.Fatalf("expected agent to be claimed")
	}
	if got := a.snapshotBootstrap().AgentID; got != "edge_ui_1" {
		t.Fatalf("agent_id = %q, want edge_ui_1", got)
	}
}

func TestSetupRootRedirectsToLocalWebUIURL(t *testing.T) {
	a := newTestAgent(t)
	a.setLocalWebUIURL("http://127.0.0.1:54123/")
	mux := http.NewServeMux()
	a.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "http://127.0.0.1:54123/" {
		t.Fatalf("location = %q, want local web ui url", got)
	}
}

func TestSetupStatusIncludesLocalWebUIPort(t *testing.T) {
	a := newTestAgent(t)
	a.setLocalWebUIURL("http://127.0.0.1:54123/")
	req := httptest.NewRequest(http.MethodGet, "/setup/status", nil)
	rec := httptest.NewRecorder()

	a.handleSetupStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if payload["local_web_ui_port"] != "54123" {
		t.Fatalf("local_web_ui_port = %v, want 54123", payload["local_web_ui_port"])
	}
}

func TestLocalObservationStoreMarksRuntimeErrorGroup(t *testing.T) {
	a := newTestAgent(t)
	now := time.Now().UTC()
	a.localObservations.upsertRuntimeSuccess(
		edgeBinding{PrinterID: 1, AdapterFamily: "moonraker", EndpointURL: "http://192.168.1.90:7125"},
		bindingSnapshot{
			PrinterState:      "error",
			JobState:          "failed",
			TelemetrySource:   "moonraker",
			DetectedName:      "Forge 90",
			DetectedModelHint: "RatRig",
		},
		currentStateItem{
			PrinterID:           1,
			CurrentPrinterState: "error",
			CurrentJobState:     "failed",
		},
		now,
	)

	payload := a.localObservations.snapshot(localAgentStatus{}, now)
	if len(payload.Printers) != 1 {
		t.Fatalf("printer count = %d, want 1", len(payload.Printers))
	}
	if payload.Printers[0].Group != localObservationGroupError {
		t.Fatalf("group = %q, want %q", payload.Printers[0].Group, localObservationGroupError)
	}
}

func TestLocalObservationStoreMarksPrintingPrinterBusy(t *testing.T) {
	a := newTestAgent(t)
	now := time.Now().UTC()
	a.localObservations.upsertRuntimeSuccess(
		edgeBinding{PrinterID: 1, AdapterFamily: "moonraker", EndpointURL: "http://192.168.1.91:7125"},
		bindingSnapshot{
			PrinterState:      "printing",
			JobState:          "printing",
			TelemetrySource:   "moonraker",
			DetectedName:      "Forge 91",
			DetectedModelHint: "Voron",
		},
		currentStateItem{
			PrinterID:           1,
			CurrentPrinterState: "printing",
			CurrentJobState:     "printing",
		},
		now,
	)

	payload := a.localObservations.snapshot(localAgentStatus{}, now)
	if len(payload.Printers) != 1 {
		t.Fatalf("printer count = %d, want 1", len(payload.Printers))
	}
	if payload.Printers[0].Group != localObservationGroupBusy {
		t.Fatalf("group = %q, want %q", payload.Printers[0].Group, localObservationGroupBusy)
	}
	if payload.Summary.BusyCount != 1 {
		t.Fatalf("busy_count = %d, want 1", payload.Summary.BusyCount)
	}
}

func TestLocalObservationStoreKeepsRecentlyDisconnectedWithinRetention(t *testing.T) {
	a := newTestAgent(t)
	now := time.Now().UTC()
	a.localObservations.upsertDiscoveryCandidates([]discoveryCandidateResult{
		{
			AdapterFamily:       "moonraker",
			EndpointURL:         "http://192.168.1.33:7125",
			Status:              "reachable",
			CurrentPrinterState: "idle",
			CurrentJobState:     "pending",
			DetectedPrinterName: "Forge 33",
			Evidence: map[string]any{
				"discovery_source": "moonraker",
			},
		},
	}, now.Add(-1*time.Minute))
	a.localObservations.upsertRuntimeFailure(
		edgeBinding{PrinterID: 33, AdapterFamily: "moonraker", EndpointURL: "http://192.168.1.33:7125"},
		currentStateItem{
			PrinterID:           33,
			LastErrorCode:       "connectivity_error",
			LastErrorMessage:    "dial tcp timeout",
			CurrentPrinterState: "idle",
		},
		now,
	)

	payload := a.localObservations.snapshot(localAgentStatus{}, now)
	if len(payload.Printers) != 1 {
		t.Fatalf("printer count = %d, want 1", len(payload.Printers))
	}
	if payload.Printers[0].Group != localObservationGroupRecentlyDisconnected {
		t.Fatalf("group = %q, want %q", payload.Printers[0].Group, localObservationGroupRecentlyDisconnected)
	}
}

func TestLocalObservationStorePrunesStaleDisconnected(t *testing.T) {
	a := newTestAgent(t)
	now := time.Now().UTC()
	a.localObservations.upsertDiscoveryCandidates([]discoveryCandidateResult{
		{
			AdapterFamily:       "moonraker",
			EndpointURL:         "http://192.168.1.77:7125",
			Status:              "reachable",
			CurrentPrinterState: "idle",
			CurrentJobState:     "pending",
			DetectedPrinterName: "Forge 77",
			Evidence: map[string]any{
				"discovery_source": "moonraker",
			},
		},
	}, now.Add(-20*time.Minute))
	a.localObservations.upsertRuntimeFailure(
		edgeBinding{PrinterID: 77, AdapterFamily: "moonraker", EndpointURL: "http://192.168.1.77:7125"},
		currentStateItem{
			PrinterID:        77,
			LastErrorCode:    "connectivity_error",
			LastErrorMessage: "dial tcp timeout",
		},
		now.Add(-19*time.Minute),
	)

	payload := a.localObservations.snapshot(localAgentStatus{}, now)
	if len(payload.Printers) != 0 {
		t.Fatalf("printer count = %d, want 0", len(payload.Printers))
	}
}

func TestStartLocalWebUIServerCascadesToFallbackPort(t *testing.T) {
	// Occupy the primary port when available so the server must fall back.
	primary, err := net.Listen("tcp", "127.0.0.1:"+localWebUIDefaultPort)
	if err != nil {
		t.Logf("primary port %s already occupied externally; validating cascade behavior against the live environment", localWebUIDefaultPort)
	} else {
		defer primary.Close()
	}

	fallbackAvailable := false
	fallbackProbe, err := net.Listen("tcp", "127.0.0.1:"+localWebUIFallbackPort)
	if err == nil {
		fallbackAvailable = true
		_ = fallbackProbe.Close()
	}

	a := newTestAgent(t)
	a.cfg.LocalUIBindAddr = "" // no explicit override — cascade should kick in

	srv, _, port, err := a.startLocalWebUIServer()
	if err != nil {
		t.Fatalf("startLocalWebUIServer failed: %v", err)
	}
	defer srv.Close()

	if fallbackAvailable {
		if port != localWebUIFallbackPort {
			t.Fatalf("port = %q, want fallback %q", port, localWebUIFallbackPort)
		}
		return
	}

	if port == localWebUIDefaultPort {
		t.Fatalf("port = %q, want a non-default cascade target when default is unavailable", port)
	}
}

func TestStartLocalWebUIServerUsesDefaultPort(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:"+localWebUIDefaultPort)
	if err != nil {
		t.Skipf("default local web ui port %s is already in use: %v", localWebUIDefaultPort, err)
	}
	_ = probe.Close()

	a := newTestAgent(t)
	a.cfg.LocalUIBindAddr = "" // no explicit override

	srv, _, port, err := a.startLocalWebUIServer()
	if err != nil {
		t.Fatalf("startLocalWebUIServer failed: %v", err)
	}
	defer srv.Close()

	if port != localWebUIDefaultPort {
		t.Fatalf("port = %q, want default %q", port, localWebUIDefaultPort)
	}
}

func TestStartLocalWebUIServerRespectsExplicitBindAddr(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.LocalUIBindAddr = "127.0.0.1:0" // explicit random port

	srv, _, port, err := a.startLocalWebUIServer()
	if err != nil {
		t.Fatalf("startLocalWebUIServer failed: %v", err)
	}
	defer srv.Close()

	// Should NOT be one of the cascade ports — it's a random ephemeral port.
	if port == localWebUIDefaultPort || port == localWebUIFallbackPort {
		t.Fatalf("port = %q, expected random ephemeral port when explicit bind addr is set", port)
	}
}

func TestLocalObservationStoreSuppressesBambuDiscoveryOnlyState(t *testing.T) {
	a := newTestAgent(t)
	now := time.Now().UTC()
	a.localObservations.upsertDiscoveryCandidates([]discoveryCandidateResult{
		{
			AdapterFamily:       "bambu",
			EndpointURL:         "bambu://serial-123",
			Status:              "reachable",
			CurrentPrinterState: "idle",
			CurrentJobState:     "pending",
			DetectedPrinterName: "Forge 123",
			Evidence: map[string]any{
				"discovery_source": discoverySourceBambuLAN,
				"ip_address":       "192.168.1.123",
			},
		},
	}, now)

	payload := a.localObservations.snapshot(localAgentStatus{}, now)
	if len(payload.Printers) != 1 {
		t.Fatalf("printer count = %d, want 1", len(payload.Printers))
	}
	if payload.Printers[0].CurrentPrinterState != "" {
		t.Fatalf("current_printer_state = %q, want empty", payload.Printers[0].CurrentPrinterState)
	}
	if payload.Printers[0].StatusDetailLevel != localObservationDetailDiscoveryBasic {
		t.Fatalf("status_detail_level = %q, want %q", payload.Printers[0].StatusDetailLevel, localObservationDetailDiscoveryBasic)
	}
}

func TestLocalPrinterCameraRouteProxiesMoonrakerStream(t *testing.T) {
	a := newTestAgent(t)

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/webcams/list":
			writeJSON(w, http.StatusOK, map[string]any{
				"webcams": []map[string]any{
					{
						"name":           "Default",
						"enabled":        true,
						"default_camera": true,
						"stream_url":     "/webcam/?action=stream",
						"snapshot_url":   "/webcam/?action=snapshot",
					},
				},
			})
		case "/webcam/":
			if r.URL.Query().Get("action") != "stream" {
				t.Fatalf("unexpected webcam action: %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
			_, _ = w.Write([]byte("--frame\r\nContent-Type: image/jpeg\r\n\r\nframe-body\r\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	a.bindings[22] = edgeBinding{PrinterID: 22, AdapterFamily: "moonraker", EndpointURL: moonrakerSrv.URL}

	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/local/printers/22/camera/stream", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "multipart/x-mixed-replace") {
		t.Fatalf("content-type = %q, want mjpeg stream", got)
	}
	if !strings.Contains(rec.Body.String(), "frame-body") {
		t.Fatalf("body missing proxied frame payload")
	}
}

func TestFetchMoonrakerPrimaryWebcamFallsBackToMonitorSnapshot(t *testing.T) {
	a := newTestAgent(t)

	moonrakerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/webcams/list":
			writeJSON(w, http.StatusOK, map[string]any{
				"result": map[string]any{
					"webcams": []map[string]any{},
				},
			})
		case "/server/files/camera/monitor.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write([]byte{0xff, 0xd8, 0xff, 0xd9})
		default:
			http.NotFound(w, r)
		}
	}))
	defer moonrakerSrv.Close()

	webcam, err := a.fetchMoonrakerPrimaryWebcam(context.Background(), moonrakerSrv.URL)
	if err != nil {
		t.Fatalf("fetchMoonrakerPrimaryWebcam failed: %v", err)
	}
	if webcam.SnapshotURL == "" {
		t.Fatalf("expected snapshot fallback url")
	}
	if !strings.Contains(webcam.SnapshotURL, "/server/files/camera/monitor.jpg?ts={ts}") {
		t.Fatalf("snapshot fallback url = %q, want monitor.jpg template", webcam.SnapshotURL)
	}
}

func TestLocalPrinterCameraRouteRejectsUnsupportedAdapter(t *testing.T) {
	a := newTestAgent(t)
	a.bindings[9] = edgeBinding{PrinterID: 9, AdapterFamily: "bambu", EndpointURL: "bambu://printer_9"}

	mux := http.NewServeMux()
	a.registerLocalWebUIRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/local/printers/9/camera/stream", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestBuildClaimCapabilitiesIncludesLocalWebUIFields(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.DiscoveryAllowedAdapters = []string{"moonraker", "bambu"}
	a.setLocalWebUIURL("http://127.0.0.1:18800/")

	capabilities := a.buildClaimCapabilities()
	if capabilities["local_web_ui_url"] != "http://127.0.0.1:18800/" {
		t.Fatalf("local_web_ui_url = %q, want http://127.0.0.1:18800/", capabilities["local_web_ui_url"])
	}
	if capabilities["local_web_ui_port"] != "18800" {
		t.Fatalf("local_web_ui_port = %q, want 18800", capabilities["local_web_ui_port"])
	}
}

func TestBambuCameraRTSPCandidatesUseLANCredentials(t *testing.T) {
	urls, err := bambuCameraRTSPCandidates(bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		AccessCode: "abc123",
	})
	if err != nil {
		t.Fatalf("bambuCameraRTSPCandidates failed: %v", err)
	}
	if len(urls) != 3 {
		t.Fatalf("candidate count = %d, want 3", len(urls))
	}
	if urls[0] != "rtsp://bblp:abc123@192.168.1.88:6000/streaming/live/1" {
		t.Fatalf("first rtsp url = %q, want rtsp://...:6000/streaming/live/1", urls[0])
	}
	if strings.Contains(strings.Join(urls, ","), ":322/") {
		t.Fatalf("rtsp candidates = %#v, did not expect port 322 fallback", urls)
	}
}

func TestResolveBambuCameraSourcePrefersHelperByDefault(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.BambuCameraHelperMJPEGURLTemplate = "http://127.0.0.1:1984/api/stream.mjpeg?src={serial}"
	a.cfg.BambuCameraRTSPFallbackEnabled = false

	originalHelperProber := bambuCameraHelperProber
	originalCandidateProber := bambuCameraCandidateProber
	t.Cleanup(func() {
		bambuCameraHelperProber = originalHelperProber
		bambuCameraCandidateProber = originalCandidateProber
	})

	bambuCameraHelperProber = func(context.Context, string) error {
		return nil
	}
	bambuCameraCandidateProber = func(context.Context, string) error {
		t.Fatalf("RTSP fallback should not run when helper is reachable")
		return nil
	}

	source, err := a.resolveBambuCameraSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "abc123",
	})
	if err != nil {
		t.Fatalf("resolveBambuCameraSource failed: %v", err)
	}
	if source.Kind != bambuCameraSourceKindHelper {
		t.Fatalf("source kind = %q, want %q", source.Kind, bambuCameraSourceKindHelper)
	}
	if source.URL != "http://127.0.0.1:1984/api/stream.mjpeg?src=01P09C470101190" {
		t.Fatalf("source url = %q, want helper url", source.URL)
	}
}

func TestResolveBambuCameraSourceRequiresHelperWhenFallbackDisabled(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.BambuCameraHelperMJPEGURLTemplate = ""
	a.cfg.BambuCameraRTSPFallbackEnabled = false

	_, err := a.resolveBambuCameraSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "abc123",
	})
	if err == nil {
		t.Fatalf("expected helper-required error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_helper_required") {
		t.Fatalf("error = %q, want helper-required reason", err)
	}
}

func TestResolveBambuCameraSourceReturnsHelperUnreachableWhenFallbackDisabled(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.BambuCameraHelperMJPEGURLTemplate = "http://127.0.0.1:1984/api/stream.mjpeg?src={serial}"
	a.cfg.BambuCameraRTSPFallbackEnabled = false

	originalHelperProber := bambuCameraHelperProber
	t.Cleanup(func() {
		bambuCameraHelperProber = originalHelperProber
	})
	bambuCameraHelperProber = func(context.Context, string) error {
		return errors.New("dial tcp 127.0.0.1:1984: connect: connection refused")
	}

	_, err := a.resolveBambuCameraSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "abc123",
	})
	if err == nil {
		t.Fatalf("expected helper-unreachable error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_helper_unreachable") {
		t.Fatalf("error = %q, want helper-unreachable reason", err)
	}
}

func TestResolveBambuCameraSourceRTSPFallbackRedactsCandidateErrors(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.BambuCameraHelperMJPEGURLTemplate = ""
	a.cfg.BambuCameraRTSPFallbackEnabled = true

	originalCandidateProber := bambuCameraCandidateProber
	t.Cleanup(func() {
		bambuCameraCandidateProber = originalCandidateProber
	})
	bambuCameraCandidateProber = func(_ context.Context, candidate string) error {
		if strings.Contains(candidate, ":322/") {
			t.Fatalf("unexpected 322 fallback candidate: %q", candidate)
		}
		return errors.New("connection refused")
	}

	_, err := a.resolveBambuCameraSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "secret-access-code",
	})
	if err == nil {
		t.Fatalf("expected RTSP fallback probe error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_rtsp_probe_failed") {
		t.Fatalf("error = %q, want rtsp probe failure", err)
	}
	if strings.Contains(err.Error(), "secret-access-code") {
		t.Fatalf("error leaked access code: %q", err)
	}
	if strings.Contains(err.Error(), ":322/") {
		t.Fatalf("error should not mention removed 322 fallback: %q", err)
	}
}

func TestBambuCameraHelperMJPEGURLUsesTemplatePlaceholders(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.BambuCameraHelperMJPEGURLTemplate = "http://127.0.0.1:1984/api/stream.mjpeg?src={serial}&host={host}"

	got := a.bambuCameraHelperMJPEGURL(bambustore.BambuLANCredentials{
		Host:   "192.168.1.88",
		Serial: "01P09C470101190",
		Name:   "Forge#1",
		Model:  "P1S",
	})
	want := "http://127.0.0.1:1984/api/stream.mjpeg?src=01P09C470101190&host=192.168.1.88"
	if got != want {
		t.Fatalf("helper url = %q, want %q", got, want)
	}
}

func TestParseInternalBambuCameraPath(t *testing.T) {
	serial, resource, ok := parseInternalBambuCameraPath("/internal/camera/v1/bambu/01P00C511601082/stream.mjpeg")
	if !ok {
		t.Fatalf("expected path to parse")
	}
	if serial != "01P00C511601082" || resource != "stream.mjpeg" {
		t.Fatalf("got serial=%q resource=%q", serial, resource)
	}
}

func TestInternalBambuCameraRouteProxiesRuntimeStream(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.SetupBindAddr = "127.0.0.1:18090"
	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "01P00C511601082",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
		Model:      "C12",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "multipart/x-mixed-replace;boundary=frame")
		_, _ = w.Write([]byte("--frame\r\nContent-Type: image/jpeg\r\n\r\nframe-body\r\n"))
	}))
	defer upstream.Close()

	originalOpenManagedReader := openManagedBambuMJPEGReader
	t.Cleanup(func() {
		openManagedBambuMJPEGReader = originalOpenManagedReader
	})
	openManagedBambuMJPEGReader = func(context.Context, bambucamera.Handle) (io.ReadCloser, error) {
		resp, err := http.Get(upstream.URL)
		if err != nil {
			t.Fatalf("http.Get upstream failed: %v", err)
		}
		return resp.Body, nil
	}

	a.bambuCameraRuntime = fakeBambuCameraRuntime{
		ensureFn: func(_ context.Context, req bambucamera.EnsureRequest) (bambucamera.Handle, error) {
			if req.Serial != "01P00C511601082" {
				t.Fatalf("serial = %q, want printer serial", req.Serial)
			}
			return bambucamera.Handle{
				Serial:            req.Serial,
				Host:              req.Host,
				AccessCode:        req.AccessCode,
				Support:           bambucamera.SupportInfo{Status: bambucamera.SupportStatusTestedSupported, DirectlyTested: true},
				PluginDir:         "/tmp/plugins",
				PluginLibraryPath: "/tmp/libBambuSource.dylib",
			}, nil
		},
	}

	mux := http.NewServeMux()
	a.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/internal/camera/v1/bambu/01P00C511601082/stream.mjpeg", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "frame-body") {
		t.Fatalf("expected proxied stream body")
	}
}

func TestInternalBambuCameraHealthReturnsUnavailableReason(t *testing.T) {
	a := newTestAgent(t)
	a.cfg.SetupBindAddr = "127.0.0.1:18090"
	store, err := bambustore.NewBambuLANCredentialsFileStore(filepath.Join(t.TempDir(), "bambu", "lan_credentials.json"))
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), bambustore.BambuLANCredentials{
		Serial:     "serial-1",
		Host:       "192.168.100.200",
		AccessCode: "87654321",
		Model:      "X1C",
	}); err != nil {
		t.Fatalf("store.Upsert failed: %v", err)
	}
	a.bambuLANStore = store
	a.bambuCameraRuntime = fakeBambuCameraRuntime{
		ensureFn: func(context.Context, bambucamera.EnsureRequest) (bambucamera.Handle, error) {
			return bambucamera.Handle{}, errors.New("bambu_camera_family_unverified: directly tested Bambu camera support currently exists only for P1S (model=X1C)")
		},
	}

	mux := http.NewServeMux()
	a.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/internal/camera/v1/bambu/serial-1/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var payload map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode health payload failed: %v", err)
	}
	if payload["available"] != false {
		t.Fatalf("available = %v, want false", payload["available"])
	}
	if !strings.Contains(payload["reason_unavailable"].(string), "bambu_camera_family_unverified") {
		t.Fatalf("reason_unavailable = %v, want family-unverified", payload["reason_unavailable"])
	}
}
