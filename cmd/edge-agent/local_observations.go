package main

import (
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	localObservationGroupAvailable            = "available"
	localObservationGroupBusy                 = "busy"
	localObservationGroupError                = "error"
	localObservationGroupRecentlyDisconnected = "recently_disconnected"

	localObservationSourceRuntime    = "local_runtime"
	localObservationSourceDiscovery  = "discovery"
	localObservationSourceHistorical = "historical"

	localObservationDetailRuntime        = "runtime"
	localObservationDetailDiscoveryBasic = "discovery_basic"
	localObservationDetailHistorical     = "historical"

	localObservationRetention                = 15 * time.Minute
	localObservationDiscoveryFreshWindow     = 2 * time.Minute
	localObservationRuntimeDetailFreshWindow = 2 * time.Minute
	localObservationRuntimeErrorFreshWindow  = 30 * time.Second
)

type localObservationsResponse struct {
	Agent    localAgentStatus          `json:"agent"`
	Summary  localObservationSummary   `json:"summary"`
	Printers []localPrinterObservation `json:"printers"`
}

type localAgentStatus struct {
	Version                   string          `json:"version"`
	Claimed                   bool            `json:"claimed"`
	ControlPlaneStatus        string          `json:"control_plane_status"`
	ControlPlaneMessage       string          `json:"control_plane_message,omitempty"`
	LastControlPlaneSuccessAt time.Time       `json:"last_control_plane_success_at,omitempty"`
	LastControlPlaneFailureAt time.Time       `json:"last_control_plane_failure_at,omitempty"`
	ControlPlaneURL           string          `json:"control_plane_url,omitempty"`
	Scan                      localScanStatus `json:"scan"`
}

type localScanStatus struct {
	Running        bool      `json:"running"`
	Source         string    `json:"source,omitempty"`
	LastStartedAt  time.Time `json:"last_started_at,omitempty"`
	LastFinishedAt time.Time `json:"last_finished_at,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
}

type localObservationSummary struct {
	AvailableCount            int `json:"available_count"`
	BusyCount                 int `json:"busy_count"`
	ErrorCount                int `json:"error_count"`
	RecentlyDisconnectedCount int `json:"recently_disconnected_count"`
	TotalCount                int `json:"total_count"`
}

type localPrinterObservation struct {
	AdapterFamily       string    `json:"adapter_family"`
	EndpointURL         string    `json:"endpoint_url"`
	DisplayName         string    `json:"display_name"`
	ModelHint           string    `json:"model_hint,omitempty"`
	Group               string    `json:"group"`
	ConnectivityStatus  string    `json:"connectivity_status"`
	CurrentPrinterState string    `json:"current_printer_state,omitempty"`
	CurrentJobState     string    `json:"current_job_state,omitempty"`
	TelemetrySource     string    `json:"telemetry_source,omitempty"`
	ObservationSource   string    `json:"observation_source"`
	ObservedHost        string    `json:"observed_host,omitempty"`
	LastSeenAt          time.Time `json:"last_seen_at"`
	LastReachableAt     time.Time `json:"last_reachable_at,omitempty"`
	ConnectivityError   string    `json:"connectivity_error,omitempty"`
	LastErrorCode       string    `json:"last_error_code,omitempty"`
	LastErrorMessage    string    `json:"last_error_message,omitempty"`
	ManualIntervention  string    `json:"manual_intervention,omitempty"`
	StatusDetailLevel   string    `json:"status_detail_level"`
}

type localObservationStore struct {
	mu       sync.RWMutex
	printers map[string]*localObservationRecord
	scan     localScanStatus
}

type localObservationRecord struct {
	AdapterFamily   string
	EndpointURL     string
	DisplayName     string
	ModelHint       string
	ObservedHost    string
	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	LastReachableAt time.Time
	Discovery       *localDiscoveryObservation
	Runtime         *localRuntimeObservation
}

type localDiscoveryObservation struct {
	ObservedAt          time.Time
	Status              string
	ConnectivityError   string
	CurrentPrinterState string
	CurrentJobState     string
	TelemetrySource     string
	ObservationSource   string
	StatusDetailLevel   string
	DisplayName         string
	ModelHint           string
	ObservedHost        string
	MacAddress          string
}

type localRuntimeObservation struct {
	ObservedAt          time.Time
	ConnectivityStatus  string
	CurrentPrinterState string
	CurrentJobState     string
	TelemetrySource     string
	ObservationSource   string
	LastErrorCode       string
	LastErrorMessage    string
	ManualIntervention  string
	DisplayName         string
	ModelHint           string
}

func newLocalObservationStore() *localObservationStore {
	return &localObservationStore{
		printers: make(map[string]*localObservationRecord),
	}
}

func (s *localObservationStore) markScanStarted(source string, startedAt time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scan.Running = true
	s.scan.Source = strings.TrimSpace(source)
	s.scan.LastStartedAt = startedAt.UTC()
	s.scan.LastError = ""
}

func (s *localObservationStore) markScanFinished(source string, finishedAt time.Time, err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scan.Running = false
	s.scan.Source = strings.TrimSpace(source)
	s.scan.LastFinishedAt = finishedAt.UTC()
	if err != nil {
		s.scan.LastError = strings.TrimSpace(err.Error())
	} else {
		s.scan.LastError = ""
	}
}

func (s *localObservationStore) scanStatus() localScanStatus {
	if s == nil {
		return localScanStatus{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scan
}

func (s *localObservationStore) upsertDiscoveryCandidates(candidates []discoveryCandidateResult, observedAt time.Time) {
	if s == nil || len(candidates) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, candidate := range candidates {
		status := strings.ToLower(strings.TrimSpace(candidate.Status))
		if status != "reachable" && status != "unreachable" && status != "lost" {
			continue
		}
		adapterFamily := normalizeAdapterFamily(candidate.AdapterFamily)
		endpointURL := strings.TrimSpace(candidate.EndpointURL)
		if adapterFamily == "" || endpointURL == "" {
			continue
		}

		key := localObservationKey(adapterFamily, endpointURL)
		record := s.ensureRecordLocked(key, adapterFamily, endpointURL, observedAt)

		source := discoveryCandidateSource(candidate)
		printerState := strings.TrimSpace(candidate.CurrentPrinterState)
		jobState := strings.TrimSpace(candidate.CurrentJobState)
		if shouldSuppressDiscoveryState(adapterFamily, source) {
			printerState = ""
			jobState = ""
		}

		displayName := strings.TrimSpace(candidate.DetectedPrinterName)
		modelHint := strings.TrimSpace(candidate.DetectedModelHint)
		observedHost := localObservationHostFromCandidate(candidate)
		telemetrySource := strings.TrimSpace(source)
		if telemetrySource == "" {
			telemetrySource = adapterFamily
		}

		record.Discovery = &localDiscoveryObservation{
			ObservedAt:          observedAt.UTC(),
			Status:              status,
			ConnectivityError:   strings.TrimSpace(candidate.ConnectivityError),
			CurrentPrinterState: printerState,
			CurrentJobState:     jobState,
			TelemetrySource:     telemetrySource,
			ObservationSource:   localObservationSourceDiscovery,
			StatusDetailLevel:   localObservationDetailDiscoveryBasic,
			DisplayName:         displayName,
			ModelHint:           modelHint,
			ObservedHost:        observedHost,
			MacAddress:          macAddressFromEvidence(candidate.Evidence),
		}
		record.LastSeenAt = observedAt.UTC()
		if status == "reachable" {
			record.LastReachableAt = observedAt.UTC()
		}
		if displayName != "" {
			record.DisplayName = displayName
		}
		if modelHint != "" {
			record.ModelHint = modelHint
		}
		if observedHost != "" {
			record.ObservedHost = observedHost
		}
	}

	s.pruneLocked(observedAt.UTC())
}

func (s *localObservationStore) upsertRuntimeSuccess(
	binding edgeBinding,
	snapshot bindingSnapshot,
	current currentStateItem,
	observedAt time.Time,
) {
	if s == nil {
		return
	}
	adapterFamily := normalizeAdapterFamily(binding.AdapterFamily)
	endpointURL := strings.TrimSpace(binding.EndpointURL)
	if adapterFamily == "" || endpointURL == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := localObservationKey(adapterFamily, endpointURL)
	record := s.ensureRecordLocked(key, adapterFamily, endpointURL, observedAt)
	record.Runtime = &localRuntimeObservation{
		ObservedAt:          observedAt.UTC(),
		ConnectivityStatus:  "reachable",
		CurrentPrinterState: strings.TrimSpace(snapshot.PrinterState),
		CurrentJobState:     strings.TrimSpace(snapshot.JobState),
		TelemetrySource:     strings.TrimSpace(snapshot.TelemetrySource),
		ObservationSource:   localObservationSourceRuntime,
		LastErrorCode:       strings.TrimSpace(current.LastErrorCode),
		LastErrorMessage:    strings.TrimSpace(current.LastErrorMessage),
		ManualIntervention:  strings.TrimSpace(snapshot.ManualIntervention),
		DisplayName:         strings.TrimSpace(snapshot.DetectedName),
		ModelHint:           strings.TrimSpace(snapshot.DetectedModelHint),
	}
	record.LastSeenAt = observedAt.UTC()
	record.LastReachableAt = observedAt.UTC()
	if snapshot.DetectedName != "" {
		record.DisplayName = strings.TrimSpace(snapshot.DetectedName)
	}
	if snapshot.DetectedModelHint != "" {
		record.ModelHint = strings.TrimSpace(snapshot.DetectedModelHint)
	}
	if host := localObservationHostFromEndpoint(endpointURL); host != "" {
		record.ObservedHost = host
	}
}

func (s *localObservationStore) upsertRuntimeFailure(binding edgeBinding, current currentStateItem, observedAt time.Time) {
	if s == nil {
		return
	}
	adapterFamily := normalizeAdapterFamily(binding.AdapterFamily)
	endpointURL := strings.TrimSpace(binding.EndpointURL)
	if adapterFamily == "" || endpointURL == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := localObservationKey(adapterFamily, endpointURL)
	record := s.ensureRecordLocked(key, adapterFamily, endpointURL, observedAt)
	record.Runtime = &localRuntimeObservation{
		ObservedAt:          observedAt.UTC(),
		ConnectivityStatus:  "unreachable",
		CurrentPrinterState: strings.TrimSpace(current.CurrentPrinterState),
		CurrentJobState:     strings.TrimSpace(current.CurrentJobState),
		TelemetrySource:     strings.TrimSpace(current.TelemetrySource),
		ObservationSource:   localObservationSourceRuntime,
		LastErrorCode:       strings.TrimSpace(current.LastErrorCode),
		LastErrorMessage:    strings.TrimSpace(current.LastErrorMessage),
		ManualIntervention:  strings.TrimSpace(current.ManualIntervention),
	}
	record.LastSeenAt = observedAt.UTC()
	if host := localObservationHostFromEndpoint(endpointURL); host != "" {
		record.ObservedHost = host
	}
	s.pruneLocked(observedAt.UTC())
}

func (s *localObservationStore) snapshot(agentStatus localAgentStatus, now time.Time) localObservationsResponse {
	if s == nil {
		return localObservationsResponse{Agent: agentStatus}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now.UTC())

	printers := make([]localPrinterObservation, 0, len(s.printers))
	summary := localObservationSummary{}
	for key, record := range s.printers {
		view, ok := buildLocalPrinterObservation(*record, now.UTC())
		if !ok {
			delete(s.printers, key)
			continue
		}
		printers = append(printers, view)
		switch view.Group {
		case localObservationGroupAvailable:
			summary.AvailableCount++
		case localObservationGroupBusy:
			summary.BusyCount++
		case localObservationGroupError:
			summary.ErrorCount++
		case localObservationGroupRecentlyDisconnected:
			summary.RecentlyDisconnectedCount++
		}
	}
	summary.TotalCount = len(printers)

	sort.Slice(printers, func(i, j int) bool {
		left := localObservationGroupOrder(printers[i].Group)
		right := localObservationGroupOrder(printers[j].Group)
		if left != right {
			return left < right
		}
		leftName := strings.ToLower(strings.TrimSpace(printers[i].DisplayName))
		rightName := strings.ToLower(strings.TrimSpace(printers[j].DisplayName))
		if leftName != rightName {
			return leftName < rightName
		}
		return printers[i].EndpointURL < printers[j].EndpointURL
	})

	return localObservationsResponse{
		Agent:    agentStatus,
		Summary:  summary,
		Printers: printers,
	}
}

func (s *localObservationStore) ensureRecordLocked(
	key string,
	adapterFamily string,
	endpointURL string,
	observedAt time.Time,
) *localObservationRecord {
	record, exists := s.printers[key]
	if !exists {
		record = &localObservationRecord{
			AdapterFamily: adapterFamily,
			EndpointURL:   endpointURL,
			FirstSeenAt:   observedAt.UTC(),
		}
		s.printers[key] = record
	}
	if record.FirstSeenAt.IsZero() {
		record.FirstSeenAt = observedAt.UTC()
	}
	return record
}

func (s *localObservationStore) pruneLocked(now time.Time) {
	for key, record := range s.printers {
		if shouldPruneLocalObservationRecord(*record, now) {
			delete(s.printers, key)
		}
	}
}

func buildLocalPrinterObservation(record localObservationRecord, now time.Time) (localPrinterObservation, bool) {
	base := localPrinterObservation{
		AdapterFamily:   record.AdapterFamily,
		EndpointURL:     record.EndpointURL,
		DisplayName:     localObservationDisplayName(record),
		ModelHint:       strings.TrimSpace(record.ModelHint),
		ObservedHost:    strings.TrimSpace(record.ObservedHost),
		LastSeenAt:      record.LastSeenAt.UTC(),
		LastReachableAt: record.LastReachableAt.UTC(),
	}

	if hasFreshRuntimeConnectivityError(record, now) {
		if record.LastReachableAt.IsZero() || now.Sub(record.LastReachableAt) > localObservationRetention {
			return localPrinterObservation{}, false
		}
		base.Group = localObservationGroupRecentlyDisconnected
		base.ConnectivityStatus = "unreachable"
		base.ObservationSource = localObservationSourceHistorical
		base.StatusDetailLevel = localObservationDetailHistorical
		base.TelemetrySource = record.Runtime.TelemetrySource
		base.LastErrorCode = firstNonEmpty(record.Runtime.LastErrorCode, "connectivity_error")
		base.LastErrorMessage = record.Runtime.LastErrorMessage
		base.ManualIntervention = record.Runtime.ManualIntervention
		return base, true
	}

	if hasFreshDiscovery(record, now) {
		discovery := record.Discovery
		base.ConnectivityStatus = discovery.Status
		base.ConnectivityError = discovery.ConnectivityError
		if discovery.Status == "reachable" {
			base.ObservationSource = localObservationSourceDiscovery
			base.StatusDetailLevel = localObservationDetailDiscoveryBasic
			base.TelemetrySource = discovery.TelemetrySource
			base.CurrentPrinterState = discovery.CurrentPrinterState
			base.CurrentJobState = discovery.CurrentJobState

			if hasFreshRuntimeDetail(record, now) {
				base.ObservationSource = localObservationSourceRuntime
				base.StatusDetailLevel = localObservationDetailRuntime
				base.TelemetrySource = record.Runtime.TelemetrySource
				base.CurrentPrinterState = record.Runtime.CurrentPrinterState
				base.CurrentJobState = record.Runtime.CurrentJobState
				base.LastErrorCode = record.Runtime.LastErrorCode
				base.LastErrorMessage = record.Runtime.LastErrorMessage
				base.ManualIntervention = record.Runtime.ManualIntervention
			}

			if strings.EqualFold(base.CurrentPrinterState, "error") {
				base.Group = localObservationGroupError
			} else if localObservationIsBusyState(base.CurrentPrinterState) {
				base.Group = localObservationGroupBusy
			} else {
				base.Group = localObservationGroupAvailable
			}
			return base, true
		}

		if record.LastReachableAt.IsZero() || now.Sub(record.LastReachableAt) > localObservationRetention {
			return localPrinterObservation{}, false
		}
		base.Group = localObservationGroupRecentlyDisconnected
		base.ObservationSource = localObservationSourceHistorical
		base.StatusDetailLevel = localObservationDetailHistorical
		if record.Runtime != nil {
			base.LastErrorCode = record.Runtime.LastErrorCode
			base.LastErrorMessage = record.Runtime.LastErrorMessage
			base.ManualIntervention = record.Runtime.ManualIntervention
		}
		return base, true
	}

	if hasFreshRuntimeDetail(record, now) {
		runtime := record.Runtime
		base.Group = localObservationGroupAvailable
		if strings.EqualFold(runtime.CurrentPrinterState, "error") {
			base.Group = localObservationGroupError
		} else if localObservationIsBusyState(runtime.CurrentPrinterState) {
			base.Group = localObservationGroupBusy
		}
		base.ConnectivityStatus = "reachable"
		base.CurrentPrinterState = runtime.CurrentPrinterState
		base.CurrentJobState = runtime.CurrentJobState
		base.TelemetrySource = runtime.TelemetrySource
		base.ObservationSource = localObservationSourceRuntime
		base.StatusDetailLevel = localObservationDetailRuntime
		base.LastErrorCode = runtime.LastErrorCode
		base.LastErrorMessage = runtime.LastErrorMessage
		base.ManualIntervention = runtime.ManualIntervention
		return base, true
	}

	if !record.LastReachableAt.IsZero() && now.Sub(record.LastReachableAt) <= localObservationRetention {
		base.Group = localObservationGroupRecentlyDisconnected
		base.ConnectivityStatus = "unreachable"
		base.ObservationSource = localObservationSourceHistorical
		base.StatusDetailLevel = localObservationDetailHistorical
		if record.Discovery != nil {
			base.ConnectivityError = record.Discovery.ConnectivityError
		}
		if record.Runtime != nil {
			base.LastErrorCode = record.Runtime.LastErrorCode
			base.LastErrorMessage = record.Runtime.LastErrorMessage
			base.ManualIntervention = record.Runtime.ManualIntervention
		}
		return base, true
	}

	return localPrinterObservation{}, false
}

func hasFreshDiscovery(record localObservationRecord, now time.Time) bool {
	if record.Discovery == nil {
		return false
	}
	return now.Sub(record.Discovery.ObservedAt) <= localObservationDiscoveryFreshWindow
}

func hasFreshRuntimeDetail(record localObservationRecord, now time.Time) bool {
	if record.Runtime == nil {
		return false
	}
	if record.Runtime.ConnectivityStatus != "reachable" {
		return false
	}
	return now.Sub(record.Runtime.ObservedAt) <= localObservationRuntimeDetailFreshWindow
}

func hasFreshRuntimeConnectivityError(record localObservationRecord, now time.Time) bool {
	if record.Runtime == nil {
		return false
	}
	if record.Runtime.ConnectivityStatus != "unreachable" {
		return false
	}
	if !strings.EqualFold(record.Runtime.LastErrorCode, "connectivity_error") {
		return false
	}
	return now.Sub(record.Runtime.ObservedAt) <= localObservationRuntimeErrorFreshWindow
}

func shouldPruneLocalObservationRecord(record localObservationRecord, now time.Time) bool {
	if hasFreshDiscovery(record, now) && strings.EqualFold(record.Discovery.Status, "reachable") {
		return false
	}
	if hasFreshRuntimeDetail(record, now) {
		return false
	}
	if !record.LastReachableAt.IsZero() && now.Sub(record.LastReachableAt) <= localObservationRetention {
		return false
	}
	return true
}

func localObservationKey(adapterFamily string, endpointURL string) string {
	return normalizeAdapterFamily(adapterFamily) + "|" + strings.TrimSpace(endpointURL)
}

func localObservationGroupOrder(group string) int {
	switch strings.TrimSpace(group) {
	case localObservationGroupAvailable:
		return 0
	case localObservationGroupBusy:
		return 1
	case localObservationGroupError:
		return 2
	case localObservationGroupRecentlyDisconnected:
		return 3
	default:
		return 4
	}
}

func localObservationDisplayName(record localObservationRecord) string {
	return firstNonEmpty(record.DisplayName, record.ObservedHost, strings.TrimSpace(record.EndpointURL))
}

func shouldSuppressDiscoveryState(adapterFamily string, discoverySource string) bool {
	if normalizeAdapterFamily(adapterFamily) != "bambu" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(discoverySource), discoverySourceBambuLAN)
}

func localObservationIsBusyState(printerState string) bool {
	switch strings.ToLower(strings.TrimSpace(printerState)) {
	case "queued", "printing", "paused":
		return true
	default:
		return false
	}
}

func localObservationHostFromCandidate(candidate discoveryCandidateResult) string {
	if candidate.Evidence != nil {
		if host := strings.TrimSpace(localObservationString(candidate.Evidence["ip_address"])); host != "" {
			return host
		}
		if host := strings.TrimSpace(localObservationString(candidate.Evidence["bambu_connect_host"])); host != "" {
			return host
		}
		location := strings.TrimSpace(localObservationString(candidate.Evidence["location"]))
		if location != "" {
			if parsed, err := url.Parse(location); err == nil {
				if host := strings.TrimSpace(parsed.Hostname()); host != "" {
					return host
				}
			}
		}
	}
	return localObservationHostFromEndpoint(candidate.EndpointURL)
}

func localObservationHostFromEndpoint(endpointURL string) string {
	if host := strings.TrimSpace(hostnameFromURL(endpointURL)); host != "" {
		return host
	}
	if strings.HasPrefix(strings.TrimSpace(endpointURL), "bambu://") {
		return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(endpointURL), "bambu://"))
	}
	return ""
}

func localObservationString(raw any) string {
	value, _ := raw.(string)
	return value
}
