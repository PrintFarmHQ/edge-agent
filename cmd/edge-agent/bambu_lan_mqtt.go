package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	bambustore "printfarmhq/edge-agent/internal/store"
)

const (
	telemetrySourceBambuLANMQTT   = "bambu_lan_mqtt"
	bambuLANMQTTBrokerPort        = "8883"
	bambuLANMQTTUsername          = "bblp"
	bambuLANFailureThreshold      = 2
	defaultBambuLANRuntimeTimeout = 2 * time.Second
	bambuLANFilamentCommandTemp   = 215
)

var fetchBambuLANMQTTSnapshot = defaultFetchBambuLANMQTTSnapshot

func (a *agent) fetchBambuLANRuntimeSnapshotByPrinterID(ctx context.Context, printerID string) (bindingSnapshot, error) {
	credentials, err := a.resolveBambuLANRuntimeCredentials(ctx, printerID)
	if err != nil {
		return bindingSnapshot{}, err
	}

	requestTimeout := a.cfg.BambuLANRuntimeTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultBambuLANRuntimeTimeout
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	snapshot, err := fetchBambuLANMQTTSnapshot(
		requestCtx,
		strings.TrimSpace(credentials.Host),
		strings.TrimSpace(credentials.Serial),
		strings.TrimSpace(credentials.AccessCode),
	)
	if err != nil {
		return bindingSnapshot{}, err
	}
	if strings.TrimSpace(snapshot.DetectedName) == "" {
		snapshot.DetectedName = strings.TrimSpace(credentials.Name)
	}
	if strings.TrimSpace(snapshot.DetectedModelHint) == "" {
		snapshot.DetectedModelHint = strings.TrimSpace(credentials.Model)
	}
	if strings.TrimSpace(snapshot.TelemetrySource) == "" {
		snapshot.TelemetrySource = telemetrySourceBambuLANMQTT
	}
	a.recordBambuLANRuntimeSnapshot(strings.TrimSpace(credentials.Serial), strings.TrimSpace(credentials.Host), snapshot)
	return snapshot, nil
}

func (a *agent) executeBambuLANControlAction(
	ctx context.Context,
	queuedAction action,
	binding edgeBinding,
	command string,
) error {
	printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
	if err != nil {
		return err
	}
	credentials, err := a.resolveBambuLANRuntimeCredentials(ctx, printerID)
	if err != nil {
		if isBambuLANCredentialsUnavailable(err) {
			return a.decorateBambuLANCredentialsUnavailable(ctx, binding, err)
		}
		return err
	}

	publisher := a.bambuMQTTPublish
	if publisher == nil {
		publisher = defaultBambuPrintCommandPublisher{}
	}
	if err := publisher.PublishPrintCommand(ctx, bambuMQTTCommandRequest{
		BrokerAddr:         net.JoinHostPort(strings.TrimSpace(credentials.Host), bambuLANMQTTBrokerPort),
		Topic:              formatBambuLANMQTTRequestTopic(strings.TrimSpace(credentials.Serial)),
		Username:           bambuLANMQTTUsername,
		Password:           strings.TrimSpace(credentials.AccessCode),
		Command:            strings.TrimSpace(command),
		Param:              "",
		InsecureSkipVerify: true,
	}); err != nil {
		return err
	}
	return a.verifyBambuControlAction(ctx, strings.TrimSpace(credentials.Serial), command)
}

func (a *agent) executeBambuLANPrinterCommand(
	ctx context.Context,
	queuedAction action,
	binding edgeBinding,
) error {
	printerID, err := parseBambuPrinterEndpointID(binding.EndpointURL)
	if err != nil {
		return err
	}
	credentials, err := a.resolveBambuLANRuntimeCredentials(ctx, printerID)
	if err != nil {
		if isBambuLANCredentialsUnavailable(err) {
			return a.decorateBambuLANCredentialsUnavailable(ctx, binding, err)
		}
		return err
	}

	var payload []byte
	switch strings.TrimSpace(queuedAction.Kind) {
	case "light_on", "light_off":
		ledMode := "on"
		if strings.TrimSpace(queuedAction.Kind) == "light_off" {
			ledMode = "off"
		}
		payload, err = json.Marshal(map[string]any{
			"system": map[string]any{
				"command":       "ledctrl",
				"sequence_id":   strconv.FormatInt(time.Now().UnixMilli(), 10),
				"led_node":      "chamber_light",
				"led_mode":      ledMode,
				"led_on_time":   500,
				"led_off_time":  500,
				"loop_times":    0,
				"interval_time": 0,
			},
		})
		if err != nil {
			return fmt.Errorf("marshal bambu led payload: %w", err)
		}
		if err := publishBambuMQTTRawFunc(
			ctx,
			net.JoinHostPort(strings.TrimSpace(credentials.Host), bambuLANMQTTBrokerPort),
			formatBambuLANMQTTRequestTopic(strings.TrimSpace(credentials.Serial)),
			bambuLANMQTTUsername,
			strings.TrimSpace(credentials.AccessCode),
			payload,
			true,
		); err != nil {
			return err
		}
		return a.verifyBambuLEDState(ctx, strings.TrimSpace(credentials.Serial), ledMode)
	case "load_filament", "unload_filament":
		target := 255
		if strings.TrimSpace(queuedAction.Kind) == "unload_filament" {
			target = 254
		}
		payload, err = json.Marshal(map[string]any{
			"print": map[string]any{
				"command":     "ams_change_filament",
				"sequence_id": strconv.FormatInt(time.Now().UnixMilli(), 10),
				"target":      target,
				"curr_temp":   bambuLANFilamentCommandTemp,
				"tar_temp":    bambuLANFilamentCommandTemp,
			},
		})
		if err != nil {
			return fmt.Errorf("marshal bambu filament payload: %w", err)
		}
		return publishBambuMQTTRawFunc(
			ctx,
			net.JoinHostPort(strings.TrimSpace(credentials.Host), bambuLANMQTTBrokerPort),
			formatBambuLANMQTTRequestTopic(strings.TrimSpace(credentials.Serial)),
			bambuLANMQTTUsername,
			strings.TrimSpace(credentials.AccessCode),
			payload,
			true,
		)
	default:
		return fmt.Errorf("validation_error: unsupported bambu lan printer command %s", queuedAction.Kind)
	}
}

func (a *agent) resolveBambuLANRuntimeCredentials(ctx context.Context, printerID string) (bambustore.BambuLANCredentials, error) {
	normalizedPrinterID := strings.TrimSpace(printerID)
	if normalizedPrinterID == "" {
		return bambustore.BambuLANCredentials{}, errors.New("validation_error: missing bambu printer identifier")
	}
	if a.bambuLANStore == nil {
		return bambustore.BambuLANCredentials{}, errors.New("bambu_lan_credentials_store_unavailable: bambu lan credentials store is not configured")
	}

	credentials, err := a.bambuLANStore.Get(ctx, normalizedPrinterID)
	if err != nil {
		if errors.Is(err, bambustore.ErrBambuLANCredentialsNotFound) || errors.Is(err, os.ErrNotExist) {
			return bambustore.BambuLANCredentials{}, fmt.Errorf("bambu_lan_credentials_missing_local: %w", err)
		}
		return bambustore.BambuLANCredentials{}, err
	}
	if record, ok := a.currentBambuLANDiscoveryRecord(normalizedPrinterID); ok {
		if host := strings.TrimSpace(record.Host); host != "" {
			credentials.Host = host
		}
		if strings.TrimSpace(credentials.Name) == "" {
			credentials.Name = strings.TrimSpace(record.Snapshot.DetectedName)
		}
		if strings.TrimSpace(credentials.Model) == "" {
			credentials.Model = strings.TrimSpace(record.Snapshot.DetectedModelHint)
		}
	}
	if strings.TrimSpace(credentials.Serial) == "" {
		credentials.Serial = normalizedPrinterID
	}
	if strings.TrimSpace(credentials.Host) == "" {
		return bambustore.BambuLANCredentials{}, errors.New("validation_error: bambu lan credentials missing host")
	}
	if strings.TrimSpace(credentials.AccessCode) == "" {
		return bambustore.BambuLANCredentials{}, errors.New("validation_error: bambu lan credentials missing access_code")
	}
	return credentials, nil
}

func isBambuLANCredentialsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, bambustore.ErrBambuLANCredentialsNotFound) {
		return true
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "bambu lan credentials store is not configured") ||
		strings.Contains(msg, "bambu_lan_credentials_missing_local")
}

func (a *agent) currentBambuLANDiscoveryRecord(printerID string) (bambuLANDiscoveryRecord, bool) {
	key := strings.ToLower(strings.TrimSpace(printerID))
	if key == "" {
		return bambuLANDiscoveryRecord{}, false
	}

	now := time.Now().UTC()
	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANRecords == nil {
		a.bambuLANRecords = make(map[string]bambuLANDiscoveryRecord)
	}
	a.pruneBambuLANRecordsLocked(now)
	record, ok := a.bambuLANRecords[key]
	return record, ok
}

func (a *agent) recordBambuLANRuntimeSnapshot(printerID string, host string, snapshot bindingSnapshot) {
	key := strings.ToLower(strings.TrimSpace(printerID))
	if key == "" {
		return
	}
	now := time.Now().UTC()
	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANRecords == nil {
		a.bambuLANRecords = make(map[string]bambuLANDiscoveryRecord)
	}
	a.pruneBambuLANRecordsLocked(now)
	a.bambuLANRecords[key] = bambuLANDiscoveryRecord{
		Snapshot: snapshot,
		Host:     strings.TrimSpace(host),
		LastSeen: now,
	}
}

func (a *agent) recordBambuLANRuntimeFailure(printerID string, err error) bool {
	key := strings.ToLower(strings.TrimSpace(printerID))
	if key == "" || err == nil {
		return false
	}

	code, _ := classifyActionError(err)

	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANFailures == nil {
		a.bambuLANFailures = make(map[string]int)
	}
	if code != "connectivity_error" {
		delete(a.bambuLANFailures, key)
		return false
	}

	a.bambuLANFailures[key] = a.bambuLANFailures[key] + 1
	return a.bambuLANFailures[key] >= bambuLANFailureThreshold
}

func (a *agent) clearBambuLANRuntimeFailure(printerID string) {
	key := strings.ToLower(strings.TrimSpace(printerID))
	if key == "" {
		return
	}

	a.bambuLANMu.Lock()
	defer a.bambuLANMu.Unlock()
	if a.bambuLANFailures == nil {
		return
	}
	delete(a.bambuLANFailures, key)
}

func defaultFetchBambuLANMQTTSnapshot(
	ctx context.Context,
	host string,
	printerID string,
	accessCode string,
) (bindingSnapshot, error) {
	trimmedHost := strings.TrimSpace(host)
	trimmedPrinterID := strings.TrimSpace(printerID)
	trimmedAccessCode := strings.TrimSpace(accessCode)
	if trimmedHost == "" {
		return bindingSnapshot{}, errors.New("validation_error: missing bambu lan host")
	}
	if trimmedPrinterID == "" {
		return bindingSnapshot{}, errors.New("validation_error: missing bambu printer identifier")
	}
	if trimmedAccessCode == "" {
		return bindingSnapshot{}, errors.New("validation_error: missing bambu lan access code")
	}

	brokerAddr := net.JoinHostPort(trimmedHost, bambuLANMQTTBrokerPort)
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	// Bambu LAN MQTT uses a printer-local certificate that is not anchored in the OS trust store.
	conn, err := tls.DialWithDialer(dialer, "tcp", brokerAddr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         trimmedHost,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return bindingSnapshot{}, fmt.Errorf("bambu lan mqtt connection failed: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	if err := writeMQTTConnect(conn, bambuLANMQTTUsername, trimmedAccessCode); err != nil {
		return bindingSnapshot{}, err
	}
	if err := readMQTTConnAck(conn); err != nil {
		return bindingSnapshot{}, err
	}

	reportTopic := formatBambuLANMQTTReportTopic(trimmedPrinterID)
	if err := writeMQTTSubscribe(conn, reportTopic, 1); err != nil {
		return bindingSnapshot{}, err
	}
	if err := readMQTTSubAck(conn, 1); err != nil {
		return bindingSnapshot{}, err
	}

	pushPayload, err := json.Marshal(map[string]any{
		"pushing": map[string]any{
			"command":     "pushall",
			"sequence_id": strconv.FormatInt(time.Now().UnixMilli(), 10),
		},
	})
	if err != nil {
		return bindingSnapshot{}, fmt.Errorf("marshal bambu lan pushall payload: %w", err)
	}
	if err := writeMQTTPublish(conn, formatBambuLANMQTTRequestTopic(trimmedPrinterID), pushPayload); err != nil {
		return bindingSnapshot{}, err
	}

	for {
		header, packet, err := readMQTTPacket(conn)
		if err != nil {
			return bindingSnapshot{}, fmt.Errorf("bambu lan mqtt read failed: %w", err)
		}
		publish, err := decodeMQTTPublishPacket(header, packet)
		if err != nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(publish.Topic), reportTopic) {
			continue
		}
		snapshot, err := parseBambuLANMQTTSnapshotPayload(publish.Payload)
		if err != nil {
			continue
		}
		return snapshot, nil
	}
}

func parseBambuLANMQTTSnapshotPayload(raw []byte) (bindingSnapshot, error) {
	var payload struct {
		Print map[string]any `json:"print"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return bindingSnapshot{}, fmt.Errorf("decode bambu lan mqtt payload: %w", err)
	}
	if len(payload.Print) == 0 {
		return bindingSnapshot{}, errors.New("bambu lan mqtt payload missing print section")
	}

	gcodeState := strings.TrimSpace(bambuLANValueAsString(payload.Print["gcode_state"]))
	printType := strings.TrimSpace(bambuLANValueAsString(payload.Print["print_type"]))
	taskID := strings.TrimSpace(bambuLANValueAsString(payload.Print["task_id"]))
	gcodeFile := strings.TrimSpace(bambuLANValueAsString(payload.Print["gcode_file"]))
	hms := bambuLANValueAsSlice(payload.Print["hms"])
	printError, hasPrintError := bambuLANValueAsFloat(payload.Print["print_error"])
	printerState, jobState := mapBambuLANGcodeState(
		gcodeState,
		printType,
		taskID,
		gcodeFile,
		len(hms) > 0,
		hasPrintError && printError > 0,
	)
	snapshot := bindingSnapshot{
		PrinterState:     printerState,
		JobState:         jobState,
		TelemetrySource:  telemetrySourceBambuLANMQTT,
		RawPrinterStatus: gcodeState,
	}

	if progressPct, ok := bambuLANValueAsFloat(payload.Print["mc_percent"]); ok {
		snapshot.ProgressPct = &progressPct
	}
	if remainingMinutes, ok := bambuLANValueAsFloat(payload.Print["mc_remaining_time"]); ok && remainingMinutes > 0 {
		remainingSeconds := remainingMinutes * 60
		snapshot.RemainingSeconds = &remainingSeconds
	}

	if len(hms) > 0 {
		snapshot.ManualIntervention = "hms_alert"
	} else if hasPrintError && printError > 0 {
		snapshot.ManualIntervention = "print_error"
	}
	ledState := parseBambuLANLightState(payload.Print["lights_report"])
	filamentState, filamentStateSource, filamentConfidence, sourceKind, sourceLabel := parseBambuLANFilamentTelemetry(payload.Print["ams"])
	filamentActionState := parseBambuLANFilamentActionState(payload.Print["subtask_name"])
	filamentCapability := map[string]any{
		"state":        filamentState,
		"state_source": filamentStateSource,
		"confidence":   filamentConfidence,
		"source_kind":  sourceKind,
	}
	if sourceLabel != "" {
		filamentCapability["source_label"] = sourceLabel
	}
	if filamentActionState != "" {
		filamentCapability["action_state"] = filamentActionState
	}
	snapshot.CommandCapabilities = map[string]any{
		"led": map[string]any{
			"supported": true,
		},
		"filament": filamentCapability,
		"load_filament": map[string]any{
			"supported": true,
		},
		"unload_filament": map[string]any{
			"supported": true,
		},
	}
	if ledState != "" {
		snapshot.CommandCapabilities["led"] = map[string]any{
			"supported": true,
			"state":     ledState,
		}
	}

	return snapshot, nil
}

func mapBambuLANGcodeState(
	raw string,
	printType string,
	taskID string,
	gcodeFile string,
	hasHMS bool,
	hasPrintError bool,
) (printerState string, jobState string) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "RUNNING", "PRINTING":
		return "printing", "printing"
	case "PAUSE", "PAUSED":
		return "paused", "printing"
	case "PREPARE", "PREPARING", "SLICING", "DOWNLOADING":
		return "queued", "pending"
	case "FAILED", "ERROR":
		if isBambuLANIdleFailureSnapshot(printType, taskID, gcodeFile, hasHMS, hasPrintError) {
			return "idle", "pending"
		}
		return "error", "failed"
	case "FINISH", "FINISHED":
		return "idle", "completed"
	case "IDLE", "":
		return "idle", "pending"
	default:
		return "idle", "pending"
	}
}

func isBambuLANIdleFailureSnapshot(
	printType string,
	taskID string,
	gcodeFile string,
	hasHMS bool,
	hasPrintError bool,
) bool {
	if hasHMS || hasPrintError {
		return false
	}

	normalizedPrintType := strings.ToLower(strings.TrimSpace(printType))
	normalizedTaskID := strings.TrimSpace(taskID)
	normalizedGCodeFile := strings.TrimSpace(gcodeFile)

	return normalizedPrintType == "idle" &&
		(normalizedTaskID == "" || normalizedTaskID == "0") &&
		normalizedGCodeFile == ""
}

func bambuLANValueAsString(raw any) string {
	switch value := raw.(type) {
	case string:
		return strings.TrimSpace(value)
	case fmt.Stringer:
		return strings.TrimSpace(value.String())
	default:
		return strings.TrimSpace(fmt.Sprint(raw))
	}
}

func bambuLANValueAsFloat(raw any) (float64, bool) {
	switch value := raw.(type) {
	case float64:
		return value, true
	case float32:
		return float64(value), true
	case int:
		return float64(value), true
	case int64:
		return float64(value), true
	case int32:
		return float64(value), true
	case json.Number:
		parsed, err := value.Float64()
		return parsed, err == nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func bambuLANValueAsInt(raw any) (int, bool) {
	switch value := raw.(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case int32:
		return int(value), true
	case float64:
		return int(value), true
	case float32:
		return int(value), true
	case json.Number:
		parsed, err := value.Int64()
		return int(parsed), err == nil
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func bambuLANValueAsSlice(raw any) []any {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	return items
}

func parseBambuLANLightState(raw any) string {
	fallback := ""
	for _, item := range bambuLANValueAsSlice(raw) {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(bambuLANValueAsString(entry["mode"])))
		if mode != "on" && mode != "off" {
			continue
		}
		node := strings.ToLower(strings.TrimSpace(bambuLANValueAsString(entry["node"])))
		if node == "chamber_light" {
			return mode
		}
		if fallback == "" && (node == "" || strings.Contains(node, "chamber") || strings.Contains(node, "light")) {
			fallback = mode
		}
	}
	return fallback
}

func parseBambuLANFilamentTelemetry(raw any) (string, string, string, string, string) {
	sourceKind, sourceLabel, sourceKnown := parseBambuLANActiveSource(raw)
	if !sourceKnown {
		return "unknown", filamentStateSourceUnknown, filamentConfidenceHeuristic, filamentSourceKindUnknown, ""
	}
	switch sourceKind {
	case filamentSourceKindExternalSpool, filamentSourceKindAMS:
		return "loaded", filamentStateSourceBambuActiveSource, filamentConfidenceConfirmed, sourceKind, sourceLabel
	case filamentSourceKindNone:
		return "unknown", filamentStateSourceBambuActiveSource, filamentConfidenceConfirmed, sourceKind, ""
	default:
		return "unknown", filamentStateSourceUnknown, filamentConfidenceHeuristic, filamentSourceKindUnknown, ""
	}
}

func parseBambuLANActiveSource(raw any) (string, string, bool) {
	amsPayload, ok := raw.(map[string]any)
	if !ok || len(amsPayload) == 0 {
		return filamentSourceKindUnknown, "", false
	}
	trayNowRaw, exists := amsPayload["tray_now"]
	if !exists {
		return filamentSourceKindUnknown, "", false
	}
	trayNow, ok := bambuLANValueAsInt(trayNowRaw)
	if !ok {
		return filamentSourceKindUnknown, "", false
	}
	switch {
	case trayNow == 254:
		return filamentSourceKindExternalSpool, "External spool", true
	case trayNow == 255:
		return filamentSourceKindNone, "", true
	case trayNow >= 80:
		return filamentSourceKindAMS, fmt.Sprintf("AMS HT %d", trayNow), true
	case trayNow >= 0:
		return filamentSourceKindAMS, fmt.Sprintf("AMS %d / Tray %d", (trayNow>>2)+1, (trayNow&0x3)+1), true
	default:
		return filamentSourceKindUnknown, "", false
	}
}

func parseBambuLANFilamentActionState(raw any) string {
	value := strings.ToLower(strings.TrimSpace(bambuLANValueAsString(raw)))
	switch {
	case strings.Contains(value, "unload") && strings.Contains(value, "filament"):
		return filamentActionStateUnloading
	case strings.Contains(value, "load") && strings.Contains(value, "filament"):
		return filamentActionStateLoading
	default:
		return ""
	}
}

func formatBambuLANMQTTRequestTopic(printerID string) string {
	return fmt.Sprintf("device/%s/request", strings.TrimSpace(printerID))
}

func formatBambuLANMQTTReportTopic(printerID string) string {
	return fmt.Sprintf("device/%s/report", strings.TrimSpace(printerID))
}
