package moonraker

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
)

type RuntimeAdapter struct {
	ExecutePrint                         func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	DownloadArtifact                     func(ctx context.Context, req printeradapter.StartPrintRequest) (StagedArtifact, error)
	CleanupArtifact                      func(path string)
	ProbeArtifactReuse                   func(ctx context.Context, endpointURL string, artifact StagedArtifact) (bool, string, error)
	UploadArtifact                       func(ctx context.Context, endpointURL string, artifact StagedArtifact) error
	CallPost                             func(ctx context.Context, endpointURL, path string, body any) error
	CallPostWithTimeout                  func(ctx context.Context, endpointURL, path string, body any, timeout time.Duration) error
	RefreshFiles                         func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	FetchDevicePowerDevices              func(ctx context.Context, endpointURL string) ([]PowerDevice, error)
	ResolvePrimaryLightDevice            func(devices []PowerDevice) (string, string, bool)
	FetchObjectList                      func(ctx context.Context, endpointURL string) ([]string, error)
	ResolvePrimaryLEDObject              func(objects []string) (string, bool)
	LEDObjectConfigName                  func(objectName string) string
	IsSnapmakerU1Printer                 func(printerID int) bool
	BuildSnapmakerU1HomeAxesScript       func(payload map[string]any) (string, error)
	BuildMoonrakerHomeAxesScript         func(payload map[string]any) (string, error)
	BuildMoonrakerJogMotionProgram       func(payload map[string]any) (string, error)
	BuildMoonrakerJogMotionBatchProgram  func(payload map[string]any) (string, error)
	BuildMoonrakerFanControlGCode        func(payload map[string]any) (string, error)
	FetchActiveExtruderName              func(ctx context.Context, endpointURL string) (string, error)
	BuildMoonrakerHeaterTemperatureGCode func(heaterName string, payload map[string]any, fieldName string) (string, error)
	HomeRequestTimeout                   func(defaultTimeout time.Duration) time.Duration
	RequestTimeout                       time.Duration
	FetchRemoteMetadata                  func(ctx context.Context, endpointURL string, filename string) (*int64, *time.Time, bool, error)
	FetchCurrentFilename                 func(ctx context.Context, endpointURL string) (string, error)
	DeletePath                           func(ctx context.Context, endpointURL, path string) error
	IsPrintableFileFormat                func(path string) bool
	Audit                                func(event string, payload map[string]any)
}

type PowerDevice struct {
	Device string
	Status string
}

type StagedArtifact struct {
	LocalPath           string
	SourceFilename      string
	NormalizedExtension string
	SizeBytes           int64
	SHA256              string
	RemoteName          string
}

func (a StagedArtifact) PreferredSourceName() string {
	if source := strings.TrimSpace(a.SourceFilename); source != "" {
		return source
	}
	return strings.TrimSpace(a.RemoteName)
}

func (a StagedArtifact) MoonrakerRemoteName() string {
	return strings.TrimSpace(a.RemoteName)
}

type FileFingerprint struct {
	Path       string
	SizeBytes  *int64
	ModifiedAt *time.Time
}

type DeleteTarget struct {
	Path     string
	Expected FileFingerprint
}

func (a RuntimeAdapter) ExecuteAction(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	switch action.Kind {
	case "print":
		return a.executePrint(ctx, action, binding)
	case "pause":
		return a.callPost(ctx, binding.EndpointURL, "/printer/print/pause", nil)
	case "resume":
		return a.callPost(ctx, binding.EndpointURL, "/printer/print/resume", nil)
	case "stop":
		return a.callPost(ctx, binding.EndpointURL, "/printer/print/cancel", nil)
	case "light_on", "light_off":
		return a.executeLight(ctx, binding, action.Kind)
	case "load_filament":
		return a.executeMacro(ctx, binding.EndpointURL, "LOAD_FILAMENT")
	case "unload_filament":
		return a.executeMacro(ctx, binding.EndpointURL, "UNLOAD_FILAMENT")
	case "refresh_file_index":
		return a.refreshFiles(ctx, action, binding)
	case "start_existing_file":
		return a.startExistingFile(ctx, action, binding)
	case "delete_file":
		return a.deleteFile(ctx, action, binding)
	case "delete_all_files":
		return a.deleteAllFiles(ctx, action, binding)
	case "home_axes", "jog_motion", "jog_motion_batch", "set_fan_enabled", "set_nozzle_temperature", "set_bed_temperature":
		return a.executePrinterCommand(ctx, binding, action)
	default:
		return fmt.Errorf("unsupported action kind: %s", action.Kind)
	}
}

func (a RuntimeAdapter) executePrint(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	if a.DownloadArtifact != nil && a.CleanupArtifact != nil && a.ProbeArtifactReuse != nil && a.UploadArtifact != nil {
		artifact, err := a.DownloadArtifact(ctx, action.Target)
		if err != nil {
			return err
		}
		defer a.CleanupArtifact(artifact.LocalPath)

		remoteName := artifact.MoonrakerRemoteName()
		baseAuditFields := a.printStartAuditFields(binding, action, remoteName)
		a.audit("artifact_downloaded", mergedAuditFields(baseAuditFields, map[string]any{
			"source_filename": artifact.PreferredSourceName(),
			"size_bytes":      artifact.SizeBytes,
		}))
		a.audit("artifact_reuse_probe_attempt", mergedAuditFields(baseAuditFields, map[string]any{
			"transport": "moonraker_file_manager",
		}))

		reused, reason, probeErr := a.ProbeArtifactReuse(ctx, binding.EndpointURL, artifact)
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
			if err := a.UploadArtifact(ctx, binding.EndpointURL, artifact); err != nil {
				return err
			}
			a.audit("artifact_uploaded", mergedAuditFields(baseAuditFields, map[string]any{
				"transport": "moonraker_file_manager",
			}))
		}

		if err := a.callPost(ctx, binding.EndpointURL, "/printer/print/start", map[string]string{"filename": remoteName}); err != nil {
			return err
		}
		a.audit("print_start_requested", baseAuditFields)
		return nil
	}
	if a.ExecutePrint == nil {
		return fmt.Errorf("moonraker runtime adapter is missing print executor")
	}
	return a.ExecutePrint(ctx, action, binding)
}

func (a RuntimeAdapter) callPost(ctx context.Context, endpointURL, path string, body any) error {
	if a.CallPost == nil {
		return fmt.Errorf("moonraker runtime adapter is missing post executor")
	}
	return a.CallPost(ctx, endpointURL, path, body)
}

func (a RuntimeAdapter) executeLight(ctx context.Context, binding printeradapter.Binding, commandKey string) error {
	if a.FetchDevicePowerDevices == nil || a.ResolvePrimaryLightDevice == nil || a.FetchObjectList == nil || a.ResolvePrimaryLEDObject == nil || a.LEDObjectConfigName == nil {
		return fmt.Errorf("moonraker runtime adapter is missing light dependencies")
	}
	devices, err := a.FetchDevicePowerDevices(ctx, binding.EndpointURL)
	if err != nil {
		return err
	}
	deviceName, _, ok := a.ResolvePrimaryLightDevice(devices)
	action := "on"
	if strings.TrimSpace(commandKey) == "light_off" {
		action = "off"
	}
	if ok {
		return a.callPost(
			ctx,
			binding.EndpointURL,
			"/machine/device_power/device?device="+url.QueryEscape(deviceName)+"&action="+url.QueryEscape(action),
			nil,
		)
	}

	objects, err := a.FetchObjectList(ctx, binding.EndpointURL)
	if err != nil {
		return err
	}
	ledObjectName, ok := a.ResolvePrimaryLEDObject(objects)
	if !ok {
		return errors.New("validation_error: moonraker primary light device is not configured")
	}
	ledConfigName := a.LEDObjectConfigName(ledObjectName)
	if ledConfigName == "" {
		return errors.New("validation_error: moonraker led object is missing config name")
	}

	whiteValue := "1"
	if action == "off" {
		whiteValue = "0"
	}
	return a.callPost(
		ctx,
		binding.EndpointURL,
		"/printer/gcode/script",
		map[string]string{
			"script": fmt.Sprintf("SET_LED LED=%s WHITE=%s SYNC=0 TRANSMIT=1", ledConfigName, whiteValue),
		},
	)
}

func (a RuntimeAdapter) executeMacro(ctx context.Context, endpointURL, macroName string) error {
	return a.callPost(
		ctx,
		endpointURL,
		"/printer/gcode/script",
		map[string]string{"script": strings.TrimSpace(macroName)},
	)
}

func (a RuntimeAdapter) refreshFiles(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	if a.RefreshFiles == nil {
		return fmt.Errorf("moonraker runtime adapter is missing file refresh executor")
	}
	return a.RefreshFiles(ctx, action, binding)
}

func (a RuntimeAdapter) startExistingFile(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	path, expected, err := ParseFileActionPayload(action.Payload)
	if err != nil {
		return err
	}
	if a.IsPrintableFileFormat == nil || !a.IsPrintableFileFormat(path) {
		return fmt.Errorf("validation_error: unsupported moonraker file format for start: %s", path)
	}
	sizeBytes, modifiedAt, exists, err := a.fetchRemoteMetadata(ctx, binding.EndpointURL, path)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("printer_file_not_found: moonraker file no longer exists")
	}
	if !FileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: moonraker file changed since the last refresh")
	}
	if err := a.callPost(ctx, binding.EndpointURL, "/printer/print/start", map[string]string{"filename": path}); err != nil {
		return err
	}
	return a.refreshFiles(ctx, printeradapter.RuntimeAction{Kind: "refresh_file_index"}, binding)
}

func (a RuntimeAdapter) deleteFile(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	path, expected, err := ParseFileActionPayload(action.Payload)
	if err != nil {
		return err
	}
	sizeBytes, modifiedAt, exists, err := a.fetchRemoteMetadata(ctx, binding.EndpointURL, path)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("printer_file_not_found: moonraker file no longer exists")
	}
	if !FileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: moonraker file changed since the last refresh")
	}
	activePath, _ := a.fetchCurrentFilename(ctx, binding.EndpointURL)
	if activePath != "" && strings.EqualFold(strings.TrimSpace(activePath), strings.TrimSpace(path)) {
		return errors.New("printer_file_active: cannot delete the currently active moonraker file")
	}
	if err := a.deletePath(ctx, binding.EndpointURL, path); err != nil {
		return err
	}
	return a.refreshFiles(ctx, printeradapter.RuntimeAction{Kind: "refresh_file_index"}, binding)
}

func (a RuntimeAdapter) deleteAllFiles(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	targets, err := ParseDeleteTargetsPayload(action.Payload)
	if err != nil {
		return err
	}
	activePath, _ := a.fetchCurrentFilename(ctx, binding.EndpointURL)
	for _, target := range targets {
		sizeBytes, modifiedAt, exists, metadataErr := a.fetchRemoteMetadata(ctx, binding.EndpointURL, target.Path)
		if metadataErr != nil {
			return metadataErr
		}
		if !exists {
			return fmt.Errorf("printer_file_not_found: moonraker file no longer exists: %s", target.Path)
		}
		if !FileFingerprintMatches(target.Path, sizeBytes, modifiedAt, target.Expected) {
			return fmt.Errorf("printer_file_snapshot_mismatch: moonraker file changed since the last refresh: %s", target.Path)
		}
		if activePath != "" && strings.EqualFold(strings.TrimSpace(activePath), strings.TrimSpace(target.Path)) {
			return fmt.Errorf("printer_file_active: cannot delete the currently active moonraker file: %s", target.Path)
		}
	}
	for _, target := range targets {
		if err := a.deletePath(ctx, binding.EndpointURL, target.Path); err != nil {
			return err
		}
	}
	return a.refreshFiles(ctx, printeradapter.RuntimeAction{Kind: "refresh_file_index"}, binding)
}

func (a RuntimeAdapter) executePrinterCommand(ctx context.Context, binding printeradapter.Binding, action printeradapter.RuntimeAction) error {
	var (
		script         string
		err            error
		requestTimeout time.Duration
	)
	switch strings.TrimSpace(action.Kind) {
	case "home_axes":
		if a.IsSnapmakerU1Printer != nil && a.IsSnapmakerU1Printer(binding.PrinterID) {
			if a.BuildSnapmakerU1HomeAxesScript == nil {
				return fmt.Errorf("moonraker runtime adapter is missing Snapmaker home builder")
			}
			script, err = a.BuildSnapmakerU1HomeAxesScript(action.Payload)
		} else {
			if a.BuildMoonrakerHomeAxesScript == nil {
				return fmt.Errorf("moonraker runtime adapter is missing Moonraker home builder")
			}
			script, err = a.BuildMoonrakerHomeAxesScript(action.Payload)
		}
		if a.HomeRequestTimeout != nil {
			requestTimeout = a.HomeRequestTimeout(a.RequestTimeout)
		}
	case "jog_motion":
		if a.BuildMoonrakerJogMotionProgram == nil {
			return fmt.Errorf("moonraker runtime adapter is missing jog builder")
		}
		script, err = a.BuildMoonrakerJogMotionProgram(action.Payload)
	case "jog_motion_batch":
		if a.BuildMoonrakerJogMotionBatchProgram == nil {
			return fmt.Errorf("moonraker runtime adapter is missing jog batch builder")
		}
		script, err = a.BuildMoonrakerJogMotionBatchProgram(action.Payload)
	case "set_fan_enabled":
		if a.BuildMoonrakerFanControlGCode == nil {
			return fmt.Errorf("moonraker runtime adapter is missing fan control builder")
		}
		script, err = a.BuildMoonrakerFanControlGCode(action.Payload)
	case "set_nozzle_temperature":
		if a.FetchActiveExtruderName == nil || a.BuildMoonrakerHeaterTemperatureGCode == nil {
			return fmt.Errorf("moonraker runtime adapter is missing nozzle temperature dependencies")
		}
		var heaterName string
		heaterName, err = a.FetchActiveExtruderName(ctx, binding.EndpointURL)
		if err == nil {
			script, err = a.BuildMoonrakerHeaterTemperatureGCode(heaterName, action.Payload, "set_nozzle_temperature")
		}
	case "set_bed_temperature":
		if a.BuildMoonrakerHeaterTemperatureGCode == nil {
			return fmt.Errorf("moonraker runtime adapter is missing bed temperature builder")
		}
		script, err = a.BuildMoonrakerHeaterTemperatureGCode("heater_bed", action.Payload, "set_bed_temperature")
	default:
		return fmt.Errorf("unsupported moonraker printer command kind: %s", action.Kind)
	}
	if err != nil {
		return err
	}
	if requestTimeout > 0 {
		if a.CallPostWithTimeout == nil {
			return fmt.Errorf("moonraker runtime adapter is missing timeout-aware post executor")
		}
		return a.CallPostWithTimeout(
			ctx,
			binding.EndpointURL,
			"/printer/gcode/script",
			map[string]string{"script": script},
			requestTimeout,
		)
	}
	return a.callPost(
		ctx,
		binding.EndpointURL,
		"/printer/gcode/script",
		map[string]string{"script": script},
	)
}

func (a RuntimeAdapter) fetchRemoteMetadata(ctx context.Context, endpointURL string, filename string) (*int64, *time.Time, bool, error) {
	if a.FetchRemoteMetadata == nil {
		return nil, nil, false, fmt.Errorf("moonraker runtime adapter is missing file metadata fetcher")
	}
	return a.FetchRemoteMetadata(ctx, endpointURL, filename)
}

func (a RuntimeAdapter) fetchCurrentFilename(ctx context.Context, endpointURL string) (string, error) {
	if a.FetchCurrentFilename == nil {
		return "", fmt.Errorf("moonraker runtime adapter is missing current filename fetcher")
	}
	return a.FetchCurrentFilename(ctx, endpointURL)
}

func (a RuntimeAdapter) deletePath(ctx context.Context, endpointURL, path string) error {
	if a.DeletePath == nil {
		return fmt.Errorf("moonraker runtime adapter is missing file delete path executor")
	}
	return a.DeletePath(ctx, endpointURL, path)
}

func ParseFileActionPayload(payload map[string]any) (string, FileFingerprint, error) {
	path := strings.TrimSpace(stringValue(payload["path"]))
	if path == "" {
		return "", FileFingerprint{}, errors.New("validation_error: printer file action requires path")
	}
	rawFingerprint, ok := payload["expected_fingerprint"].(map[string]any)
	if !ok {
		return "", FileFingerprint{}, errors.New("validation_error: printer file action requires expected_fingerprint")
	}
	fingerprint := FileFingerprint{Path: path}
	if sizeRaw, ok := rawFingerprint["size_bytes"]; ok {
		switch value := sizeRaw.(type) {
		case float64:
			size := int64(value)
			fingerprint.SizeBytes = &size
		case int64:
			size := value
			fingerprint.SizeBytes = &size
		case int:
			size := int64(value)
			fingerprint.SizeBytes = &size
		}
	}
	if modifiedRaw := strings.TrimSpace(stringValue(rawFingerprint["modified_at"])); modifiedRaw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, modifiedRaw)
		if err != nil {
			return "", FileFingerprint{}, fmt.Errorf("validation_error: invalid expected modified_at: %w", err)
		}
		fingerprint.ModifiedAt = &parsed
	}
	return path, fingerprint, nil
}

func ParseDeleteTargetsPayload(payload map[string]any) ([]DeleteTarget, error) {
	rawFiles, ok := payload["files"].([]any)
	if !ok || len(rawFiles) == 0 {
		return nil, errors.New("validation_error: printer bulk delete requires files")
	}
	targets := make([]DeleteTarget, 0, len(rawFiles))
	for _, rawFile := range rawFiles {
		item, ok := rawFile.(map[string]any)
		if !ok {
			return nil, errors.New("validation_error: printer bulk delete contains invalid file entry")
		}
		path, expected, err := ParseFileActionPayload(item)
		if err != nil {
			return nil, err
		}
		targets = append(targets, DeleteTarget{Path: path, Expected: expected})
	}
	return targets, nil
}

func FileFingerprintMatches(path string, size *int64, modified *time.Time, expected FileFingerprint) bool {
	if strings.TrimSpace(path) != strings.TrimSpace(expected.Path) {
		return false
	}
	if expected.SizeBytes != nil && size != nil && *expected.SizeBytes != *size {
		return false
	}
	if expected.ModifiedAt != nil {
		if modified == nil {
			return false
		}
		expectedModified := expected.ModifiedAt.UTC().Truncate(time.Second)
		actualModified := modified.UTC().Truncate(time.Second)
		if !expectedModified.Equal(actualModified) {
			return false
		}
	}
	return true
}

func stringValue(raw any) string {
	if raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return value
	case fmt.Stringer:
		return value.String()
	default:
		return fmt.Sprint(raw)
	}
}

func (a RuntimeAdapter) audit(event string, payload map[string]any) {
	if a.Audit != nil {
		a.Audit(event, payload)
	}
}

func (a RuntimeAdapter) printStartAuditFields(binding printeradapter.Binding, action printeradapter.RuntimeAction, filename string) map[string]any {
	return map[string]any{
		"printer_id":     binding.PrinterID,
		"job_id":         strings.TrimSpace(action.Target.JobID),
		"plate_id":       action.Target.PlateID,
		"filename":       strings.TrimSpace(filename),
		"adapter_family": "moonraker",
	}
}

func mergedAuditFields(base map[string]any, extra map[string]any) map[string]any {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]any, len(base)+len(extra))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}
