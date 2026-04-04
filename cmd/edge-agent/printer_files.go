package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
)

type printerFileDeleteTarget struct {
	Path             string
	DisplayName      string
	Expected         printerFileFingerprint
	DeleteDescriptor map[string]any
}

func printerFileOriginFromPath(raw string) string {
	normalized := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	base := filepath.Base(normalized)
	if strings.HasPrefix(base, "pfh-") || strings.HasPrefix(base, "printer_") || strings.Contains(base, "_printer_") {
		return "printfarmhq"
	}
	return "external"
}

func isMoonrakerPrintableFileFormat(raw string) bool {
	switch normalizePlateArtifactExtension(raw) {
	case ".gcode", ".gco", ".gc", ".ngc":
		return true
	default:
		return false
	}
}

func isBambuPrintableFileFormat(raw string) bool {
	switch normalizePlateArtifactExtension(raw) {
	case ".3mf", ".gcode", ".gcode.3mf":
		return true
	default:
		return false
	}
}

func isBambuDeletableFileFormat(raw string) bool {
	lowered := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasSuffix(lowered, ".3mf") || strings.HasSuffix(lowered, ".gcode") || strings.HasSuffix(lowered, ".gcode.3mf") || strings.HasSuffix(lowered, ".bbl")
}

func parsePrinterFileActionPayload(payload map[string]any) (string, printerFileFingerprint, error) {
	path := strings.TrimSpace(stringFromAny(payload["path"]))
	if path == "" {
		return "", printerFileFingerprint{}, errors.New("validation_error: printer file action requires path")
	}
	rawFingerprint, ok := payload["expected_fingerprint"].(map[string]any)
	if !ok {
		return "", printerFileFingerprint{}, errors.New("validation_error: printer file action requires expected_fingerprint")
	}
	fingerprint := printerFileFingerprint{Path: path}
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
	if modifiedRaw := strings.TrimSpace(stringFromAny(rawFingerprint["modified_at"])); modifiedRaw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, modifiedRaw)
		if err != nil {
			return "", printerFileFingerprint{}, fmt.Errorf("validation_error: invalid expected modified_at: %w", err)
		}
		fingerprint.ModifiedAt = &parsed
	}
	return path, fingerprint, nil
}

func parsePrinterFileDeleteTargetsPayload(payload map[string]any) ([]printerFileDeleteTarget, error) {
	rawFiles, ok := payload["files"].([]any)
	if !ok || len(rawFiles) == 0 {
		return nil, errors.New("validation_error: printer bulk delete requires files")
	}
	targets := make([]printerFileDeleteTarget, 0, len(rawFiles))
	for _, rawFile := range rawFiles {
		item, ok := rawFile.(map[string]any)
		if !ok {
			return nil, errors.New("validation_error: printer bulk delete contains invalid file entry")
		}
		path, expected, err := parsePrinterFileActionPayload(item)
		if err != nil {
			return nil, err
		}
		targets = append(targets, printerFileDeleteTarget{
			Path:             path,
			DisplayName:      strings.TrimSpace(stringFromAny(item["display_name"])),
			Expected:         expected,
			DeleteDescriptor: mapStringAny(item["delete_descriptor"]),
		})
	}
	return targets, nil
}

func mapStringAny(raw any) map[string]any {
	value, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	return value
}

func parseStringSlice(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(stringFromAny(item))
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func parseBambuStartDescriptor(payload map[string]any) (string, string, string, error) {
	descriptor := mapStringAny(payload["start_descriptor"])
	if descriptor == nil {
		path := strings.TrimSpace(stringFromAny(payload["path"]))
		if path == "" {
			return "", "", "", errors.New("validation_error: missing bambu start path")
		}
		projectPath := ""
		if ext := normalizePlateArtifactExtension(path); ext == ".3mf" || ext == ".gcode.3mf" {
			projectPath = defaultBambuLANProjectFileParam()
		}
		return path, normalizeBambuLANRemoteStartFilename(path), projectPath, nil
	}
	ftpsPath := normalizeBambuLANFTPSPath(stringFromAny(descriptor["ftps_path"]))
	projectRemoteName := strings.TrimSpace(stringFromAny(descriptor["project_remote_name"]))
	projectPath := strings.TrimSpace(stringFromAny(descriptor["project_path"]))
	if ftpsPath == "" || projectRemoteName == "" {
		return "", "", "", errors.New("validation_error: invalid bambu start descriptor")
	}
	return ftpsPath, projectRemoteName, projectPath, nil
}

func parseBambuDeleteDescriptor(payload map[string]any) (bambuLANDeleteDescriptor, error) {
	descriptor := mapStringAny(payload["delete_descriptor"])
	if descriptor == nil {
		path := strings.TrimSpace(stringFromAny(payload["path"]))
		if path == "" {
			return bambuLANDeleteDescriptor{}, errors.New("validation_error: missing bambu delete path")
		}
		return bambuLANDeleteDescriptor{PrimaryFTPSPath: path}, nil
	}
	primaryFTPSPath := normalizeBambuLANFTPSPath(stringFromAny(descriptor["primary_ftps_path"]))
	if primaryFTPSPath == "" {
		return bambuLANDeleteDescriptor{}, errors.New("validation_error: invalid bambu delete descriptor")
	}
	companionPaths := make([]string, 0, 2)
	for _, candidate := range parseStringSlice(descriptor["companion_ftps_paths"]) {
		normalized := normalizeBambuLANFTPSPath(candidate)
		if normalized == "" {
			continue
		}
		companionPaths = append(companionPaths, normalized)
	}
	return bambuLANDeleteDescriptor{
		PrimaryFTPSPath:    primaryFTPSPath,
		CompanionFTPSPaths: companionPaths,
		ControlDeletePath:  strings.TrimSpace(stringFromAny(descriptor["control_delete_path"])),
		ControlDeleteName:  strings.TrimSpace(stringFromAny(descriptor["control_delete_name"])),
	}, nil
}

func printerFileFingerprintMatches(path string, size *int64, modified *time.Time, expected printerFileFingerprint) bool {
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

func fileFingerprint(path string, size *int64, modified *time.Time) printerFileFingerprint {
	return printerFileFingerprint{
		Path:       strings.TrimSpace(path),
		SizeBytes:  size,
		ModifiedAt: modified,
	}
}

func int64Pointer(value int64) *int64 {
	return &value
}

func parseUnixSecondsPointer(raw float64) *time.Time {
	if raw <= 0 {
		return nil
	}
	seconds := int64(raw)
	nanos := int64((raw - float64(seconds)) * float64(time.Second))
	value := time.Unix(seconds, nanos).UTC()
	return &value
}

func (a *agent) reportPrinterFilesSnapshot(
	ctx context.Context,
	binding edgeBinding,
	files []printerFileEntry,
	refreshErr error,
) error {
	bootstrap := a.snapshotBootstrap()
	if bootstrap.AgentID == "" {
		return nil
	}
	endpoint := fmt.Sprintf(
		"%s/edge/agents/%s/printer-files",
		strings.TrimSuffix(bootstrap.ControlPlaneURL, "/"),
		bootstrap.AgentID,
	)
	payload := printerFilesReportRequest{
		Items: []printerFilesSnapshotItem{
			{
				PrinterID:     binding.PrinterID,
				AdapterFamily: normalizeAdapterFamily(binding.AdapterFamily),
				Files:         files,
				ReportedAt:    edgeTimestamp{Time: time.Now().UTC()},
			},
		},
	}
	if refreshErr != nil {
		payload.Items[0].Error = refreshErr.Error()
	}
	var out printerFilesReportResponse
	return doJSONRequest(
		a.client,
		http.MethodPost,
		endpoint,
		bootstrap.SaaSAPIKey,
		"",
		payload,
		&out,
		map[string]string{"X-Agent-Schema-Version": schemaVersionHeaderValue()},
	)
}

func (a *agent) refreshMoonrakerPrinterFiles(ctx context.Context, queuedAction action, binding edgeBinding) error {
	files, err := a.listMoonrakerPrinterFiles(ctx, binding.EndpointURL)
	reportErr := a.reportPrinterFilesSnapshot(ctx, binding, files, err)
	if reportErr != nil {
		return reportErr
	}
	return err
}

func (a *agent) refreshBambuPrinterFiles(ctx context.Context, queuedAction action, binding edgeBinding) error {
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
	activeFilePath := ""
	if snapshot, snapErr := fetchBambuLANMQTTSnapshot(ctx, strings.TrimSpace(credentials.Host), strings.TrimSpace(credentials.Serial), strings.TrimSpace(credentials.AccessCode)); snapErr == nil {
		activeFilePath = snapshot.ActiveFilePath
	}
	files, listErr := defaultListBambuLANPrinterFiles(ctx, credentials, activeFilePath)
	if listErr == nil {
		files = a.enrichBambuLANDeleteDescriptorsWithControlTargets(ctx, credentials, files)
	}
	reportErr := a.reportPrinterFilesSnapshot(ctx, binding, files, listErr)
	if reportErr != nil {
		return reportErr
	}
	return listErr
}

func (a *agent) bestEffortRefreshPrinterFiles(ctx context.Context, binding edgeBinding) {
	var err error
	switch normalizeAdapterFamily(binding.AdapterFamily) {
	case "moonraker":
		err = a.refreshMoonrakerPrinterFiles(ctx, action{PrinterID: binding.PrinterID, Kind: "refresh_file_index"}, binding)
	case "bambu":
		err = a.refreshBambuPrinterFiles(ctx, action{PrinterID: binding.PrinterID, Kind: "refresh_file_index"}, binding)
	default:
		return
	}
	if err != nil {
		a.audit("printer_files_refresh_error", map[string]any{
			"printer_id":     binding.PrinterID,
			"adapter_family": normalizeAdapterFamily(binding.AdapterFamily),
			"error":          err.Error(),
		})
	}
}

func (a *agent) listMoonrakerPrinterFiles(ctx context.Context, endpointURL string) ([]printerFileEntry, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/server/files/list?root=gcodes"),
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
		return nil, fmt.Errorf("moonraker file list failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Result []struct {
			Path        string      `json:"path"`
			ModifiedRaw json.Number `json:"modified"`
			SizeRaw     json.Number `json:"size"`
			Permissions string      `json:"permissions"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	activePath, _ := a.fetchMoonrakerCurrentFilename(ctx, endpointURL)
	normalizedActivePath := strings.TrimSpace(activePath)
	files := make([]printerFileEntry, 0, len(payload.Result))
	for _, item := range payload.Result {
		path := strings.TrimSpace(item.Path)
		if !isMoonrakerPrintableFileFormat(path) {
			continue
		}
		sizeBytes, _ := item.SizeRaw.Int64()
		modifiedFloat, _ := item.ModifiedRaw.Float64()
		sizePtr := int64Pointer(sizeBytes)
		modifiedAt := parseUnixSecondsPointer(modifiedFloat)
		isActive := normalizedActivePath != "" && strings.EqualFold(normalizedActivePath, path)
		files = append(files, printerFileEntry{
			Path:                path,
			DisplayName:         filepath.Base(path),
			SizeBytes:           sizePtr,
			ModifiedAt:          modifiedAt,
			Format:              normalizePlateArtifactExtension(path),
			Origin:              printerFileOriginFromPath(path),
			Startable:           true,
			Deletable:           !isActive,
			IsActiveFile:        isActive,
			ExpectedFingerprint: fileFingerprint(path, sizePtr, modifiedAt),
		})
	}
	return files, nil
}

func (a *agent) fetchMoonrakerCurrentFilename(ctx context.Context, endpointURL string) (string, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/printer/objects/query?print_stats"),
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
		return "", fmt.Errorf("moonraker print_stats query failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Result struct {
			Status struct {
				PrintStats struct {
					Filename string `json:"filename"`
				} `json:"print_stats"`
			} `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return strings.TrimSpace(payload.Result.Status.PrintStats.Filename), nil
}

func (a *agent) fetchMoonrakerRemoteFileMetadata(
	ctx context.Context,
	endpointURL string,
	filename string,
) (*int64, *time.Time, bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		resolveURL(endpointURL, "/server/files/metadata?filename="+url.QueryEscape(filename)),
		nil,
	)
	if err != nil {
		return nil, nil, false, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, nil, false, fmt.Errorf("moonraker file metadata failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Result struct {
			SizeRaw     json.Number `json:"size"`
			ModifiedRaw json.Number `json:"modified"`
		} `json:"result"`
	}
	decoder := json.NewDecoder(resp.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, nil, false, err
	}
	sizeBytes, err := payload.Result.SizeRaw.Int64()
	if err != nil {
		floatValue, floatErr := payload.Result.SizeRaw.Float64()
		if floatErr != nil {
			return nil, nil, true, fmt.Errorf("moonraker metadata invalid size %q: %w", payload.Result.SizeRaw.String(), err)
		}
		sizeBytes = int64(floatValue)
	}
	modifiedFloat, _ := payload.Result.ModifiedRaw.Float64()
	return int64Pointer(sizeBytes), parseUnixSecondsPointer(modifiedFloat), true, nil
}

func (a *agent) executeMoonrakerStartExistingFile(ctx context.Context, queuedAction action, binding edgeBinding) error {
	return a.moonrakerRuntimeAdapter().ExecuteAction(ctx, runtimeActionFromQueuedAction(queuedAction), printeradapter.Binding{
		PrinterID:     binding.PrinterID,
		AdapterFamily: binding.AdapterFamily,
		EndpointURL:   binding.EndpointURL,
	})
}

func (a *agent) executeMoonrakerDeleteFile(ctx context.Context, queuedAction action, binding edgeBinding) error {
	return a.moonrakerRuntimeAdapter().ExecuteAction(ctx, runtimeActionFromQueuedAction(queuedAction), printeradapter.Binding{
		PrinterID:     binding.PrinterID,
		AdapterFamily: binding.AdapterFamily,
		EndpointURL:   binding.EndpointURL,
	})
}

func (a *agent) executeMoonrakerDeleteAllFiles(ctx context.Context, queuedAction action, binding edgeBinding) error {
	return a.moonrakerRuntimeAdapter().ExecuteAction(ctx, runtimeActionFromQueuedAction(queuedAction), printeradapter.Binding{
		PrinterID:     binding.PrinterID,
		AdapterFamily: binding.AdapterFamily,
		EndpointURL:   binding.EndpointURL,
	})
}

func (a *agent) executeBambuLANStartExistingFile(ctx context.Context, queuedAction action, binding edgeBinding) error {
	return a.bambuRuntimeAdapter().ExecuteAction(ctx, runtimeActionFromQueuedAction(queuedAction), printeradapter.Binding{
		PrinterID:     binding.PrinterID,
		AdapterFamily: binding.AdapterFamily,
		EndpointURL:   binding.EndpointURL,
	})
}

func (a *agent) executeBambuLANDeleteFile(ctx context.Context, queuedAction action, binding edgeBinding) error {
	return a.bambuRuntimeAdapter().ExecuteAction(ctx, runtimeActionFromQueuedAction(queuedAction), printeradapter.Binding{
		PrinterID:     binding.PrinterID,
		AdapterFamily: binding.AdapterFamily,
		EndpointURL:   binding.EndpointURL,
	})
}

func (a *agent) executeBambuLANDeleteAllFiles(ctx context.Context, queuedAction action, binding edgeBinding) error {
	return a.bambuRuntimeAdapter().ExecuteAction(ctx, runtimeActionFromQueuedAction(queuedAction), printeradapter.Binding{
		PrinterID:     binding.PrinterID,
		AdapterFamily: binding.AdapterFamily,
		EndpointURL:   binding.EndpointURL,
	})
}
