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
	path, expected, err := parsePrinterFileActionPayload(queuedAction.Payload)
	if err != nil {
		return err
	}
	if !isMoonrakerPrintableFileFormat(path) {
		return fmt.Errorf("validation_error: unsupported moonraker file format for start: %s", path)
	}
	sizeBytes, modifiedAt, exists, err := a.fetchMoonrakerRemoteFileMetadata(ctx, binding.EndpointURL, path)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("printer_file_not_found: moonraker file no longer exists")
	}
	if !printerFileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: moonraker file changed since the last refresh")
	}
	if err := a.callMoonrakerPost(ctx, binding.EndpointURL, "/printer/print/start", map[string]string{"filename": path}); err != nil {
		return err
	}
	a.bestEffortRefreshPrinterFiles(ctx, binding)
	return nil
}

func (a *agent) executeMoonrakerDeleteFile(ctx context.Context, queuedAction action, binding edgeBinding) error {
	path, expected, err := parsePrinterFileActionPayload(queuedAction.Payload)
	if err != nil {
		return err
	}
	sizeBytes, modifiedAt, exists, err := a.fetchMoonrakerRemoteFileMetadata(ctx, binding.EndpointURL, path)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("printer_file_not_found: moonraker file no longer exists")
	}
	if !printerFileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: moonraker file changed since the last refresh")
	}
	activePath, _ := a.fetchMoonrakerCurrentFilename(ctx, binding.EndpointURL)
	if activePath != "" && strings.EqualFold(strings.TrimSpace(activePath), strings.TrimSpace(path)) {
		return errors.New("printer_file_active: cannot delete the currently active moonraker file")
	}

	requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodDelete,
		resolveURL(binding.EndpointURL, "/server/files/gcodes/"+url.PathEscape(path)),
		nil,
	)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("moonraker delete file failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	a.bestEffortRefreshPrinterFiles(ctx, binding)
	return nil
}

func (a *agent) executeMoonrakerDeleteAllFiles(ctx context.Context, queuedAction action, binding edgeBinding) error {
	targets, err := parsePrinterFileDeleteTargetsPayload(queuedAction.Payload)
	if err != nil {
		return err
	}
	activePath, _ := a.fetchMoonrakerCurrentFilename(ctx, binding.EndpointURL)
	for _, target := range targets {
		sizeBytes, modifiedAt, exists, metadataErr := a.fetchMoonrakerRemoteFileMetadata(ctx, binding.EndpointURL, target.Path)
		if metadataErr != nil {
			return metadataErr
		}
		if !exists {
			return fmt.Errorf("printer_file_not_found: moonraker file no longer exists: %s", target.Path)
		}
		if !printerFileFingerprintMatches(target.Path, sizeBytes, modifiedAt, target.Expected) {
			return fmt.Errorf("printer_file_snapshot_mismatch: moonraker file changed since the last refresh: %s", target.Path)
		}
		if activePath != "" && strings.EqualFold(strings.TrimSpace(activePath), strings.TrimSpace(target.Path)) {
			return fmt.Errorf("printer_file_active: cannot delete the currently active moonraker file: %s", target.Path)
		}
	}

	for _, target := range targets {
		requestCtx, cancel := context.WithTimeout(ctx, a.cfg.MoonrakerRequestTimeout)
		req, reqErr := http.NewRequestWithContext(
			requestCtx,
			http.MethodDelete,
			resolveURL(binding.EndpointURL, "/server/files/gcodes/"+url.PathEscape(target.Path)),
			nil,
		)
		if reqErr != nil {
			cancel()
			return reqErr
		}
		resp, doErr := a.client.Do(req)
		if doErr != nil {
			cancel()
			return doErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			cancel()
			return fmt.Errorf("moonraker delete file failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		resp.Body.Close()
		cancel()
	}
	a.bestEffortRefreshPrinterFiles(ctx, binding)
	return nil
}

func (a *agent) executeBambuLANStartExistingFile(ctx context.Context, queuedAction action, binding edgeBinding) error {
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
	path, expected, err := parsePrinterFileActionPayload(queuedAction.Payload)
	if err != nil {
		return err
	}
	if !isBambuPrintableFileFormat(path) {
		return fmt.Errorf("validation_error: unsupported bambu printer file format for start: %s", path)
	}
	ftpsPath, projectRemoteName, projectPath, err := parseBambuStartDescriptor(queuedAction.Payload)
	if err != nil {
		return err
	}
	sizeBytes, modifiedAt, err := fetchBambuLANRemoteFileMetadata(ctx, credentials, ftpsPath)
	if err != nil {
		if isBambuLANFTPSNotFound(err) {
			return errors.New("printer_file_not_found: bambu file no longer exists")
		}
		return err
	}
	if !printerFileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: bambu file changed since the last refresh")
	}
	fileMD5, retrievedSize, err := fetchBambuLANRemoteFileMD5(ctx, credentials, ftpsPath)
	if err != nil {
		return err
	}
	if sizeBytes != nil && retrievedSize != nil && *sizeBytes != *retrievedSize {
		return errors.New("printer_file_snapshot_mismatch: bambu file size changed during start verification")
	}
	projectReq := bambuLANProjectFileRequest{
		RemoteName:  projectRemoteName,
		FileMD5:     fileMD5,
		ProjectPath: projectPath,
	}
	if err := dispatchBambuLANProjectFile(ctx, credentials, projectReq); err != nil {
		return err
	}
	a.bestEffortRefreshPrinterFiles(ctx, binding)
	return nil
}

func (a *agent) executeBambuLANDeleteFile(ctx context.Context, queuedAction action, binding edgeBinding) error {
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
	path, expected, err := parsePrinterFileActionPayload(queuedAction.Payload)
	if err != nil {
		return err
	}
	if !isBambuDeletableFileFormat(path) {
		return fmt.Errorf("validation_error: unsupported bambu printer file format for delete: %s", path)
	}
	deleteDescriptor, err := parseBambuDeleteDescriptor(queuedAction.Payload)
	if err != nil {
		return err
	}
	sizeBytes, modifiedAt, err := fetchBambuLANRemoteFileMetadata(ctx, credentials, deleteDescriptor.PrimaryFTPSPath)
	if err != nil {
		if isBambuLANFTPSNotFound(err) {
			return errors.New("printer_file_not_found: bambu file no longer exists")
		}
		return err
	}
	if !printerFileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: bambu file changed since the last refresh")
	}
	if snapshot, snapErr := fetchBambuLANMQTTSnapshot(ctx, strings.TrimSpace(credentials.Host), strings.TrimSpace(credentials.Serial), strings.TrimSpace(credentials.AccessCode)); snapErr == nil {
		if snapshot.ActiveFilePath != "" && strings.EqualFold(bambuLANLogicalPrintableKey(snapshot.ActiveFilePath), bambuLANLogicalPrintableKey(path)) {
			return errors.New("printer_file_active: cannot delete the currently active bambu file")
		}
	}
	controlDeleteAttempted := false
	if deleteDescriptor.ControlDeletePath != "" || deleteDescriptor.ControlDeleteName != "" {
		if pluginLibraryPath, pluginErr := ensureBambuLANPluginLibrary(ctx, a.cfg.BambuCameraRuntimeDir); pluginErr == nil {
			controlDeleteAttempted = true
			controlErr := deleteBambuLANControlFiles(ctx, pluginLibraryPath, credentials, []bambuLANControlDeleteTarget{{
				Path: deleteDescriptor.ControlDeletePath,
				Name: deleteDescriptor.ControlDeleteName,
			}})
			if controlErr != nil {
				a.audit("bambu_file_control_delete_fallback", map[string]any{
					"printer_id": binding.PrinterID,
					"path":       path,
					"error":      controlErr.Error(),
				})
			}
		}
	}
	if err := deleteBambuLANExistingFile(ctx, credentials, deleteDescriptor.PrimaryFTPSPath); err != nil {
		if !(controlDeleteAttempted && isBambuLANFTPSNotFound(err)) {
			return err
		}
	}
	for _, companionFTPSPath := range deleteDescriptor.CompanionFTPSPaths {
		if err := deleteBambuLANExistingFile(ctx, credentials, companionFTPSPath); err != nil && !isBambuLANFTPSNotFound(err) {
			return err
		}
	}
	activeFilePath := ""
	if snapshot, snapErr := fetchBambuLANMQTTSnapshot(ctx, strings.TrimSpace(credentials.Host), strings.TrimSpace(credentials.Serial), strings.TrimSpace(credentials.AccessCode)); snapErr == nil {
		activeFilePath = snapshot.ActiveFilePath
	}
	filesAfterDelete, listErr := defaultListBambuLANPrinterFiles(ctx, credentials, activeFilePath)
	if listErr != nil {
		return fmt.Errorf("printer_file_delete_verification_failed: unable to refresh printer files after delete: %w", listErr)
	}
	for _, file := range filesAfterDelete {
		if strings.TrimSpace(file.Path) == strings.TrimSpace(path) {
			return bambuLANDeleteVerificationError(path, filesAfterDelete)
		}
	}
	a.bestEffortRefreshPrinterFiles(ctx, binding)
	return nil
}

func (a *agent) executeBambuLANDeleteAllFiles(ctx context.Context, queuedAction action, binding edgeBinding) error {
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
	targets, err := parsePrinterFileDeleteTargetsPayload(queuedAction.Payload)
	if err != nil {
		return err
	}

	activeLogicalKey := ""
	if snapshot, snapErr := fetchBambuLANMQTTSnapshot(ctx, strings.TrimSpace(credentials.Host), strings.TrimSpace(credentials.Serial), strings.TrimSpace(credentials.AccessCode)); snapErr == nil {
		activeLogicalKey = bambuLANLogicalPrintableKey(snapshot.ActiveFilePath)
	}

	client, err := dialBambuLANArtifactClient(ctx, strings.TrimSpace(credentials.Host))
	if err != nil {
		return err
	}
	defer client.close()
	if err := client.login(bambuLANFTPSUsername, strings.TrimSpace(credentials.AccessCode)); err != nil {
		return err
	}
	if err := client.setBinaryMode(); err != nil {
		return err
	}

	pathsToDelete := make([]string, 0, len(targets)*2)
	controlTargets := make([]bambuLANControlDeleteTarget, 0, len(targets))
	seenPaths := make(map[string]struct{})
	for _, target := range targets {
		if !isBambuDeletableFileFormat(target.Path) {
			return fmt.Errorf("validation_error: unsupported bambu printer file format for delete: %s", target.Path)
		}
		deleteDescriptor, descriptorErr := parseBambuDeleteDescriptor(map[string]any{
			"path":              target.Path,
			"delete_descriptor": target.DeleteDescriptor,
		})
		if descriptorErr != nil {
			return descriptorErr
		}
		sizeBytes, metadataErr := client.size(deleteDescriptor.PrimaryFTPSPath)
		if metadataErr != nil {
			if isBambuLANFTPSNotFound(metadataErr) {
				return fmt.Errorf("printer_file_not_found: bambu file no longer exists: %s", target.Path)
			}
			return metadataErr
		}
		sizePtr := int64Pointer(sizeBytes)
		modifiedPtr, _ := client.modTime(deleteDescriptor.PrimaryFTPSPath)
		if !printerFileFingerprintMatches(target.Path, sizePtr, modifiedPtr, target.Expected) {
			return fmt.Errorf("printer_file_snapshot_mismatch: bambu file changed since the last refresh: %s", target.Path)
		}
		if activeLogicalKey != "" && strings.EqualFold(activeLogicalKey, bambuLANLogicalPrintableKey(target.Path)) {
			return fmt.Errorf("printer_file_active: cannot delete the currently active bambu file: %s", target.Path)
		}
		if _, ok := seenPaths[deleteDescriptor.PrimaryFTPSPath]; !ok {
			seenPaths[deleteDescriptor.PrimaryFTPSPath] = struct{}{}
			pathsToDelete = append(pathsToDelete, deleteDescriptor.PrimaryFTPSPath)
		}
		for _, companionFTPSPath := range deleteDescriptor.CompanionFTPSPaths {
			if _, ok := seenPaths[companionFTPSPath]; ok {
				continue
			}
			seenPaths[companionFTPSPath] = struct{}{}
			pathsToDelete = append(pathsToDelete, companionFTPSPath)
		}
		if deleteDescriptor.ControlDeletePath != "" || deleteDescriptor.ControlDeleteName != "" {
			controlTargets = append(controlTargets, bambuLANControlDeleteTarget{
				Path: deleteDescriptor.ControlDeletePath,
				Name: deleteDescriptor.ControlDeleteName,
			})
		}
	}

	if len(controlTargets) > 0 {
		if pluginLibraryPath, pluginErr := ensureBambuLANPluginLibrary(ctx, a.cfg.BambuCameraRuntimeDir); pluginErr == nil {
			if controlErr := deleteBambuLANControlFiles(ctx, pluginLibraryPath, credentials, controlTargets); controlErr != nil {
				a.audit("bambu_file_control_delete_fallback", map[string]any{
					"printer_id": binding.PrinterID,
					"count":      len(controlTargets),
					"error":      controlErr.Error(),
				})
			}
		}
	}

	for _, ftpsPath := range pathsToDelete {
		if err := client.delete(ftpsPath); err != nil && !isBambuLANFTPSNotFound(err) {
			return err
		}
	}

	filesAfterDelete, listErr := defaultListBambuLANPrinterFiles(ctx, credentials, "")
	if listErr != nil {
		return fmt.Errorf("printer_file_delete_verification_failed: unable to refresh printer files after bulk delete: %w", listErr)
	}
	surviving := make(map[string]struct{}, len(filesAfterDelete))
	for _, file := range filesAfterDelete {
		surviving[strings.TrimSpace(file.Path)] = struct{}{}
	}
	for _, target := range targets {
		if _, ok := surviving[strings.TrimSpace(target.Path)]; ok {
			return bambuLANDeleteVerificationError(target.Path, filesAfterDelete)
		}
	}

	a.bestEffortRefreshPrinterFiles(ctx, binding)
	return nil
}
