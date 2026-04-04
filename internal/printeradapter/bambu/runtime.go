package bambu

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
)

type RuntimeAdapter struct {
	ExecuteLANPrint                func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	ExecuteLANControl              func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding, command string) error
	IsCredentialsUnavailable       func(err error) bool
	RefreshFiles                   func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	StartExistingFile              func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	DeleteFile                     func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	DeleteAllFiles                 func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	ExecutePrinterCommand          func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error
	ResolveCredentials             func(ctx context.Context, printerID string) (Credentials, error)
	ParsePrinterID                 func(endpointURL string) (string, error)
	DecorateCredentialsUnavailable func(ctx context.Context, binding printeradapter.Binding, err error) error
	PublishLED                     func(ctx context.Context, credentials Credentials, ledMode string) error
	VerifyLEDState                 func(ctx context.Context, serial string, ledMode string) error
	PublishFilamentAction          func(ctx context.Context, credentials Credentials, kind string) error
	PublishPrinterGCode            func(ctx context.Context, credentials Credentials, gcodeLine string) error
	BuildHomeAxesGCode             func(payload map[string]any) (string, error)
	BuildJogMotionGCode            func(payload map[string]any) (string, error)
	BuildJogMotionBatchGCode       func(payload map[string]any) (string, error)
	BuildFanControlGCode           func(payload map[string]any) (string, error)
	BuildNozzleTempGCode           func(payload map[string]any) (string, error)
	BuildBedTempGCode              func(payload map[string]any) (string, error)
	FetchRemoteMetadata            func(ctx context.Context, credentials Credentials, path string) (*int64, *time.Time, error)
	IsRemoteNotFound               func(err error) bool
	FetchRemoteMD5                 func(ctx context.Context, credentials Credentials, path string) (string, *int64, error)
	DispatchProjectFile            func(ctx context.Context, credentials Credentials, req ProjectFileRequest) error
	FetchActiveFilePath            func(ctx context.Context, credentials Credentials) (string, error)
	EnsurePluginBundle             func(ctx context.Context) (string, error)
	DeleteControlFiles             func(ctx context.Context, pluginLibraryPath string, credentials Credentials, targets []ControlDeleteTarget) error
	DeleteExistingFile             func(ctx context.Context, credentials Credentials, path string) error
	ListPrinterFiles               func(ctx context.Context, credentials Credentials, activeFilePath string) ([]ListedFile, error)
	Audit                          func(event string, payload map[string]any)
	IsPrintableFileFormat          func(path string) bool
	IsDeletableFileFormat          func(path string) bool
	DownloadArtifact               func(ctx context.Context, req printeradapter.StartPrintRequest) (StagedArtifact, error)
	CleanupArtifact                func(path string)
	ProbeArtifactReuse             func(ctx context.Context, credentials Credentials, remoteName string, artifact StagedArtifact) (bool, string, error)
	UploadArtifact                 func(ctx context.Context, credentials Credentials, remoteName string, fileBytes []byte) error
	VerificationTimeout            func() time.Duration
	ExtendConnectivitySuppression  func(printerID int, duration time.Duration)
	MarkPrintStartInProgress       func(action printeradapter.RuntimeAction, binding printeradapter.Binding)
	VerifyPrintStart               func(ctx context.Context, printerID string) error
}

type Credentials struct {
	Serial     string
	Host       string
	AccessCode string
}

type FileFingerprint struct {
	Path       string
	SizeBytes  *int64
	ModifiedAt *time.Time
}

type DeleteDescriptor struct {
	PrimaryFTPSPath    string
	CompanionFTPSPaths []string
	ControlDeletePath  string
	ControlDeleteName  string
}

type DeleteTarget struct {
	Path       string
	Expected   FileFingerprint
	Descriptor DeleteDescriptor
}

type ProjectFileRequest struct {
	RemoteName  string
	FileMD5     string
	ProjectPath string
}

type ControlDeleteTarget struct {
	Path string
	Name string
}

type ListedFile struct {
	Path string
}

type StagedArtifact struct {
	LocalPath           string
	SourceFilename      string
	NormalizedExtension string
	SizeBytes           int64
	SHA256              string
	MD5                 string
	RemoteName          string
}

func (a StagedArtifact) PreferredSourceName() string {
	if source := strings.TrimSpace(a.SourceFilename); source != "" {
		return source
	}
	return strings.TrimSpace(a.RemoteName)
}

func (a StagedArtifact) RemoteStartName() string {
	return normalizeRemoteStartFilename(strings.TrimSpace(a.RemoteName))
}

func (a RuntimeAdapter) ExecuteAction(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	switch strings.ToLower(strings.TrimSpace(action.Kind)) {
	case "print":
		return a.executeLANPrint(ctx, action, binding)
	case "pause", "resume", "stop":
		command := strings.ToLower(strings.TrimSpace(action.Kind))
		return a.executeLANControl(ctx, action, binding, command)
	case "refresh_file_index":
		return a.refreshFiles(ctx, action, binding)
	case "start_existing_file":
		return a.startExistingFile(ctx, action, binding)
	case "delete_file":
		return a.deleteFile(ctx, action, binding)
	case "delete_all_files":
		return a.deleteAllFiles(ctx, action, binding)
	case "light_on", "light_off", "load_filament", "unload_filament", "home_axes", "jog_motion", "jog_motion_batch", "set_fan_enabled", "set_nozzle_temperature", "set_bed_temperature":
		return a.executePrinterCommand(ctx, action, binding)
	default:
		return fmt.Errorf("unsupported action kind: %s", action.Kind)
	}
}

func (a RuntimeAdapter) executeLANPrint(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	if a.DownloadArtifact != nil &&
		a.CleanupArtifact != nil &&
		a.ProbeArtifactReuse != nil &&
		a.UploadArtifact != nil &&
		a.VerificationTimeout != nil &&
		a.VerifyPrintStart != nil {
		printerID, err := a.parsePrinterID(binding.EndpointURL)
		if err != nil {
			return err
		}
		credentials, err := a.resolveCredentials(ctx, printerID)
		if err != nil {
			if a.isCredentialsUnavailable(err) && a.DecorateCredentialsUnavailable != nil {
				return a.DecorateCredentialsUnavailable(ctx, binding, err)
			}
			return err
		}

		artifact, err := a.DownloadArtifact(ctx, action.Target)
		if err != nil {
			return err
		}
		defer a.CleanupArtifact(artifact.LocalPath)

		if ext := strings.ToLower(strings.TrimSpace(artifact.NormalizedExtension)); ext != ".3mf" && ext != ".gcode.3mf" {
			return fmt.Errorf("validation_error: bambu lan print start requires a .3mf artifact, got %q", artifact.PreferredSourceName())
		}

		remoteStartFileName := artifact.RemoteStartName()
		projectPath := defaultProjectFileParam()
		baseAuditFields := a.printStartAuditFields(binding, action, remoteStartFileName)

		a.audit("artifact_downloaded", mergedAuditFields(baseAuditFields, map[string]any{
			"source_filename": artifact.PreferredSourceName(),
			"size_bytes":      artifact.SizeBytes,
		}))
		a.audit("artifact_reuse_probe_attempt", mergedAuditFields(baseAuditFields, map[string]any{
			"transport": "bambu_lan_ftps",
		}))

		reused, reason, probeErr := a.ProbeArtifactReuse(ctx, credentials, remoteStartFileName, artifact)
		switch {
		case probeErr != nil:
			a.audit("artifact_reuse_probe_fallback_upload", mergedAuditFields(baseAuditFields, map[string]any{
				"transport": "bambu_lan_ftps",
				"reason":    reason,
				"error":     probeErr.Error(),
			}))
		case reused:
			a.audit("artifact_reused", mergedAuditFields(baseAuditFields, map[string]any{
				"transport": "bambu_lan_ftps",
				"reason":    reason,
			}))
		case reason != "" && reason != "absent":
			a.audit("artifact_reuse_probe_mismatch", mergedAuditFields(baseAuditFields, map[string]any{
				"transport": "bambu_lan_ftps",
				"reason":    reason,
			}))
		}

		if !reused {
			fileBytes, err := os.ReadFile(artifact.LocalPath)
			if err != nil {
				return err
			}
			a.audit("bambu_lan_upload_attempt", mergedAuditFields(baseAuditFields, map[string]any{
				"transport": "bambu_lan_ftps",
			}))
			if err := a.UploadArtifact(ctx, credentials, remoteStartFileName, fileBytes); err != nil {
				a.audit("bambu_lan_upload_failed", mergedAuditFields(baseAuditFields, map[string]any{
					"transport": "bambu_lan_ftps",
					"error":     err.Error(),
				}))
				return fmt.Errorf("bambu_lan_upload_failed: %w", err)
			}
			a.audit("bambu_lan_upload_success", mergedAuditFields(baseAuditFields, map[string]any{
				"transport": "bambu_lan_ftps",
			}))
			a.audit("artifact_uploaded", mergedAuditFields(baseAuditFields, map[string]any{
				"transport": "bambu_lan_ftps",
			}))
		}

		projectReq := ProjectFileRequest{
			RemoteName:  remoteStartFileName,
			FileMD5:     strings.ToUpper(strings.TrimSpace(artifact.MD5)),
			ProjectPath: projectPath,
		}
		a.audit("bambu_print_start_dispatch_attempt", mergedAuditFields(baseAuditFields, map[string]any{
			"project_path":       projectPath,
			"transport":          "bambu_lan_mqtt",
			"has_file_md5":       projectReq.FileMD5 != "",
			"uses_fixed_options": true,
		}))
		if err := a.dispatchProjectFile(ctx, credentials, projectReq); err != nil {
			a.audit("bambu_print_start_dispatch_failure", mergedAuditFields(baseAuditFields, map[string]any{
				"project_path": projectPath,
				"transport":    "bambu_lan_mqtt",
				"error":        err.Error(),
			}))
			return err
		}
		if a.ExtendConnectivitySuppression != nil {
			a.ExtendConnectivitySuppression(binding.PrinterID, a.VerificationTimeout())
		}
		if a.MarkPrintStartInProgress != nil {
			a.MarkPrintStartInProgress(action, binding)
		}
		if err := a.VerifyPrintStart(ctx, strings.TrimSpace(printerID)); err != nil {
			return fmt.Errorf("bambu_start_verification_timeout: %w", err)
		}
		a.audit("bambu_print_start_verified", mergedAuditFields(baseAuditFields, map[string]any{
			"project_path": projectPath,
			"transport":    "bambu_lan_mqtt",
		}))
		a.audit("print_start_requested", mergedAuditFields(baseAuditFields, map[string]any{
			"transport": "bambu_lan_mqtt",
		}))
		return nil
	}
	if a.ExecuteLANPrint == nil {
		return fmt.Errorf("bambu runtime adapter is missing lan print executor")
	}
	return a.ExecuteLANPrint(ctx, action, binding)
}

func (a RuntimeAdapter) executeLANControl(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding, command string) error {
	if a.ExecuteLANControl == nil {
		return fmt.Errorf("bambu runtime adapter is missing lan control executor")
	}
	return a.ExecuteLANControl(ctx, action, binding, command)
}

func (a RuntimeAdapter) isCredentialsUnavailable(err error) bool {
	if a.IsCredentialsUnavailable == nil {
		return false
	}
	return a.IsCredentialsUnavailable(err)
}

func (a RuntimeAdapter) refreshFiles(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	if a.RefreshFiles == nil {
		return fmt.Errorf("bambu runtime adapter is missing file refresh executor")
	}
	return a.RefreshFiles(ctx, action, binding)
}

func (a RuntimeAdapter) startExistingFile(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	printerID, err := a.parsePrinterID(binding.EndpointURL)
	if err != nil {
		return err
	}
	credentials, err := a.resolveCredentials(ctx, printerID)
	if err != nil {
		if a.isCredentialsUnavailable(err) && a.DecorateCredentialsUnavailable != nil {
			return a.DecorateCredentialsUnavailable(ctx, binding, err)
		}
		return err
	}
	path, expected, err := ParseFileActionPayload(action.Payload)
	if err != nil {
		return err
	}
	if a.IsPrintableFileFormat == nil || !a.IsPrintableFileFormat(path) {
		return fmt.Errorf("validation_error: unsupported bambu printer file format for start: %s", path)
	}
	ftpsPath, projectRemoteName, projectPath, err := ParseStartDescriptor(action.Payload)
	if err != nil {
		return err
	}
	sizeBytes, modifiedAt, err := a.fetchRemoteMetadata(ctx, credentials, ftpsPath)
	if err != nil {
		if a.isRemoteNotFound(err) {
			return errors.New("printer_file_not_found: bambu file no longer exists")
		}
		return err
	}
	if !FileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: bambu file changed since the last refresh")
	}
	fileMD5, retrievedSize, err := a.fetchRemoteMD5(ctx, credentials, ftpsPath)
	if err != nil {
		return err
	}
	if sizeBytes != nil && retrievedSize != nil && *sizeBytes != *retrievedSize {
		return errors.New("printer_file_snapshot_mismatch: bambu file size changed during start verification")
	}
	if err := a.dispatchProjectFile(ctx, credentials, ProjectFileRequest{
		RemoteName:  projectRemoteName,
		FileMD5:     fileMD5,
		ProjectPath: projectPath,
	}); err != nil {
		return err
	}
	return a.refreshFiles(ctx, printeradapter.RuntimeAction{Kind: "refresh_file_index"}, binding)
}

func (a RuntimeAdapter) deleteFile(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	printerID, err := a.parsePrinterID(binding.EndpointURL)
	if err != nil {
		return err
	}
	credentials, err := a.resolveCredentials(ctx, printerID)
	if err != nil {
		if a.isCredentialsUnavailable(err) && a.DecorateCredentialsUnavailable != nil {
			return a.DecorateCredentialsUnavailable(ctx, binding, err)
		}
		return err
	}
	path, expected, err := ParseFileActionPayload(action.Payload)
	if err != nil {
		return err
	}
	if a.IsDeletableFileFormat == nil || !a.IsDeletableFileFormat(path) {
		return fmt.Errorf("validation_error: unsupported bambu printer file format for delete: %s", path)
	}
	deleteDescriptor, err := ParseDeleteDescriptor(action.Payload)
	if err != nil {
		return err
	}
	sizeBytes, modifiedAt, err := a.fetchRemoteMetadata(ctx, credentials, deleteDescriptor.PrimaryFTPSPath)
	if err != nil {
		if a.isRemoteNotFound(err) {
			return errors.New("printer_file_not_found: bambu file no longer exists")
		}
		return err
	}
	if !FileFingerprintMatches(path, sizeBytes, modifiedAt, expected) {
		return errors.New("printer_file_snapshot_mismatch: bambu file changed since the last refresh")
	}
	activeFilePath, _ := a.fetchActiveFilePath(ctx, credentials)
	if activeFilePath != "" && strings.EqualFold(LogicalPrintableKey(activeFilePath), LogicalPrintableKey(path)) {
		return errors.New("printer_file_active: cannot delete the currently active bambu file")
	}
	controlDeleteAttempted := false
	if deleteDescriptor.ControlDeletePath != "" || deleteDescriptor.ControlDeleteName != "" {
		if pluginLibraryPath, pluginErr := a.ensurePluginBundle(ctx); pluginErr == nil {
			controlDeleteAttempted = true
			controlErr := a.deleteControlFiles(ctx, pluginLibraryPath, credentials, []ControlDeleteTarget{{
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
	if err := a.deleteExistingFile(ctx, credentials, deleteDescriptor.PrimaryFTPSPath); err != nil {
		if !(controlDeleteAttempted && a.isRemoteNotFound(err)) {
			return err
		}
	}
	for _, companionFTPSPath := range deleteDescriptor.CompanionFTPSPaths {
		if err := a.deleteExistingFile(ctx, credentials, companionFTPSPath); err != nil && !a.isRemoteNotFound(err) {
			return err
		}
	}
	activeFilePath = ""
	if snapshotPath, snapErr := a.fetchActiveFilePath(ctx, credentials); snapErr == nil {
		activeFilePath = snapshotPath
	}
	filesAfterDelete, listErr := a.listPrinterFiles(ctx, credentials, activeFilePath)
	if listErr != nil {
		return fmt.Errorf("printer_file_delete_verification_failed: unable to refresh printer files after delete: %w", listErr)
	}
	for _, file := range filesAfterDelete {
		if strings.TrimSpace(file.Path) == strings.TrimSpace(path) {
			return DeleteVerificationError(path, filesAfterDelete)
		}
	}
	return a.refreshFiles(ctx, printeradapter.RuntimeAction{Kind: "refresh_file_index"}, binding)
}

func (a RuntimeAdapter) deleteAllFiles(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	printerID, err := a.parsePrinterID(binding.EndpointURL)
	if err != nil {
		return err
	}
	credentials, err := a.resolveCredentials(ctx, printerID)
	if err != nil {
		if a.isCredentialsUnavailable(err) && a.DecorateCredentialsUnavailable != nil {
			return a.DecorateCredentialsUnavailable(ctx, binding, err)
		}
		return err
	}
	targets, err := ParseDeleteTargetsPayload(action.Payload)
	if err != nil {
		return err
	}
	activeLogicalKey := ""
	if snapshotPath, snapErr := a.fetchActiveFilePath(ctx, credentials); snapErr == nil {
		activeLogicalKey = LogicalPrintableKey(snapshotPath)
	}
	pathsToDelete := make([]string, 0, len(targets)*2)
	controlTargets := make([]ControlDeleteTarget, 0, len(targets))
	seenPaths := make(map[string]struct{})
	for _, target := range targets {
		if a.IsDeletableFileFormat == nil || !a.IsDeletableFileFormat(target.Path) {
			return fmt.Errorf("validation_error: unsupported bambu printer file format for delete: %s", target.Path)
		}
		sizeBytes, modifiedAt, err := a.fetchRemoteMetadata(ctx, credentials, target.Descriptor.PrimaryFTPSPath)
		if err != nil {
			if a.isRemoteNotFound(err) {
				return fmt.Errorf("printer_file_not_found: bambu file no longer exists: %s", target.Path)
			}
			return err
		}
		if !FileFingerprintMatches(target.Path, sizeBytes, modifiedAt, target.Expected) {
			return fmt.Errorf("printer_file_snapshot_mismatch: bambu file changed since the last refresh: %s", target.Path)
		}
		if activeLogicalKey != "" && strings.EqualFold(activeLogicalKey, LogicalPrintableKey(target.Path)) {
			return fmt.Errorf("printer_file_active: cannot delete the currently active bambu file: %s", target.Path)
		}
		if _, ok := seenPaths[target.Descriptor.PrimaryFTPSPath]; !ok {
			seenPaths[target.Descriptor.PrimaryFTPSPath] = struct{}{}
			pathsToDelete = append(pathsToDelete, target.Descriptor.PrimaryFTPSPath)
		}
		for _, companionFTPSPath := range target.Descriptor.CompanionFTPSPaths {
			if _, ok := seenPaths[companionFTPSPath]; ok {
				continue
			}
			seenPaths[companionFTPSPath] = struct{}{}
			pathsToDelete = append(pathsToDelete, companionFTPSPath)
		}
		if target.Descriptor.ControlDeletePath != "" || target.Descriptor.ControlDeleteName != "" {
			controlTargets = append(controlTargets, ControlDeleteTarget{
				Path: target.Descriptor.ControlDeletePath,
				Name: target.Descriptor.ControlDeleteName,
			})
		}
	}
	if len(controlTargets) > 0 {
		if pluginLibraryPath, pluginErr := a.ensurePluginBundle(ctx); pluginErr == nil {
			if controlErr := a.deleteControlFiles(ctx, pluginLibraryPath, credentials, controlTargets); controlErr != nil {
				a.audit("bambu_file_control_delete_fallback", map[string]any{
					"printer_id": binding.PrinterID,
					"count":      len(controlTargets),
					"error":      controlErr.Error(),
				})
			}
		}
	}
	for _, ftpsPath := range pathsToDelete {
		if err := a.deleteExistingFile(ctx, credentials, ftpsPath); err != nil && !a.isRemoteNotFound(err) {
			return err
		}
	}
	filesAfterDelete, listErr := a.listPrinterFiles(ctx, credentials, "")
	if listErr != nil {
		return fmt.Errorf("printer_file_delete_verification_failed: unable to refresh printer files after bulk delete: %w", listErr)
	}
	surviving := make(map[string]struct{}, len(filesAfterDelete))
	for _, file := range filesAfterDelete {
		surviving[strings.TrimSpace(file.Path)] = struct{}{}
	}
	for _, target := range targets {
		if _, ok := surviving[strings.TrimSpace(target.Path)]; ok {
			return DeleteVerificationError(target.Path, filesAfterDelete)
		}
	}
	return a.refreshFiles(ctx, printeradapter.RuntimeAction{Kind: "refresh_file_index"}, binding)
}

func (a RuntimeAdapter) executePrinterCommand(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
	printerID, err := a.parsePrinterID(binding.EndpointURL)
	if err != nil {
		return err
	}
	credentials, err := a.resolveCredentials(ctx, printerID)
	if err != nil {
		if a.isCredentialsUnavailable(err) && a.DecorateCredentialsUnavailable != nil {
			return a.DecorateCredentialsUnavailable(ctx, binding, err)
		}
		return err
	}

	switch strings.TrimSpace(action.Kind) {
	case "light_on", "light_off":
		ledMode := "on"
		if strings.TrimSpace(action.Kind) == "light_off" {
			ledMode = "off"
		}
		if a.PublishLED == nil || a.VerifyLEDState == nil {
			return fmt.Errorf("bambu runtime adapter is missing LED dependencies")
		}
		if err := a.PublishLED(ctx, credentials, ledMode); err != nil {
			return err
		}
		return a.VerifyLEDState(ctx, strings.TrimSpace(credentials.Serial), ledMode)
	case "load_filament", "unload_filament":
		if a.PublishFilamentAction == nil {
			return fmt.Errorf("bambu runtime adapter is missing filament publisher")
		}
		return a.PublishFilamentAction(ctx, credentials, strings.TrimSpace(action.Kind))
	case "home_axes":
		if a.BuildHomeAxesGCode == nil || a.PublishPrinterGCode == nil {
			return fmt.Errorf("bambu runtime adapter is missing home dependencies")
		}
		gcodeLine, err := a.BuildHomeAxesGCode(action.Payload)
		if err != nil {
			return err
		}
		return a.PublishPrinterGCode(ctx, credentials, gcodeLine)
	case "jog_motion", "jog_motion_batch":
		if a.PublishPrinterGCode == nil {
			return fmt.Errorf("bambu runtime adapter is missing jog dependencies")
		}
		var (
			gcodeLine string
			err       error
		)
		if strings.TrimSpace(action.Kind) == "jog_motion" {
			if a.BuildJogMotionGCode == nil {
				return fmt.Errorf("bambu runtime adapter is missing jog builder")
			}
			gcodeLine, err = a.BuildJogMotionGCode(action.Payload)
		} else {
			if a.BuildJogMotionBatchGCode == nil {
				return fmt.Errorf("bambu runtime adapter is missing jog batch builder")
			}
			gcodeLine, err = a.BuildJogMotionBatchGCode(action.Payload)
		}
		if err != nil {
			return err
		}
		return a.PublishPrinterGCode(ctx, credentials, gcodeLine)
	case "set_fan_enabled":
		if a.BuildFanControlGCode == nil || a.PublishPrinterGCode == nil {
			return fmt.Errorf("bambu runtime adapter is missing fan dependencies")
		}
		gcodeLine, err := a.BuildFanControlGCode(action.Payload)
		if err != nil {
			return err
		}
		return a.PublishPrinterGCode(ctx, credentials, gcodeLine)
	case "set_nozzle_temperature":
		if a.BuildNozzleTempGCode == nil || a.PublishPrinterGCode == nil {
			return fmt.Errorf("bambu runtime adapter is missing nozzle temperature dependencies")
		}
		gcodeLine, err := a.BuildNozzleTempGCode(action.Payload)
		if err != nil {
			return err
		}
		return a.PublishPrinterGCode(ctx, credentials, gcodeLine)
	case "set_bed_temperature":
		if a.BuildBedTempGCode == nil || a.PublishPrinterGCode == nil {
			return fmt.Errorf("bambu runtime adapter is missing bed temperature dependencies")
		}
		gcodeLine, err := a.BuildBedTempGCode(action.Payload)
		if err != nil {
			return err
		}
		return a.PublishPrinterGCode(ctx, credentials, gcodeLine)
	default:
		if a.ExecutePrinterCommand == nil {
			return fmt.Errorf("bambu runtime adapter is missing printer-command executor")
		}
		return a.ExecutePrinterCommand(ctx, action, binding)
	}
}

func (a RuntimeAdapter) parsePrinterID(endpointURL string) (string, error) {
	if a.ParsePrinterID == nil {
		return "", fmt.Errorf("bambu runtime adapter is missing printer id parser")
	}
	return a.ParsePrinterID(endpointURL)
}

func (a RuntimeAdapter) resolveCredentials(ctx context.Context, printerID string) (Credentials, error) {
	if a.ResolveCredentials == nil {
		return Credentials{}, fmt.Errorf("bambu runtime adapter is missing credential resolver")
	}
	return a.ResolveCredentials(ctx, printerID)
}

func (a RuntimeAdapter) fetchRemoteMetadata(ctx context.Context, credentials Credentials, path string) (*int64, *time.Time, error) {
	if a.FetchRemoteMetadata == nil {
		return nil, nil, fmt.Errorf("bambu runtime adapter is missing remote metadata fetcher")
	}
	return a.FetchRemoteMetadata(ctx, credentials, path)
}

func (a RuntimeAdapter) isRemoteNotFound(err error) bool {
	if a.IsRemoteNotFound == nil {
		return false
	}
	return a.IsRemoteNotFound(err)
}

func (a RuntimeAdapter) fetchRemoteMD5(ctx context.Context, credentials Credentials, path string) (string, *int64, error) {
	if a.FetchRemoteMD5 == nil {
		return "", nil, fmt.Errorf("bambu runtime adapter is missing remote MD5 fetcher")
	}
	return a.FetchRemoteMD5(ctx, credentials, path)
}

func (a RuntimeAdapter) dispatchProjectFile(ctx context.Context, credentials Credentials, req ProjectFileRequest) error {
	if a.DispatchProjectFile == nil {
		return fmt.Errorf("bambu runtime adapter is missing project-file dispatcher")
	}
	return a.DispatchProjectFile(ctx, credentials, req)
}

func (a RuntimeAdapter) fetchActiveFilePath(ctx context.Context, credentials Credentials) (string, error) {
	if a.FetchActiveFilePath == nil {
		return "", fmt.Errorf("bambu runtime adapter is missing active-file fetcher")
	}
	return a.FetchActiveFilePath(ctx, credentials)
}

func (a RuntimeAdapter) ensurePluginBundle(ctx context.Context) (string, error) {
	if a.EnsurePluginBundle == nil {
		return "", fmt.Errorf("bambu runtime adapter is missing plugin bundle resolver")
	}
	return a.EnsurePluginBundle(ctx)
}

func (a RuntimeAdapter) deleteControlFiles(ctx context.Context, pluginLibraryPath string, credentials Credentials, targets []ControlDeleteTarget) error {
	if a.DeleteControlFiles == nil {
		return fmt.Errorf("bambu runtime adapter is missing control delete executor")
	}
	return a.DeleteControlFiles(ctx, pluginLibraryPath, credentials, targets)
}

func (a RuntimeAdapter) deleteExistingFile(ctx context.Context, credentials Credentials, path string) error {
	if a.DeleteExistingFile == nil {
		return fmt.Errorf("bambu runtime adapter is missing existing-file delete executor")
	}
	return a.DeleteExistingFile(ctx, credentials, path)
}

func (a RuntimeAdapter) listPrinterFiles(ctx context.Context, credentials Credentials, activeFilePath string) ([]ListedFile, error) {
	if a.ListPrinterFiles == nil {
		return nil, fmt.Errorf("bambu runtime adapter is missing printer file lister")
	}
	return a.ListPrinterFiles(ctx, credentials, activeFilePath)
}

func (a RuntimeAdapter) audit(event string, payload map[string]any) {
	if a.Audit != nil {
		a.Audit(event, payload)
	}
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

func ParseStartDescriptor(payload map[string]any) (string, string, string, error) {
	descriptor := mapStringAny(payload["start_descriptor"])
	if descriptor == nil {
		path := strings.TrimSpace(stringValue(payload["path"]))
		if path == "" {
			return "", "", "", errors.New("validation_error: missing bambu start path")
		}
		projectPath := ""
		if ext := normalizePrintableExtension(path); ext == ".3mf" || ext == ".gcode.3mf" {
			projectPath = defaultProjectFileParam()
		}
		return path, normalizeRemoteStartFilename(path), projectPath, nil
	}
	ftpsPath := normalizeFTPSPath(stringValue(descriptor["ftps_path"]))
	projectRemoteName := strings.TrimSpace(stringValue(descriptor["project_remote_name"]))
	projectPath := strings.TrimSpace(stringValue(descriptor["project_path"]))
	if ftpsPath == "" || projectRemoteName == "" {
		return "", "", "", errors.New("validation_error: invalid bambu start descriptor")
	}
	return ftpsPath, projectRemoteName, projectPath, nil
}

func ParseDeleteDescriptor(payload map[string]any) (DeleteDescriptor, error) {
	descriptor := mapStringAny(payload["delete_descriptor"])
	if descriptor == nil {
		path := strings.TrimSpace(stringValue(payload["path"]))
		if path == "" {
			return DeleteDescriptor{}, errors.New("validation_error: missing bambu delete path")
		}
		return DeleteDescriptor{PrimaryFTPSPath: path}, nil
	}
	primaryFTPSPath := normalizeFTPSPath(stringValue(descriptor["primary_ftps_path"]))
	if primaryFTPSPath == "" {
		return DeleteDescriptor{}, errors.New("validation_error: invalid bambu delete descriptor")
	}
	companionPaths := make([]string, 0, 2)
	for _, candidate := range parseStringSlice(descriptor["companion_ftps_paths"]) {
		normalized := normalizeFTPSPath(candidate)
		if normalized == "" {
			continue
		}
		companionPaths = append(companionPaths, normalized)
	}
	return DeleteDescriptor{
		PrimaryFTPSPath:    primaryFTPSPath,
		CompanionFTPSPaths: companionPaths,
		ControlDeletePath:  strings.TrimSpace(stringValue(descriptor["control_delete_path"])),
		ControlDeleteName:  strings.TrimSpace(stringValue(descriptor["control_delete_name"])),
	}, nil
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
		descriptor, err := ParseDeleteDescriptor(item)
		if err != nil {
			return nil, err
		}
		targets = append(targets, DeleteTarget{Path: path, Expected: expected, Descriptor: descriptor})
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

func DeleteVerificationError(path string, files []ListedFile) error {
	survivors := make([]string, 0, len(files))
	for _, file := range files {
		if strings.TrimSpace(file.Path) == strings.TrimSpace(path) {
			survivors = append(survivors, file.Path)
		}
	}
	if len(survivors) == 0 {
		return fmt.Errorf("printer_file_delete_verification_failed: unable to confirm removal of %s from the printer file list", path)
	}
	return fmt.Errorf("printer_file_delete_verification_failed: %s is still present after delete verification", strings.Join(survivors, ", "))
}

func LogicalPrintableKey(path string) string {
	normalized := strings.TrimSpace(strings.ToLower(path))
	if strings.HasPrefix(normalized, "/cache/") {
		normalized = strings.TrimPrefix(normalized, "/cache/")
	}
	if strings.HasSuffix(normalized, ".bbl") {
		normalized = strings.TrimSuffix(normalized, ".bbl")
	}
	return normalized
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
		trimmed := strings.TrimSpace(stringValue(item))
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func stringValue(raw any) string {
	if raw == nil {
		return ""
	}
	switch value := raw.(type) {
	case string:
		return value
	default:
		return fmt.Sprint(raw)
	}
}

func normalizePrintableExtension(rawExtension string) string {
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

func normalizeRemoteStartFilename(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	lowered := strings.ToLower(trimmed)
	if strings.HasSuffix(lowered, ".gcode.3mf") {
		return trimmed
	}
	if strings.HasSuffix(lowered, ".3mf") {
		base := strings.TrimSuffix(trimmed, filepath.Ext(trimmed))
		return base + ".gcode.3mf"
	}
	return trimmed + ".gcode.3mf"
}

func defaultProjectFileParam() string {
	return "Metadata/plate_1.gcode"
}

func normalizeFTPSPath(raw string) string {
	trimmed := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if trimmed == "" {
		return ""
	}
	return "/" + strings.TrimPrefix(trimmed, "/")
}

func (a RuntimeAdapter) printStartAuditFields(binding printeradapter.Binding, action printeradapter.RuntimeAction, filename string) map[string]any {
	return map[string]any{
		"printer_id":     binding.PrinterID,
		"job_id":         strings.TrimSpace(action.Target.JobID),
		"plate_id":       action.Target.PlateID,
		"filename":       strings.TrimSpace(filename),
		"adapter_family": "bambu",
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
