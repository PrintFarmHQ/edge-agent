package cameraruntime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type SupportStatus string

const (
	SupportStatusTestedSupported       SupportStatus = "tested_supported"
	SupportStatusUnsupportedUnverified SupportStatus = "unsupported_or_unverified"
)

type SupportInfo struct {
	Status         SupportStatus
	Family         string
	DisplayModel   string
	DirectlyTested bool
	Reason         string
}

type EnsureRequest struct {
	Serial     string
	Host       string
	AccessCode string
	Model      string
}

type Handle struct {
	Serial            string
	Host              string
	AccessCode        string
	Support           SupportInfo
	PluginDir         string
	PluginLibraryPath string
}

type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

type Runtime interface {
	Ensure(ctx context.Context, req EnsureRequest) (Handle, error)
}

type Manager struct {
	StateDir string
	Runner   Runner
	Client   *http.Client
}

type PluginBundleStatus struct {
	Version               string
	ArchiveURL            string
	CacheDir              string
	ArchivePath           string
	SourceLibraryPath     string
	NetworkingLibraryPath string
	Downloaded            bool
}

const (
	defaultPluginsSubdir = "plugins"
	bambuPluginVersion   = "01.04.00.15"
)

var (
	ErrUnsupportedPlatform = errors.New("bambu plugin bundle unsupported platform")
	ErrCacheUnavailable    = errors.New("bambu plugin bundle cache unavailable")
	ErrDownloadFailed      = errors.New("bambu plugin bundle download failed")
	ErrChecksumMismatch    = errors.New("bambu plugin bundle checksum mismatch")
	ErrIncompleteBundle    = errors.New("bambu plugin bundle incomplete")
)

func NewManager(stateDir string, runner Runner) *Manager {
	return &Manager{
		StateDir: stateDir,
		Runner:   runner,
		Client:   &http.Client{},
	}
}

type pluginArtifact struct {
	Version       string
	URL           string
	ArchiveSHA256 string
	SourceLibrary string
	NetworkingLib string
}

var currentPluginArtifactFn = currentPluginArtifact

func currentPluginArtifact() (pluginArtifact, error) {
	switch runtime.GOOS {
	case "darwin":
		return pluginArtifact{
			Version:       bambuPluginVersion,
			URL:           "https://public-cdn.bambulab.com/upgrade/studio/plugins/01.04.00.15/mac_01.04.00.15.zip",
			ArchiveSHA256: "4a57ac71bc60dfa38ab685523b56e36f284ffe44138fde03e882acb44ddc333a",
			SourceLibrary: "libBambuSource.dylib",
			NetworkingLib: "libbambu_networking.dylib",
		}, nil
	case "linux":
		return pluginArtifact{
			Version:       bambuPluginVersion,
			URL:           "https://public-cdn.bambulab.com/upgrade/studio/plugins/01.04.00.15/linux_01.04.00.15.zip",
			ArchiveSHA256: "379ec431a2bc4ffc5dbba0469725db7f331c840a2be59d0a817a9451abe7e3bc",
			SourceLibrary: "libBambuSource.so",
			NetworkingLib: "libbambu_networking.so",
		}, nil
	case "windows":
		return pluginArtifact{
			Version:       bambuPluginVersion,
			URL:           "https://public-cdn.bambulab.com/upgrade/studio/plugins/01.04.00.15/win_01.04.00.15.zip",
			ArchiveSHA256: "4552e7d7ef84a43c0267649a1784a14960e3212c3a1f1c0906a1e202b8d5fa94",
			SourceLibrary: "BambuSource.dll",
			NetworkingLib: "bambu_networking.dll",
		}, nil
	default:
		return pluginArtifact{}, fmt.Errorf("%w: platform %s is not yet supported for the pinned Bambu native plugin bundle", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

func ClassifySupport(model string) SupportInfo {
	normalized := strings.ToLower(strings.TrimSpace(model))
	display := strings.TrimSpace(model)
	if display == "" {
		display = "unknown"
	}

	switch normalized {
	case "p1s", "bambu lab p1s", "c12":
		return SupportInfo{
			Status:         SupportStatusTestedSupported,
			Family:         "p1s",
			DisplayModel:   display,
			DirectlyTested: true,
		}
	default:
		return SupportInfo{
			Status:         SupportStatusUnsupportedUnverified,
			Family:         "unverified",
			DisplayModel:   display,
			DirectlyTested: false,
			Reason:         "directly tested Bambu camera support currently exists only for P1S",
		}
	}
}

func (m *Manager) Ensure(ctx context.Context, req EnsureRequest) (Handle, error) {
	if m == nil {
		return Handle{}, errors.New("bambu_camera_runtime_unavailable: runtime manager is not configured")
	}
	if strings.TrimSpace(req.Serial) == "" {
		return Handle{}, errors.New("bambu_camera_runtime_unavailable: missing printer serial")
	}
	if strings.TrimSpace(req.Host) == "" {
		return Handle{}, errors.New("bambu_camera_runtime_unavailable: missing printer host")
	}
	if strings.TrimSpace(req.AccessCode) == "" {
		return Handle{}, errors.New("bambu_camera_runtime_unavailable: missing printer access code")
	}

	support := ClassifySupport(req.Model)
	if support.Status != SupportStatusTestedSupported {
		return Handle{}, fmt.Errorf(
			"bambu_camera_family_unverified: %s (model=%s)",
			support.Reason,
			support.DisplayModel,
		)
	}

	status, err := m.preparePluginBundle(ctx)
	if err != nil {
		return Handle{}, fmt.Errorf("bambu_camera_runtime_unavailable: %w", err)
	}

	return Handle{
		Serial:            strings.TrimSpace(req.Serial),
		Host:              strings.TrimSpace(req.Host),
		AccessCode:        strings.TrimSpace(req.AccessCode),
		Support:           support,
		PluginDir:         status.CacheDir,
		PluginLibraryPath: status.SourceLibraryPath,
	}, nil
}

func (m *Manager) EnsurePluginBundle(ctx context.Context) (dir string, sourceLibrary string, err error) {
	if m == nil {
		return "", "", errors.New("bambu_camera_runtime_unavailable: runtime manager is not configured")
	}
	status, err := m.preparePluginBundle(ctx)
	if err != nil {
		return "", "", fmt.Errorf("bambu_camera_runtime_unavailable: %w", err)
	}
	return status.CacheDir, status.SourceLibraryPath, nil
}

func (m *Manager) PreflightPluginBundle(ctx context.Context) (PluginBundleStatus, error) {
	if m == nil {
		return PluginBundleStatus{}, errors.New("runtime manager is not configured")
	}
	return m.preparePluginBundle(ctx)
}

func (m *Manager) preparePluginBundle(ctx context.Context) (PluginBundleStatus, error) {
	artifact, err := currentPluginArtifactFn()
	if err != nil {
		return newPluginBundleStatus(m.StateDir, nil), err
	}
	status := newPluginBundleStatus(m.StateDir, &artifact)
	if err := validatePluginBundle(status, artifact); err == nil {
		return status, nil
	}
	if err := m.repairPluginBundle(ctx, status, artifact); err != nil {
		return status, err
	}
	status.Downloaded = true
	if err := validatePluginBundle(status, artifact); err != nil {
		return status, err
	}
	return status, nil
}

func (m *Manager) repairPluginBundle(ctx context.Context, status PluginBundleStatus, artifact pluginArtifact) error {
	if err := os.RemoveAll(status.CacheDir); err != nil {
		return wrapCacheError("reset pinned plugin cache", err)
	}
	if err := os.MkdirAll(status.CacheDir, 0o755); err != nil {
		return wrapCacheError("create pinned plugin cache directory", err)
	}
	if err := m.downloadPluginArchive(ctx, artifact, status.ArchivePath); err != nil {
		return err
	}
	if err := extractPluginArchive(status.ArchivePath, status.CacheDir, artifact); err != nil {
		return err
	}
	return nil
}

func validatePluginBundle(status PluginBundleStatus, artifact pluginArtifact) error {
	if !fileExists(status.ArchivePath) {
		return fmt.Errorf("%w: pinned archive missing at %s", ErrIncompleteBundle, status.ArchivePath)
	}
	sum, err := checksumFile(status.ArchivePath)
	if err != nil {
		return wrapCacheError("read pinned plugin archive", err)
	}
	if !strings.EqualFold(sum, artifact.ArchiveSHA256) {
		return fmt.Errorf("%w: got %s want %s", ErrChecksumMismatch, sum, artifact.ArchiveSHA256)
	}
	if !fileExists(status.SourceLibraryPath) {
		return fmt.Errorf("%w: missing %s", ErrIncompleteBundle, filepath.Base(status.SourceLibraryPath))
	}
	if !fileExists(status.NetworkingLibraryPath) {
		return fmt.Errorf("%w: missing %s", ErrIncompleteBundle, filepath.Base(status.NetworkingLibraryPath))
	}
	return nil
}

func (m *Manager) downloadPluginArchive(ctx context.Context, artifact pluginArtifact, targetPath string) error {
	if m.Client == nil {
		m.Client = &http.Client{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrDownloadFailed, err)
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDownloadFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%w: status=%d body=%s", ErrDownloadFailed, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var buffer bytes.Buffer
	hasher := sha256.New()
	writer := io.MultiWriter(&buffer, hasher)
	if _, err := io.Copy(writer, resp.Body); err != nil {
		return fmt.Errorf("%w: %v", ErrDownloadFailed, err)
	}
	sum := fmt.Sprintf("%x", hasher.Sum(nil))
	if !strings.EqualFold(sum, artifact.ArchiveSHA256) {
		return fmt.Errorf("%w: got %s want %s", ErrChecksumMismatch, sum, artifact.ArchiveSHA256)
	}
	if err := os.WriteFile(targetPath, buffer.Bytes(), 0o644); err != nil {
		return wrapCacheError("write pinned plugin archive", err)
	}
	return nil
}

func extractPluginArchive(archivePath string, targetDir string, artifact pluginArtifact) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("%w: open archive %s: %v", ErrIncompleteBundle, archivePath, err)
	}
	defer reader.Close()

	want := map[string]struct{}{
		artifact.SourceLibrary: {},
		artifact.NetworkingLib: {},
	}
	for _, file := range reader.File {
		name := filepath.Base(strings.TrimSpace(file.Name))
		if _, ok := want[name]; !ok {
			continue
		}
		stream, err := file.Open()
		if err != nil {
			return fmt.Errorf("%w: open archive entry %s: %v", ErrIncompleteBundle, name, err)
		}
		data, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			return fmt.Errorf("%w: read archive entry %s: %v", ErrIncompleteBundle, name, err)
		}
		targetPath := filepath.Join(targetDir, name)
		mode := os.FileMode(0o644)
		if runtime.GOOS != "windows" {
			mode = 0o755
		}
		if err := os.WriteFile(targetPath, data, mode); err != nil {
			return wrapCacheError("write extracted plugin library", err)
		}
		delete(want, name)
	}
	if len(want) != 0 {
		return fmt.Errorf("%w: plugin archive missing required files: %v", ErrIncompleteBundle, mapsKeys(want))
	}
	return nil
}

func newPluginBundleStatus(stateDir string, artifact *pluginArtifact) PluginBundleStatus {
	version := bambuPluginVersion
	sourceLibrary := ""
	networkingLibrary := ""
	archiveURL := ""
	if artifact != nil {
		version = artifact.Version
		sourceLibrary = artifact.SourceLibrary
		networkingLibrary = artifact.NetworkingLib
		archiveURL = artifact.URL
	}
	cacheDir := filepath.Join(stateDir, defaultPluginsSubdir, runtime.GOOS, version)
	status := PluginBundleStatus{
		Version:     version,
		ArchiveURL:  archiveURL,
		CacheDir:    cacheDir,
		ArchivePath: filepath.Join(cacheDir, "plugin.zip"),
	}
	if sourceLibrary != "" {
		status.SourceLibraryPath = filepath.Join(cacheDir, sourceLibrary)
	}
	if networkingLibrary != "" {
		status.NetworkingLibraryPath = filepath.Join(cacheDir, networkingLibrary)
	}
	return status
}

func checksumFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func wrapCacheError(action string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrCacheUnavailable, action, err)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func mapsKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
