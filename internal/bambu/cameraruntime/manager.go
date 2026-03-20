package cameraruntime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed assets/**
var assetsFS embed.FS

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
	HelperBinaryPath  string
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

const (
	defaultAssetsSubdir  = "assets"
	defaultBinSubdir     = "bin"
	defaultPluginsSubdir = "plugins"
	bambuPluginVersion   = "01.04.00.15"
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
		return pluginArtifact{}, fmt.Errorf("platform %s is not yet supported for pinned Bambu camera plugins", runtime.GOOS)
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
	if m == nil || m.Runner == nil {
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

	if err := m.ensureEmbeddedAssets(); err != nil {
		return Handle{}, fmt.Errorf("bambu_camera_runtime_init_failed: %w", err)
	}
	pluginDir, pluginLib, err := m.ensurePluginBundle(ctx)
	if err != nil {
		return Handle{}, fmt.Errorf("bambu_camera_runtime_unavailable: %w", err)
	}
	helperBinary, err := m.ensureHelperBinary(ctx)
	if err != nil {
		return Handle{}, err
	}

	return Handle{
		Serial:            strings.TrimSpace(req.Serial),
		Host:              strings.TrimSpace(req.Host),
		AccessCode:        strings.TrimSpace(req.AccessCode),
		Support:           support,
		PluginDir:         pluginDir,
		PluginLibraryPath: pluginLib,
		HelperBinaryPath:  helperBinary,
	}, nil
}

func (m *Manager) ensureEmbeddedAssets() error {
	root := filepath.Join(m.StateDir, defaultAssetsSubdir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	return fs.WalkDir(assetsFS, "assets", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path, "assets")
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			return nil
		}
		target := filepath.Join(root, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, readErr := assetsFS.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func (m *Manager) ensureHelperBinary(ctx context.Context) (string, error) {
	compiler, err := findCompiler()
	if err != nil {
		return "", fmt.Errorf("bambu_camera_runtime_unavailable: %w", err)
	}

	binDir := filepath.Join(m.StateDir, defaultBinSubdir)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", fmt.Errorf("bambu_camera_runtime_init_failed: create runtime bin dir: %w", err)
	}
	target := filepath.Join(binDir, helperBinaryName())
	if _, statErr := os.Stat(target); statErr == nil {
		return target, nil
	}

	sourceRoot := filepath.Join(m.StateDir, defaultAssetsSubdir, "src")
	source := filepath.Join(sourceRoot, "BambuP1Streamer.cpp")
	if _, err := m.Runner(ctx, compiler, source, "-o", target); err != nil {
		return "", fmt.Errorf("bambu_camera_runtime_init_failed: compile helper binary with %s: %w", compiler, err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		return "", fmt.Errorf("bambu_camera_runtime_init_failed: chmod helper binary: %w", err)
	}
	return target, nil
}

func helperBinaryName() string {
	if runtime.GOOS == "windows" {
		return "BambuP1Streamer.exe"
	}
	return "BambuP1Streamer"
}

func findCompiler() (string, error) {
	candidates := []string{"c++", "clang++", "g++"}
	pathEnv := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
	for _, candidate := range candidates {
		for _, dir := range pathEnv {
			if dir == "" {
				continue
			}
			target := filepath.Join(dir, candidate)
			if info, err := os.Stat(target); err == nil && !info.IsDir() {
				return target, nil
			}
		}
	}
	return "", errors.New("no supported C++ compiler found in PATH")
}

func (m *Manager) ensurePluginBundle(ctx context.Context) (dir string, sourceLibrary string, err error) {
	artifact, err := currentPluginArtifactFn()
	if err != nil {
		return "", "", err
	}
	root := filepath.Join(m.StateDir, defaultPluginsSubdir, runtime.GOOS, artifact.Version)
	sourcePath := filepath.Join(root, artifact.SourceLibrary)
	networkingPath := filepath.Join(root, artifact.NetworkingLib)
	if fileExists(sourcePath) && fileExists(networkingPath) {
		return root, sourcePath, nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", "", err
	}

	archivePath := filepath.Join(root, "plugin.zip")
	if err := m.downloadPluginArchive(ctx, artifact, archivePath); err != nil {
		return "", "", err
	}
	if err := extractPluginArchive(archivePath, root, artifact); err != nil {
		return "", "", err
	}
	if !fileExists(sourcePath) || !fileExists(networkingPath) {
		return "", "", errors.New("downloaded Bambu camera plugin bundle is incomplete")
	}
	return root, sourcePath, nil
}

func (m *Manager) downloadPluginArchive(ctx context.Context, artifact pluginArtifact, targetPath string) error {
	if m.Client == nil {
		m.Client = &http.Client{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return err
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("download pinned Bambu plugin archive failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var buffer bytes.Buffer
	hasher := sha256.New()
	writer := io.MultiWriter(&buffer, hasher)
	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}
	sum := fmt.Sprintf("%x", hasher.Sum(nil))
	if !strings.EqualFold(sum, artifact.ArchiveSHA256) {
		return fmt.Errorf("Bambu plugin archive checksum mismatch: got %s want %s", sum, artifact.ArchiveSHA256)
	}
	return os.WriteFile(targetPath, buffer.Bytes(), 0o644)
}

func extractPluginArchive(archivePath string, targetDir string, artifact pluginArtifact) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
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
			return err
		}
		data, err := io.ReadAll(stream)
		_ = stream.Close()
		if err != nil {
			return err
		}
		targetPath := filepath.Join(targetDir, name)
		mode := os.FileMode(0o644)
		if runtime.GOOS != "windows" {
			mode = 0o755
		}
		if err := os.WriteFile(targetPath, data, mode); err != nil {
			return err
		}
		delete(want, name)
	}
	if len(want) != 0 {
		return fmt.Errorf("plugin archive missing required files: %v", mapsKeys(want))
	}
	return nil
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
	return out
}
