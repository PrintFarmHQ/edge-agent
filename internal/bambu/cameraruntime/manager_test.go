package cameraruntime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestClassifySupportP1SIsDirectlyTested(t *testing.T) {
	info := ClassifySupport("C12")
	if info.Status != SupportStatusTestedSupported {
		t.Fatalf("status = %q, want %q", info.Status, SupportStatusTestedSupported)
	}
	if !info.DirectlyTested {
		t.Fatalf("expected directly tested support")
	}
}

func TestClassifySupportX1CIsUnverified(t *testing.T) {
	info := ClassifySupport("X1C")
	if info.Status != SupportStatusUnsupportedUnverified {
		t.Fatalf("status = %q, want %q", info.Status, SupportStatusUnsupportedUnverified)
	}
	if info.DirectlyTested {
		t.Fatalf("did not expect directly tested support")
	}
}

func TestManagerEnsureDownloadsPinnedPluginAndCompilesHelper(t *testing.T) {
	artifact := testPluginArtifactForRuntime()
	archiveBytes := buildTestPluginArchive(t, artifact.SourceLibrary, artifact.NetworkingLib)
	checksum := fmt.Sprintf("%x", sha256.Sum256(archiveBytes))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archiveBytes)
	}))
	defer server.Close()

	originalArtifactFn := currentPluginArtifactFn
	t.Cleanup(func() {
		currentPluginArtifactFn = originalArtifactFn
	})
	currentPluginArtifactFn = func() (pluginArtifact, error) {
		artifact.URL = server.URL + "/plugin.zip"
		artifact.ArchiveSHA256 = checksum
		return artifact, nil
	}

	var compileCall string
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		compileCall = name + " " + strings.Join(args, " ")
		target := args[len(args)-1]
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir target dir failed: %v", err)
		}
		if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
			t.Fatalf("write target failed: %v", err)
		}
		return nil, nil
	}

	manager := NewManager(filepath.Join(t.TempDir(), "runtime"), runner)
	manager.Client = server.Client()
	handle, err := manager.Ensure(context.Background(), EnsureRequest{
		Serial:     "01P00C511601082",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
		Model:      "C12",
	})
	if err != nil {
		t.Fatalf("Ensure failed: %v", err)
	}
	if !strings.Contains(compileCall, "BambuP1Streamer.cpp") {
		t.Fatalf("compile call = %q, want helper compile", compileCall)
	}
	if !strings.HasSuffix(handle.PluginLibraryPath, artifact.SourceLibrary) {
		t.Fatalf("plugin library = %q, want %q", handle.PluginLibraryPath, artifact.SourceLibrary)
	}
	if !fileExists(filepath.Join(handle.PluginDir, artifact.NetworkingLib)) {
		t.Fatalf("expected networking library in plugin dir")
	}
}

func TestManagerEnsureRejectsChecksumMismatch(t *testing.T) {
	artifact := testPluginArtifactForRuntime()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-a-zip"))
	}))
	defer server.Close()

	originalArtifactFn := currentPluginArtifactFn
	t.Cleanup(func() {
		currentPluginArtifactFn = originalArtifactFn
	})
	currentPluginArtifactFn = func() (pluginArtifact, error) {
		artifact.URL = server.URL + "/plugin.zip"
		artifact.ArchiveSHA256 = strings.Repeat("0", 64)
		return artifact, nil
	}

	manager := NewManager(filepath.Join(t.TempDir(), "runtime"), func(context.Context, string, ...string) ([]byte, error) {
		t.Fatalf("helper compile should not run when checksum fails")
		return nil, nil
	})
	manager.Client = server.Client()
	_, err := manager.Ensure(context.Background(), EnsureRequest{
		Serial:     "01P00C511601082",
		Host:       "192.168.100.172",
		AccessCode: "12345678",
		Model:      "C12",
	})
	if err == nil {
		t.Fatalf("expected checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %q, want checksum mismatch", err)
	}
}

func TestManagerEnsureRejectsUnverifiedFamilies(t *testing.T) {
	manager := NewManager(filepath.Join(t.TempDir(), "runtime"), func(context.Context, string, ...string) ([]byte, error) {
		t.Fatalf("runner should not be called for unsupported family")
		return nil, nil
	})

	_, err := manager.Ensure(context.Background(), EnsureRequest{
		Serial:     "x1c-serial",
		Host:       "192.168.100.200",
		AccessCode: "12345678",
		Model:      "X1C",
	})
	if err == nil {
		t.Fatalf("expected unverified family error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_family_unverified") {
		t.Fatalf("error = %q, want family-unverified", err)
	}
}

func buildTestPluginArchive(t *testing.T, sourceLibrary string, networkingLib string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, name := range []string{sourceLibrary, networkingLib} {
		writer, err := archive.Create(name)
		if err != nil {
			t.Fatalf("create zip entry failed: %v", err)
		}
		if _, err := writer.Write([]byte("binary-" + name)); err != nil {
			t.Fatalf("write zip entry failed: %v", err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatalf("close zip failed: %v", err)
	}
	return buffer.Bytes()
}

func testPluginArtifactForRuntime() pluginArtifact {
	switch runtime.GOOS {
	case "darwin":
		return pluginArtifact{
			Version:       bambuPluginVersion,
			SourceLibrary: "libBambuSource.dylib",
			NetworkingLib: "libbambu_networking.dylib",
		}
	case "linux":
		return pluginArtifact{
			Version:       bambuPluginVersion,
			SourceLibrary: "libBambuSource.so",
			NetworkingLib: "libbambu_networking.so",
		}
	default:
		return pluginArtifact{
			Version:       bambuPluginVersion,
			SourceLibrary: "BambuSource.dll",
			NetworkingLib: "bambu_networking.dll",
		}
	}
}
