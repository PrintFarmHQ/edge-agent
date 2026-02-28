package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBambuCredentialsStorePermissions0600(t *testing.T) {
	baseDir := t.TempDir()
	storePath := filepath.Join(baseDir, "bambu", "credentials.json")

	store, err := NewBambuCredentialsFileStore(storePath)
	if err != nil {
		t.Fatalf("NewBambuCredentialsFileStore failed: %v", err)
	}

	err = store.Save(context.Background(), BambuCredentials{
		Username:     "user@example.com",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
		MaskedEmail:  "j***@example.com",
		MQTTUsername: "3911589060",
	})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("stat credentials file failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("credentials file permissions = %o, want 600", got)
	}

	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.AccessToken != "access-token" {
		t.Fatalf("loaded access token = %q, want access-token", loaded.AccessToken)
	}
	if loaded.Username != "user@example.com" {
		t.Fatalf("loaded username = %q, want user@example.com", loaded.Username)
	}
	if loaded.RefreshToken != "refresh-token" {
		t.Fatalf("loaded refresh token = %q, want refresh-token", loaded.RefreshToken)
	}
	if loaded.ExpiresAt.IsZero() {
		t.Fatalf("loaded expires_at should not be zero")
	}
	if loaded.MQTTUsername != "3911589060" {
		t.Fatalf("loaded mqtt username = %q, want 3911589060", loaded.MQTTUsername)
	}
}

func TestDefaultBambuCredentialsPathUsesPrintfarmhq(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	got, err := DefaultBambuCredentialsPath()
	if err != nil {
		t.Fatalf("DefaultBambuCredentialsPath failed: %v", err)
	}
	want := filepath.Join(homeDir, ".printfarmhq", "bambu", "credentials.json")
	if got != want {
		t.Fatalf("DefaultBambuCredentialsPath = %q, want %q", got, want)
	}
}
