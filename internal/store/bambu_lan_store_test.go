package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBambuLANCredentialsStorePermissionsAndUpsert(t *testing.T) {
	baseDir := t.TempDir()
	storePath := filepath.Join(baseDir, "bambu", "lan_credentials.json")

	store, err := NewBambuLANCredentialsFileStore(storePath)
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}

	if err := store.Upsert(context.Background(), BambuLANCredentials{
		Serial:     "01P00C511601082",
		Host:       "192.168.100.175",
		AccessCode: "12345678",
		Name:       "Forge#2",
		Model:      "C12",
	}); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("stat credentials file failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("credentials file permissions = %o, want 600", got)
	}

	record, err := store.Get(context.Background(), "01P00C511601082")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if record.Host != "192.168.100.175" {
		t.Fatalf("record host = %q, want 192.168.100.175", record.Host)
	}
	if record.AccessCode != "12345678" {
		t.Fatalf("record access code = %q, want 12345678", record.AccessCode)
	}
	if record.Name != "Forge#2" {
		t.Fatalf("record name = %q, want Forge#2", record.Name)
	}
	if record.Model != "C12" {
		t.Fatalf("record model = %q, want C12", record.Model)
	}

	if err := store.Upsert(context.Background(), BambuLANCredentials{
		Serial:     "01P00C511601082",
		Host:       "192.168.100.176",
		AccessCode: "87654321",
		Name:       "Forge#2",
		Model:      "C12",
	}); err != nil {
		t.Fatalf("second Upsert failed: %v", err)
	}

	updated, err := store.Get(context.Background(), "01P00C511601082")
	if err != nil {
		t.Fatalf("Get after update failed: %v", err)
	}
	if updated.Host != "192.168.100.176" {
		t.Fatalf("updated host = %q, want 192.168.100.176", updated.Host)
	}
	if updated.AccessCode != "87654321" {
		t.Fatalf("updated access code = %q, want 87654321", updated.AccessCode)
	}
}

func TestBambuLANCredentialsStoreMissingSerial(t *testing.T) {
	baseDir := t.TempDir()
	storePath := filepath.Join(baseDir, "bambu", "lan_credentials.json")

	store, err := NewBambuLANCredentialsFileStore(storePath)
	if err != nil {
		t.Fatalf("NewBambuLANCredentialsFileStore failed: %v", err)
	}
	if err := store.Upsert(context.Background(), BambuLANCredentials{
		Serial:     "serial-1",
		Host:       "192.168.1.50",
		AccessCode: "12345678",
	}); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	_, err = store.Get(context.Background(), "missing-serial")
	if !errors.Is(err, ErrBambuLANCredentialsNotFound) {
		t.Fatalf("Get missing serial error = %v, want ErrBambuLANCredentialsNotFound", err)
	}
}

func TestDefaultBambuLANCredentialsPathUsesPrintfarmhq(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	got, err := DefaultBambuLANCredentialsPath()
	if err != nil {
		t.Fatalf("DefaultBambuLANCredentialsPath failed: %v", err)
	}
	want := filepath.Join(homeDir, ".printfarmhq", "bambu", "lan_credentials.json")
	if got != want {
		t.Fatalf("DefaultBambuLANCredentialsPath = %q, want %q", got, want)
	}
}
