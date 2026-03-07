package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrBambuLANCredentialsNotFound = errors.New("bambu lan credentials not found")

type BambuLANCredentials struct {
	Serial     string    `json:"serial"`
	Host       string    `json:"host"`
	AccessCode string    `json:"access_code"`
	Name       string    `json:"name,omitempty"`
	Model      string    `json:"model,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
}

type BambuLANCredentialsStore interface {
	Upsert(ctx context.Context, credentials BambuLANCredentials) error
	Get(ctx context.Context, serial string) (BambuLANCredentials, error)
	Path() string
}

type bambuLANCredentialsFilePayload struct {
	Printers map[string]BambuLANCredentials `json:"printers"`
}

type BambuLANCredentialsFileStore struct {
	path string
}

func NewBambuLANCredentialsFileStore(path string) (*BambuLANCredentialsFileStore, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("bambu lan credentials store path is required")
	}
	return &BambuLANCredentialsFileStore{path: trimmed}, nil
}

func NewDefaultBambuLANCredentialsFileStore() (*BambuLANCredentialsFileStore, error) {
	path, err := DefaultBambuLANCredentialsPath()
	if err != nil {
		return nil, err
	}
	return NewBambuLANCredentialsFileStore(path)
}

func DefaultBambuLANCredentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return "", errors.New("resolve user home directory: empty home path")
	}
	return filepath.Join(home, ".printfarmhq", "bambu", "lan_credentials.json"), nil
}

func (s *BambuLANCredentialsFileStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *BambuLANCredentialsFileStore) Upsert(_ context.Context, credentials BambuLANCredentials) error {
	if s == nil {
		return errors.New("bambu lan credentials store is nil")
	}

	serial := strings.TrimSpace(credentials.Serial)
	if serial == "" {
		return errors.New("serial is required")
	}
	host := strings.TrimSpace(credentials.Host)
	if host == "" {
		return errors.New("host is required")
	}
	accessCode := strings.TrimSpace(credentials.AccessCode)
	if accessCode == "" {
		return errors.New("access_code is required")
	}

	payload, err := s.loadPayload()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if payload.Printers == nil {
		payload.Printers = make(map[string]BambuLANCredentials)
	}

	existing := payload.Printers[serial]
	existing.Serial = serial
	existing.Host = host
	existing.AccessCode = accessCode
	existing.Name = strings.TrimSpace(credentials.Name)
	existing.Model = strings.TrimSpace(credentials.Model)
	existing.UpdatedAt = time.Now().UTC()
	if !credentials.LastSeenAt.IsZero() {
		existing.LastSeenAt = credentials.LastSeenAt.UTC()
	}
	payload.Printers[serial] = existing

	return s.savePayload(payload)
}

func (s *BambuLANCredentialsFileStore) Get(_ context.Context, serial string) (BambuLANCredentials, error) {
	if s == nil {
		return BambuLANCredentials{}, errors.New("bambu lan credentials store is nil")
	}
	payload, err := s.loadPayload()
	if err != nil {
		return BambuLANCredentials{}, err
	}
	normalizedSerial := strings.TrimSpace(serial)
	record, ok := payload.Printers[normalizedSerial]
	if !ok {
		return BambuLANCredentials{}, fmt.Errorf("%w: %s", ErrBambuLANCredentialsNotFound, normalizedSerial)
	}
	return record, nil
}

func (s *BambuLANCredentialsFileStore) loadPayload() (bambuLANCredentialsFilePayload, error) {
	payloadBytes, err := os.ReadFile(s.path)
	if err != nil {
		return bambuLANCredentialsFilePayload{}, err
	}
	var payload bambuLANCredentialsFilePayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return bambuLANCredentialsFilePayload{}, fmt.Errorf("decode bambu lan credentials: %w", err)
	}
	if payload.Printers == nil {
		payload.Printers = make(map[string]BambuLANCredentials)
	}
	return payload, nil
}

func (s *BambuLANCredentialsFileStore) savePayload(payload bambuLANCredentialsFilePayload) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create bambu lan credentials directory: %w", err)
	}

	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bambu lan credentials: %w", err)
	}

	tmpPath := filepath.Join(dir, ".lan_credentials.json.tmp")
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("write bambu lan credentials temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename bambu lan credentials file: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("chmod bambu lan credentials file: %w", err)
	}
	return nil
}
