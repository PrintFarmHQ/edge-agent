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

type BambuCredentials struct {
	Username           string    `json:"username,omitempty"`
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token,omitempty"`
	ExpiresAt          time.Time `json:"expires_at"`
	MaskedEmail        string    `json:"masked_email,omitempty"`
	MaskedPhone        string    `json:"masked_phone,omitempty"`
	AccountDisplayName string    `json:"account_display_name,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type BambuCredentialsStore interface {
	Save(ctx context.Context, credentials BambuCredentials) error
	Load(ctx context.Context) (BambuCredentials, error)
	Path() string
}

type BambuCredentialsFileStore struct {
	path string
}

func NewBambuCredentialsFileStore(path string) (*BambuCredentialsFileStore, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("bambu credentials store path is required")
	}
	return &BambuCredentialsFileStore{path: trimmed}, nil
}

func NewDefaultBambuCredentialsFileStore() (*BambuCredentialsFileStore, error) {
	path, err := DefaultBambuCredentialsPath()
	if err != nil {
		return nil, err
	}
	return NewBambuCredentialsFileStore(path)
}

func DefaultBambuCredentialsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return "", errors.New("resolve user home directory: empty home path")
	}
	return filepath.Join(home, ".printfarmhq", "bambu", "credentials.json"), nil
}

func (s *BambuCredentialsFileStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

func (s *BambuCredentialsFileStore) Save(_ context.Context, credentials BambuCredentials) error {
	if s == nil {
		return errors.New("bambu credentials store is nil")
	}
	if strings.TrimSpace(credentials.AccessToken) == "" {
		return errors.New("access_token is required")
	}
	if credentials.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
	}
	credentials.UpdatedAt = time.Now().UTC()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create bambu credentials directory: %w", err)
	}

	payload, err := json.MarshalIndent(credentials, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bambu credentials: %w", err)
	}

	tmpPath := filepath.Join(dir, ".credentials.json.tmp")
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return fmt.Errorf("write bambu credentials temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename bambu credentials file: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("chmod bambu credentials file: %w", err)
	}
	return nil
}

func (s *BambuCredentialsFileStore) Load(_ context.Context) (BambuCredentials, error) {
	if s == nil {
		return BambuCredentials{}, errors.New("bambu credentials store is nil")
	}
	payload, err := os.ReadFile(s.path)
	if err != nil {
		return BambuCredentials{}, err
	}
	var out BambuCredentials
	if err := json.Unmarshal(payload, &out); err != nil {
		return BambuCredentials{}, fmt.Errorf("decode bambu credentials: %w", err)
	}
	return out, nil
}
