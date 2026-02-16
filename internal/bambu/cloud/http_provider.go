package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	bambuauth "printfarmhq/edge-agent/internal/bambu/auth"
)

const defaultLoginPath = "/v1/user-service/user/login"
const defaultRefreshPath = "/v1/user-service/user/refreshtoken"

type HTTPProviderConfig struct {
	AuthBaseURL string
	Client      *http.Client
	LoginPath   string
	RefreshPath string
}

type HTTPProvider struct {
	authBaseURL string
	client      *http.Client
	loginPath   string
	refreshPath string
}

func NewHTTPProvider(cfg HTTPProviderConfig) *HTTPProvider {
	loginPath := strings.TrimSpace(cfg.LoginPath)
	if loginPath == "" {
		loginPath = defaultLoginPath
	}
	refreshPath := strings.TrimSpace(cfg.RefreshPath)
	if refreshPath == "" {
		refreshPath = defaultRefreshPath
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &HTTPProvider{
		authBaseURL: strings.TrimSpace(cfg.AuthBaseURL),
		client:      client,
		loginPath:   loginPath,
		refreshPath: refreshPath,
	}
}

func (p *HTTPProvider) Login(ctx context.Context, req bambuauth.LoginRequest) (bambuauth.Session, error) {
	baseURL := strings.TrimSpace(p.authBaseURL)
	if baseURL == "" {
		return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: "bambu auth endpoint is not configured"}
	}

	body := map[string]string{
		"account":  strings.TrimSpace(req.Username),
		"apiError": "",
	}
	if strings.TrimSpace(req.MFACode) != "" {
		body["code"] = strings.TrimSpace(req.MFACode)
	} else {
		body["password"] = req.Password
	}

	data, err := json.Marshal(body)
	if err != nil {
		return bambuauth.Session{}, fmt.Errorf("marshal bambu auth login request: %w", err)
	}

	endpoint := strings.TrimSuffix(baseURL, "/") + p.loginPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return bambuauth.Session{}, fmt.Errorf("build bambu auth login request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu auth request failed: %v", err)}
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(payload))
		lowerMessage := strings.ToLower(message)
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			if strings.Contains(lowerMessage, "mfa") || strings.Contains(lowerMessage, "otp") {
				return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrMFARequired, Message: "bambu cloud requires MFA"}
			}
			return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "bambu cloud rejected credentials"}
		case resp.StatusCode >= 500:
			return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu auth temporary failure (%d)", resp.StatusCode)}
		default:
			return bambuauth.Session{}, fmt.Errorf("bambu auth login returned %d from %s: %s", resp.StatusCode, endpoint, message)
		}
	}

	parsed, err := parseSessionPayload(payload)
	if err != nil {
		return bambuauth.Session{}, err
	}
	return parsed, nil
}

func (p *HTTPProvider) Refresh(ctx context.Context, req bambuauth.RefreshRequest) (bambuauth.Session, error) {
	baseURL := strings.TrimSpace(p.authBaseURL)
	if baseURL == "" {
		return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: "bambu auth endpoint is not configured"}
	}
	refreshToken := strings.TrimSpace(req.RefreshToken)
	if refreshToken == "" {
		return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "missing refresh token"}
	}

	body := map[string]string{"refreshToken": refreshToken}
	data, err := json.Marshal(body)
	if err != nil {
		return bambuauth.Session{}, fmt.Errorf("marshal bambu auth refresh request: %w", err)
	}

	endpoint := strings.TrimSuffix(baseURL, "/") + p.refreshPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return bambuauth.Session{}, fmt.Errorf("build bambu auth refresh request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu refresh request failed: %v", err)}
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(payload))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "bambu refresh rejected"}
		}
		if resp.StatusCode >= 500 {
			return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu refresh temporary failure (%d)", resp.StatusCode)}
		}
		return bambuauth.Session{}, fmt.Errorf("bambu auth refresh returned %d from %s: %s", resp.StatusCode, endpoint, message)
	}

	parsed, err := parseSessionPayload(payload)
	if err != nil {
		return bambuauth.Session{}, err
	}
	return parsed, nil
}

func parseSessionPayload(payload []byte) (bambuauth.Session, error) {
	type accountPayload struct {
		EmailMasked string `json:"email_masked"`
		PhoneMasked string `json:"phone_masked"`
		DisplayName string `json:"display_name"`
	}
	type tokenPayload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		ExpiresAt    string `json:"expires_at"`
	}
	type responsePayload struct {
		AccessToken   string         `json:"accessToken"`
		AccessTokenV1 string         `json:"access_token"`
		RefreshToken  string         `json:"refreshToken"`
		RefreshTokenV string         `json:"refresh_token"`
		ExpiresIn     int64          `json:"expiresIn"`
		ExpiresInV1   int64          `json:"expires_in"`
		ExpiresAt     string         `json:"expiresAt"`
		ExpiresAtV1   string         `json:"expires_at"`
		LoginType     string         `json:"loginType"`
		LoginTypeV1   string         `json:"login_type"`
		Token         tokenPayload   `json:"token"`
		Account       accountPayload `json:"account"`
	}

	var resp responsePayload
	if err := json.Unmarshal(payload, &resp); err != nil {
		return bambuauth.Session{}, fmt.Errorf("decode bambu auth response: %w", err)
	}

	accessToken := strings.TrimSpace(resp.AccessToken)
	if accessToken == "" {
		accessToken = strings.TrimSpace(resp.AccessTokenV1)
	}
	if accessToken == "" {
		accessToken = strings.TrimSpace(resp.Token.AccessToken)
	}
	refreshToken := strings.TrimSpace(resp.RefreshToken)
	if refreshToken == "" {
		refreshToken = strings.TrimSpace(resp.RefreshTokenV)
	}
	if refreshToken == "" {
		refreshToken = strings.TrimSpace(resp.Token.RefreshToken)
	}

	expiresAt := time.Time{}
	rawExpiresAt := strings.TrimSpace(resp.ExpiresAt)
	if rawExpiresAt == "" {
		rawExpiresAt = strings.TrimSpace(resp.ExpiresAtV1)
	}
	if rawExpiresAt == "" {
		rawExpiresAt = strings.TrimSpace(resp.Token.ExpiresAt)
	}
	if rawExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, rawExpiresAt)
		if err != nil {
			return bambuauth.Session{}, fmt.Errorf("invalid bambu auth expires_at: %w", err)
		}
		expiresAt = parsed.UTC()
	} else {
		expiresIn := resp.ExpiresIn
		if expiresIn <= 0 {
			expiresIn = resp.ExpiresInV1
		}
		if expiresIn <= 0 {
			expiresIn = resp.Token.ExpiresIn
		}
		if expiresIn > 0 {
			expiresAt = time.Now().UTC().Add(time.Duration(expiresIn) * time.Second)
		}
	}

	loginType := strings.ToLower(strings.TrimSpace(resp.LoginType))
	if loginType == "" {
		loginType = strings.ToLower(strings.TrimSpace(resp.LoginTypeV1))
	}
	if accessToken == "" && (loginType == "verifycode" || loginType == "verify_code" || strings.Contains(loginType, "verify")) {
		return bambuauth.Session{}, &bambuauth.Error{Kind: bambuauth.ErrMFARequired, Message: "bambu cloud requires verification code"}
	}

	if accessToken == "" {
		return bambuauth.Session{}, errors.New("bambu auth response missing access token")
	}
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(1 * time.Hour)
	}

	return bambuauth.Session{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		ExpiresAt:          expiresAt,
		MaskedEmail:        strings.TrimSpace(resp.Account.EmailMasked),
		MaskedPhone:        strings.TrimSpace(resp.Account.PhoneMasked),
		AccountDisplayName: strings.TrimSpace(resp.Account.DisplayName),
	}, nil
}
