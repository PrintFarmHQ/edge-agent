package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	bambuauth "printfarmhq/edge-agent/internal/bambu/auth"
)

const defaultLoginPath = "/v1/user-service/user/login"
const defaultRefreshPath = "/v1/user-service/user/refreshtoken"
const defaultUserBindPath = "/v1/iot-service/api/user/bind"
const defaultUploadPath = "/v1/iot-service/api/user/upload"
const defaultPrintPath = "/v1/iot-service/api/user/print"

var ErrPrintStartUnsupported = errors.New("bambu print start endpoint unsupported")

type HTTPProviderConfig struct {
	AuthBaseURL  string
	Client       *http.Client
	LoginPath    string
	RefreshPath  string
	UserBindPath string
	UploadPath   string
	PrintPath    string
}

type HTTPProvider struct {
	authBaseURL  string
	client       *http.Client
	loginPath    string
	refreshPath  string
	userBindPath string
	uploadPath   string
	printPath    string
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
	userBindPath := strings.TrimSpace(cfg.UserBindPath)
	if userBindPath == "" {
		userBindPath = defaultUserBindPath
	}
	uploadPath := strings.TrimSpace(cfg.UploadPath)
	if uploadPath == "" {
		uploadPath = defaultUploadPath
	}
	printPath := strings.TrimSpace(cfg.PrintPath)
	if printPath == "" {
		printPath = defaultPrintPath
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &HTTPProvider{
		authBaseURL:  strings.TrimSpace(cfg.AuthBaseURL),
		client:       client,
		loginPath:    loginPath,
		refreshPath:  refreshPath,
		userBindPath: userBindPath,
		uploadPath:   uploadPath,
		printPath:    printPath,
	}
}

type CloudDevice struct {
	DeviceID    string
	Name        string
	Model       string
	PrintStatus string
	Online      bool
	AccessCode  string
}

type CloudUploadURLs struct {
	UploadFileURL string
	UploadSizeURL string
	FileURL       string
	FileName      string
	FileID        string
}

type CloudPrintStartRequest struct {
	DeviceID string
	FileName string
	FileURL  string
	FileID   string
}

type cloudDevicePayload struct {
	DevID          string `json:"dev_id"`
	DeviceID       string `json:"device_id"`
	Name           string `json:"name"`
	DeviceName     string `json:"device_name"`
	DevModelName   string `json:"dev_model_name"`
	DevProductName string `json:"dev_product_name"`
	Model          string `json:"model"`
	PrintStatus    string `json:"print_status"`
	Status         string `json:"status"`
	Online         *bool  `json:"online"`
	DevAccessCode  string `json:"dev_access_code"`
	AccessCode     string `json:"access_code"`
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

func (p *HTTPProvider) ListBoundDevices(ctx context.Context, accessToken string) ([]CloudDevice, error) {
	baseURL := strings.TrimSpace(p.authBaseURL)
	if baseURL == "" {
		return nil, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: "bambu auth endpoint is not configured"}
	}
	token := strings.TrimSpace(accessToken)
	if token == "" {
		return nil, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "missing access token"}
	}

	endpoint := strings.TrimSuffix(baseURL, "/") + p.userBindPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build bambu device list request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu device list request failed: %v", err)}
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(payload))
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return nil, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "bambu device list rejected access token"}
		case resp.StatusCode >= 500:
			return nil, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu device list temporary failure (%d)", resp.StatusCode)}
		default:
			return nil, fmt.Errorf("bambu device list returned %d from %s: %s", resp.StatusCode, endpoint, message)
		}
	}

	devices, err := parseBoundDevicesPayload(payload)
	if err != nil {
		return nil, err
	}
	return devices, nil
}

func (p *HTTPProvider) GetUploadURLs(ctx context.Context, accessToken, filename string, sizeBytes int64) (CloudUploadURLs, error) {
	baseURL := strings.TrimSpace(p.authBaseURL)
	if baseURL == "" {
		return CloudUploadURLs{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: "bambu auth endpoint is not configured"}
	}
	token := strings.TrimSpace(accessToken)
	if token == "" {
		return CloudUploadURLs{}, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "missing access token"}
	}
	trimmedFileName := strings.TrimSpace(filename)
	if trimmedFileName == "" {
		return CloudUploadURLs{}, errors.New("validation_error: missing bambu upload filename")
	}
	if sizeBytes < 0 {
		return CloudUploadURLs{}, errors.New("validation_error: invalid bambu upload size")
	}

	endpoint, err := url.Parse(strings.TrimSuffix(baseURL, "/") + p.uploadPath)
	if err != nil {
		return CloudUploadURLs{}, fmt.Errorf("build bambu upload endpoint: %w", err)
	}
	query := endpoint.Query()
	query.Set("filename", trimmedFileName)
	query.Set("size", strconv.FormatInt(sizeBytes, 10))
	endpoint.RawQuery = query.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return CloudUploadURLs{}, fmt.Errorf("build bambu upload request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return CloudUploadURLs{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu upload request failed: %v", err)}
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(payload))
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return CloudUploadURLs{}, &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "bambu upload request rejected access token"}
		case resp.StatusCode >= 500:
			return CloudUploadURLs{}, &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu upload temporary failure (%d)", resp.StatusCode)}
		default:
			return CloudUploadURLs{}, fmt.Errorf("bambu upload request returned %d from %s: %s", resp.StatusCode, endpoint.String(), message)
		}
	}

	uploadURLs, err := parseUploadURLsPayload(payload)
	if err != nil {
		return CloudUploadURLs{}, err
	}
	if strings.TrimSpace(uploadURLs.UploadFileURL) == "" {
		return CloudUploadURLs{}, errors.New("bambu upload response missing filename upload url")
	}
	if strings.TrimSpace(uploadURLs.FileName) == "" {
		uploadURLs.FileName = trimmedFileName
	}
	if strings.TrimSpace(uploadURLs.FileURL) == "" {
		return CloudUploadURLs{}, errors.New("validation_error: bambu upload response missing file_url")
	}
	return uploadURLs, nil
}

func (p *HTTPProvider) UploadToSignedURLs(ctx context.Context, uploadURLs CloudUploadURLs, fileBytes []byte) error {
	uploadFileURL := strings.TrimSpace(uploadURLs.UploadFileURL)
	if uploadFileURL == "" {
		return errors.New("validation_error: missing bambu filename upload url")
	}

	err := p.uploadSignedPayload(ctx, uploadFileURL, fileBytes, "application/octet-stream")
	if err != nil {
		// Some signed URLs are issued without a content-type constraint.
		// Retry once without Content-Type when the provider reports signature mismatch.
		if !isSignatureMismatchError(err) {
			return err
		}
		err = p.uploadSignedPayload(ctx, uploadFileURL, fileBytes, "")
		if err != nil {
			return err
		}
	}

	uploadSizeURL := strings.TrimSpace(uploadURLs.UploadSizeURL)
	if uploadSizeURL == "" {
		return nil
	}
	sizePayload := []byte(strconv.Itoa(len(fileBytes)))
	if err := p.uploadSignedPayload(ctx, uploadSizeURL, sizePayload, ""); err != nil {
		return err
	}
	return nil
}

func (p *HTTPProvider) uploadSignedPayload(ctx context.Context, endpoint string, payload []byte, contentType string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build bambu signed upload request: %w", err)
	}
	if strings.TrimSpace(contentType) != "" {
		req.Header.Set("Content-Type", strings.TrimSpace(contentType))
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("bambu file upload request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("bambu file upload failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	return nil
}

func isSignatureMismatchError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(msg, "signaturedoesnotmatch") || strings.Contains(msg, "signature does not match")
}

func (p *HTTPProvider) StartPrintJob(ctx context.Context, accessToken string, req CloudPrintStartRequest) error {
	baseURL := strings.TrimSpace(p.authBaseURL)
	if baseURL == "" {
		return &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: "bambu auth endpoint is not configured"}
	}
	token := strings.TrimSpace(accessToken)
	if token == "" {
		return &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "missing access token"}
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return errors.New("validation_error: missing bambu device id")
	}
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		return errors.New("validation_error: missing bambu file name")
	}
	fileURL := strings.TrimSpace(req.FileURL)
	if fileURL == "" {
		return errors.New("validation_error: missing bambu file url")
	}
	fileID := strings.TrimSpace(req.FileID)

	payload := map[string]any{
		"device_id": deviceID,
		"dev_id":    deviceID,
		"file_name": fileName,
		"file_url":  fileURL,
	}
	if fileID != "" {
		payload["file_id"] = fileID
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal bambu print start payload: %w", err)
	}

	printPath := strings.TrimSpace(p.printPath)
	if printPath == "" {
		printPath = defaultPrintPath
	}
	candidates := []struct {
		Method string
		Path   string
	}{
		{Method: http.MethodPost, Path: printPath},
		{Method: http.MethodPut, Path: printPath},
		{Method: http.MethodPost, Path: strings.TrimSuffix(printPath, "/") + "/start"},
		{Method: http.MethodPut, Path: strings.TrimSuffix(printPath, "/") + "/start"},
	}

	var lastErr error
	attemptErrors := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		endpoint := strings.TrimSuffix(baseURL, "/") + candidate.Path
		err = p.doPrintStartRequest(ctx, candidate.Method, endpoint, token, data)
		if err == nil {
			return nil
		}
		lastErr = err
		if errors.Is(err, bambuauth.ErrInvalidCredentials) || errors.Is(err, bambuauth.ErrTemporary) {
			return err
		}
		attemptErrors = append(attemptErrors, err.Error())
		lowerErr := strings.ToLower(err.Error())
		// Continue only when endpoint/method shape appears unsupported.
		if strings.Contains(lowerErr, "status=404") || strings.Contains(lowerErr, "status=405") {
			continue
		}
		return err
	}
	if lastErr != nil {
		return fmt.Errorf("%w: bambu print start failed after trying all fallback endpoints: %s", ErrPrintStartUnsupported, strings.Join(attemptErrors, " || "))
	}
	return ErrPrintStartUnsupported
}

func (p *HTTPProvider) doPrintStartRequest(ctx context.Context, method, endpoint, accessToken string, payload []byte) error {
	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build bambu print start request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu print start request failed: %v", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	message := strings.TrimSpace(string(responseBody))
	allowHeader := strings.TrimSpace(resp.Header.Get("Allow"))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return &bambuauth.Error{Kind: bambuauth.ErrInvalidCredentials, Message: "bambu print start rejected access token"}
	case resp.StatusCode >= 500:
		return &bambuauth.Error{Kind: bambuauth.ErrTemporary, Message: fmt.Sprintf("bambu print start temporary failure (%d)", resp.StatusCode)}
	default:
		if allowHeader != "" {
			return fmt.Errorf("bambu print start %s %s failed: status=%d allow=%s body=%s", method, endpoint, resp.StatusCode, allowHeader, message)
		}
		return fmt.Errorf("bambu print start %s %s failed: status=%d body=%s", method, endpoint, resp.StatusCode, message)
	}
}

func parseSessionPayload(payload []byte) (bambuauth.Session, error) {
	type accountPayload struct {
		EmailMasked string `json:"email_masked"`
		PhoneMasked string `json:"phone_masked"`
		DisplayName string `json:"display_name"`
		UserID      string `json:"user_id"`
		UserIDV1    string `json:"userId"`
		UID         string `json:"uid"`
		AccountID   string `json:"account_id"`
		AccountIDV1 string `json:"accountId"`
	}
	type tokenPayload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		ExpiresAt    string `json:"expires_at"`
		UserID       string `json:"user_id"`
		UserIDV1     string `json:"userId"`
		UID          string `json:"uid"`
		Sub          string `json:"sub"`
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
		UserID        string         `json:"user_id"`
		UserIDV1      string         `json:"userId"`
		UID           string         `json:"uid"`
		AccountID     string         `json:"account_id"`
		AccountIDV1   string         `json:"accountId"`
		Sub           string         `json:"sub"`
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
	mqttUsername := firstNonEmptyString(
		resp.UserID,
		resp.UserIDV1,
		resp.UID,
		resp.AccountID,
		resp.AccountIDV1,
		resp.Sub,
		resp.Account.UserID,
		resp.Account.UserIDV1,
		resp.Account.UID,
		resp.Account.AccountID,
		resp.Account.AccountIDV1,
		resp.Token.UserID,
		resp.Token.UserIDV1,
		resp.Token.UID,
		resp.Token.Sub,
	)
	if strings.TrimSpace(mqttUsername) == "" {
		var document any
		if err := json.Unmarshal(payload, &document); err == nil {
			mqttUsername = firstValue(document, "user_id", "userId", "uid", "account_id", "accountId", "sub")
		}
	}

	return bambuauth.Session{
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		ExpiresAt:          expiresAt,
		MaskedEmail:        strings.TrimSpace(resp.Account.EmailMasked),
		MaskedPhone:        strings.TrimSpace(resp.Account.PhoneMasked),
		AccountDisplayName: strings.TrimSpace(resp.Account.DisplayName),
		MQTTUsername:       strings.TrimSpace(mqttUsername),
	}, nil
}

func parseBoundDevicesPayload(payload []byte) ([]CloudDevice, error) {
	type responseEnvelope struct {
		Devices []cloudDevicePayload `json:"devices"`
		Data    struct {
			Devices []cloudDevicePayload `json:"devices"`
			Items   []cloudDevicePayload `json:"items"`
		} `json:"data"`
		Items []cloudDevicePayload `json:"items"`
	}

	var direct []cloudDevicePayload
	if err := json.Unmarshal(payload, &direct); err == nil {
		return normalizeCloudDevices(direct), nil
	}

	var envelope responseEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode bambu device list response: %w", err)
	}

	switch {
	case len(envelope.Devices) > 0:
		return normalizeCloudDevices(envelope.Devices), nil
	case len(envelope.Data.Devices) > 0:
		return normalizeCloudDevices(envelope.Data.Devices), nil
	case len(envelope.Data.Items) > 0:
		return normalizeCloudDevices(envelope.Data.Items), nil
	case len(envelope.Items) > 0:
		return normalizeCloudDevices(envelope.Items), nil
	default:
		return []CloudDevice{}, nil
	}
}

type uploadURLEntry struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	UploadURL string `json:"upload_url"`
	SignedURL string `json:"signed_url"`
	Filename  string `json:"filename"`
	File      string `json:"file"`
	Size      string `json:"size"`
}

type uploadSection struct {
	URLs          []uploadURLEntry `json:"urls"`
	UploadURLs    []uploadURLEntry `json:"upload_urls"`
	FileURL       string           `json:"file_url"`
	ObjectURL     string           `json:"object_url"`
	DownloadURL   string           `json:"download_url"`
	FileName      string           `json:"file_name"`
	Filename      string           `json:"filename"`
	ObjectKey     string           `json:"object_key"`
	FileID        string           `json:"file_id"`
	ModelID       string           `json:"model_id"`
	FilenameURL   string           `json:"filename_url"`
	UploadURL     string           `json:"upload_url"`
	FileUploadURL string           `json:"file_upload_url"`
	SignedURL     string           `json:"signed_url"`
	SizeURL       string           `json:"size_url"`
	UploadSizeURL string           `json:"upload_size_url"`
	FileSizeURL   string           `json:"file_size_url"`
}

type uploadEnvelope struct {
	Data uploadSection `json:"data"`
	uploadSection
}

func parseUploadURLsPayload(payload []byte) (CloudUploadURLs, error) {
	var envelope uploadEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return CloudUploadURLs{}, fmt.Errorf("decode bambu upload response: %w", err)
	}

	fileUploadURL := firstNonEmptyString(
		findUploadURLByTypeInGroups("filename", envelope.Data.URLs, envelope.Data.UploadURLs, envelope.URLs, envelope.UploadURLs),
		findUploadURLByTypeInGroups("file", envelope.Data.URLs, envelope.Data.UploadURLs, envelope.URLs, envelope.UploadURLs),
		findUploadURLByTypeInGroups("upload", envelope.Data.URLs, envelope.Data.UploadURLs, envelope.URLs, envelope.UploadURLs),
		strings.TrimSpace(envelope.Data.FilenameURL),
		strings.TrimSpace(envelope.Data.UploadURL),
		strings.TrimSpace(envelope.Data.FileUploadURL),
		strings.TrimSpace(envelope.Data.SignedURL),
		strings.TrimSpace(envelope.FilenameURL),
		strings.TrimSpace(envelope.UploadURL),
		strings.TrimSpace(envelope.FileUploadURL),
		strings.TrimSpace(envelope.SignedURL),
	)
	sizeUploadURL := firstNonEmptyString(
		findUploadURLByTypeInGroups("size", envelope.Data.URLs, envelope.Data.UploadURLs, envelope.URLs, envelope.UploadURLs),
		findUploadURLByTypeInGroups("filesize", envelope.Data.URLs, envelope.Data.UploadURLs, envelope.URLs, envelope.UploadURLs),
		strings.TrimSpace(envelope.Data.SizeURL),
		strings.TrimSpace(envelope.Data.UploadSizeURL),
		strings.TrimSpace(envelope.Data.FileSizeURL),
		strings.TrimSpace(envelope.SizeURL),
		strings.TrimSpace(envelope.UploadSizeURL),
		strings.TrimSpace(envelope.FileSizeURL),
	)
	fileURL := firstNonEmptyString(
		strings.TrimSpace(envelope.Data.FileURL),
		strings.TrimSpace(envelope.Data.ObjectURL),
		strings.TrimSpace(envelope.Data.DownloadURL),
		strings.TrimSpace(envelope.FileURL),
		strings.TrimSpace(envelope.ObjectURL),
		strings.TrimSpace(envelope.DownloadURL),
	)
	fileName := firstNonEmptyString(
		strings.TrimSpace(envelope.Data.FileName),
		strings.TrimSpace(envelope.Data.Filename),
		strings.TrimSpace(envelope.Data.ObjectKey),
		strings.TrimSpace(envelope.FileName),
		strings.TrimSpace(envelope.Filename),
		strings.TrimSpace(envelope.ObjectKey),
	)
	fileID := firstNonEmptyString(
		strings.TrimSpace(envelope.Data.FileID),
		strings.TrimSpace(envelope.Data.ModelID),
		strings.TrimSpace(envelope.FileID),
		strings.TrimSpace(envelope.ModelID),
	)

	return CloudUploadURLs{
		UploadFileURL: fileUploadURL,
		UploadSizeURL: sizeUploadURL,
		FileURL:       fileURL,
		FileName:      fileName,
		FileID:        fileID,
	}, nil
}

func normalizeCloudDevices(values []cloudDevicePayload) []CloudDevice {
	out := make([]CloudDevice, 0, len(values))
	for _, item := range values {
		deviceID := strings.TrimSpace(item.DevID)
		if deviceID == "" {
			deviceID = strings.TrimSpace(item.DeviceID)
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = strings.TrimSpace(item.DeviceName)
		}
		model := strings.TrimSpace(item.DevProductName)
		if model == "" {
			model = strings.TrimSpace(item.DevModelName)
		}
		if model == "" {
			model = strings.TrimSpace(item.Model)
		}
		printStatus := strings.TrimSpace(item.PrintStatus)
		if printStatus == "" {
			printStatus = strings.TrimSpace(item.Status)
		}

		online := false
		if item.Online != nil {
			online = *item.Online
		}
		accessCode := strings.TrimSpace(item.DevAccessCode)
		if accessCode == "" {
			accessCode = strings.TrimSpace(item.AccessCode)
		}

		out = append(out, CloudDevice{
			DeviceID:    deviceID,
			Name:        name,
			Model:       model,
			PrintStatus: printStatus,
			Online:      online,
			AccessCode:  accessCode,
		})
	}
	return out
}

func firstValue(document any, keys ...string) string {
	if len(keys) == 0 {
		return ""
	}
	keySet := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keySet[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
	}
	var values []string
	var walk func(value any)
	walk = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, raw := range typed {
				if _, ok := keySet[strings.ToLower(strings.TrimSpace(key))]; ok {
					text := strings.TrimSpace(asString(raw))
					if text != "" {
						values = append(values, text)
					}
				}
				walk(raw)
			}
		case []any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(document)
	return firstNonEmptyString(values...)
}

func findUploadURLByTypeInGroups(expectedType string, groups ...[]uploadURLEntry) string {
	target := strings.ToLower(strings.TrimSpace(expectedType))
	if target == "" {
		return ""
	}
	for _, group := range groups {
		for _, item := range group {
			if strings.ToLower(strings.TrimSpace(item.Type)) != target {
				continue
			}
			candidate := firstNonEmptyString(
				strings.TrimSpace(item.URL),
				strings.TrimSpace(item.UploadURL),
				strings.TrimSpace(item.SignedURL),
				strings.TrimSpace(item.Filename),
				strings.TrimSpace(item.File),
				strings.TrimSpace(item.Size),
			)
			if candidate != "" {
				return candidate
			}
		}
	}
	return ""
}

func asString(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
