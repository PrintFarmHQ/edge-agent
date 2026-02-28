package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	bambuauth "printfarmhq/edge-agent/internal/bambu/auth"
)

func TestHTTPProviderLoginSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/user-service/user/login" {
			http.NotFound(w, r)
			return
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode login request failed: %v", err)
		}
		if req["account"] != "user@example.com" {
			t.Fatalf("unexpected account: %q", req["account"])
		}
		if req["apiError"] != "" {
			t.Fatalf("unexpected apiError: %q", req["apiError"])
		}
		if req["password"] != "secret" {
			t.Fatalf("unexpected password")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken":  "access-1",
			"refreshToken": "refresh-1",
			"expiresIn":    3600,
			"account": map[string]any{
				"email_masked": "u***@example.com",
				"user_id":      "3911589060",
			},
		})
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	session, err := provider.Login(context.Background(), bambuauth.LoginRequest{Username: "user@example.com", Password: "secret"})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if session.AccessToken != "access-1" {
		t.Fatalf("access token = %q, want access-1", session.AccessToken)
	}
	if session.RefreshToken != "refresh-1" {
		t.Fatalf("refresh token = %q, want refresh-1", session.RefreshToken)
	}
	if session.ExpiresAt.IsZero() {
		t.Fatalf("expires_at should not be zero")
	}
	if session.MQTTUsername != "3911589060" {
		t.Fatalf("mqtt username = %q, want 3911589060", session.MQTTUsername)
	}
}

func TestHTTPProviderLoginMFARequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/user-service/user/login" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"","refreshToken":"","expiresIn":0,"loginType":"verifyCode"}`))
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	_, err := provider.Login(context.Background(), bambuauth.LoginRequest{Username: "user@example.com", Password: "secret"})
	if err == nil {
		t.Fatalf("expected MFA required error")
	}
	if !errors.Is(err, bambuauth.ErrMFARequired) {
		t.Fatalf("expected ErrMFARequired, got %v", err)
	}
}

func TestHTTPProviderListBoundDevicesSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "success",
			"devices": []map[string]any{
				{
					"dev_id":           "dev-1",
					"name":             "P1S Office",
					"dev_product_name": "P1S",
					"print_status":     "ACTIVE",
					"online":           true,
					"dev_access_code":  "code-1",
				},
				{
					"dev_id":           "dev-2",
					"name":             "X1C Garage",
					"dev_product_name": "X1C",
					"print_status":     "OFFLINE",
					"online":           false,
				},
			},
		})
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{
		AuthBaseURL: srv.URL,
		Client:      &http.Client{Timeout: 2 * time.Second},
	})
	devices, err := provider.ListBoundDevices(context.Background(), "access-1")
	if err != nil {
		t.Fatalf("ListBoundDevices failed: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("device count = %d, want 2", len(devices))
	}
	if devices[0].DeviceID != "dev-1" || devices[0].Name != "P1S Office" || !devices[0].Online {
		t.Fatalf("unexpected first device: %+v", devices[0])
	}
	if devices[0].AccessCode != "code-1" {
		t.Fatalf("access code = %q, want code-1", devices[0].AccessCode)
	}
	if devices[1].DeviceID != "dev-2" || devices[1].Model != "X1C" || devices[1].Online {
		t.Fatalf("unexpected second device: %+v", devices[1])
	}
}

func TestHTTPProviderListBoundDevicesUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{
		AuthBaseURL: srv.URL,
		Client:      &http.Client{Timeout: 2 * time.Second},
	})
	_, err := provider.ListBoundDevices(context.Background(), "access-1")
	if err == nil {
		t.Fatalf("expected unauthorized error")
	}
	if !errors.Is(err, bambuauth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestHTTPProviderGetUploadURLsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/upload" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		if got := r.URL.Query().Get("filename"); got != "plate.gcode.3mf" {
			t.Fatalf("filename query = %q, want plate.gcode.3mf", got)
		}
		if got := r.URL.Query().Get("size"); got != "12" {
			t.Fatalf("size query = %q, want 12", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"urls": []map[string]any{
					{"type": "filename", "url": "https://uploads.local/file"},
					{"type": "size", "url": "https://uploads.local/size"},
				},
				"file_url": "https://objects.local/plate.gcode.3mf",
			},
		})
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	uploadURLs, err := provider.GetUploadURLs(context.Background(), "access-1", "plate.gcode.3mf", 12)
	if err != nil {
		t.Fatalf("GetUploadURLs failed: %v", err)
	}
	if uploadURLs.UploadFileURL != "https://uploads.local/file" {
		t.Fatalf("upload file url = %q, want https://uploads.local/file", uploadURLs.UploadFileURL)
	}
	if uploadURLs.UploadSizeURL != "https://uploads.local/size" {
		t.Fatalf("upload size url = %q, want https://uploads.local/size", uploadURLs.UploadSizeURL)
	}
	if uploadURLs.FileURL != "https://objects.local/plate.gcode.3mf" {
		t.Fatalf("file url = %q, want https://objects.local/plate.gcode.3mf", uploadURLs.FileURL)
	}
}

func TestHTTPProviderGetUploadURLsMissingFileURLFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/upload" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"urls": []map[string]any{
					{"type": "filename", "url": "https://uploads.local/file"},
					{"type": "size", "url": "https://uploads.local/size"},
				},
			},
		})
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	_, err := provider.GetUploadURLs(context.Background(), "access-1", "plate.gcode.3mf", 12)
	if err == nil {
		t.Fatalf("expected missing file_url validation error")
	}
	if got := err.Error(); got != "validation_error: bambu upload response missing file_url" {
		t.Fatalf("error = %q, want validation_error: bambu upload response missing file_url", got)
	}
}

func TestHTTPProviderUploadToSignedURLsUploadsFileAndSize(t *testing.T) {
	var fileBody []byte
	var sizeBody []byte
	var fileRequests int
	var sizeRequests int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upload/file":
			fileRequests++
			if r.Method != http.MethodPut {
				t.Fatalf("file upload method = %s, want PUT", r.Method)
			}
			fileBody, _ = io.ReadAll(r.Body)
		case "/upload/size":
			sizeRequests++
			if r.Method != http.MethodPut {
				t.Fatalf("size upload method = %s, want PUT", r.Method)
			}
			sizeBody, _ = io.ReadAll(r.Body)
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: "https://api.bambulab.com", Client: &http.Client{Timeout: 2 * time.Second}})
	err := provider.UploadToSignedURLs(
		context.Background(),
		CloudUploadURLs{
			UploadFileURL: srv.URL + "/upload/file",
			UploadSizeURL: srv.URL + "/upload/size",
		},
		[]byte("gcode-bytes"),
	)
	if err != nil {
		t.Fatalf("UploadToSignedURLs failed: %v", err)
	}
	if fileRequests != 1 {
		t.Fatalf("file request count = %d, want 1", fileRequests)
	}
	if sizeRequests != 1 {
		t.Fatalf("size request count = %d, want 1", sizeRequests)
	}
	if !bytes.Equal(fileBody, []byte("gcode-bytes")) {
		t.Fatalf("file body = %q, want gcode-bytes", string(fileBody))
	}
	if !bytes.Equal(sizeBody, []byte(strconv.Itoa(len([]byte("gcode-bytes"))))) {
		t.Fatalf("size body = %q, want %d", string(sizeBody), len([]byte("gcode-bytes")))
	}
}

func TestHTTPProviderUploadToSignedURLsRetriesWithoutContentTypeOnSignatureMismatch(t *testing.T) {
	var (
		fileRequests int
		firstHeader  string
		secondHeader string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/upload/file" {
			http.NotFound(w, r)
			return
		}
		fileRequests++
		switch fileRequests {
		case 1:
			firstHeader = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Error><Code>SignatureDoesNotMatch</Code></Error>`))
		case 2:
			secondHeader = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected extra request %d", fileRequests)
		}
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: "https://api.bambulab.com", Client: &http.Client{Timeout: 2 * time.Second}})
	err := provider.UploadToSignedURLs(
		context.Background(),
		CloudUploadURLs{
			UploadFileURL: srv.URL + "/upload/file",
		},
		[]byte("gcode-bytes"),
	)
	if err != nil {
		t.Fatalf("UploadToSignedURLs failed: %v", err)
	}
	if fileRequests != 2 {
		t.Fatalf("file request count = %d, want 2", fileRequests)
	}
	if firstHeader != "application/octet-stream" {
		t.Fatalf("first content-type = %q, want application/octet-stream", firstHeader)
	}
	if secondHeader != "" {
		t.Fatalf("second content-type = %q, want empty", secondHeader)
	}
}

func TestHTTPProviderStartPrintJobSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/print" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode print start payload failed: %v", err)
		}
		if payload["device_id"] != "dev-1" {
			t.Fatalf("device_id = %v, want dev-1", payload["device_id"])
		}
		if payload["dev_id"] != "dev-1" {
			t.Fatalf("dev_id = %v, want dev-1", payload["dev_id"])
		}
		if payload["file_name"] != "plate.gcode.3mf" {
			t.Fatalf("file_name = %v, want plate.gcode.3mf", payload["file_name"])
		}
		if payload["file_url"] != "https://objects.local/plate.gcode.3mf" {
			t.Fatalf("file_url = %v, want https://objects.local/plate.gcode.3mf", payload["file_url"])
		}
		if payload["file_id"] != "file-id-1" {
			t.Fatalf("file_id = %v, want file-id-1", payload["file_id"])
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	err := provider.StartPrintJob(context.Background(), "access-1", CloudPrintStartRequest{
		DeviceID: "dev-1",
		FileName: "plate.gcode.3mf",
		FileURL:  "https://objects.local/plate.gcode.3mf",
		FileID:   "file-id-1",
	})
	if err != nil {
		t.Fatalf("StartPrintJob failed: %v", err)
	}
}

func TestHTTPProviderStartPrintJobUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/print" {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	err := provider.StartPrintJob(context.Background(), "access-1", CloudPrintStartRequest{
		DeviceID: "dev-1",
		FileName: "plate.gcode.3mf",
		FileURL:  "https://objects.local/plate.gcode.3mf",
	})
	if err == nil {
		t.Fatalf("expected unauthorized error")
	}
	if !errors.Is(err, bambuauth.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestParseUploadURLsPayloadSupportsTypedURLs(t *testing.T) {
	payload := []byte(`{
		"message":"success",
		"data":{
			"urls":[
				{"type":"filename","url":"https://uploads.local/file"},
				{"type":"size","url":"https://uploads.local/size"}
			],
			"file_id":"file-id-1",
			"file_url":"https://objects.local/plate.gcode.3mf",
			"file_name":"plate.gcode.3mf"
		}
	}`)

	parsed, err := parseUploadURLsPayload(payload)
	if err != nil {
		t.Fatalf("parseUploadURLsPayload failed: %v", err)
	}
	if parsed.UploadFileURL != "https://uploads.local/file" {
		t.Fatalf("UploadFileURL = %q, want https://uploads.local/file", parsed.UploadFileURL)
	}
	if parsed.UploadSizeURL != "https://uploads.local/size" {
		t.Fatalf("UploadSizeURL = %q, want https://uploads.local/size", parsed.UploadSizeURL)
	}
	if parsed.FileURL != "https://objects.local/plate.gcode.3mf" {
		t.Fatalf("FileURL = %q, want https://objects.local/plate.gcode.3mf", parsed.FileURL)
	}
	if parsed.FileName != "plate.gcode.3mf" {
		t.Fatalf("FileName = %q, want plate.gcode.3mf", parsed.FileName)
	}
	if parsed.FileID != "file-id-1" {
		t.Fatalf("FileID = %q, want file-id-1", parsed.FileID)
	}
}

func TestParseUploadURLsPayloadPrefersDeterministicFileIDPaths(t *testing.T) {
	payload := []byte(`{
		"id":"top-level-id",
		"data":{
			"id":"nested-random-id",
			"urls":[{"type":"filename","url":"https://uploads.local/file"}],
			"file_url":"https://objects.local/plate.gcode.3mf",
			"file_name":"plate.gcode.3mf",
			"file_id":"file-id-expected",
			"meta":{"id":"another-id"}
		}
	}`)

	parsed, err := parseUploadURLsPayload(payload)
	if err != nil {
		t.Fatalf("parseUploadURLsPayload failed: %v", err)
	}
	if parsed.FileID != "file-id-expected" {
		t.Fatalf("FileID = %q, want file-id-expected", parsed.FileID)
	}
}

func TestHTTPProviderStartPrintJobFallsBackToPutOn405(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/print" {
			http.NotFound(w, r)
			return
		}
		methods = append(methods, r.Method)
		if r.Method == http.MethodPost {
			w.Header().Set("Allow", "PUT")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	err := provider.StartPrintJob(context.Background(), "access-1", CloudPrintStartRequest{
		DeviceID: "dev-1",
		FileName: "plate.gcode.3mf",
		FileURL:  "https://objects.local/plate.gcode.3mf",
	})
	if err != nil {
		t.Fatalf("StartPrintJob fallback failed: %v", err)
	}
	if len(methods) != 2 || methods[0] != http.MethodPost || methods[1] != http.MethodPut {
		t.Fatalf("methods = %v, want [POST PUT]", methods)
	}
}

func TestHTTPProviderStartPrintJobReturnsUnsupportedWhenAllEndpointsReject(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v1/iot-service/api/user/print":
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/v1/iot-service/api/user/print/start":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Not Found"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	provider := NewHTTPProvider(HTTPProviderConfig{AuthBaseURL: srv.URL, Client: &http.Client{Timeout: 2 * time.Second}})
	err := provider.StartPrintJob(context.Background(), "access-1", CloudPrintStartRequest{
		DeviceID: "dev-1",
		FileName: "plate.gcode.3mf",
		FileURL:  "https://objects.local/plate.gcode.3mf",
	})
	if err == nil {
		t.Fatalf("expected unsupported error")
	}
	if !errors.Is(err, ErrPrintStartUnsupported) {
		t.Fatalf("expected ErrPrintStartUnsupported, got %v", err)
	}
	if len(requests) != 4 {
		t.Fatalf("request count = %d, want 4", len(requests))
	}
}
