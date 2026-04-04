package moonraker

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
)

const MonitorSnapshotPath = "/server/files/camera/monitor.jpg"

type WebcamConfig struct {
	Name        string
	StreamURL   string
	SnapshotURL string
	Enabled     bool
	IsDefault   bool
}

type AuditFn func(event string, payload map[string]any)

type CameraAdapter struct {
	HTTPClient         *http.Client
	StreamClient       func() *http.Client
	RequestTimeout     time.Duration
	SendMonitorCommand func(ctx context.Context, endpointURL string, stop bool) error
	Audit              AuditFn
}

func (a CameraAdapter) DescribeCamera(ctx context.Context, binding printeradapter.Binding, snapshot printeradapter.RuntimeSnapshot) (printeradapter.CameraCapability, error) {
	webcam, err := a.FetchPrimaryWebcam(ctx, binding.EndpointURL)
	if err != nil {
		return printeradapter.CameraCapability{
			Available:         false,
			Mode:              printeradapter.CameraModeUnsupported,
			ReasonUnavailable: err.Error(),
		}, nil
	}
	if strings.TrimSpace(webcam.StreamURL) != "" {
		return printeradapter.CameraCapability{
			Available:        true,
			Mode:             printeradapter.CameraModeLiveStream,
			Transport:        "moonraker_webcam_stream",
			SupportsLive:     true,
			SupportsSnapshot: strings.TrimSpace(webcam.SnapshotURL) != "",
		}, nil
	}
	if strings.TrimSpace(webcam.SnapshotURL) != "" {
		return printeradapter.CameraCapability{
			Available:        true,
			Mode:             printeradapter.CameraModeSnapshotPoll,
			Transport:        "moonraker_webcam_snapshot",
			SupportsLive:     false,
			SupportsSnapshot: true,
			RefreshInterval:  1 * time.Second,
		}, nil
	}
	return printeradapter.CameraCapability{
		Available:         false,
		Mode:              printeradapter.CameraModeUnsupported,
		ReasonUnavailable: "no enabled moonraker webcams expose a stream or snapshot url",
	}, nil
}

func (a CameraAdapter) OpenCameraStream(ctx context.Context, binding printeradapter.Binding) (printeradapter.CameraStream, error) {
	webcam, err := a.FetchPrimaryWebcam(ctx, binding.EndpointURL)
	if err != nil {
		return printeradapter.CameraStream{}, err
	}
	if strings.TrimSpace(webcam.StreamURL) != "" {
		client := a.streamHTTPClient()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSpace(webcam.StreamURL), nil)
		if err != nil {
			return printeradapter.CameraStream{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return printeradapter.CameraStream{}, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return printeradapter.CameraStream{}, fmt.Errorf("moonraker camera stream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
		if contentType == "" {
			contentType = "multipart/x-mixed-replace"
		}
		return printeradapter.CameraStream{
			Reader:      resp.Body,
			ContentType: contentType,
		}, nil
	}
	if strings.TrimSpace(webcam.SnapshotURL) != "" {
		a.StartMonitorKeepalive(ctx, binding.EndpointURL, strings.TrimSpace(webcam.SnapshotURL))
		reader, contentType, err := a.OpenSnapshotLoopReader(ctx, strings.TrimSpace(webcam.SnapshotURL))
		if err != nil {
			return printeradapter.CameraStream{}, err
		}
		return printeradapter.CameraStream{
			Reader:      reader,
			ContentType: contentType,
		}, nil
	}
	return printeradapter.CameraStream{}, errors.New("moonraker camera has neither stream_url nor snapshot_url")
}

func (a CameraAdapter) FetchCameraSnapshot(ctx context.Context, binding printeradapter.Binding) ([]byte, error) {
	webcam, err := a.FetchPrimaryWebcam(ctx, binding.EndpointURL)
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(webcam.SnapshotURL)
	if target == "" {
		return nil, errors.New("moonraker camera snapshot url is unavailable")
	}
	target = strings.ReplaceAll(target, "{ts}", strconv.FormatInt(time.Now().UnixMilli(), 10))
	return a.FetchSnapshotBytes(ctx, target)
}

func (a CameraAdapter) FetchPrimaryWebcam(ctx context.Context, endpointURL string) (WebcamConfig, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.requestTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, resolveURL(endpointURL, "/server/webcams/list"), nil)
	if err != nil {
		return WebcamConfig{}, err
	}

	resp, err := a.httpClient().Do(req)
	if err != nil {
		return WebcamConfig{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return WebcamConfig{}, fmt.Errorf("moonraker webcams failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Webcams []struct {
			Name          string `json:"name"`
			StreamURL     string `json:"stream_url"`
			SnapshotURL   string `json:"snapshot_url"`
			Enabled       *bool  `json:"enabled"`
			Default       bool   `json:"default"`
			DefaultCamera bool   `json:"default_camera"`
		} `json:"webcams"`
		Result struct {
			Webcams []struct {
				Name          string `json:"name"`
				StreamURL     string `json:"stream_url"`
				SnapshotURL   string `json:"snapshot_url"`
				Enabled       *bool  `json:"enabled"`
				Default       bool   `json:"default"`
				DefaultCamera bool   `json:"default_camera"`
			} `json:"webcams"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return WebcamConfig{}, err
	}

	rawWebcams := payload.Webcams
	if len(rawWebcams) == 0 {
		rawWebcams = payload.Result.Webcams
	}
	webcams := make([]WebcamConfig, 0, len(rawWebcams))
	for _, item := range rawWebcams {
		enabled := true
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		webcams = append(webcams, WebcamConfig{
			Name:        strings.TrimSpace(item.Name),
			StreamURL:   normalizeCameraURL(endpointURL, item.StreamURL),
			SnapshotURL: normalizeCameraURL(endpointURL, item.SnapshotURL),
			Enabled:     enabled,
			IsDefault:   item.Default || item.DefaultCamera,
		})
	}

	webcam, ok := pickPrimaryWebcam(webcams)
	if !ok {
		fallback, fallbackErr := a.fetchSnapshotFallback(ctx, endpointURL)
		if fallbackErr == nil {
			return fallback, nil
		}
		return WebcamConfig{}, errors.New("no enabled moonraker webcams expose a stream or snapshot url")
	}
	return webcam, nil
}

func (a CameraAdapter) StartMonitorKeepalive(ctx context.Context, endpointURL string, snapshotURL string) {
	if !IsMonitorSnapshotURL(snapshotURL) {
		return
	}

	go func() {
		triggerCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := a.sendMonitorCommand(triggerCtx, endpointURL, false)
		cancel()
		if err != nil {
			a.audit("moonraker_camera_monitor_start_error", map[string]any{
				"endpoint_url": endpointURL,
				"error":        err.Error(),
			})
		}

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := a.sendMonitorCommand(stopCtx, endpointURL, true); err != nil {
					a.audit("moonraker_camera_monitor_stop_error", map[string]any{
						"endpoint_url": endpointURL,
						"error":        err.Error(),
					})
				}
				stopCancel()
				return
			case <-ticker.C:
				keepaliveCtx, keepaliveCancel := context.WithTimeout(ctx, 5*time.Second)
				if err := a.sendMonitorCommand(keepaliveCtx, endpointURL, false); err != nil {
					a.audit("moonraker_camera_monitor_keepalive_error", map[string]any{
						"endpoint_url": endpointURL,
						"error":        err.Error(),
					})
				}
				keepaliveCancel()
			}
		}
	}()
}

func (a CameraAdapter) OpenSnapshotLoopReader(ctx context.Context, snapshotURL string) (io.ReadCloser, string, error) {
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		const (
			snapshotPollInterval           = 1 * time.Second
			maxSnapshotConsecutiveFailures = 30
		)
		ticker := time.NewTicker(snapshotPollInterval)
		defer ticker.Stop()
		defer pipeWriter.Close()
		consecutiveFailures := 0
		var lastErr error
		for {
			requestURL := strings.ReplaceAll(snapshotURL, "{ts}", strconv.FormatInt(time.Now().UnixMilli(), 10))
			snapshotBytes, err := a.FetchSnapshotBytes(ctx, requestURL)
			if err != nil {
				lastErr = err
				consecutiveFailures++
				if consecutiveFailures >= maxSnapshotConsecutiveFailures {
					_ = pipeWriter.CloseWithError(
						fmt.Errorf(
							"camera snapshot polling failed after %d consecutive errors: %w",
							consecutiveFailures,
							lastErr,
						),
					)
					return
				}
			} else {
				consecutiveFailures = 0
				frameHeader := fmt.Sprintf("--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(snapshotBytes))
				if _, err := pipeWriter.Write([]byte(frameHeader)); err != nil {
					return
				}
				if _, err := pipeWriter.Write(snapshotBytes); err != nil {
					return
				}
				if _, err := pipeWriter.Write([]byte("\r\n")); err != nil {
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return pipeReader, "multipart/x-mixed-replace;boundary=frame", nil
}

func (a CameraAdapter) FetchSnapshotBytes(ctx context.Context, snapshotURL string) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, a.requestTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, snapshotURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("camera snapshot returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
}

func (a CameraAdapter) fetchSnapshotFallback(ctx context.Context, endpointURL string) (WebcamConfig, error) {
	snapshotURLTemplate := resolveURL(endpointURL, fmt.Sprintf("%s?ts=%d", MonitorSnapshotPath, time.Now().UnixMilli()))
	if _, err := a.FetchSnapshotBytes(ctx, snapshotURLTemplate); err != nil {
		return WebcamConfig{}, err
	}
	return WebcamConfig{
		Name:        "snapshot_fallback",
		SnapshotURL: resolveURL(endpointURL, MonitorSnapshotPath+"?ts={ts}"),
		Enabled:     true,
		IsDefault:   true,
	}, nil
}

func IsMonitorSnapshotURL(snapshotURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(snapshotURL))
	if err != nil {
		return false
	}
	return parsed.Path == MonitorSnapshotPath
}

func pickPrimaryWebcam(webcams []WebcamConfig) (WebcamConfig, bool) {
	if len(webcams) == 0 {
		return WebcamConfig{}, false
	}
	var firstEnabled *WebcamConfig
	var firstUsable *WebcamConfig
	for idx := range webcams {
		webcam := webcams[idx]
		usable := strings.TrimSpace(webcam.StreamURL) != "" || strings.TrimSpace(webcam.SnapshotURL) != ""
		if webcam.Enabled && usable && webcam.IsDefault {
			return webcam, true
		}
		if webcam.Enabled && usable && firstEnabled == nil {
			candidate := webcam
			firstEnabled = &candidate
		}
		if usable && firstUsable == nil {
			candidate := webcam
			firstUsable = &candidate
		}
	}
	if firstEnabled != nil {
		return *firstEnabled, true
	}
	if firstUsable != nil {
		return *firstUsable, true
	}
	return WebcamConfig{}, false
}

func normalizeCameraURL(endpointURL string, rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	return resolveURL(endpointURL, trimmed)
}

func SendMonitorCommandDefault(ctx context.Context, endpointURL string, stop bool) error {
	websocketURL, err := moonrakerWebSocketURL(endpointURL)
	if err != nil {
		return err
	}

	conn, reader, acceptKey, err := dialMoonrakerWebSocket(ctx, websocketURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := completeMoonrakerWebSocketHandshake(reader, acceptKey); err != nil {
		return err
	}

	method := "camera.start_monitor"
	params := map[string]any{
		"domain":   "lan",
		"interval": 0,
	}
	if stop {
		method = "camera.stop_monitor"
		params = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
		"id":      time.Now().UnixNano(),
	})
	if err != nil {
		return err
	}
	return writeWebSocketTextFrame(conn, payload)
}

func resolveURL(baseURL, path string) string {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return strings.TrimSuffix(baseURL, "/") + path
	}
	ref, err := url.Parse(path)
	if err != nil {
		return strings.TrimSuffix(baseURL, "/") + path
	}
	return base.ResolveReference(ref).String()
}

func moonrakerWebSocketURL(endpointURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpointURL))
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", errors.New("validation_error: moonraker endpoint is missing host")
	}
	switch parsed.Scheme {
	case "http", "":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	default:
		return "", fmt.Errorf("validation_error: unsupported moonraker endpoint scheme %q", parsed.Scheme)
	}
	parsed.Path = "/websocket"
	return parsed.String(), nil
}

func dialMoonrakerWebSocket(ctx context.Context, websocketURL string) (net.Conn, *bufio.Reader, string, error) {
	parsed, err := url.Parse(websocketURL)
	if err != nil {
		return nil, nil, "", err
	}

	address := parsed.Host
	if !strings.Contains(address, ":") {
		if parsed.Scheme == "wss" {
			address = net.JoinHostPort(address, "443")
		} else {
			address = net.JoinHostPort(address, "80")
		}
	}

	dialer := &net.Dialer{}
	var conn net.Conn
	switch parsed.Scheme {
	case "ws":
		conn, err = dialer.DialContext(ctx, "tcp", address)
	case "wss":
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: parsed.Hostname(),
		})
	default:
		err = fmt.Errorf("validation_error: unsupported websocket scheme %q", parsed.Scheme)
	}
	if err != nil {
		return nil, nil, "", err
	}

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, nil, "", err
	}
	webSocketKey := base64.StdEncoding.EncodeToString(keyBytes)
	requestPath := parsed.RequestURI()
	if requestPath == "" {
		requestPath = "/websocket"
	}
	handshake := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		requestPath,
		parsed.Host,
		webSocketKey,
	)
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := io.WriteString(conn, handshake); err != nil {
		conn.Close()
		return nil, nil, "", err
	}
	return conn, bufio.NewReader(conn), ComputeWebSocketAcceptKey(webSocketKey), nil
}

func completeMoonrakerWebSocketHandshake(reader *bufio.Reader, acceptKey string) error {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(statusLine, "101") {
		return fmt.Errorf("moonraker websocket upgrade failed: %s", strings.TrimSpace(statusLine))
	}

	headers := make(http.Header)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			break
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	if !strings.EqualFold(strings.TrimSpace(headers.Get("Sec-WebSocket-Accept")), acceptKey) {
		return errors.New("moonraker websocket upgrade failed: invalid accept key")
	}
	return nil
}

func ComputeWebSocketAcceptKey(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeWebSocketTextFrame(conn net.Conn, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("moonraker websocket payload too large")
	}

	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}

	frame := make([]byte, 0, 2+len(mask)+len(payload))
	frame = append(frame, 0x81, byte(0x80|len(payload)))
	frame = append(frame, mask...)
	for idx, b := range payload {
		frame = append(frame, b^mask[idx%len(mask)])
	}
	_, err := conn.Write(frame)
	return err
}

func (a CameraAdapter) requestTimeout() time.Duration {
	if a.RequestTimeout > 0 {
		return a.RequestTimeout
	}
	return 8 * time.Second
}

func (a CameraAdapter) httpClient() *http.Client {
	if a.HTTPClient != nil {
		return a.HTTPClient
	}
	return &http.Client{}
}

func (a CameraAdapter) streamHTTPClient() *http.Client {
	if a.StreamClient != nil {
		if client := a.StreamClient(); client != nil {
			return client
		}
	}
	return a.httpClient()
}

func (a CameraAdapter) sendMonitorCommand(ctx context.Context, endpointURL string, stop bool) error {
	if a.SendMonitorCommand != nil {
		return a.SendMonitorCommand(ctx, endpointURL, stop)
	}
	return SendMonitorCommandDefault(ctx, endpointURL, stop)
}

func (a CameraAdapter) audit(event string, payload map[string]any) {
	if a.Audit != nil {
		a.Audit(event, payload)
	}
}
