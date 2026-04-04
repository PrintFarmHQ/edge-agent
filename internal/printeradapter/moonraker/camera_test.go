package moonraker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newIPv4Server(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func TestFetchPrimaryWebcamFallsBackToMonitorSnapshot(t *testing.T) {
	srv := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/server/webcams/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]any{
					"webcams": []map[string]any{},
				},
			})
		case "/server/files/camera/monitor.jpg":
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write([]byte{0xff, 0xd8, 0xff, 0xd9})
		default:
			http.NotFound(w, r)
		}
	}))

	adapter := CameraAdapter{HTTPClient: srv.Client()}
	webcam, err := adapter.FetchPrimaryWebcam(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchPrimaryWebcam failed: %v", err)
	}
	if webcam.SnapshotURL == "" {
		t.Fatalf("expected snapshot fallback url")
	}
	if !strings.Contains(webcam.SnapshotURL, "/server/files/camera/monitor.jpg?ts={ts}") {
		t.Fatalf("snapshot fallback url = %q, want monitor.jpg template", webcam.SnapshotURL)
	}
}

func TestOpenSnapshotLoopReaderToleratesTransientSnapshotFailures(t *testing.T) {
	requestCount := 0
	srv := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount <= 2 {
			http.Error(w, "temporary camera error", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write([]byte{0xff, 0xd8, 0xff, 0xd9})
	}))

	adapter := CameraAdapter{HTTPClient: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader, contentType, err := adapter.OpenSnapshotLoopReader(ctx, srv.URL+"/monitor.jpg?ts={ts}")
	if err != nil {
		t.Fatalf("OpenSnapshotLoopReader failed: %v", err)
	}
	defer reader.Close()

	if contentType != "multipart/x-mixed-replace;boundary=frame" {
		t.Fatalf("contentType = %q, want multipart/x-mixed-replace;boundary=frame", contentType)
	}

	readResult := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 128)
		n, err := io.ReadAtLeast(reader, buf, 64)
		if err != nil {
			readErr <- err
			return
		}
		readResult <- append([]byte(nil), buf[:n]...)
	}()

	select {
	case err := <-readErr:
		t.Fatalf("snapshot loop reader failed before recovery: %v", err)
	case payload := <-readResult:
		if !bytes.Contains(payload, []byte("--frame")) {
			t.Fatalf("payload = %q, want multipart frame header", string(payload))
		}
		if !bytes.Contains(payload, []byte{0xff, 0xd8, 0xff, 0xd9}) {
			t.Fatalf("payload missing jpeg frame bytes: %v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for snapshot loop reader to recover")
	}
}

func TestSendMonitorCommandDefaultSendsStartMonitorRPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer listener.Close()

	payloadCh := make(chan map[string]any, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		headers := make(http.Header)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				errCh <- readErr
				return
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "GET ") {
				continue
			}
			if trimmed == "" {
				break
			}
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}

		acceptKey := ComputeWebSocketAcceptKey(headers.Get("Sec-WebSocket-Key"))
		if _, err := io.WriteString(
			conn,
			"HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Accept: "+acceptKey+"\r\n\r\n",
		); err != nil {
			errCh <- err
			return
		}

		header := make([]byte, 2)
		if _, err := io.ReadFull(reader, header); err != nil {
			errCh <- err
			return
		}
		payloadLen := int(header[1] & 0x7f)
		mask := make([]byte, 4)
		if _, err := io.ReadFull(reader, mask); err != nil {
			errCh <- err
			return
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			errCh <- err
			return
		}
		for idx := range payload {
			payload[idx] ^= mask[idx%len(mask)]
		}

		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			errCh <- err
			return
		}
		payloadCh <- decoded
	}()

	endpointURL := "http://" + listener.Addr().String()
	if err := SendMonitorCommandDefault(context.Background(), endpointURL, false); err != nil {
		t.Fatalf("SendMonitorCommandDefault failed: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("websocket capture failed: %v", err)
	case payload := <-payloadCh:
		if payload["method"] != "camera.start_monitor" {
			t.Fatalf("method = %v, want camera.start_monitor", payload["method"])
		}
		params, ok := payload["params"].(map[string]any)
		if !ok {
			t.Fatalf("params = %#v, want object", payload["params"])
		}
		if params["domain"] != "lan" {
			t.Fatalf("domain = %v, want lan", params["domain"])
		}
		if params["interval"] != float64(0) {
			t.Fatalf("interval = %v, want 0", params["interval"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for websocket payload")
	}
}

func TestStartMonitorKeepaliveSkipsNonMonitorSnapshots(t *testing.T) {
	calls := make(chan string, 4)
	adapter := CameraAdapter{
		SendMonitorCommand: func(ctx context.Context, endpointURL string, stop bool) error {
			if stop {
				calls <- "stop"
			} else {
				calls <- "start"
			}
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	adapter.StartMonitorKeepalive(ctx, "http://moonraker.local", "http://moonraker.local/webcam/?action=snapshot")
	time.Sleep(150 * time.Millisecond)
	cancel()

	select {
	case call := <-calls:
		t.Fatalf("unexpected keepalive call for non-monitor snapshot: %s", call)
	default:
	}
}

func TestStartMonitorKeepaliveTriggersMonitorCommands(t *testing.T) {
	calls := make(chan string, 4)
	adapter := CameraAdapter{
		SendMonitorCommand: func(ctx context.Context, endpointURL string, stop bool) error {
			if stop {
				calls <- "stop"
			} else {
				calls <- "start"
			}
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	adapter.StartMonitorKeepalive(ctx, "http://moonraker.local", "http://moonraker.local/server/files/camera/monitor.jpg?ts=1")

	select {
	case call := <-calls:
		if call != "start" {
			t.Fatalf("first keepalive call = %q, want start", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for start monitor call")
	}

	cancel()

	select {
	case call := <-calls:
		if call != "stop" {
			t.Fatalf("stop keepalive call = %q, want stop", call)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stop monitor call")
	}
}
