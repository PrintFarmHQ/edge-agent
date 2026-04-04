package moonraker

import (
	"context"
	"testing"
	"time"

	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
)

func TestRuntimeAdapterExecuteActionDispatchesPause(t *testing.T) {
	called := false
	adapter := RuntimeAdapter{
		CallPost: func(ctx context.Context, endpointURL, path string, body any) error {
			called = true
			if path != "/printer/print/pause" {
				t.Fatalf("path = %q, want pause endpoint", path)
			}
			return nil
		},
	}
	err := adapter.ExecuteAction(context.Background(), printeradapter.RuntimeAction{Kind: "pause"}, printeradapter.Binding{EndpointURL: "http://moonraker.local"})
	if err != nil {
		t.Fatalf("ExecuteAction failed: %v", err)
	}
	if !called {
		t.Fatalf("expected CallPost to be invoked")
	}
}

func TestRuntimeAdapterExecuteActionDeletesAllFilesThroughDependencies(t *testing.T) {
	deleteCount := 0
	adapter := RuntimeAdapter{
		FetchRemoteMetadata: func(ctx context.Context, endpointURL string, filename string) (*int64, *time.Time, bool, error) {
			size := int64(123)
			return &size, nil, true, nil
		},
		FetchCurrentFilename:  func(ctx context.Context, endpointURL string) (string, error) { return "", nil },
		DeletePath:            func(ctx context.Context, endpointURL, path string) error { deleteCount++; return nil },
		IsPrintableFileFormat: func(path string) bool { return true },
		RefreshFiles: func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
			return nil
		},
	}
	err := adapter.ExecuteAction(context.Background(), printeradapter.RuntimeAction{
		Kind: "delete_all_files",
		Payload: map[string]any{
			"files": []any{
				map[string]any{
					"path": "folder/a.gcode",
					"expected_fingerprint": map[string]any{
						"path":       "folder/a.gcode",
						"size_bytes": 123,
					},
				},
				map[string]any{
					"path": "folder/b.gcode",
					"expected_fingerprint": map[string]any{
						"path":       "folder/b.gcode",
						"size_bytes": 123,
					},
				},
			},
		},
	}, printeradapter.Binding{})
	if err != nil {
		t.Fatalf("ExecuteAction failed: %v", err)
	}
	if deleteCount != 2 {
		t.Fatalf("deleteCount = %d, want 2", deleteCount)
	}
}

func TestRuntimeAdapterExecuteLightUsesDevicePowerWhenAvailable(t *testing.T) {
	var calledPath string
	adapter := RuntimeAdapter{
		CallPost: func(ctx context.Context, endpointURL, path string, body any) error {
			calledPath = path
			return nil
		},
		FetchDevicePowerDevices: func(ctx context.Context, endpointURL string) ([]PowerDevice, error) {
			return []PowerDevice{{Device: "chamber_light", Status: "off"}}, nil
		},
		ResolvePrimaryLightDevice: func(devices []PowerDevice) (string, string, bool) {
			return "chamber_light", "off", true
		},
		FetchObjectList:         func(ctx context.Context, endpointURL string) ([]string, error) { return nil, nil },
		ResolvePrimaryLEDObject: func(objects []string) (string, bool) { return "", false },
		LEDObjectConfigName:     func(objectName string) string { return objectName },
	}
	if err := adapter.ExecuteAction(context.Background(), printeradapter.RuntimeAction{Kind: "light_on"}, printeradapter.Binding{EndpointURL: "http://moonraker.local"}); err != nil {
		t.Fatalf("ExecuteAction failed: %v", err)
	}
	if calledPath == "" || calledPath != "/machine/device_power/device?device=chamber_light&action=on" {
		t.Fatalf("calledPath = %q, want device_power on path", calledPath)
	}
}
