package bambu

import (
	"context"
	"errors"
	"testing"
	"time"

	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
)

func TestRuntimeAdapterExecuteActionReturnsLANErrorForPause(t *testing.T) {
	lanCalled := false
	adapter := RuntimeAdapter{
		ExecuteLANControl: func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding, command string) error {
			lanCalled = true
			return errors.New("credentials missing")
		},
	}
	err := adapter.ExecuteAction(context.Background(), printeradapter.RuntimeAction{Kind: "pause"}, printeradapter.Binding{})
	if err == nil {
		t.Fatalf("expected ExecuteAction to return the LAN error")
	}
	if !lanCalled {
		t.Fatalf("expected LAN path to be invoked")
	}
}

func TestRuntimeAdapterExecuteActionDispatchesDeleteFile(t *testing.T) {
	called := false
	adapter := RuntimeAdapter{
		ParsePrinterID: func(endpointURL string) (string, error) { return "printer_1", nil },
		ResolveCredentials: func(ctx context.Context, printerID string) (Credentials, error) {
			return Credentials{Serial: "printer_1", Host: "192.168.1.88", AccessCode: "12345678"}, nil
		},
		IsDeletableFileFormat: func(path string) bool { return true },
		FetchRemoteMetadata: func(ctx context.Context, credentials Credentials, path string) (*int64, *time.Time, error) {
			return nil, nil, nil
		},
		FetchActiveFilePath: func(ctx context.Context, credentials Credentials) (string, error) {
			return "", nil
		},
		DeleteExistingFile: func(ctx context.Context, credentials Credentials, path string) error {
			called = true
			return nil
		},
		ListPrinterFiles: func(ctx context.Context, credentials Credentials, activeFilePath string) ([]ListedFile, error) {
			return nil, nil
		},
		RefreshFiles: func(ctx context.Context, action printeradapter.RuntimeAction, binding printeradapter.Binding) error {
			return nil
		},
	}
	err := adapter.ExecuteAction(context.Background(), printeradapter.RuntimeAction{
		Kind: "delete_file",
		Payload: map[string]any{
			"path": "plate.3mf",
			"expected_fingerprint": map[string]any{
				"path": "plate.3mf",
			},
			"delete_descriptor": map[string]any{
				"primary_ftps_path": "/cache/plate.3mf",
			},
		},
	}, printeradapter.Binding{EndpointURL: "bambu://printer_1"})
	if err != nil {
		t.Fatalf("ExecuteAction failed: %v", err)
	}
	if !called {
		t.Fatalf("expected DeleteFile to be invoked")
	}
}

func TestRuntimeAdapterExecutePrinterCommandPublishesLED(t *testing.T) {
	adapter := RuntimeAdapter{
		ParsePrinterID: func(endpointURL string) (string, error) { return "printer_1", nil },
		ResolveCredentials: func(ctx context.Context, printerID string) (Credentials, error) {
			return Credentials{Serial: "printer_1", Host: "192.168.1.88", AccessCode: "12345678"}, nil
		},
		PublishLED: func(ctx context.Context, credentials Credentials, ledMode string) error {
			if ledMode != "on" {
				t.Fatalf("ledMode = %q, want on", ledMode)
			}
			return nil
		},
		VerifyLEDState: func(ctx context.Context, serial string, ledMode string) error {
			if serial != "printer_1" {
				t.Fatalf("serial = %q, want printer_1", serial)
			}
			return nil
		},
	}
	if err := adapter.ExecuteAction(context.Background(), printeradapter.RuntimeAction{Kind: "light_on"}, printeradapter.Binding{EndpointURL: "bambu://printer_1"}); err != nil {
		t.Fatalf("ExecuteAction failed: %v", err)
	}
}

func TestRuntimeAdapterExecutePrinterCommandBuildsAndPublishesHomeGCode(t *testing.T) {
	adapter := RuntimeAdapter{
		ParsePrinterID: func(endpointURL string) (string, error) { return "printer_1", nil },
		ResolveCredentials: func(ctx context.Context, printerID string) (Credentials, error) {
			return Credentials{Serial: "printer_1", Host: "192.168.1.88", AccessCode: "12345678"}, nil
		},
		BuildHomeAxesGCode: func(payload map[string]any) (string, error) {
			return "G28", nil
		},
		PublishPrinterGCode: func(ctx context.Context, credentials Credentials, gcodeLine string) error {
			if gcodeLine != "G28" {
				t.Fatalf("gcodeLine = %q, want G28", gcodeLine)
			}
			return nil
		},
	}
	if err := adapter.ExecuteAction(context.Background(), printeradapter.RuntimeAction{Kind: "home_axes"}, printeradapter.Binding{EndpointURL: "bambu://printer_1"}); err != nil {
		t.Fatalf("ExecuteAction failed: %v", err)
	}
}
