package bambu

import (
	"context"
	"errors"
	"strings"
	"testing"

	bambucamera "printfarmhq/edge-agent/internal/bambu/cameraruntime"
	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
	bambustore "printfarmhq/edge-agent/internal/store"
)

type fakeRuntimeManager struct {
	ensureFn func(ctx context.Context, req bambucamera.EnsureRequest) (bambucamera.Handle, error)
}

func (f fakeRuntimeManager) Ensure(ctx context.Context, req bambucamera.EnsureRequest) (bambucamera.Handle, error) {
	if f.ensureFn == nil {
		return bambucamera.Handle{}, errors.New("ensure not implemented")
	}
	return f.ensureFn(ctx, req)
}

func TestRTSPCandidatesUseLANCredentials(t *testing.T) {
	urls, err := RTSPCandidates(bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		AccessCode: "abc123",
	})
	if err != nil {
		t.Fatalf("RTSPCandidates failed: %v", err)
	}
	if len(urls) != 3 {
		t.Fatalf("candidate count = %d, want 3", len(urls))
	}
	if urls[0] != "rtsp://bblp:abc123@192.168.1.88:6000/streaming/live/1" {
		t.Fatalf("first rtsp url = %q, want rtsp://...:6000/streaming/live/1", urls[0])
	}
	if strings.Contains(strings.Join(urls, ","), ":322/") {
		t.Fatalf("rtsp candidates = %#v, did not expect port 322 fallback", urls)
	}
}

func TestHelperMJPEGURLUsesTemplatePlaceholders(t *testing.T) {
	adapter := CameraAdapter{
		HelperURLTemplate: "http://127.0.0.1:1984/api/stream.mjpeg?src={serial}&host={host}",
	}

	got := adapter.HelperMJPEGURL(bambustore.BambuLANCredentials{
		Host:   "192.168.1.88",
		Serial: "01P09C470101190",
		Name:   "Forge#1",
		Model:  "P1S",
	})
	want := "http://127.0.0.1:1984/api/stream.mjpeg?src=01P09C470101190&host=192.168.1.88"
	if got != want {
		t.Fatalf("helper url = %q, want %q", got, want)
	}
}

func TestResolveSourcePrefersHelperByDefault(t *testing.T) {
	adapter := CameraAdapter{
		HelperURLTemplate:   "http://127.0.0.1:1984/api/stream.mjpeg?src={serial}",
		RTSPFallbackEnabled: false,
		HelperProber: func(context.Context, string) error {
			return nil
		},
		CandidateProber: func(context.Context, string) error {
			t.Fatalf("RTSP fallback should not run when helper is reachable")
			return nil
		},
	}

	source, err := adapter.ResolveSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "abc123",
	})
	if err != nil {
		t.Fatalf("ResolveSource failed: %v", err)
	}
	if source.Kind != CameraSourceKindHelperMJPEG {
		t.Fatalf("source kind = %q, want %q", source.Kind, CameraSourceKindHelperMJPEG)
	}
	if source.URL != "http://127.0.0.1:1984/api/stream.mjpeg?src=01P09C470101190" {
		t.Fatalf("source url = %q, want helper url", source.URL)
	}
}

func TestResolveSourceRequiresHelperWhenFallbackDisabled(t *testing.T) {
	adapter := CameraAdapter{
		HelperURLTemplate:   "",
		RTSPFallbackEnabled: false,
	}

	_, err := adapter.ResolveSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "abc123",
	})
	if err == nil {
		t.Fatalf("expected helper-required error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_helper_required") {
		t.Fatalf("error = %q, want helper-required reason", err)
	}
}

func TestResolveSourceReturnsHelperUnreachableWhenFallbackDisabled(t *testing.T) {
	adapter := CameraAdapter{
		HelperURLTemplate:   "http://127.0.0.1:1984/api/stream.mjpeg?src={serial}",
		RTSPFallbackEnabled: false,
		HelperProber: func(context.Context, string) error {
			return errors.New("dial tcp 127.0.0.1:1984: connect: connection refused")
		},
	}

	_, err := adapter.ResolveSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "abc123",
	})
	if err == nil {
		t.Fatalf("expected helper-unreachable error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_helper_unreachable") {
		t.Fatalf("error = %q, want helper-unreachable reason", err)
	}
}

func TestResolveSourceRTSPFallbackRedactsCandidateErrors(t *testing.T) {
	adapter := CameraAdapter{
		HelperURLTemplate:   "",
		RTSPFallbackEnabled: true,
		CandidateProber: func(_ context.Context, candidate string) error {
			if strings.Contains(candidate, ":322/") {
				t.Fatalf("unexpected 322 fallback candidate: %q", candidate)
			}
			return errors.New("connection refused")
		},
	}

	_, err := adapter.ResolveSource(context.Background(), bambustore.BambuLANCredentials{
		Host:       "192.168.1.88",
		Serial:     "01P09C470101190",
		AccessCode: "secret-access-code",
	})
	if err == nil {
		t.Fatalf("expected RTSP fallback probe error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_rtsp_probe_failed") {
		t.Fatalf("error = %q, want rtsp probe failure", err)
	}
	if strings.Contains(err.Error(), "secret-access-code") {
		t.Fatalf("error leaked access code: %q", err)
	}
	if strings.Contains(err.Error(), ":322/") {
		t.Fatalf("error should not mention removed 322 fallback: %q", err)
	}
}

func TestEnsureRuntimeHandleReturnsUnverifiedFamilyError(t *testing.T) {
	adapter := CameraAdapter{
		RuntimeManager: fakeRuntimeManager{
			ensureFn: func(ctx context.Context, req bambucamera.EnsureRequest) (bambucamera.Handle, error) {
				return bambucamera.Handle{}, errors.New("bambu_camera_family_unverified: directly tested Bambu camera support currently exists only for P1S (model=X1C)")
			},
		},
		ResolveCredentials: func(context.Context, string) (bambustore.BambuLANCredentials, error) {
			return bambustore.BambuLANCredentials{
				Serial:     "serial-1",
				Host:       "192.168.100.200",
				AccessCode: "87654321",
				Model:      "X1C",
			}, nil
		},
	}

	_, err := adapter.EnsureRuntimeHandle(context.Background(), "serial-1")
	if err == nil {
		t.Fatalf("expected family-unverified error")
	}
	if !strings.Contains(err.Error(), "bambu_camera_family_unverified") {
		t.Fatalf("error = %q, want family-unverified", err)
	}
}

func TestDescribeCameraReturnsUnsupportedWhenRuntimeIsUnverified(t *testing.T) {
	adapter := CameraAdapter{
		RuntimeManager: fakeRuntimeManager{
			ensureFn: func(ctx context.Context, req bambucamera.EnsureRequest) (bambucamera.Handle, error) {
				return bambucamera.Handle{}, errors.New("bambu_camera_family_unverified: directly tested Bambu camera support currently exists only for P1S (model=X1C)")
			},
		},
		ParsePrinterID: func(endpointURL string) (string, error) { return "serial-1", nil },
		ResolveCredentials: func(context.Context, string) (bambustore.BambuLANCredentials, error) {
			return bambustore.BambuLANCredentials{
				Serial:     "serial-1",
				Host:       "192.168.100.200",
				AccessCode: "87654321",
				Model:      "X1C",
			}, nil
		},
	}

	capability, err := adapter.DescribeCamera(context.Background(), printeradapter.Binding{
		PrinterID:     1,
		AdapterFamily: "bambu",
		EndpointURL:   "bambu://serial-1",
	}, printeradapter.RuntimeSnapshot{})
	if err != nil {
		t.Fatalf("DescribeCamera returned error: %v", err)
	}
	if capability.Available {
		t.Fatalf("expected camera to be unavailable")
	}
	if capability.Mode != printeradapter.CameraModeUnsupported {
		t.Fatalf("mode = %q, want unsupported", capability.Mode)
	}
	if !strings.Contains(capability.ReasonUnavailable, "bambu_camera_family_unverified") {
		t.Fatalf("reason = %q, want family-unverified", capability.ReasonUnavailable)
	}
}
