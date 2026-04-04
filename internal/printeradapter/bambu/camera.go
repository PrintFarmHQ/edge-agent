package bambu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"time"

	bambucamera "printfarmhq/edge-agent/internal/bambu/cameraruntime"
	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
	bambustore "printfarmhq/edge-agent/internal/store"
)

type CameraSourceKind string

const (
	CameraSourceKindHelperMJPEG CameraSourceKind = "helper_mjpeg"
	CameraSourceKindRTSP        CameraSourceKind = "rtsp"
)

type CameraSource struct {
	URL  string
	Kind CameraSourceKind
}

type ParsePrinterIDFn func(endpointURL string) (string, error)
type ResolveCredentialsFn func(ctx context.Context, printerID string) (bambustore.BambuLANCredentials, error)
type InternalContractURLFn func(printerID string, resource string) (string, error)
type OpenHTTPReaderFn func(ctx context.Context, targetURL string, defaultContentType string) (io.ReadCloser, string, error)
type OpenFFmpegReaderFn func(ctx context.Context, inputURL string, snapshot bool) (io.ReadCloser, string, error)
type RuntimeStreamReaderFn func(ctx context.Context, handle bambucamera.Handle) (io.ReadCloser, error)
type RuntimeSnapshotFn func(ctx context.Context, handle bambucamera.Handle) ([]byte, error)
type HelperProbeFn func(ctx context.Context, helperURL string) error
type CandidateProbeFn func(ctx context.Context, candidate string) error

type CameraAdapter struct {
	RuntimeManager              bambucamera.Runtime
	ParsePrinterID              ParsePrinterIDFn
	ResolveCredentials          ResolveCredentialsFn
	InternalContractURL         InternalContractURLFn
	OpenHTTPReader              OpenHTTPReaderFn
	OpenFFmpegReader            OpenFFmpegReaderFn
	OpenManagedRuntimeReader    RuntimeStreamReaderFn
	FetchManagedRuntimeSnapshot RuntimeSnapshotFn
	HelperURLTemplate           string
	RTSPFallbackEnabled         bool
	HelperProber                HelperProbeFn
	CandidateProber             CandidateProbeFn
}

func (a CameraAdapter) DescribeCamera(ctx context.Context, binding printeradapter.Binding, snapshot printeradapter.RuntimeSnapshot) (printeradapter.CameraCapability, error) {
	printerID, err := a.parsePrinterID(binding.EndpointURL)
	if err != nil {
		return unsupportedCapability(err.Error()), nil
	}
	if a.RuntimeManager != nil {
		if _, err := a.EnsureRuntimeHandle(ctx, printerID); err != nil {
			return unsupportedCapability(err.Error()), nil
		}
		return printeradapter.CameraCapability{
			Available:        true,
			Mode:             printeradapter.CameraModeLiveStream,
			Transport:        "edge_upload_mjpeg",
			SupportsLive:     true,
			SupportsSnapshot: true,
		}, nil
	}
	credentials, err := a.resolveCredentials(ctx, printerID)
	if err != nil {
		return unsupportedCapability(err.Error()), nil
	}
	source, err := a.ResolveSource(ctx, credentials)
	if err != nil {
		return unsupportedCapability(err.Error()), nil
	}
	return printeradapter.CameraCapability{
		Available:        true,
		Mode:             printeradapter.CameraModeLiveStream,
		Transport:        "edge_upload_mjpeg",
		SupportsLive:     true,
		SupportsSnapshot: source.Kind == CameraSourceKindHelperMJPEG || source.Kind == CameraSourceKindRTSP,
	}, nil
}

func (a CameraAdapter) OpenCameraStream(ctx context.Context, binding printeradapter.Binding) (printeradapter.CameraStream, error) {
	return a.OpenProxyReader(ctx, binding, "stream")
}

func (a CameraAdapter) FetchCameraSnapshot(ctx context.Context, binding printeradapter.Binding) ([]byte, error) {
	printerID, err := a.parsePrinterID(binding.EndpointURL)
	if err != nil {
		return nil, err
	}
	if a.RuntimeManager != nil {
		return a.FetchManagedSnapshot(ctx, printerID)
	}
	stream, err := a.OpenProxyReader(ctx, binding, "snapshot")
	if err != nil {
		return nil, err
	}
	defer stream.Reader.Close()
	return io.ReadAll(stream.Reader)
}

func (a CameraAdapter) OpenProxyReader(ctx context.Context, binding printeradapter.Binding, variant string) (printeradapter.CameraStream, error) {
	printerID, err := a.parsePrinterID(binding.EndpointURL)
	if err != nil {
		return printeradapter.CameraStream{}, err
	}
	resource := "stream.mjpeg"
	defaultContentType := "multipart/x-mixed-replace;boundary=frame"
	if strings.EqualFold(strings.TrimSpace(variant), "snapshot") {
		resource = "snapshot.jpg"
		defaultContentType = "image/jpeg"
	}
	if a.RuntimeManager != nil {
		internalURL, err := a.internalContractURL(printerID, resource)
		if err != nil {
			return printeradapter.CameraStream{}, err
		}
		reader, contentType, err := a.openHTTPReader(ctx, internalURL, defaultContentType)
		if err != nil {
			return printeradapter.CameraStream{}, err
		}
		return printeradapter.CameraStream{Reader: reader, ContentType: contentType}, nil
	}
	credentials, err := a.resolveCredentials(ctx, printerID)
	if err != nil {
		return printeradapter.CameraStream{}, err
	}
	source, err := a.ResolveSource(ctx, credentials)
	if err != nil {
		return printeradapter.CameraStream{}, err
	}
	if source.Kind == CameraSourceKindHelperMJPEG && strings.EqualFold(strings.TrimSpace(variant), "stream") {
		reader, contentType, err := a.openHTTPReader(ctx, source.URL, "multipart/x-mixed-replace;boundary=frame")
		if err != nil {
			return printeradapter.CameraStream{}, err
		}
		return printeradapter.CameraStream{Reader: reader, ContentType: contentType}, nil
	}
	reader, contentType, err := a.openFFmpegReader(ctx, source.URL, strings.EqualFold(strings.TrimSpace(variant), "snapshot"))
	if err != nil {
		return printeradapter.CameraStream{}, err
	}
	return printeradapter.CameraStream{Reader: reader, ContentType: contentType}, nil
}

func (a CameraAdapter) EnsureRuntimeHandle(ctx context.Context, printerID string) (bambucamera.Handle, error) {
	if a.RuntimeManager == nil {
		return bambucamera.Handle{}, errors.New("bambu_camera_runtime_unavailable: internal runtime manager is not configured")
	}
	credentials, err := a.resolveCredentials(ctx, printerID)
	if err != nil {
		return bambucamera.Handle{}, err
	}
	return a.RuntimeManager.Ensure(ctx, bambucamera.EnsureRequest{
		Serial:     strings.TrimSpace(printerID),
		Host:       strings.TrimSpace(credentials.Host),
		AccessCode: strings.TrimSpace(credentials.AccessCode),
		Model:      strings.TrimSpace(credentials.Model),
	})
}

func (a CameraAdapter) OpenManagedRuntimeStream(ctx context.Context, printerID string) (io.ReadCloser, error) {
	handle, err := a.EnsureRuntimeHandle(ctx, printerID)
	if err != nil {
		return nil, err
	}
	return a.openManagedRuntimeReader(ctx, handle)
}

func (a CameraAdapter) FetchManagedSnapshot(ctx context.Context, printerID string) ([]byte, error) {
	handle, err := a.EnsureRuntimeHandle(ctx, printerID)
	if err != nil {
		return nil, err
	}
	return a.fetchManagedRuntimeSnapshot(ctx, handle)
}

func (a CameraAdapter) ResolveSource(ctx context.Context, credentials bambustore.BambuLANCredentials) (CameraSource, error) {
	helperURL := a.HelperMJPEGURL(credentials)
	if helperURL == "" {
		if !a.RTSPFallbackEnabled {
			return CameraSource{}, errors.New("bambu_camera_helper_required: configure BAMBU_CAMERA_HELPER_MJPEG_URL_TEMPLATE or enable BAMBU_CAMERA_RTSP_FALLBACK_ENABLED")
		}
		streamURL, err := a.ResolveRTSPStreamURL(ctx, credentials)
		if err != nil {
			return CameraSource{}, err
		}
		return CameraSource{URL: streamURL, Kind: CameraSourceKindRTSP}, nil
	}

	if err := a.helperProber(ctx, helperURL); err == nil {
		return CameraSource{URL: helperURL, Kind: CameraSourceKindHelperMJPEG}, nil
	} else if !a.RTSPFallbackEnabled {
		return CameraSource{}, fmt.Errorf("bambu_camera_helper_unreachable: helper %s is not reachable: %v", SanitizeCameraURL(helperURL), err)
	}

	streamURL, err := a.ResolveRTSPStreamURL(ctx, credentials)
	if err != nil {
		return CameraSource{}, err
	}
	return CameraSource{URL: streamURL, Kind: CameraSourceKindRTSP}, nil
}

func (a CameraAdapter) ResolveRTSPStreamURL(ctx context.Context, credentials bambustore.BambuLANCredentials) (string, error) {
	candidates, err := RTSPCandidates(credentials)
	if err != nil {
		return "", err
	}
	failures := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		probeErr := a.candidateProber(ctx, candidate)
		if probeErr == nil {
			return candidate, nil
		}
		failures = append(failures, fmt.Sprintf("%s => %s", SanitizeCameraURL(candidate), strings.TrimSpace(probeErr.Error())))
	}
	if len(failures) == 0 {
		return "", errors.New("bambu_camera_rtsp_probe_failed: no RTSP candidates configured")
	}
	return "", fmt.Errorf("bambu_camera_rtsp_probe_failed: %s", strings.Join(failures, "; "))
}

func (a CameraAdapter) HelperMJPEGURL(credentials bambustore.BambuLANCredentials) string {
	template := strings.TrimSpace(a.HelperURLTemplate)
	if template == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"{host}", strings.TrimSpace(credentials.Host),
		"{serial}", strings.TrimSpace(credentials.Serial),
		"{name}", url.QueryEscape(strings.TrimSpace(credentials.Name)),
		"{model}", url.QueryEscape(strings.TrimSpace(credentials.Model)),
	)
	return replacer.Replace(template)
}

func RTSPCandidates(credentials bambustore.BambuLANCredentials) ([]string, error) {
	host := strings.TrimSpace(credentials.Host)
	accessCode := strings.TrimSpace(credentials.AccessCode)
	if host == "" {
		return nil, errors.New("bambu camera unavailable: missing bambu host")
	}
	if accessCode == "" {
		return nil, errors.New("bambu camera unavailable: missing bambu access code")
	}

	type candidateShape struct {
		scheme string
		port   string
		path   string
	}
	shapes := []candidateShape{
		{scheme: "rtsp", port: "6000", path: "/streaming/live/1"},
		{scheme: "rtsp", port: "6000", path: "/live"},
		{scheme: "rtsps", port: "6000", path: "/streaming/live/1"},
	}

	out := make([]string, 0, len(shapes))
	seen := make(map[string]struct{}, len(shapes))
	for _, shape := range shapes {
		candidate := (&url.URL{
			Scheme: shape.scheme,
			User:   url.UserPassword("bblp", accessCode),
			Host:   net.JoinHostPort(host, shape.port),
			Path:   shape.path,
		}).String()
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out, nil
}

func ProbeHelperDefault(ctx context.Context, helperURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(helperURL))
	if err != nil {
		return err
	}
	address := strings.TrimSpace(parsed.Host)
	if address == "" {
		return errors.New("bambu camera helper probe missing host")
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func ProbeRTSPCandidateDefault(ctx context.Context, candidate string) error {
	ffprobePath, err := exec.LookPath("ffprobe")
	if err == nil {
		requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(
			requestCtx,
			ffprobePath,
			"-v", "error",
			"-rtsp_transport", "tcp",
			"-rw_timeout", "3000000",
			"-i", candidate,
			"-show_streams",
			"-of", "compact",
		)
		output, probeErr := cmd.CombinedOutput()
		if probeErr == nil {
			return nil
		}
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return errors.New(trimmed)
		}
		return probeErr
	}

	parsed, err := url.Parse(candidate)
	if err != nil {
		return err
	}
	address := strings.TrimSpace(parsed.Host)
	if address == "" {
		return errors.New("bambu camera candidate missing host")
	}
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func SanitizeCameraURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	if parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
	}
	return parsed.String()
}

func OpenManagedMJPEGReader(ctx context.Context, handle bambucamera.Handle) (io.ReadCloser, error) {
	session, err := bambucamera.OpenSession(handle)
	if err != nil {
		return nil, err
	}
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		defer session.Close()

		for {
			frame, frameErr := bambucamera.ReadJPEGFrame(ctx, session)
			if frameErr != nil {
				switch {
				case errors.Is(frameErr, io.EOF):
					_ = pipeWriter.Close()
				default:
					_ = pipeWriter.CloseWithError(frameErr)
				}
				return
			}

			frameHeader := fmt.Sprintf("--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(frame))
			if _, err := pipeWriter.Write([]byte(frameHeader)); err != nil {
				return
			}
			if _, err := pipeWriter.Write(frame); err != nil {
				return
			}
			if _, err := pipeWriter.Write([]byte("\r\n")); err != nil {
				return
			}
		}
	}()
	return pipeReader, nil
}

func FetchManagedSnapshot(ctx context.Context, handle bambucamera.Handle) ([]byte, error) {
	session, err := bambucamera.OpenSession(handle)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	imageBytes, err := bambucamera.ReadJPEGFrame(ctx, session)
	if err != nil {
		return nil, err
	}
	if len(imageBytes) == 0 {
		return nil, errors.New("bambu snapshot failed: empty image output")
	}
	return imageBytes, nil
}

func unsupportedCapability(reason string) printeradapter.CameraCapability {
	return printeradapter.CameraCapability{
		Available:         false,
		Mode:              printeradapter.CameraModeUnsupported,
		ReasonUnavailable: strings.TrimSpace(reason),
	}
}

func (a CameraAdapter) parsePrinterID(endpointURL string) (string, error) {
	if a.ParsePrinterID == nil {
		return "", errors.New("bambu camera adapter is missing printer id parser")
	}
	return a.ParsePrinterID(endpointURL)
}

func (a CameraAdapter) resolveCredentials(ctx context.Context, printerID string) (bambustore.BambuLANCredentials, error) {
	if a.ResolveCredentials == nil {
		return bambustore.BambuLANCredentials{}, errors.New("bambu camera adapter is missing credential resolver")
	}
	return a.ResolveCredentials(ctx, printerID)
}

func (a CameraAdapter) internalContractURL(printerID string, resource string) (string, error) {
	if a.InternalContractURL == nil {
		return "", errors.New("bambu camera adapter is missing internal contract url resolver")
	}
	return a.InternalContractURL(printerID, resource)
}

func (a CameraAdapter) openHTTPReader(ctx context.Context, targetURL string, defaultContentType string) (io.ReadCloser, string, error) {
	if a.OpenHTTPReader == nil {
		return nil, "", errors.New("bambu camera adapter is missing HTTP reader opener")
	}
	return a.OpenHTTPReader(ctx, targetURL, defaultContentType)
}

func (a CameraAdapter) openFFmpegReader(ctx context.Context, inputURL string, snapshot bool) (io.ReadCloser, string, error) {
	if a.OpenFFmpegReader == nil {
		return nil, "", errors.New("bambu camera adapter is missing ffmpeg reader opener")
	}
	return a.OpenFFmpegReader(ctx, inputURL, snapshot)
}

func (a CameraAdapter) openManagedRuntimeReader(ctx context.Context, handle bambucamera.Handle) (io.ReadCloser, error) {
	if a.OpenManagedRuntimeReader != nil {
		return a.OpenManagedRuntimeReader(ctx, handle)
	}
	return OpenManagedMJPEGReader(ctx, handle)
}

func (a CameraAdapter) fetchManagedRuntimeSnapshot(ctx context.Context, handle bambucamera.Handle) ([]byte, error) {
	if a.FetchManagedRuntimeSnapshot != nil {
		return a.FetchManagedRuntimeSnapshot(ctx, handle)
	}
	return FetchManagedSnapshot(ctx, handle)
}

func (a CameraAdapter) helperProber(ctx context.Context, helperURL string) error {
	if a.HelperProber != nil {
		return a.HelperProber(ctx, helperURL)
	}
	return ProbeHelperDefault(ctx, helperURL)
}

func (a CameraAdapter) candidateProber(ctx context.Context, candidate string) error {
	if a.CandidateProber != nil {
		return a.CandidateProber(ctx, candidate)
	}
	return ProbeRTSPCandidateDefault(ctx, candidate)
}
