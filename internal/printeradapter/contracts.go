package printeradapter

import (
	"context"
	"io"
	"time"
)

type Binding struct {
	PrinterID     int
	AdapterFamily string
	EndpointURL   string
}

type RuntimeSnapshot struct {
	PrinterState      string
	JobState          string
	ProgressPct       *float64
	RemainingSeconds  *float64
	TelemetrySource   string
	DetectedName      string
	DetectedModelHint string
}

type CameraMode string

const (
	CameraModeUnsupported  CameraMode = "unsupported"
	CameraModeSnapshotPoll CameraMode = "snapshot_poll"
	CameraModeLiveStream   CameraMode = "live_stream"
)

type CameraCapability struct {
	Available         bool
	Mode              CameraMode
	Transport         string
	SupportsLive      bool
	SupportsSnapshot  bool
	RefreshInterval   time.Duration
	ReasonUnavailable string
}

type CameraStream struct {
	Reader      io.ReadCloser
	ContentType string
}

type ActionState struct {
	Supported         bool
	Enabled           bool
	Label             string
	ReasonUnavailable string
}

type CommandCatalog struct {
	PrintStart       ActionState
	PrintPause       ActionState
	PrintResume      ActionState
	PrintStop        ActionState
	LightOn          ActionState
	LightOff         ActionState
	LoadFilament     ActionState
	UnloadFilament   ActionState
}

type StartPrintRequest struct {
	ArtifactURL     string
	ChecksumSHA256  string
	JobID           string
	PlateID         int
}

type CoreAdapter interface {
	Key() string
	Family() string
	FetchRuntimeSnapshot(ctx context.Context, binding Binding) (RuntimeSnapshot, error)
}

type CameraAdapter interface {
	DescribeCamera(ctx context.Context, binding Binding, snapshot RuntimeSnapshot) (CameraCapability, error)
	OpenCameraStream(ctx context.Context, binding Binding) (CameraStream, error)
	FetchCameraSnapshot(ctx context.Context, binding Binding) ([]byte, error)
}

type PrintLifecycleAdapter interface {
	StartPrint(ctx context.Context, binding Binding, req StartPrintRequest) error
	PausePrint(ctx context.Context, binding Binding) error
	ResumePrint(ctx context.Context, binding Binding) error
	StopPrint(ctx context.Context, binding Binding) error
}

type LightAdapter interface {
	SetLight(ctx context.Context, binding Binding, on bool) error
}

type FilamentAdapter interface {
	LoadFilament(ctx context.Context, binding Binding) error
	UnloadFilament(ctx context.Context, binding Binding) error
}

type CapabilityAdapter interface {
	CoreAdapter
	DescribeCommands(ctx context.Context, binding Binding, snapshot RuntimeSnapshot) (CommandCatalog, error)
}
