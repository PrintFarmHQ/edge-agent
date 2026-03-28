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

type PanelKey string

const (
	PanelStatus   PanelKey = "status"
	PanelQueue    PanelKey = "queue"
	PanelCamera   PanelKey = "camera"
	PanelControls PanelKey = "controls"
)

type SupportTier string

const (
	SupportTierOfficial     SupportTier = "official"
	SupportTierCommunity    SupportTier = "community"
	SupportTierExperimental SupportTier = "experimental"
	SupportTierGeneric      SupportTier = "generic"
	SupportTierUnsupported  SupportTier = "unsupported"
)

type ProfileDescriptor struct {
	Key               string
	Family            string
	DisplayName       string
	SupportTier       SupportTier
	SupportedPanels   []PanelKey
	UnsupportedReason string
	DocumentationSlug string
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

type ControlSelectorOption struct {
	ID    string
	Label string
}

type ControlSelector struct {
	ID      string
	Label   string
	Scope   string
	Options []ControlSelectorOption
}

type ControlReadout struct {
	ID       string
	Label    string
	Scope    string
	Writable bool
}

type ControlAction struct {
	ID         string
	Label      string
	CommandKey string
}

type ControlSection struct {
	ID        string
	Label     string
	Selectors []ControlSelector
	Readouts  []ControlReadout
	Actions   []ControlAction
}

type ControlSchema struct {
	Sections []ControlSection
}

type MaterialSystemDescriptor struct {
	ID        string
	Kind      string
	Label     string
	SlotCount int
}

type CommandCatalog struct {
	PrintStart     ActionState
	PrintPause     ActionState
	PrintResume    ActionState
	PrintStop      ActionState
	LightOn        ActionState
	LightOff       ActionState
	LoadFilament   ActionState
	UnloadFilament ActionState
}

type StartPrintRequest struct {
	ArtifactURL    string
	ChecksumSHA256 string
	JobID          string
	PlateID        int
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

type ControlAdapter interface {
	DescribeControlSchema(ctx context.Context, binding Binding, snapshot RuntimeSnapshot) (ControlSchema, error)
}

type MaterialSystemAdapter interface {
	DescribeMaterialSystems(ctx context.Context, binding Binding, snapshot RuntimeSnapshot) ([]MaterialSystemDescriptor, error)
}

type CapabilityAdapter interface {
	CoreAdapter
	DescribeCommands(ctx context.Context, binding Binding, snapshot RuntimeSnapshot) (CommandCatalog, error)
}
