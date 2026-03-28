package snapmaker_u1

import (
	"context"
	"strings"
	"time"

	printeradapter "printfarmhq/edge-agent/internal/printeradapter"
)

const (
	ProfileKey         = "moonraker.snapmaker_u1"
	DisplayName        = "Snapmaker U1"
	DocumentationSlug  = "moonraker-snapmaker-u1"
	HomeRequestTimeout = 45 * time.Second
)

type Adapter struct{}

func (Adapter) Key() string {
	return ProfileKey
}

func (Adapter) Family() string {
	return "moonraker"
}

func (Adapter) DescribeControlSchema(_ context.Context, _ printeradapter.Binding, _ printeradapter.RuntimeSnapshot) (printeradapter.ControlSchema, error) {
	return printeradapter.ControlSchema{
		Sections: []printeradapter.ControlSection{
			{
				ID:    "toolheads",
				Label: "Toolheads",
				Selectors: []printeradapter.ControlSelector{
					{
						ID:    "active_toolhead",
						Label: "Active Toolhead",
						Scope: "toolhead",
						Options: []printeradapter.ControlSelectorOption{
							{ID: "extruder", Label: "T0"},
							{ID: "extruder1", Label: "T1"},
							{ID: "extruder2", Label: "T2"},
							{ID: "extruder3", Label: "T3"},
						},
					},
				},
			},
			{
				ID:    "temperatures",
				Label: "Temperatures",
				Readouts: []printeradapter.ControlReadout{
					{ID: "nozzle", Label: "Nozzle", Scope: "toolhead", Writable: true},
					{ID: "bed", Label: "Bed", Scope: "printer", Writable: true},
					{ID: "chamber", Label: "Chamber", Scope: "printer", Writable: false},
				},
			},
			{
				ID:    "motion",
				Label: "Motion",
				Actions: []printeradapter.ControlAction{
					{ID: "home_axes", Label: "Home", CommandKey: "home_axes"},
					{ID: "jog_motion_batch", Label: "Jog", CommandKey: "jog_motion_batch"},
				},
			},
		},
	}, nil
}

func MatchesModelHint(raw string) bool {
	return strings.Contains(strings.TrimSpace(strings.ToLower(raw)), "snapmaker u1")
}

func BuildHomeScript(axes []string) string {
	needsX := false
	needsY := false
	needsZ := false
	if len(axes) == 0 {
		needsX = true
		needsY = true
		needsZ = true
	}
	for _, axis := range axes {
		switch strings.TrimSpace(strings.ToUpper(axis)) {
		case "X":
			needsX = true
		case "Y":
			needsY = true
		case "Z":
			needsZ = true
		}
	}

	lines := make([]string, 0, 2)
	switch {
	case needsX && needsY:
		lines = append(lines, "_HOMING_PRECISE_COREXY_ADVANCED")
	case needsX:
		lines = append(lines, "SENSORLESS_HOME_X")
	case needsY:
		lines = append(lines, "SENSORLESS_HOME_Y")
	}
	if needsZ {
		lines = append(lines, "SENSORLESS_HOME_Z")
	}
	return strings.Join(lines, "\n")
}
