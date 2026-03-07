package main

import (
	"encoding/json"
	"testing"
)

func TestBuildBambuMQTTPayloadIncludesParam(t *testing.T) {
	payload, err := buildBambuMQTTPayload("start", map[string]any{
		"file_url":  "https://objects.local/plate.gcode",
		"file_name": "plate.gcode",
		"file_id":   "file-1",
	})
	if err != nil {
		t.Fatalf("buildBambuMQTTPayload failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode payload failed: %v", err)
	}
	printSection, ok := decoded["print"].(map[string]any)
	if !ok {
		t.Fatalf("missing print section: %+v", decoded)
	}
	if printSection["command"] != "start" {
		t.Fatalf("command = %v, want start", printSection["command"])
	}
	param, ok := printSection["param"].(map[string]any)
	if !ok {
		t.Fatalf("missing param section: %+v", printSection)
	}
	if param["file_url"] != "https://objects.local/plate.gcode" {
		t.Fatalf("param file_url = %v, want https://objects.local/plate.gcode", param["file_url"])
	}
	if param["file_name"] != "plate.gcode" {
		t.Fatalf("param file_name = %v, want plate.gcode", param["file_name"])
	}
	if param["file_id"] != "file-1" {
		t.Fatalf("param file_id = %v, want file-1", param["file_id"])
	}
}

func TestBuildBambuMQTTPayloadDropsEmptyParamKeys(t *testing.T) {
	payload, err := buildBambuMQTTPayload("pause", map[string]any{"": "ignored"})
	if err != nil {
		t.Fatalf("buildBambuMQTTPayload failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode payload failed: %v", err)
	}
	printSection, ok := decoded["print"].(map[string]any)
	if !ok {
		t.Fatalf("missing print section: %+v", decoded)
	}
	if _, exists := printSection["param"]; exists {
		t.Fatalf("expected param to be omitted when keys are empty")
	}
}

func TestBuildBambuMQTTPayloadPreservesEmptyStringParam(t *testing.T) {
	payload, err := buildBambuMQTTPayload("pause", "")
	if err != nil {
		t.Fatalf("buildBambuMQTTPayload failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode payload failed: %v", err)
	}
	printSection, ok := decoded["print"].(map[string]any)
	if !ok {
		t.Fatalf("missing print section: %+v", decoded)
	}
	if printSection["param"] != "" {
		t.Fatalf("param = %v, want empty string", printSection["param"])
	}
}
