package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	bambucamera "printfarmhq/edge-agent/internal/bambu/cameraruntime"
	bambustore "printfarmhq/edge-agent/internal/store"
)

const (
	bambuLANFileControlListInfo = 0x0001
	bambuLANFileControlDelete   = 0x0003
)

type bambuLANControlModelFile struct {
	Name       string
	Path       string
	SizeBytes  int64
	ModifiedAt *time.Time
}

type bambuLANControlDeleteTarget struct {
	Path string
	Name string
}

type bambuLANDeleteDescriptor struct {
	PrimaryFTPSPath    string
	CompanionFTPSPaths []string
	ControlDeletePath  string
	ControlDeleteName  string
}

type bambuLANFileControlReply struct {
	Result int
	Reply  map[string]any
}

type bambuLANFileControlEnvelope struct {
	CmdType  int            `json:"cmdtype"`
	Sequence int64          `json:"sequence"`
	Result   *int           `json:"result,omitempty"`
	Reply    map[string]any `json:"reply,omitempty"`
	Notify   map[string]any `json:"notify,omitempty"`
}

var ensureBambuLANPluginLibrary = defaultEnsureBambuLANPluginLibrary
var listBambuLANControlModelFiles = defaultListBambuLANControlModelFiles
var deleteBambuLANControlFiles = defaultDeleteBambuLANControlFiles

func defaultEnsureBambuLANPluginLibrary(ctx context.Context, stateDir string) (string, error) {
	manager := bambucamera.NewManager(stateDir, runExternalCommand)
	_, pluginLibraryPath, err := manager.EnsurePluginBundle(ctx)
	if err != nil {
		return "", err
	}
	return pluginLibraryPath, nil
}

func defaultListBambuLANControlModelFiles(
	ctx context.Context,
	pluginLibraryPath string,
	credentials bambustore.BambuLANCredentials,
) ([]bambuLANControlModelFile, error) {
	reply, err := executeBambuLANFileControlRequest(
		ctx,
		pluginLibraryPath,
		credentials,
		bambuLANFileControlListInfo,
		map[string]any{
			"type":        "model",
			"storage":     "internal",
			"api_version": 2,
			"notify":      "DETAIL",
		},
	)
	if err != nil {
		return nil, err
	}
	rawFiles, ok := reply.Reply["file_lists"].([]any)
	if !ok {
		return nil, errors.New("bambu file control list response missing file_lists")
	}
	files := make([]bambuLANControlModelFile, 0, len(rawFiles))
	for _, rawFile := range rawFiles {
		item, ok := rawFile.(map[string]any)
		if !ok {
			continue
		}
		name := strings.TrimSpace(stringFromAny(item["name"]))
		path := strings.TrimSpace(stringFromAny(item["path"]))
		if name == "" && path == "" {
			continue
		}
		sizeBytes := int64(numberFromAny(item["size"]))
		modifiedAt := parseUnixSecondsPointer(numberFromAny(item["time"]))
		files = append(files, bambuLANControlModelFile{
			Name:       name,
			Path:       path,
			SizeBytes:  sizeBytes,
			ModifiedAt: modifiedAt,
		})
	}
	return files, nil
}

func defaultDeleteBambuLANControlFiles(
	ctx context.Context,
	pluginLibraryPath string,
	credentials bambustore.BambuLANCredentials,
	targets []bambuLANControlDeleteTarget,
) error {
	if len(targets) == 0 {
		return nil
	}
	pathSet := make(map[string]struct{}, len(targets))
	nameSet := make(map[string]struct{}, len(targets))
	paths := make([]any, 0, len(targets))
	names := make([]any, 0, len(targets))
	for _, target := range targets {
		if trimmedPath := strings.TrimSpace(target.Path); trimmedPath != "" {
			if _, ok := pathSet[trimmedPath]; ok {
				continue
			}
			pathSet[trimmedPath] = struct{}{}
			paths = append(paths, trimmedPath)
			continue
		}
		if trimmedName := strings.TrimSpace(target.Name); trimmedName != "" {
			if _, ok := nameSet[trimmedName]; ok {
				continue
			}
			nameSet[trimmedName] = struct{}{}
			names = append(names, trimmedName)
		}
	}
	if len(paths) > 0 {
		if _, err := executeBambuLANFileControlRequest(
			ctx,
			pluginLibraryPath,
			credentials,
			bambuLANFileControlDelete,
			map[string]any{"paths": paths},
		); err != nil {
			return err
		}
	}
	if len(names) > 0 {
		if _, err := executeBambuLANFileControlRequest(
			ctx,
			pluginLibraryPath,
			credentials,
			bambuLANFileControlDelete,
			map[string]any{"delete": names},
		); err != nil {
			return err
		}
	}
	return nil
}

func executeBambuLANFileControlRequest(
	ctx context.Context,
	pluginLibraryPath string,
	credentials bambustore.BambuLANCredentials,
	commandType int,
	req map[string]any,
) (bambuLANFileControlReply, error) {
	host := strings.TrimSpace(credentials.Host)
	accessCode := strings.TrimSpace(credentials.AccessCode)
	if pluginLibraryPath == "" {
		return bambuLANFileControlReply{}, errors.New("validation_error: missing bambu plugin library path")
	}
	if host == "" || accessCode == "" {
		return bambuLANFileControlReply{}, errors.New("validation_error: missing bambu control credentials")
	}

	session, err := bambucamera.OpenControlSession(pluginLibraryPath, host, accessCode)
	if err != nil {
		return bambuLANFileControlReply{}, err
	}
	defer session.Close()

	sequence := time.Now().UnixNano()
	payload, err := json.Marshal(map[string]any{
		"cmdtype":  commandType,
		"sequence": sequence,
		"req":      req,
	})
	if err != nil {
		return bambuLANFileControlReply{}, fmt.Errorf("marshal bambu file control payload: %w", err)
	}
	if err := session.SendMessage(payload); err != nil {
		return bambuLANFileControlReply{}, err
	}

	for {
		if err := ctx.Err(); err != nil {
			return bambuLANFileControlReply{}, err
		}
		rawMessage, err := session.ReadMessage()
		switch {
		case err == nil:
		case bambucamera.IsWouldBlock(err):
			time.Sleep(100 * time.Millisecond)
			continue
		case bambucamera.IsStreamEnd(err):
			return bambuLANFileControlReply{}, errors.New("bambu file control stream ended before reply")
		default:
			return bambuLANFileControlReply{}, err
		}
		if len(rawMessage) == 0 {
			continue
		}
		envelope, err := parseBambuLANFileControlEnvelope(rawMessage)
		if err != nil {
			continue
		}
		if envelope.Result == nil || envelope.Sequence != sequence {
			continue
		}
		if *envelope.Result != 0 {
			return bambuLANFileControlReply{}, fmt.Errorf(
				"bambu file control request failed: cmd=%d result=%d",
				commandType,
				*envelope.Result,
			)
		}
		return bambuLANFileControlReply{
			Result: *envelope.Result,
			Reply:  envelope.Reply,
		}, nil
	}
}

func parseBambuLANFileControlEnvelope(raw []byte) (bambuLANFileControlEnvelope, error) {
	jsonPayload := raw
	if separator := bytes.Index(raw, []byte("\n\n")); separator >= 0 {
		jsonPayload = raw[:separator]
	}
	var envelope bambuLANFileControlEnvelope
	if err := json.Unmarshal(jsonPayload, &envelope); err != nil {
		return bambuLANFileControlEnvelope{}, err
	}
	return envelope, nil
}

func numberFromAny(raw any) float64 {
	switch value := raw.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case int32:
		return float64(value)
	case json.Number:
		floatValue, _ := value.Float64()
		return floatValue
	default:
		return 0
	}
}

func (a *agent) enrichBambuLANDeleteDescriptorsWithControlTargets(
	ctx context.Context,
	credentials bambustore.BambuLANCredentials,
	files []printerFileEntry,
) []printerFileEntry {
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	pluginLibraryPath, err := ensureBambuLANPluginLibrary(lookupCtx, a.cfg.BambuCameraRuntimeDir)
	if err != nil {
		return files
	}
	controlFiles, err := listBambuLANControlModelFiles(lookupCtx, pluginLibraryPath, credentials)
	if err != nil {
		return files
	}
	lookup := make(map[string]bambuLANControlDeleteTarget, len(controlFiles)*3)
	for _, file := range controlFiles {
		target := bambuLANControlDeleteTarget{
			Path: strings.TrimSpace(file.Path),
			Name: strings.TrimSpace(file.Name),
		}
		for _, candidate := range []string{file.Path, file.Name, filepath.Base(file.Path)} {
			key := normalizeBambuLANControlLookupKey(candidate)
			if key == "" {
				continue
			}
			if _, ok := lookup[key]; !ok {
				lookup[key] = target
			}
		}
	}

	if len(lookup) == 0 {
		return files
	}
	enriched := make([]printerFileEntry, 0, len(files))
	for _, file := range files {
		if file.DeleteDescriptor == nil || strings.EqualFold(strings.TrimSpace(file.Format), ".bbl") {
			enriched = append(enriched, file)
			continue
		}
		matched, ok := matchBambuLANControlDeleteTarget(lookup, file)
		if !ok {
			enriched = append(enriched, file)
			continue
		}
		file.DeleteDescriptor = withBambuLANControlDeleteTarget(file.DeleteDescriptor, matched)
		enriched = append(enriched, file)
	}
	return enriched
}

func normalizeBambuLANControlLookupKey(raw string) string {
	trimmed := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(filepath.Base(trimmed))
}

func matchBambuLANControlDeleteTarget(
	lookup map[string]bambuLANControlDeleteTarget,
	file printerFileEntry,
) (bambuLANControlDeleteTarget, bool) {
	candidates := []string{
		file.Path,
		file.DisplayPath,
		file.DisplayName,
		filepath.Base(file.Path),
		filepath.Base(file.DisplayPath),
		filepath.Base(file.DisplayName),
	}
	for _, candidate := range candidates {
		key := normalizeBambuLANControlLookupKey(candidate)
		if key == "" {
			continue
		}
		if matched, ok := lookup[key]; ok {
			return matched, true
		}
	}
	return bambuLANControlDeleteTarget{}, false
}
