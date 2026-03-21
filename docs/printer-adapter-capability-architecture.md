# Printer Adapter Capability Architecture

## Purpose

This document defines the structural direction for printer support in `edge-agent`.

PrintFarmHQ wants broad printer support without turning every feature into a vendor-specific special case. The correct approach is:
- one canonical capability contract
- adapter-owned execution
- printer-family-specific fallbacks only where necessary

## Canonical Capability Model

Initial capability groups:
- `camera`
- `print_lifecycle`
- `light`
- `filament`

Each capability should report:
- `available`
- `mode` or transport
- supported actions
- prerequisite or unavailable reason

For `camera`, the minimum normalized modes are:
- `live_stream`
- `snapshot_poll`
- `unsupported`

## Package Layout

Adapter code should live under:
- `edge-agent/internal/printeradapter/`

Planned structure:
- `edge-agent/internal/printeradapter/contracts.go`
- `edge-agent/internal/printeradapter/registry.go`
- `edge-agent/internal/printeradapter/moonraker/`
- `edge-agent/internal/printeradapter/moonraker/snapmaker/`
- `edge-agent/internal/printeradapter/bambu/`

Reasoning:
- keeps adapter contracts out of the `cmd/edge-agent` monolith
- gives each adapter family a clean implementation boundary
- allows printer-family fallbacks such as Snapmaker to live under the broader Moonraker family instead of becoming top-level vendor sprawl

## Ownership Boundaries

### SaaS

SaaS is responsible for:
- authorization
- session lifecycle
- operator-facing payloads
- vendor-independent UI contracts

SaaS is not responsible for:
- vendor-specific camera transport details
- vendor-specific command implementation
- local printer credential handling

### edge-agent

`edge-agent` is responsible for:
- capability detection
- local camera acquisition
- local command execution
- vendor-specific helper usage
- truthful capability reporting

## Adapter Rules

### Rule 1: Generic first

Always try the standard adapter path first.

Examples:
- Moonraker camera:
  1. `server/webcams/list` with `stream_url`
  2. `server/webcams/list` with `snapshot_url`

### Rule 2: Printer-family fallback second

If a printer does not expose the standard adapter path, add a narrow fallback under the same adapter family.

Examples:
- Stock Snapmaker U1 under the Moonraker family:
  - use `server/files/camera/monitor.jpg?ts=<now>`
  - treat camera as `snapshot_poll`
  - keep the camera pipeline alive with `camera.start_monitor` while the snapshot session is active
  - if `device_power` is unavailable but Moonraker exposes `led cavity_led` (or another single LED object), treat light control as supported through `SET_LED`
- Bambu P1/P1S:
  - prefer an `edge-agent`-owned local runtime that exposes a stable loopback MJPEG contract
  - do not treat blind `:322` RTSP probing as a default supported path
  - directly tested support currently exists only for `P1S`
  - treat camera as `live_stream`

### Rule 3: Truth over symmetry

Do not pretend all printers support the same level of fidelity.

If a printer only supports snapshots, report `snapshot_poll`.
If it has no stable source, report `unsupported`.

## Adapter Interfaces

Use a small core interface plus capability-specific interfaces rather than one giant mandatory adapter surface.

### Core adapter

Every adapter must implement:
- `Key() string`
- `Family() string`
- `FetchRuntimeSnapshot(ctx, binding) (RuntimeSnapshot, error)`

### Camera capability

Adapters that support camera must implement:
- `DescribeCamera(ctx, binding, snapshot) (CameraCapability, error)`
- `OpenCameraStream(ctx, binding) (CameraStream, error)`
- `FetchCameraSnapshot(ctx, binding) ([]byte, error)`

### Print lifecycle capability

Adapters that support lifecycle control must implement:
- `StartPrint(ctx, binding, req) error`
- `PausePrint(ctx, binding) error`
- `ResumePrint(ctx, binding) error`
- `StopPrint(ctx, binding) error`

### Light capability

Adapters that support printer lighting must implement:
- `SetLight(ctx, binding, on bool) error`

### Filament capability

Adapters that support assisted filament actions must implement:
- `LoadFilament(ctx, binding) error`
- `UnloadFilament(ctx, binding) error`

### Command description

Capability-aware adapters should also implement:
- `DescribeCommands(ctx, binding, snapshot) (CommandCatalog, error)`

This keeps SaaS and frontend reading from one normalized command/capability model while the execution remains adapter-owned.

## Camera Slice

Camera is the first migration slice because it already demonstrates the need for multiple capability levels.

### `live_stream`

Use when the adapter can expose a stable live feed:
- standard Moonraker MJPEG/stream URL
- Bambu helper-backed MJPEG

### `snapshot_poll`

Use when the adapter can only provide repeated still images:
- Snapmaker U1 `monitor.jpg` polling

### `unsupported`

Use when no truthful or stable camera source exists.

## Command Migration Follow-On

After camera, move these behind the same adapter model:
- `start`
- `stop`
- `pause`
- `resume`
- `light_on`
- `light_off`
- `home_axes`
- `jog_motion`
- `jog_motion_batch`
- `set_fan_enabled`
- `set_nozzle_temperature`
- `set_bed_temperature`
- `load_filament`
- `unload_filament`

The same principles apply:
- normalized capability surface
- adapter-owned execution
- truthful unavailable reasons

For the current Bambu slice specifically:
- temperatures and fan read-state come from local MQTT runtime telemetry
- motion/home and fan writes route through local MQTT `gcode_line`
- the SaaS-side Print Jobs `Control` panel is Bambu-only until equivalent truthfully normalized contracts exist for other adapters

## Implementation Expectations

- Keep capability logic readable and centralized.
- Avoid scattering vendor checks through unrelated code paths.
- Add targeted tests per adapter behavior and per fallback.
- Update docs when a new printer-family fallback becomes part of the supported path.
