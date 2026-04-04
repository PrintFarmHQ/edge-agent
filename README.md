# Edge Agent Local Workflow

Binary-first workflow (no installer, no Docker runtime).

## Commands

```bash
cd edge-agent
make build
make dev EDGE_API_KEY=pfh_edge_xxx
make down
```

- `make build`: refreshes embedded web UI assets and compiles `bin/edge-agent`.
- `make dev`: rebuilds then runs in foreground with logs attached (defaults to `EDGE_AGENT_FLAGS=--klipper`).
- `make down`: kills all local `edge-agent` processes by name.
- Local builds now default to `CGO_ENABLED=1` because the in-process Bambu camera runtime uses `cgo` to call the pinned native plugin libraries.
- Edge-managed printer recovery now reuses discovery to recover moved printer endpoints:
  - Moonraker/Klipper recovery can probe the bound endpoint plus subnet targets and rotate the live binding only when the same printer MAC is rediscovered.
  - Bambu recovery keeps the serial binding stable and refreshes the resolved LAN host from new discovery evidence when the same serial is rediscovered.
  - recovery must not stop a manual printer-side action; if SaaS does not currently own an active print lifecycle, edge-agent now treats printer-side activity as external authority instead of converging it back to `idle`.

Optional test commands:

```bash
make test
```

- Edge-managed print start now uses content-addressed printer-side filenames and reuses an existing printer-local artifact when the adapter-specific probe proves the remote bytes already match.
- Reuse is supported for:
  - Moonraker via file metadata plus remote SHA256 verification
  - adopted Bambu LAN printers via FTPS `SIZE` plus streamed MD5 verification
- Edge-managed printer files can now be refreshed and reported back to SaaS for the Print Jobs printer side panel:
  - Moonraker lists printable files from the `gcodes` root and supports start/delete of existing files.
  - adopted Bambu LAN mirrors the printer SD-card view using `.3mf` / `.gcode` entries backed by `/cache`, hides paired `.bbl` internals from the UI, starts existing cache-backed files by computing remote MD5 before `project_file`, and now enriches delete actions with the same native Bambu file-control identity the official client uses so delete can update the printer-side SD-card index before FTPS cleanup/verification runs.

## Dev defaults

- Backend health check: `http://localhost:8000/health`
- Control plane URL for `make dev`: `http://localhost:8000`
- Local HTTP bind address: `127.0.0.1:18090`

Override example:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx DEV_CONTROL_PLANE_URL=http://localhost:8000 SETUP_BIND_ADDR=127.0.0.1:18100 EDGE_AGENT_FLAGS="--klipper"
```

Bambu LAN example:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx EDGE_AGENT_FLAGS="--klipper --bambu"
```

Run with both Klipper and Bambu discovery while connecting to SaaS:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx DEV_CONTROL_PLANE_URL=http://localhost:8000 EDGE_AGENT_FLAGS="--klipper --bambu"
```

- `EDGE_API_KEY` maps to `--api-key` for SaaS auth.
- `DEV_CONTROL_PLANE_URL` maps to `--control-plane-url`.

## Local Web UI

- `edge-agent` now starts a built-in read-only local dashboard automatically on its own random loopback port.
- Your existing `make dev ...` command does not need additional flags or parameters.
- On startup, `edge-agent` prints a terminal banner first, including the exact UI URL and the published dashboard port.
- If `edge-agent` is not connected to PrintFarmHQ SaaS at startup, it automatically opens the local dashboard in the default browser.
- The fixed setup server remains on `SETUP_BIND_ADDR`; opening `/` on that port redirects to the current UI URL.
- `GET /setup/status` and `GET /health` expose both `local_web_ui_url` and `local_web_ui_port`.
- The dashboard is localhost-only and shows what this `edge-agent` currently sees on the network:
  - reachable idle printers,
  - reachable busy printers,
  - reachable printers in an error state,
  - printers that were recently seen but are now disconnected.
- The UI uses local observation only. It does not expose printer controls or depend on SaaS availability.
- When the agent is not connected to SaaS, the dashboard switches into a connection screen:
  - green badge: connected
  - red badge: not connected
  - yellow badge: renew key
- In the red or yellow states, the dashboard hides printer cards and asks the user to paste a valid API key.
- Manual refresh triggers a local discovery scan through `POST /api/local/observations/scan`.
- The dashboard polls `GET /api/local/observations` for updates.
- Tune the background local scan cadence with `LOCAL_UI_SCAN_INTERVAL_MS` (default `15000`).
- Optional: override the UI listener only if needed with `LOCAL_UI_BIND_ADDR` (default `127.0.0.1:0`).
- Optional: disable automatic browser opening with `EDGE_AGENT_DISABLE_BROWSER_OPEN=1`.

## Current Bambu Status

- Bambu support in `edge-agent` is now LAN-only.
- Bambu mode requires only `--bambu`.
- `edge-agent` does not use Bambu cloud auth or Bambu Connect for discovery, snapshots, or runtime actions.
- Adopted Bambu printers rely on the local LAN credentials store plus LAN transports:
  - local discovery
  - local MQTT for print/control commands
  - FTPS for printer-resident files and print-start artifact reuse
- Bambu camera is now managed internally by `edge-agent`:
  - `edge-agent` owns the local Bambu camera runtime and exposes a loopback-only internal MJPEG contract for its own use.
  - when started with `--bambu`, `edge-agent` preflights the pinned native Bambu plugin bundle before startup continues.
  - the required Bambu plugin bundle is pinned to a specific version and checksum-verified before use.
  - if the pinned plugin bundle is missing or invalid, `edge-agent` repairs it from the official pinned archive into `~/.printfarmhq` instead of following whatever Bambu Studio version is installed locally.
  - if the pinned plugin bundle still cannot be prepared, startup exits with a clear operator-facing error instead of running with a broken Bambu runtime.
  - the same pinned native bundle also backs the native Bambu control tunnel used for printer file-control operations.
  - SaaS still does not connect to `edge-agent` directly; `edge-agent` pulls camera-session work and pushes stream bytes back to the control plane.
  - directly tested Bambu camera support currently exists only for `P1S`.
  - unverified families such as `X1C` must remain truthfully unavailable until they are directly validated and implemented.
- Print Jobs command-center runtime commands are enabled for edge-managed printers:
  - edge-agent now also resolves a printer support profile and publishes metadata such as `profile_key`, `support_tier`, and supported panels so SaaS/frontend can gate UI from a stable contract instead of raw adapter checks.
  - Moonraker supports LED on/off through `device_power`, Snapmaker-style `led <name>` fallback when `device_power` is absent, filament load/unload through `LOAD_FILAMENT` / `UNLOAD_FILAMENT` macros, and the broader `Control` panel through Moonraker object queries plus `printer/gcode/script`.
  - adopted Bambu LAN printers support LED on/off and external-spool load/unload over local MQTT when local credentials are available and the printer is reachable.
  - Moonraker now also pushes live control-status telemetry every second for nozzle/bed plus optional chamber temperatures and writable fan state, and reuses the same buffered `jog_motion_batch` UX as Bambu.
  - the command-center filament button now uses edge-reported `filament_state` plus `filament_action_state`; Moonraker needs a real filament sensor for a trustworthy single-button filament UX, and Bambu prefers `ams.tray_now` active-source detection with command-memory fallback plus `needs_user_confirmation` when load/unload flows still require operator completion on the printer.
  - when a printer rejects a command, edge-agent now summarizes the printer-facing error message before acknowledging it back to SaaS so the UI can show the real reason instead of a huge traceback blob.
- Print start success is verified against Bambu LAN runtime telemetry (`queued`/`printing`) before the action is marked successful.
- To reduce repeated retries on deterministic non-retryable failures, tune:
  - `ACTION_NON_RETRYABLE_COOLDOWN_MS` (default `180000`)
- The completed LAN-first Bambu rollout is tracked in `backlog/todos/done/bambu-start-control-across-saas-edge.md`.

## Docs

- `docs/architecture-overview.md`
- `docs/edge-agent-state-normalization.md`
- `docs/discovery-vs-runtime-state.md`
- `docs/bambu-adoption-behavior.md`
- `docs/local-webui.md`

Direct run is also supported:

```bash
./bin/edge-agent --klipper --control-plane-url="http://localhost:8000" --api-key="pfh_edge_xxx"
```

Direct run with both adapters:

```bash
./bin/edge-agent --klipper --bambu --control-plane-url="http://localhost:8000" --api-key="pfh_edge_xxx"
```

`--saas-api-key` is accepted as an alias for `--api-key`.
