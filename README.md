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

Optional test commands:

```bash
make test
```

- Edge-managed print start now uses content-addressed printer-side filenames and reuses an existing printer-local artifact when the adapter-specific probe proves the remote bytes already match.
- Reuse is supported for:
  - Moonraker via file metadata plus remote SHA256 verification
  - adopted Bambu LAN printers via FTPS `SIZE` plus streamed MD5 verification

## Dev defaults

- Backend health check: `http://localhost:8000/health`
- Control plane URL for `make dev`: `http://localhost:8000`
- Local HTTP bind address: `127.0.0.1:18090`

Override example:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx DEV_CONTROL_PLANE_URL=http://localhost:8000 SETUP_BIND_ADDR=127.0.0.1:18100 EDGE_AGENT_FLAGS="--klipper"
```

Bambu cloud auth example:

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

- Bambu startup now performs cloud authentication (MFA supported) and persists token material locally in `~/.printfarmhq/bambu/credentials.json`.
- Bambu mode requires only `--bambu`.
- Startup first tries stored token reuse (and refresh token when available). If not valid, it prompts for username/password interactively.
- Password input is treated as secret in terminal sessions and is not echoed back.
- When MFA is required, startup blocks and asks for the code on the interactive console.
- Empty/invalid MFA code (or non-interactive console) makes startup fail with a non-zero exit.
- Bambu cloud devices are discovered through the same discovery inventory pipeline as Klipper and submitted to SaaS on the periodic inventory cadence (default 30s).
- Bambu print lifecycle actions are enabled:
  - adopted LAN print start uses Bambu FTPS upload plus local MQTT `project_file`, and skips upload when the target printer already has the same content-addressed artifact with matching size and MD5.
  - pause/resume/stop prefer the local MQTT command channel when LAN credentials are available, with the legacy cloud path remaining as fallback outside the adopted LAN path.
- Bambu camera is now managed internally by `edge-agent`:
  - `edge-agent` owns the local Bambu camera runtime and exposes a loopback-only internal MJPEG contract for its own use.
  - the required Bambu plugin bundle is pinned to a specific version and checksum-verified before use.
  - if the pinned plugin bundle is missing, `edge-agent` downloads the official archive into `~/.printfarmhq` and uses the cached copy instead of following whatever Bambu Studio version is installed locally.
  - SaaS still does not connect to `edge-agent` directly; `edge-agent` pulls camera-session work and pushes stream bytes back to the control plane.
  - directly tested Bambu camera support currently exists only for `P1S`.
  - unverified families such as `X1C` must remain truthfully unavailable until they are directly validated and implemented.
- Print Jobs command-center runtime commands are enabled for edge-managed printers:
  - Moonraker supports LED on/off through `device_power` and filament load/unload through `LOAD_FILAMENT` / `UNLOAD_FILAMENT` macros when those printer-side capabilities exist.
  - adopted Bambu LAN printers support LED on/off and external-spool load/unload over local MQTT when local credentials are available and the printer is reachable.
  - the command-center filament button now uses edge-reported `filament_state` plus `filament_action_state`; Moonraker needs a real filament sensor for a trustworthy single-button filament UX, and Bambu prefers `ams.tray_now` active-source detection with command-memory fallback plus `needs_user_confirmation` when load/unload flows still require operator completion on the printer.
- MQTT command auth resolves username from the current Bambu access-token claims (`user_id`/`uid`/`sub`) at action time.
- Print start success is verified against Bambu cloud telemetry (`queued`/`printing`) before the action is marked successful.
- If the upload response does not include a printable `file_url`, print-start fails fast with a validation error (no signed-upload-URL guessing).
- Runtime action auth reuses the same persisted token store (`~/.printfarmhq/bambu/credentials.json`) and re-initializes auth on token expiry/rejection.
- If Bambu cloud API paths differ by region/account, override with:
  - `BAMBU_CLOUD_UPLOAD_PATH` (default `/v1/iot-service/api/user/upload`)
  - `BAMBU_CLOUD_PRINT_PATH` (default `/v1/iot-service/api/user/print`)
- To reduce repeated retries on deterministic non-retryable failures, tune:
  - `ACTION_NON_RETRYABLE_COOLDOWN_MS` (default `180000`)
- Cloud auth/MFA + cloud print lifecycle rollout is tracked in `backlog/todo/p0.md`.

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
