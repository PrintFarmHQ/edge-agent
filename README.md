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
  - print start uses Bambu cloud upload + print submit APIs, with MQTT fallback when the cloud print-start endpoint is not available for the account/region.
  - pause/resume/stop use the Bambu cloud MQTT command channel.
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
