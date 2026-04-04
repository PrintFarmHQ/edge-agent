# Local Web UI

## Purpose

`edge-agent` exposes a built-in read-only local dashboard for operators who want a clean view of what the local agent can currently observe on the network.

The UI is intentionally narrow:
- it shows local observation only,
- it is read-only,
- it runs from the same `edge-agent` binary,
- it does not require any extra service or application.

Exception:
- when the agent is not connected to SaaS, the dashboard exposes a local API-key paste flow so the operator can claim/reconnect the agent without leaving the browser

## Default Access

- URL: randomized loopback URL chosen on startup, using `127.0.0.1:0`
- Startup behavior:
  - `edge-agent` prints a startup banner first, including the exact UI URL and published dashboard port
  - if the agent is not connected to SaaS, `edge-agent` opens that URL in the default browser
  - the fixed setup server root (`/`) redirects to the current UI URL
- Browser targets:
  - Chrome desktop
  - Firefox desktop
- Platform targets:
  - macOS
  - Windows
  - Linux

The UI routes are restricted to loopback clients even if the bind address is overridden.

## Data Contract

The dashboard is powered by `GET /api/local/observations`.

It groups printers into:
- `available`: reachable and idle
- `busy`: reachable and actively printing, calibrating/preparing, queued, or paused
- `error`: reachable and in a locally observed error state
- `recently_disconnected`: not reachable now, but seen reachable within the last 15 minutes of the current process lifetime

The dashboard only shows printers for which this process has local evidence from:
- discovery scans
- runtime snapshots collected by `edge-agent`

It does not project SaaS inventory, desired state, or adoption state into the printer list.

## Connection States

The dashboard shows a control-plane badge with three user-facing states:
- `connected`
  - green
  - the printer dashboard is visible
- `not_connected`
  - red
  - shown when the agent is not connected to SaaS
  - the dashboard asks the user to paste a valid API key
- `renew_key`
  - yellow
  - shown when the current API key was rejected
  - the dashboard asks the user to paste a new API key

When the state is `not_connected` or `renew_key`, the printer board is hidden and the connection panel becomes the primary UI.

## Discovery and Freshness

- `edge-agent` runs a background local scan every `LOCAL_UI_SCAN_INTERVAL_MS` milliseconds.
- The default interval is `15000`.
- The Refresh button triggers an additional local scan.
- Discovery and UI-triggered scans share the same scan lock used by control-plane discovery flows.

## Truthfulness Rules

- Discovery is the main source of reachability.
- Fresh runtime connectivity failures can override stale reachable discovery and move a printer into `recently_disconnected`.
- Fresh runtime snapshots provide richer state details when available.
- Local UI grouping treats canonical `queued`, `printing`, and `paused` states as `busy`.
- Bambu LAN SSDP discovery-only records do not pretend to provide truthful runtime `idle/pending` state; they render as visibility-only until a real runtime snapshot exists.

## Endpoints

- Fixed setup server (`SETUP_BIND_ADDR`)
  - `GET /`
    - redirects to the current local UI URL
  - `GET /health`
    - includes `local_web_ui_url` and `local_web_ui_port`
  - `GET /setup/status`
    - includes `local_web_ui_url` and `local_web_ui_port`
- `POST /setup/claim`
    - used by the local dashboard API-key paste flow
- Dedicated local UI server (random loopback port)
  - `GET /`
    - serves the embedded dashboard
  - `GET /assets/*`
    - serves embedded static assets
  - `GET /api/local/observations`
    - returns the current local observation model
  - `POST /api/local/observations/scan`
    - starts a local scan and returns `202 Accepted`
    - returns `status=in_progress` when another discovery run is already active
  - `GET /api/local/printers/{printer_id}/camera/stream`
    - proxies the configured Moonraker webcam stream for the bound printer
  - `GET /api/local/printers/{printer_id}/camera/snapshot`
    - proxies the configured Moonraker webcam snapshot for the bound printer

## Camera Notes

- The local web UI camera routes remain useful for local diagnostics, but they are no longer the intended SaaS printer-camera transport.
- The SaaS printer camera now relies on a camera-session bridge where `edge-agent` uploads stream bytes to the control plane for inline playback in the printer sheet.
- Camera support is intentionally narrow and truthful:
  - Moonraker webcams are supported through the local proxy.
  - Bambu cameras are served through an `edge-agent`-owned local runtime and internal loopback contract.
  - the Bambu plugin bundle is version-pinned, preflighted on `--bambu` startup, repaired from the official source when missing or invalid, and checksum-verified before `edge-agent` uses it from `~/.printfarmhq`.
  - directly tested Bambu camera support currently exists only for `P1S`.
  - unverified families remain explicitly unavailable instead of pretending to work through blind fallback probes.
  - Unsupported or unreachable camera sources remain explicitly unavailable instead of showing a fake stream.
