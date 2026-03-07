# Edge-Agent State Normalization

## Purpose

`edge-agent` is the normalization layer between provider-specific printer telemetry and SaaS runtime state.

It must always push canonical runtime states, regardless of provider.

## Canonical Runtime Contract

Agent state pushes use only:

- `current_printer_state`: `idle | queued | printing | paused | error`
- `current_job_state`: `pending | printing | completed | failed | canceled`

These values are provider-agnostic and stable.

Auxiliary state fields can remain provider-specific when they do not affect the canonical
runtime state machine. `manual_intervention` is one of those fields: it should be sent as a
lowercase snake_case token such as `canceled`, `stopped`, `hms_alert`, or `print_error`.
SaaS may assign special behavior to `canceled` and `stopped`, but it must preserve other
vendor-specific tokens instead of rejecting the whole state batch.

## Provider Mapping

### Moonraker / Klipper

- `printing` -> `printing / printing`
- `paused` -> `paused / printing`
- `queued` -> `queued / pending`
- `cancelled` / `canceled` -> `idle / canceled`
- `error` -> `error / failed`
- unknown states -> `idle / pending`

### Bambu Cloud

- `PRINTING` / `RUNNING` / `IN_PROGRESS` -> `printing / printing`
- `QUEUED` / `PENDING` / `PREPARING` / `STARTING` / `HEATING` / `SLICING` -> `queued / pending`
- `PAUSED` / `PAUSING` -> `paused / printing`
- `ERROR` / `FAILED` / `FAULT` -> `error / failed`
- `CANCELED` / `CANCELLED` -> `idle / canceled`
- `ACTIVE` / `IDLE` / `READY` / `STANDBY` / `COMPLETED` / `FINISHED` -> `idle / completed`

For runtime snapshots, if a Bambu cloud device is offline, the agent returns connectivity failure for that binding so SaaS can project printer offline.

### Bambu LAN MQTT

- `RUNNING` / `PRINTING` -> `printing / printing`
- `PAUSE` / `PAUSED` -> `paused / printing`
- `PREPARE` / `PREPARING` / `SLICING` / `DOWNLOADING` -> `queued / pending`
- `FAILED` / `ERROR` -> `error / failed`, unless the payload also says the printer is otherwise idle (`print_type=idle`, `task_id=0`, empty `gcode_file`, and no HMS/print_error). In that stale-idle case, normalize to `idle / pending`.
- `FINISH` / `FINISHED` -> `idle / completed`
- `IDLE` -> `idle / pending`, unless the printer has just transitioned from an active PrintFarm-managed print, in which case edge-agent emits a one-shot `completed` job state so SaaS can activate cleanup confirmation.
- When edge-agent restarts during an active PrintFarm-managed print, it rehydrates the active desired job/plate identity onto the resumed active snapshot so SaaS can keep the correct active plate context, clear false stalled-start warnings, and continue showing live progress after reconnect.
- For adopted Bambu printers, edge-agent uses a dedicated short live-runtime timeout for local MQTT snapshots. It tolerates one transient live MQTT runtime miss by falling back to the recent LAN discovery cache. After 2 consecutive live runtime connectivity failures, it stops trusting discovery cache and pushes `connectivity_error` so SaaS can mark the printer unreachable in near real time.
- While a Bambu `print` action is still inflight, transient live-runtime connectivity misses are suppressed instead of downgrading the printer to `unreachable`, because printers can briefly stop answering snapshot reads during upload/start preparation even though the print is starting successfully.
- After a Bambu printer accepts `project_file`, edge-agent immediately projects `queued / pending` with the target job/plate identity before final verification completes. That allows SaaS to treat calibration/preparation as a legitimate in-progress start instead of a stalled start that never began.

## Discovery vs Runtime

Discovery inventory uses connectivity statuses (`reachable`, `unreachable`, `lost`) and is separate from runtime printer/job state.
