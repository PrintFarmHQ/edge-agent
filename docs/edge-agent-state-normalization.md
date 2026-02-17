# Edge-Agent State Normalization

## Purpose

`edge-agent` is the normalization layer between provider-specific printer telemetry and SaaS runtime state.

It must always push canonical runtime states, regardless of provider.

## Canonical Runtime Contract

Agent state pushes use only:

- `current_printer_state`: `idle | queued | printing | paused | error`
- `current_job_state`: `pending | printing | completed | failed | canceled`

These values are provider-agnostic and stable.

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

## Discovery vs Runtime

Discovery inventory uses connectivity statuses (`reachable`, `unreachable`, `lost`) and is separate from runtime printer/job state.
