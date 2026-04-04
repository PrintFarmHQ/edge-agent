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
lowercase snake_case token such as `paused`, `stopped`, `canceled`, `hms_alert`, or `print_error`.
SaaS may assign special behavior to `paused`, `stopped`, and `canceled`, but it must preserve other
vendor-specific tokens instead of rejecting the whole state batch.

`command_capabilities` is another auxiliary field. It does not alter the canonical
printer/job runtime state, but it does tell SaaS which command-center controls are
currently supported by the selected printer and, when applicable, the last known LED state,
filament state, and filament action progress.

When a printer rejects an action, `edge-agent` should prefer a concise printer-facing
message in `last_error_message` and printer-command acknowledgements, instead of forwarding
full transport wrappers or vendor tracebacks to SaaS/UI. Full raw errors may still remain
in edge audit logs for debugging.

Supported adapters may also have a separate high-frequency control-status telemetry path.
That path is for operator-facing live control data such as temperatures and fan states,
not for the canonical printer/job runtime state machine.

## Convergence Safety Rule

When SaaS does not actively own a printer/job lifecycle, it should not publish a default
`idle` desired target for that printer. In that state, edge-agent must treat printer-side
activity as authoritative external activity, not as drift to correct by stopping the printer.

When edge-agent detects a printer-side manual intervention for a SaaS-owned lifecycle, it should
report that through `manual_intervention` and yield convergence until SaaS issues a newer explicit
operator intent:

- `paused`: do not auto-resume
- `stopped`: do not auto-restart
- `canceled`: do not auto-restart

For edge-managed pause, resume, and stop specifically, SaaS operator actions should be delivered as
explicit printer commands rather than inferred from desired-state reconciliation. Desired state still
tracks ownership/runtime intent, but edge-agent should not autonomously emit pause/resume/stop from
that intent alone.

## Provider Mapping

### Moonraker / Klipper

- `printing` -> `printing / printing`
- `paused` -> `paused / printing`
- `queued` -> `queued / pending`
- `cancelled` / `canceled` -> `idle / canceled`
- `error` -> `error / failed`
- unknown states -> `idle / pending`
- command capabilities are discovered separately from runtime state:
  - LED support comes from Moonraker `device_power`
  - filament load/unload support comes from the presence of `gcode_macro LOAD_FILAMENT` and `gcode_macro UNLOAD_FILAMENT`
  - a truthful single-button filament UX additionally requires a real `filament_switch_sensor` or `filament_motion_sensor`
  - filament action progress can transiently report `loading` or `unloading`; if the sensor never converges, edge-agent falls back to `unknown`
 - control-status telemetry is now also reported separately from canonical runtime state:
   - nozzle and optional bed/chamber temperatures come from Moonraker object queries
   - writable fan read-state comes from standard `fan` and `fan_generic` objects
   - motion/home and heater/fan writes use Moonraker `printer/gcode/script`
   - edge-agent pushes Moonraker control-status telemetry to SaaS every second, and SaaS retains the last 60 seconds for the Print Jobs `Control` panel

### Bambu Cloud

- `PRINTING` / `RUNNING` / `IN_PROGRESS` -> `printing / printing`
- `QUEUED` / `PENDING` / `PREPARING` / `STARTING` / `HEATING` / `SLICING` -> `queued / pending`
- `PAUSED` / `PAUSING` -> `paused / printing`
- `ERROR` / `FAILED` / `FAULT` -> `error / failed`
- `CANCELED` / `CANCELLED` -> `idle / canceled`
- `ACTIVE` / `IDLE` / `READY` / `STANDBY` / `COMPLETED` / `FINISHED` -> `idle / completed`

For runtime snapshots, if a Bambu LAN printer is unreachable, the agent returns connectivity failure for that binding so SaaS can project printer offline.

### Bambu LAN MQTT

- `RUNNING` / `PRINTING` -> `printing / printing`
- `PAUSE` / `PAUSED` -> `paused / printing`
- `PREPARE` / `PREPARING` / `SLICING` / `DOWNLOADING` -> `queued / pending`
- `FAILED` / `ERROR` -> `error / failed`, unless the payload also says the printer is otherwise idle (`print_type=idle`, `task_id=0`, empty `gcode_file`, and no HMS/print_error). In that stale-idle case, normalize to `idle / pending`.
- `FINISH` / `FINISHED` -> `idle / completed`
- `IDLE` -> `idle / pending`, unless the printer has just transitioned from an active PrintFarm-managed print, in which case edge-agent emits a one-shot `completed` job state so SaaS can activate cleanup confirmation.
- When edge-agent restarts during an active PrintFarm-managed print, it rehydrates the active desired job/plate identity onto the resumed active snapshot so SaaS can keep the correct active plate context, clear false stalled-start warnings, and continue showing live progress after reconnect.
- For adopted Bambu printers, edge-agent now coalesces local MQTT runtime reads behind a shared per-printer snapshot coordinator instead of opening duplicate one-shot MQTT sessions from the state loop, control-status loop, and command verification paths.
- Recent successful Bambu runtime snapshots are reused for the live control/status cadence, so short MQTT read turbulence does not immediately surface as printer flapping in SaaS.
- edge-agent only pushes `connectivity_error` for adopted Bambu printers after runtime reads have stayed unhealthy beyond a 15-second grace window; before that, SaaS continues to see the printer as reachable.
- While a Bambu `print` action is still inflight, transient live-runtime connectivity misses are suppressed instead of downgrading the printer to `unreachable`, because printers can briefly stop answering snapshot reads during upload/start preparation even though the print is starting successfully.
- After a Bambu printer accepts `project_file`, edge-agent immediately projects `queued / pending` with the target job/plate identity before final verification completes. That allows SaaS to treat calibration/preparation as a legitimate in-progress start instead of a stalled start that never began.
- During that same PrintFarm-owned Bambu start window, a transient `idle / pending` runtime snapshot that still matches the active desired job/plate must be treated as startup noise, not as a synthetic manual `stopped` intervention.
- command capabilities come from the same local MQTT runtime path:
  - LED state is derived from `lights_report`
  - LED on/off uses the local MQTT `system.ledctrl` envelope
  - spool load/unload uses the local MQTT `print.ams_change_filament` envelope
  - active filament-source detection comes from `print.ams.tray_now`; `vt_tray` is metadata for the external spool, not proof that filament is currently loaded
  - when runtime telemetry is ambiguous at idle, edge-agent can fall back to short-lived command memory so the single filament button remains truthful after a completed unload
  - read-path AMS source detection is supported, but AMS write actions remain gated until the exact MQTT write contract is verified
  - Bambu filament actions can surface `needs_user_confirmation` when the printer does not converge automatically after a load/unload request
- control-status telemetry is reported separately from canonical runtime state:
  - temperatures are parsed from local MQTT fields such as nozzle, bed, and chamber temperature values
  - per-fan read-state is parsed from the local MQTT report payload
  - motion/home, fan writes, and heater setpoint writes use local MQTT `print.gcode_line`
  - edge-agent pushes Bambu control-status telemetry to SaaS every second, and SaaS retains the last 60 seconds for the Print Jobs `Control` panel

## Discovery vs Runtime

Discovery inventory uses connectivity statuses (`reachable`, `unreachable`, `lost`) and is separate from runtime printer/job state.
