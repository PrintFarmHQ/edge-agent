# Edge Agent Guidance

## Scope

These instructions apply to all files under `edge-agent/`.

## Project Management

- Implementation work in `edge-agent/` must be tracked in the separate `backlog/` repository.
- Task files live under `backlog/todos/`; linked implementation plans live under `backlog/plans/`.
- Follow the detailed planning structure and workflow rules in `../backlog/AGENTS.md`.
- If implementation scope, decisions, or status change, update the matching backlog task and plan files in the same patch set.

## Delivery Direction

- Treat printer integrations as adapter-driven capabilities, not one-off vendor branches spread across the codebase.
- Before adding or changing printer behavior, read:
  - `docs/printer-adapter-capability-architecture.md`
- Follow the normalized capability model first, then implement vendor-specific execution under the appropriate adapter path.

## Camera-First Migration Rule

- Camera work is the first migration slice for the adapter-capability architecture.
- Keep these camera modes explicit:
  - `live_stream`
  - `snapshot_poll`
  - `unsupported`
- Do not force every printer into the same transport if the hardware or firmware exposes different levels of support.

## Adapter Strategy

- Keep generic Moonraker behavior generic.
- Add printer-family-specific fallbacks only when a printer demonstrably does not expose the standard capability path.
- Current examples:
  - Bambu P1/P1S helper-backed live stream
  - Snapmaker U1 `monitor.jpg` snapshot polling fallback

## Implementation Guardrails

- Keep printer-local credentials, camera helpers, and vendor-specific binaries on the edge host only.
- Prefer capability reporting and truthful unavailable reasons over hidden assumptions.
- When helper dependencies are required, make them explicit in logs, config, and docs.
- Preserve a clean seam so later command migration can reuse the same capability architecture.
