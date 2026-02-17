# Edge Print Architecture Overview

## Roles

- `edge-agent`
  - Discovers printers from providers (Moonraker, Bambu cloud)
  - Normalizes provider-specific data into canonical runtime states
  - Pushes runtime state and discovery inventory to SaaS

- SaaS backend
  - Stores discovery inventory and runtime state
  - Governs adoption policy and binding lifecycle
  - Projects printer connectivity/availability for frontend APIs

- SaaS frontend
  - Renders discovery inventory and adoption actions
  - Renders adopted printer status and queue state

## Data Flow

1. Agent discovers devices and reports inventory (`reachable`/`unreachable`/`lost`).
2. User adopts inventory entries manually.
3. SaaS creates or confirms printer + binding.
4. Agent refreshes runtime state for bound printers using canonical state mapping.
5. SaaS projects connectivity and availability in Printers UI.

## Compatibility Rule

Provider differences must be handled in the agent normalization layer before runtime state push.  
SaaS should consume normalized runtime states and discovery connectivity statuses as-is.
