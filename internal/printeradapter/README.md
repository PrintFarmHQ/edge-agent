# printeradapter

This package is the dedicated home for printer adapter contracts and, over time,
their implementations.

Intended layout:
- `contracts.go`: canonical adapter interfaces and shared types
- `registry.go`: adapter lookup and printer-family fallback resolution
- `moonraker/`: standard Moonraker-family implementation
- `moonraker/snapmaker/`: Snapmaker-specific fallback behavior under the Moonraker family
- `bambu/`: Bambu-family implementation and helper-backed camera support

Current architecture direction:
- `registry.go` is the profile catalog and fallback resolver
- `moonraker/camera.go` is now the adapter-owned home for generic Moonraker camera behavior
- `bambu/camera.go` is now the adapter-owned home for Bambu camera behavior
- `moonraker/runtime.go` is now the adapter-owned home for top-level Moonraker runtime dispatch
- `bambu/runtime.go` is now the adapter-owned home for top-level Bambu runtime dispatch
- Moonraker print start, command/control, and printer-file actions now dispatch through the Moonraker runtime package
- Bambu LAN print start, command/control, and printer-file actions now dispatch through the Bambu runtime package
- Bambu support is LAN-only; cloud/connect paths are no longer part of the runtime architecture
- profiles are matched from adapter family plus detected model/runtime hints
- the resolver publishes printer support metadata such as:
  - `profile_key`
  - `support_tier`
  - `supported_panels`
  - `documentation_slug`
- supported panels now also include the Print Jobs printer-side `Files` panel for supported Moonraker and Bambu profiles
- richer extensibility should build on capability-specific contracts such as:
  - `ControlAdapter` for schema-driven control surfaces
  - `MaterialSystemAdapter` for AMS/toolchanger/material-system descriptions
- edge-agent remains the source of truth for runtime support metadata
- SaaS and frontend should consume the resolved profile instead of inferring support from business `printer_type`

Current rule:
- generic adapter behavior first
- printer-family-specific fallback second
- no scattered vendor checks outside the adapter layer unless migration is still in progress
