# printeradapter

This package is the dedicated home for printer adapter contracts and, over time,
their implementations.

Intended layout:
- `contracts.go`: canonical adapter interfaces and shared types
- `registry.go`: adapter lookup and printer-family fallback resolution
- `moonraker/`: standard Moonraker-family implementation
- `moonraker/snapmaker/`: Snapmaker-specific fallback behavior under the Moonraker family
- `bambu/`: Bambu-family implementation and helper-backed camera support

Current rule:
- generic adapter behavior first
- printer-family-specific fallback second
- no scattered vendor checks outside the adapter layer unless migration is still in progress
