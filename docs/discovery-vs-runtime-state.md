# Discovery vs Runtime State

## Two Different State Channels

## 1) Discovery Inventory (`/discovery-inventory`)

Discovery tracks whether a device is seen by adapter scans:

- `reachable`: currently seen/online
- `unreachable`: known device, currently offline/unreachable
- `lost`: not seen in recent scans

This channel drives adoption workflows.

## 2) Runtime State (`/state`)

Runtime tracks current printer/job execution states for already adopted bindings, using canonical values only.

This channel drives printer availability and print execution UX.

## Practical Example (Bambu)

- Bambu cloud account has 5 devices.
- Discovery can list all 5, with some `reachable` and some `unreachable`.
- User can adopt both reachable and unreachable Bambu entries.
- After adopting an unreachable Bambu entry, printer appears in Printers list as `offline` until device comes back online and runtime updates become reachable.
