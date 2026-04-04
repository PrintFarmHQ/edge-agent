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

- Bambu LAN discovery sees 5 devices on the local network.
- Discovery can list all 5, with some `reachable` and some `unreachable`.
- User can adopt both reachable and unreachable Bambu entries.
- After adopting an unreachable Bambu entry, printer appears in Printers list as `offline` until device comes back online and runtime updates become reachable.

## Endpoint Recovery

For adopted `edge_managed` printers, SaaS can now bridge these two channels for connection-target recovery:

- runtime still determines whether a bound printer is currently reachable
- discovery is used to find the same physical printer again when the old bound endpoint is no longer reachable

Recovery rules:

- SaaS only triggers targeted recovery when the bound agent is still healthy and the printer itself is failing with a connectivity error
- recovery runs through the normal discovery job path instead of a separate transport
- strong identity is required before SaaS auto-applies a new connection target
  - Moonraker: MAC address
  - Bambu: serial endpoint
- weak matches such as name-only history remain visible in discovery but do not change the live binding automatically

This keeps the orchestration printer-independent while still allowing each adapter family to own its final apply behavior.
