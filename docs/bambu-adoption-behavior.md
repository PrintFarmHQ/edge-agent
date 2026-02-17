# Bambu Adoption Behavior

## Discovery Status Matrix

For Bambu discovery entries:

- `reachable`: adoptable
- `unreachable`: adoptable
- `lost`: not adoptable

## Adoption Outcome

When confirming a Bambu discovery entry:

- If inventory status is `reachable`, the adopted printer is initialized as `idle`.
- If inventory status is `unreachable`, the adopted printer is initialized as `offline`.

Both are bound as `edge_managed`.

## Why This Behavior

Bambu cloud discovery is account/device based and can return devices that are currently powered off.  
Those devices are valid adoption targets even when offline at adoption time.
