# snapmaker_u1

This package is the dedicated home for Snapmaker U1 behavior under the broader Moonraker family.

Current responsibilities:
- identify the `moonraker.snapmaker_u1` profile
- hold Snapmaker-specific control schema details
- hold Snapmaker-specific homing behavior that differs from the generic Moonraker path

The goal is to keep U1-specific logic here instead of letting it leak back into generic Moonraker handling.
