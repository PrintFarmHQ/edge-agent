# Bambu Adoption Behavior

## Discovery Status Matrix

For Bambu discovery entries:

- `reachable`: adoptable
- `unreachable`: not adoptable
- `lost`: not adoptable

## Adoption Outcome

When confirming a Bambu discovery entry:

- If inventory status is `reachable`, the adopted printer is initialized as `idle`.
- The operator must provide the printer access code during adoption.
- SaaS enqueues that access code into a short-lived edge config-command for the owning agent.
- edge-agent stores the access code locally, keyed by printer serial.

Reachable entries are bound as `edge_managed`.

## Why This Behavior

Bambu onboarding is now LAN-first and serial-based. Discovery comes from the local network, not from a cloud account device list.

Because LAN discovery is subnet-local, an `unreachable` or `lost` Bambu entry is not a safe adoption target:

- the printer may have moved to a different IP or subnet,
- the device may no longer be present on the LAN,
- local follow-up control will depend on the edge agent being able to reach the printer directly.

That is why only `reachable` Bambu LAN entries are offered for adoption.

Because Bambu LAN discovery can be intermittent and operators often need a moment to fetch the access code from the printer, SaaS keeps recently seen Bambu rows alive longer before marking them `lost`.

## Secret Boundary

- Discovery does not require the Bambu access code.
- Adoption requires it because the local Bambu LAN runtime is authenticated.
- The access code must not be stored on ordinary SaaS printer records or binding records.
- The access code is persisted locally on the edge-agent host for runtime use.
- SaaS keeps a control-plane recovery copy only while the printer remains actively adopted and edge-managed.
- If the printer is removed or switched away from edge-managed control, SaaS deletes the stored access code and forgets it.

## Access-Code Usage After Adoption

Once the access code is stored on the edge host:

- edge-agent uses it for authenticated local MQTT snapshot reads,
- edge-agent routes Bambu `pause`, `resume`, and `stop` through local MQTT when credentials are available,
- edge-agent can start prints unattended over the local LAN when the printer is in `LAN Only + Developer Mode`,
- unattended LAN start currently requires a `.3mf` artifact and uses a fixed agent-side start profile.

If the local edge state is lost while the printer is still adopted:

- edge-agent can request a fresh `bambu_lan_credentials_upsert` from SaaS control plane,
- SaaS will reissue the access code only while that printer is still actively adopted,
- removed/unadopted printers are not recoverable and require fresh operator re-entry on the next adoption.
