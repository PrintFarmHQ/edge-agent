# Bambu Camera Runtime

## Purpose

This document describes how `edge-agent` manages Bambu camera support without requiring:

- a user-managed Docker container,
- a separately launched helper process,
- inbound connectivity from SaaS to the customer LAN.

The operator runs only `edge-agent`.

`edge-agent` owns the Bambu camera runtime lifecycle locally and pushes camera bytes back to SaaS through the existing camera-session relay flow.

The same pinned native bundle is also reused by `edge-agent` for Bambu native control-tunnel work such as printer file-control operations. This document focuses on the bundle lifecycle and camera runtime contract.

Current ownership checkpoint:
- the low-level native runtime still lives under `internal/bambu/cameraruntime/`
- the higher-level Bambu camera selection and orchestration path is now beginning to move into `internal/printeradapter/bambu/`

## Network Model

The camera architecture is intentionally outbound-only:

1. SaaS creates a printer camera session.
2. `edge-agent` polls SaaS for pending camera sessions.
3. `edge-agent` acquires camera bytes locally from the Bambu runtime.
4. `edge-agent` uploads the stream bytes back to SaaS.
5. The browser watches the relayed SaaS stream.

SaaS must never dial into `edge-agent` directly.

The only local contract is loopback-only on the edge host:

- `GET /internal/camera/v1/bambu/{serial}/stream.mjpeg`
- `GET /internal/camera/v1/bambu/{serial}/snapshot.jpg`
- `GET /internal/camera/v1/bambu/{serial}/health`

These routes are for `edge-agent`'s own runtime and diagnostics. They are not a public SaaS dependency.

## Dependency Policy

`edge-agent` does not follow whatever Bambu Studio version happens to be installed.

Instead, the Bambu native plugin dependency is:

- pinned to a specific version,
- preflighted on `--bambu` startup,
- downloaded from the official Bambu CDN when missing,
- checksum-verified before use,
- cached under `~/.printfarmhq`,
- reused from the cache on later runs.

Current pinned plugin version:

- `01.04.00.15`

If the pinned bundle is missing or invalid:

1. `edge-agent` downloads the pinned official archive for the current platform.
2. It verifies the archive SHA256.
3. It extracts the required plugin libraries into its own cache.
4. It uses the cached copy instead of depending on the live Bambu Studio install.

If checksum verification fails, camera startup must fail closed.

## Startup Preflight

When `edge-agent` starts with `--bambu`, startup first verifies that the pinned plugin bundle is ready in the edge-managed cache.

Valid pinned bundle requirements:

- `plugin.zip` exists in the pinned version directory
- `plugin.zip` SHA256 matches the pinned official checksum
- the required source library exists for the current platform
- the required networking library exists for the current platform

If any of those checks fail:

1. `edge-agent` clears the broken pinned-version cache directory.
2. It re-downloads the pinned official archive.
3. It re-verifies the archive checksum.
4. It re-extracts the required native libraries.

If the bundle still cannot be prepared, `edge-agent` exits with a clear operator-facing error that explains:

- the pinned version,
- the expected cache directory,
- what failed,
- and what the operator should check next.

## Cache Layout

Current runtime-owned paths live under the edge state directory:

- runtime root:
  - `~/.printfarmhq/bambu/camera_runtime/`
- pinned plugin bundle cache:
  - `~/.printfarmhq/bambu/camera_runtime/plugins/<goos>/<version>/`

Example:

```text
~/.printfarmhq/bambu/camera_runtime/
  plugins/
    darwin/
      01.04.00.15/
        plugin.zip
        libBambuSource.dylib
        libbambu_networking.dylib
```

## Pinned Official Artifacts

The runtime currently pins these official plugin archives:

- macOS
  - URL:
    - `https://public-cdn.bambulab.com/upgrade/studio/plugins/01.04.00.15/mac_01.04.00.15.zip`
  - SHA256:
    - `4a57ac71bc60dfa38ab685523b56e36f284ffe44138fde03e882acb44ddc333a`
  - extracted files:
    - `libBambuSource.dylib`
    - `libbambu_networking.dylib`

- Linux
  - URL:
    - `https://public-cdn.bambulab.com/upgrade/studio/plugins/01.04.00.15/linux_01.04.00.15.zip`
  - SHA256:
    - `379ec431a2bc4ffc5dbba0469725db7f331c840a2be59d0a817a9451abe7e3bc`
  - extracted files:
    - `libBambuSource.so`
    - `libbambu_networking.so`

- Windows
  - URL:
    - `https://public-cdn.bambulab.com/upgrade/studio/plugins/01.04.00.15/win_01.04.00.15.zip`
  - SHA256:
    - `4552e7d7ef84a43c0267649a1784a14960e3212c3a1f1c0906a1e202b8d5fa94`
  - extracted files:
    - `BambuSource.dll`
    - `bambu_networking.dll`

## Go Runtime

`edge-agent` now loads the pinned Bambu plugin libraries directly through an in-process Go runtime with a small `cgo` bridge.

This means:

- there is no user-managed helper process,
- there is no local helper compilation step,
- the operator still runs only `edge-agent`.

## Support Matrix

Bambu camera support must remain truthful and capability-gated.

Directly tested today:

- `P1S`

Unverified / not yet directly supported:

- `P1P`
- `X1`
- `X1C`
- `X1E`
- `A1`
- `A1 Mini`
- any newer Bambu family

Rules:

- only directly tested families may report camera support as available by default,
- unverified families must surface an explicit unavailable reason,
- we must not imply `X1C` support until it is directly verified and implemented.

## Failure Behavior

Camera startup must fail closed for cases such as:

- pinned plugin archive missing,
- pinned plugin archive checksum mismatch,
- required plugin library missing after extraction,
- native runtime initialization failure,
- unsupported or unverified Bambu family.

The user-facing error should be specific and actionable, but it must not leak secrets like access codes.

## Notes

- This document focuses on the pinned native bundle lifecycle plus the camera runtime that consumes it.
- The same pinned bundle is also reused by the Bambu native control tunnel for file-control flows.
- It does not change the Bambu print/control architecture.
- It does not change the trust boundary: printer-local secrets remain on the edge host.
