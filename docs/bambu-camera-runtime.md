# Bambu Camera Runtime

## Purpose

This document describes how `edge-agent` manages Bambu camera support without requiring:

- a user-managed Docker container,
- a separately launched helper process,
- inbound connectivity from SaaS to the customer LAN.

The operator runs only `edge-agent`.

`edge-agent` owns the Bambu camera runtime lifecycle locally and pushes camera bytes back to SaaS through the existing camera-session relay flow.

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
- downloaded from the official Bambu CDN when missing,
- checksum-verified before use,
- cached under `~/.printfarmhq`,
- reused from the cache on later runs.

Current pinned plugin version:

- `01.04.00.15`

If the cached bundle is missing:

1. `edge-agent` downloads the pinned official archive for the current platform.
2. It verifies the archive SHA256.
3. It extracts the required plugin libraries into its own cache.
4. It uses the cached copy instead of depending on the live Bambu Studio install.

If checksum verification fails, camera startup must fail closed.

## Cache Layout

Current runtime-owned paths live under the edge state directory:

- runtime root:
  - `~/.printfarmhq/bambu/camera_runtime/`
- embedded helper source/assets:
  - `~/.printfarmhq/bambu/camera_runtime/assets/`
- compiled helper binary:
  - `~/.printfarmhq/bambu/camera_runtime/bin/`
- pinned plugin bundle cache:
  - `~/.printfarmhq/bambu/camera_runtime/plugins/<goos>/<version>/`

Example:

```text
~/.printfarmhq/bambu/camera_runtime/
  assets/
    src/BambuP1Streamer.cpp
    src/BambuTunnel.h
  bin/
    BambuP1Streamer
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

## Helper Runtime

`edge-agent` currently compiles a small native helper from embedded source:

- `BambuP1Streamer.cpp`
- `BambuTunnel.h`

That helper is built locally into the runtime bin directory and invoked as a child process by `edge-agent`.

Important current constraint:

- this means the host still needs a working C++ compiler toolchain available in `PATH`

This is still preferable to a user-managed container or sidecar because the operator only launches `edge-agent`, but it is not yet a zero-toolchain distribution story.

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
- helper compile failure,
- helper runtime launch failure,
- unsupported or unverified Bambu family.

The user-facing error should be specific and actionable, but it must not leak secrets like access codes.

## Notes

- This document covers the camera runtime only.
- It does not change the Bambu print/control architecture.
- It does not change the trust boundary: printer-local secrets remain on the edge host.
