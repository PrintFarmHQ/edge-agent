# Edge Agent Local Workflow

Binary-first workflow (no installer, no Docker runtime).

## Commands

```bash
cd edge-agent
make build
make dev EDGE_API_KEY=pfh_edge_xxx
make down
```

- `make build`: compiles `bin/edge-agent`.
- `make dev`: rebuilds then runs in foreground with logs attached (defaults to `EDGE_AGENT_FLAGS=--klipper`).
- `make down`: kills all local `edge-agent` processes by name.

Optional test commands:

```bash
make test
```

## Dev defaults

- Backend health check: `http://localhost:8000/health`
- Control plane URL for `make dev`: `http://localhost:8000`
- Setup bind address: `127.0.0.1:18090`

Override example:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx DEV_CONTROL_PLANE_URL=http://localhost:8000 SETUP_BIND_ADDR=127.0.0.1:18100 EDGE_AGENT_FLAGS="--klipper"
```

Bambu cloud auth example:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx EDGE_AGENT_FLAGS="--klipper --bambu"
```

Run with both Klipper and Bambu discovery while connecting to SaaS:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx DEV_CONTROL_PLANE_URL=http://localhost:8000 EDGE_AGENT_FLAGS="--klipper --bambu"
```

- `EDGE_API_KEY` maps to `--api-key` for SaaS auth.
- `DEV_CONTROL_PLANE_URL` maps to `--control-plane-url`.

## Current Bambu Status

- Bambu startup now performs cloud authentication (MFA supported) and persists token material locally in `~/.printfarmhq/bambu/credentials.json`.
- Bambu mode requires only `--bambu`.
- Startup first tries stored token reuse (and refresh token when available). If not valid, it prompts for username/password interactively.
- Password input is treated as secret in terminal sessions and is not echoed back.
- When MFA is required, startup blocks and asks for the code on the interactive console.
- Empty/invalid MFA code (or non-interactive console) makes startup fail with a non-zero exit.
- Bambu cloud devices are discovered through the same discovery inventory pipeline as Klipper and submitted to SaaS on the periodic inventory cadence (default 30s).
- Bambu print lifecycle actions are not enabled yet in this code path.
- Cloud auth/MFA + cloud print lifecycle rollout is tracked in `backlog/todo/p0.md`.

## Docs

- `docs/architecture-overview.md`
- `docs/edge-agent-state-normalization.md`
- `docs/discovery-vs-runtime-state.md`
- `docs/bambu-adoption-behavior.md`

Direct run is also supported:

```bash
./bin/edge-agent --klipper --control-plane-url="http://localhost:8000" --api-key="pfh_edge_xxx"
```

Direct run with both adapters:

```bash
./bin/edge-agent --klipper --bambu --control-plane-url="http://localhost:8000" --api-key="pfh_edge_xxx"
```

`--saas-api-key` is accepted as an alias for `--api-key`.
