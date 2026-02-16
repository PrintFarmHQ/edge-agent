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

Bambu Connect example:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx EDGE_AGENT_FLAGS="--klipper --bambu --bambu-connect-uri=http://127.0.0.1:3123"
```

Run with both Klipper and Bambu discovery while connecting to SaaS:

```bash
make dev EDGE_API_KEY=pfh_edge_xxx DEV_CONTROL_PLANE_URL=http://localhost:8000 EDGE_AGENT_FLAGS="--klipper --bambu --bambu-connect-uri=http://127.0.0.1:3123"
```

- `EDGE_API_KEY` maps to `--api-key` for SaaS auth.
- `DEV_CONTROL_PLANE_URL` maps to `--control-plane-url`.
- Ensure Bambu Connect is installed and running at `--bambu-connect-uri`.

Direct run is also supported:

```bash
./bin/edge-agent --klipper --control-plane-url="http://localhost:8000" --api-key="pfh_edge_xxx"
```

Direct run with both adapters:

```bash
./bin/edge-agent --klipper --bambu --bambu-connect-uri="http://127.0.0.1:3123" --control-plane-url="http://localhost:8000" --api-key="pfh_edge_xxx"
```

`--saas-api-key` is accepted as an alias for `--api-key`.
