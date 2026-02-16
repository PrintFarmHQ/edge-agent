# Edge Agent local workflow entrypoint (minimal binary-first flow)

BIN_DIR := $(CURDIR)/bin
BIN_PATH := $(BIN_DIR)/edge-agent
EDGE_STATE_DIR ?= $(HOME)/.printfarmhq
BOOTSTRAP_CONFIG_PATH ?= $(EDGE_STATE_DIR)/bootstrap/config.json
AUDIT_LOG_PATH ?= $(EDGE_STATE_DIR)/logs/audit.log
ARTIFACT_STAGE_DIR ?= $(EDGE_STATE_DIR)/artifacts
SETUP_BIND_ADDR ?= 127.0.0.1:18090

DEV_CONTROL_PLANE_URL ?= http://localhost:8000
LOCAL_BACKEND_HEALTH_URL ?= http://localhost:8000/health
EDGE_API_KEY ?=
EDGE_AGENT_FLAGS ?= --klipper

DISCOVERY_PROFILE_MAX ?= hybrid
DISCOVERY_NETWORK_MODE ?= host
DISCOVERY_ALLOWED_ADAPTERS ?= moonraker,bambu
DISCOVERY_ENDPOINT_HINTS ?=
DISCOVERY_CIDR_ALLOWLIST ?=
DISCOVERY_INVENTORY_INTERVAL_MS ?= 60000
DISCOVERY_MANUAL_POLL_INTERVAL_MS ?= 5000
DISCOVERY_MAX_TARGETS ?= 256
DISCOVERY_WORKER_COUNT ?= 16
DISCOVERY_PROBE_TIMEOUT_MS ?= 2500

GOCACHE ?= $(CURDIR)/.cache/go-build
GOMODCACHE ?= $(CURDIR)/.cache/go-mod

.DEFAULT_GOAL := help

.PHONY: help build dev down test

help: ## Show available edge-agent commands
	@awk 'BEGIN {FS = ":.*##"; printf "\033[36m%-10s\033[0m %s\n", "Command", "Description"} /^[a-zA-Z0-9_.-]+:.*?##/ { printf "\033[36m%-10s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build local edge-agent binary (bin/edge-agent)
	@mkdir -p "$(BIN_DIR)" "$(GOCACHE)" "$(GOMODCACHE)"
	@GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" CGO_ENABLED=0 go build -o "$(BIN_PATH)" ./cmd/edge-agent
	@echo "Built native binary: $(BIN_PATH)"

dev: ## Build and run edge-agent in foreground (Ctrl+C to stop)
	@$(MAKE) --no-print-directory build
	@if ! command -v curl >/dev/null 2>&1; then \
		echo "curl is required for backend health check."; \
		exit 1; \
	fi
	@if ! curl -fsS "$(LOCAL_BACKEND_HEALTH_URL)" >/dev/null 2>&1; then \
		echo "Local backend is not reachable at $(LOCAL_BACKEND_HEALTH_URL). Run 'make dev' from repository root first."; \
		exit 1; \
	fi
	@mkdir -p "$$(dirname "$(BOOTSTRAP_CONFIG_PATH)")" "$$(dirname "$(AUDIT_LOG_PATH)")" "$(ARTIFACT_STAGE_DIR)"
	@echo "Running edge-agent in foreground (Ctrl+C stops it)..."
	@if [ -n "$(EDGE_API_KEY)" ]; then \
		echo "Starting with API key and control-plane URL flags."; \
		SETUP_BIND_ADDR="$(SETUP_BIND_ADDR)" \
		BOOTSTRAP_CONFIG_PATH="$(BOOTSTRAP_CONFIG_PATH)" \
		AUDIT_LOG_PATH="$(AUDIT_LOG_PATH)" \
		ARTIFACT_STAGE_DIR="$(ARTIFACT_STAGE_DIR)" \
		DISCOVERY_PROFILE_MAX="$(DISCOVERY_PROFILE_MAX)" \
		DISCOVERY_NETWORK_MODE="$(DISCOVERY_NETWORK_MODE)" \
		DISCOVERY_ALLOWED_ADAPTERS="$(DISCOVERY_ALLOWED_ADAPTERS)" \
		DISCOVERY_ENDPOINT_HINTS="$(DISCOVERY_ENDPOINT_HINTS)" \
		DISCOVERY_CIDR_ALLOWLIST="$(DISCOVERY_CIDR_ALLOWLIST)" \
		DISCOVERY_INVENTORY_INTERVAL_MS="$(DISCOVERY_INVENTORY_INTERVAL_MS)" \
		DISCOVERY_MANUAL_POLL_INTERVAL_MS="$(DISCOVERY_MANUAL_POLL_INTERVAL_MS)" \
		DISCOVERY_MAX_TARGETS="$(DISCOVERY_MAX_TARGETS)" \
		DISCOVERY_WORKER_COUNT="$(DISCOVERY_WORKER_COUNT)" \
		DISCOVERY_PROBE_TIMEOUT_MS="$(DISCOVERY_PROBE_TIMEOUT_MS)" \
		"$(BIN_PATH)" $(EDGE_AGENT_FLAGS) --control-plane-url="$(DEV_CONTROL_PLANE_URL)" --api-key="$(EDGE_API_KEY)"; \
	else \
		echo "Starting with control-plane URL flag (unclaimed until API key is provided)."; \
		SETUP_BIND_ADDR="$(SETUP_BIND_ADDR)" \
		BOOTSTRAP_CONFIG_PATH="$(BOOTSTRAP_CONFIG_PATH)" \
		AUDIT_LOG_PATH="$(AUDIT_LOG_PATH)" \
		ARTIFACT_STAGE_DIR="$(ARTIFACT_STAGE_DIR)" \
		DISCOVERY_PROFILE_MAX="$(DISCOVERY_PROFILE_MAX)" \
		DISCOVERY_NETWORK_MODE="$(DISCOVERY_NETWORK_MODE)" \
		DISCOVERY_ALLOWED_ADAPTERS="$(DISCOVERY_ALLOWED_ADAPTERS)" \
		DISCOVERY_ENDPOINT_HINTS="$(DISCOVERY_ENDPOINT_HINTS)" \
		DISCOVERY_CIDR_ALLOWLIST="$(DISCOVERY_CIDR_ALLOWLIST)" \
		DISCOVERY_INVENTORY_INTERVAL_MS="$(DISCOVERY_INVENTORY_INTERVAL_MS)" \
		DISCOVERY_MANUAL_POLL_INTERVAL_MS="$(DISCOVERY_MANUAL_POLL_INTERVAL_MS)" \
		DISCOVERY_MAX_TARGETS="$(DISCOVERY_MAX_TARGETS)" \
		DISCOVERY_WORKER_COUNT="$(DISCOVERY_WORKER_COUNT)" \
		DISCOVERY_PROBE_TIMEOUT_MS="$(DISCOVERY_PROBE_TIMEOUT_MS)" \
		"$(BIN_PATH)" $(EDGE_AGENT_FLAGS) --control-plane-url="$(DEV_CONTROL_PLANE_URL)"; \
	fi

down: ## Stop all local edge-agent processes by name
	@count="$$(pgrep -x edge-agent 2>/dev/null | wc -l | tr -d ' ')"; \
	if [ "$$count" = "0" ]; then \
		echo "No edge-agent process running."; \
		exit 0; \
	fi; \
	echo "Stopping $$count edge-agent process(es)..."; \
	pkill -x edge-agent >/dev/null 2>&1 || true; \
	sleep 1; \
	if pgrep -x edge-agent >/dev/null 2>&1; then \
		echo "Force killing remaining edge-agent process(es)..."; \
		pkill -9 -x edge-agent >/dev/null 2>&1 || true; \
	fi; \
	remaining="$$(pgrep -x edge-agent 2>/dev/null | wc -l | tr -d ' ')"; \
	if [ "$$remaining" = "0" ]; then \
		echo "All edge-agent processes stopped."; \
	else \
		echo "Failed to stop $$remaining edge-agent process(es)."; \
		exit 1; \
	fi

test: ## Run edge-agent tests
	@mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	@GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" go test ./...
