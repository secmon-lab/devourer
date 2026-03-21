# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Devourer is a network traffic monitoring tool that captures packets via libpcap, extracts and aggregates network flows (5-tuple), and stores flow logs to BigQuery, files, or stdout.

## Build & Development Commands

```bash
# Build (requires libpcap-dev)
go build -o devourer .

# Run all tests
go test -v ./...

# Run a single test
go test -v ./pkg/domain/logic/ -run TestFlowMap

# Lint (uses golangci-lint)
golangci-lint run

# Docker build
docker build -t devourer .
```

**System dependency**: libpcap-dev (required for gopacket/pcap)

## Architecture

Clean Architecture with three layers:

- **`pkg/cli/`** — CLI commands (urfave/cli/v3), flag parsing, config modules for BigQuery and logging
- **`pkg/domain/`** — Core business logic, protocol-independent
  - `interfaces/` — `Capture` and `Dumper` interfaces
  - `model/` — `Flow`, `Record`, `FlowKey` types. Flows are bidirectional (A→B == B→A) using xxhash
  - `logic/` — `Engine` (packet→flow processing, 120s timeout expiry) and `FlowMap` (thread-safe flow storage)
  - `types/` — Constants (`AppVersion`) and custom errors
- **`pkg/infra/`** — Infrastructure implementations
  - `capture/` — PCAP device/file readers + mock
  - `bq/` — BigQuery dumper (auto-creates day-partitioned `flow_logs` table)
  - `infra.go` — `Clients` struct for dependency injection

Entry point: `main.go` → `cli.Run(os.Args)`

## Usage

```bash
# Capture and output to stdout (default)
devourer capture -i <interface>

# Capture and store to BigQuery
devourer capture -i eth0 --output bigquery \
    --bigquery-project-id <project-id> \
    --bigquery-dataset-id <dataset-id> \
    --bigquery-sa-key-file <sa-key-file>

# Capture and write to file
devourer capture -i eth0 --output file --write-file flows.json

# With statistics display (every 10s)
devourer capture -i eth0 --stat-interval 10s
```

Flags can also be set via environment variables (prefix `DEVOURER_`, e.g. `DEVOURER_INTERFACE`, `DEVOURER_OUTPUT`, `DEVOURER_BQ_PROJECT_ID`).

## Key Libraries

| Library | Purpose |
|---|---|
| `github.com/google/gopacket` | Packet capture and protocol layer parsing via libpcap |
| `cloud.google.com/go/bigquery` | BigQuery client for flow log storage (auto-creates day-partitioned `flow_logs` table) |
| `github.com/urfave/cli/v3` | CLI framework — commands, flags, env var binding |
| `github.com/cespare/xxhash` | Fast hashing for flow key calculation (bidirectional normalization) |
| `github.com/m-mizutani/goerr/v2` | Error wrapping with contextual key-value pairs |
| `github.com/m-mizutani/clog` | Structured logging with color support |
| `github.com/m-mizutani/masq` | Secret masking in log output |
| `github.com/m-mizutani/gt` | Test assertion library (used in all tests) |
| `github.com/google/uuid` | UUID generation for flow IDs |
| `github.com/fatih/color` | Terminal color output for statistics |

## Key Patterns

- Dependency injection via `Clients` struct holding `Capture` and `Dumper` interfaces, configured with functional options (`infra.WithDumper()`, `infra.WithCapture()`)
- Flow key normalization: bidirectional flows share the same key (sorted by IP/port before hashing)
- Engine event loop: reads packets, processes into flows, ticks every second to expire stale flows (120s timeout), handles SIGTERM/SIGINT for graceful flush
- Three output modes: `stdout` (JSON to stdout), `file` (JSON to file), `bigquery` (BigQuery insert)
- Global logger via `utils.Logger()` with slog-based structured logging
