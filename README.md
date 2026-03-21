# devourer

<p align="center">
  <img src="https://github.com/m-mizutani/devourer/assets/605953/65b12b2d-3d79-4ba0-b312-de171210210b" height="128" />
</p>

A network flow collector that captures packets via libpcap, aggregates them into bidirectional flows, resolves peer names from DNS/mDNS/LLMNR/NBNS/DHCP, and outputs the results to BigQuery, a file, or stdout.

## Background

Modern network traffic is almost entirely encrypted with TLS. Deep packet inspection, which was once a primary technique for network security monitoring, can no longer see the contents of most communications. What remains observable at the network level is metadata: who talked to whom, on which port, how much data was exchanged, and for how long — i.e., **network flows**. Combined with **name resolution** (DNS lookups, mDNS, NBNS, etc.), flow logs provide a practical basis for detecting anomalies, investigating incidents, and understanding network behavior without relying on payload inspection.

devourer is built for this purpose. It captures raw packets, aggregates them into flows, enriches them with hostnames collected from name resolution protocols on the wire, and stores the results for analysis.

## Features

- **Flow aggregation**: Groups packets into bidirectional flows based on 5-tuple (src/dst IP, src/dst port, protocol). A→B and B→A are treated as the same flow.
- **Name resolution**: Passively extracts hostnames from DNS, mDNS, LLMNR, NBNS, and DHCP traffic observed on the network. Resolved names are attached to the corresponding flow peers.
- **Multiple outputs**: Supports BigQuery (with automatic table creation and day partitioning), JSON file, and stdout.
- **Protocols**: TCP, UDP, ICMPv4, ICMPv6.
- **Real-time statistics**: Optional display of packets/sec, bits/sec, and active flow count at a configurable interval.
- **Graceful shutdown**: Flushes all in-memory flows on SIGTERM/SIGINT before exiting.

## How it works

1. devourer captures packets from a network interface (or pcap file) using libpcap.
2. Each packet is classified into a flow by its 5-tuple. The flow key is normalized so that both directions of a conversation map to the same flow.
3. Name resolution packets (DNS responses, mDNS, LLMNR, NBNS, DHCP) are parsed in parallel to build an in-memory mapping of IP addresses and MAC addresses to hostnames.
4. When a flow has been idle for 120 seconds (configurable), it is expired, enriched with any resolved names, and sent to the configured output.
5. On shutdown, all remaining flows are flushed immediately.

## Output example

Each flow is output as a JSON record:

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "protocol": "tcp",
  "src": {
    "addr": "192.168.1.10",
    "port": 52431,
    "hw_addr": "aa:bb:cc:dd:ee:f0",
    "names": ["my-laptop.local"]
  },
  "dst": {
    "addr": "93.184.216.34",
    "port": 443,
    "names": ["example.com"]
  },
  "first_seen_at": "2025-01-15T10:30:00Z",
  "last_seen_at": "2025-01-15T10:31:12Z",
  "src_stat": { "bytes": 12340, "packets": 42 },
  "dst_stat": { "bytes": 98210, "packets": 65 },
  "status": "established"
}
```

## Installation

### Binary

```bash
go install github.com/secmon-lab/devourer@latest
```

Requires `libpcap-dev` (Debian/Ubuntu) or `libpcap` (macOS via Homebrew).

### Docker

```bash
docker pull ghcr.io/m-mizutani/devourer:latest
```

## Usage

### Capture and output to stdout (default)

```bash
devourer capture -i <interface>
```

### Capture and store to BigQuery

```bash
devourer capture -i eth0 --output bigquery \
    --bigquery-project-id <project-id> \
    --bigquery-dataset-id <dataset-id> \
    --bigquery-sa-key-file <sa-key-file>
```

The `flow_logs` table is created automatically with day-based time partitioning.

### Capture and write to file

```bash
devourer capture -i eth0 --output file --write-file flows.json
```

### With real-time statistics

```bash
devourer capture -i eth0 --stat-interval 10s
```

### Environment variables

All flags can be set via environment variables with the prefix `DEVOURER_`:

```bash
export DEVOURER_INTERFACE=eth0
export DEVOURER_OUTPUT=bigquery
export DEVOURER_BIGQUERY_PROJECT_ID=my-project
export DEVOURER_BIGQUERY_DATASET_ID=network_logs
export DEVOURER_BIGQUERY_SA_KEY_FILE=/path/to/key.json
devourer capture
```

## BigQuery schema

The `flow_logs` table has the following columns:

| Column | Type | Description |
|---|---|---|
| id | STRING | Unique flow identifier (UUID) |
| protocol | STRING | Transport protocol (`tcp`, `udp`, `icmp4`, `icmp6`) |
| src_addr | STRING | Source IP address |
| dst_addr | STRING | Destination IP address |
| src_port | INTEGER | Source port (0 for ICMP) |
| dst_port | INTEGER | Destination port (0 for ICMP) |
| src_hw_addr | STRING | Source MAC address |
| dst_hw_addr | STRING | Destination MAC address |
| src_names | STRING (REPEATED) | Source peer hostnames (from DNS/mDNS/LLMNR/NBNS/DHCP) |
| dst_names | STRING (REPEATED) | Destination peer hostnames (from DNS/mDNS/LLMNR/NBNS/DHCP/TLS SNI) |
| first_seen_at | TIMESTAMP | When the first packet was observed |
| last_seen_at | TIMESTAMP | When the last packet was observed |
| src_bytes | INTEGER | Bytes from source to destination |
| dst_bytes | INTEGER | Bytes from destination to source |
| src_packets | INTEGER | Packets from source to destination |
| dst_packets | INTEGER | Packets from destination to source |
| status | STRING | `init` (one-way only) or `established` (both directions seen) |

## License

Apache License 2.0
