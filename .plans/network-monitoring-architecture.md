# Architecture Specification: Home Network Analysis & Device Monitor

## Architectural Overview
This system is an on-premise, asynchronous network discovery and telemetry platform architected around strict layer separation:
1. **Ingestion Engine (Async Collector Core):**
   - **L2 Fast-Poller:** High-frequency, non-intrusive ARP/ICMP ping sweeps across local CIDRs every 60–120 seconds to establish real-time device liveness and presence timestamps.
   - **Deep-Scanner (Event-Driven):** Triggered strictly on discovery of a novel device fingerprint or explicit user request. Executes scoped, rate-limited Nmap invocations (`-sS`, `-sV`, `--top-ports 100`) via native Windows `nmap.exe` binary.
   - **Protocol Augmenter:** Queries passive/local broadcast protocols (mDNS / SSDP / UPnP IGD) to harvest hostnames, friendly names, and model metadata without touching router admin web scraping.
2. **Persistence & Identity Engine (State Machine):**
   - **Database:** Embedded SQLite configured in Write-Ahead Logging (`WAL`) mode with synchronous normal for high concurrency and zero daemon overhead.
   - **Deterministic Entity Resolution:** Resolves dynamic IP shifts and MAC randomization churn by computing a composite identity (`hardware_mac` if non-randomized, falling back to canonical `hostname + vendor_oui + open_fingerprint_hash`).
3. **Application & Delivery Layer:**
   - **FastAPI Core:** Serves REST endpoints for snapshot queries and Server-Sent Events (SSE) / WebSocket streams for live presence updates.
   - **Presentation:** Decoupled modern frontend (Vite/React + Tailwind CSS) communicating strictly over the typed API contract.

```
+-------------------------------------------------------------+
|                     Ingestion Layer                         |
|  [ARP Sweeper]   [mDNS/SSDP Sniffer]   [Lazy Nmap Service]  |
+------------------------------+------------------------------+
                               | Normalized Events
                               v
+-------------------------------------------------------------+
|             Identity Resolution & Persistence               |
|            [Entity Resolver] <-> [SQLite WAL]               |
+------------------------------+------------------------------+
                               | Queries / Realtime Stream
                               v
+-------------------------------------------------------------+
|                     Presentation Layer                      |
|             [FastAPI SSE] <-> [React Dashboard]             |
+-------------------------------------------------------------+
```

---

## Immutable Data Contracts

### 1. Ingestion Output Contract (`NetworkScanSnapshot`)
Every discovery sweep emits a strict payload adhering to this schema:
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "NetworkScanSnapshot",
  "type": "object",
  "required": ["scan_id", "timestamp_utc", "collector_source", "network_scope", "endpoints"],
  "properties": {
    "scan_id": { "type": "string", "format": "uuid" },
    "timestamp_utc": { "type": "string", "format": "date-time" },
    "collector_source": { "type": "string", "enum": ["ARP_SWEEP", "NMAP_TARGETED", "MDNS_SSDP"] },
    "network_scope": { "type": "string" },
    "endpoints": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/DiscoveredEndpoint"
      }
    }
  },
  "definitions": {
    "DiscoveredEndpoint": {
      "type": "object",
      "required": ["observed_ip", "is_randomized_mac", "reachability", "first_seen_utc", "last_seen_utc"],
      "properties": {
        "fingerprint_id": { "type": "string" },
        "observed_ip": { "type": "string", "format": "ipv4" },
        "observed_mac": { "type": ["string", "null"] },
        "is_randomized_mac": { "type": "boolean" },
        "hostname": { "type": ["string", "null"] },
        "vendor": { "type": ["string", "null"] },
        "reachability": { "type": "string", "enum": ["ONLINE", "OFFLINE", "DEGRADED"] },
        "latency_ms": { "type": ["number", "null"] },
        "services": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["port", "protocol", "state"],
            "properties": {
              "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
              "protocol": { "type": "string", "enum": ["TCP", "UDP"] },
              "service_name": { "type": ["string", "null"] },
              "service_version": { "type": ["string", "null"] },
              "state": { "type": "string", "enum": ["OPEN", "FILTERED", "CLOSED"] }
            }
          }
        }
      }
    }
  }
}
```

### 2. Entity State Machine Contract
State transitions for monitored network devices:
```
[NEW_DISCOVERED] ---> (L2 Sweep Detects) ---> [ONLINE]
      |                                          |
      | (Deep Scan Queued)                       | (Missed N Consecutive Pings)
      v                                          v
[SCANNING_SERVICES]                         [OFFLINE]
      |                                          |
      +------------> [PROFILED] <----------------+
```

---

## Affected Files
Explicit, isolated file paths to create during implementation (zero clutter, pure separation):

- `/.gitignore` (Security exclusion list: database files, environment credentials, caches)
- `/pyproject.toml` (Dependency specifications: fastapi, uvicorn, pydantic, aiosqlite, scapy/zeroconf)
- `/src/core/contracts.py` (Pydantic models strictly implementing the immutable schemas)
- `/src/storage/db.py` (SQLite connection manager, WAL initialization, schema migration DDL)
- `/src/storage/repository.py` (Device entity CRUD, deterministic identity resolution logic)
- `/src/ingestion/scanner.py` (Subprocess wrapper for host `nmap.exe` and ARP sweep runner)
- `/src/ingestion/protocols.py` (mDNS and SSDP query listeners for metadata enrichment)
- `/src/api/server.py` (FastAPI app, SSE event broadcaster, REST routes)
- `/src/main.py` (Application bootstrap, background task runner orchestration)
- `/tests/test_contracts.py` (Unit tests for payload validation and schema adherence)
- `/tests/test_entity_resolution.py` (Unit tests for MAC randomization & identity matching)

---

## Step-by-Step Micro-Tasks

### Phase 1: Repository Hardening & Environment Baseline
1. Create `/.gitignore` excluding `.env`, `*.db`, `*.db-wal`, `__pycache__`, `node_modules`, and raw credentials.
2. Initialize local Git repository tracking and establish main branch.
3. Configure `pyproject.toml` with `uv` or `pip` dependencies adhering to Python 3.10+ typing standards.

### Phase 2: Domain Schema & Data Layer
1. Implement immutable domain models in `src/core/contracts.py` using Pydantic V2 with strict type validation.
2. Implement SQLite WAL database initialization and schema DDL in `src/storage/db.py`.
3. Implement `src/storage/repository.py` including the identity deduplication hash function.

### Phase 3: Ingestion Engine
1. Implement `src/ingestion/scanner.py` with defensive subprocess handling for `nmap.exe` (timeouts, stdout parsing, Npcap validation).
2. Implement metadata resolution in `src/ingestion/protocols.py` for mDNS/UPnP service resolution.
3. Build the tiered scan coordinator (fast ARP sweep every 60s + lazy Nmap queue).

### Phase 4: API & SSE Broadcaster
1. Build FastAPI endpoints in `src/api/server.py` for snapshot retrieval (`GET /api/devices`), scan triggers (`POST /api/scan`), and live feed (`GET /api/events` via SSE).
2. Wire application entrypoint in `src/main.py` with graceful shutdown handlers.

---

## Failure Modes & Mitigation (Chaos Monkey Injection)

### 1. Subprocess Pipe Exhaustion & Zombie Process Leaks
* **Failure Vector:** On Windows, `asyncio.create_subprocess_exec` buffers stdout/stderr to an OS pipe. A verbose Nmap scan (`-sV --top-ports 100`) against responsive subnets will fill the pipe buffer (typically 64KB on Windows), causing Nmap and the Python event loop to deadlock indefinitely.
* **Mitigation:**
  - Standardize all Nmap invocations to write XML directly to a secured temp file (`-oX %TEMP%\\scan_<uuid>.xml`) rather than piping raw stdout.
  - Implement a hard timeout wrapper with defensive process termination: if the timeout expires, execute `taskkill /F /T /PID <pid>` to prune both the wrapper and orphaned `nmap.exe` instances.
  - Enforce an OS lock preventing concurrent Nmap invocations (limit concurrency to exactly 1 active deep-scan worker).

### 2. SQLite Write-Collision (`OperationalError: database is locked`)
* **Failure Vector:** SQLite WAL mode supports concurrent readers, but exactly ONE writer. When the 60s ARP sweep worker, a deep-scan completion callback, and a user API trigger write concurrently, transactions fail with database locks.
* **Mitigation:**
  - Implement an asynchronous single-writer channel pattern (`asyncio.Queue`) for all database write operations.
  - Configure `busy_timeout = 5000` (5-second wait) on the SQLite connection to queue transient contention.
  - All write transactions must execute within atomic transaction scopes (`BEGIN IMMEDIATE`) processed sequentially by the background writer task.

### 3. Device Reachability Flapping & SSE Event Storms
* **Failure Vector:** Mobile devices entering low-power sleep modes or devices on Wi-Fi fringes drop occasional ICMP/ARP packets, causing state flapping (`ONLINE -> OFFLINE -> ONLINE`) every 60 seconds. This causes database thrashing, bloated history tables, and client-side DOM render cascades.
* **Mitigation:**
  - Introduce an entity **Hysteresis Buffer**: A device transitions `ONLINE -> OFFLINE` ONLY after failing 3 consecutive sweep cycles (3–6 minutes of silence).
  - Outgoing SSE broadcasts must be throttled with a 1-second debounce buffer, batching multi-device state changes into a single event frame.

### 4. Command Injection & Subnet Traversal via API
* **Failure Vector:** `POST /api/scan` receiving unvalidated user input or CIDR ranges can allow attackers to inject arbitrary Nmap flags (e.g., `--script=arbitrary.nse` or output redirection), executing arbitrary local code under user privileges.
* **Mitigation:**
  - The API must parse and validate targets strictly through Python's `ipaddress.ip_network(strict=True)`.
  - Disallow any input containing hyphens, spaces, or semicolons.
  - Arguments to `subprocess` must be passed as an immutable list of arguments (`sys.argv` array), never through `shell=True`.

### 5. Multi-NIC & Virtual Adapter Silent Discovery Failure
* **Failure Vector:** Windows workstations routinely host multiple virtual NICs (WSL2 vEthernet, Hyper-V, Tailscale, Docker NAT). If Nmap runs without an explicit adapter flag, it selects the default routing adapter (often WSL or VPN), resulting in 0 local devices discovered or scans routed into corporate VPN subnets.
* **Mitigation:**
  - Implement interface auto-detection: probe the host default gateway (`netifaces` or socket probe to `8.8.8.8:80`) to identify the physical LAN interface name and IP.
  - Explicitly pass `-e <interface>` or constrain target CIDR to the detected physical LAN subnet.

---

## Verification Criteria
1. **Schema Integrity:** `pytest tests/test_contracts.py` passes 100%, rejecting invalid IP/MAC formats and malformed scan results.
2. **Entity Resolution:** `pytest tests/test_entity_resolution.py` verifies that randomized MAC addresses do not produce duplicate database entities for the same physical host across multiple DHCP lease assignments.
3. **Execution Safety:** Nmap subprocess invocations terminate cleanly with hard timeouts without blocking async event loops or leaking file descriptors.
4. **Git Perimeter:** `git status` confirms zero sensitive files (`.env`, `*.db`) are untracked or staged.

---

## Context Pruning
When the **Builder** executes micro-tasks, it must strictly read ONLY these files:
- `/.plans/network-monitoring-architecture.md`
- The single file currently undergoing mutation (e.g., `src/core/contracts.py`).
- No extraneous codebase indexing or speculative context reads.
