# Home Network Analysis & Monitor

On-premise asynchronous home network discovery and device telemetry engine built with **FastAPI**, **SQLite (WAL mode)**, and **Nmap**, styled with the **Evreghen Command Center** interface.

---

## Key Features
- **Tiered Network Discovery:** Fast 60-second L2 ARP/ping sweeps (`nmap -sn`) for real-time presence tracking paired with automatic and on-demand port scanning (`nmap -sT -T4 --open`).
- **MAC Randomization & DHCP Churn Resilience:** Detects IEEE 802 locally administered (randomized) MAC addresses and maintains deterministic device fingerprints across IP lease changes.
- **Hysteresis Debouncing:** Requires 3 consecutive missed sweeps before marking a device `OFFLINE`, preventing false disconnect alerts from sleeping mobile devices.
- **Persistent Device Renaming:** Assign custom friendly names to any endpoint directly in the UI without losing the underlying network DNS hostname.
- **Real-Time Command Center Dashboard:** Live updates via Server-Sent Events (SSE), instant search/filtering, exposed service badges, and a chronological Presence Audit Timeline.

---

## Prerequisites
- **Windows 10/11** with [Nmap](https://nmap.org/download.html) (and Npcap) installed.
- **Python 3.10+** and [`uv`](https://docs.astral.sh/uv/) package manager.

---

## Quick Start (One-Click Launcher)
Double-click **`run.bat`** in File Explorer or run from PowerShell:
```powershell
.\run.bat
```
This automatically initializes the `.venv` virtual environment (if missing), starts the background scanner and FastAPI server, and opens **`http://localhost:8000`** in your browser.

---

## CLI Options
```powershell
.venv\Scripts\python -m home_network_analysis.main [OPTIONS]
```
| Argument | Default | Description |
| :--- | :--- | :--- |
| `--host` | `0.0.0.0` | Binding host address |
| `--port` | `8000` | Web dashboard and API port |
| `--db` | `data/network.db` | Path to local SQLite WAL database |
| `--interval` | `60` | Seconds between background subnet discovery sweeps |
| `--no-auto-scan` | `False` | Disable periodic background scanning (manual triggers only) |

---

## REST & SSE API Endpoints
- `GET /` — Serves the Command Center web dashboard.
- `GET /api/status` — Returns engine health, detected local CIDR subnet, and active SSE subscriber count.
- `GET /api/devices` — Lists all discovered devices, custom aliases, reachability states, and open TCP services.
- `PATCH /api/devices/{fingerprint_id}` — Updates a device's persistent `custom_name`.
- `POST /api/scan` — Triggers an immediate subnet discovery sweep.
- `POST /api/scan/device` — Runs a targeted top-ports scan on a single IPv4 address.
- `GET /api/logs` — Returns the most recent presence and state transition audit logs.
- `GET /api/events` — Server-Sent Events (SSE) stream for live UI push updates.

---

## Development & Testing
```powershell
# Run full test suite (16 unit & integration tests)
.venv\Scripts\pytest -v

# Run Ruff linter & formatter check
.venv\Scripts\ruff check src tests
```
