# Project Conventions (copy from master, edit per project)
Agents read this before planning and building. Anything decided here is not re-asked in /grill-me.
Lines marked EDIT are placeholders, not decisions.

## Stack
- Language / runtime: Python 3.10+ (native Windows host, calls installed Nmap binary)
- UI (if any): FastAPI + single-page HTML/Tailwind (`command-center-DESIGN.md`, Evreghen Command Center)
- Data store: SQLite file (`data/network.db` in WAL mode via `aiosqlite`)
- Package manager: `uv` with `pyproject.toml`. The README setup steps follow this.
- Dependencies: standard library first; ask before adding any new package.

## Layout
- `src/` application code; `tests/` tests; `.plans/` specs; `.env.example` lists variables with no values.

## Config & secrets
- Settings from environment variables or a `.env` file that is git-ignored. Never hardcode keys. Never print or log them.

## Logging & errors
- stdlib `logging` to a file with timestamp, level, traceback. No silent `except: pass`.
- Fail loudly with a clear message when input data is missing or malformed.

## Windows
- `pathlib` for all paths; no hardcoded absolute paths; PowerShell commands; quote paths with spaces.

## Data safety
- Tests use fixtures or temp copies. Never write to or delete the user's real data files in tests.

## Done means
- Validator PASS, README updated if CLI args / env vars / setup changed, no secrets in the diff.
