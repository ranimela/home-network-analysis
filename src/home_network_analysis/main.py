"""Application entry point and CLI runner."""

import argparse
import logging
import sys

import uvicorn

from home_network_analysis.api.server import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


def main() -> None:
    """Parse CLI arguments and launch the application server."""
    parser = argparse.ArgumentParser(description="Home Network Analysis & Device Monitor")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Binding port (default: 8000)")
    parser.add_argument("--db", default="data/network.db", help="Path to SQLite database file")
    parser.add_argument(
        "--no-auto-scan", action="store_true", help="Disable the background periodic sweep worker"
    )
    parser.add_argument(
        "--interval", type=int, default=60, help="Interval in seconds between sweeps (default: 60)"
    )

    args = parser.parse_args()

    app = create_app(
        db_path=args.db,
        auto_start_scanner=not args.no_auto_scan,
        sweep_interval_seconds=args.interval,
    )

    print("\n" + "=" * 60)
    print("  Home Network Analysis & Monitor")
    print(f"  Dashboard available at: http://localhost:{args.port}")
    print(f"  Database storage: {args.db}")
    print("=" * 60 + "\n")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
