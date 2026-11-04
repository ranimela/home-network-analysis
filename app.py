"""Vercel serverless ASGI entrypoint."""

import sys
from pathlib import Path

_SRC_DIR = str(Path(__file__).resolve().parent / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from home_network_analysis.api.server import app

__all__ = ["app"]
