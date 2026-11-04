"""Vercel serverless ASGI entrypoint."""

from home_network_analysis.api.server import app

__all__ = ["app"]
