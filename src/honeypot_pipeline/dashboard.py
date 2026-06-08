"""Compatibility wrapper for the dashboard API."""

from .api.dashboard import build_parser, create_app, main

__all__ = ["build_parser", "create_app", "main"]

