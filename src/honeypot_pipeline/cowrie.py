"""Compatibility wrapper for Cowrie parsing helpers."""

from .parsers.cowrie import iter_normalized_cowrie_events, normalize_cowrie_event

__all__ = ["iter_normalized_cowrie_events", "normalize_cowrie_event"]

