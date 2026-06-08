"""Compatibility wrapper for risk scoring."""

from .analysis.risk import risk_level, score_event_record, score_session_snapshot

__all__ = ["risk_level", "score_event_record", "score_session_snapshot"]

