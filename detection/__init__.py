"""Reusable PII detection package, independent of the Flask application."""

from .pii_detector import detect_pii

__all__ = ["detect_pii"]