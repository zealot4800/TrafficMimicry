"""
Statistical helper functions shared across analysis scripts.
"""

from __future__ import annotations

def safe_slug(name: str) -> str:
    """
    Return a filesystem-safe slug version of the provided name.
    """
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name.lower())

