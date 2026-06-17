from __future__ import annotations


class BrrError(Exception):
    """Base exception for expected CLI failures."""

    exit_code = 1


class PermissionDeniedError(BrrError):
    """Raised when kernel state cannot be accessed with current privileges."""

    exit_code = 2


class UnsupportedFeatureError(BrrError):
    """Raised when required kernel features are unavailable."""

    exit_code = 3
