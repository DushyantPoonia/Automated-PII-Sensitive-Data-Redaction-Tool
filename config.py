"""Flask configuration loaded from environment variables."""

from __future__ import annotations

import os


def _environment_flag(name: str, default: bool = False) -> bool:
    """Read a boolean environment setting using common truthy spellings."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Default application settings suitable for local development."""

    APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
    DEBUG = _environment_flag("FLASK_DEBUG")
    MAX_UPLOAD_SIZE = 2 * 1024 * 1024
    ALLOWED_EXTENSIONS = frozenset({"txt"})
    # Allow multipart headers while enforcing the exact file limit in file_handler.
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE + 64 * 1024
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _environment_flag(
        "SESSION_COOKIE_SECURE", default=APP_ENV == "production"
    )
    PROPAGATE_EXCEPTIONS = False