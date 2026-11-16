"""Application paths and constants."""

from pathlib import Path

from platformdirs import user_config_path

APP_NAME = "mega-cli"


def config_dir() -> Path:
    """Return the platform-specific configuration directory."""
    return user_config_path(APP_NAME, ensure_exists=False)
