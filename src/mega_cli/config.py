"""Application paths and constants."""

from pathlib import Path

from platformdirs import user_config_path

from mega_cli import CLI_NAME


def config_dir() -> Path:
    """Return the platform-specific configuration directory."""
    return user_config_path(CLI_NAME, ensure_exists=False)
