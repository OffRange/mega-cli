from importlib.metadata import PackageNotFoundError, version

# must match [project].name in pyproject.toml
CLI_NAME = "mega-cli"

try:
    __version__ = version(CLI_NAME)
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
