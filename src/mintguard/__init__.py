"""MintGuard: TUI de seguridad ligera en español para Linux."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Single source of truth: pyproject.toml (the installed package's metadata).
# A hardcoded number here drifted from pyproject (0.2.0 vs 0.3.0 was seen
# in the wild the day of the first release).
try:
    __version__ = _pkg_version("mintguard")
except PackageNotFoundError:  # running from the source tree without installing
    __version__ = "0.3.0"
