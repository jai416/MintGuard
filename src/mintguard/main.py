"""Application entrypoint."""

from __future__ import annotations

import sys

from mintguard import __version__
from mintguard.ui.app import MintGuardApp


def main() -> None:
    if "--version" in sys.argv:
        print(f"MintGuard {__version__}")
        return
    MintGuardApp().run()


if __name__ == "__main__":
    main()
