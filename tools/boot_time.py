"""Boot-time measurement (~1 s total). Not picked up by unittest discover.

    .venv/bin/python tools/boot_time.py
"""

import asyncio
import time

from mintguard.ui.app import MintGuardApp


async def main() -> None:
    samples = []
    for _ in range(3):
        t0 = time.perf_counter()
        app = MintGuardApp()  # includes distro detection + system info
        t1 = time.perf_counter()
        async with app.run_test(size=(120, 38)) as pilot:
            await pilot.pause()
            t2 = time.perf_counter()
        samples.append((t1 - t0, t2 - t1))
    for construction, mount in samples:
        print(
            f"construccion={construction*1000:6.0f} ms   "
            f"primer-frame={mount*1000:6.0f} ms   "
            f"total={(construction+mount)*1000:6.0f} ms"
        )


asyncio.run(main())
