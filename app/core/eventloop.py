"""Event loop factory helpers.

uvicorn's bundled loop factories run ``asyncio.SelectorEventLoop`` in
subprocess-based deployments (``--reload`` or ``--workers``). On Windows the
``SelectorEventLoop`` cannot spawn subprocesses, which is a hard requirement of
Playwright's node driver during the design-system browser startup. This module
provides a factory that always yields the Windows ``ProactorEventLoop`` so the
app behaves identically regardless of reload/worker mode.

Use it with uvicorn's ``--loop`` option:

    uvicorn app.main:app --reload --loop app.core.eventloop:proactor_event_loop

On non-Windows platforms a regular event loop is created instead.
"""

from __future__ import annotations

import asyncio
import sys


def proactor_event_loop() -> asyncio.AbstractEventLoop:
    """Create an event loop that supports subprocesses on Windows."""
    if sys.platform == "win32":
        return asyncio.ProactorEventLoop()
    return asyncio.new_event_loop()


__all__ = ["proactor_event_loop"]
