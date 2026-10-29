from __future__ import annotations

import asyncio

from model_harrier.db import store
from model_harrier.tui import ModelHarrierApp


def test_tui_mounts_and_navigates_without_database(monkeypatch) -> None:
    monkeypatch.setattr(store, "init_db", lambda: None)
    monkeypatch.setattr(store, "get_scan_history", lambda limit=50: [])
    monkeypatch.setattr(store, "get_watch_targets", lambda: [])

    async def exercise() -> None:
        app = ModelHarrierApp()
        async with app.run_test(size=(120, 40)) as pilot:
            assert app.query_one("#home").has_class("active")
            await pilot.click("#nav-scan")
            assert app.query_one("#scan").has_class("active")
            await pilot.click("#nav-history")
            assert app.query_one("#history").has_class("active")

    asyncio.run(exercise())
