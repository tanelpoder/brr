from __future__ import annotations

import asyncio
from contextlib import nullcontext
from threading import Condition
from typing import Any

from brr.collector.service import BpfSnapshotService
from brr.models import BpfProgram, BpfProgramActivity
from brr.top import BrrConfig, _create_top_app


class _SnapshotCollector:
    def __init__(self, snapshots: list[list[BpfProgram]]) -> None:
        self.snapshots = iter(snapshots)

    def enable_runtime_stats(self):
        return nullcontext()

    def list_programs(self) -> list[BpfProgram]:
        return next(self.snapshots)


class _EmptyBpffsScanner:
    def scan_pinned_paths(self, _collector: object) -> dict[str, dict[int, tuple[str, ...]]]:
        return {kind: {} for kind in ("program", "map", "link", "btf")}


def _program(
    program_id: int,
    *,
    run_count: int,
    run_time_ns: int,
) -> BpfProgram:
    return BpfProgram(
        id=program_id,
        program_type="tracing",
        name=f"program_{program_id}",
        run_count=run_count,
        run_time_ns=run_time_ns,
    )


def test_activity_window_discovers_new_program_and_drops_unloaded_program() -> None:
    collector = _SnapshotCollector(
        [
            [
                _program(1, run_count=10, run_time_ns=1_000),
                _program(2, run_count=20, run_time_ns=2_000),
            ],
            [
                _program(1, run_count=15, run_time_ns=1_500),
                _program(3, run_count=7, run_time_ns=900),
            ],
        ]
    )
    service = BpfSnapshotService(collector, _EmptyBpffsScanner())  # type: ignore[arg-type]

    activities = service.collect_program_activity(
        duration=1,
        include_all=True,
        limit=0,
        sleeper=lambda _duration: None,
    )

    assert [activity.id for activity in activities] == [3, 1]
    new_program = next(activity for activity in activities if activity.id == 3)
    assert new_program.run_count_delta == 7
    assert new_program.run_time_ns_delta == 900
    assert all(activity.id != 2 for activity in activities)


def _activity(program_id: int, run_time_ns_delta: int) -> BpfProgramActivity:
    return BpfProgramActivity(
        id=program_id,
        program_type="tracing",
        name=f"program_{program_id}",
        tag=None,
        run_count_delta=1,
        run_time_ns_delta=run_time_ns_delta,
        run_count_total=1,
        run_time_ns_total=run_time_ns_delta,
    )


class _SequencedActivityService:
    def __init__(self, reports: list[list[BpfProgramActivity]]) -> None:
        self.reports = reports
        self.condition = Condition()
        self.allowed_calls = 0
        self.calls = 0
        self.active_calls = 0
        self.max_active_calls = 0

    def allow_call(self, count: int) -> None:
        with self.condition:
            self.allowed_calls = count
            self.condition.notify_all()

    def collect_program_activity(self, **_kwargs: Any) -> list[BpfProgramActivity]:
        with self.condition:
            index = self.calls
            self.calls += 1
            self.active_calls += 1
            self.max_active_calls = max(self.max_active_calls, self.active_calls)
            allowed = self.condition.wait_for(
                lambda: self.allowed_calls > index,
                timeout=5,
            )
            self.active_calls -= 1
        if not allowed:
            raise TimeoutError("test did not release activity refresh")
        return self.reports[index]


async def _wait_until(predicate, *, timeout: float = 3) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() >= deadline:
            raise AssertionError("condition was not satisfied before timeout")
        await asyncio.sleep(0.01)


def test_live_top_chains_windows_and_updates_program_inventory() -> None:
    service = _SequencedActivityService(
        [
            [_activity(1, 100)],
            [_activity(2, 300), _activity(1, 100)],
            [_activity(2, 250)],
        ]
    )
    config = BrrConfig(
        bpffs="/sys/fs/bpf",
        delay=60,
        limit=0,
        include_all=True,
        event="auto",
        profile_duration=5,
        frequency=997,
        line_limit=5,
        source_limit=0,
        inspect_mode="source",
        theme="textual-dark",
    )

    async def exercise() -> None:
        app = _create_top_app(service, config)  # type: ignore[arg-type]
        async with app.run_test(size=(140, 40)):
            await _wait_until(lambda: service.calls == 1)
            service.allow_call(1)
            await _wait_until(lambda: app.activity_ids == [1])

            await _wait_until(lambda: service.calls == 2)
            service.allow_call(2)
            await _wait_until(lambda: app.activity_ids == [2, 1])

            await _wait_until(lambda: service.calls == 3)
            app.refresh_paused = True
            service.allow_call(3)
            await _wait_until(lambda: app.activity_ids == [2])
            await asyncio.sleep(0.05)

            assert service.calls == 3
            assert service.max_active_calls == 1

    asyncio.run(exercise())
