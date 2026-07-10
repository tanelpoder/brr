from __future__ import annotations

import asyncio
from threading import Condition
from typing import Any

from textual.widgets import DataTable, Static

from brr.inspection import BrrInspectReport, BrrInspectRow
from brr.models import (
    BpfInstruction,
    BpfProfile,
    BpfProfileMetadata,
    BpfProfileProgram,
    BpfProgram,
    BpfProgramActivity,
    BpfProgramDump,
    BpfSourceLine,
)
from brr.top import BrrConfig, _create_top_app


class _DelayedInspectService:
    def __init__(self) -> None:
        self.condition = Condition()
        self.activity_allowed = False
        self.activity_calls = 0
        self.started_dumps: list[int] = []
        self.released_dumps: set[int] = set()

    def allow_activity(self) -> None:
        with self.condition:
            self.activity_allowed = True
            self.condition.notify_all()

    def release_dump(self, program_id: int) -> None:
        with self.condition:
            self.released_dumps.add(program_id)
            self.condition.notify_all()

    def collect_program_activity(self, **_kwargs: Any) -> list[BpfProgramActivity]:
        with self.condition:
            self.activity_calls += 1
            self.condition.notify_all()
            allowed = self.condition.wait_for(lambda: self.activity_allowed, timeout=5)
        if not allowed:
            raise TimeoutError("test did not release activity collection")
        return [
            _activity(1, 200),
            _activity(2, 100),
        ]

    def collect_program_dump(self, program_id: int) -> BpfProgramDump:
        with self.condition:
            self.started_dumps.append(program_id)
            self.condition.notify_all()
            released = self.condition.wait_for(
                lambda: program_id in self.released_dumps,
                timeout=5,
            )
        if not released:
            raise TimeoutError(f"test did not release dump {program_id}")
        source = BpfSourceLine(
            file_name=f"program_{program_id}.bpf.c",
            line_number=program_id,
            column=1,
            source=f"return {program_id};",
        )
        return BpfProgramDump(
            program=BpfProgram(
                id=program_id,
                program_type="tracing",
                name=f"program_{program_id}",
            ),
            instructions=[BpfInstruction(0, "95000000", 0x95, 0, 0, 0, 0, source)],
            line_info_count=1,
        )


def _activity(program_id: int, run_time_ns_delta: int) -> BpfProgramActivity:
    return BpfProgramActivity(
        id=program_id,
        program_type="tracing",
        name=f"program_{program_id}",
        tag=None,
        run_count_delta=1,
        run_time_ns_delta=run_time_ns_delta,
    )


async def _wait_until(predicate, *, timeout: float = 3) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() >= deadline:
            raise AssertionError("condition was not satisfied before timeout")
        await asyncio.sleep(0.01)


def _config() -> BrrConfig:
    return BrrConfig(
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


def test_inspect_open_close_clears_rows_and_rejects_stale_worker_updates() -> None:
    service = _DelayedInspectService()

    async def exercise() -> None:
        app = _create_top_app(service, _config())  # type: ignore[arg-type]
        async with app.run_test(size=(140, 40)):
            await _wait_until(lambda: service.activity_calls == 1)
            app.refresh_paused = True
            service.allow_activity()
            await _wait_until(lambda: app.activity_ids == [1, 2])

            activity_table = app.query_one("#activity", DataTable)
            inspect_table = app.query_one("#inspect-table", DataTable)
            activity_table.move_cursor(row=0, animate=False)
            app.action_inspect()
            await _wait_until(lambda: service.started_dumps == [1])
            first_tokens = (app.inspect_token, app.render_token, app.profile_token)

            # Keep close focused on inspect state; activity refresh behavior is covered separately.
            app.activity_refreshing = True
            app.action_close_inspect()
            assert inspect_table.row_count == 0
            assert app.inspect_report is None
            assert app.inspect_dump is None
            assert (app.inspect_token, app.render_token, app.profile_token) != first_tokens

            activity_table.move_cursor(row=1, animate=False)
            app.action_inspect()
            second_tokens = (app.inspect_token, app.render_token, app.profile_token)
            assert inspect_table.row_count == 0
            assert app.inspect_loading is True
            assert str(app.query_one("#inspect-title", Static).content) == "loading program 2..."
            assert str(app.query_one("#inspect-status", Static).content) == ""

            app._handle_worker_error("inspect-load", first_tokens[0], RuntimeError("stale"))
            app._handle_worker_cancelled("inspect-render", first_tokens[1])
            app._handle_worker_success("inspect-load", first_tokens[0], object())
            app.profile_running = True
            app._handle_worker_error("profile", first_tokens[2], RuntimeError("stale"))
            app._handle_worker_cancelled("profile", first_tokens[2])
            app._handle_worker_success("profile", first_tokens[2], object())
            assert app.inspect_loading is True
            assert app.profile_running is True
            assert (app.inspect_token, app.render_token, app.profile_token) == second_tokens
            assert str(app.query_one("#inspect-status", Static).content) == ""

            service.release_dump(1)
            await _wait_until(lambda: service.started_dumps == [1, 2])
            assert inspect_table.row_count == 0
            assert app.inspect_report is None

            service.release_dump(2)
            await _wait_until(
                lambda: app.inspect_report is not None and app.inspect_report.program.id == 2
            )
            assert inspect_table.row_count == 1
            assert "program_2.bpf.c" in str(inspect_table.get_row_at(0)[2])

            app.action_close_inspect()
            assert inspect_table.row_count == 0
            assert app.inspect_report is None
            assert app.inspect_profile is None
            assert app.inspect_fold_ranges == []
            assert app.inspect_search_query == ""
            assert app.inspect_markers_visible is False

    asyncio.run(exercise())


def test_inspect_status_expands_for_wrapped_compact_profile_context() -> None:
    service = _DelayedInspectService()
    context = (
        "CPU: 150.0000% total = 120.0000% eBPF + 25.0000% under eBPF + "
        "5.0000% unaccounted (100% = one CPU)"
    )

    async def exercise() -> None:
        app = _create_top_app(service, _config())  # type: ignore[arg-type]
        async with app.run_test(size=(80, 24)) as pilot:
            app.query_one("#inspect-modal").styles.display = "block"
            status = app.query_one("#inspect-status", Static)
            status.update(context)
            await pilot.pause()

            table = app.query_one("#inspect-table", DataTable)
            assert status.size.height > 1
            assert status.size.height == status.content_size.height
            assert table.region.y >= status.region.bottom
            app.refresh_paused = True
            service.allow_activity()
            await _wait_until(lambda: app.activity_ids == [1, 2])

    asyncio.run(exercise())


def test_tui_collapsed_and_expanded_samples_each_total_one_hundred() -> None:
    service = _DelayedInspectService()
    profile_program = BpfProfileProgram(
        id=1,
        program_type="tracing",
        name="program_1",
        tag=None,
        samples=80,
        sample_percent=100,
        cpu_percent=80,
        kernel_samples=20,
        kernel_cpu_percent=20,
    )
    profile = BpfProfile(
        metadata=BpfProfileMetadata(
            requested_event="cycles",
            selected_event="cycles",
            duration=1,
            frequency=100,
            limit=1,
            line_limit=0,
            total_samples=100,
            lost_samples=0,
            unresolved_samples=0,
            actual_duration=1,
        ),
        items=[profile_program],
    )
    report = BrrInspectReport(
        program=BpfProgram(id=1, program_type="tracing", name="program_1"),
        mode="source",
        rows=[
            BrrInspectRow(
                kind="source",
                code="caller",
                samples=80,
                child_key="caller",
                has_children=True,
                attribution="direct",
            ),
            BrrInspectRow(
                kind="kernel",
                code="  -> helper",
                samples=20,
                child_key="caller",
                attribution="under",
            ),
        ],
        profile=profile,
        profile_program=profile_program,
    )

    async def exercise() -> None:
        app = _create_top_app(service, _config())  # type: ignore[arg-type]
        async with app.run_test(size=(100, 30)):
            app.refresh_paused = True
            service.allow_activity()
            await _wait_until(lambda: app.activity_ids == [1, 2])
            app.inspect_open = True
            app.inspect_profile = profile
            app.inspect_profile_program = profile_program
            app.inspect_report = report
            app.query_one("#inspect-modal").styles.display = "block"

            table = app.query_one("#inspect-table", DataTable)
            app._render_inspect_view()
            assert table.row_count == 1
            assert str(table.get_row_at(0)[0]) == "100"
            assert str(table.get_row_at(0)[1]) == "100.00"

            app.inspect_expanded_child_keys = {"caller"}
            app._render_inspect_view()
            assert table.row_count == 2
            assert [str(table.get_row_at(index)[0]) for index in range(2)] == ["80", "20"]
            assert sum(float(str(table.get_row_at(index)[1])) for index in range(2)) == 100

    asyncio.run(exercise())
