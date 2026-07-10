from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import nullcontext
from typing import TypeVar

from brr.collector.bpffs import BpffsScanner
from brr.collector.syscall import SyscallBpfCollector
from brr.models import (
    BpfLink,
    BpfMap,
    BpfProfile,
    BpfProgram,
    BpfProgramActivity,
    BpfProgramDetails,
    BpfProgramDump,
    BpfSnapshot,
    BtfObject,
)
from brr.profiler import (
    CallGraphMode,
    KallsymsResolver,
    PerfEventAvailability,
    PerfSampler,
    ProfileAccumulator,
    choose_perf_event,
    list_openable_perf_events,
)

T = TypeVar("T", BpfProgram, BpfMap, BpfLink, BtfObject)


class BpfSnapshotService:
    def __init__(
        self,
        collector: SyscallBpfCollector,
        bpffs_scanner: BpffsScanner,
        profiler: PerfSampler | None = None,
    ) -> None:
        self.collector = collector
        self.bpffs_scanner = bpffs_scanner
        self.profiler = profiler

    def collect_programs(self, *, with_stats: bool = False) -> list[BpfProgram]:
        context = self.collector.enable_runtime_stats() if with_stats else nullcontext()
        with context:
            programs = self.collector.list_programs()
        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["program"]
        return self._sort_and_attach(programs, pinned)

    def collect_program_activity(
        self,
        *,
        duration: float,
        include_all: bool = False,
        limit: int = 20,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> list[BpfProgramActivity]:
        with self.collector.enable_runtime_stats():
            baseline = self.collector.list_programs()
            sleeper(duration)
            current = self.collector.list_programs()

        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["program"]
        baseline_by_id = {program.id: program for program in baseline}
        activities = [
            self._program_activity(
                current_program,
                baseline_by_id.get(current_program.id),
                pinned.get(current_program.id, ()),
            )
            for current_program in current
        ]
        if not include_all:
            activities = [
                activity
                for activity in activities
                if activity.run_count_delta > 0 or activity.run_time_ns_delta > 0
            ]
        activities.sort(
            key=lambda activity: (
                -activity.run_time_ns_delta,
                -activity.run_count_delta,
                activity.id,
            )
        )
        if limit > 0:
            return activities[:limit]
        return activities

    def collect_program_dump(self, program_id: int) -> BpfProgramDump:
        details = self.collect_program_details(program_id)
        return BpfProgramDump(
            program=details.program,
            instructions=details.instructions,
            line_info_count=len(details.line_info),
            jit_ranges=details.jit_ranges,
        )

    def collect_profile(
        self,
        *,
        requested_event: str,
        duration: float,
        frequency: int,
        limit: int,
        line_limit: int,
        kernel_samples: bool = False,
        call_graph: CallGraphMode = "fp",
        perf_buffer_pages: int | None = None,
        perf_drain_ms: int | None = None,
    ) -> BpfProfile:
        selected_event = choose_perf_event(
            requested_event,
            opener=self._profiler().opener,
            frequency=frequency,
        )
        details = self.collector.list_program_details()
        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["program"]
        details = self._attach_program_details_pins(details, pinned)
        accumulator = ProfileAccumulator(
            program_details=details,
            requested_event=requested_event,
            selected_event=selected_event.name,
            duration=duration,
            frequency=frequency,
            limit=limit,
            line_limit=line_limit,
            kernel_samples=kernel_samples,
            call_graph=call_graph,
            kernel_symbol_resolver=KallsymsResolver.from_proc() if kernel_samples else None,
        )
        result = self._profiler().sample(
            event=selected_event,
            duration=duration,
            frequency=frequency,
            callchain=kernel_samples,
            call_graph=call_graph,
            buffer_pages=perf_buffer_pages,
            drain_interval_ms=perf_drain_ms,
            on_samples=accumulator.consume,
        )
        return accumulator.finish(capture=result)

    def collect_profile_for_program(
        self,
        program_id: int,
        *,
        requested_event: str,
        duration: float,
        frequency: int,
        line_limit: int,
        kernel_samples: bool = False,
        call_graph: CallGraphMode = "fp",
        perf_buffer_pages: int | None = None,
        perf_drain_ms: int | None = None,
    ) -> BpfProfile:
        selected_event = choose_perf_event(
            requested_event,
            opener=self._profiler().opener,
            frequency=frequency,
        )
        details = self.collector.list_program_details()
        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["program"]
        details = self._attach_program_details_pins(details, pinned)
        accumulator = ProfileAccumulator(
            program_details=details,
            requested_event=requested_event,
            selected_event=selected_event.name,
            duration=duration,
            frequency=frequency,
            limit=1,
            line_limit=line_limit,
            selected_program_id=program_id,
            kernel_samples=kernel_samples,
            call_graph=call_graph,
            kernel_symbol_resolver=KallsymsResolver.from_proc() if kernel_samples else None,
        )
        result = self._profiler().sample(
            event=selected_event,
            duration=duration,
            frequency=frequency,
            callchain=kernel_samples,
            call_graph=call_graph,
            buffer_pages=perf_buffer_pages,
            drain_interval_ms=perf_drain_ms,
            on_samples=accumulator.consume,
        )
        return accumulator.finish(capture=result)

    def collect_perf_events(self, *, frequency: int = 997) -> list[PerfEventAvailability]:
        return list_openable_perf_events(opener=self._profiler().opener, frequency=frequency)

    def collect_program_details(self, program_id: int) -> BpfProgramDetails:
        details = self.collector.get_program_details_by_id(program_id)
        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["program"]
        details.program.pinned_paths = pinned.get(details.program.id, ())
        return details

    def collect_maps(self) -> list[BpfMap]:
        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["map"]
        return self._sort_and_attach(self.collector.list_maps(), pinned)

    def collect_links(self) -> list[BpfLink]:
        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["link"]
        return self._sort_and_attach(self.collector.list_links(), pinned)

    def collect_btfs(self) -> list[BtfObject]:
        pinned = self.bpffs_scanner.scan_pinned_paths(self.collector)["btf"]
        return self._sort_and_attach(self.collector.list_btfs(), pinned)

    def collect_snapshot(self, *, with_stats: bool = False) -> BpfSnapshot:
        return BpfSnapshot(
            programs=self.collect_programs(with_stats=with_stats),
            maps=self.collect_maps(),
            links=self.collect_links(),
            btfs=self.collect_btfs(),
        )

    def _sort_and_attach(self, objects: list[T], pinned: dict[int, tuple[str, ...]]) -> list[T]:
        enriched = [self._replace_pinned_paths(obj, pinned.get(obj.id, ())) for obj in objects]
        enriched.sort(key=lambda obj: obj.id)
        return enriched

    def _attach_program_details_pins(
        self,
        details: list[BpfProgramDetails],
        pinned: dict[int, tuple[str, ...]],
    ) -> list[BpfProgramDetails]:
        for detail in details:
            detail.program.pinned_paths = pinned.get(detail.program.id, ())
        details.sort(key=lambda detail: detail.program.id)
        return details

    def _profiler(self) -> PerfSampler:
        if self.profiler is None:
            self.profiler = PerfSampler()
        return self.profiler

    def _replace_pinned_paths(self, obj: T, pinned_paths: tuple[str, ...]) -> T:
        if not pinned_paths:
            return obj
        obj.pinned_paths = pinned_paths
        return obj

    def _program_activity(
        self,
        current: BpfProgram,
        baseline: BpfProgram | None,
        pinned_paths: tuple[str, ...],
    ) -> BpfProgramActivity:
        baseline_run_count = (
            baseline.run_count if baseline is not None and baseline.run_count else 0
        )
        baseline_run_time_ns = (
            baseline.run_time_ns if baseline is not None and baseline.run_time_ns else 0
        )
        current_run_count = current.run_count or 0
        current_run_time_ns = current.run_time_ns or 0
        return BpfProgramActivity(
            id=current.id,
            program_type=current.program_type,
            name=current.name,
            tag=current.tag,
            run_count_delta=max(0, current_run_count - baseline_run_count),
            run_time_ns_delta=max(0, current_run_time_ns - baseline_run_time_ns),
            run_count_total=current_run_count,
            run_time_ns_total=current_run_time_ns,
            xlated_size_bytes=current.xlated_size_bytes,
            jited_size_bytes=current.jited_size_bytes,
            pinned_paths=pinned_paths,
        )
