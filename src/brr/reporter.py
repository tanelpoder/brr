from __future__ import annotations

from dataclasses import dataclass

from brr.collector.service import BpfSnapshotService
from brr.models import (
    BpfHotspot,
    BpfInstruction,
    BpfProfile,
    BpfProfileProgram,
    BpfProgram,
    BpfProgramActivity,
)


@dataclass(frozen=True, slots=True)
class BrrActivityItem:
    activity: BpfProgramActivity
    bpf_percent: float


@dataclass(frozen=True, slots=True)
class BrrActivityReport:
    duration: float
    items: list[BrrActivityItem]


@dataclass(frozen=True, slots=True)
class BrrSourceLine:
    first_offset: int
    instruction_count: int
    file_name: str | None
    line_number: int | None
    column: int | None
    source: str | None
    samples: int = 0
    sample_percent: float = 0.0
    cpu_percent: float = 0.0


@dataclass(frozen=True, slots=True)
class BrrDetailReport:
    program: BpfProgram
    profile: BpfProfile
    profile_program: BpfProfileProgram | None
    source_lines: list[BrrSourceLine]


@dataclass(frozen=True, slots=True)
class _HotspotTotal:
    samples: int
    sample_percent: float
    cpu_percent: float


def collect_activity_report(
    service: BpfSnapshotService,
    *,
    duration: float,
    include_all: bool,
    limit: int,
) -> BrrActivityReport:
    activities = service.collect_program_activity(
        duration=duration,
        include_all=include_all,
        limit=limit,
    )
    return BrrActivityReport(
        duration=duration,
        items=[
            BrrActivityItem(
                activity=activity,
                bpf_percent=_bpf_percent(activity.run_time_ns_delta, duration=duration),
            )
            for activity in activities
        ],
    )


def collect_detail_report(
    service: BpfSnapshotService,
    program_id: int,
    *,
    requested_event: str,
    duration: float,
    frequency: int,
    line_limit: int,
    source_limit: int,
) -> BrrDetailReport:
    dump = service.collect_program_dump(program_id)
    profile = service.collect_profile_for_program(
        program_id,
        requested_event=requested_event,
        duration=duration,
        frequency=frequency,
        line_limit=line_limit,
    )
    profile_program = profile.items[0] if profile.items else None
    hotspots = profile_program.hotspots if profile_program is not None else []
    return BrrDetailReport(
        program=dump.program,
        profile=profile,
        profile_program=profile_program,
        source_lines=annotate_source_lines(
            dump.program.id,
            dump.instructions,
            hotspots=hotspots,
            source_limit=source_limit,
        ),
    )


def annotate_source_lines(
    _program_id: int,
    instructions: list[BpfInstruction],
    *,
    hotspots: list[BpfHotspot],
    source_limit: int,
) -> list[BrrSourceLine]:
    rows = _unique_source_lines(instructions)
    if not rows:
        return []

    annotated = _annotate_source_rows(rows, hotspots)
    annotated.sort(key=_source_line_sort_key)

    hot_indexes = [index for index, row in enumerate(annotated) if row.samples > 0]
    if source_limit > 0 and hot_indexes:
        selected_indexes: set[int] = set()
        for index in hot_indexes:
            selected_indexes.update(range(max(0, index - 2), min(len(annotated), index + 3)))
        selected = [annotated[index] for index in sorted(selected_indexes)]
    else:
        selected = annotated

    if source_limit > 0:
        return selected[:source_limit]
    return selected


def annotate_instruction_source_lines(
    _program_id: int,
    instructions: list[BpfInstruction],
    *,
    hotspots: list[BpfHotspot],
) -> list[BrrSourceLine]:
    rows = _unique_source_lines(instructions)
    if not rows:
        return []
    return _annotate_source_rows(rows, hotspots)


def _annotate_source_rows(
    rows: list[BrrSourceLine],
    hotspots: list[BpfHotspot],
) -> list[BrrSourceLine]:
    hotspot_by_key = _aggregate_hotspots(hotspots)
    annotated: list[BrrSourceLine] = []
    for row in rows:
        hotspot = hotspot_by_key.get(_line_key(row.file_name, row.line_number, row.source))
        annotated.append(
            BrrSourceLine(
                first_offset=row.first_offset,
                instruction_count=row.instruction_count,
                file_name=row.file_name,
                line_number=row.line_number,
                column=row.column,
                source=row.source,
                samples=hotspot.samples if hotspot is not None else 0,
                sample_percent=hotspot.sample_percent if hotspot is not None else 0.0,
                cpu_percent=hotspot.cpu_percent if hotspot is not None else 0.0,
            )
        )
    return annotated


def _unique_source_lines(instructions: list[BpfInstruction]) -> list[BrrSourceLine]:
    rows: list[BrrSourceLine] = []
    indexes: dict[tuple[str | None, int | None, str | None], int] = {}
    for instruction in instructions:
        source = instruction.source
        if source is None or (
            source.file_name is None and source.line_number is None and source.source is None
        ):
            continue
        key = _line_key(source.file_name, source.line_number, source.source)
        existing = indexes.get(key)
        if existing is None:
            indexes[key] = len(rows)
            rows.append(
                BrrSourceLine(
                    first_offset=instruction.offset,
                    instruction_count=1,
                    file_name=source.file_name,
                    line_number=source.line_number,
                    column=source.column,
                    source=source.source,
                )
            )
            continue
        row = rows[existing]
        rows[existing] = BrrSourceLine(
            first_offset=row.first_offset,
            instruction_count=row.instruction_count + 1,
            file_name=row.file_name,
            line_number=row.line_number,
            column=row.column,
            source=row.source,
            samples=row.samples,
            sample_percent=row.sample_percent,
            cpu_percent=row.cpu_percent,
        )
    return rows


def _line_key(
    file_name: str | None,
    line_number: int | None,
    source: str | None,
) -> tuple[str | None, int | None, str | None]:
    return (file_name, line_number, source)


def _source_line_sort_key(row: BrrSourceLine) -> tuple[int, int, str, int]:
    return (
        row.line_number if row.line_number is not None else 2**31,
        row.column if row.column is not None else 2**31,
        row.file_name or "",
        row.first_offset,
    )


def _aggregate_hotspots(
    hotspots: list[BpfHotspot],
) -> dict[tuple[str | None, int | None, str | None], _HotspotTotal]:
    totals: dict[tuple[str | None, int | None, str | None], _HotspotTotal] = {}
    for hotspot in hotspots:
        key = _line_key(hotspot.file_name, hotspot.line_number, hotspot.source)
        current = totals.get(key, _HotspotTotal(samples=0, sample_percent=0.0, cpu_percent=0.0))
        totals[key] = _HotspotTotal(
            samples=current.samples + hotspot.samples,
            sample_percent=round(current.sample_percent + hotspot.sample_percent, 2),
            cpu_percent=round(current.cpu_percent + hotspot.cpu_percent, 4),
        )
    return totals


def _bpf_percent(run_time_ns_delta: int, *, duration: float) -> float:
    if duration <= 0:
        return 0.0
    return round((run_time_ns_delta / (duration * 1_000_000_000)) * 100, 4)
