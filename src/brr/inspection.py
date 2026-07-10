from __future__ import annotations

import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any, Literal

from brr.collector.service import BpfSnapshotService
from brr.models import (
    BpfHotspot,
    BpfInstruction,
    BpfJitRange,
    BpfKernelHotspot,
    BpfProfile,
    BpfProfileMetadata,
    BpfProfileProgram,
    BpfProgram,
    BpfProgramDump,
)
from brr.profiler import CallGraphMode
from brr.reporter import BrrSourceLine, annotate_instruction_source_lines

InspectMode = Literal["source", "mixed"]
InspectRowKind = Literal["source", "instruction", "fold", "context", "kernel"]
MANY_INSTRUCTIONS_MARKER_THRESHOLD = 8
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".hxx")
MARKER_DESCRIPTIONS: tuple[tuple[str, str], ...] = (
    ("source-mismatch", "BTF source snippet differs from resolved local source."),
    ("unmapped", "Instruction has no source-line metadata."),
    ("split", "Same source line appears in multiple non-contiguous instruction blocks."),
    ("backjump", "Mapped instruction order moves backward within the same file."),
    ("file-switch", "Adjacent mapped blocks switch source files."),
    ("header", "Mapped source file has a header suffix."),
    ("same-line-cols", "Same source line maps through multiple BTF columns."),
    (
        "many-insns",
        "One source line maps to at least "
        f"{MANY_INSTRUCTIONS_MARKER_THRESHOLD} translated instructions.",
    ),
)


@dataclass(frozen=True, slots=True)
class BpftoolInstruction:
    disasm: str
    source: str | None = None
    file_name: str | None = None
    line_number: int | None = None
    column: int | None = None


@dataclass(frozen=True, slots=True)
class BrrInspectRow:
    kind: InspectRowKind
    code: str
    samples: int = 0
    sample_percent: float = 0.0
    cpu_percent: float = 0.0
    file_name: str | None = None
    line_number: int | None = None
    column: int | None = None
    offset: int | None = None
    markers: tuple[str, ...] = ()
    child_key: str | None = None
    has_children: bool = False
    children_expanded: bool = True

    @property
    def weight(self) -> str:
        return str(self.samples) if self.samples > 0 else ""

    def display_code(self, *, show_markers: bool = True) -> str:
        prefix = ""
        if self.has_children:
            prefix = "- " if self.children_expanded else "+ "
        code = f"{prefix}{self.code}"
        if not show_markers or not self.markers:
            return code
        return f"{code} {_format_markers(self.markers)}"


@dataclass(frozen=True, slots=True)
class BrrInspectReport:
    program: BpfProgram
    mode: InspectMode
    rows: list[BrrInspectRow]
    profile: BpfProfile | None = None
    profile_program: BpfProfileProgram | None = None
    instruction_source: str = "internal"

    @property
    def profiled(self) -> bool:
        return self.profile is not None


def with_inspect_marker(row: BrrInspectRow, marker: str) -> BrrInspectRow:
    if marker in row.markers:
        return row
    marker_set = {*row.markers, marker}
    return BrrInspectRow(
        kind=row.kind,
        code=row.code,
        samples=row.samples,
        sample_percent=row.sample_percent,
        cpu_percent=row.cpu_percent,
        file_name=row.file_name,
        line_number=row.line_number,
        column=row.column,
        offset=row.offset,
        markers=tuple(item for item in _marker_order() if item in marker_set),
        child_key=row.child_key,
        has_children=row.has_children,
        children_expanded=row.children_expanded,
    )


def profile_status_message(
    *,
    program_id: int,
    profile: BpfProfile,
    profile_program: BpfProfileProgram | None,
    has_mapped_source_samples: bool,
) -> str:
    metadata = profile.metadata
    selected_samples = (
        metadata.selected_program_samples
        if metadata.selected_program_samples > 0 or profile_program is None
        else profile_program.samples
    )
    selected_kernel_samples = profile_program.kernel_samples if profile_program is not None else 0
    selected_inclusive_samples = (
        profile_program.inclusive_samples
        if profile_program is not None
        else selected_samples + selected_kernel_samples
    )
    outside_bpf_samples = (
        metadata.non_bpf_samples if metadata.non_bpf_samples > 0 else metadata.unresolved_samples
    )
    source_mapped_samples = (
        metadata.source_mapped_samples
        if metadata.source_mapped_samples > 0 or not has_mapped_source_samples
        else selected_samples
    )
    base = (
        f"profiled {program_id}: event={metadata.selected_event} "
        f"total_samples={metadata.total_samples} "
        f"lost={metadata.lost_samples} "
        f"buffer={metadata.perf_buffer_pages_per_cpu}pages/cpu "
        f"occupancy={metadata.perf_max_ring_occupancy_percent:.1f}% "
        f"running={metadata.perf_running_percent:.2f}%; "
        f"selected program samples={selected_samples}; "
        f"attributed kernel/helper samples={selected_kernel_samples}; "
        f"other BPF program samples={metadata.other_bpf_samples}; "
        f"outside BPF samples={outside_bpf_samples}"
    )
    if selected_inclusive_samples == 0:
        return _with_profile_warnings(
            f"{base}; no samples captured in selected program",
            metadata.warnings,
        )
    if source_mapped_samples:
        message = f"{base}; source mapped={source_mapped_samples}"
        if metadata.source_unmapped_samples:
            message = f"{message}; source unmapped={metadata.source_unmapped_samples}"
        return _with_profile_warnings(
            f"{message}; source annotations use inclusive selected program samples",
            metadata.warnings,
        )
    return _with_profile_warnings(
        f"{base}; selected program samples had no source-line mapping; "
        "source annotations use inclusive selected program samples",
        metadata.warnings,
    )


def _with_profile_warnings(message: str, warnings: tuple[str, ...]) -> str:
    if not warnings:
        return message
    return f"{message}; Warning: {'; '.join(warnings)}"


BpftoolProvider = Callable[[int], list[BpftoolInstruction]]


def collect_inspect_report(
    service: BpfSnapshotService,
    program_id: int,
    *,
    mode: InspectMode,
    profile: bool,
    requested_event: str,
    duration: float,
    frequency: int,
    line_limit: int,
    kernel_samples: bool = False,
    call_graph: CallGraphMode = "fp",
    perf_buffer_pages: int | None = None,
    perf_drain_ms: int | None = None,
    bpftool_provider: BpftoolProvider | None = None,
) -> BrrInspectReport:
    dump = service.collect_program_dump(program_id)
    profile_result: BpfProfile | None = None
    profile_program: BpfProfileProgram | None = None
    hotspots: list[BpfHotspot] = []
    kernel_hotspots: list[BpfKernelHotspot] = []
    if profile:
        profile_result = service.collect_profile_for_program(
            program_id,
            requested_event=requested_event,
            duration=duration,
            frequency=frequency,
            line_limit=line_limit,
            kernel_samples=kernel_samples,
            call_graph=call_graph,
            perf_buffer_pages=perf_buffer_pages,
            perf_drain_ms=perf_drain_ms,
        )
        profile_program = profile_result.items[0] if profile_result.items else None
        hotspots = profile_program.hotspots if profile_program is not None else []
        kernel_hotspots = profile_program.kernel_hotspots if profile_program is not None else []

    report = build_inspect_report(
        dump,
        mode=mode,
        hotspots=hotspots,
        kernel_hotspots=kernel_hotspots,
        bpftool_provider=bpftool_provider or collect_bpftool_xlated,
    )
    return BrrInspectReport(
        program=report.program,
        mode=report.mode,
        rows=report.rows,
        profile=profile_result,
        profile_program=profile_program,
        instruction_source=report.instruction_source,
    )


def build_inspect_report(
    dump: BpfProgramDump,
    *,
    mode: InspectMode,
    hotspots: list[BpfHotspot],
    kernel_hotspots: list[BpfKernelHotspot] | None = None,
    bpftool_provider: BpftoolProvider | None = None,
) -> BrrInspectReport:
    kernel_hotspots = kernel_hotspots or []
    inclusive_hotspots = [*hotspots, *_bpf_hotspots_from_kernel_hotspots(kernel_hotspots)]
    kernel_children = _kernel_children_by_source(kernel_hotspots)
    source_lines = annotate_instruction_source_lines(
        dump.program.id,
        dump.instructions,
        hotspots=inclusive_hotspots,
    )
    source_markers = _source_markers(dump.instructions, source_lines)
    if mode == "source":
        return BrrInspectReport(
            program=dump.program,
            mode=mode,
            rows=_source_rows(
                source_lines,
                dump.instructions,
                source_markers=source_markers,
                kernel_children=kernel_children,
            ),
        )

    bpftool_instructions: list[BpftoolInstruction] = []
    instruction_source = "internal"
    if bpftool_provider is not None:
        bpftool_instructions = bpftool_provider(dump.program.id)
        if bpftool_instructions:
            instruction_source = "bpftool"

    return BrrInspectReport(
        program=dump.program,
        mode=mode,
        rows=_mixed_rows(
            source_lines,
            dump.instructions,
            hotspots=hotspots,
            jit_ranges=dump.jit_ranges,
            bpftool_instructions=bpftool_instructions,
            source_markers=source_markers,
            kernel_children=kernel_children,
        ),
        instruction_source=instruction_source,
    )


def collect_bpftool_xlated(program_id: int) -> list[BpftoolInstruction]:
    try:
        completed = subprocess.run(
            ["bpftool", "-j", "prog", "dump", "xlated", "id", str(program_id), "linum"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    return _parse_bpftool_instructions(payload)


def profile_metadata_for_empty(
    *,
    requested_event: str,
    duration: float,
    frequency: int,
    line_limit: int,
) -> BpfProfileMetadata:
    return BpfProfileMetadata(
        requested_event=requested_event,
        selected_event=requested_event,
        duration=duration,
        frequency=frequency,
        limit=1,
        line_limit=line_limit,
        total_samples=0,
        lost_samples=0,
        unresolved_samples=0,
    )


def _bpf_hotspots_from_kernel_hotspots(
    kernel_hotspots: list[BpfKernelHotspot],
) -> list[BpfHotspot]:
    return [
        BpfHotspot(
            samples=hotspot.samples,
            sample_percent=hotspot.sample_percent,
            cpu_percent=hotspot.cpu_percent,
            jited_address=hotspot.bpf_jited_address,
            file_name=hotspot.bpf_file_name,
            line_number=hotspot.bpf_line_number,
            column=hotspot.bpf_column,
            source=hotspot.bpf_source,
        )
        for hotspot in kernel_hotspots
    ]


def _kernel_children_by_source(
    kernel_hotspots: list[BpfKernelHotspot],
) -> dict[tuple[str | None, int | None, str | None], list[BrrInspectRow]]:
    children: dict[tuple[str | None, int | None, str | None], list[BrrInspectRow]] = {}
    for hotspot in kernel_hotspots:
        key = _line_key(hotspot.bpf_file_name, hotspot.bpf_line_number, hotspot.bpf_source)
        children.setdefault(key, []).append(
            BrrInspectRow(
                kind="kernel",
                code=_format_kernel_child(hotspot),
                samples=hotspot.samples,
                sample_percent=hotspot.sample_percent,
                cpu_percent=hotspot.cpu_percent,
                file_name=hotspot.bpf_file_name,
                line_number=hotspot.bpf_line_number,
                column=hotspot.bpf_column,
                offset=None,
                child_key=_child_key(key),
            )
        )
    return children


def _format_kernel_child(hotspot: BpfKernelHotspot) -> str:
    symbol = hotspot.symbol or f"0x{hotspot.ip:x}"
    if hotspot.symbol_offset:
        symbol = f"{symbol}+0x{hotspot.symbol_offset:x}"
    module = f" [{hotspot.module}]" if hotspot.module else ""
    return f"  -> {hotspot.symbol_kind} {symbol}{module}"


def _source_rows(
    source_lines: list[BrrSourceLine],
    instructions: list[BpfInstruction],
    *,
    source_markers: dict[tuple[str | None, int | None, str | None], tuple[str, ...]],
    kernel_children: dict[tuple[str | None, int | None, str | None], list[BrrInspectRow]],
) -> list[BrrInspectRow]:
    if source_lines:
        rows: list[BrrInspectRow] = []
        for line in source_lines:
            key = _line_key(line.file_name, line.line_number, line.source)
            child_rows = kernel_children.get(key, [])
            rows.append(
                BrrInspectRow(
                    kind="source",
                    code=_format_source_line(line),
                    samples=line.samples,
                    sample_percent=line.sample_percent,
                    cpu_percent=line.cpu_percent,
                    file_name=line.file_name,
                    line_number=line.line_number,
                    column=line.column,
                    offset=line.first_offset,
                    markers=source_markers.get(key, ()),
                    child_key=_child_key(key) if child_rows else None,
                    has_children=bool(child_rows),
                    children_expanded=True,
                )
            )
            rows.extend(child_rows)
        return rows
    return [_instruction_row(instruction, None) for instruction in instructions]


def _mixed_rows(
    source_lines: list[BrrSourceLine],
    instructions: list[BpfInstruction],
    *,
    hotspots: list[BpfHotspot],
    jit_ranges: list[BpfJitRange],
    bpftool_instructions: Sequence[BpftoolInstruction],
    source_markers: dict[tuple[str | None, int | None, str | None], tuple[str, ...]],
    kernel_children: dict[tuple[str | None, int | None, str | None], list[BrrInspectRow]],
) -> list[BrrInspectRow]:
    source_by_key = {
        _line_key(line.file_name, line.line_number, line.source): line for line in source_lines
    }
    instruction_weights = _instruction_hotspot_weights(
        hotspots,
        jit_ranges=jit_ranges,
        instructions=instructions,
    )
    previous_source_key: tuple[str | None, int | None, str | None] | None = None
    rows: list[BrrInspectRow] = []
    for index, instruction in enumerate(instructions):
        source = instruction.source
        source_key = (
            _line_key(source.file_name, source.line_number, source.source)
            if source is not None
            else None
        )
        if source_key is not None and source_key != previous_source_key:
            source_line = source_by_key.get(source_key)
            if source_line is not None:
                child_rows = kernel_children.get(source_key, [])
                rows.append(
                    BrrInspectRow(
                        kind="source",
                        code=_format_source_line(source_line),
                        samples=source_line.samples,
                        sample_percent=source_line.sample_percent,
                        cpu_percent=source_line.cpu_percent,
                        file_name=source_line.file_name,
                        line_number=source_line.line_number,
                        column=source_line.column,
                        offset=source_line.first_offset,
                        markers=source_markers.get(source_key, ()),
                        child_key=_child_key(source_key) if child_rows else None,
                        has_children=bool(child_rows),
                        children_expanded=True,
                    )
                )
                rows.extend(child_rows)
        previous_source_key = source_key
        bpftool_instruction = (
            bpftool_instructions[index] if index < len(bpftool_instructions) else None
        )
        rows.append(
            _instruction_row(
                instruction,
                bpftool_instruction,
                weight=instruction_weights.get(instruction.offset),
            )
        )

    if rows:
        return rows
    return _source_rows(
        source_lines,
        instructions,
        source_markers=source_markers,
        kernel_children=kernel_children,
    )


def _instruction_row(
    instruction: BpfInstruction,
    bpftool_instruction: BpftoolInstruction | None,
    *,
    weight: _InspectWeight | None = None,
) -> BrrInspectRow:
    source = instruction.source
    return BrrInspectRow(
        kind="instruction",
        code=_format_instruction(instruction, bpftool_instruction),
        samples=weight.samples if weight is not None else 0,
        sample_percent=weight.sample_percent if weight is not None else 0.0,
        cpu_percent=weight.cpu_percent if weight is not None else 0.0,
        file_name=source.file_name if source is not None else None,
        line_number=source.line_number if source is not None else None,
        column=source.column if source is not None else None,
        offset=instruction.offset,
        markers=("unmapped",) if source is None else (),
    )


@dataclass(frozen=True, slots=True)
class _SourceBlock:
    key: tuple[str | None, int | None, str | None] | None
    file_name: str | None
    line_number: int | None
    column: int | None


def _source_markers(
    instructions: list[BpfInstruction],
    source_lines: list[BrrSourceLine],
) -> dict[tuple[str | None, int | None, str | None], tuple[str, ...]]:
    marker_sets: dict[tuple[str | None, int | None, str | None], set[str]] = {
        _line_key(line.file_name, line.line_number, line.source): set() for line in source_lines
    }
    if not marker_sets:
        return {}

    blocks = _source_blocks(instructions)
    block_counts: dict[tuple[str | None, int | None, str | None], int] = {}
    columns_by_key: dict[tuple[str | None, int | None, str | None], set[int | None]] = {}
    for instruction in instructions:
        source = instruction.source
        if source is None:
            continue
        key = _line_key(source.file_name, source.line_number, source.source)
        columns_by_key.setdefault(key, set()).add(source.column)

    previous_block: _SourceBlock | None = None
    for block in blocks:
        if block.key is None:
            previous_block = block
            continue
        block_counts[block.key] = block_counts.get(block.key, 0) + 1
        markers = marker_sets.setdefault(block.key, set())
        if _is_header_file(block.file_name):
            markers.add("header")
        if (
            previous_block is not None
            and previous_block.key is not None
            and previous_block.file_name != block.file_name
        ):
            markers.add("file-switch")
        if (
            previous_block is not None
            and previous_block.key is not None
            and previous_block.file_name == block.file_name
            and previous_block.line_number is not None
            and block.line_number is not None
            and block.line_number < previous_block.line_number
        ):
            markers.add("backjump")
        previous_block = block

    for line in source_lines:
        key = _line_key(line.file_name, line.line_number, line.source)
        markers = marker_sets.setdefault(key, set())
        if block_counts.get(key, 0) > 1:
            markers.add("split")
        if len(columns_by_key.get(key, set())) > 1:
            markers.add("same-line-cols")
        if line.instruction_count >= MANY_INSTRUCTIONS_MARKER_THRESHOLD:
            markers.add("many-insns")

    return {
        key: tuple(marker for marker in _marker_order() if marker in markers)
        for key, markers in marker_sets.items()
        if markers
    }


def _source_blocks(instructions: list[BpfInstruction]) -> list[_SourceBlock]:
    blocks: list[_SourceBlock] = []
    previous_key: tuple[str | None, int | None, str | None] | None = None
    previous_was_unmapped = False
    for instruction in instructions:
        source = instruction.source
        if source is None:
            key = None
            if not previous_was_unmapped:
                blocks.append(_SourceBlock(key=None, file_name=None, line_number=None, column=None))
            previous_key = key
            previous_was_unmapped = True
            continue
        key = _line_key(source.file_name, source.line_number, source.source)
        if previous_was_unmapped or key != previous_key:
            blocks.append(
                _SourceBlock(
                    key=key,
                    file_name=source.file_name,
                    line_number=source.line_number,
                    column=source.column,
                )
            )
        previous_key = key
        previous_was_unmapped = False
    return blocks


def _is_header_file(file_name: str | None) -> bool:
    if not file_name:
        return False
    return PurePath(file_name).suffix.lower() in HEADER_SUFFIXES


def _marker_order() -> tuple[str, ...]:
    return tuple(marker for marker, _description in MARKER_DESCRIPTIONS)


def _format_markers(markers: tuple[str, ...]) -> str:
    return " ".join(f"[{marker}]" for marker in markers)


@dataclass(frozen=True, slots=True)
class _InspectWeight:
    samples: int
    sample_percent: float
    cpu_percent: float


def _instruction_hotspot_weights(
    hotspots: list[BpfHotspot],
    *,
    jit_ranges: list[BpfJitRange],
    instructions: list[BpfInstruction],
) -> dict[int, _InspectWeight]:
    instruction_offsets = {instruction.offset for instruction in instructions}
    weights: dict[int, _InspectWeight] = {}
    for hotspot in hotspots:
        offset = _hotspot_instruction_offset(
            hotspot,
            jit_ranges=jit_ranges,
            instruction_offsets=instruction_offsets,
        )
        if offset is None:
            continue
        current = weights.get(offset, _InspectWeight(0, 0.0, 0.0))
        weights[offset] = _InspectWeight(
            samples=current.samples + hotspot.samples,
            sample_percent=round(current.sample_percent + hotspot.sample_percent, 2),
            cpu_percent=round(current.cpu_percent + hotspot.cpu_percent, 4),
        )
    return weights


def _hotspot_instruction_offset(
    hotspot: BpfHotspot,
    *,
    jit_ranges: list[BpfJitRange],
    instruction_offsets: set[int],
) -> int | None:
    if hotspot.jited_address is None:
        return None
    for jit_range in jit_ranges:
        if jit_range.start <= hotspot.jited_address < jit_range.end:
            offset = hotspot.jited_address - jit_range.start
            if offset in instruction_offsets:
                return offset
    return None


def _format_source_line(line: BrrSourceLine) -> str:
    location = str(line.line_number) if line.line_number is not None else "-"
    if line.file_name:
        return f"{PurePath(line.file_name).name}:{location}: {line.source or '-'}"
    return f"{location}: {line.source or '-'}"


def _format_instruction(
    instruction: BpfInstruction,
    bpftool_instruction: BpftoolInstruction | None,
) -> str:
    if bpftool_instruction is not None and bpftool_instruction.disasm:
        return f"  {instruction.offset // 8:4d}: {bpftool_instruction.disasm}"
    return (
        f"  0x{instruction.offset:04x}: raw={instruction.raw} "
        f"op=0x{instruction.opcode:02x} dst={instruction.dst_reg} "
        f"src={instruction.src_reg} off={instruction.off} imm={instruction.imm}"
    )


def _parse_bpftool_instructions(payload: list[Any]) -> list[BpftoolInstruction]:
    instructions: list[BpftoolInstruction] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        disasm = item.get("disasm")
        if not isinstance(disasm, str) or not disasm:
            continue
        instructions.append(
            BpftoolInstruction(
                disasm=disasm,
                source=_optional_str(item.get("src")),
                file_name=_optional_str(item.get("file")),
                line_number=_optional_int(item.get("line_num")),
                column=_optional_int(item.get("line_col")),
            )
        )
    return instructions


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _line_key(
    file_name: str | None,
    line_number: int | None,
    source: str | None,
) -> tuple[str | None, int | None, str | None]:
    return (file_name, line_number, source)


def _child_key(key: tuple[str | None, int | None, str | None]) -> str:
    file_name, line_number, source = key
    return f"{file_name or ''}\0{line_number or ''}\0{source or ''}"
