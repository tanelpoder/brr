from __future__ import annotations

import csv
from io import StringIO
from typing import Any

from brr.dump_compare import DumpCompareResult
from brr.models import (
    BpfHotspot,
    BpfInstruction,
    BpfJitRange,
    BpfKernelHotspot,
    BpfLink,
    BpfMap,
    BpfProfile,
    BpfProfileProgram,
    BpfProgram,
    BpfProgramActivity,
    BpfProgramDump,
    BtfObject,
)
from brr.profiler import PerfEventAvailability
from brr.source_context import SourceContextReport

PROGRAM_FIELDS = [
    "id",
    "type",
    "name",
    "tag",
    "xlated_size_bytes",
    "jited_size_bytes",
    "run_time_ns",
    "run_count",
    "map_ids",
    "btf_id",
    "pinned_paths",
]

ACTIVITY_FIELDS = [
    "duration",
    "limit",
    "include_all",
    "id",
    "type",
    "name",
    "tag",
    "xlated_size_bytes",
    "jited_size_bytes",
    "run_count_delta",
    "run_time_ns_delta",
    "avg_run_time_ns",
    "run_count_total",
    "run_time_ns_total",
    "cumulative_avg_run_time_ns",
    "pinned_paths",
]

DUMP_FIELDS = [
    "program_id",
    "program_type",
    "program_name",
    "program_tag",
    "line_info_count",
    "jit_ranges",
    "offset",
    "raw",
    "opcode",
    "dst_reg",
    "src_reg",
    "off",
    "imm",
    "file",
    "line",
    "column",
    "source",
]

DUMP_COMPARE_FIELDS = [
    "program_id",
    "passed",
    "brr_instruction_slots",
    "brr_visible_slots",
    "bpftool_instruction_count",
    "lddw_slots",
    "source_rows_compared",
    "offset_mismatch_count",
    "source_mismatch_count",
]

PROFILE_FIELDS = [
    "requested_event",
    "selected_event",
    "duration",
    "frequency",
    "limit",
    "line_limit",
    "total_samples",
    "lost_samples",
    "unresolved_samples",
    "bpf_jit_samples",
    "non_bpf_samples",
    "selected_program_samples",
    "other_bpf_samples",
    "source_mapped_samples",
    "source_unmapped_samples",
    "callchain_samples",
    "kernel_attributed_samples",
    "kernel_unattributed_samples",
    "kernel_symbolized_samples",
    "call_graph",
    "actual_duration",
    "perf_cpus",
    "perf_buffer_pages_per_cpu",
    "perf_buffer_bytes_per_cpu",
    "perf_buffer_bytes_total",
    "perf_drain_interval_ms",
    "perf_drain_count",
    "perf_max_ring_occupancy_percent",
    "perf_throttle_events",
    "perf_unthrottle_events",
    "perf_malformed_records",
    "perf_unknown_records",
    "perf_discarded_bytes",
    "perf_time_enabled_ns",
    "perf_time_running_ns",
    "perf_running_percent",
    "incomplete",
    "warnings",
    "program_id",
    "program_type",
    "program_name",
    "program_tag",
    "program_samples",
    "program_sample_percent",
    "program_cpu_percent",
    "program_inclusive_samples",
    "program_inclusive_cpu_percent",
    "program_kernel_samples",
    "program_kernel_cpu_percent",
    "program_direct_source_mapped_samples",
    "program_direct_source_unmapped_samples",
    "program_under_bpf_caller_source_mapped_samples",
    "program_under_bpf_caller_source_unmapped_samples",
    "program_direct_hotspot_samples_omitted_by_limit",
    "program_under_bpf_hotspot_samples_omitted_by_limit",
    "program_unaccounted_samples",
    "pinned_paths",
    "hotspot_kind",
    "hotspot_rank",
    "hotspot_samples",
    "hotspot_sample_percent",
    "hotspot_cpu_percent",
    "jited_address",
    "instruction_offset",
    "file",
    "line",
    "column",
    "source",
    "kernel_ip",
    "kernel_symbol",
    "kernel_module",
    "kernel_symbol_offset",
    "kernel_symbol_kind",
    "bpf_jited_address",
    "bpf_instruction_offset",
    "bpf_file",
    "bpf_line",
    "bpf_column",
    "bpf_source",
]

PERF_EVENT_FIELDS = ["name", "type", "config", "precise_ip", "selected_by_auto"]
MAP_FIELDS = [
    "id",
    "type",
    "name",
    "key_size",
    "value_size",
    "max_entries",
    "btf_id",
    "pinned_paths",
]
LINK_FIELDS = [
    "id",
    "type",
    "prog_id",
    "attach_type",
    "target_obj_id",
    "target_btf_id",
    "pinned_paths",
]
BTF_FIELDS = ["id", "name", "size", "pinned_paths"]


def render_programs_csv(programs: list[BpfProgram]) -> str:
    return _render_csv(PROGRAM_FIELDS, [_program_to_row(program) for program in programs])


def render_program_activity_csv(
    activities: list[BpfProgramActivity],
    *,
    duration: float,
    limit: int,
    include_all: bool,
) -> str:
    return _render_csv(
        ACTIVITY_FIELDS,
        [
            {
                "duration": duration,
                "limit": limit,
                "include_all": include_all,
                **_program_activity_to_row(activity),
            }
            for activity in activities
        ],
    )


def render_program_dump_csv(
    dump: BpfProgramDump,
    *,
    source_context: SourceContextReport | None = None,
) -> str:
    del source_context
    program_fields = {
        "program_id": dump.program.id,
        "program_type": dump.program.program_type,
        "program_name": dump.program.name,
        "program_tag": dump.program.tag,
        "line_info_count": dump.line_info_count,
        "jit_ranges": _join_jit_ranges(dump.jit_ranges),
    }
    return _render_csv(
        DUMP_FIELDS,
        [
            {
                **program_fields,
                **_instruction_to_row(instruction),
            }
            for instruction in dump.instructions
        ],
    )


def render_dump_compare_csv(result: DumpCompareResult) -> str:
    return _render_csv(
        DUMP_COMPARE_FIELDS,
        [
            {
                "program_id": result.program_id,
                "passed": result.passed,
                "brr_instruction_slots": result.brr_instruction_slots,
                "brr_visible_slots": result.brr_visible_slots,
                "bpftool_instruction_count": result.bpftool_instruction_count,
                "lddw_slots": result.lddw_slots,
                "source_rows_compared": result.source_rows_compared,
                "offset_mismatch_count": len(result.offset_mismatches),
                "source_mismatch_count": len(result.source_mismatches),
            }
        ],
    )


def render_profile_csv(
    profile: BpfProfile,
    *,
    source_context_by_program: dict[int, SourceContextReport] | None = None,
) -> str:
    del source_context_by_program
    metadata = {
        "requested_event": profile.metadata.requested_event,
        "selected_event": profile.metadata.selected_event,
        "duration": profile.metadata.duration,
        "frequency": profile.metadata.frequency,
        "limit": profile.metadata.limit,
        "line_limit": profile.metadata.line_limit,
        "total_samples": profile.metadata.total_samples,
        "lost_samples": profile.metadata.lost_samples,
        "unresolved_samples": profile.metadata.unresolved_samples,
        "bpf_jit_samples": profile.metadata.bpf_jit_samples,
        "non_bpf_samples": profile.metadata.non_bpf_samples,
        "selected_program_samples": profile.metadata.selected_program_samples,
        "other_bpf_samples": profile.metadata.other_bpf_samples,
        "source_mapped_samples": profile.metadata.source_mapped_samples,
        "source_unmapped_samples": profile.metadata.source_unmapped_samples,
        "callchain_samples": profile.metadata.callchain_samples,
        "kernel_attributed_samples": profile.metadata.kernel_attributed_samples,
        "kernel_unattributed_samples": profile.metadata.kernel_unattributed_samples,
        "kernel_symbolized_samples": profile.metadata.kernel_symbolized_samples,
        "call_graph": profile.metadata.call_graph,
        "actual_duration": profile.metadata.actual_duration,
        "perf_cpus": profile.metadata.perf_cpus,
        "perf_buffer_pages_per_cpu": profile.metadata.perf_buffer_pages_per_cpu,
        "perf_buffer_bytes_per_cpu": profile.metadata.perf_buffer_bytes_per_cpu,
        "perf_buffer_bytes_total": profile.metadata.perf_buffer_bytes_total,
        "perf_drain_interval_ms": profile.metadata.perf_drain_interval_ms,
        "perf_drain_count": profile.metadata.perf_drain_count,
        "perf_max_ring_occupancy_percent": (profile.metadata.perf_max_ring_occupancy_percent),
        "perf_throttle_events": profile.metadata.perf_throttle_events,
        "perf_unthrottle_events": profile.metadata.perf_unthrottle_events,
        "perf_malformed_records": profile.metadata.perf_malformed_records,
        "perf_unknown_records": profile.metadata.perf_unknown_records,
        "perf_discarded_bytes": profile.metadata.perf_discarded_bytes,
        "perf_time_enabled_ns": profile.metadata.perf_time_enabled_ns,
        "perf_time_running_ns": profile.metadata.perf_time_running_ns,
        "perf_running_percent": profile.metadata.perf_running_percent,
        "incomplete": profile.metadata.incomplete,
        "warnings": profile.metadata.warnings,
    }
    rows: list[dict[str, Any]] = []
    for program in profile.items:
        program_fields = _profile_program_to_row(program)
        if not program.hotspots and not program.kernel_hotspots:
            rows.append({**metadata, **program_fields})
            continue
        for rank, hotspot in enumerate(program.hotspots, start=1):
            rows.append(
                {
                    **metadata,
                    **program_fields,
                    **_hotspot_to_row(hotspot, rank=rank),
                }
            )
        for rank, hotspot in enumerate(program.kernel_hotspots, start=1):
            rows.append(
                {
                    **metadata,
                    **program_fields,
                    **_kernel_hotspot_to_row(hotspot, rank=rank),
                }
            )
    return _render_csv(PROFILE_FIELDS, rows)


def render_perf_events_csv(events: list[PerfEventAvailability]) -> str:
    return _render_csv(
        PERF_EVENT_FIELDS,
        [
            {
                "name": event.name,
                "type": event.event_type,
                "config": event.config,
                "precise_ip": event.precise_ip,
                "selected_by_auto": event.selected_by_auto,
            }
            for event in events
        ],
    )


def render_maps_csv(maps: list[BpfMap]) -> str:
    return _render_csv(
        MAP_FIELDS,
        [
            {
                "id": map_.id,
                "type": map_.map_type,
                "name": map_.name,
                "key_size": map_.key_size,
                "value_size": map_.value_size,
                "max_entries": map_.max_entries,
                "btf_id": map_.btf_id,
                "pinned_paths": map_.pinned_paths,
            }
            for map_ in maps
        ],
    )


def render_links_csv(links: list[BpfLink]) -> str:
    return _render_csv(
        LINK_FIELDS,
        [
            {
                "id": link.id,
                "type": link.link_type,
                "prog_id": link.prog_id,
                "attach_type": link.attach_type,
                "target_obj_id": link.target_obj_id,
                "target_btf_id": link.target_btf_id,
                "pinned_paths": link.pinned_paths,
            }
            for link in links
        ],
    )


def render_btfs_csv(btfs: list[BtfObject]) -> str:
    return _render_csv(
        BTF_FIELDS,
        [
            {
                "id": btf.id,
                "name": btf.name,
                "size": btf.size,
                "pinned_paths": btf.pinned_paths,
            }
            for btf in btfs
        ],
    )


def _program_to_row(program: BpfProgram) -> dict[str, Any]:
    return {
        "id": program.id,
        "type": program.program_type,
        "name": program.name,
        "tag": program.tag,
        "xlated_size_bytes": program.xlated_size_bytes,
        "jited_size_bytes": program.jited_size_bytes,
        "run_time_ns": program.run_time_ns,
        "run_count": program.run_count,
        "map_ids": program.map_ids,
        "btf_id": program.btf_id,
        "pinned_paths": program.pinned_paths,
    }


def _program_activity_to_row(activity: BpfProgramActivity) -> dict[str, Any]:
    return {
        "id": activity.id,
        "type": activity.program_type,
        "name": activity.name,
        "tag": activity.tag,
        "xlated_size_bytes": activity.xlated_size_bytes,
        "jited_size_bytes": activity.jited_size_bytes,
        "run_count_delta": activity.run_count_delta,
        "run_time_ns_delta": activity.run_time_ns_delta,
        "avg_run_time_ns": activity.avg_run_time_ns,
        "run_count_total": activity.run_count_total,
        "run_time_ns_total": activity.run_time_ns_total,
        "cumulative_avg_run_time_ns": activity.cumulative_avg_run_time_ns,
        "pinned_paths": activity.pinned_paths,
    }


def _instruction_to_row(instruction: BpfInstruction) -> dict[str, Any]:
    source = instruction.source
    return {
        "offset": instruction.offset,
        "raw": instruction.raw,
        "opcode": instruction.opcode,
        "dst_reg": instruction.dst_reg,
        "src_reg": instruction.src_reg,
        "off": instruction.off,
        "imm": instruction.imm,
        "file": source.file_name if source is not None else None,
        "line": source.line_number if source is not None else None,
        "column": source.column if source is not None else None,
        "source": source.source if source is not None else None,
    }


def _profile_program_to_row(program: BpfProfileProgram) -> dict[str, Any]:
    return {
        "program_id": program.id,
        "program_type": program.program_type,
        "program_name": program.name,
        "program_tag": program.tag,
        "program_samples": program.samples,
        "program_sample_percent": program.sample_percent,
        "program_cpu_percent": program.cpu_percent,
        "program_inclusive_samples": program.inclusive_samples,
        "program_inclusive_cpu_percent": program.inclusive_cpu_percent,
        "program_kernel_samples": program.kernel_samples,
        "program_kernel_cpu_percent": program.kernel_cpu_percent,
        "program_direct_source_mapped_samples": program.direct_source_mapped_samples,
        "program_direct_source_unmapped_samples": program.direct_source_unmapped_samples,
        "program_under_bpf_caller_source_mapped_samples": (
            program.under_bpf_caller_source_mapped_samples
        ),
        "program_under_bpf_caller_source_unmapped_samples": (
            program.under_bpf_caller_source_unmapped_samples
        ),
        "program_direct_hotspot_samples_omitted_by_limit": (
            program.direct_hotspot_samples_omitted_by_limit
        ),
        "program_under_bpf_hotspot_samples_omitted_by_limit": (
            program.under_bpf_hotspot_samples_omitted_by_limit
        ),
        "program_unaccounted_samples": program.unaccounted_samples,
        "pinned_paths": program.pinned_paths,
    }


def _hotspot_to_row(hotspot: BpfHotspot, *, rank: int) -> dict[str, Any]:
    return {
        "hotspot_kind": "bpf",
        "hotspot_rank": rank,
        "hotspot_samples": hotspot.samples,
        "hotspot_sample_percent": hotspot.sample_percent,
        "hotspot_cpu_percent": hotspot.cpu_percent,
        "jited_address": hotspot.jited_address,
        "instruction_offset": hotspot.instruction_offset,
        "file": hotspot.file_name,
        "line": hotspot.line_number,
        "column": hotspot.column,
        "source": hotspot.source,
    }


def _kernel_hotspot_to_row(hotspot: BpfKernelHotspot, *, rank: int) -> dict[str, Any]:
    return {
        "hotspot_kind": "kernel",
        "hotspot_rank": rank,
        "hotspot_samples": hotspot.samples,
        "hotspot_sample_percent": hotspot.sample_percent,
        "hotspot_cpu_percent": hotspot.cpu_percent,
        "kernel_ip": hotspot.ip,
        "kernel_symbol": hotspot.symbol,
        "kernel_module": hotspot.module,
        "kernel_symbol_offset": hotspot.symbol_offset,
        "kernel_symbol_kind": hotspot.symbol_kind,
        "bpf_jited_address": hotspot.bpf_jited_address,
        "bpf_instruction_offset": hotspot.bpf_instruction_offset,
        "bpf_file": hotspot.bpf_file_name,
        "bpf_line": hotspot.bpf_line_number,
        "bpf_column": hotspot.bpf_column,
        "bpf_source": hotspot.bpf_source,
    }


def _join_jit_ranges(jit_ranges: list[BpfJitRange]) -> str:
    return ";".join(
        f"{jit_range.function_index}:0x{jit_range.start:x}-0x{jit_range.end:x}"
        for jit_range in jit_ranges
    )


def _render_csv(fieldnames: list[str], rows: list[dict[str, Any]]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: _csv_value(row.get(field)) for field in fieldnames})
    return output.getvalue().rstrip("\n")


def _csv_value(value: Any) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (list, tuple)):
        return ";".join(str(item) for item in value)
    return value
