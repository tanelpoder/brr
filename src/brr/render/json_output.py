from __future__ import annotations

import json
from typing import Any

from brr.dump_compare import NORMALIZATION_NOTE, DumpCompareResult
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


def render_programs_json(programs: list[BpfProgram], *, pretty: bool = False) -> str:
    return _render_json(
        {
            "kind": "programs",
            "items": [_program_to_json(program) for program in programs],
            "metadata": {},
        },
        pretty=pretty,
    )


def render_program_activity_json(
    activities: list[BpfProgramActivity],
    *,
    duration: float,
    limit: int,
    include_all: bool,
    pretty: bool = False,
) -> str:
    return _render_json(
        {
            "kind": "program_activity",
            "items": [_program_activity_to_json(activity) for activity in activities],
            "metadata": {
                "duration": duration,
                "limit": limit,
                "include_all": include_all,
            },
        },
        pretty=pretty,
    )


def render_program_dump_json(
    dump: BpfProgramDump,
    *,
    pretty: bool = False,
    source_context: SourceContextReport | None = None,
) -> str:
    metadata: dict[str, Any] = {
        "program": _program_to_json(dump.program),
        "line_info_count": dump.line_info_count,
        "jit_ranges": [_jit_range_to_json(jit_range) for jit_range in dump.jit_ranges],
    }
    if source_context is not None:
        metadata["source_context"] = _source_context_to_json(source_context)
    return _render_json(
        {
            "kind": "program_dump",
            "items": [_instruction_to_json(instruction) for instruction in dump.instructions],
            "metadata": metadata,
        },
        pretty=pretty,
    )


def render_dump_compare_json(result: DumpCompareResult, *, pretty: bool = False) -> str:
    return _render_json(
        {
            "kind": "dump_compare",
            "items": [_dump_compare_result_to_json(result)],
            "metadata": {
                "bpftool_available": True,
                "bpftool_source": "bpftool prog dump xlated id PROG_ID linum",
                "normalization": NORMALIZATION_NOTE,
            },
        },
        pretty=pretty,
    )


def render_profile_json(
    profile: BpfProfile,
    *,
    pretty: bool = False,
    source_context_by_program: dict[int, SourceContextReport] | None = None,
) -> str:
    return _render_json(
        {
            "kind": "profile",
            "items": [
                _profile_program_to_json(
                    item,
                    source_context=(
                        source_context_by_program.get(item.id)
                        if source_context_by_program is not None
                        else None
                    ),
                )
                for item in profile.items
            ],
            "metadata": {
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
                "perf_cpus": list(profile.metadata.perf_cpus),
                "perf_buffer_pages_per_cpu": profile.metadata.perf_buffer_pages_per_cpu,
                "perf_buffer_bytes_per_cpu": profile.metadata.perf_buffer_bytes_per_cpu,
                "perf_buffer_bytes_total": profile.metadata.perf_buffer_bytes_total,
                "perf_drain_interval_ms": profile.metadata.perf_drain_interval_ms,
                "perf_drain_count": profile.metadata.perf_drain_count,
                "perf_max_ring_occupancy_percent": (
                    profile.metadata.perf_max_ring_occupancy_percent
                ),
                "perf_throttle_events": profile.metadata.perf_throttle_events,
                "perf_unthrottle_events": profile.metadata.perf_unthrottle_events,
                "perf_malformed_records": profile.metadata.perf_malformed_records,
                "perf_unknown_records": profile.metadata.perf_unknown_records,
                "perf_discarded_bytes": profile.metadata.perf_discarded_bytes,
                "perf_time_enabled_ns": profile.metadata.perf_time_enabled_ns,
                "perf_time_running_ns": profile.metadata.perf_time_running_ns,
                "perf_running_percent": profile.metadata.perf_running_percent,
                "incomplete": profile.metadata.incomplete,
                "warnings": list(profile.metadata.warnings),
            },
        },
        pretty=pretty,
    )


def render_perf_events_json(
    events: list[PerfEventAvailability],
    *,
    pretty: bool = False,
) -> str:
    return _render_json(
        {
            "kind": "perf_events",
            "items": [_perf_event_to_json(event) for event in events],
            "metadata": {},
        },
        pretty=pretty,
    )


def render_maps_json(maps: list[BpfMap], *, pretty: bool = False) -> str:
    return _render_json(
        {
            "kind": "maps",
            "items": [_map_to_json(map_) for map_ in maps],
            "metadata": {},
        },
        pretty=pretty,
    )


def render_links_json(links: list[BpfLink], *, pretty: bool = False) -> str:
    return _render_json(
        {
            "kind": "links",
            "items": [_link_to_json(link) for link in links],
            "metadata": {},
        },
        pretty=pretty,
    )


def render_btfs_json(btfs: list[BtfObject], *, pretty: bool = False) -> str:
    return _render_json(
        {
            "kind": "btfs",
            "items": [_btf_to_json(btf) for btf in btfs],
            "metadata": {},
        },
        pretty=pretty,
    )


def _render_json(payload: dict[str, Any], *, pretty: bool) -> str:
    if pretty:
        return json.dumps(payload, indent=2)
    return json.dumps(payload, separators=(",", ":"))


def _program_to_json(program: BpfProgram) -> dict[str, Any]:
    return {
        "id": program.id,
        "type": program.program_type,
        "name": program.name,
        "tag": program.tag,
        "xlated_size_bytes": program.xlated_size_bytes,
        "jited_size_bytes": program.jited_size_bytes,
        "run_time_ns": program.run_time_ns,
        "run_count": program.run_count,
        "map_ids": list(program.map_ids),
        "btf_id": program.btf_id,
        "pinned_paths": list(program.pinned_paths),
    }


def _program_activity_to_json(activity: BpfProgramActivity) -> dict[str, Any]:
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
        "pinned_paths": list(activity.pinned_paths),
    }


def _instruction_to_json(instruction: BpfInstruction) -> dict[str, Any]:
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


def _jit_range_to_json(jit_range: BpfJitRange) -> dict[str, Any]:
    return {
        "start": jit_range.start,
        "end": jit_range.end,
        "length": jit_range.length,
        "function_index": jit_range.function_index,
    }


def _dump_compare_result_to_json(result: DumpCompareResult) -> dict[str, Any]:
    return {
        "program_id": result.program_id,
        "passed": result.passed,
        "brr_instruction_slots": result.brr_instruction_slots,
        "brr_visible_slots": result.brr_visible_slots,
        "bpftool_instruction_count": result.bpftool_instruction_count,
        "lddw_slots": result.lddw_slots,
        "source_rows_compared": result.source_rows_compared,
        "offset_mismatches": [
            {
                "position": mismatch.position,
                "expected_index": mismatch.expected_index,
                "actual_index": mismatch.actual_index,
            }
            for mismatch in result.offset_mismatches
        ],
        "source_mismatches": [
            {
                "index": mismatch.index,
                "field": mismatch.field,
                "expected": mismatch.expected,
                "actual": mismatch.actual,
            }
            for mismatch in result.source_mismatches
        ],
    }


def _profile_program_to_json(
    program: BpfProfileProgram,
    *,
    source_context: SourceContextReport | None = None,
) -> dict[str, Any]:
    payload = {
        "id": program.id,
        "type": program.program_type,
        "name": program.name,
        "tag": program.tag,
        "samples": program.samples,
        "sample_percent": program.sample_percent,
        "cpu_percent": program.cpu_percent,
        "inclusive_samples": program.inclusive_samples,
        "inclusive_cpu_percent": program.inclusive_cpu_percent,
        "pinned_paths": list(program.pinned_paths),
        "hotspots": [_hotspot_to_json(hotspot) for hotspot in program.hotspots],
        "kernel_samples": program.kernel_samples,
        "kernel_cpu_percent": program.kernel_cpu_percent,
        "kernel_hotspots": [
            _kernel_hotspot_to_json(hotspot) for hotspot in program.kernel_hotspots
        ],
    }
    if source_context is not None:
        payload["source_context"] = _source_context_to_json(source_context)
    return payload


def _hotspot_to_json(hotspot: BpfHotspot) -> dict[str, Any]:
    return {
        "samples": hotspot.samples,
        "sample_percent": hotspot.sample_percent,
        "cpu_percent": hotspot.cpu_percent,
        "jited_address": hotspot.jited_address,
        "file": hotspot.file_name,
        "line": hotspot.line_number,
        "column": hotspot.column,
        "source": hotspot.source,
    }


def _kernel_hotspot_to_json(hotspot: BpfKernelHotspot) -> dict[str, Any]:
    return {
        "samples": hotspot.samples,
        "sample_percent": hotspot.sample_percent,
        "cpu_percent": hotspot.cpu_percent,
        "ip": hotspot.ip,
        "symbol": hotspot.symbol,
        "module": hotspot.module,
        "symbol_offset": hotspot.symbol_offset,
        "symbol_kind": hotspot.symbol_kind,
        "bpf_jited_address": hotspot.bpf_jited_address,
        "bpf_file": hotspot.bpf_file_name,
        "bpf_line": hotspot.bpf_line_number,
        "bpf_column": hotspot.bpf_column,
        "bpf_source": hotspot.bpf_source,
    }


def _perf_event_to_json(event: PerfEventAvailability) -> dict[str, Any]:
    return {
        "name": event.name,
        "type": event.event_type,
        "config": event.config,
        "precise_ip": event.precise_ip,
        "selected_by_auto": event.selected_by_auto,
    }


def _source_context_to_json(report: SourceContextReport) -> dict[str, Any]:
    return {
        "enabled": report.enabled,
        "devdir": report.devdir,
        "unresolved_files": report.unresolved_files,
        "ambiguous_files": report.ambiguous_files,
        "source_mismatches": [
            {
                "file": mismatch.file_name,
                "line": mismatch.line_number,
                "btf_source": mismatch.btf_source,
                "file_source": mismatch.file_source,
                "resolved_path": mismatch.resolved_path,
            }
            for mismatch in report.source_mismatches
        ],
        "rows": [
            {
                "kind": "mapped" if row.mapped else "context",
                "file": row.file_name,
                "line": row.line_number,
                "source": row.source,
                "resolved_path": row.resolved_path,
            }
            for row in report.rows
        ],
    }


def _map_to_json(map_: BpfMap) -> dict[str, Any]:
    return {
        "id": map_.id,
        "type": map_.map_type,
        "name": map_.name,
        "key_size": map_.key_size,
        "value_size": map_.value_size,
        "max_entries": map_.max_entries,
        "btf_id": map_.btf_id,
        "pinned_paths": list(map_.pinned_paths),
    }


def _link_to_json(link: BpfLink) -> dict[str, Any]:
    return {
        "id": link.id,
        "type": link.link_type,
        "prog_id": link.prog_id,
        "attach_type": link.attach_type,
        "target_obj_id": link.target_obj_id,
        "target_btf_id": link.target_btf_id,
        "pinned_paths": list(link.pinned_paths),
    }


def _btf_to_json(btf: BtfObject) -> dict[str, Any]:
    return {
        "id": btf.id,
        "name": btf.name,
        "size": btf.size,
        "pinned_paths": list(btf.pinned_paths),
    }
