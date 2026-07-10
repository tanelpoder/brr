from __future__ import annotations

from pathlib import PurePath

from brr.inspection import BrrInspectReport, profile_status_message
from brr.models import BpfHotspot, BpfKernelHotspot, BpfProfileMetadata, BpfProfileProgram
from brr.render.text import _render_table
from brr.reporter import BrrActivityItem, BrrActivityReport, BrrDetailReport, BrrSourceLine


def render_brr_activity(
    report: BrrActivityReport,
    *,
    cumulative: bool = False,
    extended: bool = False,
) -> str:
    header = f"BRR ACTIVITY duration={report.duration:g}"
    if not report.items:
        return f"{header}\nNo active eBPF program runtime deltas observed."
    rows = [
        _activity_row(item, duration=report.duration, cumulative=cumulative, extended=extended)
        for item in report.items
    ]
    return "\n".join([header, _render_top_activity_table(rows)])


def render_brr_detail(report: BrrDetailReport, *, extended: bool = False) -> str:
    return "\n\n".join(
        [
            _render_profile_section(report, extended=extended),
            _render_source_section(report),
        ]
    )


def render_brr_inspect(report: BrrInspectReport, *, extended: bool = False) -> str:
    profiled = "yes" if report.profiled else "no"
    header = (
        f"BRR INSPECT program={report.program.id} name={report.program.name} "
        f"mode={report.mode} profiled={profiled} instructions={report.instruction_source}"
    )
    sections = [header]
    if report.profile is not None:
        metadata = report.profile.metadata
        has_mapped_source_samples = any(row.samples > 0 for row in report.rows)
        sections.append(
            "BRR INSPECT PROFILE "
            f"duration={metadata.duration:g} event={metadata.selected_event} "
            f"{_profile_sample_summary(metadata)}"
        )
        sections.append(
            profile_status_message(
                program_id=report.program.id,
                profile=report.profile,
                profile_program=report.profile_program,
                has_mapped_source_samples=has_mapped_source_samples,
            )
        )
    if report.rows:
        sections.append(_render_table([_inspect_row(row) for row in report.rows]))
    else:
        sections.append("No source-line metadata or translated eBPF instructions available.")
    return "\n".join(sections)


def _render_profile_section(report: BrrDetailReport, *, extended: bool = False) -> str:
    metadata = report.profile.metadata
    header = (
        f"BRR PROFILE program={report.program.id} name={report.program.name} "
        f"duration={metadata.duration:g} event={metadata.selected_event} "
        f"{_profile_sample_summary(metadata)}"
    )
    if report.profile_program is None:
        return "\n".join(
            [
                header,
                *_profile_warning_lines(metadata),
                "No BPF JIT samples captured for selected program.",
            ]
        )

    sections = [
        header,
        *_profile_warning_lines(metadata),
        _render_table([_profile_program_row(report.profile_program, extended=extended)]),
    ]
    if report.profile_program.hotspots:
        sections.append(
            _render_table([_hotspot_row(hotspot) for hotspot in report.profile_program.hotspots])
        )
    if report.profile_program.kernel_hotspots:
        sections.append("Kernel/helper samples")
        sections.append(
            _render_table(
                [_kernel_hotspot_row(hotspot) for hotspot in report.profile_program.kernel_hotspots]
            )
        )
    return "\n".join(sections)


def _render_source_section(report: BrrDetailReport) -> str:
    header = f"BRR SOURCE program={report.program.id} name={report.program.name}"
    if not report.source_lines:
        return f"{header}\nNo source-line metadata available."
    return "\n".join([header, _render_table([_source_row(row) for row in report.source_lines])])


def _activity_row(
    item: BrrActivityItem,
    *,
    duration: float,
    cumulative: bool = False,
    extended: bool = False,
) -> dict[str, str]:
    activity = item.activity
    row = {
        "ID": str(activity.id),
        "TYPE": activity.program_type,
        "NAME": activity.name,
        "CPU%": f"{item.bpf_percent:.4f}",
        "EXECS/s": _format_rate(activity.run_count_delta, duration=duration),
        "AVG_NS": _format_int(activity.avg_run_time_ns),
    }
    if cumulative:
        row["CUMUL_AVG_NS"] = _format_int(activity.cumulative_avg_run_time_ns)
    row["NS_PER/s"] = _format_rate(activity.run_time_ns_delta, duration=duration)
    if cumulative:
        row["EXECS_DELTA"] = _format_int(activity.run_count_delta)
        row["TOTAL_NS"] = _format_int(activity.run_time_ns_delta)
        row["EXECS_TOTAL"] = _format_int(activity.run_count_total)
        row["CUMUL_NS"] = _format_int(activity.run_time_ns_total)
    row["XLAT_B"] = _format_int(activity.xlated_size_bytes)
    row["JIT_B"] = _format_int(activity.jited_size_bytes)
    if extended:
        row["TAG"] = activity.tag or "-"
        row["PINNED"] = ",".join(activity.pinned_paths) if activity.pinned_paths else "-"
    return row


def _profile_program_row(
    program: BpfProfileProgram,
    *,
    extended: bool = False,
) -> dict[str, str]:
    row = {
        "ID": str(program.id),
        "TYPE": program.program_type,
        "NAME": program.name,
        "SAMPLES": str(program.samples),
        "CPU%": f"{program.cpu_percent:.4f}",
    }
    if extended:
        row["TAG"] = program.tag or "-"
        row["PINNED"] = ",".join(program.pinned_paths) if program.pinned_paths else "-"
    return row


def _hotspot_row(hotspot: BpfHotspot) -> dict[str, str]:
    return {
        "SAMPLES": str(hotspot.samples),
        "CPU%": f"{hotspot.cpu_percent:.4f}",
        "FILE": _file_name(hotspot.file_name),
        "LINE": str(hotspot.line_number) if hotspot.line_number is not None else "-",
        "SOURCE": hotspot.source or "-",
    }


def _kernel_hotspot_row(hotspot: BpfKernelHotspot) -> dict[str, str]:
    return {
        "SAMPLES": str(hotspot.samples),
        "CPU%": f"{hotspot.cpu_percent:.4f}",
        "KIND": hotspot.symbol_kind,
        "SYMBOL": hotspot.symbol or "-",
        "MODULE": hotspot.module or "-",
        "BPF_FILE": _file_name(hotspot.bpf_file_name),
        "BPF_LINE": (str(hotspot.bpf_line_number) if hotspot.bpf_line_number is not None else "-"),
        "BPF_SOURCE": hotspot.bpf_source or "-",
    }


def _source_row(row: BrrSourceLine) -> dict[str, str]:
    return {
        "HOT": ">" if row.samples else "-",
        "SAMPLES": str(row.samples),
        "CPU%": f"{row.cpu_percent:.4f}",
        "FILE": _file_name(row.file_name),
        "LINE": str(row.line_number) if row.line_number is not None else "-",
        "SOURCE": row.source or "-",
    }


def _file_name(file_name: str | None) -> str:
    if not file_name:
        return "-"
    return PurePath(file_name).name or file_name


def _inspect_row(row) -> dict[str, str]:
    return {
        "WEIGHT": row.weight,
        "CODE": row.display_code(),
    }


def _profile_bucket_summary(metadata: BpfProfileMetadata) -> str:
    return _profile_sample_summary(metadata)


def _profile_warning_lines(metadata: BpfProfileMetadata) -> list[str]:
    return [f"Warning: {warning}" for warning in metadata.warnings]


def _profile_sample_summary(metadata: BpfProfileMetadata) -> str:
    outside_bpf_samples = (
        metadata.non_bpf_samples if metadata.non_bpf_samples > 0 else metadata.unresolved_samples
    )
    summary = (
        f"samples_total={metadata.total_samples} "
        f"lost={metadata.lost_samples} "
        f"outside_bpf={outside_bpf_samples} "
        f"bpf_total={metadata.bpf_jit_samples} "
        f"selected_program={metadata.selected_program_samples} "
        f"other_bpf={metadata.other_bpf_samples} "
        f"source_mapped={metadata.source_mapped_samples} "
        f"source_unmapped={metadata.source_unmapped_samples} "
        f"call_graph={metadata.call_graph} "
        f"buffer_pages={metadata.perf_buffer_pages_per_cpu} "
        f"drain_ms={metadata.perf_drain_interval_ms} "
        f"drains={metadata.perf_drain_count} "
        f"occupancy={metadata.perf_max_ring_occupancy_percent:.1f}% "
        f"running={metadata.perf_running_percent:.2f}% "
        f"lost={metadata.lost_samples} "
        f"throttle={metadata.perf_throttle_events} "
        f"malformed={metadata.perf_malformed_records} "
        f"discarded_bytes={metadata.perf_discarded_bytes} "
        f"incomplete={'yes' if metadata.incomplete else 'no'}"
    )
    if not any(
        (
            metadata.callchain_samples,
            metadata.kernel_attributed_samples,
            metadata.kernel_unattributed_samples,
            metadata.kernel_symbolized_samples,
        )
    ):
        return summary
    return (
        f"{summary} "
        f"callchain={metadata.callchain_samples} "
        f"kernel_attributed={metadata.kernel_attributed_samples} "
        f"kernel_unattributed={metadata.kernel_unattributed_samples} "
        f"kernel_symbolized={metadata.kernel_symbolized_samples}"
    )


_TOP_NUMERIC_COLUMNS = {
    "ID",
    "CPU%",
    "EXECS/s",
    "NS_PER/s",
    "AVG_NS",
    "CUMUL_AVG_NS",
    "EXECS_DELTA",
    "TOTAL_NS",
    "EXECS_TOTAL",
    "CUMUL_NS",
    "XLAT_B",
    "JIT_B",
}


def _render_top_activity_table(rows: list[dict[str, str]]) -> str:
    columns = list(rows[0].keys())
    widths = {column: max(len(column), max(len(row[column]) for row in rows)) for column in columns}
    header = "  ".join(
        _format_cell(column, widths[column], right=column in _TOP_NUMERIC_COLUMNS)
        for column in columns
    )
    body = [
        "  ".join(
            _format_cell(
                row[column],
                widths[column],
                right=column in _TOP_NUMERIC_COLUMNS,
            )
            for column in columns
        )
        for row in rows
    ]
    return "\n".join([header, *body])


def _format_cell(value: str, width: int, *, right: bool) -> str:
    return f"{value:>{width}}" if right else f"{value:<{width}}"


def _format_int(value: int) -> str:
    return f"{value:,}"


def _format_rate(value: int, *, duration: float) -> str:
    if duration <= 0:
        return "0"
    return _format_int(round(value / duration))
