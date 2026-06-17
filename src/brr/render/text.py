from __future__ import annotations

from pathlib import PurePath

from brr.dump_compare import DumpCompareResult
from brr.models import (
    BpfHotspot,
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


def render_programs(programs: list[BpfProgram], *, with_stats: bool = False) -> str:
    if not programs:
        return "No eBPF programs found."

    rows = []
    for program in programs:
        row = {
            "ID": str(program.id),
            "TYPE": program.program_type,
            "NAME": program.name,
            "XLATED_BYTES": str(program.xlated_size_bytes),
            "JITED_BYTES": str(program.jited_size_bytes),
            "TAG": program.tag or "-",
            "PINNED": ",".join(program.pinned_paths) if program.pinned_paths else "-",
        }
        if with_stats:
            row["RUN_CNT"] = str(program.run_count or 0)
            row["RUN_TIME_NS"] = str(program.run_time_ns or 0)
        rows.append(row)
    return _render_table(rows)


def render_program_activity(activities: list[BpfProgramActivity]) -> str:
    if not activities:
        return "No active eBPF program runtime deltas observed."

    return _render_table(
        [
            {
                "ID": str(activity.id),
                "TYPE": activity.program_type,
                "NAME": activity.name,
                "XLATED_BYTES": str(activity.xlated_size_bytes),
                "JITED_BYTES": str(activity.jited_size_bytes),
                "RUN_CNT_DELTA": str(activity.run_count_delta),
                "RUN_TIME_NS_DELTA": str(activity.run_time_ns_delta),
                "AVG_RUN_TIME_NS": str(activity.avg_run_time_ns),
                "TAG": activity.tag or "-",
                "PINNED": ",".join(activity.pinned_paths) if activity.pinned_paths else "-",
            }
            for activity in activities
        ]
    )


def render_program_dump(
    dump: BpfProgramDump,
    *,
    source_context: SourceContextReport | None = None,
) -> str:
    identity = (
        f"Program {dump.program.id}: type={dump.program.program_type} "
        f"name={dump.program.name} tag={dump.program.tag or '-'}"
    )
    if not dump.instructions:
        sections = [identity, "No translated eBPF instructions available."]
        if source_context is not None:
            sections.append(_render_source_context(source_context, title="Source context"))
        return "\n".join(sections)

    rows = []
    for instruction in dump.instructions:
        source = instruction.source
        rows.append(
            {
                "OFF": f"0x{instruction.offset:04x}",
                "RAW": instruction.raw,
                "OP": f"0x{instruction.opcode:02x}",
                "DST": str(instruction.dst_reg),
                "SRC": str(instruction.src_reg),
                "INSN_OFF": str(instruction.off),
                "IMM": str(instruction.imm),
                "FILE": source.file_name if source is not None and source.file_name else "-",
                "LINE": (
                    str(source.line_number)
                    if source is not None and source.line_number is not None
                    else "-"
                ),
                "SOURCE": source.source if source is not None and source.source else "-",
            }
        )
    sections = [identity, _render_table(rows)]
    if source_context is not None:
        sections.append(_render_source_context(source_context, title="Source context"))
    return "\n".join(sections)


def render_dump_compare(result: DumpCompareResult) -> str:
    status = "PASS" if result.passed else "FAIL"
    lines = [
        (
            f"{status} program={result.program_id} "
            f"brr_slots={result.brr_instruction_slots} "
            f"brr_visible={result.brr_visible_slots} "
            f"bpftool={result.bpftool_instruction_count} "
            f"lddw_slots={result.lddw_slots} "
            f"source_rows={result.source_rows_compared}"
        )
    ]
    for mismatch in result.offset_mismatches[:5]:
        lines.append(
            "offset mismatch "
            f"position={mismatch.position} "
            f"expected_index={_optional_number(mismatch.expected_index)} "
            f"actual_index={_optional_number(mismatch.actual_index)}"
        )
    for mismatch in result.source_mismatches[:5]:
        lines.append(
            "source mismatch "
            f"index={mismatch.index} field={mismatch.field} "
            f"expected={_optional_value(mismatch.expected)} "
            f"actual={_optional_value(mismatch.actual)}"
        )
    return "\n".join(lines)


def render_profile(
    profile: BpfProfile,
    *,
    wide: bool = False,
    source_context_by_program: dict[int, SourceContextReport] | None = None,
) -> str:
    if not profile.items:
        return "\n".join([*_profile_warning_lines(profile), "No BPF JIT samples captured."])

    show_kernel_summary = any(program.kernel_samples for program in profile.items)
    program_rows = [
        _profile_program_row(program, wide=wide, show_kernel=show_kernel_summary)
        for program in profile.items
    ]
    rendered = [*_profile_warning_lines(profile), _render_table(program_rows)]
    for program in profile.items:
        source_context = (
            source_context_by_program.get(program.id)
            if source_context_by_program is not None
            else None
        )
        if program.hotspots:
            rendered.append(f"Breakdown of program {program.id} ({program.name}):")
            rendered.append(
                _render_table(
                    [_profile_hotspot_row(hotspot, wide=wide) for hotspot in program.hotspots]
                )
            )
        if program.kernel_hotspots:
            rendered.append(f"Kernel/helper samples for program {program.id} ({program.name}):")
            rendered.append(
                _render_table(
                    [
                        _profile_kernel_hotspot_row(hotspot, wide=wide)
                        for hotspot in program.kernel_hotspots
                    ]
                )
            )
        if source_context is not None:
            rendered.append(
                _render_source_context(
                    source_context,
                    title=f"Source context for program {program.id}",
                )
            )
    return "\n\n".join(rendered)


def _profile_warning_lines(profile: BpfProfile) -> list[str]:
    return [f"Warning: {warning}" for warning in profile.metadata.warnings]


def render_perf_events(events: list[PerfEventAvailability]) -> str:
    if not events:
        return "No openable brr perf events found."
    return _render_table(
        [
            {
                "NAME": event.name,
                "TYPE": event.event_type,
                "CONFIG": str(event.config),
                "PRECISE": str(event.precise_ip),
                "AUTO": "yes" if event.selected_by_auto else "",
            }
            for event in events
        ]
    )


def _profile_hotspot_row(hotspot: BpfHotspot, *, wide: bool) -> dict[str, str]:
    row = {}
    if wide:
        row["SAMPLES"] = str(hotspot.samples)
    row["CPU%"] = f"{hotspot.cpu_percent:.4f}"
    if wide:
        row["JIT_ADDR"] = (
            f"0x{hotspot.jited_address:x}" if hotspot.jited_address is not None else "-"
        )
    row["FILE"] = _profile_file_name(hotspot.file_name, wide=wide)
    row["LINE"] = str(hotspot.line_number) if hotspot.line_number is not None else "-"
    row["SOURCE"] = hotspot.source or "-"
    return row


def _profile_program_row(
    program: BpfProfileProgram,
    *,
    wide: bool,
    show_kernel: bool = False,
) -> dict[str, str]:
    row = {
        "ID": str(program.id),
        "TYPE": program.program_type,
        "NAME": program.name,
    }
    if wide:
        row["SAMPLES"] = str(program.samples)
    if show_kernel:
        row["KERNEL_SAMPLES"] = str(program.kernel_samples)
        row["INCL_SAMPLES"] = str(program.inclusive_samples)
    row["CPU%"] = f"{program.cpu_percent:.4f}"
    if show_kernel:
        row["KERNEL_CPU%"] = f"{program.kernel_cpu_percent:.4f}"
        row["INCL_CPU%"] = f"{program.inclusive_cpu_percent:.4f}"
    row["TAG"] = program.tag or "-"
    row["PINNED"] = ",".join(program.pinned_paths) if program.pinned_paths else "-"
    return row


def _profile_kernel_hotspot_row(hotspot: BpfKernelHotspot, *, wide: bool) -> dict[str, str]:
    row = {}
    if wide:
        row["SAMPLES"] = str(hotspot.samples)
    row["CPU%"] = f"{hotspot.cpu_percent:.4f}"
    row["KIND"] = hotspot.symbol_kind
    row["SYMBOL"] = hotspot.symbol or "-"
    row["MODULE"] = hotspot.module or "-"
    if wide:
        row["IP"] = f"0x{hotspot.ip:x}"
        row["SYMBOL_OFF"] = (
            f"0x{hotspot.symbol_offset:x}" if hotspot.symbol_offset is not None else "-"
        )
        row["BPF_JIT_ADDR"] = (
            f"0x{hotspot.bpf_jited_address:x}" if hotspot.bpf_jited_address is not None else "-"
        )
    row["BPF_FILE"] = _profile_file_name(hotspot.bpf_file_name, wide=wide)
    row["BPF_LINE"] = str(hotspot.bpf_line_number) if hotspot.bpf_line_number is not None else "-"
    row["BPF_SOURCE"] = hotspot.bpf_source or "-"
    return row


def _render_source_context(report: SourceContextReport, *, title: str) -> str:
    if not report.rows:
        sections = _source_context_warning_lines(report)
        sections.append(f"{title}: no matching source context found.")
        return "\n".join(sections)
    rows = [
        {
            "KIND": "mapped" if row.mapped else "context",
            "FILE": _profile_file_name(row.file_name, wide=False),
            "LINE": str(row.line_number),
            "SOURCE": row.source or "-",
        }
        for row in report.rows
    ]
    return "\n".join([*_source_context_warning_lines(report), f"{title}:", _render_table(rows)])


def _source_context_warning_lines(report: SourceContextReport) -> list[str]:
    if not report.source_mismatches:
        return []
    lines = [
        (
            "Warning: "
            f"{len(report.source_mismatches)} BTF source snippet(s) differ from resolved files."
        )
    ]
    for mismatch in report.source_mismatches[:5]:
        lines.append(
            "source mismatch "
            f"file={_profile_file_name(mismatch.file_name, wide=False)} "
            f"line={mismatch.line_number} "
            f"resolved={mismatch.resolved_path}"
        )
    return lines


def render_maps(maps: list[BpfMap]) -> str:
    if not maps:
        return "No eBPF maps found."
    return _render_table(
        [
            {
                "ID": str(map_.id),
                "TYPE": map_.map_type,
                "NAME": map_.name,
                "KEY": str(map_.key_size),
                "VALUE": str(map_.value_size),
                "MAX_ENTRIES": str(map_.max_entries),
                "BTF_ID": str(map_.btf_id or "-"),
                "PINNED": ",".join(map_.pinned_paths) if map_.pinned_paths else "-",
            }
            for map_ in maps
        ]
    )


def render_links(links: list[BpfLink]) -> str:
    if not links:
        return "No eBPF links found."
    return _render_table(
        [
            {
                "ID": str(link.id),
                "TYPE": link.link_type,
                "PROG_ID": str(link.prog_id),
                "ATTACH_TYPE": link.attach_type or "-",
                "TARGET_OBJ_ID": str(link.target_obj_id or "-"),
                "TARGET_BTF_ID": str(link.target_btf_id or "-"),
                "PINNED": ",".join(link.pinned_paths) if link.pinned_paths else "-",
            }
            for link in links
        ]
    )


def render_btfs(btfs: list[BtfObject]) -> str:
    if not btfs:
        return "No BTF objects found."
    return _render_table(
        [
            {
                "ID": str(btf.id),
                "NAME": btf.name,
                "SIZE": str(btf.size),
            }
            for btf in btfs
        ]
    )


def _render_table(rows: list[dict[str, str]]) -> str:
    columns = list(rows[0].keys())
    widths = {column: max(len(column), max(len(row[column]) for row in rows)) for column in columns}
    header = "  ".join(
        _format_cell(column, widths[column], right=column == "ID") for column in columns
    )
    body = [
        "  ".join(
            _format_cell(row[column], widths[column], right=_is_numeric_column(column))
            for column in columns
        )
        for row in rows
    ]
    return "\n".join([header, *body])


def _format_cell(value: str, width: int, *, right: bool) -> str:
    return f"{value:>{width}}" if right else f"{value:<{width}}"


def _optional_number(value: int | None) -> str:
    return str(value) if value is not None else "-"


def _optional_value(value: str | int | None) -> str:
    return str(value) if value is not None else "-"


def _profile_file_name(file_name: str | None, *, wide: bool) -> str:
    if not file_name:
        return "-"
    if wide:
        return file_name
    return PurePath(file_name).name or file_name


def _is_numeric_column(column: str) -> bool:
    return column in {
        "ID",
        "KEY",
        "VALUE",
        "MAX_ENTRIES",
        "BTF_ID",
        "PROG_ID",
        "TARGET_OBJ_ID",
        "TARGET_BTF_ID",
        "RUN_CNT",
        "RUN_TIME_NS",
        "XLATED_BYTES",
        "JITED_BYTES",
        "RUN_CNT_DELTA",
        "RUN_TIME_NS_DELTA",
        "AVG_RUN_TIME_NS",
        "SIZE",
        "SAMPLES",
        "KERNEL_SAMPLES",
        "BPF%",
        "CPU%",
        "KERNEL_CPU%",
        "LINE",
        "BPF_LINE",
        "SYMBOL_OFF",
        "COLUMN",
        "DST",
        "SRC",
        "INSN_OFF",
        "IMM",
    }
