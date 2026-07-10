from __future__ import annotations

from brr.inspection import (
    BrrInspectReport,
    BrrInspectRow,
    build_inspect_report,
    limit_inspect_report_source_rows,
)
from brr.models import (
    BpfHotspot,
    BpfInstruction,
    BpfKernelHotspot,
    BpfProfile,
    BpfProfileMetadata,
    BpfProfileProgram,
    BpfProgram,
    BpfProgramDump,
    BpfSourceLine,
)
from brr.render.brr_text import render_brr_inspect


def _program() -> BpfProgram:
    return BpfProgram(id=42, program_type="tracing", name="sample")


def _profile_program() -> BpfProfileProgram:
    return BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=80,
        sample_percent=20.0,
        cpu_percent=120.0,
        kernel_samples=20,
        kernel_cpu_percent=30.0,
        inclusive_samples=100,
        inclusive_cpu_percent=150.0,
    )


def _profile(program: BpfProfileProgram | None = None) -> BpfProfile:
    metadata = BpfProfileMetadata(
        requested_event="cycles",
        selected_event="cycles:k",
        duration=5.0,
        frequency=997,
        limit=1,
        line_limit=5,
        total_samples=400,
        lost_samples=2,
        unresolved_samples=250,
        selected_program_samples=80,
        source_mapped_samples=75,
        source_unmapped_samples=5,
        actual_duration=4.75,
        perf_running_percent=98.5,
        perf_max_ring_occupancy_percent=12.3,
        incomplete=True,
        warnings=("capture lost samples",),
    )
    return BpfProfile(metadata=metadata, items=[program] if program is not None else [])


def test_inspect_samples_and_this_percent_rendering() -> None:
    profile_program = _profile_program()
    report = BrrInspectReport(
        program=_program(),
        mode="mixed",
        rows=[
            BrrInspectRow(kind="source", code="parent source", samples=60, attribution="aggregate"),
            BrrInspectRow(
                kind="instruction", code="direct instruction", samples=40, attribution="direct"
            ),
            BrrInspectRow(kind="kernel", code="helper child", samples=20, attribution="under"),
            BrrInspectRow(kind="instruction", code="cold instruction", attribution="direct"),
        ],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    text = render_brr_inspect(report)

    assert "SAMPLES" in text
    assert "%THIS" in text
    assert "%PROG" not in text
    assert "WEIGHT" not in text
    table_header = next(line for line in text.splitlines() if "%THIS" in line and "SAMPLES" in line)
    assert table_header.index("%THIS") < table_header.index("SAMPLES") < table_header.index("CODE")
    assert not any("60" in line and "parent source" in line for line in text.splitlines())
    assert any("40.00" in line and "direct instruction" in line for line in text.splitlines())
    assert any("20.00" in line and "helper child" in line for line in text.splitlines())
    assert not any("0.00" in line and "cold instruction" in line for line in text.splitlines())
    assert any(
        "40.00" in line and "Other eBPF samples not placed" in line for line in text.splitlines()
    )
    assert "Unaccounted samples" not in text


def test_this_percent_is_blank_without_profile_or_with_zero_denominator() -> None:
    row = BrrInspectRow(kind="source", code="source", samples=3, attribution="direct")
    unprofiled = BrrInspectReport(program=_program(), mode="source", rows=[row])
    zero_program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=0,
        sample_percent=0,
    )
    zero = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=[row],
        profile=_profile(),
        profile_program=zero_program,
    )

    assert unprofiled.this_percent(0) == ""
    assert zero.this_percent(0) == ""
    rendered = render_brr_inspect(unprofiled)
    assert "%THIS" in rendered
    assert any("3" in line and "source" in line for line in rendered.splitlines()[1:])


def test_direct_only_profile_uses_direct_samples_as_inclusive_denominator() -> None:
    row = BrrInspectRow(kind="instruction", code="instruction", samples=20, attribution="direct")
    profile_program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=40,
        sample_percent=10,
    )
    report = BrrInspectReport(
        program=_program(),
        mode="mixed",
        rows=[row],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    assert profile_program.inclusive_samples == 40
    assert report.this_percent(0) == "50.00"
    assert report.rows[-1].attribution == "direct"
    assert report.this_percent(len(report.rows) - 1) == "50.00"


def test_source_parent_and_helper_samples_do_not_overlap() -> None:
    source = BpfSourceLine("sample.bpf.c", 10, 2, "return 0;")
    dump = BpfProgramDump(
        program=_program(),
        instructions=[BpfInstruction(0, "95000000", 0x95, 0, 0, 0, 0, source)],
        line_info_count=1,
    )
    report = build_inspect_report(
        dump,
        mode="source",
        hotspots=[
            BpfHotspot(
                samples=80,
                sample_percent=100,
                file_name=source.file_name,
                line_number=source.line_number,
                column=source.column,
                source=source.source,
            )
        ],
        kernel_hotspots=[
            BpfKernelHotspot(
                samples=20,
                sample_percent=100,
                cpu_percent=30,
                ip=0xFFFF,
                symbol="bpf_get_current_task",
                symbol_kind="helper",
                bpf_file_name=source.file_name,
                bpf_line_number=source.line_number,
                bpf_column=source.column,
                bpf_source=source.source,
            )
        ],
    )

    assert [(row.kind, row.samples) for row in report.rows] == [
        ("source", 80),
        ("kernel", 20),
    ]
    assert [row.attribution for row in report.rows] == ["direct", "under"]


def test_kernel_function_rows_hide_offsets_until_ip_detail_is_enabled() -> None:
    source = BpfSourceLine("sample.bpf.c", 10, 2, "call helper;")
    dump = BpfProgramDump(
        program=_program(),
        instructions=[BpfInstruction(0, "95000000", 0x95, 0, 0, 0, 0, source)],
        line_info_count=1,
    )
    raw_hotspots = [
        BpfKernelHotspot(
            samples=3,
            sample_percent=60,
            cpu_percent=3,
            ip=0x5001,
            symbol="bpf_task_storage_get",
            symbol_offset=1,
            symbol_kind="bpf_helper",
            bpf_file_name=source.file_name,
            bpf_line_number=source.line_number,
            bpf_source=source.source,
        ),
        BpfKernelHotspot(
            samples=2,
            sample_percent=40,
            cpu_percent=2,
            ip=0x5002,
            symbol="bpf_task_storage_get",
            symbol_offset=2,
            symbol_kind="bpf_helper",
            bpf_file_name=source.file_name,
            bpf_line_number=source.line_number,
            bpf_source=source.source,
        ),
    ]
    function_hotspot = BpfKernelHotspot(
        samples=5,
        sample_percent=100,
        cpu_percent=5,
        ip=0x5001,
        symbol="bpf_task_storage_get",
        symbol_kind="bpf_helper",
        bpf_file_name=source.file_name,
        bpf_line_number=source.line_number,
        bpf_source=source.source,
        ip_count=2,
    )

    collapsed = build_inspect_report(
        dump,
        mode="source",
        hotspots=[],
        kernel_hotspots=[function_hotspot],
    )
    detailed = build_inspect_report(
        dump,
        mode="source",
        hotspots=[],
        kernel_hotspots=raw_hotspots,
        kernel_ip_detail=True,
    )

    collapsed_children = [row for row in collapsed.rows if row.kind == "kernel"]
    detailed_children = [row for row in detailed.rows if row.kind == "kernel"]
    assert len(collapsed_children) == 1
    assert collapsed_children[0].samples == 5
    assert "bpf_task_storage_get (2 IPs)" in collapsed_children[0].code
    assert "+0x" not in collapsed_children[0].code
    assert [row.samples for row in detailed_children] == [3, 2]
    assert "+0x1" in detailed_children[0].code
    assert "+0x2" in detailed_children[1].code


def test_mixed_view_uses_translated_instruction_offset_for_hotspots() -> None:
    source = BpfSourceLine("sample.bpf.c", 10, 2, "return 0;")
    dump = BpfProgramDump(
        program=_program(),
        instructions=[BpfInstruction(24, "95000000", 0x95, 0, 0, 0, 0, source)],
        line_info_count=1,
    )
    report = build_inspect_report(
        dump,
        mode="mixed",
        hotspots=[
            BpfHotspot(
                samples=5,
                sample_percent=100,
                jited_address=0x1237,
                instruction_offset=24,
                file_name=source.file_name,
                line_number=source.line_number,
                column=source.column,
                source=source.source,
            )
        ],
    )

    instruction = next(row for row in report.rows if row.kind == "instruction")
    assert instruction.samples == 5


def test_profile_context_uses_complete_direct_and_under_cpu_totals() -> None:
    profile_program = _profile_program()
    report = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=[
            BrrInspectRow(kind="source", code="source", samples=80, attribution="direct"),
            BrrInspectRow(kind="kernel", code="helper", samples=10, attribution="under"),
        ],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    lines = render_brr_inspect(report).splitlines()

    assert lines[1] == (
        "CPU: 150.0000% total = 120.0000% eBPF + 30.0000% under eBPF + "
        "0.0000% unaccounted (100% = one CPU)"
    )
    assert lines[2] == "Warning: capture lost samples"
    assert not any(line.startswith(("Capture:", "Samples:")) for line in lines)


def test_this_percent_rounding_totals_exactly_one_hundred() -> None:
    profile_program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=2,
        sample_percent=100,
        kernel_samples=1,
    )
    report = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=[
            BrrInspectRow(kind="source", code="first", samples=1, attribution="direct"),
            BrrInspectRow(kind="source", code="second", samples=1, attribution="direct"),
            BrrInspectRow(kind="kernel", code="helper", samples=1, attribution="under"),
        ],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    percentages = [report.this_percent(index) for index in range(len(report.rows))]

    assert percentages == ["33.34", "33.33", "33.33"]
    assert sum(float(value) for value in percentages) == 100.0


def test_line_limits_remain_in_direct_and_under_attribution() -> None:
    direct_hotspot = BpfHotspot(
        samples=12,
        sample_percent=63.16,
        instruction_offset=0,
        file_name="sample.bpf.c",
        line_number=10,
        source="direct",
    )
    under_hotspot = BpfKernelHotspot(
        samples=24,
        sample_percent=36.92,
        cpu_percent=24,
        ip=0xFFFF,
        bpf_instruction_offset=0,
        bpf_file_name="sample.bpf.c",
        bpf_line_number=10,
        bpf_source="direct",
    )
    profile_program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=19,
        sample_percent=100,
        cpu_percent=19,
        hotspots=[direct_hotspot],
        kernel_samples=65,
        kernel_cpu_percent=65,
        kernel_hotspots=[under_hotspot],
        inclusive_samples=84,
        inclusive_cpu_percent=84,
        direct_source_mapped_samples=19,
        under_bpf_caller_source_mapped_samples=65,
        direct_hotspot_samples_omitted_by_limit=7,
        under_bpf_hotspot_samples_omitted_by_limit=41,
    )
    report = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=[
            BrrInspectRow(kind="source", code="direct", samples=12, attribution="direct"),
            BrrInspectRow(kind="kernel", code="under", samples=24, attribution="under"),
        ],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    rendered = render_brr_inspect(report)

    assert sum(row.samples for row in report.rows if row.attribution == "direct") == 19
    assert sum(row.samples for row in report.rows if row.attribution == "under") == 65
    assert sum(float(report.this_percent(index)) for index in range(len(report.rows))) == 100
    assert "Other eBPF samples not shown (--line-limit=5)" in rendered
    assert "Other under-eBPF samples not shown (--line-limit=5)" in rendered
    assert "Unaccounted samples" not in rendered
    assert "19.0000% eBPF + 65.0000% under eBPF + 0.0000% unaccounted" in rendered


def test_source_limit_adds_attributed_summary_rows_outside_limit() -> None:
    profile_program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=3,
        sample_percent=100,
    )
    report = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=[
            BrrInspectRow(kind="source", code=f"line {index}", samples=1, attribution="direct")
            for index in range(3)
        ],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    limited = limit_inspect_report_source_rows(report, 1)

    assert len([row for row in limited.rows if row.kind == "source"]) == 1
    assert sum(row.samples for row in limited.rows if row.attribution == "direct") == 3
    assert limited.rows[-1].samples == 2
    assert "--source-limit=1" in limited.rows[-1].code
    assert sum(float(limited.this_percent(index)) for index in range(len(limited.rows))) == 100


def test_missing_source_metadata_keeps_known_cpu_attribution() -> None:
    profile_program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=2,
        sample_percent=100,
        kernel_samples=1,
        direct_source_mapped_samples=1,
        direct_source_unmapped_samples=1,
        under_bpf_caller_source_unmapped_samples=1,
    )
    report = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=[BrrInspectRow(kind="source", code="mapped", samples=1, attribution="direct")],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    assert sum(row.samples for row in report.rows if row.attribution == "direct") == 2
    assert sum(row.samples for row in report.rows if row.attribution == "under") == 1
    assert any("without BTF/JIT" in row.code for row in report.rows)
    assert any("without BPF caller" in row.code for row in report.rows)
    assert not any(row.attribution == "unaccounted" for row in report.rows)


def test_only_inclusive_attribution_residual_is_unaccounted() -> None:
    profile_program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=8,
        sample_percent=100,
        cpu_percent=80,
        kernel_samples=1,
        kernel_cpu_percent=10,
        inclusive_samples=10,
        inclusive_cpu_percent=100,
    )
    report = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=[
            BrrInspectRow(kind="source", code="direct", samples=8, attribution="direct"),
            BrrInspectRow(kind="kernel", code="under", samples=1, attribution="under"),
        ],
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    assert profile_program.unaccounted_samples == 1
    assert report.rows[-1].attribution == "unaccounted"
    assert report.rows[-1].samples == 1
    assert "invariant mismatch" in report.rows[-1].code
    assert sum(float(report.this_percent(index)) for index in range(len(report.rows))) == 100


def test_collapsed_text_rolls_helper_samples_into_caller() -> None:
    profile_program = _profile_program()
    rows = [
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
    ]
    report = BrrInspectReport(
        program=_program(),
        mode="source",
        rows=rows,
        profile=_profile(profile_program),
        profile_program=profile_program,
    )

    expanded = render_brr_inspect(report)
    collapsed = render_brr_inspect(report, collapse_samples=True)

    assert any("80.00" in line and "- caller" in line for line in expanded.splitlines())
    assert any("20.00" in line and "-> helper" in line for line in expanded.splitlines())
    assert "helper" not in collapsed
    assert any("100.00" in line and "+ caller" in line for line in collapsed.splitlines())
