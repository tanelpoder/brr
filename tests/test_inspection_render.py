from __future__ import annotations

from brr.inspection import BrrInspectReport, BrrInspectRow, build_inspect_report
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
    assert not any("60" in line and "parent source" in line for line in text.splitlines())
    assert any("40.00" in line and "direct instruction" in line for line in text.splitlines())
    assert any("20.00" in line and "helper child" in line for line in text.splitlines())
    assert not any("0.00" in line and "cold instruction" in line for line in text.splitlines())
    assert any("40.00" in line and "Unaccounted samples" in line for line in text.splitlines())


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
    assert report.rows[-1].attribution == "unaccounted"
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


def test_profile_context_is_compact_and_reports_unaccounted_cpu() -> None:
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
        "CPU: 150.0000% total = 120.0000% eBPF + 15.0000% under eBPF + "
        "15.0000% unaccounted (100% = one CPU)"
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
