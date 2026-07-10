from __future__ import annotations

import csv
import json
from io import StringIO

from brr.models import (
    BpfHotspot,
    BpfKernelHotspot,
    BpfProfile,
    BpfProfileMetadata,
    BpfProfileProgram,
)
from brr.render.csv_output import render_profile_csv
from brr.render.json_output import render_profile_json
from brr.render.text import render_profile


def _profile() -> BpfProfile:
    program = BpfProfileProgram(
        id=42,
        program_type="tracing",
        name="sample",
        tag=None,
        samples=19,
        sample_percent=100,
        cpu_percent=19,
        hotspots=[
            BpfHotspot(
                samples=12,
                sample_percent=63.16,
                cpu_percent=12,
                jited_address=0x1000,
                instruction_offset=24,
                file_name="sample.bpf.c",
                line_number=10,
                source="direct",
            )
        ],
        kernel_samples=65,
        kernel_cpu_percent=65,
        kernel_hotspots=[
            BpfKernelHotspot(
                samples=24,
                sample_percent=36.92,
                cpu_percent=24,
                ip=0x2000,
                bpf_jited_address=0x1000,
                bpf_instruction_offset=24,
                bpf_file_name="sample.bpf.c",
                bpf_line_number=10,
                bpf_source="direct",
            )
        ],
        direct_source_mapped_samples=19,
        under_bpf_caller_source_mapped_samples=65,
        direct_hotspot_samples_omitted_by_limit=7,
        under_bpf_hotspot_samples_omitted_by_limit=41,
    )
    return BpfProfile(
        metadata=BpfProfileMetadata(
            requested_event="cycles",
            selected_event="cycles",
            duration=1,
            frequency=100,
            limit=1,
            line_limit=5,
            total_samples=84,
            lost_samples=0,
            unresolved_samples=0,
        ),
        items=[program],
    )


def test_profile_text_reports_direct_and_under_limit_aggregates() -> None:
    rendered = render_profile(_profile())

    assert "Other eBPF samples not shown (--line-limit=5)" in rendered
    assert "Other under-eBPF samples not shown (--line-limit=5)" in rendered
    assert "Unaccounted samples" not in rendered
    assert any(line.strip().startswith("7 ") for line in rendered.splitlines())
    assert any(line.strip().startswith("41 ") for line in rendered.splitlines())


def test_profile_json_exposes_attribution_diagnostics_and_instruction_offsets() -> None:
    program = json.loads(render_profile_json(_profile()))["items"][0]

    assert program["direct_source_mapped_samples"] == 19
    assert program["direct_source_unmapped_samples"] == 0
    assert program["under_bpf_caller_source_mapped_samples"] == 65
    assert program["direct_hotspot_samples_omitted_by_limit"] == 7
    assert program["under_bpf_hotspot_samples_omitted_by_limit"] == 41
    assert program["unaccounted_samples"] == 0
    assert program["hotspots"][0]["instruction_offset"] == 24
    assert program["kernel_hotspots"][0]["bpf_instruction_offset"] == 24


def test_profile_csv_exposes_attribution_diagnostics_and_instruction_offsets() -> None:
    rows = list(csv.DictReader(StringIO(render_profile_csv(_profile()))))

    assert rows[0]["program_direct_source_mapped_samples"] == "19"
    assert rows[0]["program_direct_hotspot_samples_omitted_by_limit"] == "7"
    assert rows[0]["program_under_bpf_hotspot_samples_omitted_by_limit"] == "41"
    assert rows[0]["program_unaccounted_samples"] == "0"
    assert rows[0]["instruction_offset"] == "24"
    assert rows[1]["bpf_instruction_offset"] == "24"
