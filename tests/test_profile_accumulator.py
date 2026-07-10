from __future__ import annotations

from brr.models import BpfJitRange, BpfLineInfo, BpfProgram, BpfProgramDetails
from brr.profiler import PerfSample, ProfileAccumulator, build_profile


def _details() -> list[BpfProgramDetails]:
    return [
        BpfProgramDetails(
            program=BpfProgram(id=42, program_type="tracing", name="sample"),
            jit_ranges=[BpfJitRange(program_id=42, function_index=0, start=1000, length=100)],
        )
    ]


def test_streaming_accumulator_matches_batch_profile() -> None:
    samples = [PerfSample(ip=1010), PerfSample(ip=1020), PerfSample(ip=5000)]
    expected = build_profile(
        program_details=_details(),
        samples=samples,
        lost_samples=3,
        requested_event="cpu-clock",
        selected_event="cpu-clock",
        duration=1.0,
        frequency=100,
        limit=0,
        line_limit=0,
        warnings=("test warning",),
    )
    accumulator = ProfileAccumulator(
        program_details=_details(),
        requested_event="cpu-clock",
        selected_event="cpu-clock",
        duration=1.0,
        frequency=100,
        limit=0,
        line_limit=0,
    )

    accumulator.consume(samples[:1])
    accumulator.consume(samples[1:])
    actual = accumulator.finish(lost_samples=3, warnings=("test warning",))

    assert actual == expected


def test_profile_tracks_mapping_and_limit_omissions_per_program() -> None:
    details = BpfProgramDetails(
        program=BpfProgram(id=42, program_type="tracing", name="sample"),
        line_info=[
            BpfLineInfo(
                insn_offset=0,
                file_name="sample.bpf.c",
                line_number=10,
                source="first",
                jited_address=1000,
            ),
            BpfLineInfo(
                insn_offset=3,
                file_name="sample.bpf.c",
                line_number=20,
                source="second",
                jited_address=1050,
            ),
        ],
        jit_ranges=[BpfJitRange(program_id=42, function_index=0, start=990, length=110)],
    )
    profile = build_profile(
        program_details=[details],
        samples=[
            PerfSample(ip=1001),
            PerfSample(ip=1002),
            PerfSample(ip=1051),
            PerfSample(ip=995),
            PerfSample(ip=5000, callchain=(1001,)),
            PerfSample(ip=5000, callchain=(1002,)),
            PerfSample(ip=6000, callchain=(1051,)),
            PerfSample(ip=7000, callchain=(995,)),
        ],
        lost_samples=0,
        requested_event="cpu-clock",
        selected_event="cpu-clock",
        duration=1,
        frequency=100,
        limit=1,
        line_limit=1,
        selected_program_id=42,
        kernel_samples=True,
    )

    program = profile.items[0]
    assert program.samples == 4
    assert program.kernel_samples == 4
    assert program.direct_source_mapped_samples == 3
    assert program.direct_source_unmapped_samples == 1
    assert program.under_bpf_caller_source_mapped_samples == 3
    assert program.under_bpf_caller_source_unmapped_samples == 1
    assert program.direct_hotspot_samples_omitted_by_limit == 2
    assert program.under_bpf_hotspot_samples_omitted_by_limit == 2
    assert program.hotspots[0].samples == 2
    assert program.hotspots[0].instruction_offset == 0
    assert program.kernel_hotspots[0].samples == 2
    assert program.kernel_hotspots[0].bpf_instruction_offset == 0
    assert program.unaccounted_samples == 0
