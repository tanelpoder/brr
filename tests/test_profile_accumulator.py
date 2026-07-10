from __future__ import annotations

from brr.models import BpfJitRange, BpfProgram, BpfProgramDetails
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
