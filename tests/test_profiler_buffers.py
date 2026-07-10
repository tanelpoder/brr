from __future__ import annotations

import pytest

from brr.profiler import plan_perf_buffers, validate_perf_ring_pages


def test_default_direct_buffer_plan() -> None:
    plan = plan_perf_buffers(
        frequency=997,
        cpus=range(4),
        callchain=False,
        call_graph="fp",
        page_size=4096,
        mlock_kb=516,
    )

    assert plan.pages_per_cpu == 8
    assert plan.bytes_per_cpu == 32768
    assert plan.total_mapped_bytes == 4 * (32768 + 4096)
    assert plan.drain_interval_ms == 100
    assert plan.wakeup_watermark_bytes == 8192
    assert plan.estimated_record_bytes == 48
    assert plan.warnings == ()


def test_callchain_plan_uses_mlock_allowance() -> None:
    plan = plan_perf_buffers(
        frequency=997,
        cpus=range(4),
        callchain=True,
        call_graph="fp",
        page_size=4096,
        mlock_kb=516,
        max_stack=127,
        max_contexts=8,
    )

    assert plan.pages_per_cpu == 128
    assert plan.estimated_record_bytes == 1136
    assert plan.drain_interval_ms == 100


def test_lbr_plan_reduces_drain_interval_when_capped() -> None:
    plan = plan_perf_buffers(
        frequency=997,
        cpus=range(4),
        callchain=True,
        call_graph="lbr",
        page_size=4096,
        mlock_kb=516,
    )

    assert plan.pages_per_cpu == 128
    assert plan.drain_interval_ms == 82
    assert "capped" in plan.warnings[0]


def test_explicit_overrides_are_preserved_with_warning() -> None:
    plan = plan_perf_buffers(
        frequency=10_000,
        cpus=(0, 1),
        callchain=False,
        call_graph="fp",
        requested_pages=8,
        requested_drain_ms=500,
        page_size=4096,
        mlock_kb=516,
    )

    assert plan.pages_per_cpu == 8
    assert plan.drain_interval_ms == 500
    assert any("exceeds the estimated safe interval" in warning for warning in plan.warnings)


@pytest.mark.parametrize("pages", [1, 2, 8, 128])
def test_power_of_two_page_validation(pages: int) -> None:
    assert validate_perf_ring_pages(pages) == pages


@pytest.mark.parametrize("pages", [0, -1, 3, 12])
def test_invalid_page_counts(pages: int) -> None:
    with pytest.raises(ValueError, match="positive power of two"):
        validate_perf_ring_pages(pages)
