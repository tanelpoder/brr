from __future__ import annotations

import select
import struct
from dataclasses import dataclass

import pytest

from brr.errors import PerfBufferAllocationError
from brr.profiler import (
    CPU_CLOCK_EVENT,
    PERF_MMAP_DATA_HEAD_OFFSET,
    PERF_MMAP_DATA_OFFSET_OFFSET,
    PERF_MMAP_DATA_SIZE_OFFSET,
    PERF_RECORD_SAMPLE,
    PerfSampler,
)


def _sample_record(ip: int) -> bytes:
    payload = struct.pack("<QIIQIIQ", ip, 1, 1, 1, 0, 0, 1)
    return struct.pack("<IHH", PERF_RECORD_SAMPLE, 0, 8 + len(payload)) + payload


@dataclass
class _Clock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now


class _Handle:
    def __init__(self) -> None:
        self.fd = 10
        self.cpu = 0
        self.data_pages = 8
        self.ring = bytearray(4096 * 9)
        struct.pack_into("<Q", self.ring, PERF_MMAP_DATA_OFFSET_OFFSET, 4096)
        struct.pack_into("<Q", self.ring, PERF_MMAP_DATA_SIZE_OFFSET, 4096 * 8)
        self.closed = False

    def read_timing(self) -> tuple[int, int]:
        return (20_000_000, 20_000_000)

    def close(self) -> None:
        self.closed = True


class _Opener:
    def __init__(self, handle: _Handle) -> None:
        self.handle = handle

    def open_handle(self, *args: object, **kwargs: object) -> _Handle:
        return self.handle


class _Poller:
    def __init__(self, handle: _Handle, clock: _Clock) -> None:
        self.handle = handle
        self.clock = clock
        self.calls = 0

    def register(self, fd: int, flags: int) -> None:
        assert fd == self.handle.fd
        assert flags & select.POLLIN

    def poll(self, timeout_ms: int) -> list[tuple[int, int]]:
        self.calls += 1
        record = _sample_record(0x1000 + self.calls)
        head = struct.unpack_from("<Q", self.handle.ring, PERF_MMAP_DATA_HEAD_OFFSET)[0]
        start = 4096 + head
        self.handle.ring[start : start + len(record)] = record
        struct.pack_into(
            "<Q",
            self.handle.ring,
            PERF_MMAP_DATA_HEAD_OFFSET,
            head + len(record),
        )
        self.clock.now += 0.01
        return [(self.handle.fd, select.POLLIN)]


def test_sampler_polls_and_streams_each_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    handle = _Handle()
    clock = _Clock()
    poller = _Poller(handle, clock)
    batches: list[list[int]] = []
    monkeypatch.setattr("brr.profiler.fcntl.ioctl", lambda *args: 0)
    monkeypatch.setattr("brr.profiler.perf_event_max_sample_rate", lambda: 100_000)
    monkeypatch.setattr("brr.profiler.perf_event_mlock_kb", lambda: 516)

    result = PerfSampler(_Opener(handle)).sample(
        event=CPU_CLOCK_EVENT,
        duration=0.02,
        frequency=997,
        cpus=(0,),
        on_samples=lambda samples: batches.append([sample.ip for sample in samples]),
        poll_factory=lambda: poller,
        clock=clock,
    )

    assert batches == [[0x1001], [0x1002]]
    assert result.samples == []
    assert result.drain_count == 2
    assert result.lost_samples == 0
    assert result.running_percent == 100.0
    assert result.actual_duration == pytest.approx(0.02)
    assert handle.closed


class _FailingOpener:
    def open_handle(self, *args: object, **kwargs: object) -> _Handle:
        raise OSError(12, "Cannot allocate memory")


def test_sampler_reports_ring_allocation_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("brr.profiler.perf_event_max_sample_rate", lambda: 100_000)
    monkeypatch.setattr("brr.profiler.perf_event_mlock_kb", lambda: 516)

    with pytest.raises(PerfBufferAllocationError) as failure:
        PerfSampler(_FailingOpener()).sample(
            event=CPU_CLOCK_EVENT,
            duration=0.01,
            frequency=997,
            cpus=(0, 1),
            buffer_pages=128,
        )

    message = str(failure.value)
    assert "CPU 0" in message
    assert "128 data pages" in message
    assert "524288 bytes per CPU" in message
    assert "kernel.perf_event_mlock_kb" in message
