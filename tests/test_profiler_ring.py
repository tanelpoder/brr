from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from brr import profiler
from brr.profiler import (
    PERF_MMAP_DATA_HEAD_OFFSET,
    PERF_MMAP_DATA_OFFSET_OFFSET,
    PERF_MMAP_DATA_SIZE_OFFSET,
    PERF_MMAP_DATA_TAIL_OFFSET,
    PERF_RECORD_LOST,
    PERF_RECORD_SAMPLE,
    PERF_RECORD_THROTTLE,
    PERF_RECORD_UNTHROTTLE,
    PERF_SAMPLE_IP,
    PerfRingMemoryOrder,
    parse_perf_mmap_ring,
    parse_perf_records,
)


class FakeAtomicFunction:
    argtypes: list[object]
    restype: object

    def __call__(self, *_args) -> None:
        return None


def fake_atomic_library() -> SimpleNamespace:
    return SimpleNamespace(
        __atomic_load_8=FakeAtomicFunction(),
        __atomic_store_8=FakeAtomicFunction(),
    )


def _record(record_type: int, payload: bytes = b"") -> bytes:
    return struct.pack("<IHH", record_type, 0, 8 + len(payload)) + payload


def _write_ring_bytes(ring: bytearray, position: int, payload: bytes) -> None:
    data_offset = 4096
    data_size = 4096
    for index, value in enumerate(payload):
        ring[data_offset + ((position + index) % data_size)] = value


def test_parse_perf_records_reports_loss_throttle_and_unknown() -> None:
    sample = _record(PERF_RECORD_SAMPLE, struct.pack("<Q", 0x1234))
    lost = _record(PERF_RECORD_LOST, struct.pack("<QQ", 1, 7))
    records = b"".join(
        [
            sample,
            lost,
            _record(PERF_RECORD_THROTTLE),
            _record(PERF_RECORD_UNTHROTTLE),
            _record(999),
        ]
    )

    result = parse_perf_records(records, PERF_SAMPLE_IP)

    assert [sample.ip for sample in result.samples] == [0x1234]
    assert result.lost_samples == 7
    assert result.throttle_events == 1
    assert result.unthrottle_events == 1
    assert result.unknown_records == 1
    assert result.malformed_records == 0


def test_parse_perf_records_reports_malformed_tail() -> None:
    result = parse_perf_records(struct.pack("<IHH", PERF_RECORD_SAMPLE, 0, 64), PERF_SAMPLE_IP)

    assert result.samples == []
    assert result.malformed_records == 1
    assert result.discarded_bytes == 8


def test_incremental_ring_drain_handles_wrap_and_advances_tail() -> None:
    ring = bytearray(8192)
    struct.pack_into("<Q", ring, PERF_MMAP_DATA_OFFSET_OFFSET, 4096)
    struct.pack_into("<Q", ring, PERF_MMAP_DATA_SIZE_OFFSET, 4096)
    start = 4090
    first = _record(PERF_RECORD_SAMPLE, struct.pack("<Q", 0xAAAA))
    _write_ring_bytes(ring, start, first)
    struct.pack_into("<Q", ring, PERF_MMAP_DATA_TAIL_OFFSET, start)
    struct.pack_into("<Q", ring, PERF_MMAP_DATA_HEAD_OFFSET, start + len(first))

    result = parse_perf_mmap_ring(ring, PERF_SAMPLE_IP)

    assert [sample.ip for sample in result.samples] == [0xAAAA]
    assert result.available_bytes == len(first)
    assert struct.unpack_from("<Q", ring, PERF_MMAP_DATA_TAIL_OFFSET)[0] == start + len(first)

    second_start = start + len(first)
    second = _record(PERF_RECORD_SAMPLE, struct.pack("<Q", 0xBBBB))
    _write_ring_bytes(ring, second_start, second)
    struct.pack_into("<Q", ring, PERF_MMAP_DATA_HEAD_OFFSET, second_start + len(second))

    result = parse_perf_mmap_ring(ring, PERF_SAMPLE_IP)

    assert [sample.ip for sample in result.samples] == [0xBBBB]
    assert struct.unpack_from("<Q", ring, PERF_MMAP_DATA_TAIL_OFFSET)[0] == (
        second_start + len(second)
    )


def test_perf_ring_memory_order_tries_bundled_libatomic_soname(monkeypatch) -> None:
    loaded_names = []
    monkeypatch.setattr(profiler.ctypes.util, "find_library", lambda _name: None)
    monkeypatch.setattr(
        profiler.ctypes,
        "CDLL",
        lambda name: loaded_names.append(name) or fake_atomic_library(),
    )

    memory_order = PerfRingMemoryOrder()

    assert memory_order._atomic is not None
    assert loaded_names == ["libatomic.so.1"]


def test_perf_ring_memory_order_preserves_missing_library_fallback(monkeypatch) -> None:
    monkeypatch.setattr(profiler.ctypes.util, "find_library", lambda _name: None)
    monkeypatch.setattr(
        profiler.ctypes,
        "CDLL",
        lambda _name: (_ for _ in ()).throw(OSError("missing")),
    )
    monkeypatch.setattr(profiler.platform, "machine", lambda: "aarch64")
    memory_order = PerfRingMemoryOrder()

    with pytest.raises(profiler.UnsupportedFeatureError, match="libatomic is required"):
        memory_order.load_acquire(bytearray(16), 0)
