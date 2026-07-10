from __future__ import annotations

import bisect
import ctypes
import ctypes.util
import errno
import fcntl
import math
import mmap
import os
import platform
import resource
import select
import struct
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from typing import Literal

from brr.bpf_details import BPF_INSN_SIZE, JitRangeResolver, SourceLineMapper
from brr.errors import (
    BrrError,
    PerfBufferAllocationError,
    PermissionDeniedError,
    UnsupportedFeatureError,
)
from brr.models import (
    BpfHotspot,
    BpfJitRange,
    BpfKernelHotspot,
    BpfLineInfo,
    BpfProfile,
    BpfProfileMetadata,
    BpfProfileProgram,
    BpfProgramDetails,
)

PERF_TYPE_HARDWARE = 0
PERF_TYPE_SOFTWARE = 1
PERF_COUNT_HW_CPU_CYCLES = 0
PERF_COUNT_HW_INSTRUCTIONS = 1
PERF_COUNT_HW_CACHE_REFERENCES = 2
PERF_COUNT_HW_CACHE_MISSES = 3
PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4
PERF_COUNT_HW_BRANCH_MISSES = 5
PERF_COUNT_HW_BUS_CYCLES = 6
PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7
PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8
PERF_COUNT_HW_REF_CPU_CYCLES = 9
PERF_COUNT_SW_CPU_CLOCK = 0

PERF_SAMPLE_IP = 1 << 0
PERF_SAMPLE_TID = 1 << 1
PERF_SAMPLE_TIME = 1 << 2
PERF_SAMPLE_CALLCHAIN = 1 << 5
PERF_SAMPLE_CPU = 1 << 7
PERF_SAMPLE_PERIOD = 1 << 8
PERF_SAMPLE_BRANCH_STACK = 1 << 11
PROFILE_SAMPLE_TYPE = (
    PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_PERIOD
)
PROFILE_CALLCHAIN_SAMPLE_TYPE = PROFILE_SAMPLE_TYPE | PERF_SAMPLE_CALLCHAIN
PROFILE_BRANCH_STACK_SAMPLE_TYPE = PROFILE_SAMPLE_TYPE | PERF_SAMPLE_BRANCH_STACK

PERF_RECORD_LOST = 2
PERF_RECORD_THROTTLE = 5
PERF_RECORD_UNTHROTTLE = 6
PERF_RECORD_SAMPLE = 9
PERF_RECORD_LOST_SAMPLES = 13
PERF_CONTEXT_MARKER_MIN = (1 << 64) - 4095
PERF_SAMPLE_BRANCH_USER = 1 << 0
PERF_SAMPLE_BRANCH_KERNEL = 1 << 1
PERF_SAMPLE_BRANCH_CALL_STACK = 1 << 11

PERF_FLAG_FD_CLOEXEC = 1 << 3
PERF_EVENT_IOC_ENABLE = 0x2400
PERF_EVENT_IOC_DISABLE = 0x2401
PERF_FORMAT_TOTAL_TIME_ENABLED = 1 << 0
PERF_FORMAT_TOTAL_TIME_RUNNING = 1 << 1
PERF_ATTR_SIZE_VER0 = 64
PERF_ATTR_SIZE_VER2 = 80
CALL_GRAPH_MODES = ("fp", "lbr")

CallGraphMode = Literal["fp", "lbr"]

PERF_MMAP_DATA_HEAD_OFFSET = 1024
PERF_MMAP_DATA_TAIL_OFFSET = 1032
PERF_MMAP_DATA_OFFSET_OFFSET = 1040
PERF_MMAP_DATA_SIZE_OFFSET = 1048
PERF_EVENT_MAX_SAMPLE_RATE_PATH = "/proc/sys/kernel/perf_event_max_sample_rate"
PERF_EVENT_MLOCK_KB_PATH = "/proc/sys/kernel/perf_event_mlock_kb"
PERF_EVENT_MAX_STACK_PATH = "/proc/sys/kernel/perf_event_max_stack"
PERF_EVENT_MAX_CONTEXTS_PATH = "/proc/sys/kernel/perf_event_max_contexts_per_stack"

DEFAULT_PERF_RING_PAGES = 128
MIN_PERF_RING_PAGES = 8
DEFAULT_PERF_DRAIN_MS = 100
MIN_PERF_DRAIN_MS = 1
PERF_RING_HEADROOM = 4
PERF_RING_WATERMARK_FRACTION = 4
BASE_SAMPLE_RECORD_BYTES = 48
MAX_LBR_ENTRIES_ESTIMATE = 64
POLL_ERROR_MASK = select.POLLERR | select.POLLHUP | select.POLLNVAL
ATOMIC_ACQUIRE = 2
ATOMIC_RELEASE = 3

SYS_PERF_EVENT_OPEN_BY_MACHINE = {
    "aarch64": 241,
    "arm64": 241,
    "x86_64": 298,
}


@dataclass(frozen=True, slots=True)
class PerfEventConfig:
    name: str
    event_type: int
    config: int
    precise_ip: int = 0


@dataclass(frozen=True, slots=True)
class PerfEventAvailability:
    name: str
    event_type: str
    config: int
    precise_ip: int
    selected_by_auto: bool = False


@dataclass(frozen=True, slots=True)
class PerfBranchEntry:
    from_ip: int
    to_ip: int
    flags: int


@dataclass(frozen=True, slots=True)
class PerfSample:
    ip: int
    pid: int | None = None
    tid: int | None = None
    time: int | None = None
    cpu: int | None = None
    period: int | None = None
    callchain: tuple[int, ...] = ()
    branch_stack: tuple[PerfBranchEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class KernelSymbol:
    start: int
    end: int | None
    name: str
    module: str | None = None


@dataclass(frozen=True, slots=True)
class KernelSymbolResolution:
    ip: int
    symbol: str | None
    module: str | None
    offset: int | None
    kind: str


@dataclass(frozen=True, slots=True)
class PerfParseResult:
    samples: list[PerfSample]
    lost_samples: int = 0
    throttle_events: int = 0
    unthrottle_events: int = 0
    malformed_records: int = 0
    unknown_records: int = 0
    discarded_bytes: int = 0
    available_bytes: int = 0
    data_size: int = 0
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PerfBufferPlan:
    cpus: tuple[int, ...]
    pages_per_cpu: int
    bytes_per_cpu: int
    total_mapped_bytes: int
    drain_interval_ms: int
    wakeup_watermark_bytes: int
    estimated_record_bytes: int
    pages_auto: bool
    drain_auto: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PerfCaptureResult:
    samples: list[PerfSample]
    lost_samples: int
    throttle_events: int
    unthrottle_events: int
    malformed_records: int
    unknown_records: int
    discarded_bytes: int
    actual_duration: float
    cpus: tuple[int, ...]
    buffer_pages_per_cpu: int
    buffer_bytes_per_cpu: int
    buffer_bytes_total: int
    drain_interval_ms: int
    drain_count: int
    max_ring_occupancy_percent: float
    time_enabled_ns: int
    time_running_ns: int
    running_percent: float
    warnings: tuple[str, ...] = ()

    @property
    def incomplete(self) -> bool:
        return bool(
            self.lost_samples
            or self.throttle_events
            or self.malformed_records
            or self.discarded_bytes
            or self.running_percent < 99.0
            or any("sample rate" in warning or "incomplete" in warning for warning in self.warnings)
        )


@dataclass(slots=True)
class PerfEventHandle:
    fd: int
    ring: mmap.mmap
    cpu: int
    data_pages: int

    def close(self) -> None:
        try:
            self.ring.close()
        finally:
            os.close(self.fd)

    def read_timing(self) -> tuple[int, int]:
        payload = os.read(self.fd, 24)
        if len(payload) < 24:
            return (0, 0)
        _value, enabled, running = struct.unpack_from("<QQQ", payload)
        return (enabled, running)


class PerfOpenError(OSError):
    pass


class PerfRingMemoryOrder:
    def __init__(self) -> None:
        library_name = ctypes.util.find_library("atomic") or "libatomic.so.1"
        try:
            self._atomic = ctypes.CDLL(library_name)
        except OSError:
            self._atomic = None
        if self._atomic is not None:
            self._load = getattr(self._atomic, "__atomic_load_8")
            self._load.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_int]
            self._load.restype = ctypes.c_uint64
            self._store = getattr(self._atomic, "__atomic_store_8")
            self._store.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint64, ctypes.c_int]
            self._store.restype = None
        else:
            self._load = None
            self._store = None

    def load_acquire(self, ring: mmap.mmap, offset: int) -> int:
        cell = ctypes.c_uint64.from_buffer(ring, offset)
        try:
            if self._load is not None:
                return int(self._load(ctypes.byref(cell), ATOMIC_ACQUIRE))
            if platform.machine().lower() != "x86_64":
                raise UnsupportedFeatureError(
                    "libatomic is required for ordered perf ring access on this architecture"
                )
            return int(cell.value)
        finally:
            del cell

    def store_release(self, ring: mmap.mmap, offset: int, value: int) -> None:
        cell = ctypes.c_uint64.from_buffer(ring, offset)
        try:
            if self._store is not None:
                self._store(ctypes.byref(cell), value, ATOMIC_RELEASE)
                return
            if platform.machine().lower() != "x86_64":
                raise UnsupportedFeatureError(
                    "libatomic is required for ordered perf ring access on this architecture"
                )
            cell.value = value
        finally:
            del cell


RING_MEMORY_ORDER = PerfRingMemoryOrder()


def validate_perf_ring_pages(pages: int) -> int:
    if pages <= 0 or pages & (pages - 1):
        raise ValueError("perf buffer pages must be a positive power of two")
    return pages


def estimate_perf_record_bytes(
    *,
    callchain: bool,
    call_graph: CallGraphMode,
    max_stack: int | None = None,
    max_contexts: int | None = None,
) -> int:
    if not callchain:
        return BASE_SAMPLE_RECORD_BYTES
    if call_graph == "lbr":
        return BASE_SAMPLE_RECORD_BYTES + 8 + (MAX_LBR_ENTRIES_ESTIMATE * 24)
    stack_entries = max_stack if max_stack is not None else perf_event_max_stack()
    context_entries = max_contexts if max_contexts is not None else perf_event_max_contexts()
    return BASE_SAMPLE_RECORD_BYTES + 8 + ((stack_entries + context_entries) * 8)


def plan_perf_buffers(
    *,
    frequency: int,
    cpus: Iterable[int],
    callchain: bool,
    call_graph: CallGraphMode,
    requested_pages: int | None = None,
    requested_drain_ms: int | None = None,
    page_size: int = mmap.PAGESIZE,
    mlock_kb: int | None = None,
    max_stack: int | None = None,
    max_contexts: int | None = None,
) -> PerfBufferPlan:
    cpu_tuple = tuple(cpus)
    if not cpu_tuple:
        raise UnsupportedFeatureError("no online CPUs available for perf sampling")
    if requested_pages is not None:
        validate_perf_ring_pages(requested_pages)
    if requested_drain_ms is not None and requested_drain_ms <= 0:
        raise ValueError("perf drain interval must be greater than zero")

    estimated_record_bytes = estimate_perf_record_bytes(
        callchain=callchain,
        call_graph=call_graph,
        max_stack=max_stack,
        max_contexts=max_contexts,
    )
    target_drain_ms = requested_drain_ms or DEFAULT_PERF_DRAIN_MS
    target_bytes = math.ceil(
        frequency * (target_drain_ms / 1000) * estimated_record_bytes * PERF_RING_HEADROOM
    )
    needed_pages = max(MIN_PERF_RING_PAGES, math.ceil(target_bytes / page_size))
    auto_pages = 1 << (needed_pages - 1).bit_length()

    warnings: list[str] = []
    pages_auto = requested_pages is None
    if requested_pages is not None:
        pages = requested_pages
    else:
        allowance_kb = mlock_kb if mlock_kb is not None else perf_event_mlock_kb()
        allowance_bytes = max(0, allowance_kb * 1024 - page_size)
        allowance_pages = allowance_bytes // page_size
        if allowance_pages > 0:
            capped_pages = 1 << (allowance_pages.bit_length() - 1)
        else:
            capped_pages = DEFAULT_PERF_RING_PAGES
        cap = max(1, capped_pages)
        pages = min(auto_pages, cap)
        if pages < auto_pages:
            warnings.append(
                f"automatic perf buffer was capped at {pages} pages per CPU by "
                f"kernel.perf_event_mlock_kb={allowance_kb}"
            )

    bytes_per_cpu = pages * page_size
    byte_rate = max(1, frequency * estimated_record_bytes * PERF_RING_HEADROOM)
    safe_drain_ms = max(MIN_PERF_DRAIN_MS, math.floor((bytes_per_cpu / byte_rate) * 1000))
    drain_auto = requested_drain_ms is None
    drain_interval_ms = (
        min(DEFAULT_PERF_DRAIN_MS, safe_drain_ms)
        if requested_drain_ms is None
        else requested_drain_ms
    )
    if drain_interval_ms > safe_drain_ms:
        warnings.append(
            f"configured perf drain interval {drain_interval_ms}ms exceeds the estimated "
            f"safe interval {safe_drain_ms}ms; watermark polling will drain earlier"
        )
    if drain_interval_ms < 5:
        warnings.append(
            f"perf sampling requires a {drain_interval_ms}ms drain interval at this frequency; "
            "profiling overhead may be high"
        )

    watermark = max(estimated_record_bytes, bytes_per_cpu // PERF_RING_WATERMARK_FRACTION)
    watermark = min(bytes_per_cpu, watermark)
    total_mapped_bytes = len(cpu_tuple) * (bytes_per_cpu + page_size)
    return PerfBufferPlan(
        cpus=cpu_tuple,
        pages_per_cpu=pages,
        bytes_per_cpu=bytes_per_cpu,
        total_mapped_bytes=total_mapped_bytes,
        drain_interval_ms=drain_interval_ms,
        wakeup_watermark_bytes=watermark,
        estimated_record_bytes=estimated_record_bytes,
        pages_auto=pages_auto,
        drain_auto=drain_auto,
        warnings=tuple(warnings),
    )


class KallsymsResolver:
    def __init__(self, symbols: list[KernelSymbol]) -> None:
        self._symbols = sorted(symbols, key=lambda symbol: symbol.start)
        self._starts = [symbol.start for symbol in self._symbols]

    @classmethod
    def from_proc(cls, path: str = "/proc/kallsyms") -> KallsymsResolver:
        try:
            with open(path, encoding="utf-8") as symbol_file:
                return cls.from_lines(symbol_file)
        except OSError:
            return cls([])

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> KallsymsResolver:
        parsed: list[tuple[int, str, str | None]] = []
        for line in lines:
            symbol = _parse_kallsyms_line(line)
            if symbol is not None:
                parsed.append(symbol)
        parsed.sort(key=lambda item: item[0])

        symbols: list[KernelSymbol] = []
        for index, (start, name, module) in enumerate(parsed):
            end = parsed[index + 1][0] if index + 1 < len(parsed) else None
            if end is not None and end <= start:
                end = None
            symbols.append(KernelSymbol(start=start, end=end, name=name, module=module))
        return cls(symbols)

    def resolve(self, ip: int) -> KernelSymbolResolution:
        if not self._symbols:
            return KernelSymbolResolution(
                ip=ip,
                symbol=None,
                module=None,
                offset=None,
                kind="unknown",
            )
        index = bisect.bisect_right(self._starts, ip) - 1
        if index < 0:
            return KernelSymbolResolution(
                ip=ip,
                symbol=None,
                module=None,
                offset=None,
                kind="unknown",
            )
        symbol = self._symbols[index]
        if symbol.end is not None and ip >= symbol.end:
            return KernelSymbolResolution(
                ip=ip,
                symbol=None,
                module=None,
                offset=None,
                kind="unknown",
            )
        return KernelSymbolResolution(
            ip=ip,
            symbol=symbol.name,
            module=symbol.module,
            offset=ip - symbol.start,
            kind=_kernel_symbol_kind(symbol.name),
        )


class PerfEventAttr(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("config", ctypes.c_uint64),
        ("sample_freq", ctypes.c_uint64),
        ("sample_type", ctypes.c_uint64),
        ("read_format", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("wakeup_events", ctypes.c_uint32),
        ("bp_type", ctypes.c_uint32),
        ("config1", ctypes.c_uint64),
        ("config2", ctypes.c_uint64),
        ("branch_sample_type", ctypes.c_uint64),
    ]


CYCLES_EVENT = PerfEventConfig(
    name="cycles",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_CPU_CYCLES,
)
CYCLES_P_EVENT = PerfEventConfig(
    name="cycles:p",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_CPU_CYCLES,
    precise_ip=1,
)
CYCLES_PP_EVENT = PerfEventConfig(
    name="cycles:pp",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_CPU_CYCLES,
    precise_ip=2,
)
CYCLES_PPP_EVENT = PerfEventConfig(
    name="cycles:ppp",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_CPU_CYCLES,
    precise_ip=3,
)
CPU_CLOCK_EVENT = PerfEventConfig(
    name="cpu-clock",
    event_type=PERF_TYPE_SOFTWARE,
    config=PERF_COUNT_SW_CPU_CLOCK,
)
INSTRUCTIONS_EVENT = PerfEventConfig(
    name="instructions",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_INSTRUCTIONS,
)
CACHE_REFERENCES_EVENT = PerfEventConfig(
    name="cache-references",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_CACHE_REFERENCES,
)
CACHE_MISSES_EVENT = PerfEventConfig(
    name="cache-misses",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_CACHE_MISSES,
)
BRANCHES_EVENT = PerfEventConfig(
    name="branches",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
)
BRANCH_MISSES_EVENT = PerfEventConfig(
    name="branch-misses",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_BRANCH_MISSES,
)
BUS_CYCLES_EVENT = PerfEventConfig(
    name="bus-cycles",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_BUS_CYCLES,
)
STALLED_CYCLES_FRONTEND_EVENT = PerfEventConfig(
    name="stalled-cycles-frontend",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_STALLED_CYCLES_FRONTEND,
)
STALLED_CYCLES_BACKEND_EVENT = PerfEventConfig(
    name="stalled-cycles-backend",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_STALLED_CYCLES_BACKEND,
)
REF_CYCLES_EVENT = PerfEventConfig(
    name="ref-cycles",
    event_type=PERF_TYPE_HARDWARE,
    config=PERF_COUNT_HW_REF_CPU_CYCLES,
)
SUPPORTED_EVENTS = (
    CYCLES_PPP_EVENT,
    CYCLES_PP_EVENT,
    CYCLES_P_EVENT,
    CYCLES_EVENT,
    CPU_CLOCK_EVENT,
    INSTRUCTIONS_EVENT,
    CACHE_REFERENCES_EVENT,
    CACHE_MISSES_EVENT,
    BRANCHES_EVENT,
    BRANCH_MISSES_EVENT,
    BUS_CYCLES_EVENT,
    STALLED_CYCLES_FRONTEND_EVENT,
    STALLED_CYCLES_BACKEND_EVENT,
    REF_CYCLES_EVENT,
)
AUTO_EVENT_CANDIDATES = (
    CYCLES_PPP_EVENT,
    CYCLES_PP_EVENT,
    CYCLES_P_EVENT,
    CYCLES_EVENT,
    CPU_CLOCK_EVENT,
)
EVENTS_BY_NAME = {event.name: event for event in SUPPORTED_EVENTS}


class PerfEventOpener:
    def __init__(self) -> None:
        libc_name = ctypes.util.find_library("c")
        if libc_name is None:
            raise UnsupportedFeatureError("unable to locate libc for perf_event_open access")
        self._sys_perf_event_open = self._resolve_sys_perf_event_open()
        self._libc = ctypes.CDLL(libc_name, use_errno=True)
        self._libc.syscall.restype = ctypes.c_long

    def open_fd(
        self,
        event: PerfEventConfig,
        *,
        cpu: int,
        frequency: int,
        sample_callchain: bool = False,
        call_graph: CallGraphMode = "fp",
        wakeup_watermark_bytes: int | None = None,
    ) -> int:
        attr = _build_perf_event_attr(
            event,
            frequency,
            sample_callchain=sample_callchain,
            call_graph=call_graph,
            wakeup_watermark_bytes=wakeup_watermark_bytes,
        )
        result = self._libc.syscall(
            self._sys_perf_event_open,
            ctypes.byref(attr),
            -1,
            cpu,
            -1,
            PERF_FLAG_FD_CLOEXEC,
        )
        if result < 0:
            err = ctypes.get_errno()
            raise PerfOpenError(err, os.strerror(err))
        return int(result)

    def open_handle(
        self,
        event: PerfEventConfig,
        *,
        cpu: int,
        frequency: int,
        ring_pages: int = 8,
        sample_callchain: bool = False,
        call_graph: CallGraphMode = "fp",
        wakeup_watermark_bytes: int | None = None,
    ) -> PerfEventHandle:
        fd = self.open_fd(
            event,
            cpu=cpu,
            frequency=frequency,
            sample_callchain=sample_callchain,
            call_graph=call_graph,
            wakeup_watermark_bytes=wakeup_watermark_bytes,
        )
        page_size = mmap.PAGESIZE
        length = page_size * (ring_pages + 1)
        try:
            ring = mmap.mmap(
                fd,
                length,
                flags=mmap.MAP_SHARED | getattr(mmap, "MAP_POPULATE", 0),
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        except OSError:
            os.close(fd)
            raise
        return PerfEventHandle(fd=fd, ring=ring, cpu=cpu, data_pages=ring_pages)

    def _resolve_sys_perf_event_open(self) -> int:
        machine = platform.machine().lower()
        syscall_number = SYS_PERF_EVENT_OPEN_BY_MACHINE.get(machine)
        if syscall_number is None:
            raise UnsupportedFeatureError(
                f"unsupported machine architecture for perf_event_open: {machine}"
            )
        return syscall_number


class PerfSampler:
    def __init__(self, opener: PerfEventOpener | None = None) -> None:
        self.opener = opener or PerfEventOpener()

    def sample(
        self,
        *,
        event: PerfEventConfig,
        duration: float,
        frequency: int,
        cpus: Iterable[int] | None = None,
        callchain: bool = False,
        call_graph: CallGraphMode = "fp",
        buffer_pages: int | None = None,
        drain_interval_ms: int | None = None,
        on_samples: Callable[[list[PerfSample]], None] | None = None,
        poll_factory: Callable[[], select.poll] = select.poll,
        clock: Callable[[], float] = time.monotonic,
    ) -> PerfCaptureResult:
        validate_perf_frequency(frequency)
        starting_max_sample_rate = perf_event_max_sample_rate()
        requested_cpus = tuple(cpus) if cpus is not None else tuple(online_cpus())
        plan = plan_perf_buffers(
            frequency=frequency,
            cpus=requested_cpus,
            callchain=callchain,
            call_graph=call_graph,
            requested_pages=buffer_pages,
            requested_drain_ms=drain_interval_ms,
        )
        _validate_perf_fd_limit(len(plan.cpus))
        handles: list[PerfEventHandle] = []
        sample_type = _profile_sample_type(callchain=callchain, call_graph=call_graph)
        capture_warnings = list(plan.warnings)
        enabled = False
        try:
            for cpu in plan.cpus:
                try:
                    handle = self.opener.open_handle(
                        event,
                        cpu=cpu,
                        frequency=frequency,
                        ring_pages=plan.pages_per_cpu,
                        sample_callchain=callchain,
                        call_graph=call_graph,
                        wakeup_watermark_bytes=plan.wakeup_watermark_bytes,
                    )
                except PerfOpenError as exc:
                    if exc.errno == errno.ENODEV and cpu not in online_cpus():
                        capture_warnings.append(
                            f"CPU {cpu} went offline before perf sampling and was skipped"
                        )
                        continue
                    raise
                except OSError as exc:
                    raise PerfBufferAllocationError(
                        _perf_buffer_allocation_message(
                            cpu=cpu,
                            plan=plan,
                            exc=exc,
                        )
                    ) from exc
                handles.append(handle)
            if not handles:
                raise UnsupportedFeatureError("no online CPUs remained for perf sampling")

            actual_cpus = tuple(handle.cpu for handle in handles)
            if actual_cpus != plan.cpus:
                plan = replace(
                    plan,
                    cpus=actual_cpus,
                    total_mapped_bytes=len(actual_cpus) * (plan.bytes_per_cpu + mmap.PAGESIZE),
                )

            poller = poll_factory()
            handles_by_fd = {handle.fd: handle for handle in handles}
            for handle in handles:
                poller.register(handle.fd, select.POLLIN | POLL_ERROR_MASK)

            for handle in handles:
                fcntl.ioctl(handle.fd, PERF_EVENT_IOC_ENABLE, 0)
            enabled = True
            started_at = clock()
            deadline = started_at + duration

            samples: list[PerfSample] = []
            lost_samples = 0
            throttle_events = 0
            unthrottle_events = 0
            malformed_records = 0
            unknown_records = 0
            discarded_bytes = 0
            drain_count = 0
            max_occupancy = 0.0

            def drain(selected: Iterable[PerfEventHandle]) -> None:
                nonlocal lost_samples
                nonlocal throttle_events
                nonlocal unthrottle_events
                nonlocal malformed_records
                nonlocal unknown_records
                nonlocal discarded_bytes
                nonlocal drain_count
                nonlocal max_occupancy
                for selected_handle in selected:
                    result = parse_perf_mmap_ring(selected_handle.ring, sample_type)
                    if result.data_size > 0:
                        occupancy = (result.available_bytes / result.data_size) * 100
                        max_occupancy = max(max_occupancy, occupancy)
                    if result.available_bytes > 0:
                        drain_count += 1
                    if result.samples:
                        if on_samples is None:
                            samples.extend(result.samples)
                        else:
                            on_samples(result.samples)
                    lost_samples += result.lost_samples
                    throttle_events += result.throttle_events
                    unthrottle_events += result.unthrottle_events
                    malformed_records += result.malformed_records
                    unknown_records += result.unknown_records
                    discarded_bytes += result.discarded_bytes

            while True:
                remaining = deadline - clock()
                if remaining <= 0:
                    break
                timeout_ms = max(
                    1,
                    min(plan.drain_interval_ms, math.ceil(remaining * 1000)),
                )
                try:
                    ready = poller.poll(timeout_ms)
                except InterruptedError:
                    continue
                if not ready:
                    drain(handles)
                    continue
                selected_handles: list[PerfEventHandle] = []
                for fd, flags in ready:
                    if flags & POLL_ERROR_MASK:
                        raise BrrError(
                            f"perf polling failed on CPU {handles_by_fd[fd].cpu}: "
                            f"poll flags 0x{flags:x}"
                        )
                    selected_handles.append(handles_by_fd[fd])
                drain(selected_handles)

            for handle in handles:
                fcntl.ioctl(handle.fd, PERF_EVENT_IOC_DISABLE, 0)
            enabled = False
            ended_at = clock()
            drain(handles)

            time_enabled_ns = 0
            time_running_ns = 0
            for handle in handles:
                try:
                    handle_enabled, handle_running = handle.read_timing()
                except OSError as exc:
                    capture_warnings.append(
                        f"perf timing metadata is incomplete for CPU {handle.cpu}: {exc}"
                    )
                    continue
                time_enabled_ns += handle_enabled
                time_running_ns += handle_running
            running_percent = (
                100.0
                if time_enabled_ns <= 0
                else round((time_running_ns / time_enabled_ns) * 100, 4)
            )

            capture_warnings.extend(
                _frequency_warnings_after_sampling(
                    requested_frequency=frequency,
                    starting_max_sample_rate=starting_max_sample_rate,
                )
            )
            if lost_samples:
                capture_warnings.append(
                    f"perf dropped {lost_samples} samples; CPU percentages are lower bounds"
                )
            if throttle_events:
                capture_warnings.append(
                    f"perf throttled sampling {throttle_events} times; profile is incomplete"
                )
            if malformed_records or discarded_bytes:
                capture_warnings.append(
                    f"perf ring parsing discarded {discarded_bytes} bytes across "
                    f"{malformed_records} malformed records; profile is incomplete"
                )
            if running_percent < 99.0:
                capture_warnings.append(
                    f"perf events ran for {running_percent:.2f}% of enabled time; "
                    "profile is incomplete due to multiplexing"
                )
            if max_occupancy >= 75.0:
                capture_warnings.append(
                    f"perf ring occupancy reached {max_occupancy:.1f}%; consider increasing "
                    "--perf-buffer-pages or reducing --perf-drain-ms"
                )

            return PerfCaptureResult(
                samples=samples,
                lost_samples=lost_samples,
                throttle_events=throttle_events,
                unthrottle_events=unthrottle_events,
                malformed_records=malformed_records,
                unknown_records=unknown_records,
                discarded_bytes=discarded_bytes,
                actual_duration=max(0.0, ended_at - started_at),
                cpus=plan.cpus,
                buffer_pages_per_cpu=plan.pages_per_cpu,
                buffer_bytes_per_cpu=plan.bytes_per_cpu,
                buffer_bytes_total=plan.total_mapped_bytes,
                drain_interval_ms=plan.drain_interval_ms,
                drain_count=drain_count,
                max_ring_occupancy_percent=round(max_occupancy, 2),
                time_enabled_ns=time_enabled_ns,
                time_running_ns=time_running_ns,
                running_percent=running_percent,
                warnings=tuple(capture_warnings),
            )
        except PerfOpenError as exc:
            raise_perf_open_error(event, exc)
        finally:
            if enabled:
                for handle in handles:
                    try:
                        fcntl.ioctl(handle.fd, PERF_EVENT_IOC_DISABLE, 0)
                    except OSError:
                        pass
            for handle in handles:
                handle.close()


def choose_perf_event(
    requested_event: str,
    *,
    opener: PerfEventOpener,
    frequency: int,
    cpus: Iterable[int] | None = None,
) -> PerfEventConfig:
    validate_perf_frequency(frequency)
    probe_cpu = next(iter(cpus or online_cpus()), 0)
    if requested_event == "auto":
        for event in AUTO_EVENT_CANDIDATES:
            if _can_open(opener, event, cpu=probe_cpu, frequency=frequency):
                return event
        try:
            opener.open_fd(CPU_CLOCK_EVENT, cpu=probe_cpu, frequency=frequency)
        except PerfOpenError as exc:
            raise_perf_open_error(CPU_CLOCK_EVENT, exc)
        raise UnsupportedFeatureError("unable to select a supported perf event")

    event = event_config_for_name(requested_event)
    try:
        fd = opener.open_fd(event, cpu=probe_cpu, frequency=frequency)
    except PerfOpenError as exc:
        raise_perf_open_error(event, exc)
    else:
        os.close(fd)
    return event


def event_config_for_name(name: str) -> PerfEventConfig:
    event = EVENTS_BY_NAME.get(name)
    if event is None:
        raise UnsupportedFeatureError(
            f"unsupported perf event {name!r}; run 'brr perf-events' to list openable events"
        )
    return event


def validate_perf_event_name(name: str) -> str:
    if name == "auto":
        return name
    event_config_for_name(name)
    return name


def supported_perf_event_names() -> tuple[str, ...]:
    return ("auto", *EVENTS_BY_NAME)


def list_openable_perf_events(
    *,
    opener: PerfEventOpener,
    frequency: int,
    cpus: Iterable[int] | None = None,
) -> list[PerfEventAvailability]:
    validate_perf_frequency(frequency)
    probe_cpu = next(iter(cpus or online_cpus()), 0)
    openable: list[PerfEventConfig] = []
    for event in SUPPORTED_EVENTS:
        if _can_open(opener, event, cpu=probe_cpu, frequency=frequency):
            openable.append(event)

    auto_event = next((event for event in AUTO_EVENT_CANDIDATES if event in openable), None)
    return [
        PerfEventAvailability(
            name=event.name,
            event_type=_event_type_name(event.event_type),
            config=event.config,
            precise_ip=event.precise_ip,
            selected_by_auto=event == auto_event,
        )
        for event in openable
    ]


def parse_perf_records(records: bytes, sample_type: int) -> PerfParseResult:
    offset = 0
    samples: list[PerfSample] = []
    lost_samples = 0
    throttle_events = 0
    unthrottle_events = 0
    malformed_records = 0
    unknown_records = 0
    discarded_bytes = 0
    while offset + 8 <= len(records):
        record_type, _misc, size = struct.unpack_from("<IHH", records, offset)
        if size < 8 or offset + size > len(records):
            malformed_records += 1
            discarded_bytes += len(records) - offset
            offset = len(records)
            break
        payload = records[offset + 8 : offset + size]
        if record_type == PERF_RECORD_SAMPLE:
            sample = _parse_sample_record(payload, sample_type)
            if sample is not None:
                samples.append(sample)
            else:
                malformed_records += 1
                discarded_bytes += size
        elif record_type == PERF_RECORD_LOST:
            if len(payload) >= 16:
                _event_id, lost = struct.unpack_from("<QQ", payload, 0)
                lost_samples += lost
            else:
                malformed_records += 1
                discarded_bytes += size
        elif record_type == PERF_RECORD_LOST_SAMPLES:
            if len(payload) >= 8:
                (lost,) = struct.unpack_from("<Q", payload, 0)
                lost_samples += lost
            else:
                malformed_records += 1
                discarded_bytes += size
        elif record_type == PERF_RECORD_THROTTLE:
            throttle_events += 1
        elif record_type == PERF_RECORD_UNTHROTTLE:
            unthrottle_events += 1
        else:
            unknown_records += 1
        offset += size
    if offset < len(records):
        malformed_records += 1
        discarded_bytes += len(records) - offset
    return PerfParseResult(
        samples=samples,
        lost_samples=lost_samples,
        throttle_events=throttle_events,
        unthrottle_events=unthrottle_events,
        malformed_records=malformed_records,
        unknown_records=unknown_records,
        discarded_bytes=discarded_bytes,
    )


def parse_perf_mmap_ring(ring: mmap.mmap, sample_type: int) -> PerfParseResult:
    head = RING_MEMORY_ORDER.load_acquire(ring, PERF_MMAP_DATA_HEAD_OFFSET)
    tail = struct.unpack_from("<Q", ring, PERF_MMAP_DATA_TAIL_OFFSET)[0]
    data_offset = struct.unpack_from("<Q", ring, PERF_MMAP_DATA_OFFSET_OFFSET)[0]
    data_size = struct.unpack_from("<Q", ring, PERF_MMAP_DATA_SIZE_OFFSET)[0]
    if data_offset == 0:
        data_offset = mmap.PAGESIZE
    if data_size == 0:
        data_size = len(ring) - data_offset
    if data_size <= 0 or head <= tail:
        return PerfParseResult(samples=[], data_size=max(0, data_size))

    available_bytes = head - tail
    overrun_bytes = 0
    if head - tail > data_size:
        overrun_bytes = (head - tail) - data_size
        tail = head - data_size

    records = bytearray()
    position = tail
    while position < head:
        header = _read_ring_bytes(ring, data_offset, data_size, position, 8)
        if len(header) < 8:
            break
        _record_type, _misc, size = struct.unpack_from("<IHH", header, 0)
        if size < 8 or size > data_size:
            break
        records.extend(_read_ring_bytes(ring, data_offset, data_size, position, size))
        position += size

    RING_MEMORY_ORDER.store_release(ring, PERF_MMAP_DATA_TAIL_OFFSET, head)
    result = parse_perf_records(bytes(records), sample_type)
    return replace(
        result,
        discarded_bytes=result.discarded_bytes + overrun_bytes,
        available_bytes=available_bytes,
        data_size=data_size,
    )


class ProfileAccumulator:
    def __init__(
        self,
        *,
        program_details: list[BpfProgramDetails],
        requested_event: str,
        selected_event: str,
        duration: float,
        frequency: int,
        limit: int,
        line_limit: int,
        selected_program_id: int | None = None,
        kernel_samples: bool = False,
        call_graph: CallGraphMode = "fp",
        kernel_symbol_resolver: KallsymsResolver | None = None,
    ) -> None:
        ranges = [jit_range for details in program_details for jit_range in details.jit_ranges]
        self.resolver = JitRangeResolver(ranges)
        self.details_by_id = {details.program.id: details for details in program_details}
        self.line_mappers = {
            details.program.id: SourceLineMapper(details.line_info) for details in program_details
        }
        self.requested_event = requested_event
        self.selected_event = selected_event
        self.duration = duration
        self.frequency = frequency
        self.limit = limit
        self.line_limit = line_limit
        self.selected_program_id = selected_program_id
        self.kernel_samples = kernel_samples
        self.call_graph = call_graph
        self.symbol_resolver = kernel_symbol_resolver
        self.total_samples = 0
        self.program_counts: Counter[int] = Counter()
        self.hotspot_counts: dict[int, Counter[HotspotKey]] = defaultdict(Counter)
        self.kernel_program_counts: Counter[int] = Counter()
        self.kernel_hotspot_counts: dict[int, Counter[KernelHotspotKey]] = defaultdict(Counter)
        self.non_bpf_samples = 0
        self.source_mapped_samples = 0
        self.source_unmapped_samples = 0
        self.source_mapped_program_counts: Counter[int] = Counter()
        self.source_unmapped_program_counts: Counter[int] = Counter()
        self.kernel_source_mapped_program_counts: Counter[int] = Counter()
        self.kernel_source_unmapped_program_counts: Counter[int] = Counter()
        self.callchain_samples = 0
        self.kernel_attributed_samples = 0
        self.kernel_unattributed_samples = 0
        self.kernel_symbolized_samples = 0

    def consume(self, samples: list[PerfSample]) -> None:
        self.total_samples += len(samples)
        for sample in samples:
            if sample.callchain or sample.branch_stack:
                self.callchain_samples += 1
            jit_range = self.resolver.resolve(sample.ip)
            if jit_range is None:
                self.non_bpf_samples += 1
                if not self.kernel_samples:
                    continue
                caller = _bpf_caller_from_sample(
                    sample,
                    resolver=self.resolver,
                    call_graph=self.call_graph,
                )
                if caller is None:
                    self.kernel_unattributed_samples += 1
                    continue
                caller_range, caller_ip = caller
                self.kernel_attributed_samples += 1
                self.kernel_program_counts[caller_range.program_id] += 1
                bpf_line_info = self.line_mappers[caller_range.program_id].for_jited_ip(caller_ip)
                if bpf_line_info is None:
                    self.kernel_source_unmapped_program_counts[caller_range.program_id] += 1
                else:
                    self.kernel_source_mapped_program_counts[caller_range.program_id] += 1
                resolution = (
                    self.symbol_resolver.resolve(sample.ip)
                    if self.symbol_resolver is not None
                    else KernelSymbolResolution(
                        ip=sample.ip,
                        symbol=None,
                        module=None,
                        offset=None,
                        kind="unknown",
                    )
                )
                if resolution.symbol is not None:
                    self.kernel_symbolized_samples += 1
                self.kernel_hotspot_counts[caller_range.program_id][
                    _kernel_hotspot_key(
                        resolution,
                        caller_ip=caller_ip,
                        line_info=bpf_line_info,
                    )
                ] += 1
                continue
            self.program_counts[jit_range.program_id] += 1
            line_info = self.line_mappers[jit_range.program_id].for_jited_ip(sample.ip)
            count_source_mapping = (
                self.selected_program_id is None or jit_range.program_id == self.selected_program_id
            )
            if count_source_mapping:
                if line_info is None:
                    self.source_unmapped_samples += 1
                else:
                    self.source_mapped_samples += 1
            if line_info is None:
                self.source_unmapped_program_counts[jit_range.program_id] += 1
            else:
                self.source_mapped_program_counts[jit_range.program_id] += 1
            self.hotspot_counts[jit_range.program_id][_hotspot_key(line_info)] += 1

    def finish(
        self,
        *,
        capture: PerfCaptureResult | None = None,
        lost_samples: int = 0,
        warnings: tuple[str, ...] = (),
    ) -> BpfProfile:
        effective_duration = (
            capture.actual_duration
            if capture is not None and capture.actual_duration > 0
            else self.duration
        )
        rows: list[BpfProfileProgram] = []
        program_ids = set(self.program_counts) | set(self.kernel_program_counts)
        for program_id in sorted(
            program_ids,
            key=lambda item: (
                -(self.program_counts[item] + self.kernel_program_counts[item]),
                item,
            ),
        ):
            if self.selected_program_id is not None and program_id != self.selected_program_id:
                continue
            details = self.details_by_id[program_id]
            program = details.program
            count = self.program_counts[program_id]
            kernel_count = self.kernel_program_counts[program_id]
            hotspots = _hotspots_from_counts(
                self.hotspot_counts[program_id],
                program_samples=count,
                duration=effective_duration,
                frequency=self.frequency,
                line_limit=self.line_limit,
            )
            kernel_hotspots = _kernel_hotspots_from_counts(
                self.kernel_hotspot_counts[program_id],
                program_kernel_samples=kernel_count,
                duration=effective_duration,
                frequency=self.frequency,
                line_limit=self.line_limit,
            )
            kernel_function_hotspots = _kernel_function_hotspots_from_counts(
                self.kernel_hotspot_counts[program_id],
                program_kernel_samples=kernel_count,
                duration=effective_duration,
                frequency=self.frequency,
                line_limit=self.line_limit,
            )
            rows.append(
                BpfProfileProgram(
                    id=program.id,
                    program_type=program.program_type,
                    name=program.name,
                    tag=program.tag,
                    samples=count,
                    sample_percent=_percent(count, self.total_samples),
                    cpu_percent=_cpu_percent(
                        count,
                        duration=effective_duration,
                        frequency=self.frequency,
                    ),
                    pinned_paths=program.pinned_paths,
                    hotspots=hotspots,
                    kernel_samples=kernel_count,
                    kernel_cpu_percent=_cpu_percent(
                        kernel_count,
                        duration=effective_duration,
                        frequency=self.frequency,
                    ),
                    kernel_hotspots=kernel_hotspots,
                    kernel_function_hotspots=kernel_function_hotspots,
                    inclusive_samples=count + kernel_count,
                    inclusive_cpu_percent=_cpu_percent(
                        count + kernel_count,
                        duration=effective_duration,
                        frequency=self.frequency,
                    ),
                    direct_source_mapped_samples=self.source_mapped_program_counts[program_id],
                    direct_source_unmapped_samples=self.source_unmapped_program_counts[program_id],
                    under_bpf_caller_source_mapped_samples=(
                        self.kernel_source_mapped_program_counts[program_id]
                    ),
                    under_bpf_caller_source_unmapped_samples=(
                        self.kernel_source_unmapped_program_counts[program_id]
                    ),
                    direct_hotspot_samples_omitted_by_limit=max(
                        0, count - sum(hotspot.samples for hotspot in hotspots)
                    ),
                    under_bpf_hotspot_samples_omitted_by_limit=max(
                        0, kernel_count - sum(hotspot.samples for hotspot in kernel_hotspots)
                    ),
                    under_bpf_function_samples_omitted_by_limit=max(
                        0,
                        kernel_count - sum(hotspot.samples for hotspot in kernel_function_hotspots),
                    ),
                )
            )

        if self.limit > 0:
            rows = rows[: self.limit]
        capture_warnings = capture.warnings if capture is not None else warnings
        capture_lost = capture.lost_samples if capture is not None else lost_samples
        return BpfProfile(
            metadata=BpfProfileMetadata(
                requested_event=self.requested_event,
                selected_event=self.selected_event,
                duration=self.duration,
                frequency=self.frequency,
                limit=self.limit,
                line_limit=self.line_limit,
                total_samples=self.total_samples,
                lost_samples=capture_lost,
                unresolved_samples=self.non_bpf_samples,
                bpf_jit_samples=sum(self.program_counts.values()),
                non_bpf_samples=self.non_bpf_samples,
                selected_program_samples=(
                    self.program_counts[self.selected_program_id]
                    if self.selected_program_id is not None
                    else 0
                ),
                other_bpf_samples=(
                    sum(
                        count
                        for program_id, count in self.program_counts.items()
                        if program_id != self.selected_program_id
                    )
                    if self.selected_program_id is not None
                    else 0
                ),
                source_mapped_samples=self.source_mapped_samples,
                source_unmapped_samples=self.source_unmapped_samples,
                callchain_samples=self.callchain_samples,
                kernel_attributed_samples=self.kernel_attributed_samples,
                kernel_unattributed_samples=self.kernel_unattributed_samples,
                kernel_symbolized_samples=self.kernel_symbolized_samples,
                call_graph=self.call_graph,
                actual_duration=(capture.actual_duration if capture is not None else self.duration),
                perf_cpus=(capture.cpus if capture is not None else ()),
                perf_buffer_pages_per_cpu=(
                    capture.buffer_pages_per_cpu if capture is not None else 0
                ),
                perf_buffer_bytes_per_cpu=(
                    capture.buffer_bytes_per_cpu if capture is not None else 0
                ),
                perf_buffer_bytes_total=(capture.buffer_bytes_total if capture is not None else 0),
                perf_drain_interval_ms=(capture.drain_interval_ms if capture is not None else 0),
                perf_drain_count=(capture.drain_count if capture is not None else 0),
                perf_max_ring_occupancy_percent=(
                    capture.max_ring_occupancy_percent if capture is not None else 0.0
                ),
                perf_throttle_events=(capture.throttle_events if capture is not None else 0),
                perf_unthrottle_events=(capture.unthrottle_events if capture is not None else 0),
                perf_malformed_records=(capture.malformed_records if capture is not None else 0),
                perf_unknown_records=(capture.unknown_records if capture is not None else 0),
                perf_discarded_bytes=(capture.discarded_bytes if capture is not None else 0),
                perf_time_enabled_ns=(capture.time_enabled_ns if capture is not None else 0),
                perf_time_running_ns=(capture.time_running_ns if capture is not None else 0),
                perf_running_percent=(capture.running_percent if capture is not None else 100.0),
                incomplete=(capture.incomplete if capture is not None else bool(capture_lost)),
                warnings=capture_warnings,
            ),
            items=rows,
        )


def build_profile(
    *,
    program_details: list[BpfProgramDetails],
    samples: list[PerfSample],
    lost_samples: int,
    requested_event: str,
    selected_event: str,
    duration: float,
    frequency: int,
    limit: int,
    line_limit: int,
    selected_program_id: int | None = None,
    kernel_samples: bool = False,
    call_graph: CallGraphMode = "fp",
    kernel_symbol_resolver: KallsymsResolver | None = None,
    warnings: tuple[str, ...] = (),
) -> BpfProfile:
    accumulator = ProfileAccumulator(
        program_details=program_details,
        requested_event=requested_event,
        selected_event=selected_event,
        duration=duration,
        frequency=frequency,
        limit=limit,
        line_limit=line_limit,
        selected_program_id=selected_program_id,
        kernel_samples=kernel_samples,
        call_graph=call_graph,
        kernel_symbol_resolver=kernel_symbol_resolver,
    )
    accumulator.consume(samples)
    return accumulator.finish(lost_samples=lost_samples, warnings=warnings)


def online_cpus() -> list[int]:
    online_path = "/sys/devices/system/cpu/online"
    try:
        with open(online_path, encoding="utf-8") as cpu_file:
            text = cpu_file.read().strip()
    except OSError:
        return sorted(os.sched_getaffinity(0))
    return _parse_cpu_ranges(text)


def perf_event_max_sample_rate(
    path: str = PERF_EVENT_MAX_SAMPLE_RATE_PATH,
) -> int | None:
    return _read_positive_int(path)


def perf_event_mlock_kb(path: str = PERF_EVENT_MLOCK_KB_PATH) -> int:
    return _read_positive_int(path) or DEFAULT_PERF_RING_PAGES * (mmap.PAGESIZE // 1024)


def perf_event_max_stack(path: str = PERF_EVENT_MAX_STACK_PATH) -> int:
    return _read_positive_int(path) or 127


def perf_event_max_contexts(path: str = PERF_EVENT_MAX_CONTEXTS_PATH) -> int:
    return _read_positive_int(path) or 8


def _read_positive_int(path: str) -> int | None:
    try:
        with open(path, encoding="utf-8") as value_file:
            text = value_file.read().strip()
    except OSError:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def _validate_perf_fd_limit(required_fds: int) -> None:
    soft_limit, _hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit == resource.RLIM_INFINITY:
        return
    try:
        open_fds = len(os.listdir("/proc/self/fd"))
    except OSError:
        open_fds = 0
    if open_fds + required_fds <= soft_limit:
        return
    raise PerfBufferAllocationError(
        f"perf sampling needs {required_fds} additional file descriptors for "
        f"{required_fds} CPUs, but RLIMIT_NOFILE={soft_limit} and approximately "
        f"{open_fds} descriptors are already open; raise the file-descriptor limit"
    )


def _perf_buffer_allocation_message(
    *,
    cpu: int,
    plan: PerfBufferPlan,
    exc: OSError,
) -> str:
    soft_memlock, hard_memlock = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    return (
        f"failed to allocate perf ring for CPU {cpu}: {plan.pages_per_cpu} data pages "
        f"({plan.bytes_per_cpu} bytes per CPU, {plan.total_mapped_bytes} bytes total): "
        f"{exc.strerror or exc}; kernel.perf_event_mlock_kb={perf_event_mlock_kb()}, "
        f"RLIMIT_MEMLOCK={soft_memlock}/{hard_memlock}; lower --perf-buffer-pages or "
        "sampling frequency, or raise the perf/memlock allowance"
    )


def validate_perf_frequency(frequency: int) -> None:
    max_sample_rate = perf_event_max_sample_rate()
    if max_sample_rate is None or frequency <= max_sample_rate:
        return
    raise UnsupportedFeatureError(_perf_frequency_limit_message(frequency, max_sample_rate))


def raise_perf_open_error(event: PerfEventConfig, exc: PerfOpenError) -> None:
    if exc.errno in {errno.EACCES, errno.EPERM}:
        raise PermissionDeniedError(
            f"permission denied while opening perf event {event.name}; run brr with sudo "
            "or check perf_event_paranoid"
        ) from exc
    if exc.errno in {errno.EINVAL, errno.ENODEV, errno.EOPNOTSUPP, errno.ENOENT}:
        raise UnsupportedFeatureError(
            f"perf event {event.name} is not supported on this host"
        ) from exc
    raise OSError(exc.errno, f"failed to open perf event {event.name}: {exc.strerror}") from exc


def _frequency_warnings_after_sampling(
    *,
    requested_frequency: int,
    starting_max_sample_rate: int | None,
) -> tuple[str, ...]:
    ending_max_sample_rate = perf_event_max_sample_rate()
    if ending_max_sample_rate is None or ending_max_sample_rate >= requested_frequency:
        return ()
    if starting_max_sample_rate is not None and ending_max_sample_rate >= starting_max_sample_rate:
        return ()
    return (_perf_frequency_downgrade_warning(requested_frequency, ending_max_sample_rate),)


def _perf_frequency_limit_message(frequency: int, max_sample_rate: int) -> str:
    return (
        f"requested perf sample frequency {frequency} Hz exceeds current "
        f"kernel.perf_event_max_sample_rate {max_sample_rate} Hz; lower -F/--frequency "
        f"or raise {PERF_EVENT_MAX_SAMPLE_RATE_PATH}"
    )


def _perf_frequency_downgrade_warning(frequency: int, max_sample_rate: int) -> str:
    return (
        f"kernel.perf_event_max_sample_rate was lowered below requested perf sample "
        f"frequency during sampling ({max_sample_rate} Hz < {frequency} Hz); sampled "
        "dataset may be inconsistent, rerun with a lower -F/--frequency"
    )


def _build_perf_event_attr(
    event: PerfEventConfig,
    frequency: int,
    *,
    sample_callchain: bool = False,
    call_graph: CallGraphMode = "fp",
    wakeup_watermark_bytes: int | None = None,
) -> PerfEventAttr:
    attr = PerfEventAttr()
    attr.type = event.event_type
    attr.size = _perf_attr_size(callchain=sample_callchain, call_graph=call_graph)
    attr.config = event.config
    attr.sample_freq = frequency
    attr.sample_type = _profile_sample_type(callchain=sample_callchain, call_graph=call_graph)
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING
    attr.flags = (1 << 0) | (1 << 4) | (1 << 6) | (1 << 10)
    attr.flags |= event.precise_ip << 15
    if wakeup_watermark_bytes is None:
        attr.wakeup_events = 1
    else:
        attr.flags |= 1 << 14
        attr.wakeup_events = wakeup_watermark_bytes
    attr.bp_type = 0
    attr.config1 = 0
    attr.config2 = 0
    attr.branch_sample_type = 0
    if sample_callchain and call_graph == "lbr":
        attr.branch_sample_type = (
            PERF_SAMPLE_BRANCH_USER | PERF_SAMPLE_BRANCH_KERNEL | PERF_SAMPLE_BRANCH_CALL_STACK
        )
    return attr


def _perf_attr_size(*, callchain: bool, call_graph: CallGraphMode) -> int:
    if callchain and call_graph == "lbr":
        return PERF_ATTR_SIZE_VER2
    return PERF_ATTR_SIZE_VER0


def _profile_sample_type(*, callchain: bool, call_graph: CallGraphMode = "fp") -> int:
    if not callchain:
        return PROFILE_SAMPLE_TYPE
    if call_graph == "lbr":
        return PROFILE_BRANCH_STACK_SAMPLE_TYPE
    return PROFILE_CALLCHAIN_SAMPLE_TYPE


def _event_type_name(event_type: int) -> str:
    if event_type == PERF_TYPE_HARDWARE:
        return "hardware"
    if event_type == PERF_TYPE_SOFTWARE:
        return "software"
    return str(event_type)


def _parse_kallsyms_line(line: str) -> tuple[int, str, str | None] | None:
    parts = line.strip().split()
    if len(parts) < 3:
        return None
    try:
        address = int(parts[0], 16)
    except ValueError:
        return None
    if address == 0:
        return None
    name = parts[2]
    module = None
    if len(parts) >= 4 and parts[3].startswith("[") and parts[3].endswith("]"):
        module = parts[3][1:-1] or None
    return address, name, module


def _kernel_symbol_kind(name: str) -> str:
    if not name:
        return "unknown"
    lowered = name.lower()
    if (
        lowered.startswith("bpf_map_")
        or "_map_" in lowered
        or lowered.endswith("_map_lookup_elem")
        or lowered.endswith("_map_update_elem")
        or lowered.endswith("_map_delete_elem")
    ):
        return "bpf_map"
    if (
        lowered.startswith("bpf_")
        or lowered.startswith("__bpf_")
        or lowered.startswith("____bpf_")
        or "bpf_helper" in lowered
    ):
        return "bpf_helper"
    return "kernel"


def _can_open(
    opener: PerfEventOpener,
    event: PerfEventConfig,
    *,
    cpu: int,
    frequency: int,
) -> bool:
    try:
        fd = opener.open_fd(event, cpu=cpu, frequency=frequency)
    except PerfOpenError:
        return False
    os.close(fd)
    return True


def _parse_sample_record(payload: bytes, sample_type: int) -> PerfSample | None:
    offset = 0
    ip: int | None = None
    pid: int | None = None
    tid: int | None = None
    sample_time: int | None = None
    cpu: int | None = None
    period: int | None = None
    callchain: tuple[int, ...] = ()
    branch_stack: tuple[PerfBranchEntry, ...] = ()

    if sample_type & PERF_SAMPLE_IP:
        if offset + 8 > len(payload):
            return None
        (ip,) = struct.unpack_from("<Q", payload, offset)
        offset += 8
    if sample_type & PERF_SAMPLE_TID:
        if offset + 8 > len(payload):
            return None
        pid, tid = struct.unpack_from("<II", payload, offset)
        offset += 8
    if sample_type & PERF_SAMPLE_TIME:
        if offset + 8 > len(payload):
            return None
        (sample_time,) = struct.unpack_from("<Q", payload, offset)
        offset += 8
    if sample_type & PERF_SAMPLE_CPU:
        if offset + 8 > len(payload):
            return None
        cpu, _reserved = struct.unpack_from("<II", payload, offset)
        offset += 8
    if sample_type & PERF_SAMPLE_PERIOD:
        if offset + 8 > len(payload):
            return None
        (period,) = struct.unpack_from("<Q", payload, offset)
        offset += 8
    if sample_type & PERF_SAMPLE_CALLCHAIN:
        parsed = _parse_callchain(payload, offset)
        if parsed is None:
            return None
        callchain, offset = parsed
    if sample_type & PERF_SAMPLE_BRANCH_STACK:
        parsed = _parse_branch_stack(payload, offset)
        if parsed is None:
            return None
        branch_stack, offset = parsed

    if ip is None:
        return None
    return PerfSample(
        ip=ip,
        pid=pid,
        tid=tid,
        time=sample_time,
        cpu=cpu,
        period=period,
        callchain=callchain,
        branch_stack=branch_stack,
    )


def _parse_callchain(payload: bytes, offset: int) -> tuple[tuple[int, ...], int] | None:
    if offset + 8 > len(payload):
        return None
    (frame_count,) = struct.unpack_from("<Q", payload, offset)
    offset += 8
    frame_bytes = frame_count * 8
    if frame_count > (len(payload) - offset) // 8:
        return None
    frames = struct.unpack_from(f"<{frame_count}Q", payload, offset) if frame_count else ()
    offset += frame_bytes
    return tuple(frame for frame in frames if _is_callchain_ip(frame)), offset


def _parse_branch_stack(
    payload: bytes,
    offset: int,
) -> tuple[tuple[PerfBranchEntry, ...], int] | None:
    if offset + 8 > len(payload):
        return None
    (branch_count,) = struct.unpack_from("<Q", payload, offset)
    offset += 8
    if branch_count > (len(payload) - offset) // 24:
        return None
    entries: list[PerfBranchEntry] = []
    for _ in range(branch_count):
        from_ip, to_ip, flags = struct.unpack_from("<QQQ", payload, offset)
        offset += 24
        if from_ip != 0 or to_ip != 0:
            entries.append(PerfBranchEntry(from_ip=from_ip, to_ip=to_ip, flags=flags))
    return tuple(entries), offset


def _is_callchain_ip(frame: int) -> bool:
    if frame == 0:
        return False
    return frame < PERF_CONTEXT_MARKER_MIN


def _read_ring_bytes(
    ring: mmap.mmap,
    data_offset: int,
    data_size: int,
    position: int,
    length: int,
) -> bytes:
    start = position % data_size
    first_length = min(length, data_size - start)
    first = ring[data_offset + start : data_offset + start + first_length]
    remaining = length - first_length
    if remaining == 0:
        return first
    return first + ring[data_offset : data_offset + remaining]


@dataclass(frozen=True, slots=True)
class HotspotKey:
    jited_address: int | None
    instruction_offset: int | None
    file_name: str | None
    line_number: int | None
    column: int | None
    source: str | None


@dataclass(frozen=True, slots=True)
class KernelHotspotKey:
    ip: int
    symbol: str | None
    module: str | None
    symbol_offset: int | None
    symbol_kind: str
    bpf_jited_address: int | None
    bpf_instruction_offset: int | None
    bpf_file_name: str | None
    bpf_line_number: int | None
    bpf_column: int | None
    bpf_source: str | None


@dataclass(frozen=True, slots=True)
class KernelFunctionHotspotKey:
    symbol: str | None
    module: str | None
    symbol_kind: str
    unknown_ip: int | None
    bpf_file_name: str | None
    bpf_line_number: int | None
    bpf_source: str | None


def _hotspot_key(line_info: BpfLineInfo | None) -> HotspotKey:
    if line_info is None:
        return HotspotKey(None, None, None, None, None, None)
    return HotspotKey(
        jited_address=line_info.jited_address,
        instruction_offset=line_info.insn_offset * BPF_INSN_SIZE,
        file_name=line_info.file_name,
        line_number=line_info.line_number,
        column=line_info.column,
        source=line_info.source,
    )


def _kernel_hotspot_key(
    resolution: KernelSymbolResolution,
    *,
    caller_ip: int,
    line_info: BpfLineInfo | None,
) -> KernelHotspotKey:
    return KernelHotspotKey(
        ip=resolution.ip,
        symbol=resolution.symbol,
        module=resolution.module,
        symbol_offset=resolution.offset,
        symbol_kind=resolution.kind,
        bpf_jited_address=line_info.jited_address if line_info is not None else caller_ip,
        bpf_instruction_offset=(
            line_info.insn_offset * BPF_INSN_SIZE if line_info is not None else None
        ),
        bpf_file_name=line_info.file_name if line_info is not None else None,
        bpf_line_number=line_info.line_number if line_info is not None else None,
        bpf_column=line_info.column if line_info is not None else None,
        bpf_source=line_info.source if line_info is not None else None,
    )


def _bpf_caller_from_callchain(
    callchain: tuple[int, ...],
    *,
    resolver: JitRangeResolver,
) -> tuple[BpfJitRange, int] | None:
    for frame in callchain:
        jit_range = resolver.resolve(frame)
        if jit_range is not None:
            return jit_range, frame
    return None


def _bpf_caller_from_sample(
    sample: PerfSample,
    *,
    resolver: JitRangeResolver,
    call_graph: CallGraphMode,
) -> tuple[BpfJitRange, int] | None:
    if call_graph == "lbr":
        return _bpf_caller_from_branch_stack(sample.branch_stack, resolver=resolver)
    return _bpf_caller_from_callchain(sample.callchain, resolver=resolver)


def _bpf_caller_from_branch_stack(
    branch_stack: tuple[PerfBranchEntry, ...],
    *,
    resolver: JitRangeResolver,
) -> tuple[BpfJitRange, int] | None:
    for branch in branch_stack:
        for ip in (branch.from_ip, branch.to_ip):
            jit_range = resolver.resolve(ip)
            if jit_range is not None:
                return jit_range, ip
    return None


def _hotspots_from_counts(
    counts: Counter[HotspotKey],
    *,
    program_samples: int,
    duration: float,
    frequency: int,
    line_limit: int,
) -> list[BpfHotspot]:
    ordered = sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0].file_name or "", item[0].line_number or 0),
    )
    if line_limit > 0:
        ordered = ordered[:line_limit]
    return [
        BpfHotspot(
            samples=count,
            sample_percent=_percent(count, program_samples),
            cpu_percent=_cpu_percent(count, duration=duration, frequency=frequency),
            jited_address=key.jited_address,
            instruction_offset=key.instruction_offset,
            file_name=key.file_name,
            line_number=key.line_number,
            column=key.column,
            source=key.source,
        )
        for key, count in ordered
    ]


def _kernel_hotspots_from_counts(
    counts: Counter[KernelHotspotKey],
    *,
    program_kernel_samples: int,
    duration: float,
    frequency: int,
    line_limit: int,
) -> list[BpfKernelHotspot]:
    ordered = sorted(
        counts.items(),
        key=lambda item: (
            -item[1],
            item[0].symbol or "",
            item[0].ip,
            item[0].bpf_file_name or "",
            item[0].bpf_line_number or 0,
        ),
    )
    if line_limit > 0:
        ordered = ordered[:line_limit]
    return [
        BpfKernelHotspot(
            samples=count,
            sample_percent=_percent(count, program_kernel_samples),
            cpu_percent=_cpu_percent(count, duration=duration, frequency=frequency),
            ip=key.ip,
            symbol=key.symbol,
            module=key.module,
            symbol_offset=key.symbol_offset,
            symbol_kind=key.symbol_kind,
            bpf_jited_address=key.bpf_jited_address,
            bpf_instruction_offset=key.bpf_instruction_offset,
            bpf_file_name=key.bpf_file_name,
            bpf_line_number=key.bpf_line_number,
            bpf_column=key.bpf_column,
            bpf_source=key.bpf_source,
        )
        for key, count in ordered
    ]


def _kernel_function_hotspots_from_counts(
    counts: Counter[KernelHotspotKey],
    *,
    program_kernel_samples: int,
    duration: float,
    frequency: int,
    line_limit: int,
) -> list[BpfKernelHotspot]:
    grouped_counts: Counter[KernelFunctionHotspotKey] = Counter()
    grouped_ips: dict[KernelFunctionHotspotKey, set[int]] = defaultdict(set)
    grouped_bpf_jited_addresses: dict[KernelFunctionHotspotKey, set[int]] = defaultdict(set)
    grouped_bpf_instruction_offsets: dict[KernelFunctionHotspotKey, set[int]] = defaultdict(set)
    grouped_bpf_columns: dict[KernelFunctionHotspotKey, set[int]] = defaultdict(set)
    for key, count in counts.items():
        function_key = KernelFunctionHotspotKey(
            symbol=key.symbol,
            module=key.module,
            symbol_kind=key.symbol_kind,
            unknown_ip=key.ip if key.symbol is None else None,
            bpf_file_name=key.bpf_file_name,
            bpf_line_number=key.bpf_line_number,
            bpf_source=key.bpf_source,
        )
        grouped_counts[function_key] += count
        grouped_ips[function_key].add(key.ip)
        if key.bpf_jited_address is not None:
            grouped_bpf_jited_addresses[function_key].add(key.bpf_jited_address)
        if key.bpf_instruction_offset is not None:
            grouped_bpf_instruction_offsets[function_key].add(key.bpf_instruction_offset)
        if key.bpf_column is not None:
            grouped_bpf_columns[function_key].add(key.bpf_column)

    ordered = sorted(
        grouped_counts.items(),
        key=lambda item: (
            -item[1],
            item[0].symbol or "",
            item[0].module or "",
            item[0].unknown_ip or 0,
            item[0].bpf_file_name or "",
            item[0].bpf_line_number or 0,
        ),
    )
    if line_limit > 0:
        ordered = ordered[:line_limit]
    return [
        BpfKernelHotspot(
            samples=count,
            sample_percent=_percent(count, program_kernel_samples),
            cpu_percent=_cpu_percent(count, duration=duration, frequency=frequency),
            ip=min(grouped_ips[key]),
            symbol=key.symbol,
            module=key.module,
            symbol_offset=None,
            symbol_kind=key.symbol_kind,
            bpf_jited_address=min(grouped_bpf_jited_addresses[key], default=None),
            bpf_instruction_offset=min(grouped_bpf_instruction_offsets[key], default=None),
            bpf_file_name=key.bpf_file_name,
            bpf_line_number=key.bpf_line_number,
            bpf_column=min(grouped_bpf_columns[key], default=None),
            bpf_source=key.bpf_source,
            ip_count=len(grouped_ips[key]),
        )
        for key, count in ordered
    ]


def _percent(part: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round((part / total) * 100, 2)


def _cpu_percent(samples: int, *, duration: float, frequency: int) -> float:
    denominator = duration * frequency
    if denominator <= 0:
        return 0.0
    return round((samples / denominator) * 100, 4)


def _parse_cpu_ranges(text: str) -> list[int]:
    cpus: list[int] = []
    for part in text.split(","):
        if "-" in part:
            start, end = [int(value) for value in part.split("-", 1)]
            cpus.extend(range(start, end + 1))
        elif part:
            cpus.append(int(part))
    return cpus
