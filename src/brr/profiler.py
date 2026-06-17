from __future__ import annotations

import bisect
import ctypes
import ctypes.util
import errno
import fcntl
import mmap
import os
import platform
import struct
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from brr.bpf_details import JitRangeResolver, SourceLineMapper
from brr.errors import PermissionDeniedError, UnsupportedFeatureError
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
PERF_RECORD_SAMPLE = 9
PERF_RECORD_LOST_SAMPLES = 13
PERF_CONTEXT_MARKER_MIN = (1 << 64) - 4095
PERF_SAMPLE_BRANCH_USER = 1 << 0
PERF_SAMPLE_BRANCH_KERNEL = 1 << 1
PERF_SAMPLE_BRANCH_CALL_STACK = 1 << 11

PERF_FLAG_FD_CLOEXEC = 1 << 3
PERF_EVENT_IOC_ENABLE = 0x2400
PERF_EVENT_IOC_DISABLE = 0x2401
PERF_ATTR_SIZE_VER0 = 64
PERF_ATTR_SIZE_VER2 = 80
CALL_GRAPH_MODES = ("fp", "lbr")

CallGraphMode = Literal["fp", "lbr"]

PERF_MMAP_DATA_HEAD_OFFSET = 1024
PERF_MMAP_DATA_TAIL_OFFSET = 1032
PERF_MMAP_DATA_OFFSET_OFFSET = 1040
PERF_MMAP_DATA_SIZE_OFFSET = 1048
PERF_EVENT_MAX_SAMPLE_RATE_PATH = "/proc/sys/kernel/perf_event_max_sample_rate"

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
    warnings: tuple[str, ...] = ()


@dataclass(slots=True)
class PerfEventHandle:
    fd: int
    ring: mmap.mmap
    cpu: int

    def close(self) -> None:
        try:
            self.ring.close()
        finally:
            os.close(self.fd)


class PerfOpenError(OSError):
    pass


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
    ) -> int:
        attr = _build_perf_event_attr(
            event,
            frequency,
            sample_callchain=sample_callchain,
            call_graph=call_graph,
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
    ) -> PerfEventHandle:
        fd = self.open_fd(
            event,
            cpu=cpu,
            frequency=frequency,
            sample_callchain=sample_callchain,
            call_graph=call_graph,
        )
        page_size = mmap.PAGESIZE
        length = page_size * (ring_pages + 1)
        try:
            ring = mmap.mmap(
                fd,
                length,
                flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        except OSError:
            os.close(fd)
            raise
        return PerfEventHandle(fd=fd, ring=ring, cpu=cpu)

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
        sleeper: Callable[[float], None] = time.sleep,
        callchain: bool = False,
        call_graph: CallGraphMode = "fp",
    ) -> PerfParseResult:
        validate_perf_frequency(frequency)
        starting_max_sample_rate = perf_event_max_sample_rate()
        handles: list[PerfEventHandle] = []
        sample_type = _profile_sample_type(callchain=callchain, call_graph=call_graph)
        try:
            for cpu in cpus or online_cpus():
                handles.append(
                    self.opener.open_handle(
                        event,
                        cpu=cpu,
                        frequency=frequency,
                        sample_callchain=callchain,
                        call_graph=call_graph,
                    )
                )
            for handle in handles:
                fcntl.ioctl(handle.fd, PERF_EVENT_IOC_ENABLE, 0)
            sleeper(duration)
            for handle in handles:
                fcntl.ioctl(handle.fd, PERF_EVENT_IOC_DISABLE, 0)

            samples: list[PerfSample] = []
            lost_samples = 0
            for handle in handles:
                result = parse_perf_mmap_ring(handle.ring, sample_type)
                samples.extend(result.samples)
                lost_samples += result.lost_samples
            warnings = _frequency_warnings_after_sampling(
                requested_frequency=frequency,
                starting_max_sample_rate=starting_max_sample_rate,
            )
            return PerfParseResult(
                samples=samples,
                lost_samples=lost_samples,
                warnings=warnings,
            )
        except PerfOpenError as exc:
            raise_perf_open_error(event, exc)
        finally:
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
    while offset + 8 <= len(records):
        record_type, _misc, size = struct.unpack_from("<IHH", records, offset)
        if size < 8 or offset + size > len(records):
            break
        payload = records[offset + 8 : offset + size]
        if record_type == PERF_RECORD_SAMPLE:
            sample = _parse_sample_record(payload, sample_type)
            if sample is not None:
                samples.append(sample)
        elif record_type == PERF_RECORD_LOST and len(payload) >= 16:
            _event_id, lost = struct.unpack_from("<QQ", payload, 0)
            lost_samples += lost
        elif record_type == PERF_RECORD_LOST_SAMPLES and len(payload) >= 8:
            (lost,) = struct.unpack_from("<Q", payload, 0)
            lost_samples += lost
        offset += size
    return PerfParseResult(samples=samples, lost_samples=lost_samples)


def parse_perf_mmap_ring(ring: mmap.mmap, sample_type: int) -> PerfParseResult:
    head = struct.unpack_from("<Q", ring, PERF_MMAP_DATA_HEAD_OFFSET)[0]
    tail = struct.unpack_from("<Q", ring, PERF_MMAP_DATA_TAIL_OFFSET)[0]
    data_offset = struct.unpack_from("<Q", ring, PERF_MMAP_DATA_OFFSET_OFFSET)[0]
    data_size = struct.unpack_from("<Q", ring, PERF_MMAP_DATA_SIZE_OFFSET)[0]
    if data_offset == 0:
        data_offset = mmap.PAGESIZE
    if data_size == 0:
        data_size = len(ring) - data_offset
    if data_size <= 0 or head <= tail:
        return PerfParseResult(samples=[])

    if head - tail > data_size:
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

    ring[PERF_MMAP_DATA_TAIL_OFFSET : PERF_MMAP_DATA_TAIL_OFFSET + 8] = struct.pack("<Q", head)
    return parse_perf_records(bytes(records), sample_type)


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
    ranges = [jit_range for details in program_details for jit_range in details.jit_ranges]
    resolver = JitRangeResolver(ranges)
    details_by_id = {details.program.id: details for details in program_details}
    line_mappers = {
        details.program.id: SourceLineMapper(details.line_info) for details in program_details
    }
    program_counts: Counter[int] = Counter()
    hotspot_counts: dict[int, Counter[HotspotKey]] = defaultdict(Counter)
    kernel_program_counts: Counter[int] = Counter()
    kernel_hotspot_counts: dict[int, Counter[KernelHotspotKey]] = defaultdict(Counter)
    non_bpf_samples = 0
    source_mapped_samples = 0
    source_unmapped_samples = 0
    callchain_samples = 0
    kernel_attributed_samples = 0
    kernel_unattributed_samples = 0
    kernel_symbolized_samples = 0
    symbol_resolver = kernel_symbol_resolver if kernel_symbol_resolver is not None else None

    for sample in samples:
        if sample.callchain or sample.branch_stack:
            callchain_samples += 1
        jit_range = resolver.resolve(sample.ip)
        if jit_range is None:
            non_bpf_samples += 1
            if not kernel_samples:
                continue
            caller = _bpf_caller_from_sample(sample, resolver=resolver, call_graph=call_graph)
            if caller is None:
                kernel_unattributed_samples += 1
                continue
            caller_range, caller_ip = caller
            kernel_attributed_samples += 1
            kernel_program_counts[caller_range.program_id] += 1
            bpf_line_info = line_mappers[caller_range.program_id].for_jited_ip(caller_ip)
            resolution = (
                symbol_resolver.resolve(sample.ip)
                if symbol_resolver is not None
                else KernelSymbolResolution(
                    ip=sample.ip,
                    symbol=None,
                    module=None,
                    offset=None,
                    kind="unknown",
                )
            )
            if resolution.symbol is not None:
                kernel_symbolized_samples += 1
            kernel_hotspot_counts[caller_range.program_id][
                _kernel_hotspot_key(resolution, caller_ip=caller_ip, line_info=bpf_line_info)
            ] += 1
            continue
        program_counts[jit_range.program_id] += 1
        line_info = line_mappers[jit_range.program_id].for_jited_ip(sample.ip)
        count_source_mapping = (
            selected_program_id is None or jit_range.program_id == selected_program_id
        )
        if count_source_mapping:
            if line_info is None:
                source_unmapped_samples += 1
            else:
                source_mapped_samples += 1
        hotspot_counts[jit_range.program_id][_hotspot_key(line_info)] += 1

    total_samples = len(samples)
    rows: list[BpfProfileProgram] = []
    program_ids = set(program_counts) | set(kernel_program_counts)
    for program_id in sorted(
        program_ids,
        key=lambda item: (-(program_counts[item] + kernel_program_counts[item]), item),
    ):
        if selected_program_id is not None and program_id != selected_program_id:
            continue
        details = details_by_id[program_id]
        program = details.program
        count = program_counts[program_id]
        kernel_count = kernel_program_counts[program_id]
        hotspots = _hotspots_from_counts(
            hotspot_counts[program_id],
            program_samples=count,
            duration=duration,
            frequency=frequency,
            line_limit=line_limit,
        )
        kernel_hotspots = _kernel_hotspots_from_counts(
            kernel_hotspot_counts[program_id],
            program_kernel_samples=kernel_count,
            duration=duration,
            frequency=frequency,
            line_limit=line_limit,
        )
        rows.append(
            BpfProfileProgram(
                id=program.id,
                program_type=program.program_type,
                name=program.name,
                tag=program.tag,
                samples=count,
                sample_percent=_percent(count, total_samples),
                cpu_percent=_cpu_percent(count, duration=duration, frequency=frequency),
                pinned_paths=program.pinned_paths,
                hotspots=hotspots,
                kernel_samples=kernel_count,
                kernel_cpu_percent=_cpu_percent(
                    kernel_count,
                    duration=duration,
                    frequency=frequency,
                ),
                kernel_hotspots=kernel_hotspots,
                inclusive_samples=count + kernel_count,
                inclusive_cpu_percent=_cpu_percent(
                    count + kernel_count,
                    duration=duration,
                    frequency=frequency,
                ),
            )
        )

    if limit > 0:
        rows = rows[:limit]

    return BpfProfile(
        metadata=BpfProfileMetadata(
            requested_event=requested_event,
            selected_event=selected_event,
            duration=duration,
            frequency=frequency,
            limit=limit,
            line_limit=line_limit,
            total_samples=total_samples,
            lost_samples=lost_samples,
            unresolved_samples=non_bpf_samples,
            bpf_jit_samples=sum(program_counts.values()),
            non_bpf_samples=non_bpf_samples,
            selected_program_samples=(
                program_counts[selected_program_id] if selected_program_id is not None else 0
            ),
            other_bpf_samples=(
                sum(
                    count
                    for program_id, count in program_counts.items()
                    if program_id != selected_program_id
                )
                if selected_program_id is not None
                else 0
            ),
            source_mapped_samples=source_mapped_samples,
            source_unmapped_samples=source_unmapped_samples,
            callchain_samples=callchain_samples,
            kernel_attributed_samples=kernel_attributed_samples,
            kernel_unattributed_samples=kernel_unattributed_samples,
            kernel_symbolized_samples=kernel_symbolized_samples,
            call_graph=call_graph,
            warnings=warnings,
        ),
        items=rows,
    )


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
    try:
        with open(path, encoding="utf-8") as rate_file:
            text = rate_file.read().strip()
    except OSError:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


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
) -> PerfEventAttr:
    attr = PerfEventAttr()
    attr.type = event.event_type
    attr.size = _perf_attr_size(callchain=sample_callchain, call_graph=call_graph)
    attr.config = event.config
    attr.sample_freq = frequency
    attr.sample_type = _profile_sample_type(callchain=sample_callchain, call_graph=call_graph)
    attr.read_format = 0
    attr.flags = (1 << 0) | (1 << 4) | (1 << 6) | (1 << 10)
    attr.flags |= event.precise_ip << 15
    attr.wakeup_events = 1
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
    bpf_file_name: str | None
    bpf_line_number: int | None
    bpf_column: int | None
    bpf_source: str | None


def _hotspot_key(line_info: BpfLineInfo | None) -> HotspotKey:
    if line_info is None:
        return HotspotKey(None, None, None, None, None)
    return HotspotKey(
        jited_address=line_info.jited_address,
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
            bpf_file_name=key.bpf_file_name,
            bpf_line_number=key.bpf_line_number,
            bpf_column=key.bpf_column,
            bpf_source=key.bpf_source,
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
