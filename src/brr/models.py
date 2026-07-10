from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class BpfProgram:
    id: int
    program_type: str
    name: str
    tag: str | None = None
    xlated_size_bytes: int = 0
    jited_size_bytes: int = 0
    run_time_ns: int | None = None
    run_count: int | None = None
    map_ids: tuple[int, ...] = ()
    btf_id: int | None = None
    pinned_paths: tuple[str, ...] = ()


@dataclass(slots=True)
class BpfSourceLine:
    file_name: str | None
    line_number: int | None
    column: int | None
    source: str | None


@dataclass(slots=True)
class BpfLineInfo:
    insn_offset: int
    file_name: str | None = None
    line_number: int | None = None
    column: int | None = None
    source: str | None = None
    jited_address: int | None = None


@dataclass(slots=True)
class BpfInstruction:
    offset: int
    raw: str
    opcode: int
    dst_reg: int
    src_reg: int
    off: int
    imm: int
    source: BpfSourceLine | None = None


@dataclass(slots=True)
class BpfJitRange:
    program_id: int
    function_index: int
    start: int
    length: int

    @property
    def end(self) -> int:
        return self.start + self.length


@dataclass(slots=True)
class BpfProgramDetails:
    program: BpfProgram
    instructions: list[BpfInstruction] = field(default_factory=list)
    line_info: list[BpfLineInfo] = field(default_factory=list)
    jit_ranges: list[BpfJitRange] = field(default_factory=list)


@dataclass(slots=True)
class BpfProgramDump:
    program: BpfProgram
    instructions: list[BpfInstruction]
    line_info_count: int
    jit_ranges: list[BpfJitRange] = field(default_factory=list)


@dataclass(slots=True)
class BpfHotspot:
    samples: int
    sample_percent: float
    cpu_percent: float = 0.0
    jited_address: int | None = None
    instruction_offset: int | None = None
    file_name: str | None = None
    line_number: int | None = None
    column: int | None = None
    source: str | None = None


@dataclass(slots=True)
class BpfKernelHotspot:
    samples: int
    sample_percent: float
    cpu_percent: float
    ip: int
    symbol: str | None = None
    module: str | None = None
    symbol_offset: int | None = None
    symbol_kind: str = "unknown"
    bpf_jited_address: int | None = None
    bpf_instruction_offset: int | None = None
    bpf_file_name: str | None = None
    bpf_line_number: int | None = None
    bpf_column: int | None = None
    bpf_source: str | None = None


@dataclass(slots=True)
class BpfProfileProgram:
    id: int
    program_type: str
    name: str
    tag: str | None
    samples: int
    sample_percent: float
    cpu_percent: float = 0.0
    pinned_paths: tuple[str, ...] = ()
    hotspots: list[BpfHotspot] = field(default_factory=list)
    kernel_samples: int = 0
    kernel_cpu_percent: float = 0.0
    kernel_hotspots: list[BpfKernelHotspot] = field(default_factory=list)
    inclusive_samples: int = 0
    inclusive_cpu_percent: float = 0.0
    direct_source_mapped_samples: int = 0
    direct_source_unmapped_samples: int = 0
    under_bpf_caller_source_mapped_samples: int = 0
    under_bpf_caller_source_unmapped_samples: int = 0
    direct_hotspot_samples_omitted_by_limit: int = 0
    under_bpf_hotspot_samples_omitted_by_limit: int = 0

    def __post_init__(self) -> None:
        if self.inclusive_samples == 0:
            self.inclusive_samples = self.samples + self.kernel_samples
        if self.inclusive_cpu_percent == 0.0:
            self.inclusive_cpu_percent = round(self.cpu_percent + self.kernel_cpu_percent, 4)
        if (
            self.samples > 0
            and self.direct_source_mapped_samples == 0
            and self.direct_source_unmapped_samples == 0
        ):
            self.direct_source_mapped_samples = self.samples
        if (
            self.kernel_samples > 0
            and self.under_bpf_caller_source_mapped_samples == 0
            and self.under_bpf_caller_source_unmapped_samples == 0
        ):
            self.under_bpf_caller_source_mapped_samples = self.kernel_samples

    @property
    def unaccounted_samples(self) -> int:
        return max(0, self.inclusive_samples - self.samples - self.kernel_samples)


@dataclass(slots=True)
class BpfProfileMetadata:
    requested_event: str
    selected_event: str
    duration: float
    frequency: int
    limit: int
    line_limit: int
    total_samples: int
    lost_samples: int
    unresolved_samples: int
    bpf_jit_samples: int = 0
    non_bpf_samples: int = 0
    selected_program_samples: int = 0
    other_bpf_samples: int = 0
    source_mapped_samples: int = 0
    source_unmapped_samples: int = 0
    callchain_samples: int = 0
    kernel_attributed_samples: int = 0
    kernel_unattributed_samples: int = 0
    kernel_symbolized_samples: int = 0
    call_graph: str = "fp"
    actual_duration: float = 0.0
    perf_cpus: tuple[int, ...] = ()
    perf_buffer_pages_per_cpu: int = 0
    perf_buffer_bytes_per_cpu: int = 0
    perf_buffer_bytes_total: int = 0
    perf_drain_interval_ms: int = 0
    perf_drain_count: int = 0
    perf_max_ring_occupancy_percent: float = 0.0
    perf_throttle_events: int = 0
    perf_unthrottle_events: int = 0
    perf_malformed_records: int = 0
    perf_unknown_records: int = 0
    perf_discarded_bytes: int = 0
    perf_time_enabled_ns: int = 0
    perf_time_running_ns: int = 0
    perf_running_percent: float = 100.0
    incomplete: bool = False
    warnings: tuple[str, ...] = ()


@dataclass(slots=True)
class BpfProfile:
    metadata: BpfProfileMetadata
    items: list[BpfProfileProgram] = field(default_factory=list)


@dataclass(slots=True)
class BpfProgramActivity:
    id: int
    program_type: str
    name: str
    tag: str | None
    run_count_delta: int
    run_time_ns_delta: int
    run_count_total: int = 0
    run_time_ns_total: int = 0
    xlated_size_bytes: int = 0
    jited_size_bytes: int = 0
    pinned_paths: tuple[str, ...] = ()

    @property
    def avg_run_time_ns(self) -> int:
        if self.run_count_delta == 0:
            return 0
        return self.run_time_ns_delta // self.run_count_delta

    @property
    def cumulative_avg_run_time_ns(self) -> int:
        if self.run_count_total == 0:
            return 0
        return self.run_time_ns_total // self.run_count_total


@dataclass(slots=True)
class BpfMap:
    id: int
    map_type: str
    name: str
    key_size: int
    value_size: int
    max_entries: int
    btf_id: int | None = None
    pinned_paths: tuple[str, ...] = ()


@dataclass(slots=True)
class BpfLink:
    id: int
    link_type: str
    prog_id: int
    attach_type: str | None = None
    target_obj_id: int | None = None
    target_btf_id: int | None = None
    pinned_paths: tuple[str, ...] = ()


@dataclass(slots=True)
class BtfObject:
    id: int
    name: str
    size: int
    pinned_paths: tuple[str, ...] = ()


@dataclass(slots=True)
class BpfSnapshot:
    programs: list[BpfProgram] = field(default_factory=list)
    maps: list[BpfMap] = field(default_factory=list)
    links: list[BpfLink] = field(default_factory=list)
    btfs: list[BtfObject] = field(default_factory=list)
