from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import platform
from collections.abc import Iterator
from contextlib import AbstractContextManager

from brr.bpf_details import (
    BPF_LINE_INFO_SIZE,
    BtfStringTable,
    attach_jited_addresses,
    parse_bpf_instructions,
    parse_jited_line_addresses,
    parse_line_info_records,
)
from brr.errors import PermissionDeniedError, UnsupportedFeatureError
from brr.models import BpfJitRange, BpfLink, BpfMap, BpfProgram, BpfProgramDetails, BtfObject

BPF_OBJ_GET = 7
BPF_PROG_GET_NEXT_ID = 11
BPF_MAP_GET_NEXT_ID = 12
BPF_PROG_GET_FD_BY_ID = 13
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_BTF_GET_FD_BY_ID = 19
BPF_BTF_GET_NEXT_ID = 23
BPF_LINK_GET_FD_BY_ID = 30
BPF_LINK_GET_NEXT_ID = 31
BPF_ENABLE_STATS = 32
BPF_STATS_RUN_TIME = 0

BPF_OBJ_NAME_LEN = 16
BPF_TAG_SIZE = 8
SYS_BPF_BY_MACHINE = {
    "aarch64": 280,
    "arm64": 280,
    "x86_64": 321,
}

PROGRAM_TYPE_NAMES = {
    0: "unspec",
    1: "socket_filter",
    2: "kprobe",
    3: "sched_cls",
    4: "sched_act",
    5: "tracepoint",
    6: "xdp",
    7: "perf_event",
    8: "cgroup_skb",
    9: "cgroup_sock",
    10: "lwt_in",
    11: "lwt_out",
    12: "lwt_xmit",
    13: "sock_ops",
    14: "sk_skb",
    15: "cgroup_device",
    16: "sk_msg",
    17: "raw_tracepoint",
    18: "cgroup_sock_addr",
    19: "lwt_seg6local",
    20: "lirc_mode2",
    21: "sk_reuseport",
    22: "flow_dissector",
    23: "cgroup_sysctl",
    24: "raw_tracepoint_writable",
    25: "cgroup_sockopt",
    26: "tracing",
    27: "struct_ops",
    28: "ext",
    29: "lsm",
    30: "sk_lookup",
    31: "syscall",
    32: "netfilter",
}

MAP_TYPE_NAMES = {
    0: "unspec",
    1: "hash",
    2: "array",
    3: "prog_array",
    4: "perf_event_array",
    5: "percpu_hash",
    6: "percpu_array",
    7: "stack_trace",
    8: "cgroup_array",
    9: "lru_hash",
    10: "lru_percpu_hash",
    11: "lpm_trie",
    12: "array_of_maps",
    13: "hash_of_maps",
    14: "devmap",
    15: "sockmap",
    16: "cpumap",
    17: "xskmap",
    18: "sockhash",
    19: "cgroup_storage",
    20: "reuseport_sockarray",
    21: "percpu_cgroup_storage",
    22: "queue",
    23: "stack",
    24: "sk_storage",
    25: "devmap_hash",
    26: "struct_ops",
    27: "ringbuf",
    28: "inode_storage",
    29: "task_storage",
    30: "bloom_filter",
    31: "user_ringbuf",
    32: "cgrp_storage",
    33: "arena",
}

ATTACH_TYPE_NAMES = {
    0: "cgroup_inet_ingress",
    1: "cgroup_inet_egress",
    2: "cgroup_inet_sock_create",
    3: "cgroup_sock_ops",
    4: "sk_skb_stream_parser",
    5: "sk_skb_stream_verdict",
    6: "cgroup_device",
    7: "sk_msg_verdict",
    8: "cgroup_inet4_bind",
    9: "cgroup_inet6_bind",
    10: "cgroup_inet4_connect",
    11: "cgroup_inet6_connect",
    12: "cgroup_inet4_post_bind",
    13: "cgroup_inet6_post_bind",
    14: "cgroup_udp4_sendmsg",
    15: "cgroup_udp6_sendmsg",
    16: "lirc_mode2",
    17: "flow_dissector",
    18: "cgroup_sysctl",
    19: "cgroup_udp4_recvmsg",
    20: "cgroup_udp6_recvmsg",
    21: "cgroup_getsockopt",
    22: "cgroup_setsockopt",
    23: "trace_raw_tp",
    24: "trace_fentry",
    25: "trace_fexit",
    26: "modify_return",
    27: "lsm_mac",
    28: "trace_iter",
    29: "cgroup_inet4_getpeername",
    30: "cgroup_inet6_getpeername",
    31: "cgroup_inet4_getsockname",
    32: "cgroup_inet6_getsockname",
    33: "xdp_devmap",
    34: "cgroup_inet_sock_release",
    35: "xdp_cpumap",
    36: "sk_lookup",
    37: "xdp",
    38: "sk_skb_verdict",
    39: "sk_reuseport_select",
    40: "sk_reuseport_select_or_migrate",
    41: "perf_event",
    42: "trace_kprobe_multi",
    43: "lsm_cgroup",
    44: "struct_ops",
    45: "netfilter",
    46: "tcx_ingress",
    47: "tcx_egress",
}

LINK_TYPE_NAMES = {
    0: "unspec",
    1: "raw_tracepoint",
    2: "tracing",
    3: "cgroup",
    4: "iter",
    5: "netns",
    6: "xdp",
    7: "perf_event",
    8: "kprobe_multi",
    9: "struct_ops",
    10: "netfilter",
    11: "tcx",
    12: "uprobe_multi",
    13: "netkit",
    14: "sockmap",
}

PINNED_KIND_PROGRAM = "program"
PINNED_KIND_MAP = "map"
PINNED_KIND_LINK = "link"
PINNED_KIND_BTF = "btf"


class NextIdAttr(ctypes.Structure):
    _fields_ = [
        ("start_id", ctypes.c_uint32),
        ("next_id", ctypes.c_uint32),
        ("open_flags", ctypes.c_uint32),
        ("fd_by_id_token_fd", ctypes.c_int32),
    ]


class FdByIdAttr(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint32),
        ("open_flags", ctypes.c_uint32),
        ("fd_by_id_token_fd", ctypes.c_int32),
    ]


class InfoByFdAttr(ctypes.Structure):
    _fields_ = [
        ("bpf_fd", ctypes.c_uint32),
        ("info_len", ctypes.c_uint32),
        ("info", ctypes.c_uint64),
    ]


class ObjGetAttr(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
        ("path_fd", ctypes.c_int32),
    ]


class EnableStatsAttr(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32)]


class BpfProgInfo(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("tag", ctypes.c_ubyte * BPF_TAG_SIZE),
        ("jited_prog_len", ctypes.c_uint32),
        ("xlated_prog_len", ctypes.c_uint32),
        ("jited_prog_insns", ctypes.c_uint64),
        ("xlated_prog_insns", ctypes.c_uint64),
        ("load_time", ctypes.c_uint64),
        ("created_by_uid", ctypes.c_uint32),
        ("nr_map_ids", ctypes.c_uint32),
        ("map_ids", ctypes.c_uint64),
        ("name", ctypes.c_char * BPF_OBJ_NAME_LEN),
        ("ifindex", ctypes.c_uint32),
        ("gpl_compatible", ctypes.c_uint32, 1),
        ("__reserved_1", ctypes.c_uint32, 31),
        ("netns_dev", ctypes.c_uint64),
        ("netns_ino", ctypes.c_uint64),
        ("nr_jited_ksyms", ctypes.c_uint32),
        ("nr_jited_func_lens", ctypes.c_uint32),
        ("jited_ksyms", ctypes.c_uint64),
        ("jited_func_lens", ctypes.c_uint64),
        ("btf_id", ctypes.c_uint32),
        ("func_info_rec_size", ctypes.c_uint32),
        ("func_info", ctypes.c_uint64),
        ("nr_func_info", ctypes.c_uint32),
        ("nr_line_info", ctypes.c_uint32),
        ("line_info", ctypes.c_uint64),
        ("jited_line_info", ctypes.c_uint64),
        ("nr_jited_line_info", ctypes.c_uint32),
        ("line_info_rec_size", ctypes.c_uint32),
        ("jited_line_info_rec_size", ctypes.c_uint32),
        ("nr_prog_tags", ctypes.c_uint32),
        ("prog_tags", ctypes.c_uint64),
        ("run_time_ns", ctypes.c_uint64),
        ("run_cnt", ctypes.c_uint64),
        ("recursion_misses", ctypes.c_uint64),
        ("verified_insns", ctypes.c_uint32),
        ("attach_btf_obj_id", ctypes.c_uint32),
        ("attach_btf_id", ctypes.c_uint32),
    ]


class BpfMapInfo(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("name", ctypes.c_char * BPF_OBJ_NAME_LEN),
        ("ifindex", ctypes.c_uint32),
        ("btf_vmlinux_value_type_id", ctypes.c_uint32),
        ("netns_dev", ctypes.c_uint64),
        ("netns_ino", ctypes.c_uint64),
        ("btf_id", ctypes.c_uint32),
        ("btf_key_type_id", ctypes.c_uint32),
        ("btf_value_type_id", ctypes.c_uint32),
        ("btf_vmlinux_id", ctypes.c_uint32),
        ("map_extra", ctypes.c_uint64),
    ]


class BpfBtfInfo(ctypes.Structure):
    _fields_ = [
        ("btf", ctypes.c_uint64),
        ("btf_size", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("name", ctypes.c_uint64),
        ("name_len", ctypes.c_uint32),
        ("kernel_btf", ctypes.c_uint32),
    ]


class LinkTracingInfo(ctypes.Structure):
    _fields_ = [
        ("attach_type", ctypes.c_uint32),
        ("target_obj_id", ctypes.c_uint32),
        ("target_btf_id", ctypes.c_uint32),
        ("__reserved", ctypes.c_uint32),
        ("cookie", ctypes.c_uint64),
    ]


class LinkCgroupInfo(ctypes.Structure):
    _fields_ = [
        ("cgroup_id", ctypes.c_uint64),
        ("attach_type", ctypes.c_uint32),
    ]


class LinkNetnsInfo(ctypes.Structure):
    _fields_ = [
        ("netns_ino", ctypes.c_uint32),
        ("attach_type", ctypes.c_uint32),
    ]


class LinkXdpInfo(ctypes.Structure):
    _fields_ = [("ifindex", ctypes.c_uint32)]


class LinkStructOpsInfo(ctypes.Structure):
    _fields_ = [("map_id", ctypes.c_uint32)]


class LinkNetfilterInfo(ctypes.Structure):
    _fields_ = [
        ("pf", ctypes.c_uint32),
        ("hooknum", ctypes.c_uint32),
        ("priority", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


class LinkInfoUnion(ctypes.Union):
    _fields_ = [
        ("tracing", LinkTracingInfo),
        ("cgroup", LinkCgroupInfo),
        ("netns", LinkNetnsInfo),
        ("xdp", LinkXdpInfo),
        ("struct_ops", LinkStructOpsInfo),
        ("netfilter", LinkNetfilterInfo),
        ("raw", ctypes.c_ubyte * 96),
    ]


class BpfLinkInfo(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("prog_id", ctypes.c_uint32),
        ("extra", LinkInfoUnion),
    ]


class _ProgramInfoBuffers:
    def __init__(
        self,
        *,
        map_capacity: int,
        xlated_capacity: int,
        jited_ksym_capacity: int,
        jited_func_len_capacity: int,
        line_info_capacity: int,
        line_info_rec_size: int,
        jited_line_info_capacity: int,
        jited_line_info_rec_size: int,
    ) -> None:
        self.map_capacity = map_capacity
        self.xlated_capacity = xlated_capacity
        self.jited_ksym_capacity = jited_ksym_capacity
        self.jited_func_len_capacity = jited_func_len_capacity
        self.line_info_capacity = line_info_capacity
        self.line_info_rec_size = line_info_rec_size
        self.jited_line_info_capacity = jited_line_info_capacity
        self.jited_line_info_rec_size = jited_line_info_rec_size

        self._map_ids = _allocate_array(ctypes.c_uint32, map_capacity)
        self._xlated = _allocate_array(ctypes.c_ubyte, xlated_capacity)
        self._jited_ksyms = _allocate_array(ctypes.c_uint64, jited_ksym_capacity)
        self._jited_func_lens = _allocate_array(ctypes.c_uint32, jited_func_len_capacity)
        self._line_info = _allocate_array(
            ctypes.c_ubyte,
            line_info_capacity * line_info_rec_size,
        )
        self._jited_line_info = _allocate_array(
            ctypes.c_ubyte,
            jited_line_info_capacity * jited_line_info_rec_size,
        )

    @classmethod
    def from_info(cls, info: BpfProgInfo) -> _ProgramInfoBuffers:
        return cls(
            map_capacity=info.nr_map_ids,
            xlated_capacity=info.xlated_prog_len,
            jited_ksym_capacity=info.nr_jited_ksyms,
            jited_func_len_capacity=info.nr_jited_func_lens,
            line_info_capacity=info.nr_line_info,
            line_info_rec_size=info.line_info_rec_size or BPF_LINE_INFO_SIZE,
            jited_line_info_capacity=info.nr_jited_line_info,
            jited_line_info_rec_size=info.jited_line_info_rec_size
            or ctypes.sizeof(ctypes.c_uint64),
        )

    def assign_to_info(self, info: BpfProgInfo) -> None:
        info.nr_map_ids = self.map_capacity
        info.map_ids = _address_or_zero(self._map_ids)
        info.xlated_prog_len = self.xlated_capacity
        info.xlated_prog_insns = _address_or_zero(self._xlated)
        info.nr_jited_ksyms = self.jited_ksym_capacity
        info.jited_ksyms = _address_or_zero(self._jited_ksyms)
        info.nr_jited_func_lens = self.jited_func_len_capacity
        info.jited_func_lens = _address_or_zero(self._jited_func_lens)
        info.nr_line_info = self.line_info_capacity
        info.line_info = _address_or_zero(self._line_info)
        info.line_info_rec_size = self.line_info_rec_size
        info.nr_jited_line_info = self.jited_line_info_capacity
        info.jited_line_info = _address_or_zero(self._jited_line_info)
        info.jited_line_info_rec_size = self.jited_line_info_rec_size

    def map_ids(self, count: int) -> tuple[int, ...]:
        if self._map_ids is None:
            return ()
        return tuple(self._map_ids[index] for index in range(min(count, self.map_capacity)))

    def xlated_bytes(self, length: int) -> bytes:
        return _bytes_from_buffer(self._xlated, min(length, self.xlated_capacity))

    def line_info_bytes(self, count: int) -> bytes:
        length = min(count, self.line_info_capacity) * self.line_info_rec_size
        return _bytes_from_buffer(self._line_info, length)

    def jited_line_info_bytes(self, count: int) -> bytes:
        length = min(count, self.jited_line_info_capacity) * self.jited_line_info_rec_size
        return _bytes_from_buffer(self._jited_line_info, length)

    def jited_ksyms(self, count: int) -> tuple[int, ...]:
        if self._jited_ksyms is None:
            return ()
        return tuple(
            self._jited_ksyms[index] for index in range(min(count, self.jited_ksym_capacity))
        )

    def jited_func_lens(self, count: int) -> tuple[int, ...]:
        if self._jited_func_lens is None:
            return ()
        return tuple(
            self._jited_func_lens[index]
            for index in range(min(count, self.jited_func_len_capacity))
        )


def _allocate_array(element_type, count: int):
    if count <= 0:
        return None
    return (element_type * count)()


def _address_or_zero(buffer) -> int:
    if buffer is None:
        return 0
    return ctypes.addressof(buffer)


def _bytes_from_buffer(buffer, length: int) -> bytes:
    if buffer is None or length <= 0:
        return b""
    return bytes(buffer)[:length]


class RuntimeStatsGuard(AbstractContextManager["RuntimeStatsGuard"]):
    def __init__(self, collector: SyscallBpfCollector) -> None:
        self.collector = collector
        self.fd: int | None = None

    def __enter__(self) -> RuntimeStatsGuard:
        attr = EnableStatsAttr(type=BPF_STATS_RUN_TIME)
        try:
            self.fd = self.collector._bpf(BPF_ENABLE_STATS, attr)
        except OSError as exc:
            self.collector._raise_bpf_error("enable eBPF runtime statistics", exc)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        return None


class SyscallBpfCollector:
    def __init__(self) -> None:
        libc_name = ctypes.util.find_library("c")
        if libc_name is None:
            raise UnsupportedFeatureError("unable to locate libc for bpf() syscall access")
        self._sys_bpf = self._resolve_sys_bpf()
        self._libc = ctypes.CDLL(libc_name, use_errno=True)
        self._libc.syscall.restype = ctypes.c_long

    def enable_runtime_stats(self) -> RuntimeStatsGuard:
        return RuntimeStatsGuard(self)

    def list_programs(self) -> list[BpfProgram]:
        return [
            self.get_program_by_id(object_id) for object_id in self.iter_ids(BPF_PROG_GET_NEXT_ID)
        ]

    def list_program_details(self) -> list[BpfProgramDetails]:
        return [
            self.get_program_details_by_id(object_id)
            for object_id in self.iter_ids(BPF_PROG_GET_NEXT_ID)
        ]

    def list_maps(self) -> list[BpfMap]:
        return [self.get_map_by_id(object_id) for object_id in self.iter_ids(BPF_MAP_GET_NEXT_ID)]

    def list_links(self) -> list[BpfLink]:
        return [self.get_link_by_id(object_id) for object_id in self.iter_ids(BPF_LINK_GET_NEXT_ID)]

    def list_btfs(self) -> list[BtfObject]:
        return [self.get_btf_by_id(object_id) for object_id in self.iter_ids(BPF_BTF_GET_NEXT_ID)]

    def iter_ids(self, next_id_cmd: int) -> Iterator[int]:
        start_id = 0
        while True:
            attr = NextIdAttr(start_id=start_id, next_id=0, open_flags=0, fd_by_id_token_fd=0)
            try:
                self._bpf(next_id_cmd, attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                self._raise_bpf_error("list eBPF object IDs", exc)

            if attr.next_id == 0:
                break

            yield attr.next_id
            start_id = attr.next_id

    def get_program_by_id(self, program_id: int) -> BpfProgram:
        return self._with_fd(BPF_PROG_GET_FD_BY_ID, program_id, self.get_program_by_fd)

    def get_program_details_by_id(self, program_id: int) -> BpfProgramDetails:
        return self._with_fd(
            BPF_PROG_GET_FD_BY_ID,
            program_id,
            self.get_program_details_by_fd,
        )

    def get_map_by_id(self, map_id: int) -> BpfMap:
        return self._with_fd(BPF_MAP_GET_FD_BY_ID, map_id, self.get_map_by_fd)

    def get_link_by_id(self, link_id: int) -> BpfLink:
        return self._with_fd(BPF_LINK_GET_FD_BY_ID, link_id, self.get_link_by_fd)

    def get_btf_by_id(self, btf_id: int) -> BtfObject:
        return self._with_fd(BPF_BTF_GET_FD_BY_ID, btf_id, self.get_btf_by_fd)

    def get_btf_data_by_id(self, btf_id: int) -> bytes:
        return self._with_fd(BPF_BTF_GET_FD_BY_ID, btf_id, self.get_btf_data_by_fd)

    def get_program_by_fd(self, fd: int) -> BpfProgram:
        info = BpfProgInfo()
        map_ids = (ctypes.c_uint32 * 256)()
        info.nr_map_ids = 256
        info.map_ids = ctypes.addressof(map_ids)
        self._load_info(fd, info)
        count = min(info.nr_map_ids, 256)
        return self._program_from_info(
            info,
            tuple(map_ids[index] for index in range(count)),
        )

    def get_program_details_by_fd(self, fd: int) -> BpfProgramDetails:
        initial = BpfProgInfo()
        self._load_info(fd, initial)

        buffers = _ProgramInfoBuffers.from_info(initial)
        info = BpfProgInfo()
        buffers.assign_to_info(info)
        self._load_info(fd, info)

        map_ids = buffers.map_ids(info.nr_map_ids)
        btf_data = self.get_btf_data_by_id(info.btf_id) if info.btf_id else b""
        strings = BtfStringTable.from_btf_data(btf_data)
        line_info = parse_line_info_records(
            buffers.line_info_bytes(info.nr_line_info),
            count=info.nr_line_info,
            record_size=info.line_info_rec_size or BPF_LINE_INFO_SIZE,
            strings=strings,
        )
        jited_addresses = parse_jited_line_addresses(
            buffers.jited_line_info_bytes(info.nr_jited_line_info),
            count=info.nr_jited_line_info,
            record_size=info.jited_line_info_rec_size or ctypes.sizeof(ctypes.c_uint64),
        )
        attach_jited_addresses(line_info, jited_addresses)
        jit_ranges = [
            BpfJitRange(
                program_id=info.id,
                function_index=index,
                start=start,
                length=length,
            )
            for index, (start, length) in enumerate(
                zip(
                    buffers.jited_ksyms(info.nr_jited_ksyms),
                    buffers.jited_func_lens(info.nr_jited_func_lens),
                    strict=False,
                )
            )
            if start and length
        ]
        instructions = parse_bpf_instructions(
            buffers.xlated_bytes(info.xlated_prog_len),
            line_info,
        )
        return BpfProgramDetails(
            program=self._program_from_info(info, map_ids),
            instructions=instructions,
            line_info=line_info,
            jit_ranges=jit_ranges,
        )

    def _program_from_info(self, info: BpfProgInfo, map_ids: tuple[int, ...]) -> BpfProgram:
        return BpfProgram(
            id=info.id,
            program_type=PROGRAM_TYPE_NAMES.get(info.type, f"unknown({info.type})"),
            name=self._decode_name(info.name),
            tag=bytes(info.tag).hex(),
            xlated_size_bytes=info.xlated_prog_len,
            jited_size_bytes=info.jited_prog_len,
            run_time_ns=info.run_time_ns or None,
            run_count=info.run_cnt or None,
            map_ids=map_ids,
            btf_id=info.btf_id or None,
            pinned_paths=(),
        )

    def get_map_by_fd(self, fd: int) -> BpfMap:
        info = BpfMapInfo()
        self._load_info(fd, info)
        return BpfMap(
            id=info.id,
            map_type=MAP_TYPE_NAMES.get(info.type, f"unknown({info.type})"),
            name=self._decode_name(info.name),
            key_size=info.key_size,
            value_size=info.value_size,
            max_entries=info.max_entries,
            btf_id=info.btf_id or None,
            pinned_paths=(),
        )

    def get_link_by_fd(self, fd: int) -> BpfLink:
        info = BpfLinkInfo()
        self._load_info(fd, info)
        attach_type, target_obj_id, target_btf_id = self._decode_link_details(info)
        return BpfLink(
            id=info.id,
            link_type=LINK_TYPE_NAMES.get(info.type, f"unknown({info.type})"),
            prog_id=info.prog_id,
            attach_type=attach_type,
            target_obj_id=target_obj_id,
            target_btf_id=target_btf_id,
            pinned_paths=(),
        )

    def get_btf_by_fd(self, fd: int) -> BtfObject:
        name_buffer = ctypes.create_string_buffer(512)
        info = BpfBtfInfo(
            btf=0,
            btf_size=0,
            id=0,
            name=ctypes.addressof(name_buffer),
            name_len=ctypes.sizeof(name_buffer),
            kernel_btf=0,
        )
        self._load_info(fd, info)
        name = name_buffer.value.decode(errors="replace") or "-"
        return BtfObject(id=info.id, name=name, size=info.btf_size, pinned_paths=())

    def get_btf_data_by_fd(self, fd: int) -> bytes:
        initial = BpfBtfInfo(btf=0, btf_size=0, id=0, name=0, name_len=0, kernel_btf=0)
        self._load_info(fd, initial)
        if initial.btf_size == 0:
            return b""

        data = (ctypes.c_ubyte * initial.btf_size)()
        info = BpfBtfInfo(
            btf=ctypes.addressof(data),
            btf_size=initial.btf_size,
            id=0,
            name=0,
            name_len=0,
            kernel_btf=0,
        )
        self._load_info(fd, info)
        return bytes(data)[: info.btf_size]

    def classify_pinned_fd(self, fd: int) -> tuple[str, int] | None:
        for kind, reader in (
            (PINNED_KIND_PROGRAM, self.get_program_by_fd),
            (PINNED_KIND_MAP, self.get_map_by_fd),
            (PINNED_KIND_LINK, self.get_link_by_fd),
            (PINNED_KIND_BTF, self.get_btf_by_fd),
        ):
            try:
                obj = reader(fd)
            except OSError as exc:
                if exc.errno in {errno.EINVAL, errno.ENOTSUP, errno.EBADF}:
                    continue
                return None
            return (kind, obj.id)
        return None

    def open_pinned_path(self, path: str) -> int:
        path_buffer = ctypes.create_string_buffer(os.fsencode(path) + b"\x00")
        attr = ObjGetAttr(
            pathname=ctypes.addressof(path_buffer),
            bpf_fd=0,
            file_flags=0,
            path_fd=0,
        )
        return self._bpf(BPF_OBJ_GET, attr)

    def _with_fd(self, fd_by_id_cmd: int, object_id: int, reader):
        attr = FdByIdAttr(id=object_id, open_flags=0, fd_by_id_token_fd=0)
        try:
            fd = self._bpf(fd_by_id_cmd, attr)
        except OSError as exc:
            self._raise_bpf_error(f"open eBPF object id {object_id}", exc)
        try:
            return reader(fd)
        finally:
            os.close(fd)

    def _load_info(self, fd: int, info: ctypes.Structure) -> None:
        attr = InfoByFdAttr(
            bpf_fd=fd,
            info_len=ctypes.sizeof(info),
            info=ctypes.addressof(info),
        )
        try:
            self._bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
        except OSError as exc:
            raise OSError(exc.errno, exc.strerror) from exc

    def _decode_link_details(self, info: BpfLinkInfo) -> tuple[str | None, int | None, int | None]:
        if info.type == 2:
            tracing = info.extra.tracing
            return (
                ATTACH_TYPE_NAMES.get(tracing.attach_type, str(tracing.attach_type)),
                tracing.target_obj_id or None,
                tracing.target_btf_id or None,
            )
        if info.type == 3:
            cgroup = info.extra.cgroup
            return (ATTACH_TYPE_NAMES.get(cgroup.attach_type, str(cgroup.attach_type)), None, None)
        if info.type == 5:
            netns = info.extra.netns
            return (ATTACH_TYPE_NAMES.get(netns.attach_type, str(netns.attach_type)), None, None)
        return (None, None, None)

    def _bpf(self, cmd: int, attr: ctypes.Structure) -> int:
        result = self._libc.syscall(self._sys_bpf, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
        if result < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        return int(result)

    def _raise_bpf_error(self, action: str, exc: OSError) -> None:
        if exc.errno in {errno.EACCES, errno.EPERM}:
            raise PermissionDeniedError(
                f"permission denied while trying to {action}; run brr with sudo"
            ) from exc
        if exc.errno in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL, errno.ENOENT}:
            raise UnsupportedFeatureError(
                f"kernel does not support required bpf() features to {action}"
            ) from exc
        raise OSError(exc.errno, f"failed to {action}: {exc.strerror}") from exc

    def _decode_name(self, raw_name: bytes | ctypes.Array[ctypes.c_char]) -> str:
        name = bytes(raw_name).split(b"\x00", 1)[0].decode(errors="replace")
        return name or "-"

    def _resolve_sys_bpf(self) -> int:
        machine = platform.machine().lower()
        sys_bpf = SYS_BPF_BY_MACHINE.get(machine)
        if sys_bpf is None:
            raise UnsupportedFeatureError(
                f"unsupported machine architecture for bpf() syscall: {machine}"
            )
        return sys_bpf
