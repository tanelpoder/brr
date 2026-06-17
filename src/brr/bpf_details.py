from __future__ import annotations

import bisect
import struct

from brr.models import BpfInstruction, BpfJitRange, BpfLineInfo, BpfSourceLine

BPF_INSN_SIZE = 8
BPF_LINE_INFO_SIZE = 16
BTF_HEADER_SIZE = 24
BTF_MAGIC = 0xEB9F


class BtfStringTable:
    def __init__(self, strings: bytes = b"") -> None:
        self._strings = strings

    @classmethod
    def from_btf_data(cls, data: bytes) -> BtfStringTable:
        if len(data) < BTF_HEADER_SIZE:
            return cls()

        magic, _version, _flags, header_len, _type_off, _type_len, str_off, str_len = (
            struct.unpack_from("<HBBIIIII", data, 0)
        )
        if magic != BTF_MAGIC:
            return cls()

        start = header_len + str_off
        end = start + str_len
        if start < 0 or end > len(data) or start > end:
            return cls()
        return cls(data[start:end])

    def get(self, offset: int) -> str | None:
        if offset < 0 or offset >= len(self._strings):
            return None
        end = self._strings.find(b"\x00", offset)
        if end == -1:
            end = len(self._strings)
        raw = self._strings[offset:end]
        if not raw:
            return None
        return raw.decode(errors="replace")


class SourceLineMapper:
    def __init__(self, line_info: list[BpfLineInfo]) -> None:
        self._by_insn = sorted(line_info, key=lambda info: info.insn_offset)
        self._insn_offsets = [info.insn_offset for info in self._by_insn]
        self._by_jited = sorted(
            [info for info in line_info if info.jited_address is not None],
            key=lambda info: info.jited_address or 0,
        )
        self._jited_addresses = [info.jited_address or 0 for info in self._by_jited]

    def for_instruction(self, offset: int) -> BpfSourceLine | None:
        info = self._nearest_by_insn(offset // BPF_INSN_SIZE)
        if info is None:
            return None
        return _source_line_from_info(info)

    def for_jited_ip(self, ip: int) -> BpfLineInfo | None:
        if not self._by_jited:
            return None
        index = bisect.bisect_right(self._jited_addresses, ip) - 1
        if index < 0:
            return None
        return self._by_jited[index]

    def _nearest_by_insn(self, offset: int) -> BpfLineInfo | None:
        if not self._by_insn:
            return None
        index = bisect.bisect_right(self._insn_offsets, offset) - 1
        if index < 0:
            return None
        return self._by_insn[index]


class JitRangeResolver:
    def __init__(self, ranges: list[BpfJitRange]) -> None:
        self._ranges = sorted(
            [jit_range for jit_range in ranges if jit_range.length > 0],
            key=lambda jit_range: jit_range.start,
        )
        self._starts = [jit_range.start for jit_range in self._ranges]

    def resolve(self, ip: int) -> BpfJitRange | None:
        if not self._ranges:
            return None
        index = bisect.bisect_right(self._starts, ip) - 1
        if index < 0:
            return None
        jit_range = self._ranges[index]
        if jit_range.start <= ip < jit_range.end:
            return jit_range
        return None


def parse_bpf_instructions(
    raw_instructions: bytes, line_info: list[BpfLineInfo]
) -> list[BpfInstruction]:
    mapper = SourceLineMapper(line_info)
    instructions: list[BpfInstruction] = []
    for offset in range(0, len(raw_instructions) - (len(raw_instructions) % BPF_INSN_SIZE), 8):
        raw = raw_instructions[offset : offset + BPF_INSN_SIZE]
        opcode, regs, off, imm = struct.unpack("<BBhi", raw)
        instructions.append(
            BpfInstruction(
                offset=offset,
                raw=raw.hex(),
                opcode=opcode,
                dst_reg=regs & 0x0F,
                src_reg=(regs >> 4) & 0x0F,
                off=off,
                imm=imm,
                source=mapper.for_instruction(offset),
            )
        )
    return instructions


def parse_line_info_records(
    data: bytes,
    *,
    count: int,
    record_size: int,
    strings: BtfStringTable,
) -> list[BpfLineInfo]:
    if count <= 0 or record_size < BPF_LINE_INFO_SIZE:
        return []

    records: list[BpfLineInfo] = []
    available = min(count, len(data) // record_size)
    for index in range(available):
        base = index * record_size
        insn_offset, file_name_off, line_off, line_col = struct.unpack_from("<IIII", data, base)
        line_number, column = _decode_line_col(line_col)
        records.append(
            BpfLineInfo(
                insn_offset=insn_offset,
                file_name=strings.get(file_name_off),
                line_number=line_number,
                column=column,
                source=strings.get(line_off),
            )
        )
    return records


def parse_jited_line_addresses(data: bytes, *, count: int, record_size: int) -> list[int]:
    if count <= 0:
        return []
    resolved_size = record_size or 8
    if resolved_size < 8:
        return []

    addresses: list[int] = []
    available = min(count, len(data) // resolved_size)
    for index in range(available):
        addresses.append(struct.unpack_from("<Q", data, index * resolved_size)[0])
    return addresses


def attach_jited_addresses(
    line_info: list[BpfLineInfo],
    jited_addresses: list[int],
) -> list[BpfLineInfo]:
    for info, address in zip(line_info, jited_addresses, strict=False):
        info.jited_address = address or None
    return line_info


def _decode_line_col(line_col: int) -> tuple[int | None, int | None]:
    line_number = line_col >> 10
    column = line_col & 0x3FF
    return (line_number or None, column or None)


def _source_line_from_info(info: BpfLineInfo) -> BpfSourceLine:
    return BpfSourceLine(
        file_name=info.file_name,
        line_number=info.line_number,
        column=info.column,
        source=info.source,
    )
