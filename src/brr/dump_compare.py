from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from brr.collector.service import BpfSnapshotService
from brr.errors import BrrError
from brr.models import BpfInstruction, BpfProgramDump, BpfSourceLine

BPFT_TOOL_TIMEOUT_SECONDS = 5
LDDW_OPCODE = 0x18
NORMALIZATION_NOTE = "brr lddw second slots are omitted before comparing bpftool rows"


@dataclass(frozen=True, slots=True)
class BpftoolDumpRow:
    index: int
    file_name: str | None = None
    line_number: int | None = None
    column: int | None = None
    source: str | None = None

    @property
    def has_source(self) -> bool:
        return any(
            value is not None
            for value in (self.file_name, self.line_number, self.column, self.source)
        )


@dataclass(frozen=True, slots=True)
class BrrVisibleInstruction:
    index: int
    source: BpfSourceLine | None


@dataclass(frozen=True, slots=True)
class DumpOffsetMismatch:
    position: int
    expected_index: int | None
    actual_index: int | None


@dataclass(frozen=True, slots=True)
class DumpSourceMismatch:
    index: int
    field: str
    expected: str | int | None
    actual: str | int | None


@dataclass(frozen=True, slots=True)
class DumpCompareResult:
    program_id: int
    passed: bool
    brr_instruction_slots: int
    brr_visible_slots: int
    bpftool_instruction_count: int
    lddw_slots: int
    source_rows_compared: int
    offset_mismatches: list[DumpOffsetMismatch]
    source_mismatches: list[DumpSourceMismatch]


BpftoolDumpProvider = Callable[[int], list[BpftoolDumpRow]]


def collect_dump_compare(
    service: BpfSnapshotService,
    program_id: int,
    *,
    bpftool_provider: BpftoolDumpProvider | None = None,
) -> DumpCompareResult:
    dump = service.collect_program_dump(program_id)
    bpftool_rows = (
        bpftool_provider(program_id)
        if bpftool_provider is not None
        else collect_bpftool_dump_rows(program_id)
    )
    return compare_dump_to_bpftool(dump, bpftool_rows)


def compare_dump_to_bpftool(
    dump: BpfProgramDump,
    bpftool_rows: Sequence[BpftoolDumpRow],
) -> DumpCompareResult:
    visible, lddw_slots = _visible_brr_instructions(dump.instructions)
    offset_mismatches = _compare_indexes(visible, bpftool_rows)
    source_mismatches, source_rows_compared = _compare_source_metadata(visible, bpftool_rows)
    return DumpCompareResult(
        program_id=dump.program.id,
        passed=not offset_mismatches and not source_mismatches,
        brr_instruction_slots=len(dump.instructions),
        brr_visible_slots=len(visible),
        bpftool_instruction_count=len(bpftool_rows),
        lddw_slots=lddw_slots,
        source_rows_compared=source_rows_compared,
        offset_mismatches=offset_mismatches,
        source_mismatches=source_mismatches,
    )


def collect_bpftool_dump_rows(program_id: int) -> list[BpftoolDumpRow]:
    json_payload = _run_bpftool_json(program_id)
    indexes = _run_bpftool_text_indexes(program_id)
    source_rows = _parse_bpftool_source_rows(json_payload)
    if len(indexes) != len(source_rows):
        raise BrrError(
            "bpftool dump returned inconsistent text and JSON instruction counts "
            f"({len(indexes)} text, {len(source_rows)} JSON)"
        )
    return [
        BpftoolDumpRow(
            index=index,
            file_name=row.file_name,
            line_number=row.line_number,
            column=row.column,
            source=row.source,
        )
        for index, row in zip(indexes, source_rows, strict=True)
    ]


def _visible_brr_instructions(
    instructions: Sequence[BpfInstruction],
) -> tuple[list[BrrVisibleInstruction], int]:
    visible: list[BrrVisibleInstruction] = []
    skip_next = False
    lddw_slots = 0
    for instruction in instructions:
        if skip_next:
            lddw_slots += 1
            skip_next = False
            continue
        visible.append(
            BrrVisibleInstruction(
                index=instruction.offset // 8,
                source=instruction.source,
            )
        )
        if instruction.opcode == LDDW_OPCODE:
            skip_next = True
    return visible, lddw_slots


def _compare_indexes(
    brr_rows: Sequence[BrrVisibleInstruction],
    bpftool_rows: Sequence[BpftoolDumpRow],
) -> list[DumpOffsetMismatch]:
    mismatches: list[DumpOffsetMismatch] = []
    max_len = max(len(brr_rows), len(bpftool_rows))
    for position in range(max_len):
        expected = bpftool_rows[position].index if position < len(bpftool_rows) else None
        actual = brr_rows[position].index if position < len(brr_rows) else None
        if expected != actual:
            mismatches.append(
                DumpOffsetMismatch(
                    position=position,
                    expected_index=expected,
                    actual_index=actual,
                )
            )
    return mismatches


def _compare_source_metadata(
    brr_rows: Sequence[BrrVisibleInstruction],
    bpftool_rows: Sequence[BpftoolDumpRow],
) -> tuple[list[DumpSourceMismatch], int]:
    mismatches: list[DumpSourceMismatch] = []
    compared = 0
    for position, bpftool_row in enumerate(bpftool_rows):
        if not bpftool_row.has_source or position >= len(brr_rows):
            continue
        compared += 1
        brr_source = brr_rows[position].source
        actual_values: dict[str, str | int | None] = {
            "file": brr_source.file_name if brr_source is not None else None,
            "line": brr_source.line_number if brr_source is not None else None,
            "column": brr_source.column if brr_source is not None else None,
            "source": brr_source.source if brr_source is not None else None,
        }
        expected_values: dict[str, str | int | None] = {
            "file": bpftool_row.file_name,
            "line": bpftool_row.line_number,
            "column": bpftool_row.column,
            "source": bpftool_row.source,
        }
        for field, expected in expected_values.items():
            if expected is None:
                continue
            actual = actual_values[field]
            if expected != actual:
                mismatches.append(
                    DumpSourceMismatch(
                        index=bpftool_row.index,
                        field=field,
                        expected=expected,
                        actual=actual,
                    )
                )
    return mismatches, compared


def _run_bpftool_json(program_id: int) -> list[Any]:
    completed = _run_bpftool(
        ["bpftool", "-j", "prog", "dump", "xlated", "id", str(program_id), "linum"]
    )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BrrError(f"bpftool returned invalid JSON: {exc.msg}") from exc
    if not isinstance(payload, list):
        raise BrrError("bpftool JSON dump did not return an instruction list")
    return payload


def _run_bpftool_text_indexes(program_id: int) -> list[int]:
    completed = _run_bpftool(["bpftool", "prog", "dump", "xlated", "id", str(program_id), "linum"])
    indexes = _parse_bpftool_text_indexes(completed.stdout)
    if not indexes:
        raise BrrError("bpftool text dump did not include instruction indexes")
    return indexes


def _run_bpftool(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=BPFT_TOOL_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise BrrError("bpftool not found in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise BrrError("bpftool dump timed out") from exc
    except OSError as exc:
        raise BrrError(f"failed to run bpftool: {exc}") from exc
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "bpftool dump failed"
        raise BrrError(message)
    return completed


def _parse_bpftool_source_rows(payload: Sequence[Any]) -> list[BpftoolDumpRow]:
    rows: list[BpftoolDumpRow] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        rows.append(
            BpftoolDumpRow(
                index=0,
                file_name=_optional_str(item.get("file")),
                line_number=_optional_int(item.get("line_num")),
                column=_optional_int(item.get("line_col")),
                source=_optional_str(item.get("src")),
            )
        )
    return rows


_INSTRUCTION_INDEX_RE = re.compile(r"^\s*(\d+):\s")


def _parse_bpftool_text_indexes(output: str) -> list[int]:
    indexes: list[int] = []
    for line in output.splitlines():
        match = _INSTRUCTION_INDEX_RE.match(line)
        if match is None:
            continue
        indexes.append(int(match.group(1)))
    return indexes


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None
