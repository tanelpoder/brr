from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePath

from brr.inspection import BrrInspectRow, with_inspect_marker
from brr.models import BpfInstruction, BpfProgramDump


@dataclass(frozen=True, slots=True)
class SourceContextLine:
    file_name: str
    line_number: int
    source: str
    mapped: bool
    resolved_path: str | None = None


@dataclass(frozen=True, slots=True)
class SourceContextReport:
    enabled: bool
    devdir: str
    rows: list[SourceContextLine]
    unresolved_files: list[str] = field(default_factory=list)
    ambiguous_files: list[str] = field(default_factory=list)
    source_mismatches: list[SourceContextMismatch] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class SourceContextMismatch:
    file_name: str
    line_number: int
    btf_source: str
    file_source: str
    resolved_path: str


@dataclass(frozen=True, slots=True)
class _MappedSourceLine:
    file_name: str
    line_number: int
    source: str | None


@dataclass(frozen=True, slots=True)
class _ResolvedSourceFile:
    status: str
    path: Path | None


class SourceContextEnricher:
    def __init__(self, devdir: str | Path) -> None:
        self.devdir = Path(devdir)
        self._resolution_cache: dict[str, _ResolvedSourceFile] = {}
        self._line_cache: dict[Path, list[str]] = {}

    def report_for_dump(self, dump: BpfProgramDump) -> SourceContextReport:
        return self.report_for_mapped_lines(_mapped_lines_from_instructions(dump.instructions))

    def enrich_inspect_rows(self, rows: list[BrrInspectRow]) -> list[BrrInspectRow]:
        enriched: list[BrrInspectRow] = []
        mapped_positions = _mapped_positions_from_inspect_rows(rows)
        context_positions: set[tuple[str, int]] = set()
        previous_source: BrrInspectRow | None = None
        resume_line_after_backward: int | None = None
        terminal_tail_allowed = False

        def append_context(row: BrrInspectRow) -> None:
            key = _source_position_key(row.file_name, row.line_number)
            if key is None:
                enriched.append(row)
                return
            if key in mapped_positions or key in context_positions:
                return
            context_positions.add(key)
            enriched.append(row)

        for row in rows:
            row = self._inspect_source_row(row)
            if row.kind == "source" and row.file_name and row.line_number is not None:
                if previous_source is not None:
                    previous_line = _line_from_inspect_row(previous_source)
                    current_line = _line_from_inspect_row(row)
                    if _is_backward_jump(previous_line, current_line):
                        resume_line_after_backward = max(
                            resume_line_after_backward or previous_line.line_number,
                            previous_line.line_number,
                        )
                        terminal_tail_allowed = False
                    elif resume_line_after_backward is not None:
                        if (
                            previous_line.file_name != current_line.file_name
                            or current_line.line_number >= resume_line_after_backward
                        ):
                            resume_line_after_backward = None
                        terminal_tail_allowed = False
                    else:
                        for context_row in self._inspect_context_rows(previous_line, current_line):
                            append_context(context_row)
                        terminal_tail_allowed = previous_line.file_name == current_line.file_name
                else:
                    terminal_tail_allowed = True
                previous_source = row
            enriched.append(row)
        if previous_source is not None and terminal_tail_allowed:
            for context_row in self._inspect_tail_rows(_line_from_inspect_row(previous_source)):
                append_context(context_row)
        return enriched

    def has_resolved_inspect_source(self, rows: list[BrrInspectRow]) -> bool:
        for row in rows:
            if row.kind != "source" or not row.file_name or row.line_number is None:
                continue
            if self._resolve(row.file_name).path is not None:
                return True
        return False

    def report_for_mapped_lines(
        self,
        mapped_lines: list[_MappedSourceLine],
    ) -> SourceContextReport:
        rows: list[SourceContextLine] = []
        unresolved_files: set[str] = set()
        ambiguous_files: set[str] = set()
        source_mismatches: list[SourceContextMismatch] = []
        previous: _MappedSourceLine | None = None
        mapped_positions = _mapped_positions_from_mapped_lines(mapped_lines)
        context_positions: set[tuple[str, int]] = set()
        resume_line_after_backward: int | None = None
        terminal_tail_allowed = False

        def append_context(row: SourceContextLine) -> None:
            key = _source_position_key(row.file_name, row.line_number)
            if key is None:
                rows.append(row)
                return
            if key in mapped_positions or key in context_positions:
                return
            context_positions.add(key)
            rows.append(row)

        for line in mapped_lines:
            if previous is not None:
                if _is_backward_jump(previous, line):
                    context_rows, unresolved, ambiguous = [], set(), set()
                    resume_line_after_backward = max(
                        resume_line_after_backward or previous.line_number,
                        previous.line_number,
                    )
                    terminal_tail_allowed = False
                elif resume_line_after_backward is not None:
                    context_rows, unresolved, ambiguous = [], set(), set()
                    if (
                        previous.file_name != line.file_name
                        or line.line_number >= resume_line_after_backward
                    ):
                        resume_line_after_backward = None
                    terminal_tail_allowed = False
                else:
                    context_rows, unresolved, ambiguous = self._context_lines(previous, line)
                    terminal_tail_allowed = previous.file_name == line.file_name
                for context_row in context_rows:
                    append_context(context_row)
                unresolved_files.update(unresolved)
                ambiguous_files.update(ambiguous)
            else:
                terminal_tail_allowed = True
            resolved = self._resolve(line.file_name)
            if resolved.status == "unresolved":
                unresolved_files.add(line.file_name)
            elif resolved.status == "ambiguous":
                ambiguous_files.add(line.file_name)
            if resolved.path is not None:
                mismatch = self._source_mismatch(line, resolved.path)
                if mismatch is not None:
                    source_mismatches.append(mismatch)
            rows.append(
                SourceContextLine(
                    file_name=line.file_name,
                    line_number=line.line_number,
                    source=line.source or "",
                    mapped=True,
                    resolved_path=str(resolved.path) if resolved.path is not None else None,
                )
            )
            previous = line
        if previous is not None and terminal_tail_allowed:
            context_rows, unresolved, ambiguous = self._tail_context_lines(previous)
            for context_row in context_rows:
                append_context(context_row)
            unresolved_files.update(unresolved)
            ambiguous_files.update(ambiguous)
        return SourceContextReport(
            enabled=True,
            devdir=str(self.devdir),
            rows=rows,
            unresolved_files=sorted(unresolved_files),
            ambiguous_files=sorted(ambiguous_files),
            source_mismatches=source_mismatches,
        )

    def _inspect_context_rows(
        self,
        previous: _MappedSourceLine,
        current: _MappedSourceLine,
    ) -> list[BrrInspectRow]:
        context_rows, _unresolved, _ambiguous = self._context_lines(previous, current)
        return [
            BrrInspectRow(
                kind="context",
                code=_format_context_line(row),
                file_name=row.file_name,
                line_number=row.line_number,
            )
            for row in context_rows
        ]

    def _inspect_source_row(self, row: BrrInspectRow) -> BrrInspectRow:
        if row.kind != "source" or not row.file_name or row.line_number is None:
            return row
        resolved = self._resolve(row.file_name)
        if resolved.path is None:
            return row
        mismatch = self._source_mismatch(_line_from_inspect_row(row), resolved.path)
        if mismatch is None:
            return row
        return with_inspect_marker(row, "source-mismatch")

    def _inspect_tail_rows(self, previous: _MappedSourceLine) -> list[BrrInspectRow]:
        context_rows, _unresolved, _ambiguous = self._tail_context_lines(previous)
        return [
            BrrInspectRow(
                kind="context",
                code=_format_context_line(row),
                file_name=row.file_name,
                line_number=row.line_number,
            )
            for row in context_rows
        ]

    def _context_lines(
        self,
        previous: _MappedSourceLine,
        current: _MappedSourceLine,
    ) -> tuple[list[SourceContextLine], set[str], set[str]]:
        unresolved: set[str] = set()
        ambiguous: set[str] = set()
        if previous.file_name != current.file_name:
            return [], unresolved, ambiguous
        if current.line_number <= previous.line_number + 1:
            return [], unresolved, ambiguous

        resolved = self._resolve(previous.file_name)
        if resolved.status == "unresolved":
            unresolved.add(previous.file_name)
            return [], unresolved, ambiguous
        if resolved.status == "ambiguous":
            ambiguous.add(previous.file_name)
            return [], unresolved, ambiguous
        if resolved.path is None:
            return [], unresolved, ambiguous

        lines = self._read_lines(resolved.path)
        context_rows: list[SourceContextLine] = []
        for line_number in range(previous.line_number + 1, current.line_number):
            if line_number > len(lines):
                continue
            context_rows.append(
                SourceContextLine(
                    file_name=previous.file_name,
                    line_number=line_number,
                    source=lines[line_number - 1],
                    mapped=False,
                    resolved_path=str(resolved.path),
                )
            )
        return context_rows, unresolved, ambiguous

    def _tail_context_lines(
        self,
        previous: _MappedSourceLine,
    ) -> tuple[list[SourceContextLine], set[str], set[str]]:
        unresolved: set[str] = set()
        ambiguous: set[str] = set()
        resolved = self._resolve(previous.file_name)
        if resolved.status == "unresolved":
            unresolved.add(previous.file_name)
            return [], unresolved, ambiguous
        if resolved.status == "ambiguous":
            ambiguous.add(previous.file_name)
            return [], unresolved, ambiguous
        if resolved.path is None:
            return [], unresolved, ambiguous

        lines = self._read_lines(resolved.path)
        context_rows: list[SourceContextLine] = []
        for line_number in range(
            previous.line_number + 1,
            min(len(lines), previous.line_number + 20) + 1,
        ):
            source = lines[line_number - 1]
            context_rows.append(
                SourceContextLine(
                    file_name=previous.file_name,
                    line_number=line_number,
                    source=source,
                    mapped=False,
                    resolved_path=str(resolved.path),
                )
            )
            if source.strip() == "}":
                return context_rows, unresolved, ambiguous
        return [], unresolved, ambiguous

    def _resolve(self, file_name: str) -> _ResolvedSourceFile:
        cached = self._resolution_cache.get(file_name)
        if cached is not None:
            return cached

        exact = Path(file_name)
        if exact.exists() and exact.is_file():
            resolved = _ResolvedSourceFile("resolved", exact)
            self._resolution_cache[file_name] = resolved
            return resolved

        suffix_parts = _suffix_parts(file_name)
        if not suffix_parts:
            resolved = _ResolvedSourceFile("unresolved", None)
            self._resolution_cache[file_name] = resolved
            return resolved

        basename = suffix_parts[-1]
        candidates = [
            candidate
            for candidate in self.devdir.rglob(basename)
            if candidate.is_file() and _path_has_suffix(candidate, self.devdir, suffix_parts)
        ]
        if len(candidates) == 1:
            resolved = _ResolvedSourceFile("resolved", candidates[0])
        elif len(candidates) > 1:
            resolved = _ResolvedSourceFile("ambiguous", None)
        else:
            resolved = _ResolvedSourceFile("unresolved", None)
        self._resolution_cache[file_name] = resolved
        return resolved

    def _read_lines(self, path: Path) -> list[str]:
        cached = self._line_cache.get(path)
        if cached is not None:
            return cached
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        self._line_cache[path] = lines
        return lines

    def _source_mismatch(
        self,
        line: _MappedSourceLine,
        resolved_path: Path,
    ) -> SourceContextMismatch | None:
        if line.source is None:
            return None
        lines = self._read_lines(resolved_path)
        if line.line_number < 1 or line.line_number > len(lines):
            return None
        file_source = lines[line.line_number - 1]
        if line.source.rstrip() == file_source.rstrip():
            return None
        return SourceContextMismatch(
            file_name=line.file_name,
            line_number=line.line_number,
            btf_source=line.source,
            file_source=file_source,
            resolved_path=str(resolved_path),
        )


def _mapped_lines_from_instructions(instructions: list[BpfInstruction]) -> list[_MappedSourceLine]:
    lines: list[_MappedSourceLine] = []
    previous_key: tuple[str, int, str | None] | None = None
    for instruction in instructions:
        source = instruction.source
        if source is None or not source.file_name or source.line_number is None:
            continue
        key = (source.file_name, source.line_number, source.source)
        if key == previous_key:
            continue
        lines.append(
            _MappedSourceLine(
                file_name=source.file_name,
                line_number=source.line_number,
                source=source.source,
            )
        )
        previous_key = key
    return lines


def _mapped_positions_from_inspect_rows(rows: list[BrrInspectRow]) -> set[tuple[str, int]]:
    return {
        (row.file_name, row.line_number)
        for row in rows
        if row.kind == "source" and row.file_name and row.line_number is not None
    }


def _mapped_positions_from_mapped_lines(
    mapped_lines: list[_MappedSourceLine],
) -> set[tuple[str, int]]:
    return {(line.file_name, line.line_number) for line in mapped_lines}


def _line_from_inspect_row(row: BrrInspectRow) -> _MappedSourceLine:
    return _MappedSourceLine(
        file_name=row.file_name or "",
        line_number=row.line_number or 0,
        source=_row_source(row),
    )


def _source_position_key(file_name: str | None, line_number: int | None) -> tuple[str, int] | None:
    if not file_name or line_number is None:
        return None
    return (file_name, line_number)


def _is_backward_jump(previous: _MappedSourceLine, current: _MappedSourceLine) -> bool:
    return previous.file_name == current.file_name and current.line_number < previous.line_number


def _row_source(row: BrrInspectRow) -> str | None:
    return row.code.rsplit(": ", 1)[-1] if ": " in row.code else row.code


def _format_context_line(row: SourceContextLine) -> str:
    location = f"{PurePath(row.file_name).name}:{row.line_number}"
    return f"{location}: {row.source or '-'}"


def _suffix_parts(file_name: str) -> tuple[str, ...]:
    return tuple(part for part in PurePath(file_name).parts if part not in {"", "/"})


def _path_has_suffix(path: Path, devdir: Path, suffix_parts: tuple[str, ...]) -> bool:
    try:
        path_parts = path.relative_to(devdir).parts
    except ValueError:
        path_parts = path.parts
    if len(suffix_parts) >= len(path_parts) and suffix_parts[-len(path_parts) :] == path_parts:
        return True
    return len(path_parts) >= len(suffix_parts) and path_parts[-len(suffix_parts) :] == suffix_parts
