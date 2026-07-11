from __future__ import annotations

import argparse
import os
from collections.abc import MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from rich.text import Text

from brr.collector.service import BpfSnapshotService
from brr.errors import BrrError
from brr.inspection import (
    MARKER_DESCRIPTIONS,
    BrrInspectReport,
    BrrInspectRow,
    InspectMode,
    build_inspect_report,
    collect_bpftool_xlated,
    collect_inspect_report,
    limit_inspect_report_source_rows,
    profile_status_message,
)
from brr.models import BpfHotspot, BpfKernelHotspot, BpfProfile, BpfProfileProgram, BpfProgramDump
from brr.profiler import (
    CALL_GRAPH_MODES,
    CallGraphMode,
    supported_perf_event_names,
    validate_perf_event_name,
)
from brr.render.brr_text import render_brr_activity, render_brr_inspect
from brr.reporter import BrrActivityItem, BrrActivityReport, collect_activity_report
from brr.source_context import SourceContextEnricher

FOLD_CONTEXT_LINES = 2
TOP_ACTIVITY_COLUMNS = (
    ("ID", True),
    ("TYPE", False),
    ("NAME", False),
    ("CPU%", True),
    ("EXECS/s", True),
    ("AVG_NS", True),
    ("CUMUL_AVG_NS", True),
    ("NS_PER/s", True),
    ("EXECS_DELTA", True),
    ("TOTAL_NS", True),
    ("EXECS_TOTAL", True),
    ("CUMUL_NS", True),
    ("XLAT_B", True),
    ("JIT_B", True),
    ("TAG", False),
    ("PINNED", False),
)
CUMULATIVE_TOP_COLUMNS = {
    "CUMUL_AVG_NS",
    "NS_PER/s",
    "EXECS_DELTA",
    "TOTAL_NS",
    "EXECS_TOTAL",
    "CUMUL_NS",
}
EXTENDED_TOP_COLUMNS = {"TAG", "PINNED"}
TEXTUAL_DARK_THEME = "textual-dark"
TEXTUAL_LIGHT_THEME = "textual-light"
KNOWN_256_COLOR_TERMS = {"ghostty", "xterm-ghostty"}
TOP_ARGUMENT_DEFAULTS = {
    "delay": 1.0,
    "limit": 20,
    "include_all": False,
    "event": "auto",
    "profile_duration": 5.0,
    "frequency": 997,
    "line_limit": None,
    "source_limit": 0,
    "textmode": False,
    "profile_top": False,
    "collapse_samples": False,
    "kernel_samples": False,
    "kernel_ip_detail": False,
    "call_graph": "fp",
    "program_id": None,
    "inspect_mode": "source",
    "light": False,
    "devmode": None,
    "perf_buffer_pages": None,
    "perf_drain_ms": None,
    "fail_on_loss": False,
}
PROFILE_OPTION_INPUT_ORDER = (
    "profile-duration",
    "profile-frequency",
    "profile-event",
    "profile-call-graph",
    "profile-buffer-pages",
    "profile-drain-ms",
)
PROFILE_OPTION_INPUT_IDS = frozenset(PROFILE_OPTION_INPUT_ORDER)
PROFILE_OPTION_WIDGET_ORDER = (*PROFILE_OPTION_INPUT_ORDER, "profile-kernel-samples")
PROFILE_OPTION_WIDGET_IDS = frozenset(PROFILE_OPTION_WIDGET_ORDER)
INSPECT_HELP_ROWS = (
    ("Up/Down, PgUp/PgDn, Home/End", "Navigate rows"),
    ("Space", "Switch source/mixed view"),
    ("/", "Search source"),
    ("p / P", "Profile with defaults / choose options"),
    ("i", "Toggle kernel function/IP detail"),
    ("m / M", "Toggle source markers / marker legend"),
    ("e / c", "Expand / collapse selected branch"),
    ("E / C", "Expand / collapse all branches"),
    ("h / Esc", "Close this help"),
)
InputSubmissionTarget = Literal["delay", "profile", "search", "none"]


def _selected_activity_id(activity_ids: list[int], cursor_row: int) -> int | None:
    if cursor_row < 0 or cursor_row >= len(activity_ids):
        return None
    return activity_ids[cursor_row]


def _preserved_activity_row(
    row_count: int,
    previous_row: int,
) -> int | None:
    if row_count <= 0:
        return None
    return min(max(previous_row, 0), row_count - 1)


def _hottest_inspect_row(report: BrrInspectReport) -> int | None:
    hottest_samples = 0
    hottest_index: int | None = None
    for index, row in enumerate(report.rows):
        if row.kind != "source":
            continue
        samples = row.samples
        if row.child_key is not None:
            samples += sum(
                child.samples
                for child in report.rows
                if child.kind == "kernel" and child.child_key == row.child_key
            )
        if samples > hottest_samples:
            hottest_samples = samples
            hottest_index = index
    return hottest_index


def _input_submission_target(
    input_id: str | None,
    *,
    delay_options_open: bool,
    profile_options_open: bool,
    inspect_search_open: bool,
) -> InputSubmissionTarget:
    if input_id == "delay-options" and delay_options_open:
        return "delay"
    if input_id in PROFILE_OPTION_INPUT_IDS and profile_options_open:
        return "profile"
    if input_id == "inspect-search" and inspect_search_open:
        return "search"
    return "none"


@dataclass(frozen=True, slots=True)
class InspectFoldRange:
    id: int
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class VisibleInspectRows:
    rows: list[BrrInspectRow]
    full_indexes: list[int | None]
    fold_ids: list[int | None]


@dataclass(frozen=True, slots=True)
class InspectCursorAnchor:
    file_name: str | None
    line_number: int | None
    source: str | None
    offset: int | None
    kernel_function_key: str | None = None


@dataclass(frozen=True, slots=True)
class InspectViewportState:
    scroll_x: float
    scroll_y: float
    cursor_viewport_y: float


def _fold_ranges_for_rows(
    rows: list[BrrInspectRow],
    *,
    viewport_rows: int,
    context_lines: int = FOLD_CONTEXT_LINES,
) -> list[InspectFoldRange]:
    if viewport_rows <= 0 or len(rows) <= viewport_rows:
        return []
    hot_indexes = [
        index
        for index, row in enumerate(rows)
        if row.kind in {"source", "kernel", "summary", "unaccounted"} and row.samples
    ]
    if not hot_indexes:
        return []

    visible_indexes: set[int] = set()
    for index in hot_indexes:
        visible_indexes.update(
            range(max(0, index - context_lines), min(len(rows), index + context_lines + 1))
        )

    ranges: list[InspectFoldRange] = []
    range_start: int | None = None
    for index in range(len(rows)):
        if index in visible_indexes:
            if range_start is not None:
                ranges.append(InspectFoldRange(len(ranges), range_start, index))
                range_start = None
            continue
        if range_start is None:
            range_start = index
    if range_start is not None:
        ranges.append(InspectFoldRange(len(ranges), range_start, len(rows)))
    return ranges


def _visible_rows_for_folds(
    rows: list[BrrInspectRow],
    ranges: list[InspectFoldRange],
    expanded_fold_ids: set[int],
) -> VisibleInspectRows:
    ranges_by_start = {fold_range.start: fold_range for fold_range in ranges}
    folded_indexes = {
        index
        for fold_range in ranges
        if fold_range.id not in expanded_fold_ids
        for index in range(fold_range.start, fold_range.end)
    }
    visible_rows: list[BrrInspectRow] = []
    full_indexes: list[int | None] = []
    fold_ids: list[int | None] = []
    index = 0
    while index < len(rows):
        fold_range = ranges_by_start.get(index)
        if fold_range is not None and fold_range.id not in expanded_fold_ids:
            visible_rows.append(BrrInspectRow(kind="fold", code="..."))
            full_indexes.append(None)
            fold_ids.append(fold_range.id)
            index = fold_range.end
            continue
        if index not in folded_indexes:
            visible_rows.append(rows[index])
            full_indexes.append(index)
            fold_ids.append(None)
        index += 1
    return VisibleInspectRows(rows=visible_rows, full_indexes=full_indexes, fold_ids=fold_ids)


def _inspect_cursor_anchor(
    visible_rows: VisibleInspectRows,
    visible_row: int,
) -> InspectCursorAnchor | None:
    if visible_row < 0 or visible_row >= len(visible_rows.rows):
        return None
    row = visible_rows.rows[visible_row]
    if row.kind not in {"source", "instruction", "kernel"}:
        return None
    if (
        row.file_name is None
        and row.line_number is None
        and row.offset is None
        and row.kernel_function_key is None
    ):
        return None
    return InspectCursorAnchor(
        file_name=row.file_name,
        line_number=row.line_number,
        source=_anchor_source(row),
        offset=row.offset,
        kernel_function_key=row.kernel_function_key,
    )


def _inspect_viewport_state(table) -> InspectViewportState:
    return InspectViewportState(
        scroll_x=float(table.scroll_x),
        scroll_y=float(table.scroll_y),
        cursor_viewport_y=float(table.cursor_row) - float(table.scroll_y),
    )


def _visible_row_for_anchor(
    visible_rows: VisibleInspectRows,
    anchor: InspectCursorAnchor | None,
) -> int | None:
    if anchor is None:
        return None
    source_fallback: int | None = None
    file_line_fallback: int | None = None
    for index, row in enumerate(visible_rows.rows):
        if (
            anchor.kernel_function_key is not None
            and row.kind == "kernel"
            and row.kernel_function_key == anchor.kernel_function_key
        ):
            return index
        if row.kind != "source":
            continue
        if (
            row.file_name == anchor.file_name
            and row.line_number == anchor.line_number
            and _anchor_source(row) == anchor.source
            and row.offset == anchor.offset
        ):
            return index
        if (
            source_fallback is None
            and row.file_name == anchor.file_name
            and row.line_number == anchor.line_number
            and _anchor_source(row) == anchor.source
        ):
            source_fallback = index
        if (
            file_line_fallback is None
            and row.file_name == anchor.file_name
            and row.line_number == anchor.line_number
        ):
            file_line_fallback = index
    return source_fallback if source_fallback is not None else file_line_fallback


def _anchor_source(row: BrrInspectRow) -> str | None:
    if row.kind != "source":
        return None
    return row.code.rsplit(": ", 1)[-1] if ": " in row.code else row.code


def _fold_range_containing(
    ranges: list[InspectFoldRange],
    full_index: int,
) -> InspectFoldRange | None:
    for fold_range in ranges:
        if fold_range.start <= full_index < fold_range.end:
            return fold_range
    return None


def _top_cell(value: str, *, right: bool = False) -> Text | str:
    if right:
        return Text(value, justify="right")
    return value


def _format_int(value: int) -> str:
    return f"{value:,}"


def _format_rate(value: int, *, duration: float) -> str:
    if duration <= 0:
        return "0"
    return _format_int(round(value / duration))


def _visible_top_activity_columns(
    show_cumulative: bool,
    show_extended: bool,
) -> tuple[tuple[str, bool], ...]:
    hidden_columns = set()
    if not show_cumulative:
        hidden_columns.update(CUMULATIVE_TOP_COLUMNS)
    if not show_extended:
        hidden_columns.update(EXTENDED_TOP_COLUMNS)
    return tuple(column for column in TOP_ACTIVITY_COLUMNS if column[0] not in hidden_columns)


def _search_match_rows(rows: list[BrrInspectRow], query: str) -> list[int]:
    needle = query.casefold()
    if not needle:
        return []
    return [
        index
        for index, row in enumerate(rows)
        if row.kind != "fold" and needle in row.code.casefold()
    ]


def _inspect_code_cell(
    row: BrrInspectRow,
    *,
    show_markers: bool,
    search_query: str,
    child_expanded: bool | None = None,
) -> Text:
    code = row.code
    if row.has_children:
        expanded = row.children_expanded if child_expanded is None else child_expanded
        code = f"{'-' if expanded else '+'} {code}"
    text = Text(code)
    if show_markers and row.markers:
        text.append(" ")
        text.append(" ".join(f"[{marker}]" for marker in row.markers), style="dim")
    return _highlight_search_text(text, search_query)


def _highlight_search_text(text: Text | str, query: str) -> Text:
    rendered = text.copy() if isinstance(text, Text) else Text(text)
    if not query:
        return rendered
    lowered = rendered.plain.casefold()
    needle = query.casefold()
    if not needle or needle not in lowered:
        return rendered
    start = 0
    while True:
        match = lowered.find(needle, start)
        if match == -1:
            break
        end = match + len(needle)
        rendered.stylize("black on yellow", match, end)
        start = end
    return rendered


@dataclass(frozen=True, slots=True)
class BrrConfig:
    bpffs: str
    delay: float
    limit: int
    include_all: bool
    event: str
    profile_duration: float
    frequency: int
    line_limit: int
    source_limit: int
    inspect_mode: InspectMode
    theme: str
    devmode: bool = False
    devdir: str | None = None
    devmode_default_dir: bool = False
    kernel_samples: bool = False
    call_graph: CallGraphMode = "fp"
    extended: bool = False
    cumulative: bool = False
    perf_buffer_pages: int | None = None
    perf_drain_ms: int | None = None
    fail_on_loss: bool = False
    collapse_samples: bool = False
    kernel_ip_detail: bool = False


@dataclass(frozen=True, slots=True)
class BrrTextModeResult:
    text: str
    incomplete: bool = False


def _terminfo_colors(environ: MutableMapping[str, str]) -> int | None:
    try:
        import curses

        term = environ.get("TERM")
        if term:
            curses.setupterm(term=term)
        else:
            curses.setupterm()
        colors = curses.tigetnum("colors")
    except Exception:
        return None
    return colors if colors >= 0 else None


def _configure_textual_color_system(
    environ: MutableMapping[str, str] | None = None,
) -> None:
    env = os.environ if environ is None else environ
    if env.get("TEXTUAL_COLOR_SYSTEM") or "NO_COLOR" in env:
        return

    color_term = env.get("COLORTERM", "").strip().lower()
    if color_term in {"truecolor", "24bit"}:
        env["TEXTUAL_COLOR_SYSTEM"] = "truecolor"
        return

    colors = _terminfo_colors(env)
    if colors is not None and colors >= 256:
        env["TEXTUAL_COLOR_SYSTEM"] = "256"
        return

    term = env.get("TERM", "").strip().lower()
    if colors is None and term in KNOWN_256_COLOR_TERMS:
        env["TEXTUAL_COLOR_SYSTEM"] = "256"


def add_top_arguments(
    parser: argparse.ArgumentParser,
    *,
    dest_prefix: str = "",
    suppress_defaults: bool = False,
    include_common: bool = True,
) -> None:
    def dest(name: str) -> str:
        return f"{dest_prefix}{name}"

    def default(value: object) -> object:
        return argparse.SUPPRESS if suppress_defaults else value

    parser.add_argument(
        "-d",
        "--delay",
        dest=dest("delay"),
        type=_positive_float,
        default=default(TOP_ARGUMENT_DEFAULTS["delay"]),
        metavar="SECONDS",
        help="Run duration of refresh delay in seconds. Default: 1.",
    )
    parser.add_argument(
        "--limit",
        dest=dest("limit"),
        type=_non_negative_int,
        default=default(TOP_ARGUMENT_DEFAULTS["limit"]),
        metavar="N",
        help=(
            "Maximum rows to show in --textmode snapshots. "
            "Interactive top shows all programs. Use 0 for no limit. Default: 20."
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest=dest("include_all"),
        default=default(TOP_ARGUMENT_DEFAULTS["include_all"]),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--event",
        dest=dest("event"),
        type=_perf_event_name,
        default=default(TOP_ARGUMENT_DEFAULTS["event"]),
        metavar="EVENT",
        help="Perf event to sample for drill-down. Default: auto.",
    )
    parser.add_argument(
        "--profile-duration",
        dest=dest("profile_duration"),
        type=_positive_float,
        default=default(TOP_ARGUMENT_DEFAULTS["profile_duration"]),
        metavar="SECONDS",
        help="Seconds to profile a selected program. Default: 5.",
    )
    parser.add_argument(
        "-F",
        "--frequency",
        dest=dest("frequency"),
        type=_positive_int,
        default=default(TOP_ARGUMENT_DEFAULTS["frequency"]),
        metavar="HZ",
        help="Perf sample frequency in Hz for drill-down. Default: 997.",
    )
    parser.add_argument(
        "--line-limit",
        dest=dest("line_limit"),
        type=_non_negative_int,
        default=default(TOP_ARGUMENT_DEFAULTS["line_limit"]),
        metavar="N",
        help=(
            "Maximum detailed hotspot rows per selected program; omitted samples remain "
            "in direct/under 'Other' totals. Use 0 for no limit. Defaults: 10 in "
            "textmode, 0 in the interactive TUI."
        ),
    )
    parser.add_argument(
        "--source-limit",
        dest=dest("source_limit"),
        type=_non_negative_int,
        default=default(TOP_ARGUMENT_DEFAULTS["source_limit"]),
        metavar="N",
        help=(
            "Maximum detailed inspect rows in textmode output; omitted samples "
            "remain in direct/under 'Other' totals. Use 0 for no limit. Default: 0."
        ),
    )
    parser.add_argument(
        "--textmode",
        dest=dest("textmode"),
        action="store_true",
        default=default(TOP_ARGUMENT_DEFAULTS["textmode"]),
        help="Print one deterministic report snapshot and exit.",
    )
    parser.add_argument(
        "--profile-top",
        dest=dest("profile_top"),
        action="store_true",
        default=default(TOP_ARGUMENT_DEFAULTS["profile_top"]),
        help="In textmode, append a profile/source drill-down for the top activity row.",
    )
    parser.add_argument(
        "--collapse-samples",
        dest=dest("collapse_samples"),
        action="store_true",
        default=default(TOP_ARGUMENT_DEFAULTS["collapse_samples"]),
        help=(
            "In a profiled textmode drill-down, fold helper/kernel samples into "
            "their calling eBPF row."
        ),
    )
    if include_common:
        parser.add_argument(
            "-x",
            "--extended",
            dest=dest("extended"),
            action="store_true",
            default=default(False),
            help="Show extended TAG and PINNED columns.",
        )
        parser.add_argument(
            "-c",
            "--cumulative",
            dest=dest("cumulative"),
            action="store_true",
            default=default(False),
            help="Show cumulative runtime metric columns.",
        )
    parser.add_argument(
        "--kernel-samples",
        dest=dest("kernel_samples"),
        action="store_true",
        default=default(TOP_ARGUMENT_DEFAULTS["kernel_samples"]),
        help=(
            "In profile drill-downs, capture perf callchains and show attributed "
            "kernel/helper samples."
        ),
    )
    parser.add_argument(
        "--kernel-ip-detail",
        dest=dest("kernel_ip_detail"),
        action="store_true",
        default=default(TOP_ARGUMENT_DEFAULTS["kernel_ip_detail"]),
        help=(
            "Start human profile output with separate kernel/helper rows for exact "
            "sampled IPs instead of function groups."
        ),
    )
    parser.add_argument(
        "--call-graph",
        dest=dest("call_graph"),
        choices=CALL_GRAPH_MODES,
        default=default(TOP_ARGUMENT_DEFAULTS["call_graph"]),
        help="Perf call graph mode for --kernel-samples profile drill-downs. Default: fp.",
    )
    parser.add_argument(
        "--program-id",
        dest=dest("program_id"),
        type=_positive_int,
        default=default(TOP_ARGUMENT_DEFAULTS["program_id"]),
        metavar="PROG_ID",
        help="In textmode, append a profile/source drill-down for this program ID.",
    )
    parser.add_argument(
        "--inspect-mode",
        dest=dest("inspect_mode"),
        choices=("source", "mixed"),
        default=default(TOP_ARGUMENT_DEFAULTS["inspect_mode"]),
        help="In textmode, choose source-only or mixed source/instruction inspect output.",
    )
    parser.add_argument(
        "--light",
        dest=dest("light"),
        action="store_true",
        default=default(TOP_ARGUMENT_DEFAULTS["light"]),
        help="Start the interactive TUI with Textual's light theme.",
    )
    parser.add_argument(
        "--devmode",
        dest=dest("devmode"),
        nargs="?",
        const=True,
        default=default(TOP_ARGUMENT_DEFAULTS["devmode"]),
        metavar="DIR",
        help=(
            "Read matching source files from DIR to fill missing source lines. "
            "Defaults to the current directory."
        ),
    )
    parser.add_argument(
        "--perf-buffer-pages",
        dest=dest("perf_buffer_pages"),
        type=_auto_power_of_two,
        default=default(TOP_ARGUMENT_DEFAULTS["perf_buffer_pages"]),
        metavar="auto|PAGES",
        help="Per-CPU perf data pages as a power of two. Default: auto.",
    )
    parser.add_argument(
        "--perf-drain-ms",
        dest=dest("perf_drain_ms"),
        type=_auto_positive_int,
        default=default(TOP_ARGUMENT_DEFAULTS["perf_drain_ms"]),
        metavar="auto|MS",
        help="Maximum milliseconds between full perf ring sweeps. Default: auto.",
    )
    parser.add_argument(
        "--fail-on-loss",
        dest=dest("fail_on_loss"),
        action="store_true",
        default=default(TOP_ARGUMENT_DEFAULTS["fail_on_loss"]),
        help="In profiled textmode output, exit with status 1 if capture is incomplete.",
    )


def config_from_args(args: argparse.Namespace, *, bpffs: str) -> BrrConfig:
    devdir = _devmode_dir(args)
    line_limit = getattr(args, "line_limit", TOP_ARGUMENT_DEFAULTS["line_limit"])
    if line_limit is None:
        line_limit = 10 if getattr(args, "textmode", False) else 0
    return BrrConfig(
        bpffs=bpffs,
        delay=getattr(args, "delay", TOP_ARGUMENT_DEFAULTS["delay"]),
        limit=getattr(args, "limit", TOP_ARGUMENT_DEFAULTS["limit"]),
        include_all=True,
        event=getattr(args, "event", TOP_ARGUMENT_DEFAULTS["event"]),
        profile_duration=getattr(
            args, "profile_duration", TOP_ARGUMENT_DEFAULTS["profile_duration"]
        ),
        frequency=getattr(args, "frequency", TOP_ARGUMENT_DEFAULTS["frequency"]),
        line_limit=line_limit,
        source_limit=getattr(args, "source_limit", TOP_ARGUMENT_DEFAULTS["source_limit"]),
        inspect_mode=getattr(args, "inspect_mode", TOP_ARGUMENT_DEFAULTS["inspect_mode"]),
        theme=(
            TEXTUAL_LIGHT_THEME
            if getattr(args, "light", TOP_ARGUMENT_DEFAULTS["light"])
            else TEXTUAL_DARK_THEME
        ),
        devmode=devdir is not None,
        devdir=devdir,
        devmode_default_dir=getattr(args, "devmode", None) is True,
        kernel_samples=getattr(args, "kernel_samples", TOP_ARGUMENT_DEFAULTS["kernel_samples"]),
        call_graph=getattr(args, "call_graph", TOP_ARGUMENT_DEFAULTS["call_graph"]),
        extended=getattr(args, "extended", False),
        cumulative=getattr(args, "cumulative", False),
        perf_buffer_pages=getattr(
            args, "perf_buffer_pages", TOP_ARGUMENT_DEFAULTS["perf_buffer_pages"]
        ),
        perf_drain_ms=getattr(args, "perf_drain_ms", TOP_ARGUMENT_DEFAULTS["perf_drain_ms"]),
        fail_on_loss=getattr(args, "fail_on_loss", TOP_ARGUMENT_DEFAULTS["fail_on_loss"]),
        collapse_samples=getattr(
            args, "collapse_samples", TOP_ARGUMENT_DEFAULTS["collapse_samples"]
        ),
        kernel_ip_detail=getattr(
            args, "kernel_ip_detail", TOP_ARGUMENT_DEFAULTS["kernel_ip_detail"]
        ),
    )


def _devmode_dir(args: argparse.Namespace) -> str | None:
    devmode = getattr(args, "devmode", None)
    if devmode is None:
        return None
    if devmode is True:
        return str(Path.cwd())
    return devmode


def render_textmode(
    service: BpfSnapshotService,
    config: BrrConfig,
    *,
    profile_top: bool = False,
    program_id: int | None = None,
) -> str:
    return render_textmode_result(
        service,
        config,
        profile_top=profile_top,
        program_id=program_id,
    ).text


def render_textmode_result(
    service: BpfSnapshotService,
    config: BrrConfig,
    *,
    profile_top: bool = False,
    program_id: int | None = None,
) -> BrrTextModeResult:
    activity = collect_activity_report(
        service,
        duration=config.delay,
        include_all=True,
        limit=config.limit,
    )
    sections = [
        render_brr_activity(
            activity,
            cumulative=config.cumulative,
            extended=config.extended,
        )
    ]
    source_context_enricher = (
        SourceContextEnricher(config.devdir) if config.devmode and config.devdir else None
    )

    selected_program_id = program_id or _top_program_id(activity, profile_top=profile_top)
    incomplete = False
    if selected_program_id is not None:
        inspect = collect_inspect_report(
            service,
            selected_program_id,
            mode=config.inspect_mode,
            profile=profile_top,
            requested_event=config.event,
            duration=config.profile_duration,
            frequency=config.frequency,
            line_limit=config.line_limit,
            kernel_samples=config.kernel_samples,
            kernel_ip_detail=config.kernel_ip_detail,
            call_graph=config.call_graph,
            perf_buffer_pages=config.perf_buffer_pages,
            perf_drain_ms=config.perf_drain_ms,
        )
        inspect = _maybe_enrich_inspect_report(
            inspect,
            source_context_enricher,
            require_resolution=config.devmode_default_dir,
        )
        if config.source_limit > 0:
            inspect = limit_inspect_report_source_rows(inspect, config.source_limit)
        sections.append(
            render_brr_inspect(
                inspect,
                extended=config.extended,
                collapse_samples=config.collapse_samples,
            )
        )
        incomplete = bool(inspect.profile and inspect.profile.metadata.incomplete)
    elif profile_top:
        sections.append("BRR PROFILE program=-\nNo program selected for profiling.")

    return BrrTextModeResult(text="\n\n".join(sections), incomplete=incomplete)


def _maybe_enrich_inspect_report(
    report: BrrInspectReport,
    source_context_enricher: SourceContextEnricher | None,
    *,
    require_resolution: bool = False,
) -> BrrInspectReport:
    if source_context_enricher is None:
        return report
    if require_resolution and not source_context_enricher.has_resolved_inspect_source(report.rows):
        raise BrrError(
            "devmode did not resolve any source files from the current directory; "
            "pass --devmode DIR to point at the matching source tree"
        )
    return BrrInspectReport(
        program=report.program,
        mode=report.mode,
        rows=source_context_enricher.enrich_inspect_rows(report.rows),
        profile=report.profile,
        profile_program=report.profile_program,
        instruction_source=report.instruction_source,
        kernel_ip_detail=report.kernel_ip_detail,
        source_limit=report.source_limit,
        source_limit_omitted_direct_samples=report.source_limit_omitted_direct_samples,
        source_limit_omitted_under_bpf_samples=(report.source_limit_omitted_under_bpf_samples),
    )


def _create_top_app(service: BpfSnapshotService, config: BrrConfig):
    from threading import Lock

    _configure_textual_color_system()

    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.css.query import NoMatches
    from textual.widgets import Checkbox, DataTable, Footer, Header, HelpPanel, Input, Static
    from textual.worker import Worker, WorkerState

    @dataclass(frozen=True, slots=True)
    class ProfileOptions:
        duration: float
        frequency: int
        event: str
        kernel_samples: bool = False
        call_graph: CallGraphMode = "fp"
        perf_buffer_pages: int | None = None
        perf_drain_ms: int | None = None

    @dataclass(frozen=True, slots=True)
    class ActivityRefreshResult:
        token: int
        report: BrrActivityReport

    @dataclass(frozen=True, slots=True)
    class InspectLoadResult:
        token: int
        program_id: int
        dump: BpfProgramDump
        report: BrrInspectReport

    @dataclass(frozen=True, slots=True)
    class InspectRenderResult:
        token: int
        report: BrrInspectReport
        preserve_row: int
        preserve_anchor: InspectCursorAnchor | None
        viewport_state: InspectViewportState | None
        jump_to_hotspot: bool

    @dataclass(frozen=True, slots=True)
    class ProfileResult:
        token: int
        program_id: int
        options: ProfileOptions
        profile: BpfProfile
        profile_program: BpfProfileProgram | None
        hotspots: list[BpfHotspot]
        kernel_hotspots: list[BpfKernelHotspot]
        kernel_function_hotspots: list[BpfKernelHotspot]

    class BrrTop(App[None]):
        CSS = """
        Screen {
            layers: base overlay;
        }

        #status {
            display: none;
        }

        #activity {
            height: 1fr;
        }

        #inspect-modal {
            layer: overlay;
            width: 100%;
            height: 100%;
            offset: 0 0;
            border: heavy $accent;
            background: $panel;
            padding: 0 1;
            display: none;
        }

        #inspect-title {
            height: 1;
        }

        #inspect-status {
            height: auto;
        }

        #inspect-table {
            height: 1fr;
        }

        #profile-options {
            height: auto;
            display: none;
        }

        #delay-options {
            layer: overlay;
            position: absolute;
            width: 40;
            offset: 2 2;
            height: auto;
            display: none;
        }

        #inspect-search {
            height: auto;
            display: none;
        }

        #inspect-marker-legend {
            layer: overlay;
            width: 86;
            height: 14;
            offset: 4 3;
            border: round $accent;
            background: $panel;
            padding: 0 1;
            display: none;
        }

        #marker-legend-title {
            height: 1;
        }

        #marker-legend-table {
            height: 1fr;
        }

        #inspect-help {
            layer: overlay;
            width: 86;
            height: 14;
            offset: 4 3;
            border: round $accent;
            background: $panel;
            padding: 0 1;
            display: none;
        }

        #inspect-help-title {
            height: 1;
        }

        #inspect-help-table {
            height: 1fr;
        }
        """
        BINDINGS = [
            ("ctrl+c", "quit", "Quit"),
            ("ctrl+q", "quit", "Quit"),
            ("q", "quit", "Quit"),
            ("r", "refresh", "Refresh"),
            ("enter", "inspect", "Inspect"),
            ("question_mark", "inspect", "Inspect"),
            ("escape", "close_inspect", "Close"),
            ("space", "toggle_pause_or_inspect_mode", "Pause/mode"),
            ("x", "toggle_extended", "Extended"),
            ("p", "profile_default", "Profile"),
            ("P", "profile_custom", "Profile options"),
            ("i", "toggle_kernel_ip_detail", "Kernel IPs"),
            ("m", "toggle_inspect_markers", "Markers"),
            ("M", "toggle_marker_legend", "Marker legend"),
            ("e", "expand_fold", "Expand fold"),
            ("c", "toggle_cumulative_or_collapse_fold", "Cumulative/fold"),
            ("E", "expand_all_folds", "Expand all"),
            ("C", "collapse_all_folds", "Collapse all"),
            ("slash", "search_source", "Search"),
            ("d", "change_delay", "Delay"),
            ("h", "toggle_help", "Help"),
        ]

        def __init__(self, service: BpfSnapshotService, config: BrrConfig) -> None:
            super().__init__()
            self.theme = config.theme
            self.service = service
            self.config = config
            self.source_context_enricher = (
                SourceContextEnricher(config.devdir) if config.devmode and config.devdir else None
            )
            self.delay = config.delay
            self.service_lock = Lock()
            self.activity_ids: list[int] = []
            self.last_activity_report: BrrActivityReport | None = None
            self.refresh_timer = None
            self.refresh_paused = False
            self.show_cumulative = config.cumulative
            self.show_extended = config.extended
            self.delay_options_open = False
            self.inspect_open = False
            self.profile_options_open = False
            self.activity_refreshing = False
            self.inspect_loading = False
            self.profile_running = False
            self.inspect_dump: BpfProgramDump | None = None
            self.inspect_mode: InspectMode = "source"
            self.inspect_profile: BpfProfile | None = None
            self.inspect_profile_program: BpfProfileProgram | None = None
            self.inspect_hotspots: list[BpfHotspot] = []
            self.inspect_kernel_hotspots: list[BpfKernelHotspot] = []
            self.inspect_kernel_function_hotspots: list[BpfKernelHotspot] = []
            self.inspect_kernel_ip_detail = config.kernel_ip_detail
            self.inspect_report: BrrInspectReport | None = None
            self.inspect_fold_ranges: list[InspectFoldRange] = []
            self.inspect_expanded_fold_ids: set[int] = set()
            self.inspect_expanded_child_keys: set[str] = set()
            self.inspect_visible_full_indexes: list[int | None] = []
            self.inspect_visible_fold_ids: list[int | None] = []
            self.inspect_search_open = False
            self.inspect_search_focused = False
            self.inspect_search_query = ""
            self.inspect_status_message: str | None = None
            self.inspect_markers_visible = False
            self.inspect_marker_legend_open = False
            self.inspect_help_open = False
            self.worker_tokens: dict[int, tuple[str, int]] = {}
            self.next_token = 0
            self.activity_token = 0
            self.inspect_token = 0
            self.render_token = 0
            self.profile_token = 0

        def compose(self) -> ComposeResult:
            yield Header()
            yield Static("Sampling eBPF runtime deltas...", id="status")
            yield DataTable(id="activity")
            yield Input(id="delay-options", placeholder="refresh delay seconds")
            yield Vertical(
                Static(id="inspect-title"),
                Static(id="inspect-status"),
                Vertical(
                    Input(id="profile-duration", placeholder="seconds"),
                    Input(id="profile-frequency", placeholder="frequency Hz"),
                    Input(id="profile-event", placeholder="auto, cycles:p, cycles, cpu-clock"),
                    Input(id="profile-call-graph", placeholder="call graph: fp, lbr"),
                    Input(id="profile-buffer-pages", placeholder="perf pages: auto, 8, 16..."),
                    Input(id="profile-drain-ms", placeholder="drain ms: auto, 100..."),
                    Checkbox("kernel/helper samples", id="profile-kernel-samples"),
                    id="profile-options",
                ),
                Input(id="inspect-search", placeholder="/ search source"),
                DataTable(id="inspect-table"),
                Vertical(
                    Static("Code markers", id="marker-legend-title"),
                    DataTable(id="marker-legend-table"),
                    id="inspect-marker-legend",
                ),
                Vertical(
                    Static("Drilldown help", id="inspect-help-title"),
                    DataTable(id="inspect-help-table"),
                    id="inspect-help",
                ),
                id="inspect-modal",
            )
            yield Footer()

        def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
            if action in {"quit", "help_quit", "toggle_help"}:
                return True
            input_open = (
                self.delay_options_open or self.profile_options_open or self.inspect_search_open
            )
            if action == "close_inspect":
                return (
                    self.inspect_open
                    or input_open
                    or self.inspect_marker_legend_open
                    or self.inspect_help_open
                )
            if self.inspect_help_open:
                return action == "toggle_help"
            if self.inspect_marker_legend_open:
                return action in {"toggle_marker_legend"}
            if input_open:
                return False
            if action in {
                "refresh",
                "inspect",
                "change_delay",
                "toggle_extended",
            }:
                return not self.inspect_open
            if action == "toggle_pause_or_inspect_mode":
                return True
            if action == "toggle_cumulative_or_collapse_fold":
                return (
                    not self.inspect_open
                    or bool(self.inspect_fold_ranges)
                    or bool(self.inspect_expanded_child_keys)
                )
            if action in {
                "profile_default",
                "profile_custom",
                "search_source",
                "toggle_kernel_ip_detail",
                "toggle_inspect_markers",
                "toggle_marker_legend",
            }:
                return self.inspect_open and not self.inspect_loading
            if action in {"expand_fold", "expand_all_folds", "collapse_all_folds"}:
                return self.inspect_open and (
                    bool(self.inspect_fold_ranges) or bool(self._all_child_keys())
                )
            return True

        def on_mount(self) -> None:
            table = self.query_one("#activity", DataTable)
            table.cursor_type = "row"
            table.show_row_labels = False
            table.zebra_stripes = True
            self._reset_activity_columns()
            inspect_table = self.query_one("#inspect-table", DataTable)
            inspect_table.cursor_type = "row"
            inspect_table.show_row_labels = False
            inspect_table.zebra_stripes = True
            inspect_table.add_columns("%THIS", "SAMPLES", "CODE")
            marker_table = self.query_one("#marker-legend-table", DataTable)
            marker_table.cursor_type = "row"
            marker_table.show_row_labels = False
            marker_table.zebra_stripes = True
            marker_table.add_columns("MARKER", "MEANING")
            for marker, description in MARKER_DESCRIPTIONS:
                marker_table.add_row(Text(f"[{marker}]"), description)
            help_table = self.query_one("#inspect-help-table", DataTable)
            help_table.cursor_type = "row"
            help_table.show_row_labels = False
            help_table.zebra_stripes = True
            help_table.add_columns("KEY", "ACTION")
            for key, description in INSPECT_HELP_ROWS:
                help_table.add_row(key, description)
            self.action_refresh()
            self._restart_refresh_timer()

        def _scheduled_refresh(self) -> None:
            if self.refresh_paused or self.delay_options_open:
                return
            self.action_refresh()

        def _continue_activity_refresh(self) -> None:
            if self.refresh_paused or self.delay_options_open or self.inspect_open:
                return
            # The worker already spends self.delay seconds measuring. Chain the next
            # window now so the periodic fallback timer does not add an unmeasured gap.
            self.action_refresh()

        def _restart_refresh_timer(self) -> None:
            if self.refresh_timer is not None:
                self.refresh_timer.stop()
            self.refresh_timer = self.set_interval(
                self.delay,
                self._scheduled_refresh,
                name="activity-refresh-interval",
            )

        def action_refresh(self) -> None:
            if self.inspect_open:
                try:
                    self.query_one("#status", Static).update(
                        "Top refresh paused while inspecting; Esc returns to live view."
                    )
                except NoMatches:
                    pass
                return
            if self.activity_refreshing:
                return
            token = self._next_worker_token()
            self.activity_token = token
            self.activity_refreshing = True
            self.query_one("#status", Static).update("Refreshing eBPF runtime deltas...")

            def work() -> ActivityRefreshResult:
                with self.service_lock:
                    report = collect_activity_report(
                        self.service,
                        duration=self.delay,
                        include_all=True,
                        limit=0,
                    )
                return ActivityRefreshResult(
                    token=token,
                    report=report,
                )

            worker = self.run_worker(
                work,
                name="activity-refresh",
                group="activity-refresh",
                exclusive=True,
                thread=True,
                exit_on_error=False,
            )
            self.worker_tokens[id(worker)] = ("activity", token)

        def action_inspect(self) -> None:
            if self.profile_options_open:
                self._submit_profile_options()
                return
            if self.inspect_open:
                return
            table = self.query_one("#activity", DataTable)
            program_id = _selected_activity_id(self.activity_ids, table.cursor_row)
            if program_id is None:
                return
            self._reset_inspect_state()
            token = self._next_worker_token()
            self.inspect_token = token
            self.inspect_open = True
            self.inspect_loading = True
            self._show_inspect_modal()
            self.refresh_bindings()
            self.query_one("#status", Static).update(
                "Top refresh paused while inspecting; Esc returns to live view."
            )
            self.query_one("#inspect-title", Static).update(f"loading program {program_id}...")
            self.query_one("#inspect-status", Static).update("")

            def work() -> InspectLoadResult:
                with self.service_lock:
                    dump = self.service.collect_program_dump(program_id)
                    report = build_inspect_report(
                        dump,
                        mode="source",
                        hotspots=[],
                        kernel_hotspots=[],
                        bpftool_provider=None,
                    )
                    report = self._enrich_inspect_report(report)
                return InspectLoadResult(
                    token=token,
                    program_id=program_id,
                    dump=dump,
                    report=report,
                )

            worker = self.run_worker(
                work,
                name="inspect-load",
                group="inspect-load",
                exclusive=True,
                thread=True,
                exit_on_error=False,
            )
            self.worker_tokens[id(worker)] = ("inspect-load", token)

        def on_data_table_row_selected(self, _event) -> None:
            self.action_inspect()

        def action_close_inspect(self) -> None:
            if self.delay_options_open:
                self._close_delay_options()
                return
            if self.inspect_help_open:
                self._close_inspect_help()
                return
            if self.inspect_marker_legend_open:
                self.inspect_marker_legend_open = False
                self._set_marker_legend_visible(False)
                self.query_one("#inspect-status", Static).update(
                    self.inspect_status_message or self._inspect_help_text()
                )
                self.query_one("#inspect-table", DataTable).focus()
                self.refresh_bindings()
                return
            if self.inspect_search_open:
                self._close_search()
                return
            if self.profile_options_open:
                self.profile_options_open = False
                self._set_profile_options_visible(False)
                self.query_one("#inspect-status", Static).update(self._inspect_help_text())
                self.query_one("#inspect-table", DataTable).focus()
                self.refresh_bindings()
                return
            if self.inspect_open:
                self.inspect_open = False
                self._reset_inspect_state()
                self.query_one("#inspect-modal", Vertical).display = False
                self.query_one("#inspect-modal", Vertical).trap_focus(False)
                self.query_one("#activity", DataTable).focus()
                self.refresh_bindings()
                self.action_refresh()

        def _reset_inspect_state(self) -> None:
            """Clear the modal and invalidate every inspect-related worker generation."""
            self.inspect_token = self._next_worker_token()
            self.render_token = self._next_worker_token()
            self.profile_token = self._next_worker_token()
            self.inspect_loading = False
            self.profile_running = False
            self.profile_options_open = False
            self.inspect_dump = None
            self.inspect_mode = "source"
            self.inspect_profile = None
            self.inspect_profile_program = None
            self.inspect_hotspots = []
            self.inspect_kernel_hotspots = []
            self.inspect_kernel_function_hotspots = []
            self.inspect_kernel_ip_detail = self.config.kernel_ip_detail
            self.inspect_report = None
            self.inspect_fold_ranges = []
            self.inspect_expanded_fold_ids = set()
            self.inspect_expanded_child_keys = set()
            self.inspect_visible_full_indexes = []
            self.inspect_visible_fold_ids = []
            self.inspect_search_open = False
            self.inspect_search_focused = False
            self.inspect_search_query = ""
            self.inspect_status_message = None
            self.inspect_markers_visible = False
            self.inspect_marker_legend_open = False
            self.inspect_help_open = False
            self._set_profile_options_visible(False)
            search = self.query_one("#inspect-search", Input)
            search.value = ""
            self._set_search_visible(False)
            self._set_marker_legend_visible(False)
            self._set_inspect_help_visible(False)
            self.query_one("#inspect-title", Static).update("")
            self.query_one("#inspect-status", Static).update("")
            self.query_one("#inspect-table", DataTable).clear()

        def action_toggle_pause_or_inspect_mode(self) -> None:
            if not self.inspect_open:
                self.refresh_paused = not self.refresh_paused
                status = self.query_one("#status", Static)
                if self.refresh_paused:
                    status.update("Refresh paused; press Space to resume or r to refresh once.")
                else:
                    status.update(f"Refresh resumed with {self.delay:g}s delay.")
                    self._restart_refresh_timer()
                self.refresh_bindings()
                return
            self._toggle_inspect_mode()

        def action_toggle_extended(self) -> None:
            self.show_extended = not self.show_extended
            self._render_last_activity()
            self.query_one("#status", Static).update(
                "Extended columns shown." if self.show_extended else "Extended columns hidden."
            )
            self.refresh_bindings()

        def _toggle_inspect_mode(self) -> None:
            if (
                not self.inspect_open
                or self.profile_options_open
                or self.inspect_dump is None
                or self.inspect_loading
            ):
                return
            self.inspect_mode = "mixed" if self.inspect_mode == "source" else "source"
            self.inspect_fold_ranges = []
            self.inspect_expanded_fold_ids = set()
            self.inspect_expanded_child_keys = set()
            if self.inspect_search_open:
                self.inspect_search_open = False
                self.inspect_search_focused = False
                self.inspect_search_query = ""
                self.query_one("#inspect-search", Input).value = ""
                self._set_search_visible(False)
            self._schedule_inspect_render(jump_to_hotspot=False)

        def action_expand_fold(self) -> None:
            if not self.inspect_open or self.profile_options_open or self.inspect_loading:
                return
            table = self.query_one("#inspect-table", DataTable)
            visible = self._visible_inspect_rows(table)
            if 0 <= table.cursor_row < len(visible.rows):
                row = visible.rows[table.cursor_row]
                if (
                    row.has_children
                    and row.child_key is not None
                    and row.child_key not in self.inspect_expanded_child_keys
                ):
                    self.inspect_expanded_child_keys.add(row.child_key)
                    self._render_inspect(
                        preserve_row=table.cursor_row,
                        preserve_viewport=True,
                    )
                    return
            if not self._can_change_folds():
                return
            fold_id = self._fold_id_at_visible_row(table.cursor_row)
            if fold_id is None:
                return
            self.inspect_expanded_fold_ids.add(fold_id)
            self._render_inspect(preserve_row=table.cursor_row, preserve_viewport=True)

        def action_toggle_cumulative_or_collapse_fold(self) -> None:
            if not self.inspect_open:
                self.show_cumulative = not self.show_cumulative
                self._render_last_activity()
                self.refresh_bindings()
                return
            self._collapse_fold()

        def _collapse_fold(self) -> None:
            if not self.inspect_open or self.profile_options_open or self.inspect_loading:
                return
            table = self.query_one("#inspect-table", DataTable)
            visible = self._visible_inspect_rows(table)
            if 0 <= table.cursor_row < len(visible.rows):
                row = visible.rows[table.cursor_row]
                if row.child_key is not None and row.child_key in self.inspect_expanded_child_keys:
                    self.inspect_expanded_child_keys.discard(row.child_key)
                    self._render_inspect(
                        preserve_row=table.cursor_row,
                        preserve_viewport=True,
                    )
                    return
            if not self._can_change_folds():
                return
            full_index = self._full_index_at_visible_row(table.cursor_row)
            if full_index is None:
                return
            fold_range = _fold_range_containing(self.inspect_fold_ranges, full_index)
            if fold_range is None or fold_range.id not in self.inspect_expanded_fold_ids:
                return
            self.inspect_expanded_fold_ids.discard(fold_range.id)
            self._render_inspect(target_fold_id=fold_range.id, preserve_viewport=True)

        def action_change_delay(self) -> None:
            if self.inspect_open or self.delay_options_open:
                return
            self.delay_options_open = True
            delay_input = self.query_one("#delay-options", Input)
            delay_input.value = str(self.delay)
            self._set_delay_options_visible(True)
            self.query_one("#status", Static).update(
                "Enter a refresh delay in seconds; press Enter to apply or Esc to cancel."
            )
            delay_input.focus()
            self.refresh_bindings()

        def action_toggle_help(self) -> None:
            if self.inspect_open:
                if self.inspect_help_open:
                    self._close_inspect_help()
                    return
                if self.inspect_marker_legend_open:
                    self.inspect_marker_legend_open = False
                    self._set_marker_legend_visible(False)
                self.inspect_help_open = True
                self._set_inspect_help_visible(True)
                self.query_one("#inspect-status", Static).update(
                    "drilldown help open; Esc or h closes"
                )
                self.query_one("#inspect-help-table", DataTable).focus()
                self.refresh_bindings()
                return
            if self.screen.query(HelpPanel):
                self.action_hide_help_panel()
            else:
                self.action_show_help_panel()

        def action_expand_all_folds(self) -> None:
            if not self.inspect_open or self.profile_options_open or self.inspect_loading:
                return
            table = self.query_one("#inspect-table", DataTable)
            self.inspect_expanded_child_keys = self._all_child_keys()
            self.inspect_expanded_fold_ids = {
                fold_range.id for fold_range in self.inspect_fold_ranges
            }
            self._render_inspect(preserve_row=table.cursor_row, preserve_viewport=True)

        def action_collapse_all_folds(self) -> None:
            if not self.inspect_open or self.profile_options_open or self.inspect_loading:
                return
            self.inspect_expanded_fold_ids = set()
            self.inspect_expanded_child_keys = set()
            target_fold_id = self.inspect_fold_ranges[0].id if self.inspect_fold_ranges else None
            self._render_inspect(target_fold_id=target_fold_id, preserve_viewport=True)

        def action_search_source(self) -> None:
            if (
                not self.inspect_open
                or self.inspect_loading
                or self.inspect_report is None
                or self.inspect_report.mode != "source"
            ):
                return
            if self.profile_options_open:
                self.profile_options_open = False
                self._set_profile_options_visible(False)
            table = self.query_one("#inspect-table", DataTable)
            self.inspect_fold_ranges = self._current_fold_ranges(table)
            self.inspect_expanded_fold_ids = {
                fold_range.id for fold_range in self.inspect_fold_ranges
            }
            self.inspect_search_open = True
            self.inspect_search_focused = True
            self.inspect_search_query = ""
            search = self.query_one("#inspect-search", Input)
            search.value = ""
            self._set_search_visible(True)
            self.query_one("#inspect-status", Static).update(
                "Search source; Enter jumps to first match, Esc clears search"
            )
            self._render_inspect(preserve_row=table.cursor_row, preserve_viewport=True)

        def action_profile_default(self) -> None:
            if (
                not self.inspect_open
                or self.profile_options_open
                or self.inspect_dump is None
                or self.profile_running
                or self.inspect_loading
            ):
                return
            self._profile_inspected(
                ProfileOptions(
                    duration=self.config.profile_duration,
                    frequency=self.config.frequency,
                    event=self.config.event,
                    kernel_samples=True,
                    call_graph=self.config.call_graph,
                    perf_buffer_pages=self.config.perf_buffer_pages,
                    perf_drain_ms=self.config.perf_drain_ms,
                )
            )

        def action_profile_custom(self) -> None:
            if (
                not self.inspect_open
                or self.inspect_dump is None
                or self.profile_running
                or self.inspect_loading
            ):
                return
            self.profile_options_open = True
            self.query_one("#profile-duration", Input).value = str(self.config.profile_duration)
            self.query_one("#profile-frequency", Input).value = str(self.config.frequency)
            self.query_one("#profile-event", Input).value = self.config.event
            self.query_one("#profile-call-graph", Input).value = self.config.call_graph
            self.query_one("#profile-buffer-pages", Input).value = _auto_value(
                self.config.perf_buffer_pages
            )
            self.query_one("#profile-drain-ms", Input).value = _auto_value(
                self.config.perf_drain_ms
            )
            self.query_one("#profile-kernel-samples", Checkbox).value = self.config.kernel_samples
            self._set_profile_options_visible(True)
            self.query_one("#inspect-status", Static).update(
                "Edit duration, frequency, event, call graph, perf buffers, and samples; "
                "press Enter to profile"
            )
            self.query_one("#profile-duration", Input).focus()
            self.refresh_bindings()

        def _update_activity(
            self,
            result: ActivityRefreshResult,
        ) -> None:
            self.last_activity_report = result.report
            table = self.query_one("#activity", DataTable)
            selected_row = _preserved_activity_row(
                len(result.report.items),
                previous_row=table.cursor_row,
            )
            self._render_activity_rows(result.report)
            if selected_row is not None:
                table.move_cursor(row=selected_row, column=0, animate=False, scroll=True)
            status = self.query_one("#status", Static)
            if result.report.items:
                status.update(
                    f"Runtime deltas over {result.report.duration:g}s; "
                    "press Enter or ? to inspect a program."
                )
            else:
                status.update("No active eBPF program runtime deltas observed.")

        def _render_last_activity(self) -> None:
            if self.last_activity_report is None:
                return
            table = self.query_one("#activity", DataTable)
            previous_row = table.cursor_row
            selected_row = _preserved_activity_row(
                len(self.last_activity_report.items),
                previous_row=previous_row,
            )
            self._reset_activity_columns()
            self._render_activity_rows(self.last_activity_report)
            if selected_row is not None:
                table.move_cursor(row=selected_row, column=0, animate=False, scroll=True)

        def _reset_activity_columns(self) -> None:
            table = self.query_one("#activity", DataTable)
            table.clear(columns=True)
            for label, right in _visible_top_activity_columns(
                self.show_cumulative,
                self.show_extended,
            ):
                table.add_column(_top_cell(label, right=right))

        def _render_activity_rows(self, report: BrrActivityReport) -> None:
            table = self.query_one("#activity", DataTable)
            table.clear()
            self.activity_ids = []
            for item in report.items:
                activity = item.activity
                self.activity_ids.append(activity.id)
                table.add_row(
                    *self._activity_cells(item, duration=report.duration),
                    key=str(activity.id),
                )

        def _activity_cells(
            self,
            item: BrrActivityItem,
            *,
            duration: float,
        ) -> tuple[Text | str, ...]:
            activity = item.activity
            values = {
                "ID": _top_cell(str(activity.id), right=True),
                "TYPE": _top_cell(activity.program_type),
                "NAME": _top_cell(activity.name),
                "CPU%": _top_cell(f"{item.bpf_percent:.4f}", right=True),
                "EXECS/s": _top_cell(
                    _format_rate(activity.run_count_delta, duration=duration),
                    right=True,
                ),
                "AVG_NS": _top_cell(_format_int(activity.avg_run_time_ns), right=True),
                "CUMUL_AVG_NS": _top_cell(
                    _format_int(activity.cumulative_avg_run_time_ns),
                    right=True,
                ),
                "NS_PER/s": _top_cell(
                    _format_rate(activity.run_time_ns_delta, duration=duration),
                    right=True,
                ),
                "EXECS_DELTA": _top_cell(_format_int(activity.run_count_delta), right=True),
                "TOTAL_NS": _top_cell(_format_int(activity.run_time_ns_delta), right=True),
                "EXECS_TOTAL": _top_cell(_format_int(activity.run_count_total), right=True),
                "CUMUL_NS": _top_cell(_format_int(activity.run_time_ns_total), right=True),
                "XLAT_B": _top_cell(_format_int(activity.xlated_size_bytes), right=True),
                "JIT_B": _top_cell(_format_int(activity.jited_size_bytes), right=True),
                "TAG": activity.tag or "-",
                "PINNED": ",".join(activity.pinned_paths) if activity.pinned_paths else "-",
            }
            columns = _visible_top_activity_columns(self.show_cumulative, self.show_extended)
            return tuple(values[label] for label, _right in columns)

        def _submit_profile_options(self) -> None:
            status = self.query_one("#inspect-status", Static)
            try:
                duration = float(self.query_one("#profile-duration", Input).value)
                frequency = int(self.query_one("#profile-frequency", Input).value)
            except ValueError:
                status.update("duration must be numeric and frequency must be an integer")
                return
            event = self.query_one("#profile-event", Input).value.strip()
            if duration <= 0 or frequency <= 0:
                status.update("duration and frequency must be greater than zero")
                return
            try:
                validate_perf_event_name(event)
            except BrrError:
                status.update("event is not supported by brr; run brr perf-events to list options")
                return
            kernel_samples = self.query_one("#profile-kernel-samples", Checkbox).value
            call_graph = self.query_one("#profile-call-graph", Input).value.strip() or "fp"
            if call_graph not in CALL_GRAPH_MODES:
                status.update("call graph must be fp or lbr")
                return
            if call_graph == "lbr" and not kernel_samples:
                status.update("lbr call graph requires kernel/helper samples")
                return
            try:
                perf_buffer_pages = _parse_auto_power_of_two(
                    self.query_one("#profile-buffer-pages", Input).value
                )
                perf_drain_ms = _parse_auto_positive_int(
                    self.query_one("#profile-drain-ms", Input).value
                )
            except ValueError as exc:
                status.update(str(exc))
                return
            self.profile_options_open = False
            self._set_profile_options_visible(False)
            self.refresh_bindings()
            self._profile_inspected(
                ProfileOptions(
                    duration=duration,
                    frequency=frequency,
                    event=event,
                    kernel_samples=kernel_samples,
                    call_graph=call_graph,
                    perf_buffer_pages=perf_buffer_pages,
                    perf_drain_ms=perf_drain_ms,
                )
            )

        def _profile_inspected(self, options: ProfileOptions) -> None:
            if self.inspect_dump is None:
                return
            status = self.query_one("#inspect-status", Static)
            program_id = self.inspect_dump.program.id
            token = self._next_worker_token()
            self.profile_token = token
            self.profile_running = True
            status.update(
                f"profiling program {program_id} for {options.duration:g}s "
                f"at {options.frequency}Hz..."
            )

            def work() -> ProfileResult:
                with self.service_lock:
                    profile = self.service.collect_profile_for_program(
                        program_id,
                        requested_event=options.event,
                        duration=options.duration,
                        frequency=options.frequency,
                        line_limit=self.config.line_limit,
                        kernel_samples=options.kernel_samples,
                        call_graph=options.call_graph,
                        perf_buffer_pages=options.perf_buffer_pages,
                        perf_drain_ms=options.perf_drain_ms,
                    )
                profile_program = profile.items[0] if profile.items else None
                hotspots = profile_program.hotspots if profile_program is not None else []
                kernel_hotspots = (
                    profile_program.kernel_hotspots if profile_program is not None else []
                )
                kernel_function_hotspots = (
                    profile_program.kernel_function_hotspots if profile_program is not None else []
                )
                return ProfileResult(
                    token=token,
                    program_id=program_id,
                    options=options,
                    profile=profile,
                    profile_program=profile_program,
                    hotspots=hotspots,
                    kernel_hotspots=kernel_hotspots,
                    kernel_function_hotspots=kernel_function_hotspots,
                )

            worker = self.run_worker(
                work,
                name="inspect-profile",
                group="inspect-profile",
                exclusive=True,
                thread=True,
                exit_on_error=False,
            )
            self.worker_tokens[id(worker)] = ("profile", token)

        def _render_inspect(
            self,
            *,
            jump_to_hotspot: bool = False,
            preserve_row: int = 0,
            preserve_anchor: InspectCursorAnchor | None = None,
            target_fold_id: int | None = None,
            preserve_viewport: bool = False,
            viewport_state: InspectViewportState | None = None,
        ) -> None:
            self._render_inspect_view(
                jump_to_hotspot=jump_to_hotspot,
                preserve_row=preserve_row,
                preserve_anchor=preserve_anchor,
                target_fold_id=target_fold_id,
                preserve_viewport=preserve_viewport,
                viewport_state=viewport_state,
            )

        def _render_inspect_view(
            self,
            *,
            jump_to_hotspot: bool = False,
            preserve_row: int = 0,
            preserve_anchor: InspectCursorAnchor | None = None,
            target_fold_id: int | None = None,
            preserve_viewport: bool = False,
            viewport_state: InspectViewportState | None = None,
        ) -> None:
            if self.inspect_report is None:
                return
            title = self.query_one("#inspect-title", Static)
            status = self.query_one("#inspect-status", Static)
            table = self.query_one("#inspect-table", DataTable)
            if preserve_viewport and viewport_state is None:
                viewport_state = _inspect_viewport_state(table)
            title.update(
                f"program {self.inspect_report.program.id} {self.inspect_report.program.name} "
                f"mode={self.inspect_report.mode} disasm={self.inspect_report.instruction_source}"
                + (
                    f" kernel={'IPs' if self.inspect_kernel_ip_detail else 'functions'}"
                    if self.inspect_profile_program is not None
                    and self.inspect_profile_program.kernel_samples > 0
                    else ""
                )
            )
            target_row = _hottest_inspect_row(self.inspect_report) if jump_to_hotspot else None
            if self.inspect_profile is None:
                status.update(self._inspect_help_text())
            else:
                self.inspect_status_message = profile_status_message(self.inspect_report)
                status.update(self.inspect_status_message)
            visible = self._visible_inspect_rows(table)
            self.refresh_bindings()
            table.clear()
            children_by_key: dict[str, list[int]] = {}
            for full_index, full_row in enumerate(self.inspect_report.rows):
                if full_row.kind == "kernel" and full_row.child_key is not None:
                    children_by_key.setdefault(full_row.child_key, []).append(full_index)
            for index, row in enumerate(visible.rows):
                if row.kind == "fold":
                    table.add_row(
                        "",
                        "",
                        Text(row.code, style="dim"),
                        key=f"fold:{visible.fold_ids[index]}",
                    )
                else:
                    full_index = visible.full_indexes[index]
                    samples = (
                        row.samples if row.attribution in {"direct", "under", "unaccounted"} else 0
                    )
                    basis_points = (
                        self.inspect_report.this_basis_points(full_index)
                        if full_index is not None
                        else None
                    )
                    child_expanded = (
                        row.child_key in self.inspect_expanded_child_keys
                        if row.has_children and row.child_key is not None
                        else None
                    )
                    if row.child_key is not None and child_expanded is False:
                        child_indexes = children_by_key.get(row.child_key, [])
                        samples += sum(
                            self.inspect_report.rows[child_index].samples
                            for child_index in child_indexes
                        )
                        basis_points = (basis_points or 0) + sum(
                            self.inspect_report.this_basis_points(child_index) or 0
                            for child_index in child_indexes
                        )
                    table.add_row(
                        f"{basis_points / 100:.2f}" if basis_points is not None else "",
                        str(samples) if samples > 0 else "",
                        _inspect_code_cell(
                            row,
                            show_markers=self.inspect_markers_visible,
                            search_query=self.inspect_search_query,
                            child_expanded=child_expanded,
                        ),
                    )
            visible_target_row = self._visible_target_row(
                visible,
                full_target_row=target_row,
                anchor=preserve_anchor,
                target_fold_id=target_fold_id,
                preserve_row=preserve_row,
            )
            if visible_target_row is not None:
                if viewport_state is None:
                    table.move_cursor(row=visible_target_row, column=0, animate=False, scroll=True)
                else:
                    table.move_cursor(
                        row=visible_target_row,
                        column=0,
                        animate=False,
                        scroll=False,
                    )
                    table.scroll_to(
                        x=viewport_state.scroll_x,
                        y=visible_target_row - viewport_state.cursor_viewport_y,
                        animate=False,
                        force=True,
                    )
            if self.inspect_search_focused:
                self.query_one("#inspect-search", Input).focus()
            else:
                table.focus()

        def _set_profile_options_visible(self, visible: bool) -> None:
            self.query_one("#profile-options", Vertical).display = visible

        def _set_delay_options_visible(self, visible: bool) -> None:
            self.query_one("#delay-options", Input).display = visible

        def _close_delay_options(self) -> None:
            self.delay_options_open = False
            self._set_delay_options_visible(False)
            self.query_one("#activity", DataTable).focus()
            self.query_one("#status", Static).update(f"Refresh delay remains {self.delay:g}s.")
            self.refresh_bindings()

        def _set_search_visible(self, visible: bool) -> None:
            self.query_one("#inspect-search", Input).display = visible

        def _set_marker_legend_visible(self, visible: bool) -> None:
            self.query_one("#inspect-marker-legend", Vertical).display = visible

        def _set_inspect_help_visible(self, visible: bool) -> None:
            self.query_one("#inspect-help", Vertical).display = visible

        def _close_inspect_help(self) -> None:
            self.inspect_help_open = False
            self._set_inspect_help_visible(False)
            self.query_one("#inspect-status", Static).update(
                self.inspect_status_message or self._inspect_help_text()
            )
            self.query_one("#inspect-table", DataTable).focus()
            self.refresh_bindings()

        def _close_search(self) -> None:
            self.inspect_search_open = False
            self.inspect_search_focused = False
            self.inspect_search_query = ""
            self.query_one("#inspect-search", Input).value = ""
            self._set_search_visible(False)
            self.query_one("#inspect-status", Static).update(
                self.inspect_status_message or self._inspect_help_text()
            )
            table = self.query_one("#inspect-table", DataTable)
            self._render_inspect(preserve_row=table.cursor_row, preserve_viewport=True)
            self.refresh_bindings()

        def action_toggle_inspect_markers(self) -> None:
            if not self.inspect_open or self.inspect_loading or self.inspect_report is None:
                return
            table = self.query_one("#inspect-table", DataTable)
            preserve_anchor = _inspect_cursor_anchor(
                self._visible_inspect_rows(table), table.cursor_row
            )
            self.inspect_markers_visible = not self.inspect_markers_visible
            self._render_inspect(
                preserve_row=table.cursor_row,
                preserve_anchor=preserve_anchor,
                preserve_viewport=True,
            )
            marker_status = "shown" if self.inspect_markers_visible else "hidden"
            self.query_one("#inspect-status", Static).update(
                f"source mapping markers {marker_status}"
            )
            self.refresh_bindings()

        def action_toggle_kernel_ip_detail(self) -> None:
            if (
                not self.inspect_open
                or self.inspect_loading
                or self.inspect_dump is None
                or self.inspect_profile_program is None
            ):
                return
            if self.inspect_profile_program.kernel_samples <= 0:
                self.query_one("#inspect-status", Static).update(
                    "no kernel/helper samples; profile with kernel samples enabled"
                )
                return
            self.inspect_kernel_ip_detail = not self.inspect_kernel_ip_detail
            self._schedule_inspect_render(jump_to_hotspot=False)

        def action_toggle_marker_legend(self) -> None:
            if not self.inspect_open or self.inspect_loading or self.inspect_report is None:
                return
            if self.inspect_help_open:
                self.inspect_help_open = False
                self._set_inspect_help_visible(False)
            self.inspect_marker_legend_open = not self.inspect_marker_legend_open
            self._set_marker_legend_visible(self.inspect_marker_legend_open)
            if self.inspect_marker_legend_open:
                self.query_one("#inspect-status", Static).update(
                    "marker legend open; Esc or M closes"
                )
                self.query_one("#marker-legend-table", DataTable).focus()
            else:
                self.query_one("#inspect-status", Static).update(
                    self.inspect_status_message or self._inspect_help_text()
                )
                self.query_one("#inspect-table", DataTable).focus()
            self.refresh_bindings()

        def _show_inspect_modal(self) -> None:
            modal = self.query_one("#inspect-modal", Vertical)
            modal.display = True
            modal.trap_focus(True)
            self.query_one("#inspect-table", DataTable).focus()

        def _can_change_folds(self) -> bool:
            return (
                self.inspect_open
                and not self.profile_options_open
                and not self.inspect_loading
                and self.inspect_report is not None
                and bool(self.inspect_fold_ranges)
            )

        def _all_child_keys(self) -> set[str]:
            if self.inspect_report is None:
                return set()
            return {
                row.child_key
                for row in self.inspect_report.rows
                if row.has_children and row.child_key is not None
            }

        def _visible_inspect_rows(self, table: DataTable) -> VisibleInspectRows:
            if self.inspect_report is None:
                return VisibleInspectRows(rows=[], full_indexes=[], fold_ids=[])
            self.inspect_fold_ranges = self._current_fold_ranges(table)
            current_ids = {fold_range.id for fold_range in self.inspect_fold_ranges}
            self.inspect_expanded_fold_ids.intersection_update(current_ids)
            folded_visible = _visible_rows_for_folds(
                self.inspect_report.rows,
                self.inspect_fold_ranges,
                self.inspect_expanded_fold_ids,
            )
            visible = self._visible_rows_for_child_expansion(folded_visible)
            self.inspect_visible_full_indexes = visible.full_indexes
            self.inspect_visible_fold_ids = visible.fold_ids
            return visible

        def _visible_rows_for_child_expansion(
            self,
            visible: VisibleInspectRows,
        ) -> VisibleInspectRows:
            rows: list[BrrInspectRow] = []
            full_indexes: list[int | None] = []
            fold_ids: list[int | None] = []
            for row, full_index, fold_id in zip(
                visible.rows,
                visible.full_indexes,
                visible.fold_ids,
                strict=True,
            ):
                if row.kind == "kernel" and row.child_key not in self.inspect_expanded_child_keys:
                    continue
                rows.append(row)
                full_indexes.append(full_index)
                fold_ids.append(fold_id)
            current_child_keys = {
                row.child_key for row in visible.rows if row.has_children and row.child_key
            }
            self.inspect_expanded_child_keys.intersection_update(current_child_keys)
            return VisibleInspectRows(rows=rows, full_indexes=full_indexes, fold_ids=fold_ids)

        def _current_fold_ranges(self, table: DataTable) -> list[InspectFoldRange]:
            if (
                self.inspect_report is None
                or self.inspect_report.mode != "source"
                or self.inspect_report.profile is None
                or not any(row.samples > 0 for row in self.inspect_report.rows)
            ):
                return []
            return _fold_ranges_for_rows(
                self.inspect_report.rows,
                viewport_rows=self._inspect_viewport_rows(table),
            )

        def _inspect_viewport_rows(self, table: DataTable) -> int:
            return max(table.size.height - 2, 0)

        def _visible_target_row(
            self,
            visible: VisibleInspectRows,
            *,
            full_target_row: int | None,
            anchor: InspectCursorAnchor | None,
            target_fold_id: int | None,
            preserve_row: int,
        ) -> int | None:
            if target_fold_id is not None and target_fold_id in visible.fold_ids:
                return visible.fold_ids.index(target_fold_id)
            if full_target_row is not None and full_target_row in visible.full_indexes:
                return visible.full_indexes.index(full_target_row)
            anchor_row = _visible_row_for_anchor(visible, anchor)
            if anchor_row is not None:
                return anchor_row
            if visible.rows:
                return min(max(preserve_row, 0), len(visible.rows) - 1)
            return None

        def _fold_id_at_visible_row(self, visible_row: int) -> int | None:
            if visible_row < 0 or visible_row >= len(self.inspect_visible_fold_ids):
                return None
            return self.inspect_visible_fold_ids[visible_row]

        def _full_index_at_visible_row(self, visible_row: int) -> int | None:
            if visible_row < 0 or visible_row >= len(self.inspect_visible_full_indexes):
                return None
            return self.inspect_visible_full_indexes[visible_row]

        def on_key(self, event) -> None:
            if not self.profile_options_open:
                return
            focused_id = getattr(self.focused, "id", None)
            if focused_id not in PROFILE_OPTION_WIDGET_IDS:
                return
            if event.key in {"down", "tab"}:
                self._focus_profile_option(1)
            elif event.key in {"up", "shift+tab", "backtab"}:
                self._focus_profile_option(-1)
            else:
                return
            event.prevent_default()
            event.stop()

        def _focus_profile_option(self, direction: int) -> None:
            focused_id = getattr(self.focused, "id", None)
            if focused_id not in PROFILE_OPTION_WIDGET_IDS:
                return
            current = PROFILE_OPTION_WIDGET_ORDER.index(focused_id)
            next_index = (current + direction) % len(PROFILE_OPTION_WIDGET_ORDER)
            self.query_one(f"#{PROFILE_OPTION_WIDGET_ORDER[next_index]}").focus()

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id != "inspect-search" or not self.inspect_search_open:
                return
            self.inspect_search_query = event.value
            self.inspect_search_focused = True
            table = self.query_one("#inspect-table", DataTable)
            self._render_inspect(preserve_row=table.cursor_row, preserve_viewport=True)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            target = _input_submission_target(
                event.input.id,
                delay_options_open=self.delay_options_open,
                profile_options_open=self.profile_options_open,
                inspect_search_open=self.inspect_search_open,
            )
            if target == "delay":
                self._submit_delay_options(event.value)
                return
            if target == "profile":
                self._submit_profile_options()
                return
            if target != "search":
                return
            self.inspect_search_query = event.value
            self.inspect_search_focused = False
            table = self.query_one("#inspect-table", DataTable)
            matches = _search_match_rows(self._visible_inspect_rows(table).rows, event.value)
            if matches:
                table.move_cursor(row=matches[0], column=0, animate=False, scroll=True)
                self.query_one("#inspect-status", Static).update(
                    f"{len(matches)} source search matches for {event.value!r}"
                )
            elif event.value:
                self.query_one("#inspect-status", Static).update(
                    f"no source search matches for {event.value!r}"
                )
            else:
                self.query_one("#inspect-status", Static).update(self._inspect_help_text())
            table.focus()

        def _submit_delay_options(self, value: str) -> None:
            status = self.query_one("#status", Static)
            try:
                delay = float(value)
            except ValueError:
                status.update("delay must be a number greater than zero")
                return
            if delay <= 0:
                status.update("delay must be greater than zero")
                return
            self.delay = delay
            self.delay_options_open = False
            self._set_delay_options_visible(False)
            self._restart_refresh_timer()
            status.update(f"Refresh delay set to {self.delay:g}s.")
            self.query_one("#activity", DataTable).focus()
            self.refresh_bindings()

        def on_resize(self, _event) -> None:
            if self.inspect_open and self.inspect_report is not None and not self.inspect_loading:
                table = self.query_one("#inspect-table", DataTable)
                self._render_inspect(preserve_row=table.cursor_row, preserve_viewport=True)

        def _schedule_inspect_render(self, *, jump_to_hotspot: bool) -> None:
            if self.inspect_dump is None:
                return
            table = self.query_one("#inspect-table", DataTable)
            token = self._next_worker_token()
            self.render_token = token
            dump = self.inspect_dump
            mode = self.inspect_mode
            hotspots = list(self.inspect_hotspots)
            kernel_ip_detail = self.inspect_kernel_ip_detail
            kernel_hotspots = list(
                self.inspect_kernel_hotspots
                if kernel_ip_detail
                else self.inspect_kernel_function_hotspots
            )
            profile = self.inspect_profile
            profile_program = self.inspect_profile_program
            preserve_row = table.cursor_row
            preserve_anchor = _inspect_cursor_anchor(
                self._visible_inspect_rows(table), preserve_row
            )
            viewport_state = _inspect_viewport_state(table)
            self.inspect_loading = True
            self.query_one("#inspect-status", Static).update(f"Rendering {mode} view...")

            def work() -> InspectRenderResult:
                report = build_inspect_report(
                    dump,
                    mode=mode,
                    hotspots=hotspots,
                    kernel_hotspots=kernel_hotspots,
                    kernel_ip_detail=kernel_ip_detail,
                    bpftool_provider=collect_bpftool_xlated,
                )
                report = self._enrich_inspect_report(report)
                return InspectRenderResult(
                    token=token,
                    report=BrrInspectReport(
                        program=report.program,
                        mode=report.mode,
                        rows=report.rows,
                        profile=profile,
                        profile_program=profile_program,
                        instruction_source=report.instruction_source,
                        kernel_ip_detail=kernel_ip_detail,
                    ),
                    preserve_row=preserve_row,
                    preserve_anchor=preserve_anchor,
                    viewport_state=viewport_state,
                    jump_to_hotspot=jump_to_hotspot,
                )

            worker = self.run_worker(
                work,
                name="inspect-render",
                group="inspect-render",
                exclusive=True,
                thread=True,
                exit_on_error=False,
            )
            self.worker_tokens[id(worker)] = ("inspect-render", token)

        def _enrich_inspect_report(self, report: BrrInspectReport) -> BrrInspectReport:
            return _maybe_enrich_inspect_report(
                report,
                self.source_context_enricher,
                require_resolution=self.config.devmode_default_dir,
            )

        def _next_worker_token(self) -> int:
            self.next_token += 1
            return self.next_token

        def _inspect_help_text(self) -> str:
            return (
                "Space source/mixed | i kernel IPs | m markers | M legend | "
                "p/P profile | e/c/E/C folds | h help | Esc closes"
            )

        def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
            if event.state not in {WorkerState.SUCCESS, WorkerState.ERROR, WorkerState.CANCELLED}:
                return
            worker_key = id(event.worker)
            worker_info = self.worker_tokens.pop(worker_key, None)
            if worker_info is None:
                if event.state == WorkerState.SUCCESS:
                    self._handle_untracked_worker_success(event.worker.result)
                return
            role, token = worker_info
            if event.state == WorkerState.ERROR:
                self._handle_worker_error(role, token, event.worker.error)
                return
            if event.state == WorkerState.CANCELLED:
                self._handle_worker_cancelled(role, token)
                return
            self._handle_worker_success(role, token, event.worker.result)

        def _handle_untracked_worker_success(self, result: object) -> None:
            if isinstance(result, ActivityRefreshResult):
                self._handle_worker_success("activity", result.token, result)
            elif isinstance(result, InspectLoadResult):
                self._handle_worker_success("inspect-load", result.token, result)
            elif isinstance(result, InspectRenderResult):
                self._handle_worker_success("inspect-render", result.token, result)
            elif isinstance(result, ProfileResult):
                self._handle_worker_success("profile", result.token, result)

        def _handle_worker_success(self, role: str, token: int, result: object) -> None:
            if role == "activity":
                self.activity_refreshing = False
                if token != self.activity_token or self.inspect_open:
                    return
                if isinstance(result, ActivityRefreshResult):
                    self._update_activity(result)
                    self._continue_activity_refresh()
                return

            if role == "inspect-load":
                if token != self.inspect_token or not self.inspect_open:
                    return
                self.inspect_loading = False
                if isinstance(result, InspectLoadResult):
                    self.inspect_dump = result.dump
                    self.inspect_report = result.report
                    self._render_inspect()
                return

            if role == "inspect-render":
                if token != self.render_token or not self.inspect_open:
                    return
                self.inspect_loading = False
                if isinstance(result, InspectRenderResult):
                    self.inspect_report = result.report
                    self._render_inspect(
                        jump_to_hotspot=result.jump_to_hotspot,
                        preserve_row=result.preserve_row,
                        preserve_anchor=result.preserve_anchor,
                        viewport_state=result.viewport_state,
                    )
                return

            if role == "profile":
                if token != self.profile_token or not self.inspect_open:
                    return
                self.profile_running = False
                if isinstance(result, ProfileResult):
                    self.inspect_profile = result.profile
                    self.inspect_profile_program = result.profile_program
                    self.inspect_hotspots = result.hotspots
                    self.inspect_kernel_hotspots = result.kernel_hotspots
                    self.inspect_kernel_function_hotspots = result.kernel_function_hotspots
                    self.inspect_fold_ranges = []
                    self.inspect_expanded_fold_ids = set()
                    self.inspect_expanded_child_keys = set()
                    self._schedule_inspect_render(jump_to_hotspot=True)

        def _handle_worker_error(
            self,
            role: str,
            token: int,
            error: BaseException | None,
        ) -> None:
            message = f"brr: {error}" if error is not None else "brr: worker failed"
            if role == "activity":
                self.activity_refreshing = False
                if token == self.activity_token:
                    self.query_one("#status", Static).update(message)
            elif role in {"inspect-load", "inspect-render"}:
                current_token = self.inspect_token if role == "inspect-load" else self.render_token
                if token == current_token and self.inspect_open:
                    self.inspect_loading = False
                    self.query_one("#inspect-status", Static).update(message)
            elif role == "profile":
                if token == self.profile_token and self.inspect_open:
                    self.profile_running = False
                    self.query_one("#inspect-status", Static).update(message)

        def _handle_worker_cancelled(self, role: str, token: int) -> None:
            if role == "activity" and token == self.activity_token:
                self.activity_refreshing = False
            elif role == "inspect-load" and token == self.inspect_token and self.inspect_open:
                self.inspect_loading = False
            elif role == "inspect-render" and token == self.render_token and self.inspect_open:
                self.inspect_loading = False
            elif role == "profile" and token == self.profile_token:
                self.profile_running = False

    return BrrTop(service, config)


def run_tui(service: BpfSnapshotService, config: BrrConfig) -> int:
    _create_top_app(service, config).run()
    return 0


def _top_program_id(activity: BrrActivityReport, *, profile_top: bool) -> int | None:
    if not profile_top or not activity.items:
        return None
    return activity.items[0].activity.id


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return parsed


def _auto_power_of_two(value: str) -> int | None:
    try:
        return _parse_auto_power_of_two(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _auto_positive_int(value: str) -> int | None:
    try:
        return _parse_auto_positive_int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parse_auto_power_of_two(value: str) -> int | None:
    text = value.strip().lower()
    if not text or text == "auto":
        return None
    try:
        parsed = int(text)
    except ValueError as exc:
        raise ValueError("perf buffer pages must be auto or an integer") from exc
    if parsed <= 0 or parsed & (parsed - 1):
        raise ValueError("perf buffer pages must be auto or a positive power of two")
    return parsed


def _parse_auto_positive_int(value: str) -> int | None:
    text = value.strip().lower()
    if not text or text == "auto":
        return None
    try:
        parsed = int(text)
    except ValueError as exc:
        raise ValueError("perf drain milliseconds must be auto or an integer") from exc
    if parsed <= 0:
        raise ValueError("perf drain milliseconds must be greater than zero")
    return parsed


def _auto_value(value: int | None) -> str:
    return "auto" if value is None else str(value)


def _perf_event_name(value: str) -> str:
    try:
        return validate_perf_event_name(value)
    except BrrError as exc:
        expected = ", ".join(supported_perf_event_names())
        raise argparse.ArgumentTypeError(f"{exc}; expected one of: {expected}") from exc
