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
    ("BPF%", True),
    ("TOTAL_NS", True),
    ("RUN_COUNT", True),
    ("AVG_NS", True),
    ("CUMUL_NS", True),
    ("CUMUL_RUNS", True),
    ("CUMUL_AVG_NS", True),
    ("XLAT_B", True),
    ("JIT_B", True),
    ("TAG", False),
    ("PINNED", False),
)
CUMULATIVE_TOP_COLUMNS = {"CUMUL_NS", "CUMUL_RUNS", "CUMUL_AVG_NS"}
TEXTUAL_DARK_THEME = "textual-dark"
TEXTUAL_LIGHT_THEME = "textual-light"
KNOWN_256_COLOR_TERMS = {"ghostty", "xterm-ghostty"}
PROFILE_OPTION_INPUT_ORDER = (
    "profile-duration",
    "profile-frequency",
    "profile-event",
    "profile-call-graph",
)
PROFILE_OPTION_INPUT_IDS = frozenset(PROFILE_OPTION_INPUT_ORDER)
PROFILE_OPTION_WIDGET_ORDER = (*PROFILE_OPTION_INPUT_ORDER, "profile-kernel-samples")
PROFILE_OPTION_WIDGET_IDS = frozenset(PROFILE_OPTION_WIDGET_ORDER)
InputSubmissionTarget = Literal["delay", "profile", "search", "none"]


def _selected_activity_id(activity_ids: list[int], cursor_row: int) -> int | None:
    if cursor_row < 0 or cursor_row >= len(activity_ids):
        return None
    return activity_ids[cursor_row]


def _preserved_activity_row(
    activity_ids: list[int],
    *,
    selected_program_id: int | None,
    previous_row: int,
) -> int | None:
    if not activity_ids:
        return None
    if selected_program_id in activity_ids:
        return activity_ids.index(selected_program_id)
    return min(max(previous_row, 0), len(activity_ids) - 1)


def _hottest_inspect_row(report: BrrInspectReport) -> int | None:
    hottest_samples = 0
    hottest_index: int | None = None
    for index, row in enumerate(report.rows):
        if row.kind != "source":
            continue
        if row.samples > hottest_samples:
            hottest_samples = row.samples
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


def _fold_ranges_for_rows(
    rows: list[BrrInspectRow],
    *,
    viewport_rows: int,
    context_lines: int = FOLD_CONTEXT_LINES,
) -> list[InspectFoldRange]:
    if viewport_rows <= 0 or len(rows) <= viewport_rows:
        return []
    hot_indexes = [index for index, row in enumerate(rows) if row.kind == "source" and row.samples]
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
    if row.kind not in {"source", "instruction"}:
        return None
    if row.file_name is None and row.line_number is None and row.offset is None:
        return None
    return InspectCursorAnchor(
        file_name=row.file_name,
        line_number=row.line_number,
        source=_anchor_source(row),
        offset=row.offset,
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


def _visible_top_activity_columns(show_cumulative: bool) -> tuple[tuple[str, bool], ...]:
    if show_cumulative:
        return TOP_ACTIVITY_COLUMNS
    return tuple(
        column for column in TOP_ACTIVITY_COLUMNS if column[0] not in CUMULATIVE_TOP_COLUMNS
    )


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


def add_top_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-d",
        "--delay",
        dest="delay",
        type=_positive_float,
        default=1.0,
        metavar="SECONDS",
        help="Run duration of refresh delay in seconds. Default: 1.",
    )
    parser.add_argument(
        "--limit",
        type=_non_negative_int,
        default=20,
        metavar="N",
        help="Maximum rows to show. Use 0 for no limit. Default: 20.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        dest="include_all",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--event",
        type=_perf_event_name,
        default="auto",
        help="Perf event to sample for drill-down. Default: auto.",
    )
    parser.add_argument(
        "--profile-duration",
        type=_positive_float,
        default=5.0,
        metavar="SECONDS",
        help="Seconds to profile a selected program. Default: 5.",
    )
    parser.add_argument(
        "-F",
        "--frequency",
        type=_positive_int,
        default=997,
        metavar="HZ",
        help="Perf sample frequency in Hz for drill-down. Default: 997.",
    )
    parser.add_argument(
        "--line-limit",
        type=_non_negative_int,
        default=5,
        metavar="N",
        help="Maximum hotspot rows per selected program. Use 0 for no limit. Default: 5.",
    )
    parser.add_argument(
        "--source-limit",
        type=_non_negative_int,
        default=0,
        metavar="N",
        help=(
            "Maximum annotated source rows in textmode inspect output. "
            "Use 0 for no limit. Default: 0."
        ),
    )
    parser.add_argument(
        "--textmode",
        action="store_true",
        help="Print one deterministic report snapshot and exit.",
    )
    parser.add_argument(
        "--profile-top",
        action="store_true",
        help="In textmode, append a profile/source drill-down for the top activity row.",
    )
    parser.add_argument(
        "--kernel-samples",
        action="store_true",
        help=(
            "In profile drill-downs, capture perf callchains and show attributed "
            "kernel/helper samples."
        ),
    )
    parser.add_argument(
        "--call-graph",
        choices=CALL_GRAPH_MODES,
        default="fp",
        help="Perf call graph mode for --kernel-samples profile drill-downs. Default: fp.",
    )
    parser.add_argument(
        "--program-id",
        type=_positive_int,
        metavar="PROG_ID",
        help="In textmode, append a profile/source drill-down for this program ID.",
    )
    parser.add_argument(
        "--inspect-mode",
        choices=("source", "mixed"),
        default="source",
        help="In textmode, choose source-only or mixed source/instruction inspect output.",
    )
    parser.add_argument(
        "--light",
        action="store_true",
        help="Start the interactive TUI with Textual's light theme.",
    )
    parser.add_argument(
        "--devmode",
        nargs="?",
        const=True,
        metavar="DIR",
        help=(
            "Read matching source files from DIR to fill missing source lines. "
            "Defaults to the current directory."
        ),
    )


def config_from_args(args: argparse.Namespace, *, bpffs: str) -> BrrConfig:
    devdir = _devmode_dir(args)
    return BrrConfig(
        bpffs=bpffs,
        delay=args.delay,
        limit=args.limit,
        include_all=True,
        event=args.event,
        profile_duration=args.profile_duration,
        frequency=args.frequency,
        line_limit=args.line_limit,
        source_limit=args.source_limit,
        inspect_mode=args.inspect_mode,
        theme=TEXTUAL_LIGHT_THEME if args.light else TEXTUAL_DARK_THEME,
        devmode=devdir is not None,
        devdir=devdir,
        devmode_default_dir=getattr(args, "devmode", None) is True,
        kernel_samples=args.kernel_samples,
        call_graph=args.call_graph,
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
    activity = collect_activity_report(
        service,
        duration=config.delay,
        include_all=True,
        limit=config.limit,
    )
    sections = [render_brr_activity(activity)]
    source_context_enricher = (
        SourceContextEnricher(config.devdir) if config.devmode and config.devdir else None
    )

    selected_program_id = program_id or _top_program_id(activity, profile_top=profile_top)
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
            call_graph=config.call_graph,
        )
        inspect = _maybe_enrich_inspect_report(
            inspect,
            source_context_enricher,
            require_resolution=config.devmode_default_dir,
        )
        if config.source_limit > 0:
            inspect = BrrInspectReport(
                program=inspect.program,
                mode=inspect.mode,
                rows=inspect.rows[: config.source_limit],
                profile=inspect.profile,
                profile_program=inspect.profile_program,
                instruction_source=inspect.instruction_source,
            )
        sections.append(render_brr_inspect(inspect))
    elif profile_top:
        sections.append("BRR PROFILE program=-\nNo program selected for profiling.")

    return "\n\n".join(sections)


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
    )


def _create_top_app(service: BpfSnapshotService, config: BrrConfig):
    from threading import Lock

    _configure_textual_color_system()

    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.widgets import Checkbox, DataTable, Footer, Header, HelpPanel, Input, Static
    from textual.worker import Worker, WorkerState

    @dataclass(frozen=True, slots=True)
    class ProfileOptions:
        duration: float
        frequency: int
        event: str
        kernel_samples: bool = False
        call_graph: CallGraphMode = "fp"

    @dataclass(frozen=True, slots=True)
    class ActivityRefreshResult:
        token: int
        report: BrrActivityReport
        selected_program_id: int | None
        previous_row: int

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

        #inspect-title,
        #inspect-status {
            height: 1;
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
            ("p", "profile_default", "Profile"),
            ("P", "profile_custom", "Profile options"),
            ("i", "toggle_inspect_markers", "Markers"),
            ("I", "toggle_marker_legend", "Marker legend"),
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
            self.show_cumulative = False
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
                return self.inspect_open or input_open or self.inspect_marker_legend_open
            if self.inspect_marker_legend_open:
                return action in {"toggle_marker_legend"}
            if input_open:
                return False
            if action in {
                "refresh",
                "inspect",
                "change_delay",
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
            inspect_table.add_columns("WEIGHT", "CODE")
            marker_table = self.query_one("#marker-legend-table", DataTable)
            marker_table.cursor_type = "row"
            marker_table.show_row_labels = False
            marker_table.zebra_stripes = True
            marker_table.add_columns("MARKER", "MEANING")
            for marker, description in MARKER_DESCRIPTIONS:
                marker_table.add_row(Text(f"[{marker}]"), description)
            self.action_refresh()
            self._restart_refresh_timer()

        def _scheduled_refresh(self) -> None:
            if self.refresh_paused or self.delay_options_open:
                return
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
                self.query_one("#status", Static).update(
                    "Top refresh paused while inspecting; Esc returns to live view."
                )
                return
            if self.activity_refreshing:
                return
            table = self.query_one("#activity", DataTable)
            token = self._next_worker_token()
            self.activity_token = token
            selected_program_id = _selected_activity_id(self.activity_ids, table.cursor_row)
            previous_row = table.cursor_row
            self.activity_refreshing = True
            self.query_one("#status", Static).update("Refreshing eBPF runtime deltas...")

            def work() -> ActivityRefreshResult:
                with self.service_lock:
                    report = collect_activity_report(
                        self.service,
                        duration=self.delay,
                        include_all=True,
                        limit=self.config.limit,
                    )
                return ActivityRefreshResult(
                    token=token,
                    report=report,
                    selected_program_id=selected_program_id,
                    previous_row=previous_row,
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
            token = self._next_worker_token()
            self.inspect_token = token
            self.inspect_open = True
            self.inspect_loading = True
            self.profile_options_open = False
            self.inspect_dump = None
            self.inspect_mode = "source"
            self.inspect_profile = None
            self.inspect_profile_program = None
            self.inspect_hotspots = []
            self.inspect_kernel_hotspots = []
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
            self._set_profile_options_visible(False)
            self._set_search_visible(False)
            self._set_marker_legend_visible(False)
            self._show_inspect_modal()
            self.refresh_bindings()
            self.query_one("#status", Static).update(
                "Top refresh paused while inspecting; Esc returns to live view."
            )
            self.query_one("#inspect-title", Static).update(f"loading program {program_id}...")
            self.query_one("#inspect-status", Static).update("Loading source and instructions...")

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
                self.inspect_loading = False
                self.profile_running = False
                self.inspect_marker_legend_open = False
                self._set_marker_legend_visible(False)
                self.query_one("#inspect-modal", Vertical).display = False
                self.query_one("#inspect-modal", Vertical).trap_focus(False)
                self.query_one("#activity", DataTable).focus()
                self.refresh_bindings()
                self.action_refresh()

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
                    self._render_inspect(preserve_row=table.cursor_row)
                    return
            if not self._can_change_folds():
                return
            fold_id = self._fold_id_at_visible_row(table.cursor_row)
            if fold_id is None:
                return
            self.inspect_expanded_fold_ids.add(fold_id)
            self._render_inspect(preserve_row=table.cursor_row)

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
                    self._render_inspect(preserve_row=table.cursor_row)
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
            self._render_inspect(target_fold_id=fold_range.id)

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
            self._render_inspect(preserve_row=table.cursor_row)

        def action_collapse_all_folds(self) -> None:
            if not self.inspect_open or self.profile_options_open or self.inspect_loading:
                return
            self.inspect_expanded_fold_ids = set()
            self.inspect_expanded_child_keys = set()
            target_fold_id = self.inspect_fold_ranges[0].id if self.inspect_fold_ranges else None
            self._render_inspect(target_fold_id=target_fold_id)

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
            self._render_inspect(preserve_row=table.cursor_row)

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
            self.query_one("#profile-kernel-samples", Checkbox).value = self.config.kernel_samples
            self._set_profile_options_visible(True)
            self.query_one("#inspect-status", Static).update(
                "Edit duration, frequency, event, call graph, and kernel/helper samples; "
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
                [item.activity.id for item in result.report.items],
                selected_program_id=result.selected_program_id,
                previous_row=result.previous_row,
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
            selected_program_id = _selected_activity_id(self.activity_ids, table.cursor_row)
            selected_row = _preserved_activity_row(
                [item.activity.id for item in self.last_activity_report.items],
                selected_program_id=selected_program_id,
                previous_row=previous_row,
            )
            self._reset_activity_columns()
            self._render_activity_rows(self.last_activity_report)
            if selected_row is not None:
                table.move_cursor(row=selected_row, column=0, animate=False, scroll=True)

        def _reset_activity_columns(self) -> None:
            table = self.query_one("#activity", DataTable)
            table.clear(columns=True)
            for label, right in _visible_top_activity_columns(self.show_cumulative):
                table.add_column(_top_cell(label, right=right))

        def _render_activity_rows(self, report: BrrActivityReport) -> None:
            table = self.query_one("#activity", DataTable)
            table.clear()
            self.activity_ids = []
            for item in report.items:
                activity = item.activity
                self.activity_ids.append(activity.id)
                table.add_row(
                    *self._activity_cells(item),
                    key=str(activity.id),
                )

        def _activity_cells(self, item: BrrActivityItem) -> tuple[Text | str, ...]:
            activity = item.activity
            values = {
                "ID": _top_cell(str(activity.id), right=True),
                "TYPE": _top_cell(activity.program_type),
                "NAME": _top_cell(activity.name),
                "BPF%": _top_cell(f"{item.bpf_percent:.4f}", right=True),
                "TOTAL_NS": _top_cell(_format_int(activity.run_time_ns_delta), right=True),
                "RUN_COUNT": _top_cell(_format_int(activity.run_count_delta), right=True),
                "AVG_NS": _top_cell(_format_int(activity.avg_run_time_ns), right=True),
                "CUMUL_NS": _top_cell(_format_int(activity.run_time_ns_total), right=True),
                "CUMUL_RUNS": _top_cell(_format_int(activity.run_count_total), right=True),
                "CUMUL_AVG_NS": _top_cell(
                    _format_int(activity.cumulative_avg_run_time_ns),
                    right=True,
                ),
                "XLAT_B": _top_cell(_format_int(activity.xlated_size_bytes), right=True),
                "JIT_B": _top_cell(_format_int(activity.jited_size_bytes), right=True),
                "TAG": activity.tag or "-",
                "PINNED": ",".join(activity.pinned_paths) if activity.pinned_paths else "-",
            }
            columns = _visible_top_activity_columns(self.show_cumulative)
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
                    )
                profile_program = profile.items[0] if profile.items else None
                hotspots = profile_program.hotspots if profile_program is not None else []
                kernel_hotspots = (
                    profile_program.kernel_hotspots if profile_program is not None else []
                )
                return ProfileResult(
                    token=token,
                    program_id=program_id,
                    options=options,
                    profile=profile,
                    profile_program=profile_program,
                    hotspots=hotspots,
                    kernel_hotspots=kernel_hotspots,
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
        ) -> None:
            self._render_inspect_view(
                jump_to_hotspot=jump_to_hotspot,
                preserve_row=preserve_row,
                preserve_anchor=preserve_anchor,
                target_fold_id=target_fold_id,
            )

        def _render_inspect_view(
            self,
            *,
            jump_to_hotspot: bool = False,
            preserve_row: int = 0,
            preserve_anchor: InspectCursorAnchor | None = None,
            target_fold_id: int | None = None,
        ) -> None:
            if self.inspect_report is None:
                return
            title = self.query_one("#inspect-title", Static)
            status = self.query_one("#inspect-status", Static)
            table = self.query_one("#inspect-table", DataTable)
            title.update(
                f"program {self.inspect_report.program.id} {self.inspect_report.program.name} "
                f"mode={self.inspect_report.mode} disasm={self.inspect_report.instruction_source}"
            )
            target_row = _hottest_inspect_row(self.inspect_report) if jump_to_hotspot else None
            if self.inspect_profile is None:
                status.update(self._inspect_help_text())
            else:
                self.inspect_status_message = profile_status_message(
                    program_id=self.inspect_report.program.id,
                    profile=self.inspect_profile,
                    profile_program=self.inspect_profile_program,
                    has_mapped_source_samples=_hottest_inspect_row(self.inspect_report) is not None,
                )
                if target_row is not None:
                    self.inspect_status_message = (
                        f"{self.inspect_status_message}; jumped to hottest line"
                    )
                status.update(self.inspect_status_message)
            visible = self._visible_inspect_rows(table)
            self.refresh_bindings()
            table.clear()
            for index, row in enumerate(visible.rows):
                if row.kind == "fold":
                    table.add_row(
                        "",
                        Text(row.code, style="dim"),
                        key=f"fold:{visible.fold_ids[index]}",
                    )
                else:
                    table.add_row(
                        row.weight,
                        _inspect_code_cell(
                            row,
                            show_markers=self.inspect_markers_visible,
                            search_query=self.inspect_search_query,
                            child_expanded=(
                                row.child_key in self.inspect_expanded_child_keys
                                if row.has_children and row.child_key is not None
                                else None
                            ),
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
                table.move_cursor(row=visible_target_row, column=0, animate=False, scroll=True)
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
            self._render_inspect(preserve_row=table.cursor_row)
            self.refresh_bindings()

        def action_toggle_inspect_markers(self) -> None:
            if not self.inspect_open or self.inspect_loading or self.inspect_report is None:
                return
            table = self.query_one("#inspect-table", DataTable)
            preserve_anchor = _inspect_cursor_anchor(
                self._visible_inspect_rows(table), table.cursor_row
            )
            self.inspect_markers_visible = not self.inspect_markers_visible
            self._render_inspect(preserve_row=table.cursor_row, preserve_anchor=preserve_anchor)
            marker_status = "shown" if self.inspect_markers_visible else "hidden"
            self.query_one("#inspect-status", Static).update(
                f"source mapping markers {marker_status}"
            )
            self.refresh_bindings()

        def action_toggle_marker_legend(self) -> None:
            if not self.inspect_open or self.inspect_loading or self.inspect_report is None:
                return
            self.inspect_marker_legend_open = not self.inspect_marker_legend_open
            self._set_marker_legend_visible(self.inspect_marker_legend_open)
            if self.inspect_marker_legend_open:
                self.query_one("#inspect-status", Static).update(
                    "marker legend open; Esc or I closes"
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
            self._render_inspect(preserve_row=table.cursor_row)

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
                self._render_inspect(preserve_row=table.cursor_row)

        def _schedule_inspect_render(self, *, jump_to_hotspot: bool) -> None:
            if self.inspect_dump is None:
                return
            table = self.query_one("#inspect-table", DataTable)
            token = self._next_worker_token()
            self.render_token = token
            dump = self.inspect_dump
            mode = self.inspect_mode
            hotspots = list(self.inspect_hotspots)
            kernel_hotspots = list(self.inspect_kernel_hotspots)
            profile = self.inspect_profile
            profile_program = self.inspect_profile_program
            preserve_row = table.cursor_row
            preserve_anchor = _inspect_cursor_anchor(
                self._visible_inspect_rows(table), preserve_row
            )
            self.inspect_loading = True
            self.query_one("#inspect-status", Static).update(f"Rendering {mode} view...")

            def work() -> InspectRenderResult:
                report = build_inspect_report(
                    dump,
                    mode=mode,
                    hotspots=hotspots,
                    kernel_hotspots=kernel_hotspots,
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
                    ),
                    preserve_row=preserve_row,
                    preserve_anchor=preserve_anchor,
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
                "Space toggles source/mixed | i markers | I legend | "
                "p/P profile | e/c/E/C folds | Esc closes"
            )

        def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
            if event.state not in {WorkerState.SUCCESS, WorkerState.ERROR, WorkerState.CANCELLED}:
                return
            worker_key = id(event.worker)
            worker_info = self.worker_tokens.pop(worker_key, None)
            if worker_info is None:
                return
            role, token = worker_info
            if event.state == WorkerState.ERROR:
                self._handle_worker_error(role, token, event.worker.error)
                return
            if event.state == WorkerState.CANCELLED:
                self._handle_worker_cancelled(role, token)
                return
            self._handle_worker_success(role, token, event.worker.result)

        def _handle_worker_success(self, role: str, token: int, result: object) -> None:
            if role == "activity":
                self.activity_refreshing = False
                if token != self.activity_token or self.inspect_open:
                    return
                if isinstance(result, ActivityRefreshResult):
                    self._update_activity(result)
                return

            if role == "inspect-load":
                self.inspect_loading = False
                if token != self.inspect_token or not self.inspect_open:
                    return
                if isinstance(result, InspectLoadResult):
                    self.inspect_dump = result.dump
                    self.inspect_report = result.report
                    self._render_inspect()
                return

            if role == "inspect-render":
                self.inspect_loading = False
                if token != self.render_token or not self.inspect_open:
                    return
                if isinstance(result, InspectRenderResult):
                    self.inspect_report = result.report
                    self._render_inspect(
                        jump_to_hotspot=result.jump_to_hotspot,
                        preserve_row=result.preserve_row,
                        preserve_anchor=result.preserve_anchor,
                    )
                return

            if role == "profile":
                self.profile_running = False
                if token != self.profile_token or not self.inspect_open:
                    return
                if isinstance(result, ProfileResult):
                    self.inspect_profile = result.profile
                    self.inspect_profile_program = result.profile_program
                    self.inspect_hotspots = result.hotspots
                    self.inspect_kernel_hotspots = result.kernel_hotspots
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
                self.inspect_loading = False
                if self.inspect_open:
                    self.query_one("#inspect-status", Static).update(message)
            elif role == "profile":
                self.profile_running = False
                if token == self.profile_token and self.inspect_open:
                    self.query_one("#inspect-status", Static).update(message)

        def _handle_worker_cancelled(self, role: str, token: int) -> None:
            if role == "activity" and token == self.activity_token:
                self.activity_refreshing = False
            elif role in {"inspect-load", "inspect-render"}:
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


def _perf_event_name(value: str) -> str:
    try:
        return validate_perf_event_name(value)
    except BrrError as exc:
        expected = ", ".join(supported_perf_event_names())
        raise argparse.ArgumentTypeError(f"{exc}; expected one of: {expected}") from exc
