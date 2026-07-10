from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from brr.app import build_snapshot_service
from brr.dump_compare import collect_dump_compare
from brr.errors import BrrError
from brr.profiler import CALL_GRAPH_MODES, supported_perf_event_names, validate_perf_event_name
from brr.render.csv_output import (
    render_btfs_csv,
    render_dump_compare_csv,
    render_links_csv,
    render_maps_csv,
    render_perf_events_csv,
    render_profile_csv,
    render_program_activity_csv,
    render_program_dump_csv,
    render_programs_csv,
)
from brr.render.json_output import (
    render_btfs_json,
    render_dump_compare_json,
    render_links_json,
    render_maps_json,
    render_perf_events_json,
    render_profile_json,
    render_program_activity_json,
    render_program_dump_json,
    render_programs_json,
)
from brr.render.text import (
    render_btfs,
    render_dump_compare,
    render_links,
    render_maps,
    render_perf_events,
    render_profile,
    render_program_activity,
    render_program_dump,
    render_programs,
)
from brr.source_context import SourceContextEnricher, SourceContextReport
from brr.top import add_top_arguments, config_from_args, render_textmode_result, run_tui

PROGRAM_DESCRIPTION = "eBPF Runtime Reporter and Profiler by Tanel Poder (tanelpoder.com)."


def package_version() -> str:
    try:
        return version("brr")
    except PackageNotFoundError:
        return "0.5.1"


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
    if value.strip().lower() == "auto":
        return None
    parsed = _positive_int(value)
    if parsed & (parsed - 1):
        raise argparse.ArgumentTypeError("must be 'auto' or a positive power of two")
    return parsed


def _auto_positive_int(value: str) -> int | None:
    if value.strip().lower() == "auto":
        return None
    return _positive_int(value)


def _perf_event_name(value: str) -> str:
    try:
        return validate_perf_event_name(value)
    except BrrError as exc:
        expected = ", ".join(supported_perf_event_names())
        raise argparse.ArgumentTypeError(f"{exc}; expected one of: {expected}") from exc


def _validate_call_graph_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    call_graph = getattr(args, "call_graph", "fp")
    kernel_samples = getattr(args, "kernel_samples", False)
    if call_graph == "lbr" and not kernel_samples:
        parser.error("--call-graph lbr requires --kernel-samples")
    if getattr(args, "kernel_ip_detail", False) and not kernel_samples:
        parser.error("--kernel-ip-detail requires --kernel-samples")


def _validate_top_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not getattr(args, "collapse_samples", False):
        return
    if not getattr(args, "textmode", False) or not getattr(args, "profile_top", False):
        parser.error("--collapse-samples requires --textmode and --profile-top")


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Emit machine-readable JSON instead of text.",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Emit machine-readable CSV instead of text.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Pretty-print JSON output. Requires --json.",
    )


def _add_extended_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-x",
        "--extended",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show extended TAG and PINNED columns in text output.",
    )


def _add_cumulative_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-c",
        "--cumulative",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Show cumulative runtime metrics in text output.",
    )


def _add_devmode_options(parser: argparse.ArgumentParser) -> None:
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


def _add_perf_buffer_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--perf-buffer-pages",
        type=_auto_power_of_two,
        default=None,
        metavar="auto|PAGES",
        help="Per-CPU perf data pages as a power of two. Default: auto.",
    )
    parser.add_argument(
        "--perf-drain-ms",
        type=_auto_positive_int,
        default=None,
        metavar="auto|MS",
        help="Maximum milliseconds between full perf ring sweeps. Default: auto.",
    )
    parser.add_argument(
        "--fail-on-loss",
        action="store_true",
        help="Print incomplete profile output but exit with status 1.",
    )


def _devmode_dir(args: argparse.Namespace) -> str | None:
    devmode = getattr(args, "devmode", None)
    if devmode is None:
        return None
    if devmode is True:
        return str(Path.cwd())
    return devmode


def _devmode_uses_default_dir(args: argparse.Namespace) -> bool:
    return getattr(args, "devmode", None) is True


def _require_default_devmode_resolution(
    reports: list[SourceContextReport],
) -> None:
    if any(row.resolved_path is not None for report in reports for row in report.rows):
        return
    raise BrrError(
        "devmode did not resolve any source files from the current directory; "
        "pass --devmode DIR to point at the matching source tree"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="brr",
        description=PROGRAM_DESCRIPTION,
    )
    parser.add_argument(
        "--bpffs",
        default="/sys/fs/bpf",
        help="bpffs mount path used for pinned object enrichment.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON for the following subcommand.",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Emit machine-readable CSV for the following subcommand.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print subcommand JSON output. Requires --json.",
    )
    parser.add_argument(
        "-x",
        "--extended",
        action="store_true",
        help="Show extended TAG and PINNED columns in text output.",
    )
    parser.add_argument(
        "-c",
        "--cumulative",
        action="store_true",
        help="Show cumulative runtime metrics where available in text output.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {package_version()} - {PROGRAM_DESCRIPTION}",
        help="Show version number and exit.",
    )
    subparsers = parser.add_subparsers(dest="object_type")

    list_parser = subparsers.add_parser(
        "list",
        aliases=["prog"],
        help="List loaded eBPF programs (alias: prog).",
    )
    list_parser.set_defaults(object_type="list")
    _add_output_options(list_parser)
    _add_extended_option(list_parser)
    list_parser.add_argument(
        "--stats",
        action="store_true",
        help="Enable runtime execution statistics while collecting program info.",
    )

    activity_parser = subparsers.add_parser(
        "activity",
        help="Show eBPF program runtime deltas.",
    )
    _add_output_options(activity_parser)
    _add_cumulative_option(activity_parser)
    _add_extended_option(activity_parser)
    activity_parser.add_argument(
        "-d",
        "--duration",
        type=_positive_float,
        default=5.0,
        metavar="SECONDS",
        help="Seconds to wait between runtime snapshots. Default: 5.",
    )
    activity_parser.add_argument(
        "--limit",
        type=_non_negative_int,
        default=20,
        metavar="N",
        help="Maximum rows to show. Use 0 for no limit. Default: 20.",
    )
    activity_parser.add_argument(
        "--all",
        action="store_true",
        dest="include_all",
        help="Include programs with zero runtime and call-count delta.",
    )

    top_parser = subparsers.add_parser("top", help="Show the live eBPF top TUI.")
    add_top_arguments(top_parser)

    map_parser = subparsers.add_parser("map", help="List loaded eBPF maps.")
    _add_output_options(map_parser)
    _add_extended_option(map_parser)
    link_parser = subparsers.add_parser("link", help="List loaded eBPF links.")
    _add_output_options(link_parser)
    _add_extended_option(link_parser)
    btf_parser = subparsers.add_parser("btf", help="List loaded BTF objects.")
    _add_output_options(btf_parser)

    perf_events_parser = subparsers.add_parser(
        "perf-events",
        help="List brr-supported perf events openable on this host.",
    )
    _add_output_options(perf_events_parser)
    perf_events_parser.add_argument(
        "-F",
        "--frequency",
        type=_positive_int,
        default=997,
        metavar="HZ",
        help="Perf sample frequency to use while probing. Default: 997.",
    )

    dump_parser = subparsers.add_parser(
        "dump",
        help="Dump translated instructions and source-line metadata for a program.",
    )
    _add_output_options(dump_parser)
    _add_devmode_options(dump_parser)
    dump_parser.add_argument("prog_id", type=_positive_int, metavar="PROG_ID")

    dump_compare_parser = subparsers.add_parser(
        "dump-compare",
        help="Compare brr dump output with bpftool source-line metadata.",
    )
    _add_output_options(dump_compare_parser)
    dump_compare_parser.add_argument("prog_id", type=_positive_int, metavar="PROG_ID")

    profile_parser = subparsers.add_parser(
        "profile",
        help="Profile BPF JIT execution with native perf_event_open sampling.",
    )
    _add_output_options(profile_parser)
    _add_extended_option(profile_parser)
    _add_devmode_options(profile_parser)
    profile_parser.add_argument(
        "-d",
        "--duration",
        type=_positive_float,
        default=5.0,
        metavar="SECONDS",
        help="Seconds to sample. Default: 5.",
    )
    profile_parser.add_argument(
        "-F",
        "--frequency",
        type=_positive_int,
        default=997,
        metavar="HZ",
        help="Perf sample frequency in Hz. Default: 997.",
    )
    profile_parser.add_argument(
        "--event",
        type=_perf_event_name,
        default="auto",
        help="Perf event to sample. Default: auto.",
    )
    profile_parser.add_argument(
        "--limit",
        type=_non_negative_int,
        default=20,
        metavar="N",
        help="Maximum program rows to show. Use 0 for no limit. Default: 20.",
    )
    profile_parser.add_argument(
        "--line-limit",
        type=_non_negative_int,
        default=10,
        metavar="N",
        help=(
            "Maximum detailed hotspot rows per program; omitted samples remain in "
            "direct/under 'Other' totals. Use 0 for no limit. Default: 10."
        ),
    )
    profile_parser.add_argument(
        "--program-id",
        type=_positive_int,
        metavar="PROG_ID",
        help="Profile and annotate only this loaded BPF program ID.",
    )
    profile_parser.add_argument(
        "--kernel-samples",
        action="store_true",
        help=(
            "Capture perf callchains and attribute kernel/helper samples to a BPF "
            "program only when its JIT frame appears in the callchain."
        ),
    )
    profile_parser.add_argument(
        "--kernel-ip-detail",
        action="store_true",
        help=(
            "In human output, show separate kernel/helper rows for exact sampled IPs "
            "instead of grouping offsets by function."
        ),
    )
    profile_parser.add_argument(
        "--call-graph",
        choices=CALL_GRAPH_MODES,
        default="fp",
        help="Perf call graph mode for --kernel-samples. Default: fp.",
    )
    profile_parser.add_argument(
        "-w",
        "--wide",
        action="store_true",
        help="Show JIT addresses and full source paths in text output.",
    )
    _add_perf_buffer_options(profile_parser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.object_type is None:
        if args.json or args.csv or args.pretty:
            parser.error(
                "--json, --csv, and --pretty require a subcommand; "
                "use 'brr list --json' to list programs"
            )
        default_top_args = parser.parse_args(["top"])
        default_top_args.bpffs = args.bpffs
        default_top_args.extended = args.extended
        default_top_args.cumulative = args.cumulative
        args = default_top_args
    if args.json and args.csv:
        parser.error("--json and --csv are mutually exclusive")
    if args.pretty and args.csv:
        parser.error("--pretty requires --json")
    if args.pretty and not args.json:
        parser.error("--pretty requires --json")
    _validate_call_graph_args(parser, args)
    _validate_top_args(parser, args)

    service = build_snapshot_service(args.bpffs)

    try:
        object_type = args.object_type
        with_stats = getattr(args, "stats", False)
        if object_type == "list":
            programs = service.collect_programs(with_stats=with_stats)
            if args.json:
                print(render_programs_json(programs, pretty=args.pretty))
            elif args.csv:
                print(render_programs_csv(programs))
            else:
                print(
                    render_programs(
                        programs,
                        with_stats=with_stats,
                        extended=args.extended,
                    )
                )
        elif object_type == "activity":
            activities = service.collect_program_activity(
                duration=args.duration,
                include_all=args.include_all,
                limit=args.limit,
            )
            if args.json:
                print(
                    render_program_activity_json(
                        activities,
                        duration=args.duration,
                        include_all=args.include_all,
                        limit=args.limit,
                        pretty=args.pretty,
                    )
                )
            elif args.csv:
                print(
                    render_program_activity_csv(
                        activities,
                        duration=args.duration,
                        include_all=args.include_all,
                        limit=args.limit,
                    )
                )
            else:
                print(
                    render_program_activity(
                        activities,
                        duration=args.duration,
                        cumulative=args.cumulative,
                        extended=args.extended,
                    )
                )
        elif object_type == "top":
            config = config_from_args(args, bpffs=args.bpffs)
            if args.textmode:
                result = render_textmode_result(
                    service,
                    config,
                    profile_top=args.profile_top,
                    program_id=args.program_id,
                )
                print(result.text)
                if config.fail_on_loss and result.incomplete:
                    return 1
            else:
                return run_tui(service, config)
        elif object_type == "map":
            maps = service.collect_maps()
            if args.json:
                print(render_maps_json(maps, pretty=args.pretty))
            elif args.csv:
                print(render_maps_csv(maps))
            else:
                print(render_maps(maps, extended=args.extended))
        elif object_type == "link":
            links = service.collect_links()
            if args.json:
                print(render_links_json(links, pretty=args.pretty))
            elif args.csv:
                print(render_links_csv(links))
            else:
                print(render_links(links, extended=args.extended))
        elif object_type == "btf":
            btfs = service.collect_btfs()
            if args.json:
                print(render_btfs_json(btfs, pretty=args.pretty))
            elif args.csv:
                print(render_btfs_csv(btfs))
            else:
                print(render_btfs(btfs))
        elif object_type == "perf-events":
            events = service.collect_perf_events(frequency=args.frequency)
            if args.json:
                print(render_perf_events_json(events, pretty=args.pretty))
            elif args.csv:
                print(render_perf_events_csv(events))
            else:
                print(render_perf_events(events))
        elif object_type == "dump":
            dump = service.collect_program_dump(args.prog_id)
            source_context = None
            devdir = _devmode_dir(args)
            if devdir is not None:
                source_context = SourceContextEnricher(devdir).report_for_dump(dump)
                if _devmode_uses_default_dir(args):
                    _require_default_devmode_resolution([source_context])
            if args.json:
                print(
                    render_program_dump_json(
                        dump,
                        pretty=args.pretty,
                        source_context=source_context,
                    )
                )
            elif args.csv:
                print(render_program_dump_csv(dump, source_context=source_context))
            else:
                print(render_program_dump(dump, source_context=source_context))
        elif object_type == "dump-compare":
            result = collect_dump_compare(service, args.prog_id)
            if args.json:
                print(render_dump_compare_json(result, pretty=args.pretty))
            elif args.csv:
                print(render_dump_compare_csv(result))
            else:
                print(render_dump_compare(result))
            if not result.passed:
                return 1
        elif object_type == "profile":
            if args.program_id is not None:
                profile = service.collect_profile_for_program(
                    args.program_id,
                    requested_event=args.event,
                    duration=args.duration,
                    frequency=args.frequency,
                    line_limit=args.line_limit,
                    kernel_samples=args.kernel_samples,
                    call_graph=args.call_graph,
                    perf_buffer_pages=args.perf_buffer_pages,
                    perf_drain_ms=args.perf_drain_ms,
                )
            else:
                profile = service.collect_profile(
                    requested_event=args.event,
                    duration=args.duration,
                    frequency=args.frequency,
                    limit=args.limit,
                    line_limit=args.line_limit,
                    kernel_samples=args.kernel_samples,
                    call_graph=args.call_graph,
                    perf_buffer_pages=args.perf_buffer_pages,
                    perf_drain_ms=args.perf_drain_ms,
                )
            source_context_by_program = None
            devdir = _devmode_dir(args)
            if devdir is not None:
                enricher = SourceContextEnricher(devdir)
                source_context_by_program = {
                    item.id: enricher.report_for_dump(service.collect_program_dump(item.id))
                    for item in profile.items
                }
                if _devmode_uses_default_dir(args):
                    _require_default_devmode_resolution(list(source_context_by_program.values()))
            if args.json:
                print(
                    render_profile_json(
                        profile,
                        pretty=args.pretty,
                        source_context_by_program=source_context_by_program,
                    )
                )
            elif args.csv:
                print(
                    render_profile_csv(
                        profile,
                        source_context_by_program=source_context_by_program,
                    )
                )
            else:
                print(
                    render_profile(
                        profile,
                        wide=args.wide,
                        extended=args.extended,
                        kernel_ip_detail=args.kernel_ip_detail,
                        source_context_by_program=source_context_by_program,
                    )
                )
            if args.fail_on_loss and profile.metadata.incomplete:
                return 1
        else:
            parser.error(f"unsupported object type: {object_type}")
    except BrrError as exc:
        print(f"brr: {exc}", file=sys.stderr)
        return exc.exit_code

    return 0
