from __future__ import annotations

from typing import Any

import pytest

from brr import cli
from brr.errors import PermissionDeniedError
from brr.models import BpfProgram


class _ProgService:
    def __init__(self) -> None:
        self.with_stats: list[bool] = []

    def collect_programs(self, *, with_stats: bool = False) -> list[BpfProgram]:
        self.with_stats.append(with_stats)
        return [BpfProgram(id=7, program_type="xdp", name="pass")]


class _DeniedTopService:
    def collect_programs(self, *, with_stats: bool = False) -> list[BpfProgram]:
        assert with_stats is True
        raise PermissionDeniedError(
            "permission denied while trying to list eBPF object IDs; run brr with sudo"
        )


def test_bare_brr_dispatches_to_top_with_root_options(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    service = object()
    monkeypatch.setattr(cli, "build_snapshot_service", lambda bpffs: service)

    def fake_run_tui(actual_service, config) -> int:
        captured.update(service=actual_service, config=config)
        return 23

    monkeypatch.setattr(cli, "run_tui", fake_run_tui)

    result = cli.main(["--bpffs", "/tmp/bpf", "-x", "-c", "-d", "2.5"])

    assert result == 23
    assert captured["service"] is service
    config = captured["config"]
    assert config.bpffs == "/tmp/bpf"
    assert config.extended is True
    assert config.cumulative is True
    assert config.delay == 2.5
    assert config.line_limit == 0


@pytest.mark.parametrize("args", [[], ["top"]])
def test_top_permission_error_is_returned_before_opening_tui(
    args: list[str],
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    monkeypatch.setattr(cli, "build_snapshot_service", lambda _bpffs: _DeniedTopService())

    assert cli.main(args) == 2

    assert capsys.readouterr().err == (
        "brr: permission denied while trying to list eBPF object IDs; run brr with sudo\n"
    )


def test_bare_and_explicit_top_options_build_the_same_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configs = []
    monkeypatch.setattr(cli, "build_snapshot_service", lambda _bpffs: object())
    monkeypatch.setattr(cli, "run_tui", lambda _service, config: configs.append(config) or 0)
    top_options = [
        "-d",
        "10",
        "--limit",
        "7",
        "--event",
        "cpu-clock",
        "--profile-duration",
        "3",
        "-F",
        "123",
        "--line-limit",
        "6",
        "--source-limit",
        "8",
        "--kernel-samples",
        "--kernel-ip-detail",
        "--call-graph",
        "fp",
        "--inspect-mode",
        "mixed",
        "--light",
        "--devmode",
        "/src",
        "--perf-buffer-pages",
        "8",
        "--perf-drain-ms",
        "25",
        "--fail-on-loss",
        "-x",
        "-c",
    ]

    assert cli.main(["--bpffs", "/tmp/bpf", *top_options]) == 0
    assert cli.main(["--bpffs", "/tmp/bpf", "top", *top_options]) == 0

    assert configs[0] == configs[1]


def test_bare_and_explicit_top_textmode_arguments_are_equivalent() -> None:
    parser = cli.build_parser()
    options = [
        "--textmode",
        "--profile-top",
        "--collapse-samples",
        "--program-id",
        "42",
    ]
    bare = parser.parse_args(options)
    explicit = parser.parse_args(["top", *options])

    cli._normalize_top_args(parser, bare)
    cli._normalize_top_args(parser, explicit)

    assert vars(bare) == vars(explicit)


def test_top_options_before_explicit_top_are_preserved_and_later_values_win(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delays = []
    monkeypatch.setattr(cli, "build_snapshot_service", lambda _bpffs: object())
    monkeypatch.setattr(cli, "run_tui", lambda _service, config: delays.append(config.delay) or 0)

    assert cli.main(["-d", "4", "top"]) == 0
    assert cli.main(["-d", "4", "top", "-d", "9"]) == 0

    assert delays == [4.0, 9.0]


def test_top_options_are_rejected_for_other_subcommands(capsys) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main(["-d", "10", "activity"])

    assert "top options may only be used" in capsys.readouterr().err


def test_line_limit_defaults_depend_on_top_mode() -> None:
    parser = cli.build_parser()

    interactive = cli.config_from_args(parser.parse_args(["top"]), bpffs="/sys/fs/bpf")
    textmode = cli.config_from_args(parser.parse_args(["top", "--textmode"]), bpffs="/sys/fs/bpf")
    overridden = cli.config_from_args(
        parser.parse_args(["top", "--line-limit", "7"]), bpffs="/sys/fs/bpf"
    )
    profile = parser.parse_args(["profile"])

    assert interactive.line_limit == 0
    assert textmode.line_limit == 10
    assert overridden.line_limit == 7
    assert profile.line_limit == 10


def test_kernel_ip_detail_is_available_for_profile_and_top() -> None:
    parser = cli.build_parser()

    profile = parser.parse_args(["profile", "--kernel-samples", "--kernel-ip-detail"])
    top = parser.parse_args(["top", "--kernel-samples", "--kernel-ip-detail"])
    config = cli.config_from_args(top, bpffs="/sys/fs/bpf")

    assert profile.kernel_ip_detail is True
    assert config.kernel_ip_detail is True


@pytest.mark.parametrize(
    "args",
    [
        ["profile", "--kernel-ip-detail"],
        ["top", "--kernel-ip-detail"],
        ["--kernel-ip-detail"],
    ],
)
def test_kernel_ip_detail_requires_kernel_samples(args: list[str], capsys) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main(args)

    assert "--kernel-ip-detail requires --kernel-samples" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--json", "--csv", "--pretty"])
def test_bare_output_flags_require_a_subcommand(flag: str, capsys) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main([flag])

    assert "use 'brr prog --json'" in capsys.readouterr().err


def test_prog_lists_programs(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    service = _ProgService()
    monkeypatch.setattr(cli, "build_snapshot_service", lambda _bpffs: service)

    assert cli.main(["prog", "--stats", "--json", "--pretty"]) == 0

    output = capsys.readouterr().out
    assert '"kind": "programs"' in output
    assert '"id": 7' in output
    assert service.with_stats == [True]


def test_prog_retains_csv_and_extended_options(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    service = _ProgService()
    monkeypatch.setattr(cli, "build_snapshot_service", lambda _bpffs: service)

    assert cli.main(["prog", "--csv"]) == 0
    assert "id,type,name" in capsys.readouterr().out
    assert cli.main(["prog", "-x"]) == 0
    assert "TAG" in capsys.readouterr().out


def test_list_command_is_removed(capsys) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main(["list"])

    assert "invalid choice: 'list'" in capsys.readouterr().err


def test_root_help_and_version_remain_available(capsys) -> None:
    with pytest.raises(SystemExit, match="0"):
        cli.main(["--help"])
    help_output = capsys.readouterr().out
    assert "{prog,activity," in help_output
    assert "list (prog)" not in help_output

    with pytest.raises(SystemExit, match="0"):
        cli.main(["--version"])
    version_output = capsys.readouterr().out
    assert version_output.startswith("brr 0.6.0")
    assert "eBPF Runtime Reporter and Profiler" in version_output


@pytest.mark.parametrize(
    "args",
    [
        ["--collapse-samples"],
        ["top", "--collapse-samples"],
        ["top", "--textmode", "--collapse-samples"],
        ["top", "--profile-top", "--collapse-samples"],
    ],
)
def test_collapse_samples_requires_profiled_textmode(args: list[str], capsys) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main(args)

    assert "--collapse-samples requires --textmode and --profile-top" in capsys.readouterr().err
