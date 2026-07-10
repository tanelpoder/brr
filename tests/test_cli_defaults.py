from __future__ import annotations

from typing import Any

import pytest

from brr import cli
from brr.models import BpfProgram


class _ListService:
    def __init__(self) -> None:
        self.with_stats: list[bool] = []

    def collect_programs(self, *, with_stats: bool = False) -> list[BpfProgram]:
        self.with_stats.append(with_stats)
        return [BpfProgram(id=7, program_type="xdp", name="pass")]


def test_bare_brr_dispatches_to_top_with_root_options(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    service = object()
    monkeypatch.setattr(cli, "build_snapshot_service", lambda bpffs: service)

    def fake_run_tui(actual_service, config) -> int:
        captured.update(service=actual_service, config=config)
        return 23

    monkeypatch.setattr(cli, "run_tui", fake_run_tui)

    result = cli.main(["--bpffs", "/tmp/bpf", "-x", "-c"])

    assert result == 23
    assert captured["service"] is service
    config = captured["config"]
    assert config.bpffs == "/tmp/bpf"
    assert config.extended is True
    assert config.cumulative is True
    assert config.delay == 1.0


@pytest.mark.parametrize("flag", ["--json", "--csv", "--pretty"])
def test_bare_output_flags_require_a_subcommand(flag: str, capsys) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main([flag])

    assert "use 'brr list --json'" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["list", "prog"])
def test_list_and_prog_have_identical_program_listing_behavior(
    command: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    service = _ListService()
    monkeypatch.setattr(cli, "build_snapshot_service", lambda _bpffs: service)

    assert cli.main([command, "--stats", "--json", "--pretty"]) == 0

    output = capsys.readouterr().out
    assert '"kind": "programs"' in output
    assert '"id": 7' in output
    assert service.with_stats == [True]


def test_list_retains_csv_and_extended_options(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    service = _ListService()
    monkeypatch.setattr(cli, "build_snapshot_service", lambda _bpffs: service)

    assert cli.main(["list", "--csv"]) == 0
    assert "id,type,name" in capsys.readouterr().out
    assert cli.main(["list", "-x"]) == 0
    assert "TAG" in capsys.readouterr().out


def test_root_help_and_version_remain_available(capsys) -> None:
    with pytest.raises(SystemExit, match="0"):
        cli.main(["--help"])
    help_output = capsys.readouterr().out
    assert "{list,prog," in help_output

    with pytest.raises(SystemExit, match="0"):
        cli.main(["--version"])
    assert "eBPF Runtime Reporter and Profiler" in capsys.readouterr().out


@pytest.mark.parametrize(
    "args",
    [
        ["top", "--collapse-samples"],
        ["top", "--textmode", "--collapse-samples"],
        ["top", "--profile-top", "--collapse-samples"],
    ],
)
def test_collapse_samples_requires_profiled_textmode(args: list[str], capsys) -> None:
    with pytest.raises(SystemExit, match="2"):
        cli.main(args)

    assert "--collapse-samples requires --textmode and --profile-top" in capsys.readouterr().err
