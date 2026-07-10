from __future__ import annotations

import pytest

from brr.cli import build_parser
from brr.top import config_from_args


def test_profile_perf_buffer_options() -> None:
    args = build_parser().parse_args(
        [
            "profile",
            "--perf-buffer-pages",
            "64",
            "--perf-drain-ms",
            "25",
            "--fail-on-loss",
        ]
    )

    assert args.perf_buffer_pages == 64
    assert args.perf_drain_ms == 25
    assert args.fail_on_loss is True


def test_top_auto_perf_buffer_options() -> None:
    args = build_parser().parse_args(
        ["top", "--perf-buffer-pages", "auto", "--perf-drain-ms", "auto"]
    )
    config = config_from_args(args, bpffs="/sys/fs/bpf")

    assert config.perf_buffer_pages is None
    assert config.perf_drain_ms is None


def test_profile_rejects_non_power_of_two_pages() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["profile", "--perf-buffer-pages", "12"])
