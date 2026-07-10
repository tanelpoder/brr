from __future__ import annotations

import pytest

from brr.models import BpfProgramActivity
from brr.render.brr_text import render_brr_activity
from brr.render.text import render_program_activity
from brr.reporter import BrrActivityItem, BrrActivityReport
from brr.top import _visible_top_activity_columns


def _activity() -> BpfProgramActivity:
    return BpfProgramActivity(
        id=7,
        program_type="xdp",
        name="pass",
        tag=None,
        run_count_delta=4,
        run_time_ns_delta=200,
        run_count_total=10,
        run_time_ns_total=800,
    )


@pytest.mark.parametrize("cumulative", [False, True])
def test_ns_per_second_follows_cumulative_text_display(cumulative: bool) -> None:
    activity = _activity()
    report = BrrActivityReport(
        duration=2.0,
        items=[BrrActivityItem(activity=activity, bpf_percent=0.00001)],
    )

    rendered = (
        render_program_activity([activity], duration=2.0, cumulative=cumulative),
        render_brr_activity(report, cumulative=cumulative),
    )

    for text in rendered:
        assert ("NS_PER/s" in text) is cumulative


def test_ns_per_second_follows_cumulative_tui_columns() -> None:
    default_columns = {label for label, _right in _visible_top_activity_columns(False, False)}
    cumulative_columns = {label for label, _right in _visible_top_activity_columns(True, False)}

    assert "NS_PER/s" not in default_columns
    assert "NS_PER/s" in cumulative_columns
