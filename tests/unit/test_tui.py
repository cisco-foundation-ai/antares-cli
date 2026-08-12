# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Textual TUI widgets and screens."""

from __future__ import annotations

from pathlib import Path

import pytest

from antares_cli.agent.subagent import WorkerResult
from antares_cli.core.service import SweepProgressEvent, SweepTaskDescriptor, WorkflowResult
from antares_cli.output.finding import Finding, ReportSummary
from antares_cli.tui.app import AntaresApp
from antares_cli.tui.runner import SweepRunner
from antares_cli.tui.screens.help_overlay import HelpOverlay
from antares_cli.tui.screens.sweep import SweepOverviewScreen, WorkerDetailScreen
from antares_cli.tui.widgets.activity import ActivityEntry
from antares_cli.tui.widgets.findings import _display_path
from antares_cli.tui.widgets.footer import FooterBar
from antares_cli.tui.widgets.header import HeaderBar
from antares_cli.tui.widgets.worker_list import WorkerStatus


def _make_finding(
    title: str = "SQL Injection",
    file_path: str = "src/db.py",
    cwe_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        file_path=file_path,
        cwe_ids=cwe_ids or ["CWE-89"],
        confidence=0.9,
    )


def _make_file_level_finding(
    *,
    title: str = "Deserialization of Untrusted Data",
    file_path: str = "src/db.py",
    cwe_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        file_path=file_path,
        cwe_ids=cwe_ids or ["CWE-502"],
        confidence=0.9,
        submission_rank=1,
    )


def test_display_path_preserves_complete_paths() -> None:
    assert _display_path("case_002/app.py") == "case_002/app.py"
    assert _display_path("/tmp/repo/case_002/app.py") == "/tmp/repo/case_002/app.py"
    assert _display_path("C:\\repo\\case_002\\app.py") == "C:/repo/case_002/app.py"


def test_activity_entries_preserve_full_commands_results_and_paths() -> None:
    command = (
        "terminal(command=cat "
        "/home/developer/projects/a-very-long-repository/app/services/orders.py)"
    )
    result = "first complete line\nsecond complete line\nthird complete line"

    command_rendered = (
        ActivityEntry(
            "command",
            command,
            workspace_root="/home/developer/projects/a-very-long-repository",
        )
        .render()
        .plain
    )
    result_rendered = ActivityEntry("result", result).render().plain

    assert "…" not in command_rendered
    assert "/home/developer/projects/a-very-long-repository" in command_rendered
    assert "orders.py" in command_rendered
    assert "…" not in result_rendered
    assert "first complete line" in result_rendered
    assert "second complete line" in result_rendered
    assert "third complete line" in result_rendered


def test_fixed_terminal_chrome_uses_fold_overflow() -> None:
    header = HeaderBar(
        mode="sweep",
        profile="a-long-profile",
        target="/home/developer/projects/a-very-long-repository",
    ).render()
    footer = FooterBar().render()
    help_text = HelpOverlay(mode="sweep-overview")._render_keybinds()

    assert header.overflow == "fold"
    assert footer.overflow == "fold"
    assert help_text.overflow == "fold"


@pytest.mark.asyncio(loop_scope="function")
async def test_sweep_screen_worker_list() -> None:
    app = AntaresApp(profile="test", target="/tmp/repo", sweep_label="CWE", worker_count=4)
    async with app.run_test():
        screen = app.screen
        assert isinstance(screen, SweepOverviewScreen)
        screen.worker_list.set_workers(["Task A", "Task B", "Task C", "Task D"])
        screen.worker_list.update_worker(0, status=WorkerStatus.DONE, finding_count=2)
        screen.worker_list.update_worker(1, status=WorkerStatus.RUNNING)


@pytest.mark.asyncio(loop_scope="function")
async def test_sweep_screen_renders_file_level_finding() -> None:
    app = AntaresApp(
        profile="test",
        target="/tmp/repo",
        sweep_label="CWE",
        worker_count=4,
    )
    async with app.run_test():
        screen = app.screen
        assert isinstance(screen, SweepOverviewScreen)

        screen.push_finding(_make_file_level_finding(file_path="src/db.py", cwe_ids=["CWE-89"]))

        card = screen.findings._cards[0]
        rendered = card.render().plain
        assert rendered.startswith("Deserialization of Untrusted Data")
        assert "HIGH" not in rendered
        assert "Rank 1 file-level submission" not in rendered


@pytest.mark.asyncio(loop_scope="function")
async def test_sweep_drill_in_and_back() -> None:
    app = AntaresApp(profile="test", target="/tmp/repo", sweep_label="CWE", worker_count=3)
    async with app.run_test() as pilot:
        screen = app.screen
        screen.worker_list.set_workers(["Check A", "Check B", "Check C"])
        screen.worker_list.focus()
        await pilot.pause()

        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, WorkerDetailScreen)

        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, SweepOverviewScreen)


@pytest.mark.asyncio(loop_scope="function")
async def test_sweep_runner_applies_service_events() -> None:
    app = AntaresApp(profile="test", target="/tmp/repo", sweep_label="CWE", worker_count=1)
    async with app.run_test():
        screen = app.screen
        assert isinstance(screen, SweepOverviewScreen)
        screen.worker_list.set_workers(["CWE-89"])
        finding = _make_finding()
        descriptor = SweepTaskDescriptor(
            worker_index=0,
            label="CWE-89",
            focus_cwe_ids=["CWE-89"],
        )
        per_cwe_results = [
            {
                "cwe_id": "CWE-89",
                "investigation_trace": "/tmp/cwe-89.investigation.jsonl",
            }
        ]
        workflow_result = WorkflowResult(
            findings=[finding],
            summary=ReportSummary(
                total_findings=1,
                tool_call_count=3,
                duration_seconds=1.0,
                cwe_ids_triggered=["CWE-89"],
            ),
            metadata={},
            per_cwe_results=per_cwe_results,
        )
        runner = SweepRunner(
            app=app,
            run_sweep=lambda progress_callback: workflow_result,
            target_path=Path("/tmp/repo"),
            worker_labels=["CWE-89"],
        )

        runner._apply_sweep_event(SweepProgressEvent("started", descriptor))
        assert screen.worker_list.get_worker_info(0) == ("CWE-89", WorkerStatus.RUNNING)

        runner._apply_sweep_event(
            SweepProgressEvent(
                "completed",
                descriptor,
                result=WorkerResult(
                    task_id="cwe-89",
                    findings=[finding],
                    tool_call_count=3,
                    duration_seconds=1.0,
                ),
            )
        )
        assert screen.worker_list.get_worker_info(0) == ("CWE-89", WorkerStatus.DONE)
        assert screen.findings.count == 1

        runner._result = workflow_result
        runner._on_complete()
        assert screen._per_cwe_results == per_cwe_results


def test_sweep_runner_retains_service_exceptions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = AntaresApp(profile="test", target=str(tmp_path), sweep_label="CWE", worker_count=1)
    expected_error = RuntimeError("endpoint disconnected")

    def fail(_progress_callback):
        raise expected_error

    monkeypatch.setattr(app, "call_from_thread", lambda *_args, **_kwargs: None)
    runner = SweepRunner(
        app=app,
        run_sweep=fail,
        target_path=tmp_path,
        worker_labels=["CWE-89"],
    )

    runner._run()

    assert runner.result is None
    assert runner.error is expected_error


@pytest.mark.asyncio(loop_scope="function")
async def test_failed_worker_terminates_open_detail_screen() -> None:
    app = AntaresApp(
        profile="test",
        target="/tmp/repo",
        sweep_label="CWE",
        worker_count=1,
    )
    async with app.run_test() as pilot:
        overview = app.screen
        assert isinstance(overview, SweepOverviewScreen)
        overview.worker_list.set_workers(["CWE-89"])
        detail = WorkerDetailScreen(worker_id=0, worker_label="CWE-89", total_workers=1)
        app.push_screen(detail)
        await pilot.pause()
        workflow_result = WorkflowResult(
            findings=[],
            summary=ReportSummary(
                total_findings=0,
                tool_call_count=0,
                duration_seconds=1.0,
                cwe_ids_triggered=[],
            ),
            metadata={},
        )
        runner = SweepRunner(
            app=app,
            run_sweep=lambda _progress_callback: workflow_result,
            target_path=Path("/tmp/repo"),
            worker_labels=["CWE-89"],
        )
        descriptor = SweepTaskDescriptor(
            worker_index=0,
            label="CWE-89",
            focus_cwe_ids=["CWE-89"],
        )
        failed_result = WorkerResult(
            task_id="cwe-89",
            findings=[],
            tool_call_count=2,
            duration_seconds=1.0,
            error_message="endpoint timed out",
        )

        runner._apply_sweep_event(
            SweepProgressEvent(
                "failed",
                descriptor,
                result=failed_result,
                error_message=failed_result.error_message,
            )
        )

        assert detail._detail_active is False
        assert any("endpoint timed out" in entry._content for entry in detail.activity._entries)
        assert overview.worker_list.get_worker_info(0) == ("CWE-89", WorkerStatus.FAILED)


@pytest.mark.asyncio(loop_scope="function")
async def test_footer_progress_updates() -> None:
    app = AntaresApp(profile="test", target="/tmp/repo", sweep_label="CWE", worker_count=1)
    async with app.run_test():
        screen = app.screen
        screen.footer_bar.update_progress(
            files_done=10,
            files_total=50,
            finding_count=3,
            context_percent=60,
            elapsed_seconds=5.5,
        )
