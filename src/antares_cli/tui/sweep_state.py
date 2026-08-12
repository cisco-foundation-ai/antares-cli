# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""State container for sweep TUI worker progress."""

from __future__ import annotations

import time

from antares_cli.agent.subagent import WorkerResult
from antares_cli.output.finding import Finding, TrajectoryEntry
from antares_cli.output.renderer import AgentStateSnapshot


class SweepWorkerStore:
    """Owns per-worker sweep progress, dedupe, and replay data."""

    def __init__(
        self,
        *,
        started_at: float,
    ) -> None:
        self._started_at = started_at
        self._worker_results: dict[int, WorkerResult] = {}
        self._worker_start_times: dict[int, float] = {}
        self._worker_trajectory_lengths: dict[int, int] = {}
        self._findings_pushed_per_worker: dict[int, int] = {}
        self._worker_trajectories: dict[int, list[TrajectoryEntry]] = {}
        self._worker_findings: dict[int, list[Finding]] = {}
        self._worker_focus_cwe_ids: dict[int, list[str]] = {}
        self._worker_seen_finding_keys: dict[int, set[tuple[object, ...]]] = {}

    @property
    def completed_count(self) -> int:
        return len(self._worker_results)

    @property
    def total_finding_count(self) -> int:
        return sum(len(findings) for findings in self._worker_findings.values())

    def set_focus_cwe_ids(self, worker_id: int, focus_cwe_ids: list[str]) -> None:
        self._worker_focus_cwe_ids[worker_id] = list(focus_cwe_ids)

    def focus_cwe_ids(self, worker_id: int) -> list[str]:
        return self._worker_focus_cwe_ids.get(worker_id, [])

    def mark_started(self, worker_id: int) -> None:
        self._worker_start_times[worker_id] = time.perf_counter()

    def start_time(self, worker_id: int) -> float | None:
        return self._worker_start_times.get(worker_id)

    def elapsed(self, worker_id: int) -> float:
        return time.perf_counter() - self._worker_start_times.get(worker_id, self._started_at)

    def record_progress(
        self,
        worker_id: int,
        state: AgentStateSnapshot,
        finding: Finding | None,
    ) -> tuple[list[TrajectoryEntry], Finding | None]:
        trajectory: list[TrajectoryEntry] = getattr(state, "trajectory", [])
        prev_length = self._worker_trajectory_lengths.get(worker_id, 0)
        new_entries = trajectory[prev_length:]
        self._worker_trajectory_lengths[worker_id] = len(trajectory)
        self._worker_trajectories.setdefault(worker_id, []).extend(new_entries)
        accepted_finding = finding if self.accept_finding(worker_id, finding) else None
        return new_entries, accepted_finding

    def mark_completed(self, worker_id: int, result: WorkerResult) -> None:
        self._worker_results[worker_id] = result
        for finding in result.findings:
            self.accept_finding(worker_id, finding)

    def result(self, worker_id: int) -> WorkerResult | None:
        return self._worker_results.get(worker_id)

    def accept_finding(self, worker_id: int, finding: Finding | None) -> bool:
        if finding is None:
            return False
        seen_keys = self._worker_seen_finding_keys.setdefault(worker_id, set())
        key = _finding_key(finding)
        if key in seen_keys:
            return False
        seen_keys.add(key)
        self._worker_findings.setdefault(worker_id, []).append(finding)
        return True

    def trajectories(self, worker_id: int) -> list[TrajectoryEntry]:
        return self._worker_trajectories.get(worker_id, [])

    def findings(self, worker_id: int) -> list[Finding]:
        return self._worker_findings.get(worker_id, [])

    def pushed_count(self, worker_id: int) -> int:
        return self._findings_pushed_per_worker.get(worker_id, 0)

    def increment_pushed_count(self, worker_id: int) -> None:
        self._findings_pushed_per_worker[worker_id] = self.pushed_count(worker_id) + 1

    def set_pushed_count(self, worker_id: int, pushed_count: int) -> None:
        self._findings_pushed_per_worker[worker_id] = pushed_count

    def tool_call_count(self, worker_id: int) -> int:
        return sum(
            1
            for entry in self._worker_trajectories.get(worker_id, [])
            if entry.entry_type == "tool_call"
        )


def _finding_key(finding: Finding) -> tuple[object, ...]:
    return (
        finding.file_path,
        finding.title,
        tuple(finding.cwe_ids),
    )
