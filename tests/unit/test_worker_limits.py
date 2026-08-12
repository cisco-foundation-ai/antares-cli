# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Sweep concurrency stays bounded at every entry point."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from antares_cli.core.service import SecurityWorkflowService, SweepRequest
from antares_cli.core.worker_limits import MAX_SWEEP_WORKERS, resolve_sweep_worker_count
from antares_cli.main import app


@pytest.mark.parametrize("value", [0, MAX_SWEEP_WORKERS + 1, True, "8"])
def test_worker_count_rejects_invalid_values(value: object) -> None:
    with pytest.raises(ValueError, match="workers"):
        resolve_sweep_worker_count(value)


def test_service_rejects_excessive_workers_at_its_boundary(tmp_path: Path) -> None:
    service = SecurityWorkflowService()

    with pytest.raises(ValueError, match="between 1 and 32"):
        service.run_cwe_sweep(
            SweepRequest(
                target=tmp_path,
                cwe_ids=["CWE-89"],
                workers=MAX_SWEEP_WORKERS + 1,
            )
        )


def test_cli_rejects_excessive_workers_before_starting_a_sweep(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["sweep", str(tmp_path), "--workers", str(MAX_SWEEP_WORKERS + 1)],
    )

    assert result.exit_code == 2
    assert str(MAX_SWEEP_WORKERS) in result.output
