# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from antares_cli.core.service import _cwe_analysis_prompt, _cwe_context_block, _cwe_tasks
from antares_cli.knowledge.cwe_database import CweDatabase, CweEntry


def test_cwe_analysis_prompt_includes_natural_language_context() -> None:
    cwe_database = CweDatabase.load_default()

    prompt = _cwe_analysis_prompt(
        ["CWE-22"],
        cwe_database=cwe_database,
        query=None,
    )

    assert prompt is not None
    assert "Analyze this codebase for the following vulnerability class:" in prompt
    assert "CWE-22: Improper Limitation of a Pathname" in prompt
    assert "Path Traversal" in prompt
    assert "construct a pathname" in prompt
    assert "restricted directory" in prompt
    assert "submit the vulnerable file(s) or declare no vulnerability found" in prompt


def test_cwe_analysis_prompt_preserves_additional_instructions() -> None:
    cwe_database = CweDatabase.load_default()

    prompt = _cwe_analysis_prompt(
        ["CWE-22", "CWE-918"],
        cwe_database=cwe_database,
        query="Prioritize upload and archive handling code.",
    )

    assert prompt is not None
    assert "vulnerability classes" in prompt
    assert "CWE-22: Improper Limitation of a Pathname" in prompt
    assert "CWE-918: Server-Side Request Forgery" in prompt
    assert "request is being sent to the expected destination" in prompt
    assert "Additional instructions:\nPrioritize upload and archive handling code." in prompt


def test_placeholder_cwe_context_falls_back_to_identifier() -> None:
    cwe_database = CweDatabase(
        [
            CweEntry(
                id="CWE-999",
                name="Placeholder CWE 999",
                description="Offline placeholder entry generated to preserve broad sweep coverage.",
                extended_description="Replace with authoritative MITRE guidance.",
                detection_methods=[],
                potential_mitigations=[],
            )
        ]
    )

    assert _cwe_context_block("CWE-999", cwe_database=cwe_database) == "CWE-999"


def test_cwe_tasks_use_authoritative_description_context() -> None:
    cwe_database = CweDatabase.load_default()

    tasks = _cwe_tasks(
        ["CWE-22"],
        cwe_database=cwe_database,
        model_label="remote-1b-dense-sft",
        query=None,
    )

    assert len(tasks) == 1
    assert tasks[0].description.startswith(
        "Analyze this codebase for the following vulnerability class:"
    )
    assert "CWE-22: Improper Limitation of a Pathname" in tasks[0].description
    assert "construct a pathname" in tasks[0].description
    assert tasks[0].focus_cwe_ids == ["CWE-22"]
