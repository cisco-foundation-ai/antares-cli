# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from antares_cli.core.cwe import CweIdError, normalize_cwe_id, normalize_cwe_ids
from antares_cli.knowledge.cwe_database import CweDatabase


def test_normalize_cwe_id_accepts_loose_forms() -> None:
    assert normalize_cwe_id("22") == "CWE-22"
    assert normalize_cwe_id("cwe-22") == "CWE-22"
    assert normalize_cwe_id("CWE_022") == "CWE-22"
    assert normalize_cwe_id("CWE 89") == "CWE-89"


def test_normalize_cwe_id_rejects_invalid_values() -> None:
    with pytest.raises(CweIdError):
        normalize_cwe_id("not-a-cwe")
    with pytest.raises(CweIdError):
        normalize_cwe_id("CWE-0")


def test_normalize_cwe_ids_preserves_order_and_deduplicates() -> None:
    cwe_database = CweDatabase.load_default()

    assert normalize_cwe_ids(["89", "CWE-78", "cwe-89"], cwe_database) == [
        "CWE-89",
        "CWE-78",
    ]


def test_normalize_cwe_ids_rejects_unknown_ids() -> None:
    cwe_database = CweDatabase.load_default()

    with pytest.raises(CweIdError):
        normalize_cwe_ids(["CWE-99999"], cwe_database)
