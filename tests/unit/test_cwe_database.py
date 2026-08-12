# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from antares_cli.knowledge.cwe_database import CweDatabase


def test_cwe_database_queries() -> None:
    cwe_database = CweDatabase.load_default()

    sql_injection_entry = cwe_database.get_by_id("CWE-89")
    assert sql_injection_entry is not None
    assert "SQL Injection" in sql_injection_entry.name
    entries = cwe_database.list_all()
    assert len(entries) == 969
    assert all(not entry.name.startswith("Placeholder CWE") for entry in entries)


def test_bundled_cwe_database_reports_release_provenance() -> None:
    database = CweDatabase.load_default()

    assert database.metadata is not None
    assert database.metadata.version == "4.20"
    assert database.metadata.release_date == "2026-04-30"
    assert database.metadata.entry_count == len(database.list_all())
    assert database.metadata.source_url == "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
