# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Repository-owned licensing assets remain available from a clean checkout."""

from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ROOT_CWE_NOTICE = REPOSITORY_ROOT / "THIRD_PARTY_NOTICES.md"
PROJECT_LICENSE = REPOSITORY_ROOT / "LICENSE"
SPDX_PROJECT_LICENSE = REPOSITORY_ROOT / "LICENSES" / "Apache-2.0.txt"
PACKAGED_CWE_NOTICE = (
    REPOSITORY_ROOT / "src" / "antares_cli" / "knowledge" / "data" / "CWE_NOTICE.txt"
)


def test_mitre_cwe_notice_is_present_at_repository_and_package_boundaries() -> None:
    for notice_path in (ROOT_CWE_NOTICE, PACKAGED_CWE_NOTICE):
        notice = notice_path.read_text(encoding="utf-8")
        normalized_notice = " ".join(notice.split())
        assert "Copyright © 2006–2026, The MITRE Corporation" in normalized_notice
        assert "non-exclusive, royalty-free license to use CWE" in normalized_notice
        assert "https://cwe.mitre.org/about/termsofuse.html" in notice

    readme = " ".join((REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "[official CWE Terms of" in readme
    assert "[Apache License 2.0](LICENSE)" in readme


def test_apache_2_license_is_present() -> None:
    for license_path in (PROJECT_LICENSE, SPDX_PROJECT_LICENSE):
        license_text = license_path.read_text(encoding="utf-8")
        assert "Apache License" in license_text
        assert "Version 2.0, January 2004" in license_text
        assert "http://www.apache.org/licenses/" in license_text
