# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Reject hosted inference connection details embedded in the public wheel."""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from zipfile import ZipFile

_ALLOWED_URL_PREFIXES = (
    "https://cwe.mitre.org/",
    "https://json.schemastore.org/",
)
_ALLOWED_CREDENTIAL_ENVIRONMENT_NAMES = {"ANTARES_API_KEY"}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_public_wheel.py PATH_TO_WHEEL", file=sys.stderr)
        return 2

    wheel_path = Path(sys.argv[1])
    violations: list[str] = []
    with ZipFile(wheel_path) as wheel:
        for member in wheel.namelist():
            if not member.startswith("antares_cli/") or not member.endswith(".py"):
                continue
            source = wheel.read(member).decode("utf-8")
            tree = ast.parse(source, filename=member)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                value = node.value
                if value.startswith(("http://", "https://")) and not value.startswith(
                    _ALLOWED_URL_PREFIXES
                ):
                    violations.append(f"{member}:{node.lineno}: embedded URL")
                if (
                    value.endswith("_API_KEY")
                    and value.isidentifier()
                    and value not in _ALLOWED_CREDENTIAL_ENVIRONMENT_NAMES
                ):
                    violations.append(
                        f"{member}:{node.lineno}: provider-specific credential environment name"
                    )

    if violations:
        print("Public wheel contains hosted inference configuration:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print(f"Verified provider-neutral wheel: {wheel_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
