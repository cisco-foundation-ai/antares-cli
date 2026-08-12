# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""CWE database loading and lookup utilities."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True, frozen=True)
class CweTaxonomyMetadata:
    catalog: str
    version: str
    release_date: str
    source_url: str
    archive_sha256: str
    entry_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "catalog": self.catalog,
            "version": self.version,
            "release_date": self.release_date,
            "source_url": self.source_url,
            "archive_sha256": self.archive_sha256,
            "entry_count": self.entry_count,
        }


@dataclass(slots=True, frozen=True)
class CweEntry:
    id: str
    name: str
    description: str
    extended_description: str
    detection_methods: list[str]
    potential_mitigations: list[str]
    abstraction: str = ""
    structure: str = ""
    status: str = ""
    likelihood_of_exploit: str = ""
    related_weaknesses: list[dict[str, str]] = field(default_factory=list)
    applicable_platforms: list[dict[str, str]] = field(default_factory=list)
    modes_of_introduction: list[str] = field(default_factory=list)
    common_consequences: list[str] = field(default_factory=list)
    taxonomy_mappings: list[dict[str, str]] = field(default_factory=list)
    mapping_usage: str = ""
    mapping_rationale: str = ""
    view_ids: list[str] = field(default_factory=list)
    view_names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "extended_description": self.extended_description,
            "detection_methods": self.detection_methods,
            "potential_mitigations": self.potential_mitigations,
            "abstraction": self.abstraction,
            "structure": self.structure,
            "status": self.status,
            "likelihood_of_exploit": self.likelihood_of_exploit,
            "related_weaknesses": self.related_weaknesses,
            "applicable_platforms": self.applicable_platforms,
            "modes_of_introduction": self.modes_of_introduction,
            "common_consequences": self.common_consequences,
            "taxonomy_mappings": self.taxonomy_mappings,
            "mapping_usage": self.mapping_usage,
            "mapping_rationale": self.mapping_rationale,
            "view_ids": self.view_ids,
            "view_names": self.view_names,
        }


class CweDatabase:
    """Query interface for the bundled CWE knowledge base."""

    def __init__(
        self,
        entries: list[CweEntry],
        *,
        metadata: CweTaxonomyMetadata | None = None,
    ) -> None:
        self._entries = sorted(entries, key=_cwe_sort_key)
        self._entries_by_id = {entry.id.upper(): entry for entry in self._entries}
        self.metadata = metadata
        if metadata is not None and metadata.entry_count != len(entries):
            raise ValueError(
                f"CWE metadata declares {metadata.entry_count} entries, loaded {len(entries)}"
            )

    @classmethod
    def bundled_data_path(cls) -> Path:
        return Path(__file__).resolve().parent / "data" / "cwe_database.json"

    @classmethod
    def bundled_metadata_path(cls) -> Path:
        return Path(__file__).resolve().parent / "data" / "cwe_metadata.json"

    @classmethod
    def load_default(cls, data_path: Path | None = None) -> CweDatabase:
        resolved_data_path = data_path or cls.bundled_data_path()
        raw_entries = json.loads(resolved_data_path.read_text(encoding="utf-8"))
        entries = [CweEntry(**raw_entry) for raw_entry in raw_entries]
        metadata_path = (
            cls.bundled_metadata_path()
            if data_path is None
            else resolved_data_path.with_name("cwe_metadata.json")
        )
        metadata = None
        if metadata_path.exists():
            metadata = CweTaxonomyMetadata(**json.loads(metadata_path.read_text(encoding="utf-8")))
        return cls(entries, metadata=metadata)

    def get_by_id(self, cwe_id: str) -> CweEntry | None:
        normalized_id = cwe_id.upper().strip()
        if not normalized_id.startswith("CWE-"):
            normalized_id = f"CWE-{normalized_id}"
        return self._entries_by_id.get(normalized_id)

    def list_all(self) -> list[CweEntry]:
        return list(self._entries)


def _cwe_sort_key(entry: CweEntry) -> tuple[int, str]:
    try:
        return (int(entry.id.split("-", maxsplit=1)[1]), entry.id)
    except (IndexError, ValueError):
        return (10_000, entry.id)
