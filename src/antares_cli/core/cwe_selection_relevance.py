# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Repository relevance checks for MITRE CWE auto selection."""

from __future__ import annotations

from antares_cli.core.cwe_selection_models import RepositoryProfile, ScanScope
from antares_cli.core.cwe_selection_scopes import (
    CURRENT_OWASP_VIEW_ID,
    CURRENT_TOP_25_VIEW_ID,
)
from antares_cli.knowledge.cwe_database import CweEntry

_BROAD_LANGUAGE_CLASSES = {
    "Compiled",
    "Interpreted",
    "Memory-Unsafe",
    "Not Language-Specific",
    "Object-Oriented",
}
_BROAD_LANGUAGE_NAMES = {
    "",
    "Language-Independent",
    "Not Language-Specific",
    "SQL",
    "Unknown",
}
_UNRESTRICTED_LANGUAGE_CLASSES = {"Not Language-Specific"}
_UNRESTRICTED_LANGUAGE_NAMES = {"Language-Independent", "Not Language-Specific", "Unknown"}
_BROAD_TECHNOLOGY_CLASSES = {"", "Not Technology-Specific"}
_BROAD_TECHNOLOGY_NAMES = {"", "Not Technology-Specific"}
_LANGUAGE_NAME_TO_PROFILE = {
    "ASP.NET": "csharp",
    "C": "c",
    "C#": "csharp",
    "C++": "cpp",
    "Go": "go",
    "Java": "java",
    "JavaScript": "javascript",
    "Perl": "perl",
    "PHP": "php",
    "Python": "python",
    "Ruby": "ruby",
    "Shell": "shell",
    "Swift": "swift",
    "TypeScript": "typescript",
    "Verilog": "verilog",
    "VHDL": "vhdl",
    "XML": "xml",
}
_LANGUAGE_CLASS_TO_PROFILES = {
    "Compiled": {"c", "cpp", "csharp", "go", "java", "rust", "swift", "verilog", "vhdl"},
    "Hardware Description Language": {"verilog", "vhdl"},
    "Interpreted": {"javascript", "perl", "php", "python", "ruby", "shell", "typescript"},
    "Memory-Unsafe": {"c", "cpp"},
    "Object-Oriented": {
        "cpp",
        "csharp",
        "java",
        "javascript",
        "php",
        "python",
        "ruby",
        "swift",
        "typescript",
    },
}
_WEB_PROFILE_HINTS = {
    "django",
    "express",
    "fastapi",
    "flask",
    "next",
    "rails",
    "react",
    "spring",
}
_MOBILE_PROFILE_HINTS = {"android", "ios", "mobile", "react-native", "swift"}
_AI_PROFILE_HINTS = {"keras", "pytorch", "scikit-learn", "sklearn", "tensorflow", "torch"}
_HARDWARE_PROFILE_LANGUAGES = {"verilog", "vhdl"}


def exclusion_reason(
    entry: CweEntry,
    _profile: RepositoryProfile,
    scope: ScanScope,
) -> str | None:
    if entry.status == "Deprecated":
        return "Excluded because MITRE marks this CWE as Deprecated"
    return _scope_exclusion_reason(entry, scope)


def auto_selection_reasons(
    entry: CweEntry,
    scope: ScanScope,
    exact_platform_match: bool,
) -> tuple[str, ...]:
    reasons = ["Included from the authoritative MITRE CWE taxonomy"]
    if "CWE-699" in entry.view_ids:
        reasons.append("MITRE Software Development taxonomy member")
    if exact_platform_match:
        reasons.append("Repository language or technology evidence matches MITRE platforms")
    else:
        reasons.append("Included because repository evidence does not rule it out")
    if scope != "auto":
        reasons.append(f"User selected the {scope} candidate set")
    return tuple(reasons)


def has_exact_platform_match(entry: CweEntry, profile: RepositoryProfile) -> bool:
    return bool(
        _concrete_entry_languages(entry) & set(profile.languages)
        or (_entry_has_web_platform(entry) and _has_web_evidence(profile))
        or (_entry_has_mobile_platform(entry) and _has_mobile_evidence(profile))
        or (_entry_has_ai_platform(entry) and _has_ai_evidence(profile))
        or (_entry_has_hardware_platform(entry) and _has_hardware_evidence(profile))
        or (_has_cloud_platform(entry) and (profile.iac_signals or "cloud" in profile.frameworks))
    )


def has_concrete_language_mismatch(entry: CweEntry, profile: RepositoryProfile) -> bool:
    """Return whether concrete MITRE language examples miss known repository languages."""
    return _language_exclusion_reason(entry, profile) is not None


def _scope_exclusion_reason(
    entry: CweEntry,
    scope: ScanScope,
) -> str | None:
    if scope == "top25" and CURRENT_TOP_25_VIEW_ID not in entry.view_ids:
        return "Excluded because top25 mode only scans the current MITRE CWE Top 25"
    if scope == "owasp" and CURRENT_OWASP_VIEW_ID not in entry.view_ids:
        return "Excluded because owasp mode only scans the current MITRE OWASP Top Ten view"
    return None


def _language_exclusion_reason(entry: CweEntry, profile: RepositoryProfile) -> str | None:
    expected_languages = _concrete_entry_languages(entry)
    if (
        not expected_languages
        or _has_unrestricted_language_applicability(entry)
        or _language_classes_match_profile(entry, profile)
        or not profile.languages
    ):
        return None
    if set(profile.languages) & expected_languages:
        return None
    return (
        "Excluded because MITRE marks this CWE as language-specific and the "
        "repository profile has different languages"
    )


def _concrete_entry_languages(entry: CweEntry) -> set[str]:
    concrete: set[str] = set()
    for platform in entry.applicable_platforms:
        if platform.get("type") != "Language":
            continue
        platform_class = platform.get("class", "")
        platform_name = platform.get("name", "")
        if platform_class in _BROAD_LANGUAGE_CLASSES or platform_name in _BROAD_LANGUAGE_NAMES:
            continue
        mapped = _LANGUAGE_NAME_TO_PROFILE.get(platform_name)
        if mapped is not None:
            concrete.add(mapped)
    return concrete


def _has_unrestricted_language_applicability(entry: CweEntry) -> bool:
    return any(
        platform.get("type") == "Language"
        and (
            platform.get("class", "") in _UNRESTRICTED_LANGUAGE_CLASSES
            or platform.get("name", "") in _UNRESTRICTED_LANGUAGE_NAMES
        )
        for platform in entry.applicable_platforms
    )


def _language_classes_match_profile(entry: CweEntry, profile: RepositoryProfile) -> bool:
    profile_languages = set(profile.languages)
    return any(
        profile_languages & _LANGUAGE_CLASS_TO_PROFILES.get(platform.get("class", ""), set())
        for platform in entry.applicable_platforms
        if platform.get("type") == "Language"
    )


def _concrete_technologies(entry: CweEntry) -> list[dict[str, str]]:
    concrete: list[dict[str, str]] = []
    for platform in entry.applicable_platforms:
        if platform.get("type") != "Technology":
            continue
        platform_class = platform.get("class", "")
        platform_name = platform.get("name", "")
        if platform_class in _BROAD_TECHNOLOGY_CLASSES and platform_name in _BROAD_TECHNOLOGY_NAMES:
            continue
        concrete.append(platform)
    return concrete


def _entry_has_web_platform(entry: CweEntry) -> bool:
    return any(_is_web_technology(platform) for platform in _concrete_technologies(entry))


def _entry_has_mobile_platform(entry: CweEntry) -> bool:
    return any(_is_mobile_technology(platform) for platform in _concrete_technologies(entry))


def _entry_has_ai_platform(entry: CweEntry) -> bool:
    return any(_is_ai_technology(platform) for platform in _concrete_technologies(entry))


def _entry_has_hardware_platform(entry: CweEntry) -> bool:
    return any(_is_hardware_technology(platform) for platform in _concrete_technologies(entry))


def _has_cloud_platform(entry: CweEntry) -> bool:
    return any(
        "Cloud" in platform.get("class", "") or "Cloud" in platform.get("name", "")
        for platform in _concrete_technologies(entry)
    )


def _is_web_technology(platform: dict[str, str]) -> bool:
    return bool({"Web Based", "Web Server", "Browser"} & _platform_values(platform))


def _is_mobile_technology(platform: dict[str, str]) -> bool:
    return "Mobile" in _platform_values(platform)


def _is_ai_technology(platform: dict[str, str]) -> bool:
    return bool({"AI/ML", "Machine Learning"} & _platform_values(platform))


def _is_hardware_technology(platform: dict[str, str]) -> bool:
    values = _platform_values(platform)
    hardware_markers = (
        "Bus/Interface",
        "Hardware",
        "ICS/OT",
        "Memory Hardware",
        "Microcontroller Hardware",
        "Power Management",
        "Processor Hardware",
        "Security Hardware",
        "Sensor",
        "System on Chip",
    )
    return any(marker in value for value in values for marker in hardware_markers)


def _platform_values(platform: dict[str, str]) -> set[str]:
    return {platform.get("class", ""), platform.get("name", "")}


def _has_web_evidence(profile: RepositoryProfile) -> bool:
    return bool(
        set(profile.frameworks) & _WEB_PROFILE_HINTS
        or profile.route_files
        or profile.request_input_signals
        or profile.template_signals
        or profile.upload_signals
    )


def _has_hardware_evidence(profile: RepositoryProfile) -> bool:
    return bool(set(profile.languages) & _HARDWARE_PROFILE_LANGUAGES)


def _has_mobile_evidence(profile: RepositoryProfile) -> bool:
    return bool(set(profile.frameworks) & _MOBILE_PROFILE_HINTS or "swift" in profile.languages)


def _has_ai_evidence(profile: RepositoryProfile) -> bool:
    return bool(set(profile.frameworks) & _AI_PROFILE_HINTS)
