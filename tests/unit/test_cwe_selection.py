# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
import typer
from typer.main import get_command
from typer.testing import CliRunner

from antares_cli.commands import sweep as sweep_module
from antares_cli.commands import tool as tool_module
from antares_cli.commands import wizard as wizard_module
from antares_cli.commands._selection_options import parse_scan_scope
from antares_cli.commands.sweep import _selection_preview_lines
from antares_cli.core.cwe_selection import (
    CweSelectionRequest,
    CweSelectionService,
    _repository_specific_quota,
    _repository_specific_sort_key,
    _taxonomy_priority_score,
)
from antares_cli.core.cwe_selection_models import CweAbstractionLevel, ScanScope, SelectedCheck
from antares_cli.core.cwe_selection_profile import RepositoryProfiler
from antares_cli.core.service import SecurityWorkflowService, SweepRequest
from antares_cli.knowledge.cwe_database import CweDatabase, CweEntry
from antares_cli.main import app

runner = CliRunner()


def test_default_automatic_selection_is_bounded(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "web-app"\ndependencies = ["fastapi"]\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI, Request\napp = FastAPI()\n",
        encoding="utf-8",
    )

    service = CweSelectionService()
    plan = service.select(CweSelectionRequest(target=tmp_path))

    assert len(plan.cwe_ids()) == 50


def test_automatic_selection_is_invariant_to_repository_directory_name(tmp_path: Path) -> None:
    selected_ids = []
    for directory_name in ("u4RwYlPm", "ordinary-project"):
        repository = tmp_path / directory_name
        repository.mkdir()
        (repository / "app.py").write_text(
            "import json\nimport logging\npayload = json.loads(raw)\nlogging.info(payload)\n",
            encoding="utf-8",
        )
        plan = CweSelectionService().select(CweSelectionRequest(target=repository))
        selected_ids.append(plan.cwe_ids())

    assert selected_ids[0] == selected_ids[1]


def test_auto_ranking_does_not_reward_top25_membership() -> None:
    base_entry = CweEntry(
        id="CWE-1",
        name="Example",
        description="Example",
        extended_description="",
        detection_methods=[],
        potential_mitigations=[],
        abstraction="Base",
        status="Stable",
    )
    top25_entry = replace(base_entry, id="CWE-2", view_ids=["CWE-1435"])

    assert _taxonomy_priority_score(base_entry, scope="auto") == _taxonomy_priority_score(
        top25_entry,
        scope="auto",
    )


def test_broad_mitre_platform_marker_is_not_treated_as_language_exclusive(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert not any(check.check_id == "cwe-434" for check in plan.excluded_checks)


def test_mitre_language_class_can_match_when_example_language_does_not(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.py").write_text("print('service')\n", encoding="utf-8")

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert not any(check.check_id == "cwe-96" for check in plan.excluded_checks)


def test_auto_scope_ranks_platform_mismatches_instead_of_excluding_them(
    tmp_path: Path,
) -> None:
    (tmp_path / "lib.rs").write_text(
        "pub unsafe fn read(ptr: *const u8) -> u8 { *ptr }\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))
    excluded_ids = {check.check_id for check in plan.excluded_checks}

    assert "cwe-787" not in excluded_ids
    assert "cwe-345" not in excluded_ids


def test_broad_mitre_platform_marker_is_not_treated_as_technology_exclusive(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert not any(check.check_id == "cwe-33" for check in plan.excluded_checks)


def test_top25_mode_selects_the_complete_current_top_25(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text("print('service')\n", encoding="utf-8")
    current_top_25 = {
        entry.id for entry in CweDatabase.load_default().list_all() if "CWE-1435" in entry.view_ids
    }

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path, scope="top25"))

    assert len(current_top_25) == 25
    assert plan.candidate_cwe_count == 25
    assert set(plan.cwe_ids()) == current_top_25
    assert {"CWE-20", "CWE-200", "CWE-284"} <= set(plan.cwe_ids())
    assert any("Top25 mode" in note for note in plan.selection_notes)


def test_owasp_mode_uses_the_current_mitre_owasp_view(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text("print('service')\n", encoding="utf-8")
    database = CweDatabase.load_default()
    current_owasp = {
        entry.id
        for entry in database.list_all()
        if "CWE-1450" in entry.view_ids and entry.status != "Deprecated"
    }

    plan = CweSelectionService(cwe_database=database).select(
        CweSelectionRequest(target=tmp_path, scope="owasp")
    )

    assert plan.candidate_cwe_count == len(current_owasp)
    assert set(plan.cwe_ids()) <= current_owasp
    assert any("OWASP mode" in note for note in plan.selection_notes)


@pytest.mark.parametrize(
    "removed_scope",
    ["all", "web", "api", "native", "iac", "secrets", "catalog"],
)
def test_removed_scope_names_are_rejected(removed_scope: str) -> None:
    with pytest.raises(typer.BadParameter, match="auto, top25, owasp"):
        parse_scan_scope(removed_scope)


def test_explicit_cwe_selection_is_uncapped_and_preserves_order(tmp_path: Path) -> None:
    requested_ids = [entry.id for entry in CweDatabase.load_default().list_all()[:30]]

    plan = CweSelectionService().select(
        CweSelectionRequest(
            target=tmp_path,
            cwe_ids=requested_ids,
            max_cwes=1,
        )
    )

    assert plan.cwe_ids() == requested_ids
    assert plan.automatic_limit is None
    assert plan.to_dict()["truncated"] is False


@pytest.mark.parametrize(
    "scope",
    ["auto", "top25", "owasp"],
)
def test_every_automatic_scope_remains_bounded(scope: str, tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text("print('service')\n", encoding="utf-8")

    plan = CweSelectionService().select(
        CweSelectionRequest(target=tmp_path, scope=cast(ScanScope, scope))
    )

    assert 0 < len(plan.cwe_ids()) <= 50
    assert plan.candidate_cwe_count >= len(plan.cwe_ids())


@pytest.mark.parametrize("cwe_level", ["pillar", "class", "base", "variant", "compound"])
def test_automatic_abstraction_filter_is_applied_before_ranking(
    cwe_level: str,
    tmp_path: Path,
) -> None:
    (tmp_path / "service.py").write_text("print('service')\n", encoding="utf-8")
    database = CweDatabase.load_default()

    plan = CweSelectionService(cwe_database=database).select(
        CweSelectionRequest(
            target=tmp_path,
            cwe_level=cast(CweAbstractionLevel, cwe_level),
        )
    )

    assert plan.cwe_ids()
    assert all(
        database.get_by_id(cwe_id).abstraction.lower() == cwe_level
        for cwe_id in plan.cwe_ids()
        if database.get_by_id(cwe_id) is not None
    )


def test_automatic_selection_honors_a_smaller_requested_limit(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path, max_cwes=7))

    assert len(plan.cwe_ids()) == 7


def test_automatic_selection_allows_limits_above_fifty(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path, max_cwes=100))

    assert len(plan.cwe_ids()) == 100
    assert plan.to_dict()["selection_tier_counts"] == {"ranked-fill": 100}
    assert any("neither a ranking signal" in note for note in plan.selection_notes)


def test_plan_command_accepts_limits_above_fifty(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["plan", str(tmp_path), "--max-cwes", "100", "--format", "json"],
    )

    assert result.exit_code == 0
    assert len(json.loads(result.stdout)["selected_cwe_ids"]) == 100


@pytest.mark.parametrize("max_cwes", [-1, 0])
def test_programmatic_automatic_selection_rejects_non_positive_limits(
    max_cwes: int,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="max_cwes must be at least 1"):
        CweSelectionService().select(CweSelectionRequest(target=tmp_path, max_cwes=max_cwes))


def test_automatic_plan_reports_when_candidates_were_truncated(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    payload = (
        CweSelectionService().select(CweSelectionRequest(target=tmp_path, max_cwes=7)).to_dict()
    )

    assert payload["automatic_limit"] == 7
    assert payload["candidate_cwe_count"] > 7
    assert payload["omitted_candidate_count"] == payload["candidate_cwe_count"] - 7
    assert payload["truncated"] is True


def test_plan_command_exposes_the_automatic_cwe_limit(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["plan", str(tmp_path), "--max-cwes", "7", "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["automatic_limit"] == 7
    assert len(payload["selected_cwe_ids"]) == 7
    assert payload["selection_policy"] == "mitre_mode_aware_repository_relevance_v6"
    assert payload["taxonomy"]["version"] == "4.20"
    assert payload["selection_tier_counts"] == {"ranked-fill": 7}
    assert any("neither a ranking signal" in note for note in payload["selection_notes"])
    assert any("low confidence" in note for note in payload["selection_notes"])
    assert payload["priority_baseline"] is None
    assert all(check["ranking_score"] >= 0 for check in payload["selected_checks"])


def test_plan_command_rejects_removed_scope_names(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["plan", str(tmp_path), "--scope", "catalog", "--max-cwes", "3", "--format", "json"],
    )

    assert result.exit_code == 2
    assert "scope must be one of: auto, top25, owasp" in result.output


def test_plan_summary_explains_automatic_selection_logic(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    result = runner.invoke(app, ["plan", str(tmp_path), "--max-cwes", "7"])

    assert result.exit_code == 0
    assert "Automatic selection: 7 of" in result.stdout
    assert "eligible CWE candidates" in result.stdout
    assert "Priority baseline:" not in result.stdout
    assert "neither a ranking signal" in result.stdout
    assert "low confidence" in result.stdout
    assert "MITRE CWE 4.20" in result.stdout
    assert "direct source evidence" in result.stdout
    assert "Portfolio: 7 ranked-fill" in result.stdout


def test_sweep_preview_uses_the_requested_automatic_cwe_limit(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")

    workers = (
        SecurityWorkflowService()
        .preview_sweep_details(SweepRequest(target=tmp_path, max_cwes=7))
        .workers
    )

    assert len(workers) == 7


def test_sweep_preview_exposes_selection_plan_and_display_logic(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('service')\n", encoding="utf-8")
    request = SweepRequest(target=tmp_path, max_cwes=7)

    preview = SecurityWorkflowService().preview_sweep_details(request)
    display = "\n".join(_selection_preview_lines(preview.selection_plan, request))

    assert len(preview.workers) == 7
    assert preview.selection_plan.candidate_cwe_count > 7
    assert "Automatic selection: 7 of" in display
    assert "Priority baseline:" not in display
    assert "Portfolio: 7 ranked-fill" in display
    assert "Selected CWEs: CWE-" in display
    assert "Full rationale: antares plan" in display


def test_plan_and_sweep_profiling_honor_project_ignore_paths(tmp_path: Path) -> None:
    ignored = tmp_path / "generated"
    ignored.mkdir()
    (ignored / "dangerous.py").write_text(
        "import subprocess\nsubprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text("print('visible')\n", encoding="utf-8")
    (tmp_path / ".antares.toml").write_text(
        'ignore_paths = ["generated/**"]\n',
        encoding="utf-8",
    )

    preview = SecurityWorkflowService().preview_sweep_details(
        SweepRequest(target=tmp_path, max_cwes=7)
    )
    profiled_paths = {
        path
        for paths in preview.selection_plan.profile.cwe_evidence_files.values()
        for path in paths
    }
    plan_result = runner.invoke(app, ["plan", str(tmp_path), "--format", "json"])

    assert plan_result.exit_code == 0
    assert "generated/dangerous.py" not in profiled_paths
    assert "generated/dangerous.py" not in plan_result.output


def test_sweep_command_exposes_the_automatic_cwe_limit() -> None:
    sweep_command = get_command(app).commands["sweep"]
    max_cwes_option = next(
        parameter for parameter in sweep_command.params if "--max-cwes" in parameter.opts
    )
    scope_option = next(
        parameter for parameter in sweep_command.params if "--scope" in parameter.opts
    )

    assert max_cwes_option.default == 50
    assert max_cwes_option.show_default is True
    assert "ignored with --cwe" in max_cwes_option.help
    assert scope_option.default == "auto"
    assert scope_option.help == "Automatic candidate set: auto, top25, or owasp."


def test_wizard_propagates_the_automatic_cwe_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = wizard_module.WizardResult(
        target=tmp_path,
        mode="sweep",
        focus="",
        profile_name="test-profile",
        output_path=None,
        output_format=None,
        workers=3,
        max_cwes=7,
    )
    captured: list[sweep_module.SweepCommandOptions] = []
    monkeypatch.setattr(wizard_module, "capture_invocation", lambda argv: argv)
    monkeypatch.setattr(
        sweep_module,
        "_run_sweep_command",
        lambda options, _invocation: captured.append(options),
    )

    wizard_module._run_wizard_command(result)

    assert captured[0].max_cwes == 7
    argv = wizard_module._wizard_argv(result)
    max_cwes_index = argv.index("--max-cwes")
    assert argv[max_cwes_index : max_cwes_index + 2] == ["--max-cwes", "7"]
    assert ("Automatic CWE limit", "7") in wizard_module._summary_lines(result, "Test profile")


def test_wizard_automatic_cwe_limit_retries_until_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answers = iter(["0", "not-a-number", "75"])
    monkeypatch.setattr(wizard_module, "prompt", lambda *_args, **_kwargs: next(answers))

    assert wizard_module._prompt_automatic_cwe_limit("sweep", "") == 75


def test_json_sweep_validates_the_automatic_cwe_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tool_module,
        "SecurityWorkflowService",
        lambda: pytest.fail("service must not start for an invalid automatic CWE limit"),
    )
    result = runner.invoke(
        app,
        ["tool", "sweep", "--stdin"],
        input=json.dumps(
            {
                "target": str(tmp_path),
                "selection": {"max_cwes": 0},
            }
        ),
    )

    assert result.exit_code == 2
    assert "max_cwes must be at least 1" in result.output


def test_json_sweep_accepts_limits_above_fifty() -> None:
    assert tool_module._automatic_cwe_limit({"max_cwes": 500}) == 500


def test_repository_profile_does_not_infer_frameworks_from_documentation(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text(
        "The next section compares express delivery with spring weather. "
        "It documents password, api_key, query, and upload fields.\n",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text("print('service')\n", encoding="utf-8")

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.frameworks == ()
    assert profile.secret_signals == ()
    assert profile.request_input_signals == ()
    assert profile.upload_signals == ()


def test_repository_profile_matches_dependency_names_instead_of_substrings(
    tmp_path: Path,
) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "next-session": "1.0.0",
                    "expressive-errors": "1.0.0",
                    "preact": "1.0.0",
                }
            }
        ),
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.frameworks == ()


def test_repository_profile_matches_canonical_go_framework_module_paths(
    tmp_path: Path,
) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/service\n\n"
        "go 1.22\n\n"
        "require (\n"
        "    github.com/gin-gonic/gin v1.10.0\n"
        "    github.com/gofiber/fiber/v2 v2.52.5\n"
        ")\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.frameworks == ("fiber", "gin")


def test_repository_profile_reads_complete_dependency_manifests(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "description": "x" * 60_000,
                "dependencies": {"express": "5.0.0"},
            }
        ),
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.frameworks == ("express",)


def test_repository_profile_does_not_treat_ordinary_nodes_as_des_crypto(
    tmp_path: Path,
) -> None:
    (tmp_path / "parser.js").write_text(
        "nodes.push(child);\nreturn nodes.map(render);\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.crypto_signals == ()


def test_regular_expression_evidence_selects_complexity_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "matcher.js").write_text(
        "export function matches(userPattern, value) {\n"
        "  return new RegExp(userPattern).test(value);\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-1333" in plan.cwe_ids()
    check = next(check for check in plan.selected_checks if "CWE-1333" in check.cwe_ids)
    assert check.selection_tier == "repository-specific"
    assert any("regular-expression" in reason for reason in check.reasons)
    assert check.repository_specific_evidence_score == 110
    assert check.repository_relationship_evidence_score == 0


def test_auto_ranking_rewards_independent_file_coverage(tmp_path: Path) -> None:
    (tmp_path / "verify_primary.py").write_text(
        "verify_signature(payload, signature)\n",
        encoding="utf-8",
    )
    (tmp_path / "verify_backup.py").write_text(
        "verify_signature(payload, signature)\n",
        encoding="utf-8",
    )
    (tmp_path / "redirect.py").write_text(
        "redirect_url = request.query_params['next']\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))
    selected_ids = plan.cwe_ids()
    signature_check = next(check for check in plan.selected_checks if check.cwe_ids[0] == "CWE-347")
    redirect_check = next(check for check in plan.selected_checks if check.cwe_ids[0] == "CWE-601")

    assert signature_check.repository_specific_evidence_score == 125
    assert redirect_check.repository_specific_evidence_score == 125
    assert signature_check.repository_evidence_coverage == 2
    assert redirect_check.repository_evidence_coverage == 1
    assert selected_ids.index("CWE-347") < selected_ids.index("CWE-601")


def test_repository_specific_portfolio_prefers_direct_evidence_over_relationship_score() -> None:
    directly_supported = SelectedCheck(
        check_id="cwe-184",
        title="Incomplete List of Disallowed Inputs",
        cwe_ids=("CWE-184",),
        score=0.4,
        reasons=(),
        repository_evidence_score=80,
        repository_specific_evidence_score=80,
    )
    relationship_only = SelectedCheck(
        check_id="cwe-999",
        title="Taxonomy Relative",
        cwe_ids=("CWE-999",),
        score=0.9,
        reasons=(),
        repository_evidence_score=145,
        repository_relationship_evidence_score=45,
    )

    ranked = sorted(
        (relationship_only, directly_supported),
        key=_repository_specific_sort_key,
    )

    assert ranked == [directly_supported, relationship_only]


@pytest.mark.parametrize(
    ("automatic_limit", "expected_quota"),
    [(1, 1), (15, 5), (25, 9), (50, 18)],
)
def test_repository_specific_portfolio_preserves_roughly_two_thirds_for_priority_coverage(
    automatic_limit: int,
    expected_quota: int,
) -> None:
    assert _repository_specific_quota(automatic_limit) == expected_quota


def test_http_header_parser_evidence_selects_protocol_interpretation_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "HttpHeaderParser.java").write_text(
        "class HttpHeaderParser {\n"
        "  void validate(String name, String value) {\n"
        '    if (name.equals("Content-Length") || '
        'name.equals("Transfer-Encoding")) {}\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-113", "CWE-444"} <= set(plan.cwe_ids())
    assert all(
        check.selection_tier == "repository-specific"
        for check in plan.selected_checks
        if check.cwe_ids[0] in {"CWE-113", "CWE-444"}
    )


def test_parser_depth_and_size_evidence_selects_resource_consumption_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "JsonParser.java").write_text(
        "class JsonParser {\n"
        "  Object parseValue(InputStream input, int depth, int maxDepth) {\n"
        "    if (depth > maxDepth) throw new ParseException();\n"
        "    return parseValue(input, depth + 1, maxDepth);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-400", "CWE-1286"} <= set(plan.cwe_ids())
    check = next(check for check in plan.selected_checks if "CWE-400" in check.cwe_ids)
    assert check.selection_tier == "repository-specific"
    assert any("parser/resource" in reason for reason in check.reasons)


def test_security_randomness_evidence_selects_prng_cwe(tmp_path: Path) -> None:
    (tmp_path / "Authenticator.java").write_text(
        "class Authenticator {\n"
        "  String nonce() { return Long.toString(new Random().nextLong()); }\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-338" in plan.cwe_ids()
    check = next(check for check in plan.selected_checks if "CWE-338" in check.cwe_ids)
    assert any("randomness" in reason for reason in check.reasons)


def test_dynamic_code_generation_evidence_selects_code_injection_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "template.js").write_text(
        "export function compile(template) {\n  return new Function('data', template);\n}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-94" in plan.cwe_ids()
    check = next(check for check in plan.selected_checks if "CWE-94" in check.cwe_ids)
    assert any("dynamic code" in reason for reason in check.reasons)


def test_deserialization_evidence_selects_authenticity_and_dynamic_resource_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "scanner.py").write_text(
        "import pickle\ndef scan(payload: bytes):\n    return pickle.loads(payload)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-345", "CWE-502", "CWE-913"} <= set(plan.cwe_ids())
    assert all(
        any("deserialization" in reason for reason in check.reasons)
        for check in plan.selected_checks
        if check.cwe_ids[0] in {"CWE-345", "CWE-502", "CWE-913"}
    )


def test_unsafe_memory_evidence_selects_bounds_cwes_for_rust(tmp_path: Path) -> None:
    (tmp_path / "buffer.rs").write_text(
        "pub unsafe fn read(data: &[u8], index: usize) -> u8 {\n"
        "    *data.get_unchecked(index)\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-119", "CWE-125", "CWE-787"} <= set(plan.cwe_ids())
    assert all(
        any("unsafe memory" in reason for reason in check.reasons)
        for check in plan.selected_checks
        if check.cwe_ids[0] in {"CWE-119", "CWE-125", "CWE-787"}
    )


def test_static_file_serving_evidence_selects_exposure_cwes(tmp_path: Path) -> None:
    (tmp_path / "StaticFileServer.java").write_text(
        "class StaticFileServer {\n"
        "  byte[] serve(Path root, String requestedPath) {\n"
        "    return Files.readAllBytes(root.resolve(requestedPath));\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-402", "CWE-668"} <= set(plan.cwe_ids())
    assert all(
        any("file serving" in reason for reason in check.reasons)
        for check in plan.selected_checks
        if check.cwe_ids[0] in {"CWE-402", "CWE-668"}
    )


def test_privilege_and_authorization_evidence_selects_access_control_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "security.go").write_text(
        "const deployment = `securityContext:\n"
        "  privileged: true\n"
        "  capabilities:\n"
        "    add: [NET_ADMIN]`\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-250", "CWE-862"} <= set(plan.cwe_ids())
    check = next(check for check in plan.selected_checks if "CWE-250" in check.cwe_ids)
    assert any("privilege" in reason for reason in check.reasons)


def test_signature_verification_evidence_selects_authenticity_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "SignedDocument.java").write_text(
        "class SignedDocument {\n"
        "  boolean verify(PublicKey key, byte[] signature) {\n"
        '    Signature verifier = Signature.getInstance("SHA256withRSA");\n'
        "    verifier.initVerify(key);\n"
        "    return verifier.verify(signature);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-345", "CWE-347"} <= set(plan.cwe_ids())
    assert all(
        any("signature" in reason for reason in check.reasons)
        for check in plan.selected_checks
        if check.cwe_ids[0] in {"CWE-345", "CWE-347"}
    )


def test_dynamic_object_property_evidence_selects_prototype_pollution_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "properties.js").write_text(
        "export function set(target, key, value) {\n"
        "  if (key === '__proto__' || key === 'constructor.prototype') return;\n"
        "  target[key] = value;\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-1321" in plan.cwe_ids()
    check = next(check for check in plan.selected_checks if "CWE-1321" in check.cwe_ids)
    assert any("object property" in reason for reason in check.reasons)


def test_ignored_error_evidence_selects_exception_handling_cwes(tmp_path: Path) -> None:
    (tmp_path / "loader.go").write_text(
        "func load(path string) []byte {\n    data, _ := os.ReadFile(path)\n    return data\n}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-252", "CWE-703", "CWE-755"} <= set(plan.cwe_ids())
    assert all(
        any("error handling" in reason for reason in check.reasons)
        for check in plan.selected_checks
        if check.cwe_ids[0] in {"CWE-252", "CWE-755"}
    )


def test_ldap_and_output_encoding_evidence_selects_contextual_injection_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "directory.go").write_text(
        "func lookup(userFilter string) string {\n"
        "    result := ldap.Search(userFilter)\n"
        "    return html.EscapeString(result)\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-90", "CWE-116"} <= set(plan.cwe_ids())


def test_shared_state_synchronization_evidence_selects_concurrency_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "cache.go").write_text(
        "type Cache struct { mu sync.Mutex; values map[string]string }\n"
        "func (c *Cache) Set(key, value string) {\n"
        "    c.mu.Lock(); defer c.mu.Unlock(); c.values[key] = value\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-362", "CWE-662"} <= set(plan.cwe_ids())


def test_temporary_file_evidence_selects_lifecycle_cwes(tmp_path: Path) -> None:
    (tmp_path / "workspace.py").write_text(
        "import tempfile\ndef create():\n    return tempfile.mktemp()\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-377", "CWE-459"} <= set(plan.cwe_ids())


def test_sensitive_logging_evidence_selects_log_exposure_cwe(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "def authenticate(token: str):\n    logger.info('received token %s', token)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-532" in plan.cwe_ids()


def test_archive_expansion_evidence_selects_decompression_resource_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "archive.py").write_text(
        "import zipfile\ndef unpack(path, output):\n    zipfile.ZipFile(path).extractall(output)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-400", "CWE-409"} <= set(plan.cwe_ids())


def test_url_decoding_and_repeated_parameter_evidence_selects_input_shape_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "request.go").write_text(
        "func values(r *http.Request) []string {\n"
        "    decoded, _ := url.QueryUnescape(r.URL.RawQuery)\n"
        "    return r.URL.Query()[decoded]\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-177", "CWE-235"} <= set(plan.cwe_ids())


def test_sensitive_configuration_storage_evidence_selects_storage_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "config.py").write_text(
        "from configparser import RawConfigParser\n"
        "config = RawConfigParser()\n"
        "config.set('service', 'api_key', key)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-922" in plan.cwe_ids()


def test_sensitive_configuration_evidence_requires_a_configuration_write(
    tmp_path: Path,
) -> None:
    (tmp_path / "context.py").write_text(
        "token = request.headers.get('token')\n"
        "cache.set('last_request', request)\n"
        "config = load_config()\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert "CWE-922" not in profile.cwe_evidence


def test_test_only_evidence_is_retained_with_lower_confidence(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "NonceTest.java").write_text(
        "class NonceTest { long value() { return new Random().nextLong(); } }\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.cwe_evidence["CWE-338"] == (
        "security-sensitive randomness in tests/NonceTest.java",
    )
    assert profile.cwe_evidence_scores["CWE-338"] < 120


def test_generated_source_evidence_is_retained_with_lower_confidence(tmp_path: Path) -> None:
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "client.js").write_text("eval(userInput)\n", encoding="utf-8")

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.cwe_evidence["CWE-94"] == (
        "dynamic code or template generation in generated/client.js",
    )
    assert profile.cwe_evidence_scores["CWE-94"] < 125


def test_redirect_destination_evidence_selects_open_redirect_cwe(tmp_path: Path) -> None:
    (tmp_path / "handler.go").write_text(
        "func redirect(url string) http.Handler {\n"
        "    return http.RedirectHandler(url, http.StatusTemporaryRedirect)\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-601" in plan.cwe_ids()


def test_conflicting_request_parameter_sources_select_extra_parameter_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "params.js").write_text(
        "function value(req, name) {\n"
        "  return req.params[name] || req.query[name] || req.body[name];\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-235" in plan.cwe_ids()


def test_recursion_limit_evidence_selects_uncontrolled_recursion_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "decoder.rs").write_text(
        "if tree_height > MAX_RECURSION_DEPTH {\n"
        "    return Err(Error::MaxRecursiveDepthExceeded);\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-674" in plan.cwe_ids()


def test_os_command_execution_evidence_selects_command_injection_variants(
    tmp_path: Path,
) -> None:
    (tmp_path / "runner.js").write_text(
        "const childProcess = require('child_process');\nchildProcess.exec(command, callback);\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-77", "CWE-78"} <= set(plan.cwe_ids())


def test_legacy_cryptography_evidence_selects_broken_algorithm_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "digest.py").write_text(
        "digest = hashlib.sha1(payload).hexdigest()\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-327" in plan.cwe_ids()


def test_java_legacy_cryptography_evidence_selects_broken_algorithm_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "Digest.java").write_text(
        'MessageDigest digest = MessageDigest.getInstance("SHA-1");\n',
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-327" in plan.cwe_ids()


def test_tls_certificate_verification_evidence_selects_peer_validation_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.py").write_text(
        "verify_ssl = should_verify_ssl(url)\nsession.get(url, verify=verify_ssl)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-295" in plan.cwe_ids()


def test_message_size_limit_evidence_selects_resource_consumption_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.go").write_text(
        "if messageSize > maxRecvMessageSize {\n"
        '    return status.Error(codes.ResourceExhausted, "too large")\n'
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-400" in plan.cwe_ids()


def test_authentication_gate_evidence_selects_authentication_cwe(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "@login_required\ndef account():\n    return current_user\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-269", "CWE-287", "CWE-862", "CWE-863"} <= set(plan.cwe_ids())


def test_generic_repository_surfaces_expand_security_families(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from pathlib import Path\n"
        "import requests\n"
        "token = request.headers.get('Authorization')\n"
        "payload = Path(request.args['path']).read_text()\n"
        "response = requests.get(request.args['url'])\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {
        "CWE-15",
        "CWE-200",
        "CWE-269",
        "CWE-400",
        "CWE-404",
        "CWE-532",
        "CWE-772",
        "CWE-862",
    } <= set(plan.cwe_ids())


def test_public_api_capabilities_select_logging_parser_and_configuration_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.py").write_text(
        "import json\n"
        "import logging\n"
        "import os\n"
        "logger = logging.getLogger(__name__)\n"
        "configuration = json.loads(os.getenv('SERVICE_CONFIG', '{}'))\n"
        "logger.info(configuration)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert plan.profile.logging_signals
    assert plan.profile.parser_signals
    assert plan.profile.configuration_signals
    assert {"CWE-15", "CWE-20", "CWE-117", "CWE-532", "CWE-674", "CWE-1286"} <= set(plan.cwe_ids())


def test_web_framework_dependencies_select_server_security_families(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies><dependency>"
        "<groupId>io.netty</groupId><artifactId>netty-codec-http</artifactId>"
        "</dependency></dependencies></project>",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "netty" in plan.profile.frameworks
    assert {"CWE-20", "CWE-287", "CWE-400", "CWE-404", "CWE-772", "CWE-862"} <= set(plan.cwe_ids())


def test_public_dependency_capabilities_are_profiled(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><dependencies>"
        "<dependency><groupId>com.fasterxml.jackson.core</groupId>"
        "<artifactId>jackson-databind</artifactId></dependency>"
        "<dependency><groupId>org.slf4j</groupId>"
        "<artifactId>slf4j-api</artifactId></dependency>"
        "<dependency><groupId>com.typesafe</groupId>"
        "<artifactId>config</artifactId></dependency>"
        "</dependencies></project>",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.parser_signals == ("pom.xml",)
    assert profile.logging_signals == ("pom.xml",)
    assert profile.configuration_signals == ("pom.xml",)


def test_http_client_and_unbounded_body_evidence_selects_network_resource_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "client.js").write_text(
        "const http = require('http')\n"
        "const outbound = http.request(options)\n"
        "incoming.on('data', chunk => { body += chunk })\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-400", "CWE-770", "CWE-918"} <= set(plan.cwe_ids())


def test_csrf_and_authorization_controls_select_access_control_cwes(tmp_path: Path) -> None:
    (tmp_path / "SecurityFilterChain.java").write_text(
        "class CSRFHandler {\n"
        "  AuthorizationManager authorizationManager;\n"
        "  SecurityFilterChain securityFilterChain;\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-352", "CWE-862", "CWE-863"} <= set(plan.cwe_ids())


def test_url_output_sanitization_selects_xss_encoding_and_url_cwes(tmp_path: Path) -> None:
    (tmp_path / "sanitize.ts").write_text(
        "const safeHtml = DOMPurify.sanitize(untrustedHtml)\n"
        "const decoded = decodeURIComponent(request.query.value)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-79", "CWE-116", "CWE-177"} <= set(plan.cwe_ids())


def test_syntax_validation_selects_input_validation_cwes(tmp_path: Path) -> None:
    (tmp_path / "schema.py").write_text(
        "import jsonschema\njsonschema.validate(instance=payload, schema=request_schema)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-20", "CWE-1286"} <= set(plan.cwe_ids())


def test_command_nonreentrancy_and_script_apis_select_relevant_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "runner.py").write_text(
        "import subprocess\nsubprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    (tmp_path / "guard.py").write_text(
        "@nonreentrant('lock')\ndef update(): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "ScriptRunner.java").write_text(
        'ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");\n'
        "engine.eval(source);\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-77", "CWE-94", "CWE-662"} <= set(plan.cwe_ids())


def test_terminal_color_output_selects_output_neutralization_cwes(tmp_path: Path) -> None:
    printer = tmp_path / "printer"
    printer.mkdir()
    (printer / "color.go").write_text(
        "func render(writer io.Writer, value any) {\n"
        '  fmt.Fprint(writer, "\\\\x1b[31m", value, "\\\\x1b[0m")\n'
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-74", "CWE-116"} <= set(plan.cwe_ids())


def test_development_corpus_identifiers_are_not_direct_cwe_evidence(tmp_path: Path) -> None:
    (tmp_path / "identifiers.py").write_text(
        "DISABLE_GROOVY disableIngestionGroovy invalidProtocolRegex "
        "UNSAFE_CHARS_REGEXP escapeUnsafeChars IsValidNumber color.NoColor "
        "enableColor disableColor Q.nfcall(exec) MemberExpression FunctionExpression "
        "TaggedTemplateExpression sanitizeUrl indexAccess TomlToken unexpectedToken "
        "logger.info(unexpectedToken)\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert not profile.cwe_evidence
    assert not profile.secret_signals
    assert not profile.auth_signals
    assert not profile.parser_signals
    assert not profile.configuration_signals


def test_security_sensitive_source_paths_are_sampled_before_profile_limit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    for index in range(300):
        (source / f"module_{index:03}.java").write_text(
            "class Module {}\n",
            encoding="utf-8",
        )
    security = source / "security"
    security.mkdir()
    (security / "AuthorizationManager.java").write_text(
        "class AuthorizationManager {}\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert any(
        evidence.endswith("in src/security/AuthorizationManager.java")
        for evidence in profile.cwe_evidence["CWE-862"]
    )


def test_user_controlled_path_construction_selects_traversal_variants(
    tmp_path: Path,
) -> None:
    (tmp_path / "files.go").write_text(
        "func resolve(root, userPath string) string {\n"
        "    return filepath.Join(root, userPath)\n"
        "}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-22", "CWE-35"} <= set(plan.cwe_ids())


def test_allow_and_deny_list_evidence_selects_protection_mechanism_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "scanner.py").write_text(
        "allowlist = {'builtins': {'set'}}\n"
        "denylist = {'os': '*'}\n"
        "if module in denylist: return Dangerous\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-184", "CWE-693"} <= set(plan.cwe_ids())


def test_compiler_control_flow_evidence_selects_control_flow_cwes(tmp_path: Path) -> None:
    (tmp_path / "codegen.py").write_text(
        "def compile_branch(ast_node):\n"
        "    jump_label = generate_label(ast_node)\n"
        "    return emit_jump(jump_label)\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert {"CWE-670", "CWE-691"} <= set(plan.cwe_ids())


def test_resource_consuming_loop_evidence_selects_loop_resource_cwe(
    tmp_path: Path,
) -> None:
    (tmp_path / "parser.js").write_text(
        "while (index < input.length) {\n  stack.push(parseValue(input[index++]));\n}\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-1050" in plan.cwe_ids()


def test_repository_profile_does_not_treat_generic_go_terms_as_web_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.go").write_text(
        "func route() {}\n"
        "func query(params string) {}\n"
        "// This value accommodates the request.\n"
        "func worker(ch chan int) { select { case <-ch: } }\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.route_files == ()
    assert profile.request_input_signals == ()
    assert profile.data_store_signals == ()


def test_repository_profile_recognizes_concrete_go_http_and_upload_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "server.go").write_text(
        "func handler(w http.ResponseWriter, r *http.Request) {\n"
        '  r.FormValue("name")\n'
        "  r.ParseMultipartForm(1024)\n"
        "}\n"
        'func routes(r *mux.Router) { r.HandleFunc("/upload", handler) }\n',
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.route_files == ("server.go",)
    assert profile.request_input_signals == ("server.go",)
    assert profile.upload_signals == ("server.go",)


def test_repository_profile_prioritizes_source_files_before_sampling_limit(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    for index in range(301):
        (docs / f"guide-{index:03}.md").write_text("documentation\n", encoding="utf-8")
    (tmp_path / "z_service.py").write_text(
        "api_key = load_secret()\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.secret_signals == ("z_service.py",)


def test_repository_profile_samples_across_repository_components(tmp_path: Path) -> None:
    first_component = tmp_path / "a_component"
    first_component.mkdir()
    for index in range(300):
        (first_component / f"module_{index:03}.py").write_text(
            "print('module')\n",
            encoding="utf-8",
        )
    last_component = tmp_path / "z_component"
    last_component.mkdir()
    (last_component / "service.py").write_text(
        "api_key = load_secret()\n",
        encoding="utf-8",
    )

    profile = RepositoryProfiler().profile(tmp_path)

    assert profile.secret_signals == ("z_component/service.py",)


def test_repository_profile_keeps_code_in_documentation_and_test_directories(
    tmp_path: Path,
) -> None:
    docs = tmp_path / "docs" / "examples"
    tests = tmp_path / "tests"
    docs.mkdir(parents=True)
    tests.mkdir()
    (docs / "sample.py").write_text("api_key = load_secret()\n", encoding="utf-8")
    (tests / "test_upload.py").write_text("upload(request.files)\n", encoding="utf-8")

    profile = RepositoryProfiler().profile(tmp_path)

    assert "docs/examples/sample.py" in profile.secret_signals
    assert "tests/test_upload.py" in profile.upload_signals


def test_repository_profile_does_not_follow_file_symlinks_outside_target(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("api_key = load_secret()\n", encoding="utf-8")
    (repository / "innocent.py").symlink_to(outside)

    profile = RepositoryProfiler().profile(repository)

    assert profile.secret_signals == ()


def test_repository_profile_requires_exact_opt_in_for_sensitive_source(tmp_path: Path) -> None:
    protected_source = tmp_path / ".aws" / "client.py"
    protected_source.parent.mkdir()
    protected_source.write_text("api_key = load_secret()\n", encoding="utf-8")

    default_profile = RepositoryProfiler().profile(tmp_path)
    allowed_profile = RepositoryProfiler().profile(
        tmp_path,
        allow_sensitive_files=[".aws/client.py"],
    )

    assert default_profile.secret_signals == ()
    assert allowed_profile.secret_signals == (".aws/client.py",)


def test_repository_profile_enforces_the_snapshot_file_count_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("antares_cli.core.cwe_selection_profile.MAX_REPOSITORY_FILES", 2)
    for index in range(3):
        (tmp_path / f"file-{index}.py").write_text("pass\n", encoding="utf-8")

    with pytest.raises(ValueError, match="snapshot budget"):
        RepositoryProfiler().profile(tmp_path)


def test_repository_profile_enforces_the_snapshot_total_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("antares_cli.core.cwe_selection_profile.MAX_REPOSITORY_BYTES", 4)
    (tmp_path / "service.py").write_text("12345", encoding="utf-8")

    with pytest.raises(ValueError, match="snapshot budget"):
        RepositoryProfiler().profile(tmp_path)


def test_automatic_selection_promotes_cwes_supported_by_repository_evidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.py").write_text(
        "api_key = load_secret()\n",
        encoding="utf-8",
    )

    plan = CweSelectionService().select(CweSelectionRequest(target=tmp_path))

    assert "CWE-798" in plan.cwe_ids()
    selected_check = next(check for check in plan.selected_checks if "CWE-798" in check.cwe_ids)
    assert "Repository credential/secret evidence supports this CWE" in selected_check.reasons


def test_auto_selection_keeps_diverse_relationship_supported_cwes(
    tmp_path: Path,
) -> None:
    (tmp_path / "service.py").write_text(
        "from pathlib import Path\n"
        "def read(user_path: str) -> str:\n"
        "    return Path(user_path).read_text()\n",
        encoding="utf-8",
    )

    service = CweSelectionService()
    plan = service.select(CweSelectionRequest(target=tmp_path))
    relationship_only_checks = [
        check
        for check in plan.selected_checks
        if check.repository_relationship_evidence_score > 0
        and not check.repository_specific_evidence_score
        and not check.repository_category_evidence_score
    ]

    family_counts: dict[str, int] = {}
    for check in relationship_only_checks:
        for family_id in service._relationship_family_ids(check.cwe_ids[0]):
            family_counts[family_id] = family_counts.get(family_id, 0) + 1

    assert relationship_only_checks
    assert max(family_counts.values()) <= 2
    assert all(check.selection_tier == "repository-specific" for check in relationship_only_checks)
    assert all(
        any("CWE relationship" in reason for reason in check.reasons)
        for check in relationship_only_checks
    )
