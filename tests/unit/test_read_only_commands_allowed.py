# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Comprehensive coverage of read-only commands that must be allowed.

These tests represent the variety of exploration commands that models issue
during investigations. Every test here should PASS — a failure means a
legitimate read pattern is being incorrectly blocked.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from antares_cli.agent.tool_router import ToolRouter


@pytest.fixture()
def repository(tmp_path: Path) -> Path:
    """Create a realistic mini repository for testing."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "utils").mkdir()
    (tmp_path / "src" / "auth").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "docs").mkdir()

    (tmp_path / "README.md").write_text(
        "# Project\n\nA sample project for testing.\n", encoding="utf-8"
    )
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='project')\n", encoding="utf-8"
    )
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "main.py").write_text(
        "import os\nimport sys\n\ndef main():\n    print('hello')\n\nif __name__ == '__main__':\n    main()\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "utils" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "utils" / "helpers.py").write_text(
        "def sanitize(input_string: str) -> str:\n"
        "    return input_string.replace('<', '&lt;')\n\n"
        "def execute_query(query: str, params: list) -> list:\n"
        "    connection = get_connection()\n"
        "    cursor = connection.cursor()\n"
        "    cursor.execute(query, params)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "auth" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "auth" / "login.py").write_text(
        "from flask import request, session\n\n"
        "def login():\n"
        "    username = request.form['username']\n"
        "    password = request.form['password']\n"
        "    if verify(username, password):\n"
        "        session['user'] = username\n"
        "        return redirect('/home')\n"
        "    return 'Invalid credentials', 401\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "auth" / "tokens.py").write_text(
        "import jwt\nimport time\n\n"
        "SECRET = 'hardcoded-secret'\n\n"
        "def create_token(user_id: int) -> str:\n"
        "    payload = {'sub': user_id, 'exp': time.time() + 3600}\n"
        "    return jwt.encode(payload, SECRET)\n",
        encoding="utf-8",
    )
    (tmp_path / "tests" / "test_auth.py").write_text(
        "import pytest\nfrom src.auth.login import login\n\ndef test_login_success():\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "docs" / "api.md").write_text(
        "# API\n\n## Endpoints\n\n- POST /login\n- GET /users\n", encoding="utf-8"
    )
    (tmp_path / "Makefile").write_text(
        "test:\n\tpytest tests/\n\nlint:\n\truff check src/\n", encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text(
        "flask==2.3.0\npyjwt==2.8.0\nrequests==2.31.0\n", encoding="utf-8"
    )
    (tmp_path / ".env.example").write_text(
        "DATABASE_URL=postgres://localhost/dev\nSECRET_KEY=change-me\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture()
def router(repository: Path) -> ToolRouter:
    return ToolRouter(repository)


def _run(router: ToolRouter, command: str) -> dict:
    result = router.execute("terminal", {"command": command})
    assert result.success, f"Command should succeed: {command!r}\nError: {result.error_message}"
    return result.output


# ---------------------------------------------------------------------------
# ls — directory listing
# ---------------------------------------------------------------------------


class TestLsCommands:
    def test_ls_current_directory(self, router: ToolRouter) -> None:
        output = _run(router, "ls")
        assert "src" in output["stdout"]
        assert "README.md" in output["stdout"]

    def test_ls_subdirectory(self, router: ToolRouter) -> None:
        output = _run(router, "ls src/auth")
        assert "login.py" in output["stdout"]
        assert "tokens.py" in output["stdout"]

    def test_ls_long_format(self, router: ToolRouter) -> None:
        output = _run(router, "ls -la src/")
        assert "main.py" in output["stdout"]

    def test_ls_recursive(self, router: ToolRouter) -> None:
        output = _run(router, "ls -R src/")
        assert "helpers.py" in output["stdout"]
        assert "login.py" in output["stdout"]

    def test_ls_with_pattern_argument(self, router: ToolRouter) -> None:
        output = _run(router, "ls src/auth/")
        assert "login.py" in output["stdout"]

    def test_ls_one_per_line(self, router: ToolRouter) -> None:
        output = _run(router, "ls -1 src/auth/")
        lines = output["stdout"].strip().splitlines()
        assert "__init__.py" in lines
        assert "login.py" in lines


# ---------------------------------------------------------------------------
# cat — file reading
# ---------------------------------------------------------------------------


class TestCatCommands:
    def test_cat_single_file(self, router: ToolRouter) -> None:
        output = _run(router, "cat src/main.py")
        assert "def main():" in output["stdout"]

    def test_cat_multiple_files(self, router: ToolRouter) -> None:
        output = _run(router, "cat src/auth/login.py src/auth/tokens.py")
        assert "def login():" in output["stdout"]
        assert "def create_token" in output["stdout"]

    def test_cat_with_line_numbers(self, router: ToolRouter) -> None:
        output = _run(router, "cat -n src/main.py")
        assert "1" in output["stdout"]
        assert "def main():" in output["stdout"]

    def test_cat_show_ends(self, router: ToolRouter) -> None:
        output = _run(router, "cat -e src/main.py")
        assert "$" in output["stdout"]


# ---------------------------------------------------------------------------
# head / tail — partial file reading
# ---------------------------------------------------------------------------


class TestHeadTailCommands:
    def test_head_default(self, router: ToolRouter) -> None:
        output = _run(router, "head src/utils/helpers.py")
        assert "def sanitize" in output["stdout"]

    def test_head_line_count(self, router: ToolRouter) -> None:
        output = _run(router, "head -n 5 src/main.py")
        lines = output["stdout"].strip().splitlines()
        assert len(lines) == 5

    def test_tail_default(self, router: ToolRouter) -> None:
        output = _run(router, "tail src/auth/login.py")
        assert "401" in output["stdout"]

    def test_tail_line_count(self, router: ToolRouter) -> None:
        output = _run(router, "tail -n 2 src/auth/tokens.py")
        lines = output["stdout"].strip().splitlines()
        assert len(lines) == 2

    def test_head_bytes(self, router: ToolRouter) -> None:
        output = _run(router, "head -c 9 README.md")
        assert output["stdout"] == "# Project"


# ---------------------------------------------------------------------------
# find — file discovery
# ---------------------------------------------------------------------------


class TestFindCommands:
    def test_find_all_python_files(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' -type f")
        assert "main.py" in output["stdout"]
        assert "helpers.py" in output["stdout"]

    def test_find_with_maxdepth(self, router: ToolRouter) -> None:
        output = _run(router, "find . -maxdepth 1 -type f")
        assert "setup.py" in output["stdout"]
        assert "helpers.py" not in output["stdout"]

    def test_find_by_extension(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.md'")
        assert "README.md" in output["stdout"]
        assert "api.md" in output["stdout"]

    def test_find_directories_only(self, router: ToolRouter) -> None:
        output = _run(router, "find . -type d")
        assert "src" in output["stdout"]
        assert "tests" in output["stdout"]

    def test_find_with_path_filter(self, router: ToolRouter) -> None:
        output = _run(router, "find . -path '*/auth/*' -name '*.py'")
        assert "login.py" in output["stdout"]

    def test_find_not_pattern(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' -not -name '__init__.py'")
        assert "__init__.py" not in output["stdout"]
        assert "main.py" in output["stdout"]

    def test_find_size_filter(self, router: ToolRouter) -> None:
        output = _run(router, "find . -type f -size +0c")
        assert "main.py" in output["stdout"]

    def test_find_newer_than(self, router: ToolRouter) -> None:
        output = _run(router, "find . -type f -newer setup.py")
        assert output["returncode"] == 0

    @pytest.mark.skipif(
        os.uname().sysname == "Darwin",
        reason="macOS find does not support -printf",
    )
    def test_find_with_printf(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' -printf '%p\\n'")
        assert output["returncode"] == 0


# ---------------------------------------------------------------------------
# grep — pattern searching
# ---------------------------------------------------------------------------


class TestGrepCommands:
    def test_grep_simple_pattern(self, router: ToolRouter) -> None:
        output = _run(router, "grep 'import' src/main.py")
        assert "import os" in output["stdout"]

    def test_grep_recursive(self, router: ToolRouter) -> None:
        output = _run(router, "grep -r 'def ' src/")
        assert "main.py" in output["stdout"]
        assert "helpers.py" in output["stdout"]

    def test_grep_with_line_numbers(self, router: ToolRouter) -> None:
        output = _run(router, "grep -n 'def' src/main.py")
        assert "4:def main():" in output["stdout"]

    def test_grep_case_insensitive(self, router: ToolRouter) -> None:
        output = _run(router, "grep -i 'PROJECT' README.md")
        assert "Project" in output["stdout"]

    def test_grep_count(self, router: ToolRouter) -> None:
        output = _run(router, "grep -c 'import' src/main.py")
        assert "2" in output["stdout"]

    def test_grep_list_files(self, router: ToolRouter) -> None:
        output = _run(router, "grep -rl 'flask' src/")
        assert "login.py" in output["stdout"]

    def test_grep_extended_regex(self, router: ToolRouter) -> None:
        output = _run(router, "grep -E '(def|class) ' src/utils/helpers.py")
        assert "def sanitize" in output["stdout"]

    def test_grep_context_lines(self, router: ToolRouter) -> None:
        output = _run(router, "grep -A 2 -B 1 'execute_query' src/utils/helpers.py")
        assert "execute_query" in output["stdout"]
        assert "connection" in output["stdout"]

    def test_grep_invert_match(self, router: ToolRouter) -> None:
        output = _run(router, "grep -v '^$' src/main.py")
        assert output["returncode"] == 0

    def test_grep_word_boundary(self, router: ToolRouter) -> None:
        output = _run(router, "grep -w 'main' src/main.py")
        assert "main" in output["stdout"]

    def test_grep_with_include(self, router: ToolRouter) -> None:
        output = _run(router, "grep -r --include='*.py' 'import' src/")
        assert "main.py" in output["stdout"]

    def test_grep_fixed_strings(self, router: ToolRouter) -> None:
        output = _run(router, "grep -F 'request.form' src/auth/login.py")
        assert "request.form" in output["stdout"]


# ---------------------------------------------------------------------------
# rg (ripgrep) — fast searching
# ---------------------------------------------------------------------------


class TestRipgrepCommands:
    def test_rg_simple(self, router: ToolRouter) -> None:
        output = _run(router, "rg 'def ' src/")
        assert "main.py" in output["stdout"]

    def test_rg_with_type(self, router: ToolRouter) -> None:
        output = _run(router, "rg --type py 'import' src/")
        assert "import" in output["stdout"]

    def test_rg_list_files(self, router: ToolRouter) -> None:
        output = _run(router, "rg -l 'flask' src/")
        assert "login.py" in output["stdout"]

    def test_rg_with_context(self, router: ToolRouter) -> None:
        output = _run(router, "rg -C 2 'SECRET' src/")
        assert "SECRET" in output["stdout"]

    def test_rg_case_insensitive(self, router: ToolRouter) -> None:
        output = _run(router, "rg -i 'secret' src/")
        assert "SECRET" in output["stdout"] or "secret" in output["stdout"]

    def test_rg_multiline(self, router: ToolRouter) -> None:
        output = _run(router, "rg -U 'def.*\\n.*return' src/")
        assert output["returncode"] == 0

    def test_rg_glob_filter(self, router: ToolRouter) -> None:
        output = _run(router, "rg --glob '*.py' 'import' src/")
        assert "import" in output["stdout"]

    def test_rg_files_only(self, router: ToolRouter) -> None:
        output = _run(router, "rg --files src/")
        assert "main.py" in output["stdout"]

    def test_rg_word_boundary(self, router: ToolRouter) -> None:
        output = _run(router, "rg -w 'main' src/")
        assert "main" in output["stdout"]

    def test_rg_count(self, router: ToolRouter) -> None:
        output = _run(router, "rg -c 'import' src/main.py")
        assert "2" in output["stdout"]

    def test_rg_no_filename(self, router: ToolRouter) -> None:
        output = _run(router, "rg --no-filename 'def' src/main.py")
        assert "def main" in output["stdout"]


# ---------------------------------------------------------------------------
# tree — directory tree
# ---------------------------------------------------------------------------


class TestTreeCommands:
    def test_tree_default(self, router: ToolRouter) -> None:
        output = _run(router, "tree -L 2")
        assert "src" in output["stdout"]

    def test_tree_depth_limited(self, router: ToolRouter) -> None:
        output = _run(router, "tree -L 1")
        assert "src" in output["stdout"]

    def test_tree_files_only(self, router: ToolRouter) -> None:
        output = _run(router, "tree -L 3 --prune")
        assert output["returncode"] == 0

    def test_tree_with_pattern(self, router: ToolRouter) -> None:
        output = _run(router, "tree -P '*.py' --prune")
        assert "main.py" in output["stdout"]

    def test_tree_directories_only(self, router: ToolRouter) -> None:
        output = _run(router, "tree -d")
        assert "src" in output["stdout"]


# ---------------------------------------------------------------------------
# wc — word/line/byte counts
# ---------------------------------------------------------------------------


class TestWcCommands:
    def test_wc_line_count(self, router: ToolRouter) -> None:
        output = _run(router, "wc -l src/main.py")
        assert output["returncode"] == 0

    def test_wc_word_count(self, router: ToolRouter) -> None:
        output = _run(router, "wc -w README.md")
        assert output["returncode"] == 0

    def test_wc_multiple_files(self, router: ToolRouter) -> None:
        output = _run(router, "wc -l src/auth/login.py src/auth/tokens.py")
        assert "total" in output["stdout"]


# ---------------------------------------------------------------------------
# sort / uniq — ordering and deduplication
# ---------------------------------------------------------------------------


class TestSortUniqCommands:
    def test_sort_file(self, router: ToolRouter) -> None:
        output = _run(router, "sort requirements.txt")
        lines = output["stdout"].strip().splitlines()
        assert lines == sorted(lines)

    def test_sort_reverse(self, router: ToolRouter) -> None:
        output = _run(router, "sort -r requirements.txt")
        assert output["returncode"] == 0

    def test_sort_numeric(self, router: ToolRouter) -> None:
        output = _run(router, "sort -n requirements.txt")
        assert output["returncode"] == 0

    def test_sort_unique(self, router: ToolRouter) -> None:
        output = _run(router, "sort -u requirements.txt")
        assert output["returncode"] == 0

    def test_uniq_stdin(self, router: ToolRouter) -> None:
        output = _run(router, "sort requirements.txt | uniq")
        assert output["returncode"] == 0

    def test_uniq_count(self, router: ToolRouter) -> None:
        output = _run(router, "sort requirements.txt | uniq -c")
        assert output["returncode"] == 0


# ---------------------------------------------------------------------------
# cut — field extraction
# ---------------------------------------------------------------------------


class TestFieldExtractionCommands:
    def test_cut_delimiter(self, router: ToolRouter) -> None:
        output = _run(router, "cut -d'=' -f1 requirements.txt")
        assert "flask" in output["stdout"]

    def test_cut_character_range(self, router: ToolRouter) -> None:
        output = _run(router, "cut -c1-10 README.md")
        assert "# Project" in output["stdout"]


# ---------------------------------------------------------------------------
# sed — stream editing (read-only substitutions)
# ---------------------------------------------------------------------------


class TestSedCommands:
    def test_sed_substitution_print(self, router: ToolRouter) -> None:
        output = _run(router, "sed 's/import/IMPORT/g' src/main.py")
        assert "IMPORT os" in output["stdout"]

    def test_sed_line_range_print(self, router: ToolRouter) -> None:
        output = _run(router, "sed -n '1,5p' src/main.py")
        lines = output["stdout"].strip().splitlines()
        assert len(lines) == 5

    def test_sed_last_line_print(self, router: ToolRouter) -> None:
        output = _run(router, "sed -n '$p' src/main.py")
        assert output["returncode"] == 0

    def test_sed_with_alternate_delimiter(self, router: ToolRouter) -> None:
        output = _run(router, "sed 's#src/#SRC/#g' Makefile")
        assert "SRC/" in output["stdout"]

    def test_sed_pipe_from_find(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' | sed 's#^./##'")
        assert "src/main.py" in output["stdout"]

    def test_sed_extended_regex(self, router: ToolRouter) -> None:
        output = _run(router, "sed -E 's/(def )([a-z_]+)/\\1FUNC/g' src/main.py")
        assert "def FUNC" in output["stdout"]


# ---------------------------------------------------------------------------
# diff — file comparison
# ---------------------------------------------------------------------------


class TestDiffCommands:
    def test_diff_two_files(self, router: ToolRouter) -> None:
        output = _run(router, "diff src/auth/login.py src/auth/tokens.py")
        assert output["returncode"] in (0, 1)

    def test_diff_unified(self, router: ToolRouter) -> None:
        output = _run(router, "diff -u src/auth/login.py src/auth/tokens.py")
        assert output["returncode"] in (0, 1)


# ---------------------------------------------------------------------------
# file / stat / du — metadata
# ---------------------------------------------------------------------------


class TestMetadataCommands:
    def test_file_type(self, router: ToolRouter) -> None:
        output = _run(router, "file src/main.py")
        assert "text" in output["stdout"].lower() or "Python" in output["stdout"]

    def test_file_multiple(self, router: ToolRouter) -> None:
        output = _run(router, "file src/main.py README.md")
        assert "main.py" in output["stdout"]
        assert "README" in output["stdout"]

    def test_stat_file(self, router: ToolRouter) -> None:
        output = _run(router, "stat src/main.py")
        assert output["returncode"] == 0

    def test_du_summary(self, router: ToolRouter) -> None:
        output = _run(router, "du -sh src/")
        assert output["returncode"] == 0

    def test_du_all(self, router: ToolRouter) -> None:
        output = _run(router, "du -a src/")
        assert "main.py" in output["stdout"]


# ---------------------------------------------------------------------------
# echo / pwd / basename / dirname / realpath / nl — utilities
# ---------------------------------------------------------------------------


class TestUtilityCommands:
    def test_echo(self, router: ToolRouter) -> None:
        output = _run(router, "echo hello world")
        assert output["stdout"].strip() == "hello world"

    def test_pwd(self, router: ToolRouter) -> None:
        output = _run(router, "pwd")
        assert output["stdout"].strip() != ""

    def test_basename(self, router: ToolRouter) -> None:
        output = _run(router, "basename src/auth/login.py")
        assert output["stdout"].strip() == "login.py"

    def test_basename_remove_suffix(self, router: ToolRouter) -> None:
        output = _run(router, "basename src/auth/login.py .py")
        assert output["stdout"].strip() == "login"

    def test_dirname(self, router: ToolRouter) -> None:
        output = _run(router, "dirname src/auth/login.py")
        assert output["stdout"].strip() == "src/auth"

    def test_realpath(self, router: ToolRouter) -> None:
        output = _run(router, "realpath src/main.py")
        assert output["returncode"] == 0

    def test_nl_line_numbers(self, router: ToolRouter) -> None:
        output = _run(router, "nl src/main.py")
        assert "1" in output["stdout"]
        assert "import os" in output["stdout"]

    def test_true_exit_zero(self, router: ToolRouter) -> None:
        output = _run(router, "true")
        assert output["returncode"] == 0


# ---------------------------------------------------------------------------
# Pipelines — multi-stage commands
# ---------------------------------------------------------------------------


class TestPipelines:
    def test_find_pipe_grep(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' | grep auth")
        assert "auth" in output["stdout"]

    def test_find_pipe_sort(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' -type f | sort")
        lines = output["stdout"].strip().splitlines()
        assert lines == sorted(lines)

    def test_find_pipe_wc(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' -type f | wc -l")
        count = int(output["stdout"].strip())
        assert count >= 5

    def test_grep_pipe_cut(self, router: ToolRouter) -> None:
        output = _run(router, "grep -rn 'def ' src/ | cut -d: -f1-2")
        assert "src/" in output["stdout"]

    def test_cat_pipe_grep(self, router: ToolRouter) -> None:
        output = _run(router, "cat src/main.py | grep import")
        assert "import" in output["stdout"]

    def test_find_pipe_head(self, router: ToolRouter) -> None:
        output = _run(router, "find . -type f | head -3")
        lines = output["stdout"].strip().splitlines()
        assert len(lines) == 3

    def test_triple_pipe(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' | grep -v __init__ | sort | head -5")
        assert "main.py" in output["stdout"]

    def test_grep_pipe_sort_pipe_uniq(self, router: ToolRouter) -> None:
        output = _run(router, "grep -rh 'import' src/ | sort | uniq")
        assert "import" in output["stdout"]


# ---------------------------------------------------------------------------
# Compound operators — &&, ||, ;
# ---------------------------------------------------------------------------


class TestCompoundOperators:
    def test_and_both_succeed(self, router: ToolRouter) -> None:
        output = _run(router, "ls src/ && cat README.md")
        assert "main.py" in output["stdout"]
        assert "Project" in output["stdout"]

    def test_and_first_fails(self, router: ToolRouter) -> None:
        result = router.execute("terminal", {"command": "ls nonexistent && cat README.md"})
        assert result.success
        assert "Project" not in result.output["stdout"]

    def test_or_first_fails(self, router: ToolRouter) -> None:
        output = _run(router, "grep 'nonexistent_pattern' src/main.py || echo 'not found'")
        assert "not found" in output["stdout"]

    def test_or_first_succeeds(self, router: ToolRouter) -> None:
        output = _run(router, "grep 'import' src/main.py || echo 'not found'")
        assert "import" in output["stdout"]
        assert "not found" not in output["stdout"]

    def test_semicolon_both_run(self, router: ToolRouter) -> None:
        output = _run(router, "ls src/; cat README.md")
        assert "main.py" in output["stdout"]
        assert "Project" in output["stdout"]

    def test_or_true_fallback(self, router: ToolRouter) -> None:
        output = _run(router, "grep 'nope' src/main.py || true")
        assert output["returncode"] == 0

    def test_false_or_command(self, router: ToolRouter) -> None:
        output = _run(router, "false || cat README.md")
        assert "Project" in output["stdout"]

    def test_complex_compound(self, router: ToolRouter) -> None:
        output = _run(
            router,
            "find . -name '*.py' | head -3 && grep -l 'flask' src/auth/login.py || echo 'done'",
        )
        assert output["returncode"] == 0


# ---------------------------------------------------------------------------
# Real investigation patterns — commands models actually issue
# ---------------------------------------------------------------------------


class TestInvestigationPatterns:
    def test_initial_directory_survey(self, router: ToolRouter) -> None:
        output = _run(router, "find . -maxdepth 2 -type f | sort")
        assert output["returncode"] == 0
        assert "src/main.py" in output["stdout"]

    def test_source_file_listing(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' -not -path '*/__pycache__/*' | sort")
        assert "main.py" in output["stdout"]

    def test_search_for_sql_patterns(self, router: ToolRouter) -> None:
        output = _run(router, "grep -rn 'execute\\|cursor\\|query' src/")
        assert "helpers.py" in output["stdout"]

    def test_search_for_hardcoded_secrets(self, router: ToolRouter) -> None:
        output = _run(router, "grep -rn 'SECRET\\|password\\|api_key' src/")
        assert "tokens.py" in output["stdout"]

    def test_read_suspicious_file(self, router: ToolRouter) -> None:
        output = _run(router, "cat -n src/auth/tokens.py")
        assert "hardcoded-secret" in output["stdout"]

    def test_check_imports(self, router: ToolRouter) -> None:
        output = _run(router, "head -5 src/auth/login.py")
        assert "flask" in output["stdout"]

    def test_find_config_files(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.txt' -o -name '*.cfg' -o -name '*.ini' | sort")
        assert "requirements.txt" in output["stdout"]

    def test_count_lines_in_module(self, router: ToolRouter) -> None:
        output = _run(router, "find src/ -name '*.py' -type f | sort | head -10")
        assert output["returncode"] == 0

    def test_search_with_context(self, router: ToolRouter) -> None:
        output = _run(router, "grep -B 2 -A 5 'execute_query' src/utils/helpers.py")
        assert "execute_query" in output["stdout"]
        assert "cursor" in output["stdout"]

    def test_file_structure_overview(self, router: ToolRouter) -> None:
        output = _run(router, "tree -L 3 --dirsfirst")
        assert "src" in output["stdout"]

    def test_check_file_sizes(self, router: ToolRouter) -> None:
        output = _run(router, "find . -name '*.py' -type f | sort | head -10")
        assert output["returncode"] == 0

    def test_search_for_input_handling(self, router: ToolRouter) -> None:
        output = _run(router, "grep -rn 'request\\.' src/")
        assert "login.py" in output["stdout"]

    def test_read_multiple_auth_files(self, router: ToolRouter) -> None:
        output = _run(
            router,
            "cat src/auth/login.py; echo '---'; cat src/auth/tokens.py",
        )
        assert "def login" in output["stdout"]
        assert "---" in output["stdout"]
        assert "create_token" in output["stdout"]

    def test_find_test_files(self, router: ToolRouter) -> None:
        output = _run(router, "find . -path '*/test*' -name '*.py'")
        assert "test_auth.py" in output["stdout"]

    def test_ripgrep_multiglob(self, router: ToolRouter) -> None:
        output = _run(router, "rg --glob '*.py' --glob '!*test*' 'import' src/")
        assert "import" in output["stdout"]

    def test_diff_related_files(self, router: ToolRouter) -> None:
        result = router.execute(
            "terminal",
            {"command": "diff src/auth/login.py src/auth/tokens.py"},
        )
        assert result.success
        assert result.output["returncode"] in (0, 1)

    def test_search_env_patterns(self, repository: Path) -> None:
        router = ToolRouter(repository, allow_sensitive_files=[".env.example"])
        output = _run(router, "cat .env.example")
        assert "DATABASE_URL" in output["stdout"]


# ---------------------------------------------------------------------------
# Behavioral changes from the shell-to-subprocess migration
# ---------------------------------------------------------------------------


class TestGlobExpansionRegression:
    """Glob expansion via pre-execution expansion for subprocess arg vectors."""

    def test_quoted_grep_pattern_is_not_expanded(self, tmp_path: Path) -> None:
        (tmp_path / "fooooo").write_text("", encoding="utf-8")
        (tmp_path / "data.txt").write_text("fo\n", encoding="utf-8")
        router = ToolRouter(tmp_path)

        output = _run(router, "grep 'foo*' data.txt")

        assert output["stdout"] == "fo\n"

    def test_ls_star_py(self, router: ToolRouter) -> None:
        output = _run(router, "ls src/*.py")
        assert "main.py" in output["stdout"]

    def test_cat_star_py(self, router: ToolRouter) -> None:
        output = _run(router, "cat src/*.py")
        assert "def main" in output["stdout"]

    def test_head_star_py(self, router: ToolRouter) -> None:
        output = _run(router, "head -1 src/auth/*.py")
        assert output["returncode"] == 0

    def test_find_name_glob_still_works(self, router: ToolRouter) -> None:
        """find -name does its own globbing internally, not via shell."""
        output = _run(router, "find . -name '*.py' -type f | wc -l")
        count = int(output["stdout"].strip())
        assert count >= 5

    def test_rg_glob_flag_still_works(self, router: ToolRouter) -> None:
        """rg --glob does its own globbing internally, not via shell."""
        output = _run(router, "rg --glob '*.py' 'import' src/")
        assert "import" in output["stdout"]

    def test_grep_include_glob_still_works(self, router: ToolRouter) -> None:
        """grep --include does its own globbing internally, not via shell."""
        output = _run(router, "grep -r --include='*.py' 'import' src/")
        assert "import" in output["stdout"]


class TestPathValidatorFalsePositives:
    """Regression tests: non-path arguments must not trigger path validation."""

    def test_grep_for_ssh_string(self, router: ToolRouter) -> None:
        """Searching for .ssh in code should not be blocked."""
        output = _run(router, "grep -r '.ssh' src/")
        assert output["returncode"] in (0, 1)

    def test_grep_for_aws_string(self, router: ToolRouter) -> None:
        """Searching for .aws in code should not be blocked."""
        output = _run(router, "grep -r '.aws' src/")
        assert output["returncode"] in (0, 1)

    def test_rg_for_kube_string(self, router: ToolRouter) -> None:
        """Searching for .kube references in code should not be blocked."""
        output = _run(router, "rg '.kube' src/")
        assert output["returncode"] in (0, 1)


class TestRemovedCommands:
    """Commands intentionally removed from the allowlist."""

    def test_ag_is_no_longer_allowed(self, router: ToolRouter) -> None:
        """ag (silver searcher) removed in favor of rg."""
        result = router.execute("terminal", {"command": "ag pattern src/"})
        assert not result.success

    def test_xargs_is_no_longer_allowed(self, router: ToolRouter) -> None:
        """xargs removed because it can execute arbitrary commands."""
        result = router.execute("terminal", {"command": "find . -name '*.py' | xargs grep import"})
        assert not result.success
