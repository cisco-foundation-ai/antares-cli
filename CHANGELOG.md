# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial public release of Antares CLI.
- `antares sweep` — run one independent investigation per CWE across a repository.
- `antares query` — run a single CWE-targeted investigation.
- `antares plan` — show automatic CWE selection and rationale without running inference.
- `antares models profiles` — list configured inference profiles.
- `antares runs` — inspect local run history, traces, and portable exports.
- `antares tool` — non-interactive JSON interface for automation and pipelines.
- Repository-aware automatic CWE selection from the bundled MITRE CWE 4.20 taxonomy.
- SARIF, JSON, and Markdown report output.
- Interactive TUI for sweep progress.
- Shell completion for bash, zsh, fish, and PowerShell.
- Apache 2.0 license.
