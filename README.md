<!--
SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Antares CLI

Model-assisted, file-level vulnerability localization for source repositories,
powered by Foundation AI Antares models.

Antares reports candidate files for human review. It does not currently provide
line-level locations, code snippets, or remediation, and model
results can vary between identical runs. Treat every result as a lead to verify,
not as proof that code is vulnerable or safe.

> **Model access:** Follow the current access instructions on each Hugging Face
> model card. If authentication is required, authenticate the model server that
> downloads the weights.

## Requirements and installation

Antares CLI requires:

- Python 3.11 or later;
- [`uv`](https://docs.astral.sh/uv/) for the installation commands below;
- Linux or macOS (native Windows is not currently supported);
- a streaming OpenAI-compatible inference endpoint implementing
  `POST /v1/completions`; and
- standard POSIX inspection utilities. `ripgrep` (`rg`) and `tree` are
  recommended.

Install the released CLI from PyPI:

```bash
uv tool install cisco-antares-cli
```

Install from a source checkout instead:

```bash
uv tool install .
```

Or install a downloaded wheel:

```bash
uv tool install ./dist/cisco_antares_cli-*.whl
```

For development:

```bash
uv sync --group dev
```

Use `uv tool upgrade cisco-antares-cli` to upgrade an existing PyPI installation.

## Serve and configure a model

Antares requires a streaming OpenAI-compatible `POST /v1/completions`
endpoint. Chat completions are not equivalent: their server-side chat template
changes the raw Antares tool prompt. The served model name must exactly match
the model ID configured in the CLI.

This contract is validated with vLLM 0.19.1; pin that version when reproducing
the tested setup. Replace the repository and served name with the exact
checkpoint you intend to run:

```bash
export HF_TOKEN="your-hugging-face-token"
export MODEL_REPOSITORY="your-org/your-antares-checkpoint"
export SERVED_MODEL_NAME="your-exact-model-id"

vllm serve "$MODEL_REPOSITORY" \
  --served-model-name "$SERVED_MODEL_NAME" \
  --host 0.0.0.0 \
  --port 8000 \
  --trust-remote-code \
  --dtype bfloat16 \
  --max-model-len 16384 \
  --tensor-parallel-size 1 \
  --gpu-memory-utilization 0.90 \
  --generation-config vllm
```

`HF_TOKEN` is used by the model server to download weights. It is separate from
the optional credential used by Antares to call an authenticated inference
endpoint. Use a single GPU with enough VRAM for the selected checkpoint and its
16K context; only increase tensor parallelism when one GPU cannot hold it.

Create a user-owned profile in `~/.antares/profiles.toml`. The endpoint-neutral
defaults match the Antares deployment contract even when the exact model ID is
not in the CLI's small display catalog: raw completions, 16,384 context tokens,
4,096 maximum output tokens, temperature 0.3, top-p 1.0, frequency penalty 0.3,
the Antares stop tokens, and a 300-second cold-start timeout. The values are
shown explicitly here for reproducibility and may be omitted from the profile:

```toml
[profiles.hosted-antares]
display_name = "Hosted Antares"
model = "your-exact-model-id"
backend = "remote"
endpoint_env = "ANTARES_ENDPOINT"
api_key_env = "ANTARES_API_KEY"
context_window = 16384
remote_timeout_seconds = 300

[profiles.hosted-antares.generation]
max_tokens = 4096
temperature = 0.3
top_p = 1.0
frequency_penalty = 0.3
stop_tokens = ["<|end_of_text|>", "<|start_of_role|>"]
use_completions_api = true
```

Point the profile at the full completions route. Set the credential only when
the inference endpoint requires bearer authentication:

```bash
export ANTARES_ENDPOINT="http://localhost:8000/v1/completions"
export ANTARES_API_KEY="your-endpoint-key"
```

Confirm that the configured model ID and endpoint are the intended values, then
run an explicit CWE query or a repository-aware sweep:

```bash
antares models list
antares query ./your-project --cwe CWE-89 --profile hosted-antares
antares sweep ./your-project --profile hosted-antares
```

Antares sends the configured `model` value unchanged. Profiles are connection
configuration, not aliases: do not rely on a provider to rewrite the model ID.

Running `antares` without a subcommand opens the setup wizard when both stdin
and stdout are interactive terminals. In non-interactive environments it prints
help instead.

## Models

| Canonical model ID | Hugging Face model | Intended use |
| --- | --- | --- |
| `antares-350m` | [fdtn-ai/antares-350m](https://huggingface.co/fdtn-ai/antares-350m) | Lower-resource and quick scans |
| `antares-1b` | [fdtn-ai/antares-1b](https://huggingface.co/fdtn-ai/antares-1b) | General code audits and deeper scans |

The model card for the checkpoint you host is the source of truth for access
requirements and weight metadata. Antares sends the model ID selected with
`--model`, `ANTARES_MODEL`, or a profile exactly as provided. It does not map
legacy names to these canonical IDs.

## Command modes

| Command | Behavior |
| --- | --- |
| `antares query PATH --cwe CWE-...` | Runs one investigation for one or more explicit CWE IDs. |
| `antares sweep PATH` | Runs one independent investigation per explicit or automatically selected CWE. |
| `antares plan PATH` | Shows automatic selection and rationale without model inference. |
| `antares models list` | Lists configured inference profiles. |
| `antares runs ...` | Inspects local run history and investigation traces. |
| `antares tool query --stdin` | Runs a query from a JSON request and prints JSON. |
| `antares tool sweep --stdin` | Runs a sweep from a JSON request and prints JSON. |

`PATH` must be an existing, readable repository directory. Add request-specific
guidance with `--query` (`-q`). For a sweep, that guidance is applied to every
CWE investigation.

Sensitive files are excluded from local profiling, immutable snapshots, and
model tools by default. When a scan genuinely requires one, authorize only that
exact repository-relative file at runtime:

```bash
antares query ./your-project \
  --cwe CWE-798 \
  --allow-sensitive-file .env.example \
  --allow-sensitive-file tests/fixtures/test-key.pem
```

Repeat `--allow-sensitive-file` for additional files. Globs, directories,
symlinks, absolute paths, parent traversal, missing files, and unprotected files
are rejected. The equivalent tool JSON field is an array named
`allow_sensitive_files`.

Run `antares COMMAND --help` for the complete option reference.

## Sweep selection and tool budgets

When `--cwe` is omitted, a sweep selects up to 50 CWE targets and executes up
to 8 investigations concurrently by default:

```bash
# Change the number of selected targets.
antares sweep ./your-project --max-cwes 20

# Change concurrency independently (1-32).
antares sweep ./your-project --workers 4
```

`--max-cwes` controls the number of automatically selected targets, capped by
the eligible catalog entries. `--workers` controls endpoint concurrency. An
explicit `--cwe` list preserves the requested order and is not truncated by
`--max-cwes`:

```bash
antares sweep ./your-project --cwe CWE-89,CWE-78,CWE-918
```

Automatic selection uses the bundled MITRE CWE 4.20 taxonomy (released
2026-04-30; 969 weaknesses) and repository evidence. Candidate scopes are:

- `auto`: repository-aware selection from the non-deprecated catalog;
- `top25`: the bundled MITRE CWE Top 25 set; and
- `owasp`: the bundled MITRE view of the OWASP Top Ten.

Use `--cwe-level` to filter automatic candidates to `pillar`, `class`, `base`,
`variant`, or `compound`; the default is `all`. Inspect the exact selection
without contacting an inference endpoint:

```bash
antares plan ./your-project
antares plan ./your-project --scope top25
antares plan ./your-project --scope owasp --cwe-level base --max-cwes 20
antares plan ./your-project --format json
```

Each investigation may make up to 15 model-requested repository tool calls by default.
Set a value from 1 through 50 with `--tool-budget`. A query receives one budget;
each sweep target receives its own budget.

```bash
antares query ./your-project --cwe CWE-89 --tool-budget 30
antares sweep ./your-project --tool-budget 30
```

## Output and exit status

Every completed `query` or `sweep` saves JSON, Markdown, and SARIF reports by
default. Antares creates one private directory per execution under
`~/.local/share/antares-cli/reports/` (or `$ANTARES_DATA_DIR/reports/`) and
prints a clickable path when the scan finishes:

```text
Reports (JSON, Markdown, SARIF) → …/reports/EXECUTION_ID
```

Each report directory contains `report.json`, `report.md`, and `report.sarif`.
Omitting `--report-format` is equivalent to `--report-format all`; both save all
three files. Use `--output` to choose a different directory. Use a named
`--report-format` when a consumer needs one format, or repeat the option for a
subset:

```bash
# Save all three formats in a chosen directory.
antares query ./your-project --cwe CWE-89 --output ./reports/order-audit

# Explicitly save all three formats (the same behavior as omitting this option).
antares query ./your-project --cwe CWE-89 --report-format all

# Save only JSON.
antares query ./your-project --cwe CWE-89 --report-format json

# Save JSON and SARIF.
antares sweep ./your-project \
  --report-format json --report-format sarif

# Do not save shareable report artifacts.
antares query ./your-project --cwe CWE-89 --no-report
```

`--format json`, `--format markdown`, and `--format sarif` serialize one format
to stdout for pipelines. Saved reports are still generated unless
`--no-report` is present. The report-directory link, selection diagnostics, and
warnings are written to stderr so machine-readable stdout stays valid. Using
`--format` disables the sweep TUI.

Without `--format`, `query` renders a human-readable scan summary followed by
finding cards. An interactive `sweep` uses the TUI; use `--no-tui` for the same
headless terminal summary. The summary reports completion status, finding and
affected-file counts, CWE coverage, duration, and operational warnings before
showing findings. Markdown reports use the same outcome-first organization and
group findings by filename, then by canonical CWE ID and name.

Serialized reports and `antares tool` responses omit local invocation details,
Git metadata, Python executable paths, and private investigation-trace paths.
They retain the target directory label, model/request metadata, and any explicit
`--query` text; do not put secrets in scan instructions.

Findings identify files and CWE IDs. `submission_rank` is the model's one-based
ordering within one investigation; sweep ranks are local to each CWE and are not
a global ranking. SARIF locations are file-level and currently use note severity.

For the `query` and `sweep` commands:

| Exit code | Meaning |
| --- | --- |
| `0` | The requested work completed. Findings may still be present. |
| `1` | The work completed with findings and `--fail-on-findings` was set. |
| `2` | The invocation or configuration was invalid, or model/worker failure left the result incomplete. |

Incomplete results are still emitted with warnings before exit 2. Antares then
attempts to record an `incomplete` history entry; an unwritable history directory
produces a warning without discarding the result.
Use `--fail-on-findings` in CI only when candidate findings should fail the job.

## JSON automation interface

`antares tool` accepts a JSON object on stdin (up to 1,000,000 characters) and
prints a JSON result on stdout.

Shared request fields:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `target` | string | `.` | Existing, readable repository directory. |
| `cwe_ids` | string or string array | none | Required for `query`; optional for `sweep`. |
| `query` | string or null | null | Additional investigation instructions. |
| `profile` | string or null | null | Named connection profile. |
| `model` | string or null | configured model | Served model ID, sent exactly as provided. |
| `backend` | string or null | `remote` | Inference backend. |
| `endpoint` | string or null | configured endpoint | OpenAI-compatible endpoint. |
| `api_key` | string or null | configured credential | Prefer an environment variable or profile. |
| `tool_budget` | integer | `15` | Range 1-50, per investigation. |

Sweep-only fields:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `workers` | integer | `8` | Concurrent investigations, range 1-32. |
| `selection.scope` | string | `auto` | `auto`, `top25`, or `owasp`. |
| `selection.cwe_level` | string | `all` | `all`, `pillar`, `class`, `base`, `variant`, or `compound`. |
| `selection.max_cwes` | integer | `50` | Positive automatic-selection limit. |

The three `selection` fields may alternatively be supplied at the top level.
Do not supply the same field in both locations; ambiguous requests are rejected.

```bash
printf '%s\n' \
  '{"target":"./your-project","cwe_ids":["CWE-89"],"tool_budget":20}' \
  | antares tool query --stdin

printf '%s\n' \
  '{"target":"./your-project","workers":4,"selection":{"scope":"owasp","cwe_level":"base","max_cwes":20}}' \
  | antares tool sweep --stdin
```

Tool commands exit 2 when operational failures make a result incomplete;
candidate findings alone do not change their exit status.

## Configuration

Antares contains model behavior defaults but no hosted inference connection.
The simplest runtime configuration uses environment variables:

| Variable | Purpose |
| --- | --- |
| `ANTARES_ENDPOINT` | Base URL for the inference endpoint. |
| `ANTARES_API_KEY` | Optional bearer credential for that endpoint. |
| `ANTARES_MODEL` | Required served model ID, sent exactly as provided. |
| `ANTARES_REMOTE_TIMEOUT_SECONDS` | Total inference request deadline; defaults to 300 seconds for cold starts. |
| `ANTARES_IGNORE_PATHS` | Comma-separated paths or a JSON string array to exclude. |
| `ANTARES_DATA_DIR` | Local history and trace directory. |

For named connections, create `~/.antares/profiles.toml`:

```toml
[profiles.local-vllm]
display_name = "Local vLLM"
model = "antares-1b"
backend = "remote"
endpoint = "http://localhost:8000/v1/completions"
api_key_env = "ANTARES_API_KEY"
```

Endpoint URLs and credentials can both be resolved indirectly:

```toml
[profiles.managed-runtime]
model = "antares-1b"
backend = "remote"
endpoint_env = "INFERENCE_ENDPOINT"
api_key_env = "INFERENCE_API_KEY"
```

Keep profiles outside repositories and keep credential values in environment
variables or a secret manager, not in TOML. Inspect available profiles with:

```bash
antares models list
antares query ./your-project --cwe CWE-89 --profile local-vllm
```

A repository `.antares.toml` is deliberately untrusted. Its only accepted
setting is `ignore_paths`; model, endpoint, backend, credential, timeout, and
data-directory values in that file are ignored. It cannot authorize sensitive
files; `--allow-sensitive-file` or the matching tool JSON field must be supplied
for each invocation.

```toml
ignore_paths = [
  ".env",
  "secrets/**",
  "generated/**",
]
```

## Repository isolation and data handling

`query` and `sweep` send request instructions, repository paths, the initial file
list, and source content selected during model-requested inspection to the
configured inference endpoint. Only scan code that you are authorized to send
to that endpoint; Antares does not control endpoint-side logging or retention.
`plan` performs local profiling only and does not contact an inference endpoint.

Before inference, Antares creates a temporary snapshot of eligible repository
files. The model's command executor runs inside that snapshot, never in the
working copy. Write permissions are removed, symlinks that resolve outside the
repository are discarded, and model-issued commands are restricted to a parsed
allowlist of read-only inspection utilities without network clients.

Files matching `.env*`, private-key extensions (`.pem`, `.key`, `.p12`, `.pfx`,
`.jks`, and `.keystore`), common credential filenames, or credential directories
such as `.ssh`, `.aws`, `.azure`, `.docker`, `.gnupg`, `.kube`, and gcloud are
omitted unless individually authorized. Authorized relative paths are retained
in run metadata for auditability; file contents are never added to authorization
logs.

The snapshot excludes these directory names by default:

```text
.antares-data  .git          .gradle       .hg           .mypy_cache
.nox           .pytest_cache .ruff_cache   .svn          .tox
.venv          .worktrees    __pycache__   node_modules  venv
```

Repository `.gitignore` rules are not automatically applied. Source-bearing
directories named `build`, `dist`, `target`, or `vendor` are scanned by default;
add generated or irrelevant instances to `.antares.toml` before scanning.

Snapshot limits are 100,000 files, 2 GiB total, and 256 MiB for any one file.
If a repository exceeds a limit, Antares stops before inference and identifies
the path or budget to reduce with `ignore_paths`.

## Run history and trace exports

Every successful or failed scan attempts to record local provenance. By default Antares
uses `~/.local/share/antares-cli`; set `ANTARES_DATA_DIR` to choose another
location. If the default location has no writable parent, Antares falls back to
`.antares-data` in the current directory. Default report bundles use the same
data root under `reports/`; run records and investigation traces remain under
their existing private directories.

If history persistence fails, Antares warns on stderr and preserves completed
terminal or JSON output. An explicitly requested `--export` cannot be built
without its private history record and exits 2 after preserving any report that
was already written. Export filenames must end in `.tar.gz`.

Private local investigation traces may contain prompts, model responses, source
excerpts, tool commands and results, request instructions, repository paths, and
Git metadata. They persist until you remove them. Review them with:

```bash
antares runs list
antares runs show RUN_ID --summary
antares runs trace RUN_ID
antares runs trace RUN_ID --cat
```

Create a portable bundle from a completed scan or from history:

```bash
antares query ./your-project --cwe CWE-89 --export run.tar.gz
antares runs export RUN_ID --output run.tar.gz
```

Portable exports redact raw trace message content, tool arguments, tool-result
summaries, ingest paths and queries, endpoint URLs, and known credential fields.
They retain run provenance, request metadata, invocation data, repository and
finding file paths, Git metadata, model configuration, findings, and errors.
Request metadata may include `--query` text. Inspect every bundle before sharing
it and never place secrets in request instructions.

Git provenance includes the repository root, commit, branch, and sanitized origin
URL when available. Antares deliberately does not inspect working-tree status:
`git status` can execute repository-configured content filters in an untrusted
target. Targets whose `.git` marker is a file (including linked worktrees and
submodules) omit Git provenance rather than following an external Git directory.

## Shell completion

Generate a completion script from the live command tree for `bash`, `zsh`,
`fish`, `powershell`, or `pwsh`:

```bash
antares completion zsh
```

Save or source the generated script using the normal completion mechanism for
your shell. PowerShell completion generation does not imply native Windows scan
support.

## Licensing and third-party notices

Antares CLI includes a derived snapshot of the MITRE Common Weakness
Enumeration taxonomy. The required MITRE copyright designation and license are
reproduced in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and shipped
beside the CWE data inside the Python package. The current upstream terms are
available from the [official CWE Terms of
Use](https://cwe.mitre.org/about/termsofuse.html).

The MITRE terms apply only to the CWE-derived content. Antares CLI source code is
licensed under the [Apache License 2.0](LICENSE).
