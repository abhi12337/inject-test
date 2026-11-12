# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-11

First release.

### Added

- `inject-test run`: sends prompt-injection attack cases to the one endpoint in your config
  (or a local Python function with `--python module:function` / `path/file.py:function`) and
  reports, per case, whether the attack succeeded.
- Canary-based detection, no LLM judge: a fresh random canary per attempt; success means the
  canary shows up in the reply, in a markdown/HTML image or link URL (exfiltration), in a tool
  call (from `tool_calls_path`, `tool_patterns` or built-in patterns), or a planted
  `system_prompt_canary` / `leak_markers` string appears. An echo guard ignores canaries that
  only appear inside a verbatim echo of the attack text.
- Built-in library of 57 cases in 9 categories: direct override, role-play, system-prompt
  extraction, delimiter confusion, encoding/translation, multi-turn, indirect injection via
  `{{document}}` (HTML comments, hidden elements, invisible Unicode tag characters built at
  runtime), markdown exfiltration, tool-call coercion.
- Config in `inject-test.toml` (Python 3.11+) or `inject-test.json`: URL, method, headers with
  `${ENV}` expansion (values never printed and redacted from output), body template with
  `{{input}}`, `{{document}}` and `{{messages}}`, JSON reply path, tool-calls path, timeout,
  concurrency, rate limit, `blocked_status`, `inline_documents`.
- `--repeat N` with per-case and per-category success rates, `--only`, `--case`, `--fail-on`
  as a count or a rate, `--json`, `--junit FILE`, `--brief`, `--no-color`, `--dry-run`,
  exit codes `0` / `1` / `2`.
- Mitigations printed for every failing category.
- `inject-test init` (example config) and `inject-test list`.
- A deliberately vulnerable local demo bot (`examples/demo_target.py`, no real LLM) and a
  GitHub Actions example.
