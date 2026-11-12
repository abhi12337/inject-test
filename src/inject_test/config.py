"""Configuration: inject-test.toml (Python 3.11+) or inject-test.json (any version).

Only the endpoint written in the config (or the --python function) is ever contacted.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_FILES = ("inject-test.toml", "inject-test.json")
ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
NON_SECRET_HEADERS = {"content-type", "accept", "user-agent", "accept-encoding", "accept-language"}


class ConfigError(Exception):
    """Bad or missing configuration (exit code 2)."""


@dataclass
class TargetConfig:
    url: str = ""
    method: str = "POST"
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None                      # dict/list (JSON) or str template
    reply_path: str = ""                  # "" = whole response body is the reply
    tool_calls_path: str = ""
    timeout: float = 30.0
    concurrency: int = 1
    rate_limit: float = 0.0               # requests per second, 0 = unlimited
    blocked_status: list[int] = field(default_factory=list)
    inline_documents: bool = False
    python: str = ""                      # "module:function" or "path/file.py:function"
    secrets: list[str] = field(default_factory=list)   # values to redact everywhere

    @property
    def is_python(self) -> bool:
        return bool(self.python)

    @property
    def header_names(self) -> list[str]:
        return list(self.headers)

    def describe(self) -> str:
        if self.is_python:
            return f"python function {self.python}"
        return f"{self.method} {redact_url(self.url, self.secrets)}"

    def _template_text(self) -> str:
        return self.body if isinstance(self.body, str) else json.dumps(self.body)


@dataclass
class DetectConfig:
    system_prompt_canary: str = ""
    leak_markers: list[str] = field(default_factory=list)
    tool_patterns: list[str] = field(default_factory=list)
    echo_guard: bool = True

    @property
    def markers(self) -> list[str]:
        return [m for m in [self.system_prompt_canary, *self.leak_markers] if m and m.strip()]


@dataclass
class Config:
    target: TargetConfig
    detect: DetectConfig
    path: str = ""


def _expand(value: Any, secrets: list[str], env: dict[str, str]) -> Any:
    if isinstance(value, str):
        def sub(m: re.Match) -> str:
            name = m.group(1)
            if name not in env:
                raise ConfigError(f"environment variable {name} is not set (referenced as ${{{name}}})")
            secrets.append(env[name])
            return env[name]
        return ENV_RE.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand(v, secrets, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, secrets, env) for v in value]
    return value


def _load_raw(path: Path) -> dict:
    text = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".toml":
        if sys.version_info < (3, 11):
            raise ConfigError(f"{path}: TOML needs Python 3.11+ (tomllib). Use inject-test.json on 3.10 "
                              "(`inject-test init --format json`).")
        import tomllib
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{path}: invalid TOML: {e}") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path}: invalid JSON: {e}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be an object")
    return data


def find_config(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise ConfigError(f"config file {explicit} does not exist")
        return p
    for name in DEFAULT_FILES:
        if Path(name).is_file():
            return Path(name)
    return None


def _num(d: dict, key: str, default, kind=float, minimum=None):
    v = d.get(key, default)
    try:
        v = kind(v)
    except (TypeError, ValueError):
        raise ConfigError(f"target.{key} must be a number, got {v!r}") from None
    if minimum is not None and v < minimum:
        raise ConfigError(f"target.{key} must be >= {minimum}")
    return v


def parse_config(data: dict, *, env: dict[str, str] | None = None, path: str = "") -> Config:
    env = dict(os.environ) if env is None else env
    known = {"target", "detect"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown top-level key(s): {', '.join(sorted(unknown))} (expected [target], [detect])")
    t = data.get("target") or {}
    d = data.get("detect") or {}
    if not isinstance(t, dict) or not isinstance(d, dict):
        raise ConfigError("[target] and [detect] must be tables/objects")
    secrets: list[str] = []
    headers_raw = t.get("headers") or {}
    if not isinstance(headers_raw, dict):
        raise ConfigError("target.headers must be a table/object")
    headers = {str(k): str(_expand(str(v), secrets, env)) for k, v in headers_raw.items()}
    for k, v in headers.items():            # every non-trivial header value is treated as secret
        if k.lower() not in NON_SECRET_HEADERS and len(v) >= 6:
            secrets.append(v)
            if " " in v:
                secrets.append(v.split(" ", 1)[1])
    target = TargetConfig(
        url=_expand(str(t.get("url", "")), secrets, env),
        method=str(t.get("method", "POST")).upper(),
        headers=headers,
        body=_expand(t.get("body", {"input": "{{input}}"}), secrets, env),
        reply_path=str(t.get("reply_path", "")),
        tool_calls_path=str(t.get("tool_calls_path", "")),
        timeout=_num(t, "timeout", 30.0, float, 0.1),
        concurrency=_num(t, "concurrency", 1, int, 1),
        rate_limit=_num(t, "rate_limit", 0.0, float, 0.0),
        blocked_status=[int(s) for s in (t.get("blocked_status") or [])],
        inline_documents=bool(t.get("inline_documents", False)),
        python=str(t.get("python", "")),
        secrets=sorted({s for s in secrets if s and len(s) >= 4}, key=len, reverse=True),
    )
    if target.method not in {"POST", "PUT", "PATCH", "GET"}:
        raise ConfigError(f"target.method {target.method} is not supported (POST, PUT, PATCH, GET)")
    if not target.python:
        if not target.url:
            raise ConfigError("target.url is required (or target.python / --python for a local function)")
        scheme = urlparse(target.url).scheme
        if scheme not in ("http", "https"):
            raise ConfigError(f"target.url must be http(s), got {scheme or 'no scheme'}")
        if "{{input}}" not in target._template_text() and "{{messages}}" not in target._template_text():
            raise ConfigError("target.body must contain {{input}} (or {{messages}}) so attacks can be sent")
    for key in ("leak_markers", "tool_patterns"):
        if not isinstance(d.get(key, []), list):
            raise ConfigError(f"detect.{key} must be a list")
    detect = DetectConfig(
        system_prompt_canary=str(_expand(str(d.get("system_prompt_canary", "")), [], env)),
        leak_markers=[str(_expand(str(m), [], env)) for m in d.get("leak_markers", [])],
        tool_patterns=[str(p) for p in d.get("tool_patterns", [])],
        echo_guard=bool(d.get("echo_guard", True)),
    )
    for p in detect.tool_patterns:
        try:
            re.compile(p)
        except re.error as e:
            raise ConfigError(f"detect.tool_patterns: invalid regex {p!r}: {e}") from None
    return Config(target=target, detect=detect, path=path)


def load_config(path: str | None, *, python_target: str | None = None,
                env: dict[str, str] | None = None) -> Config:
    p = find_config(path)
    data: dict = _load_raw(p) if p else {}
    if python_target:
        data.setdefault("target", {})
        data["target"] = {**data["target"], "python": python_target}
        data["target"].setdefault("body", {"input": "{{input}}"})
    elif p is None:
        raise ConfigError("no inject-test.toml / inject-test.json here. Run `inject-test init` to create one, "
                          "pass --config FILE, or test a local function with --python module:function")
    return parse_config(data, env=env, path=str(p) if p else "")


def redact(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "****")
    return text


def redact_url(url: str, secrets: list[str]) -> str:
    url = redact(url, secrets)
    return re.sub(r"(?i)([?&](?:key|api[_-]?key|token|access_token|sig|signature|secret|code)=)[^&#]+",
                  r"\1****", url)


EXAMPLE_TOML = '''# inject-test configuration.
# Only point this at systems you own or are explicitly authorised to test.
# Secrets: write ${ENV_VAR} and export the variable; values are never printed.

[target]
url = "http://127.0.0.1:8787/chat"
method = "POST"
timeout = 30            # seconds per request
concurrency = 2         # parallel requests
rate_limit = 2.0        # max requests per second (0 = unlimited)
reply_path = "reply"    # JSON path to the reply text, e.g. "choices.0.message.content"; "" = raw body
# tool_calls_path = "choices.0.message.tool_calls"   # where tool calls appear, if your API returns them
# blocked_status = [400]   # HTTP statuses that mean "blocked by a guardrail" (counted as defended)
# inline_documents = true  # no document slot? send indirect-injection documents inside the input

[target.headers]
Content-Type = "application/json"
# Authorization = "Bearer ${MY_APP_TOKEN}"

# The request body. {{input}} is replaced by the attack text, {{document}} by a
# "retrieved" document (indirect injection), and a value of exactly "{{messages}}" by a
# [{"role": ..., "content": ...}] array (multi-turn cases).
[target.body]
message = "{{input}}"
document = "{{document}}"
# messages = "{{messages}}"

[detect]
# Plant a unique phrase in your system prompt (e.g. "Internal ref: ZEBRA-PLUM-4471") and
# put it here: system-prompt extraction cases fail if it appears in a reply.
system_prompt_canary = ""
leak_markers = []        # other distinctive strings from your system prompt
tool_patterns = []       # regexes that mean "the reply contains a tool call", e.g. ['"name"\\s*:\\s*"send_email"']
echo_guard = true        # ignore canaries that only appear inside an echo of the attack text
'''


def example_json() -> str:
    doc = {
        "target": {
            "url": "http://127.0.0.1:8787/chat",
            "method": "POST",
            "timeout": 30,
            "concurrency": 2,
            "rate_limit": 2.0,
            "reply_path": "reply",
            "headers": {"Content-Type": "application/json"},
            "body": {"message": "{{input}}", "document": "{{document}}"},
        },
        "detect": {"system_prompt_canary": "", "leak_markers": [], "tool_patterns": [], "echo_guard": True},
    }
    return json.dumps(doc, indent=2) + "\n"
