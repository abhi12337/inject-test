"""Sending one attack to the configured target: an HTTP endpoint or a local Python function."""

from __future__ import annotations

import concurrent.futures as cf
import importlib
import importlib.util
import inspect
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse

from .config import ConfigError, TargetConfig

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class TargetError(Exception):
    """The request failed (network error, timeout, bad status, unparseable reply)."""


class Blocked(Exception):
    """The target answered with a status listed in blocked_status (a guardrail fired)."""


@dataclass
class Reply:
    text: str
    tool_text: str = ""        # tool calls, serialised, if the target exposes them
    elapsed: float = 0.0


def json_path(doc: Any, path: str) -> Any:
    """Tiny JSON path: 'a.b.0.c', '$.a.b[0].c' or 'choices[0].message.content'."""
    if not path or path in ("$", "."):
        return doc
    p = path[2:] if path.startswith("$.") else path.lstrip("$")
    p = p.replace("[", ".").replace("]", "")
    cur = doc
    for part in [x for x in p.split(".") if x != ""]:
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                raise KeyError(path) from None
        elif isinstance(cur, dict):
            if part not in cur:
                raise KeyError(path)
            cur = cur[part]
        else:
            raise KeyError(path)
    return cur


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(v, dict) and "text" in v for v in value):
        return "".join(str(v["text"]) for v in value)   # content-block arrays
    return json.dumps(value, ensure_ascii=False)


def build_messages(history: list[dict], turns_so_far: list[dict], user_input: str) -> list[dict]:
    return [*history, *turns_so_far, {"role": "user", "content": user_input}]


def fill_body(body: Any, *, user_input: str, document: str | None, messages: list[dict],
              json_strings: bool) -> Any:
    """Substitute the placeholders. Structured (dict/list) bodies get raw values (json.dumps
    escapes them later); string templates get JSON-escaped values when the body is JSON."""
    def esc(v: str) -> str:
        return json.dumps(v, ensure_ascii=False)[1:-1] if json_strings else v

    if isinstance(body, str):
        return (body.replace("{{messages}}", json.dumps(messages, ensure_ascii=False))
                    .replace("{{input}}", esc(user_input))
                    .replace("{{document}}", esc(document or "")))

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            if v == "{{messages}}":
                return messages
            return v.replace("{{input}}", user_input).replace("{{document}}", document or "")
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(body)


def _is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class RateLimiter:
    def __init__(self, per_second: float):
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self.lock = threading.Lock()
        self.next = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next)
            self.next = slot + self.interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class HttpTarget:
    def __init__(self, cfg: TargetConfig):
        self.cfg = cfg
        handlers = [urllib.request.ProxyHandler({})] if _is_loopback(cfg.url) else []
        self.opener = urllib.request.build_opener(*handlers)
        ctype = next((v for k, v in cfg.headers.items() if k.lower() == "content-type"), "")
        self.json_body = not isinstance(cfg.body, str) or "json" in ctype.lower()
        self.json_strings = isinstance(cfg.body, str) and "json" in ctype.lower()
        self.supports_document = "{{document}}" in json.dumps(cfg.body) or cfg.inline_documents
        self.supports_messages = "{{messages}}" in json.dumps(cfg.body)

    def send(self, user_input: str, document: str | None, messages: list[dict]) -> Reply:
        cfg = self.cfg
        if document is not None and cfg.inline_documents and "{{document}}" not in json.dumps(cfg.body):
            user_input = f"{user_input}\n\n<document>\n{document}\n</document>"
            if messages:
                messages = [*messages[:-1], {"role": "user", "content": user_input}]
            document = None
        body = fill_body(cfg.body, user_input=user_input, document=document, messages=messages,
                         json_strings=self.json_strings)
        data = (json.dumps(body, ensure_ascii=False) if not isinstance(body, str) else body).encode("utf-8")
        headers = dict(cfg.headers)
        if not isinstance(cfg.body, str) and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(cfg.url, data=None if cfg.method == "GET" else data,
                                     headers=headers, method=cfg.method)
        t0 = time.monotonic()
        try:
            with self.opener.open(req, timeout=cfg.timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as e:
            if e.code in cfg.blocked_status:
                raise Blocked(f"HTTP {e.code}") from None
            raise TargetError(f"HTTP {e.code} {e.reason}") from None
        except (socket.timeout, TimeoutError):
            raise TargetError(f"timed out after {cfg.timeout:g}s") from None
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise TargetError(f"timed out after {cfg.timeout:g}s") from None
            raise TargetError(f"connection failed: {reason}") from None
        except (ConnectionError, OSError) as e:
            raise TargetError(f"connection failed: {e}") from None
        elapsed = time.monotonic() - t0
        text = raw[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
        if not cfg.reply_path and not cfg.tool_calls_path:
            return Reply(text=text, elapsed=elapsed)
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            raise TargetError("response is not JSON (set reply_path = \"\" to use the raw body)") from None
        try:
            reply = _as_text(json_path(doc, cfg.reply_path)) if cfg.reply_path else text
        except KeyError:
            reply = ""
            if not cfg.tool_calls_path:
                raise TargetError(f"reply_path '{cfg.reply_path}' not found in the response") from None
        tool_text = ""
        if cfg.tool_calls_path:
            try:
                tool_text = _as_text(json_path(doc, cfg.tool_calls_path))
            except KeyError:
                tool_text = ""
        return Reply(text=reply, tool_text=tool_text, elapsed=elapsed)


def load_function(spec: str) -> Callable:
    """'package.module:function' or 'path/to/file.py:function'."""
    if ":" not in spec.replace(":\\", "").replace(":/", "") or spec.endswith(":"):
        raise ConfigError(f"--python expects module:function or path/file.py:function, got {spec!r}")
    mod_part, func_name = spec.rsplit(":", 1)
    try:
        if mod_part.endswith(".py") or os.sep in mod_part or "/" in mod_part:
            if not os.path.isfile(mod_part):
                raise ConfigError(f"python target file {mod_part} does not exist")
            name = "inject_test_target_" + os.path.splitext(os.path.basename(mod_part))[0]
            spec_ = importlib.util.spec_from_file_location(name, mod_part)
            module = importlib.util.module_from_spec(spec_)
            sys.modules[name] = module
            spec_.loader.exec_module(module)
        else:
            if os.getcwd() not in sys.path:
                sys.path.insert(0, os.getcwd())
            module = importlib.import_module(mod_part)
    except ConfigError:
        raise
    except Exception as e:  # noqa: BLE001 - user code
        raise ConfigError(f"cannot import {mod_part}: {type(e).__name__}: {e}") from None
    fn = getattr(module, func_name, None)
    if not callable(fn):
        raise ConfigError(f"{mod_part} has no callable {func_name}")
    return fn


class PythonTarget:
    """Calls fn(input, document=..., messages=...) with the keyword arguments it accepts.

    It may return a str (the reply) or a dict with "reply" (or "text") and optional
    "tool_calls". If reply_path is set it is applied to a dict return value.
    """

    _pool = None

    def __init__(self, cfg: TargetConfig, fn: Callable | None = None):
        self.cfg = cfg
        self.fn = fn or load_function(cfg.python)
        try:
            params = inspect.signature(self.fn).parameters
        except (TypeError, ValueError):
            params = {}
        var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        self.supports_document = var_kw or "document" in params or cfg.inline_documents
        self.supports_messages = var_kw or "messages" in params
        self._doc_kw = var_kw or "document" in params
        self._msg_kw = self.supports_messages
        self._pool = cf.ThreadPoolExecutor(max_workers=max(1, cfg.concurrency) * 2,
                                           thread_name_prefix="inject-test-py")

    def send(self, user_input: str, document: str | None, messages: list[dict]) -> Reply:
        kwargs: dict[str, Any] = {}
        if document is not None:
            if self._doc_kw:
                kwargs["document"] = document
            else:
                user_input = f"{user_input}\n\n<document>\n{document}\n</document>"
        if self._msg_kw and messages:
            kwargs["messages"] = messages
        t0 = time.monotonic()
        fut = self._pool.submit(self.fn, user_input, **kwargs)
        try:
            out = fut.result(timeout=self.cfg.timeout)
        except cf.TimeoutError:
            raise TargetError(f"timed out after {self.cfg.timeout:g}s") from None
        except Blocked:
            raise
        except Exception as e:  # noqa: BLE001 - user code
            raise TargetError(f"function raised {type(e).__name__}: {e}") from None
        elapsed = time.monotonic() - t0
        if isinstance(out, dict):
            if self.cfg.reply_path:
                try:
                    reply = _as_text(json_path(out, self.cfg.reply_path))
                except KeyError:
                    raise TargetError(f"reply_path '{self.cfg.reply_path}' not found in the return value") from None
            else:
                reply = _as_text(out.get("reply", out.get("text", "")))
            tools = out.get("tool_calls")
            if self.cfg.tool_calls_path:
                try:
                    tools = json_path(out, self.cfg.tool_calls_path)
                except KeyError:
                    tools = None
            return Reply(text=reply, tool_text=_as_text(tools) if tools else "", elapsed=elapsed)
        return Reply(text=_as_text(out), elapsed=elapsed)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def make_target(cfg: TargetConfig, fn: Callable | None = None):
    return PythonTarget(cfg, fn) if (cfg.is_python or fn) else HttpTarget(cfg)
