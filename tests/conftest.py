"""Shared fixtures: an in-process HTTP target on 127.0.0.1 (no external network) and
helpers to write Python-function targets and config files."""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
TOKEN_RE = re.compile(r"ZQ[A-Z0-9]{10}")


def docs_only_bot(body: dict) -> dict:
    """Robust to the user's own message, vulnerable to anything in the retrieved document."""
    doc = body.get("document") or ""
    m = TOKEN_RE.search(doc)
    if m:
        return {"reply": f"Summary done. {m.group(0)}"}
    return {"reply": "I can only help with your account."}


class FakeServer:
    def __init__(self, bot, *, delay: float = 0.0, status: int = 200, raw: bool = False):
        self.bot, self.delay, self.status, self.raw = bot, delay, status, raw
        self.requests: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                outer.requests.append({"body": body, "headers": dict(self.headers), "path": self.path})
                if outer.delay:
                    time.sleep(outer.delay)
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                out = outer.bot(body, dict(self.headers))
                data = (out if outer.raw else json.dumps(out)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except OSError:
                    pass

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/chat"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def fake_server():
    servers = []

    def _make(bot=None, **kw):
        b = bot or (lambda body, headers: docs_only_bot(body))
        s = FakeServer(b, **kw)
        servers.append(s)
        return s

    yield _make
    for s in servers:
        s.close()


@pytest.fixture
def write_config(tmp_path):
    def _write(target: dict, detect: dict | None = None, name: str = "inject-test.json") -> Path:
        p = tmp_path / name
        p.write_text(json.dumps({"target": target, "detect": detect or {}}), encoding="utf-8")
        return p

    return _write


@pytest.fixture
def py_target(tmp_path):
    """Write a Python module and return 'path/to/file.py:func'."""
    def _make(source: str, func: str = "handle") -> str:
        p = tmp_path / f"target_{abs(hash(source)) % 10**8}.py"
        p.write_text(source, encoding="utf-8")
        return f"{p}:{func}"

    return _make


def http_target(url: str, **extra) -> dict:
    t = {"url": url, "reply_path": "reply", "timeout": 5, "concurrency": 4,
         "headers": {"Content-Type": "application/json"},
         "body": {"message": "{{input}}", "document": "{{document}}"}}
    t.update(extra)
    return t
