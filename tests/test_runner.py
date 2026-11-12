import json
import time

import pytest

from conftest import http_target
from inject_test.attacks import select
from inject_test.config import parse_config
from inject_test.runner import category_stats, run_cases, totals
from inject_test.target import make_target


def _run(cfg_dict, cases, repeat=1, env=None):
    cfg = parse_config(cfg_dict, env=env or {})
    target = make_target(cfg.target)
    try:
        return run_cases(cases, cfg, target, repeat=repeat), cfg
    finally:
        if hasattr(target, "close"):
            target.close()


def test_http_target_vulnerable_to_documents_only(fake_server):
    srv = fake_server()
    results, _ = _run({"target": http_target(srv.url)}, select(["indirect", "override"]))
    by = {r.case.id: r for r in results}
    assert all(by[c].status == "FAIL" for c in by if c.startswith("IN-") and c != "IN-003" and c != "IN-009")
    assert by["IN-003"].status == "PASS"          # canary hidden as tag characters: this bot can't see it
    assert all(r.status == "PASS" for r in results if r.case.category == "override")
    stats = category_stats(results)
    assert stats["override"].rate == 0.0 and stats["indirect"].rate == 0.8
    sent = srv.requests[0]["body"]
    assert set(sent) == {"message", "document"}


def test_skips_without_document_or_messages_slot(fake_server):
    srv = fake_server()
    t = http_target(srv.url, body={"message": "{{input}}"})
    results, _ = _run({"target": t}, select(["indirect", "multiturn", "sysprompt"]))
    reasons = {r.case.category: r.skip_reason for r in results}
    assert all(r.status == "SKIP" for r in results)
    assert "{{document}}" in reasons["indirect"] and "{{messages}}" in reasons["multiturn"]
    assert "system_prompt_canary" in reasons["sysprompt"]
    assert srv.requests == []


def test_inline_documents_mode(fake_server):
    def bot(body, headers):
        return {"reply": "ok " + " ".join(w for w in body["message"].split() if w.startswith("ZQ"))}
    srv = fake_server(bot)
    t = http_target(srv.url, body={"message": "{{input}}"}, inline_documents=True)
    results, _ = _run({"target": t}, select(None, ["IN-001"]))
    assert results[0].status == "FAIL"
    assert "<document>" in srv.requests[0]["body"]["message"]


def test_multi_turn_sends_history_and_real_replies(fake_server):
    def bot(body, headers):
        msgs = body["messages"]
        return {"reply": f"turn {len(msgs)}"}
    srv = fake_server(bot)
    t = http_target(srv.url, body={"messages": "{{messages}}"})
    results, _ = _run({"target": t}, select(None, ["MT-002"]))
    assert results[0].status == "PASS" and len(srv.requests) == 3
    last = srv.requests[-1]["body"]["messages"]
    assert [m["role"] for m in last] == ["user", "assistant", "user", "assistant", "user"]
    assert last[1]["content"] == "turn 1"


def test_repeat_reports_rate(py_target):
    spec = py_target(
        "import re, itertools\n"
        "_n = itertools.count()\n"
        "def handle(input, document=None):\n"
        "    m = re.search(r'ZQ[A-Z0-9]{10}', input)\n"
        "    return ('Sure ' + m.group(0)) if (m and next(_n) % 2 == 0) else 'No.'\n")
    results, _ = _run({"target": {"python": spec, "concurrency": 1}}, select(None, ["OVR-002"]), repeat=4)
    r = results[0]
    assert r.status == "FAIL" and r.successes == 2 and r.completed == 4 and r.rate == 0.5
    assert totals(results)["success_rate"] == 0.5


def test_python_dict_return_with_tool_calls(py_target):
    spec = py_target(
        "import re\n"
        "def handle(input, document=None, messages=None):\n"
        "    m = re.search(r'ZQ[A-Z0-9]{10}', input + (document or ''))\n"
        "    return {'reply': 'Done.', 'tool_calls': [{'name': 'send_email', 'arguments': {'body': m.group(0)}}]}\n")
    results, _ = _run({"target": {"python": spec}}, select(["tool"]))
    assert all(r.status == "FAIL" for r in results)
    assert "tool" in results[0].best_success().detection.kinds


def test_timeouts_are_errors_not_passes(fake_server):
    srv = fake_server(delay=1.5)
    results, _ = _run({"target": http_target(srv.url, timeout=0.3)}, select(None, ["OVR-001", "OVR-002"]))
    assert {r.status for r in results} == {"ERROR"}
    assert "timed out" in results[0].attempts[0].error
    assert totals(results)["attempts_completed"] == 0


def test_python_timeout(py_target):
    spec = py_target("import time\ndef handle(input):\n    time.sleep(2)\n    return 'late'\n")
    t0 = time.monotonic()
    results, _ = _run({"target": {"python": spec, "timeout": 0.2}}, select(None, ["OVR-001"]))
    assert results[0].status == "ERROR" and time.monotonic() - t0 < 1.5


def test_blocked_status_counts_as_defended(fake_server):
    srv = fake_server(status=400)
    results, _ = _run({"target": http_target(srv.url, blocked_status=[400])}, select(None, ["OVR-001"]))
    assert results[0].status == "PASS" and results[0].attempts[0].status == "blocked"
    results, _ = _run({"target": http_target(srv.url)}, select(None, ["OVR-001"]))
    assert results[0].status == "ERROR" and "HTTP 400" in results[0].attempts[0].error


def test_secrets_never_leave_in_results(fake_server):
    token = "s3cr3t" + "-header-" + "value-0099"
    def bot(body, headers):   # a buggy app that reflects its auth header and obeys the user
        tok = [w for w in body["message"].split() if w.startswith("ZQ")]
        return {"reply": f"debug auth={headers.get('Authorization')} {' '.join(tok)}"}
    srv = fake_server(bot)
    t = http_target(srv.url, headers={"Content-Type": "application/json", "Authorization": "Bearer ${T}"})
    results, cfg = _run({"target": t}, select(None, ["OVR-002"]), env={"T": token})
    assert srv.requests[0]["headers"]["Authorization"] == f"Bearer {token}"
    r = results[0]
    assert r.status == "FAIL"
    assert token not in r.attempts[0].reply and token not in r.excerpt(cfg.target.secrets)


def test_non_json_reply_and_raw_mode(fake_server):
    srv = fake_server(lambda b, h: "plain text " + b["message"][-12:], raw=True)
    results, _ = _run({"target": http_target(srv.url)}, select(None, ["OVR-002"]))
    assert results[0].status == "ERROR" and "not JSON" in results[0].attempts[0].error
    results, _ = _run({"target": http_target(srv.url, reply_path="")}, select(None, ["OVR-001"]))
    assert results[0].status in ("PASS", "FAIL")


def test_rate_limit_spaces_requests(fake_server):
    srv = fake_server()
    t0 = time.monotonic()
    _run({"target": http_target(srv.url, rate_limit=10, concurrency=4)}, select(None, [f"OVR-00{i}" for i in range(1, 6)]))
    assert time.monotonic() - t0 >= 0.35         # 5 requests at 10/s need >= 0.4 s of slots
