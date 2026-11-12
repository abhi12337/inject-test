import json
import sys

import pytest

from inject_test.cli import main
from inject_test.config import ConfigError, load_config, parse_config, redact_url
from inject_test.target import fill_body, json_path

SECRET = "tok" + "_live_" + "FAKEfake0123456789"


def test_env_expansion_and_secret_collection():
    cfg = parse_config({"target": {
        "url": "https://app.example.com/chat?key=${APP_KEY}",
        "headers": {"Authorization": "Bearer ${APP_TOKEN}", "Content-Type": "application/json",
                    "X-Team": "static-team-value"},
        "body": {"q": "{{input}}"},
    }}, env={"APP_TOKEN": SECRET, "APP_KEY": "k3y-value-123"})
    t = cfg.target
    assert t.headers["Authorization"] == f"Bearer {SECRET}"
    assert SECRET in t.secrets and "k3y-value-123" in t.secrets
    assert "static-team-value" in t.secrets            # non-trivial header values are treated as secret
    assert "application/json" not in t.secrets
    assert "k3y-value-123" not in t.describe() and "****" in t.describe()


def test_missing_env_var_is_an_error():
    with pytest.raises(ConfigError, match="NOPE_TOKEN"):
        parse_config({"target": {"url": "http://127.0.0.1/x", "headers": {"A": "${NOPE_TOKEN}"},
                                 "body": {"q": "{{input}}"}}}, env={})


@pytest.mark.parametrize("target, msg", [
    ({"url": "ftp://x/y", "body": {"q": "{{input}}"}}, "http"),
    ({"body": {"q": "{{input}}"}}, "url is required"),
    ({"url": "http://127.0.0.1/x", "body": {"q": "static"}}, "{{input}}"),
    ({"url": "http://127.0.0.1/x", "method": "DELETE", "body": {"q": "{{input}}"}}, "method"),
    ({"url": "http://127.0.0.1/x", "timeout": "soon", "body": {"q": "{{input}}"}}, "timeout"),
])
def test_invalid_targets(target, msg):
    with pytest.raises(ConfigError, match=msg.replace("{", r"\{").replace("}", r"\}")):
        parse_config({"target": target}, env={})


def test_unknown_key_and_bad_regex():
    with pytest.raises(ConfigError, match="unknown top-level"):
        parse_config({"target": {"url": "http://127.0.0.1/", "body": "{{input}}"}, "detct": {}}, env={})
    with pytest.raises(ConfigError, match="invalid regex"):
        parse_config({"target": {"url": "http://127.0.0.1/", "body": "{{input}}"},
                      "detect": {"tool_patterns": ["(unclosed"]}}, env={})


def test_json_file_and_python_override(tmp_path, monkeypatch):
    p = tmp_path / "inject-test.json"
    p.write_text(json.dumps({"target": {"url": "http://127.0.0.1:1/chat", "body": {"m": "{{input}}"}},
                             "detect": {"system_prompt_canary": "PLANTED-1"}}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None)                          # found by default name
    assert cfg.target.url.endswith("/chat") and cfg.detect.markers == ["PLANTED-1"]
    cfg = load_config(None, python_target="mod:fn")
    assert cfg.target.is_python and cfg.target.describe() == "python function mod:fn"


def test_no_config_is_an_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="inject-test init"):
        load_config(None)


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib needs 3.11")
def test_init_toml_round_trip(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--format", "toml"]) == 0
    cfg = load_config("inject-test.toml")
    assert cfg.target.reply_path == "reply" and cfg.target.concurrency == 2
    assert cfg.target.body == {"message": "{{input}}", "document": "{{document}}"}
    assert main(["init", "--format", "toml"]) == 2           # refuses to overwrite
    assert main(["init", "--format", "toml", "--force"]) == 0
    assert "authorised" in capsys.readouterr().out


def test_init_json_round_trip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--format", "json"]) == 0
    assert load_config("inject-test.json").target.rate_limit == 2.0


@pytest.mark.skipif(sys.version_info >= (3, 11), reason="only 3.10 lacks tomllib")
def test_toml_on_310_explains(tmp_path):
    p = tmp_path / "inject-test.toml"
    p.write_text("[target]\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="3.11"):
        load_config(str(p))


def test_json_path_variants():
    doc = {"choices": [{"message": {"content": "hi"}}], "out": [{"text": "a"}, {"text": "b"}]}
    assert json_path(doc, "choices.0.message.content") == "hi"
    assert json_path(doc, "$.choices[0].message.content") == "hi"
    assert json_path(doc, "choices[0].message") == {"content": "hi"}
    with pytest.raises(KeyError):
        json_path(doc, "choices.3.message")


def test_fill_body_structured_and_string():
    msgs = [{"role": "user", "content": 'say "x"'}]
    out = fill_body({"m": "{{input}}", "d": "Doc: {{document}}", "h": "{{messages}}", "n": 3},
                    user_input='say "x"', document=None, messages=msgs, json_strings=False)
    assert out == {"m": 'say "x"', "d": "Doc: ", "h": msgs, "n": 3}
    s = fill_body('{"m": "{{input}}", "h": {{messages}}}', user_input='a "q"\nb', document=None,
                  messages=msgs, json_strings=True)
    assert json.loads(s) == {"m": 'a "q"\nb', "h": msgs}


def test_redact_url_query_params():
    assert redact_url("https://x.example/a?api_key=abc&x=1", []) == "https://x.example/a?api_key=****&x=1"
