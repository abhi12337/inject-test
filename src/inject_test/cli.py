"""Command line interface.

  inject-test init [--format toml|json]
  inject-test list [--only CATEGORY]
  inject-test run  [--config FILE | --python module:function] [--only CATEGORY] [--repeat N]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from pathlib import Path

from . import __version__
from .attacks import categories, from_tag_chars, render, select
from .detect import redact_text
from .config import EXAMPLE_TOML, NON_SECRET_HEADERS, ConfigError, example_json, load_config
from .report import AUTH_NOTE, render_json, render_junit, render_text, use_color
from .runner import run_cases, totals
from .target import fill_body, make_target

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def parse_fail_on(value: str) -> tuple[str, float]:
    """'never' | '<count>' (cases that failed) | '<rate>%' or '0.x' (overall attack success rate)."""
    v = value.strip().lower()
    if v == "never":
        return "never", 0.0
    try:
        if v.endswith("%"):
            rate = float(v[:-1]) / 100
            if not 0 < rate <= 1:
                raise ValueError
            return "rate", rate
        if "." in v:
            rate = float(v)
            if not 0 < rate <= 1:
                raise ValueError
            return "rate", rate
        n = int(v)
        if n < 1:
            raise ValueError
        return "count", float(n)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid --fail-on {value!r}: use a count (1, 3), a rate (10%, 0.1) or 'never'") from None


def exit_code_for(results, fail_on: tuple[str, float]) -> int:
    kind, threshold = fail_on
    t = totals(results)
    if kind == "never":
        return EXIT_OK
    if kind == "count":
        return EXIT_FAIL if t["failed"] >= threshold else EXIT_OK
    return EXIT_FAIL if t["attempts_completed"] and t["success_rate"] >= threshold else EXIT_OK


def _split(values: list[str]) -> list[str]:
    return [x.strip() for v in values for x in v.split(",") if x.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inject-test",
        description="Prompt-injection test kit: runs canary-based injection attacks against YOUR OWN "
                    "LLM app endpoint (or a local Python function) and reports which ones succeeded. "
                    + AUTH_NOTE,
        epilog="Passing is not proof of security. See 'Limitations' in the README.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    i = sub.add_parser("init", help="write an example config file")
    i.add_argument("--format", choices=["toml", "json"], default=None,
                   help="toml (Python 3.11+, default there) or json (default on 3.10)")
    i.add_argument("--path", default=None, help="file to write (default: inject-test.toml / .json)")
    i.add_argument("--force", action="store_true", help="overwrite an existing file")

    ls = sub.add_parser("list", help="list the built-in attack cases")
    ls.add_argument("--only", action="append", default=[], metavar="CATEGORY",
                    help="only these categories (repeatable or comma-separated)")
    ls.add_argument("--json", action="store_true", help="print JSON")

    r = sub.add_parser("run", help="run the attack cases against the configured target")
    r.add_argument("-c", "--config", default=None,
                   help="config file (default: ./inject-test.toml, then ./inject-test.json)")
    r.add_argument("--python", default=None, metavar="MODULE:FUNCTION",
                   help="test a local function instead of HTTP: package.module:func or path/file.py:func")
    r.add_argument("--only", action="append", default=[], metavar="CATEGORY",
                   help="only these categories (repeatable or comma-separated); see `inject-test list`")
    r.add_argument("--case", action="append", default=[], metavar="ID",
                   help="only these case ids (repeatable or comma-separated), e.g. --case IN-003")
    r.add_argument("--repeat", type=int, default=1, metavar="N",
                   help="run every case N times with fresh canaries; LLMs are non-deterministic (default: 1)")
    r.add_argument("--concurrency", type=int, default=None, metavar="N", help="override target.concurrency")
    r.add_argument("--timeout", type=float, default=None, metavar="SECONDS", help="override target.timeout")
    r.add_argument("--fail-on", type=parse_fail_on, default=parse_fail_on("1"), metavar="THRESHOLD",
                   help="exit 1 when this many cases failed (e.g. 1, 3) or the overall attack success "
                        "rate reaches a rate (e.g. 10%%, 0.1); 'never' always exits 0 (default: 1)")
    r.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    r.add_argument("--junit", default=None, metavar="FILE", help="also write a JUnit XML report to FILE")
    r.add_argument("--brief", action="store_true", help="only failing cases, no mitigations")
    r.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    r.add_argument("--dry-run", action="store_true",
                   help="print the request that would be sent for the first selected case, send nothing")
    return parser


def cmd_init(args) -> int:
    fmt = args.format or ("toml" if sys.version_info >= (3, 11) else "json")
    path = Path(args.path or f"inject-test.{fmt}")
    if path.exists() and not args.force:
        print(f"error: {path} already exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_ERROR
    path.write_text(EXAMPLE_TOML if fmt == "toml" else example_json(), encoding="utf-8")
    print(f"Wrote {path}. Edit target.url, headers and body for your app, then run: inject-test run")
    print(AUTH_NOTE)
    return EXIT_OK


def cmd_list(args) -> int:
    try:
        cases = select(_split(args.only))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        sys.stdout.write(json.dumps({"categories": categories(), "cases": [c.to_dict() for c in cases]},
                                    indent=2) + "\n")
        return EXIT_OK
    cats = categories()
    for cat in cats:
        group = [c for c in cases if c.category == cat]
        if not group:
            continue
        print(f"{cat}: {cats[cat]} ({len(group)})")
        for c in group:
            needs = [n for n, on in (("document", c.needs_document), ("messages", c.needs_messages),
                                     (f"detect={c.detect}", c.detect != "canary"),
                                     (f"encode={c.encode}", bool(c.encode))) if on]
            extra = f"  [{', '.join(needs)}]" if needs else ""
            print(f"  {c.id:<8} {c.title}{extra}")
        print()
    n = len({c.category for c in cases})
    print(f"{len(cases)} case(s) in {n} categor{'y' if n == 1 else 'ies'}")
    return EXIT_OK


def visible(text: str) -> str:
    """Write invisible Unicode tag runs out as [hidden tag text: '...'] so nothing invisible is printed."""
    def sub(m: re.Match) -> str:
        return f"[hidden tag text: {from_tag_chars(m.group(0))!r}]"
    text = re.sub("[\U000E0000-\U000E007F]+", sub, text)
    return re.sub("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
                  lambda m: f"<U+{ord(m.group(0)):04X}>", text)


def _dry_run(cfg, target, case) -> int:
    r = render(case, "ZQDRYRUN0000")
    print(f"Case {case.id} ({case.category}): {case.title}")
    print(f"Target: {cfg.target.describe()}")
    if cfg.target.is_python:
        kw = {"document": r.document} if r.document is not None else {}
        print(f"Call: fn({visible(r.input)!r}{', ' + ', '.join(f'{k}=...' for k in kw) if kw else ''})")
        return EXIT_OK
    for k, v in cfg.target.headers.items():
        print(f"Header: {k}: {v if k.lower() in NON_SECRET_HEADERS else '****'}")
    messages = [*r.history, {"role": "user", "content": r.turns[0] if r.turns else r.input}]
    body = fill_body(cfg.target.body, user_input=messages[-1]["content"], document=r.document,
                     messages=messages, json_strings=getattr(target, "json_strings", False))
    text = json.dumps(body, indent=2, ensure_ascii=False) if not isinstance(body, str) else body
    print("Body:")
    print(textwrap.indent(visible(redact_text(text, cfg.target.secrets)), "  "))
    print("(nothing was sent)")
    return EXIT_OK


def cmd_run(args) -> int:
    if args.repeat < 1:
        print("error: --repeat must be >= 1", file=sys.stderr)
        return EXIT_ERROR
    try:
        cfg = load_config(args.config, python_target=args.python)
        if args.concurrency is not None:
            cfg.target.concurrency = max(1, args.concurrency)
        if args.timeout is not None:
            cfg.target.timeout = max(0.1, args.timeout)
        cases = select(_split(args.only), _split(args.case))
        target = make_target(cfg.target)
    except (ConfigError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    if not cases:
        print("error: no cases selected", file=sys.stderr)
        return EXIT_ERROR
    if args.dry_run:
        return _dry_run(cfg, target, cases[0])
    progress = not args.json and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
    try:
        results = run_cases(cases, cfg, target, repeat=args.repeat, progress=progress)
    finally:
        if hasattr(target, "close"):
            target.close()
    t = totals(results)
    exit_code = exit_code_for(results, args.fail_on)
    problem = ""
    if t["skipped"] == t["cases"]:
        problem = "every selected case was skipped (see the skip reasons); nothing was tested"
    elif t["attempts_completed"] == 0:
        problem = "no attempt completed: the target could not be reached or returned errors"
    if problem:
        exit_code = EXIT_ERROR
    secrets = cfg.target.secrets
    if args.junit:
        Path(args.junit).write_text(render_junit(results, secrets=secrets), encoding="utf-8")
    if args.json:
        sys.stdout.write(render_json(results, secrets=secrets, meta={
            "target": cfg.target.describe(),
            "headers_sent": cfg.target.header_names,
            "repeat": args.repeat,
            "fail_on": {"kind": args.fail_on[0], "threshold": args.fail_on[1]},
            "exit_code": exit_code,
            **({"problem": problem} if problem else {}),
        }))
    else:
        hdrs = f"  (headers sent: {', '.join(cfg.target.header_names)})" if cfg.target.header_names else ""
        ran = t["cases"] - t["skipped"]
        header = [f"Target: {cfg.target.describe()}{hdrs}", AUTH_NOTE,
                  f"{t['cases']} case(s): {ran} run x {args.repeat} repeat(s), {t['skipped']} skipped"]
        footer = []
        if problem:
            footer.append(f"error: {problem}")
        if args.junit:
            footer.append(f"JUnit report: {args.junit}")
        footer.append(f"Exit code: {exit_code}")
        sys.stdout.write(render_text(results, header=header, secrets=secrets, repeat=args.repeat,
                                     color=use_color(force=False if args.no_color else None),
                                     brief=args.brief, footer=footer))
    return exit_code


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass
    args = build_parser().parse_args(argv)
    return {"init": cmd_init, "list": cmd_list, "run": cmd_run}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
