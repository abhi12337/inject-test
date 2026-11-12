"""Text, JSON and JUnit XML reports."""

from __future__ import annotations

import json
import os
import sys
import textwrap
import xml.etree.ElementTree as ET

from . import __version__
from .attacks import categories
from .mitigations import COMMON, MITIGATIONS
from .runner import CaseResult, category_stats, totals

COLORS = {
    "FAIL": "\033[1;31m",
    "PASS": "\033[32m",
    "SKIP": "\033[2m",
    "ERROR": "\033[33m",
    "hit": "\033[1;97;41m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}
AUTH_NOTE = "Only test systems you own or are explicitly authorised to test."


def use_color(stream=sys.stdout, force: bool | None = None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def failing_categories(results: list[CaseResult]) -> list[str]:
    cats = list(categories())
    failing = {r.case.category for r in results if r.status == "FAIL"}
    return [c for c in cats if c in failing]


def render_text(results: list[CaseResult], *, header: list[str], secrets: list[str], repeat: int,
                color: bool = False, brief: bool = False, footer: list[str] | None = None) -> str:
    def c(name: str, s: str) -> str:
        return f"{COLORS[name]}{s}{COLORS['reset']}" if color else s

    mark = (COLORS["hit"], COLORS["reset"]) if color else ("[[", "]]")
    out = [c("bold", f"inject-test {__version__}"), *header, ""]
    order = {cat: i for i, cat in enumerate(categories())}
    title_w = 52
    for r in sorted(results, key=lambda r: order.get(r.case.category, 99)):
        st = r.status
        if brief and st in ("PASS", "SKIP"):
            continue
        title = r.case.title if len(r.case.title) <= title_w else r.case.title[: title_w - 3] + "..."
        tally = "" if st == "SKIP" else f"{r.successes}/{r.completed}"
        if r.errors and st != "SKIP":
            tally += f" ({r.errors} error{'s' if r.errors > 1 else ''})"
        line = f"{c(st, f'{st:<5}')} {r.case.id:<8} {r.case.category:<10} {title:<{title_w}} {tally}".rstrip()
        out.append(line)
        if st == "FAIL":
            best = r.best_success()
            kinds = ", ".join(best.detection.kinds) if best and best.detection else ""
            out.append(c("dim", f"      detected: {kinds}"))
            ex = r.excerpt(secrets, mark=mark)
            out.append(textwrap.fill(ex, 100, initial_indent="      reply: ", subsequent_indent="             ", break_on_hyphens=False))
        elif st == "SKIP":
            out.append(c("dim", f"      skipped: {r.skip_reason}"))
        elif st == "ERROR" or r.errors:
            err = next((a.error for a in r.attempts if a.status == "error"), "")
            out.append(c("dim", f"      error: {err}"))
    out.append("")
    stats = category_stats(results)
    cat_names = categories()
    out.append(c("bold", "By category") + c("dim", "  (cases failed / cases run; attack success rate over all attempts)"))
    for cat in categories():
        s = stats.get(cat)
        if not s:
            continue
        ran = s.cases - s.skipped
        if ran == 0:
            out.append(f"  {cat:<10} {cat_names[cat]:<44} skipped")
            continue
        label = f"{s.failed}/{ran} failed"
        rate = f"{s.successes}/{s.completed} attempts ({_pct(s.rate)})" if s.completed else "no completed attempts"
        name = c("FAIL", f"{cat:<10}") if s.failed else f"{cat:<10}"
        out.append(f"  {name} {cat_names[cat]:<44} {label:<12} {rate}")
    fails = failing_categories(results)
    if fails and not brief:
        out.append("")
        out.append(c("bold", "Mitigations for failing categories"))
        out.append(textwrap.fill(COMMON, 96, initial_indent="  ", subsequent_indent="  "))
        for cat in fails:
            out.append("")
            out.append(f"  {c('bold', cat)}: {cat_names[cat]}")
            for m in MITIGATIONS[cat]:
                out.append(textwrap.fill(m, 96, initial_indent="    - ", subsequent_indent="      "))
    t = totals(results)
    out.append("")
    summary = (f"{t['failed']} failed, {t['passed']} passed, {t['skipped']} skipped, {t['errors']} errors; "
               f"attack success rate {_pct(t['success_rate'])} "
               f"({t['successful_attempts']}/{t['attempts_completed']} attempts"
               f"{f', repeat {repeat}' if repeat > 1 else ''})")
    out.append(c("bold", "Summary: ") + summary)
    if t["passed"] and not t["failed"]:
        out.append(c("dim", "Passing these cases is not proof the app is secure: see 'Limitations' in the README."))
    out += footer or []
    return "\n".join(out) + "\n"


def case_dict(r: CaseResult, secrets: list[str]) -> dict:
    best = r.best_success()
    d = {
        **r.case.to_dict(),
        "status": r.status,
        "successes": r.successes,
        "completed": r.completed,
        "errors": r.errors,
        "success_rate": round(r.rate, 4),
    }
    if r.skip_reason:
        d["skip_reason"] = r.skip_reason
    if best:
        d["detected"] = best.detection.kinds if best.detection else []
        d["excerpt"] = r.excerpt(secrets, mark=("[[", "]]"))
        if best.detection and best.detection.urls:
            d["exfil_urls"] = best.detection.urls
    if any(a.detection and a.detection.echo_only for a in r.attempts):
        d["echo_ignored"] = True
    errs = sorted({a.error for a in r.attempts if a.status == "error"})
    if errs:
        d["error_messages"] = errs
    return d


def render_json(results: list[CaseResult], *, meta: dict, secrets: list[str]) -> str:
    stats = category_stats(results)
    doc = {
        "tool": "inject-test",
        "version": __version__,
        **meta,
        "summary": totals(results),
        "categories": {
            cat: {"title": categories()[cat], "cases": s.cases, "failed": s.failed, "skipped": s.skipped,
                  "errors": s.errored, "successful_attempts": s.successes, "attempts_completed": s.completed,
                  "success_rate": round(s.rate, 4)}
            for cat, s in stats.items()
        },
        "mitigations": {cat: MITIGATIONS[cat] for cat in failing_categories(results)},
        "cases": [case_dict(r, secrets) for r in results],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _xml_safe(text: str) -> str:
    return "".join(ch for ch in text if ord(ch) in (9, 10, 13) or 0x20 <= ord(ch) < 0xD800 or 0xE000 <= ord(ch) <= 0xFFFD)


def render_junit(results: list[CaseResult], *, secrets: list[str]) -> str:
    t = totals(results)
    root = ET.Element("testsuites", name="inject-test", tests=str(t["cases"]), failures=str(t["failed"]),
                      errors=str(t["errors"]), skipped=str(t["skipped"]))
    stats = category_stats(results)
    suites: dict[str, ET.Element] = {}
    for cat, s in stats.items():
        suites[cat] = ET.SubElement(root, "testsuite", name=f"inject-test.{cat}", tests=str(s.cases),
                                    failures=str(s.failed), errors=str(s.errored), skipped=str(s.skipped))
    for r in results:
        elapsed = sum(a.elapsed for a in r.attempts)
        tc = ET.SubElement(suites[r.case.category], "testcase", classname=f"inject-test.{r.case.category}",
                           name=f"{r.case.id} {r.case.title}", time=f"{elapsed:.3f}")
        if r.status == "FAIL":
            best = r.best_success()
            kinds = ", ".join(best.detection.kinds) if best and best.detection else ""
            f = ET.SubElement(tc, "failure", type=kinds or "injection",
                              message=f"injection succeeded in {r.successes}/{r.completed} attempts ({kinds})")
            f.text = _xml_safe(r.excerpt(secrets, mark=("[[", "]]")))
        elif r.status == "SKIP":
            ET.SubElement(tc, "skipped", message=r.skip_reason)
        elif r.status == "ERROR":
            err = next((a.error for a in r.attempts if a.status == "error"), "error")
            ET.SubElement(tc, "error", message=_xml_safe(err))
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
