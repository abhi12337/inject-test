"""Run attack cases against a target, with concurrency, a rate limit and repeats."""

from __future__ import annotations

import concurrent.futures as cf
import sys
import threading
from dataclasses import dataclass, field

from .attacks import AttackCase, render
from .config import Config
from .detect import Detection, detect, excerpt, redact_text
from .target import Blocked, RateLimiter, TargetError


@dataclass
class Attempt:
    status: str                    # success | defended | blocked | error
    canary: str = ""
    reply: str = ""                # already redacted
    detection: Detection | None = None
    error: str = ""
    elapsed: float = 0.0


@dataclass
class CaseResult:
    case: AttackCase
    attempts: list[Attempt] = field(default_factory=list)
    skip_reason: str = ""

    @property
    def successes(self) -> int:
        return sum(a.status == "success" for a in self.attempts)

    @property
    def completed(self) -> int:
        return sum(a.status in ("success", "defended", "blocked") for a in self.attempts)

    @property
    def errors(self) -> int:
        return sum(a.status == "error" for a in self.attempts)

    @property
    def status(self) -> str:
        if self.skip_reason:
            return "SKIP"
        if self.successes:
            return "FAIL"
        if self.completed == 0:
            return "ERROR"
        return "PASS"

    @property
    def rate(self) -> float:
        return self.successes / self.completed if self.completed else 0.0

    def best_success(self) -> Attempt | None:
        wins = [a for a in self.attempts if a.status == "success"]
        return min(wins, key=lambda a: len(a.reply)) if wins else None

    def excerpt(self, secrets: list[str], mark=("[[", "]]")) -> str:
        a = self.best_success()
        if not a:
            return ""
        return excerpt(a.reply, a.detection.needle if a.detection else a.canary, secrets, mark=mark)


def skip_reason(case: AttackCase, cfg: Config, target) -> str:
    if case.needs_messages and not target.supports_messages:
        return "multi-turn: the request body has no \"{{messages}}\" slot"
    if case.needs_document and not target.supports_document:
        return "indirect: no {{document}} slot (or set inline_documents = true)"
    if case.detect == "leak" and not cfg.detect.markers:
        return "set detect.system_prompt_canary to test system-prompt extraction"
    return ""


def run_attempt(case: AttackCase, cfg: Config, target, limiter: RateLimiter, canary: str | None = None) -> Attempt:
    r = render(case, canary)
    secrets = cfg.target.secrets
    convo: list[dict] = []
    turns = r.turns or [r.input]
    reply = None
    try:
        for turn in turns:
            messages = [*r.history, *convo, {"role": "user", "content": turn}]
            limiter.wait()
            reply = target.send(turn, r.document, messages)
            convo += [{"role": "user", "content": turn}, {"role": "assistant", "content": reply.text}]
    except Blocked as e:
        return Attempt(status="blocked", canary=r.canary, error=str(e))
    except TargetError as e:
        return Attempt(status="error", canary=r.canary, error=redact_text(str(e), secrets))
    det = detect(case_detect=case.detect, reply=reply.text, canary=r.canary, sent_text=r.sent_text,
                 tool_text=reply.tool_text, markers=cfg.detect.markers,
                 tool_patterns=cfg.detect.tool_patterns, echo_guard=cfg.detect.echo_guard)
    text = reply.text + (f"\n[tool calls] {reply.tool_text}" if reply.tool_text and "tool" in det.kinds
                         and r.canary.upper() not in reply.text.upper() else "")
    return Attempt(status="success" if det.success else "defended", canary=r.canary, reply=redact_text(text, secrets),
                   detection=det, elapsed=reply.elapsed)


def run_cases(cases: list[AttackCase], cfg: Config, target, *, repeat: int = 1,
              progress: bool = False) -> list[CaseResult]:
    results = [CaseResult(case=c, skip_reason=skip_reason(c, cfg, target)) for c in cases]
    jobs = [(res, i) for res in results if not res.skip_reason for i in range(repeat)]
    limiter = RateLimiter(cfg.target.rate_limit)
    lock = threading.Lock()
    done = 0
    slots: dict[int, list] = {id(res): [None] * repeat for res, _ in jobs}

    def work(res: CaseResult, i: int) -> None:
        nonlocal done
        att = run_attempt(res.case, cfg, target, limiter)
        with lock:
            slots[id(res)][i] = att
            done += 1
            if progress:
                sys.stderr.write(f"\r  {done}/{len(jobs)} attempts")
                sys.stderr.flush()

    with cf.ThreadPoolExecutor(max_workers=max(1, cfg.target.concurrency)) as pool:
        for f in [pool.submit(work, res, i) for res, i in jobs]:
            f.result()
    if progress and jobs:
        sys.stderr.write("\r" + " " * 30 + "\r")
    for res in results:
        if not res.skip_reason:
            res.attempts = [a for a in slots[id(res)] if a is not None]
    return results


@dataclass
class CategoryStats:
    category: str
    cases: int = 0
    failed: int = 0
    skipped: int = 0
    errored: int = 0
    successes: int = 0
    completed: int = 0

    @property
    def rate(self) -> float:
        return self.successes / self.completed if self.completed else 0.0


def category_stats(results: list[CaseResult]) -> dict[str, CategoryStats]:
    out: dict[str, CategoryStats] = {}
    for r in results:
        s = out.setdefault(r.case.category, CategoryStats(r.case.category))
        s.cases += 1
        s.failed += r.status == "FAIL"
        s.skipped += r.status == "SKIP"
        s.errored += r.status == "ERROR"
        s.successes += r.successes
        s.completed += r.completed
    return out


def totals(results: list[CaseResult]) -> dict:
    succ = sum(r.successes for r in results)
    comp = sum(r.completed for r in results)
    return {
        "cases": len(results),
        "failed": sum(r.status == "FAIL" for r in results),
        "passed": sum(r.status == "PASS" for r in results),
        "skipped": sum(r.status == "SKIP" for r in results),
        "errors": sum(r.status == "ERROR" for r in results),
        "attempts": sum(len(r.attempts) for r in results),
        "attempts_completed": comp,
        "attempts_errored": sum(r.errors for r in results),
        "successful_attempts": succ,
        "success_rate": round(succ / comp, 4) if comp else 0.0,
    }
