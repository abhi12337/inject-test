"""The built-in attack library (data/attacks.json) and per-attempt rendering."""

from __future__ import annotations

import base64
import codecs
import json
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

EXFIL_BASE = "https://attacker.example/c"     # reserved .example domain (RFC 2606): never resolves
CANARY_LETTERS = "ABCDEFGHJKMNPQRSTUVWXYZ"
CANARY_DIGITS = "23456789"
DETECTORS = ("canary", "leak", "exfil", "tool")
ENCODINGS = ("base64", "hex", "rot13", "leet", "reverse", "tags")
_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})


def new_canary() -> str:
    """A fresh, unguessable token: 'ZQ' + 6 letters and 4 digits in random order
    (no ambiguous characters; always mixed letters and digits so it never reads as a word)."""
    rng = secrets.SystemRandom()
    chars = [rng.choice(CANARY_LETTERS) for _ in range(6)] + [rng.choice(CANARY_DIGITS) for _ in range(4)]
    rng.shuffle(chars)
    return "ZQ" + "".join(chars)


def to_tag_chars(text: str) -> str:
    """Encode ASCII as invisible Unicode tag characters (U+E0000 block)."""
    return "".join(chr(0xE0000 + ord(c)) for c in text if 0x20 <= ord(c) < 0x7F)


def from_tag_chars(text: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) < 0xE007F)


@dataclass
class AttackCase:
    id: str
    category: str
    title: str
    input: str = ""
    document: str = ""
    turns: list[str] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)
    payload: str = ""
    encode: str = ""
    detect: str = "canary"

    @property
    def needs_document(self) -> bool:
        return bool(self.document)

    @property
    def needs_messages(self) -> bool:
        return bool(self.turns or self.history)

    def to_dict(self) -> dict:
        d = {"id": self.id, "category": self.category, "title": self.title, "detect": self.detect,
             "needs_document": self.needs_document, "needs_messages": self.needs_messages}
        if self.encode:
            d["encode"] = self.encode
        return d


@dataclass
class RenderedAttack:
    canary: str
    input: str                       # final user message
    document: str | None
    turns: list[str]                 # user turns, last one == input (multi-turn only)
    history: list[dict]
    sent_text: str                   # everything we sent, for the echo guard


def _encode(kind: str, text: str, canary: str) -> str:
    if kind == "leet":   # keep the canary itself intact
        return text.replace("{canary}", "\x00").translate(_LEET).replace("\x00", canary)
    text = text.replace("{canary}", canary)
    if kind == "base64":
        return base64.b64encode(text.encode()).decode()
    if kind == "hex":
        return text.encode().hex()
    if kind == "rot13":
        return codecs.encode(text, "rot13")
    if kind == "reverse":
        return text[::-1]
    if kind == "tags":
        return to_tag_chars(text)
    raise ValueError(f"unknown encoding {kind}")


def _fill(template: str, values: dict[str, str]) -> str:
    for k, v in values.items():
        template = template.replace("{" + k + "}", v)
    return template


def render(case: AttackCase, canary: str | None = None) -> RenderedAttack:
    canary = canary or new_canary()
    values = {"canary": canary, "canary_a": canary[:6], "canary_b": canary[6:], "exfil": EXFIL_BASE}
    if case.payload:
        enc = _encode(case.encode, case.payload, canary) if case.encode else _fill(case.payload, values)
        values["payload"] = enc
        values["hidden"] = enc if case.encode == "tags" else to_tag_chars(_fill(case.payload, values))
    turns = [_fill(t, values) for t in case.turns]
    history = [{"role": m["role"], "content": _fill(m["content"], values)} for m in case.history]
    user_input = turns[-1] if turns else _fill(case.input, values)
    document = _fill(case.document, values) if case.document else None
    sent = "\n".join([*turns, *(m["content"] for m in history), user_input, document or ""])
    return RenderedAttack(canary=canary, input=user_input, document=document, turns=turns,
                          history=history, sent_text=sent)


@lru_cache(maxsize=1)
def library() -> tuple[dict[str, str], tuple[AttackCase, ...]]:
    raw = json.loads(resources.files("inject_test").joinpath("data/attacks.json").read_text(encoding="utf-8"))
    cats: dict[str, str] = raw["categories"]
    cases = []
    for c in raw["cases"]:
        case = AttackCase(**{k: v for k, v in c.items()})
        assert case.category in cats, case.id
        assert case.detect in DETECTORS, case.id
        assert not case.encode or case.encode in ENCODINGS, case.id
        cases.append(case)
    return cats, tuple(cases)


def categories() -> dict[str, str]:
    return library()[0]


def all_cases() -> list[AttackCase]:
    return list(library()[1])


def select(only: list[str] | None = None, case_ids: list[str] | None = None) -> list[AttackCase]:
    cats = categories()
    only = [o.lower() for o in (only or [])]
    bad = [o for o in only if o not in cats]
    if bad:
        raise ValueError(f"unknown category: {', '.join(bad)} (choose from {', '.join(cats)})")
    ids = {i.upper() for i in (case_ids or [])}
    known = {c.id for c in all_cases()}
    missing = ids - known
    if missing:
        raise ValueError(f"unknown case id: {', '.join(sorted(missing))} (see `inject-test list`)")
    out = all_cases()
    if only:
        out = [c for c in out if c.category in only]
    if ids:
        out = [c for c in out if c.id in ids]
    return out
