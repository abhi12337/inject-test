import base64
from importlib import resources

import pytest

from inject_test.attacks import (EXFIL_BASE, all_cases, categories, from_tag_chars, new_canary, render,
                                 select)


def test_library_shape():
    cases = all_cases()
    assert 40 <= len(cases) <= 60
    assert len({c.id for c in cases}) == len(cases)
    assert {c.category for c in cases} == set(categories())
    for c in cases:
        text = " ".join([c.input, c.document, c.payload, *c.turns])
        if c.detect != "leak":
            assert "{canary" in text, c.id


def test_data_file_has_no_invisible_characters():
    raw = resources.files("inject_test").joinpath("data/attacks.json").read_text(encoding="utf-8")
    assert not [ch for ch in raw if ord(ch) >= 0x2000]      # tag chars etc. are built at runtime


def test_canaries_are_unique_and_mixed():
    seen = {new_canary() for _ in range(500)}
    assert len(seen) == 500
    for c in list(seen)[:50]:
        assert c.startswith("ZQ") and len(c) == 12
        assert any(ch.isdigit() for ch in c) and any(ch.isalpha() for ch in c[2:])


@pytest.mark.parametrize("case", all_cases(), ids=lambda c: c.id)
def test_every_case_carries_its_canary(case):
    c = "ZQAB3CD4EF5G"
    r = render(case, c)
    sent = r.sent_text
    if case.detect == "leak":
        return
    if case.encode == "base64":
        blob = [w for w in sent.replace(":", " ").split() if len(w) > 30][-1]
        assert c in base64.b64decode(blob).decode()
    elif case.encode == "hex":
        assert c.encode().hex() in sent
    elif case.encode == "tags":
        assert c in from_tag_chars(sent) and c not in sent
    elif case.encode == "reverse":
        assert c[::-1] in sent
    elif case.encode == "rot13":
        assert c not in sent and "MDNO3PQ4RS5T" in sent
    elif case.id == "EN-008":
        assert c not in sent and c[:6] in sent and c[6:] in sent
    else:
        assert c in sent
    if case.category == "exfil" or "{exfil}" in case.input + case.document:
        assert EXFIL_BASE in sent and ".example/" in sent


def test_select_filters_and_errors():
    assert {c.category for c in select(["exfil", "tool"])} == {"exfil", "tool"}
    assert [c.id for c in select(None, ["in-003"])] == ["IN-003"]
    with pytest.raises(ValueError, match="unknown category"):
        select(["nope"])
    with pytest.raises(ValueError, match="unknown case"):
        select(None, ["XX-999"])
