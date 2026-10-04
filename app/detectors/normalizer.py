"""Input normalization and de-obfuscation.

`normalize()` returns a cleaned text plus extra "views" of the text (decoded base64, hex, URL-encoding,
ROT13, reversed text, de-leeted text, hidden Unicode tag characters...). Detectors scan every view so an
attack hidden inside an encoding is still seen.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

MAX_VIEW_CHARS = 20_000
MAX_DEPTH = 2

# Cyrillic / Greek look-alikes -> Latin. Only applied inside words that mix scripts (so real Russian/Greek
# text is left alone).
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "У": "Y",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "ρ": "p", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Za-z])(?:0x)?(?:[0-9a-fA-F]{2}[ :,-]?){10,}(?![0-9A-Za-z])")
_URL_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}[^%]{0,40}){3,}")
_UESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
_ENTITY_RE = re.compile(r"&(?:#\d{2,5}|#x[0-9a-fA-F]{2,4}|[a-zA-Z]{2,8});")
_SPACED_RE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z][ .\-_*]){4,}[A-Za-z](?![A-Za-z0-9])")
_WORD_RE = re.compile(r"\w+", re.UNICODE)


@dataclass
class View:
    label: str
    text: str


@dataclass
class NormalizedText:
    clean: str
    views: list[View] = field(default_factory=list)  # always starts with the "plain" view
    flags: list[str] = field(default_factory=list)  # e.g. ["zero_width_removed", "base64_decoded"]


def decode_unicode_tags(text: str) -> str:
    """Characters U+E0020..U+E007E mirror ASCII and are invisible; attackers use them to smuggle text."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def strip_invisible(text: str) -> tuple[str, bool]:
    out = "".join(c for c in text if unicodedata.category(c) != "Cf")
    return out, out != text


def _script(ch: str) -> str:
    if not ch.isalpha():
        return ""
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "other"
    for s in ("LATIN", "CYRILLIC", "GREEK", "CJK", "HIRAGANA", "KATAKANA", "HANGUL", "ARABIC", "DEVANAGARI", "HEBREW"):
        if name.startswith(s):
            return s
    return "other"


def fold_homoglyphs(text: str) -> tuple[str, bool]:
    changed = False

    def fix(m: re.Match[str]) -> str:
        nonlocal changed
        w = m.group(0)
        scripts = {_script(c) for c in w if c.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            changed = True
            return "".join(HOMOGLYPHS.get(c, c) for c in w)
        return w

    return _WORD_RE.sub(fix, text), changed


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _looks_like_text(s: str) -> bool:
    if len(s) < 8 or _printable_ratio(s) < 0.95:
        return False
    letters = sum(1 for c in s if c.isalpha() or c == " ")
    return letters / len(s) >= 0.6


def _try_b64(blob: str) -> str | None:
    s = blob.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
        out = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return out if _looks_like_text(out) else None


def _try_hex(blob: str) -> str | None:
    h = re.sub(r"0x|[ :,-]", "", blob)
    if len(h) % 2:
        return None
    try:
        out = bytes.fromhex(h).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return out if _looks_like_text(out) else None


def decode_encodings(text: str) -> list[View]:
    """Find encoded blobs in `text` and return decoded views (one level only)."""
    views: list[View] = []
    for m in _B64_RE.finditer(text):
        dec = _try_b64(m.group(0))
        if dec:
            views.append(View("base64", dec))
    for m in _HEX_RE.finditer(text):
        dec = _try_hex(m.group(0))
        if dec:
            views.append(View("hex", dec))
    if _URL_RE.search(text):
        dec = unquote(text)
        if dec != text:
            views.append(View("url", dec))
    if _UESC_RE.search(text):
        try:
            dec = re.sub(r"(?:\\u[0-9a-fA-F]{4})+", lambda m: codecs.decode(m.group(0), "unicode_escape"), text)
            views.append(View("unicode_escape", dec))
        except (UnicodeDecodeError, ValueError):
            pass
    if _ENTITY_RE.search(text):
        dec = html.unescape(text)
        if dec != text:
            views.append(View("html_entity", dec))
    return views


def deobfuscate(text: str) -> str:
    """Collapse 'i g n o r e' / 'i.g.n.o.r.e' spellings and fold leetspeak inside letter-bearing words."""
    t = text
    toks = t.split()
    singles = sum(1 for x in toks if len(x) == 1 and x.isalpha())
    if len(toks) >= 8 and singles / len(toks) >= 0.5:  # "I g n o r e   a l l" (double space = word gap)
        t = " ".join(re.sub(" ", "", w) for w in re.split(r" {2,}", t))
    t = _SPACED_RE.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), t)

    def leet(m: re.Match[str]) -> str:
        w = m.group(0)
        return w.translate(LEET) if any(c.isalpha() for c in w) else w

    return re.sub(r"\S+", leet, t)


def normalize(raw: str) -> NormalizedText:
    flags: list[str] = []
    views: list[View] = []

    tags = decode_unicode_tags(raw)
    if tags:
        flags.append("unicode_tags")
        views.append(View("unicode_tags", tags))

    text = unicodedata.normalize("NFKC", raw)
    text, stripped = strip_invisible(text)
    if stripped:
        flags.append("invisible_chars_removed")
    text, folded = fold_homoglyphs(text)
    if folded:
        flags.append("homoglyphs_folded")
    spaced_src = text  # keep double spaces: they mark word gaps in "i g n o r e   a l l" style obfuscation
    text = re.sub(r"[ \t\u00a0]+", " ", text).strip()
    text = text[:MAX_VIEW_CHARS * 5]

    views.insert(0, View("plain", text[:MAX_VIEW_CHARS]))

    deob = re.sub(r"[ \t\u00a0]+", " ", deobfuscate(spaced_src)).strip()
    if deob != text:
        flags.append("deobfuscated")
        views.append(View("deobfuscated", deob[:MAX_VIEW_CHARS]))

    # decoded payloads, up to MAX_DEPTH levels deep
    frontier = [v for v in views if v.label in ("plain", "unicode_tags")]
    for _ in range(MAX_DEPTH):
        nxt: list[View] = []
        for v in frontier:
            for d in decode_encodings(v.text):
                if d.text and all(d.text != x.text for x in views):
                    flags.append(f"{d.label}_decoded")
                    dv = View(d.label, d.text[:MAX_VIEW_CHARS])
                    views.append(dv)
                    nxt.append(dv)
        frontier = nxt
        if not frontier:
            break

    letters = sum(c.isalpha() for c in text)
    if letters >= 20:
        views.append(View("rot13", codecs.encode(text[:MAX_VIEW_CHARS], "rot13")))
        views.append(View("reversed", text[:MAX_VIEW_CHARS][::-1]))

    return NormalizedText(clean=text, views=views, flags=sorted(set(flags)))
