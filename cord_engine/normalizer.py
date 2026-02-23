"""CORD input normalizer — strip adversarial obfuscation before pattern matching.

Attackers try to evade detection by encoding, splitting, or substituting characters.
This module normalizes text back to its canonical form before any pattern is applied.

Techniques defended against:
- Unicode homoglyphs and fullwidth characters (ｉｇｎｏｒｅ → ignore)
- Leetspeak substitutions (1gn0r3 → ignore)
- Word splitting with spaces/punctuation (i g n o r e → ignore)
- Base64 encoded instructions
- Zero-width characters (invisible noise between real chars)
- HTML entity encoding (&lt;system&gt; → <system>)
- Repeated character noise (i...g...n...o...r...e → ignore)
"""

from __future__ import annotations

import base64
import re
import unicodedata


# ---------------------------------------------------------------------------
# Zero-width and invisible Unicode characters to strip.
# ---------------------------------------------------------------------------
_ZERO_WIDTH = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2028\u2029\u180e\u2060]"
)

# ---------------------------------------------------------------------------
# Leetspeak substitution table.
# ---------------------------------------------------------------------------
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b",
    "@": "a", "$": "s", "!": "i", "|": "i",
    "+": "t",
    # NOTE: < ( [ are intentionally excluded — they have structural meaning
    # (HTML tags, template delimiters) and converting them would break detection.
})

# ---------------------------------------------------------------------------
# HTML entity patterns → decoded form.
# ---------------------------------------------------------------------------
_HTML_ENTITIES = [
    (re.compile(r"&lt;", re.IGNORECASE), "<"),
    (re.compile(r"&gt;", re.IGNORECASE), ">"),
    (re.compile(r"&amp;", re.IGNORECASE), "&"),
    (re.compile(r"&quot;", re.IGNORECASE), '"'),
    (re.compile(r"&#x([0-9a-fA-F]+);"), lambda m: chr(int(m.group(1), 16))),
    (re.compile(r"&#(\d+);"), lambda m: chr(int(m.group(1)))),
]

# ---------------------------------------------------------------------------
# Word-splitting pattern — single chars separated by spaces/dashes/dots/underscores.
# e.g. "i g n o r e" or "i-g-n-o-r-e" → "ignore"
# ---------------------------------------------------------------------------
_WORD_SPLIT = re.compile(r"(?<!\w)((?:[a-zA-Z0-9][\s\.\-_]){2,}[a-zA-Z0-9])(?!\w)")

# ---------------------------------------------------------------------------
# Base64 detection — long base64-looking strings in text.
# ---------------------------------------------------------------------------
_B64_CANDIDATE = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")


def _decode_b64_candidates(text: str) -> str:
    """Try to decode suspicious base64 blobs — if they decode to readable text, include both."""
    def try_decode(match: re.Match) -> str:
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="strict")
            # Only substitute if it decoded to readable ASCII text
            if decoded.isprintable() and len(decoded) > 4:
                return f"{candidate} {decoded}"
        except Exception:
            pass
        return candidate

    return _B64_CANDIDATE.sub(try_decode, text)


def _collapse_word_splits(text: str) -> str:
    """Collapse split characters back into words: 'i g n o r e' → 'ignore'."""
    def rejoin(match: re.Match) -> str:
        fragment = match.group(1)
        return re.sub(r"[\s\.\-_]", "", fragment)

    return _WORD_SPLIT.sub(rejoin, text)


def normalize(text: str) -> str:
    """Normalize text to its canonical form for safe pattern matching.

    Applies in order:
    1. Unicode normalization (NFKC) — fullwidth, homoglyphs, ligatures
    2. Zero-width character removal
    3. HTML entity decoding
    4. Base64 blob expansion (keep original + decoded)
    5. Word-split collapse
    6. Leetspeak normalization
    7. Whitespace cleanup

    Returns both the original structure AND the normalized form concatenated,
    so patterns can match against either.
    """
    if not text:
        return text

    # Step 1: Unicode NFKC normalization (handles fullwidth, ligatures, etc.)
    result = unicodedata.normalize("NFKC", text)

    # Step 2: Strip zero-width / invisible characters
    result = _ZERO_WIDTH.sub("", result)

    # Step 3: HTML entity decoding
    for pattern, replacement in _HTML_ENTITIES:
        if callable(replacement):
            result = pattern.sub(replacement, result)
        else:
            result = pattern.sub(replacement, result)

    # Step 4: Base64 expansion
    result = _decode_b64_candidates(result)

    # Step 5: Collapse word splits
    result = _collapse_word_splits(result)

    # Step 6: Leetspeak normalization
    result = result.translate(_LEET_MAP)

    # Step 7: Collapse excessive whitespace
    result = re.sub(r"[ \t]{2,}", " ", result)

    # Return normalized form. If original differs, include both so patterns
    # can match against the canonical form.
    if result != text:
        return f"{text} {result}"
    return result


def normalize_proposal_text(text: str, raw_input: str = "") -> tuple[str, str]:
    """Normalize both proposal text and raw_input for CORD evaluation.

    Returns:
        (normalized_text, normalized_raw_input)
    """
    return normalize(text), normalize(raw_input) if raw_input else ""
