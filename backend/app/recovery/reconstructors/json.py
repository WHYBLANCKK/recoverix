"""
json.py — Deterministic JSON reconstruction engine.

Recovers JSON evidence by establishing, from the surviving bytes alone, which
structural bytes are *forced* by the evidence and which are genuinely unknown.

The engine never invents content. It distinguishes two cases that are often
conflated:

  1. **Deterministically closable** — the evidence is a proper prefix of a JSON
     document: every token is complete and the document is only awaiting closing
     brackets. The closing sequence is uniquely determined by the open container
     stack, so those bytes are emitted and counted as ``reconstructed_bytes``.

  2. **Unknown missing content** — the truncation lands on an incomplete token
     (unterminated string, partial number, partial literal), on a dangling
     ``:`` or ``,``, or where a further element could still appear. The missing
     value cannot be known, so nothing is invented. The unusable trailing bytes
     are reported as ``missing_bytes`` and the verified prefix is preserved.

A third case, genuinely malformed evidence that was never a JSON prefix, is
rejected safely as unrecoverable with every byte accounted as missing.

FORENSIC INVARIANT
    Every emitted byte is either a verified evidence byte or a deterministic
    structural repair byte, and the two together account for the whole output::

        verified_bytes + reconstructed_bytes == len(recovered_bytes)

    Every input byte is either emitted as verified evidence or explicitly
    dropped as missing::

        verified_bytes + missing_bytes == len(input)

    Together these give the artifact budget used by the recovery architecture::

        verified_bytes + reconstructed_bytes + missing_bytes == artifact budget
"""

from __future__ import annotations

import hashlib
import json
from typing import List, Optional, Tuple

from backend.app.models.reconstruction import ReconstructionResult
from backend.app.recovery.validators.json import validate_json
from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
)

_WS = " \t\n\r"
_NUMBER_CHARS = "0123456789+-.eE"
_LITERALS = ("true", "false", "null")

# Prefix classifications returned by _classify_prefix().
_COMPLETE = "complete"
_CLOSABLE = "closable"
_INCOMPLETE = "incomplete"
_INVALID = "invalid"


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in _WS:
        i += 1
    return i


def _scan_string(text: str, i: int) -> Tuple[int, str]:
    """Scan a JSON string starting at the opening quote.

    Returns (index_after_string, status) where status is "ok" or
    "unterminated".
    """
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            if j + 1 >= n:
                return n, "unterminated"
            j += 2
            continue
        if c == '"':
            return j + 1, "ok"
        j += 1
    return n, "unterminated"


def _scan_number(text: str, i: int) -> Tuple[int, str]:
    """Scan a JSON number literal.

    Returns (index_after_number, status) where status is "ok", "incomplete", or "invalid".
    A number that ends exactly at end-of-input or before trailing NUL padding is complete
    (e.g. the trailing ``3`` in ``{"a":1,"b":[1,2,3`` is a whole value), so it reports "ok".
    A trailing ``.``/``e``/``e+`` with no digits is "incomplete" at EOF/NUL and "invalid" elsewhere.
    A leading zero followed by digits (e.g. ``01``, ``007``) is forbidden by RFC 8259 and reports "invalid".
    """
    n = len(text)
    j = i
    if j < n and text[j] == "-":
        j += 1
    digits_start = j
    while j < n and text[j].isdigit():
        j += 1
    if j == digits_start:
        if j == n or (j < n and text[j] == "\x00"):
            return j, "incomplete"
        return j, "invalid"

    # RFC 8259: Leading zeros forbidden (e.g. 01, 00, -01, -007)
    if text[digits_start] == "0" and (j - digits_start) > 1:
        return j, "invalid"

    if j < n and text[j] == ".":
        j += 1
        frac_start = j
        while j < n and text[j].isdigit():
            j += 1
        if j == frac_start:
            if j == n or (j < n and text[j] == "\x00"):
                return j, "incomplete"
            return j, "invalid"
    if j < n and text[j] in "eE":
        j += 1
        if j < n and text[j] in "+-":
            j += 1
        exp_start = j
        while j < n and text[j].isdigit():
            j += 1
        if j == exp_start:
            if j == n or (j < n and text[j] == "\x00"):
                return j, "incomplete"
            return j, "invalid"
    if j < n and text[j] not in _WS and text[j] not in ",}]" and text[j] != "\x00":
        return j, "invalid"
    return j, "ok"


def _scan_literal(text: str, i: int) -> Tuple[int, str]:
    """Scan true/false/null.

    Returns (index_after_literal, status) where status is "ok", "incomplete"
    (a genuine prefix such as ``tru``) or "invalid". A literal that matches in
    full exactly at end-of-input or before NUL padding is complete and reports "ok".
    """
    n = len(text)
    for lit in _LITERALS:
        if text.startswith(lit, i):
            end = i + len(lit)
            if end < n and text[end] not in _WS and text[end] not in ",}]" and text[end] != "\x00":
                return end, "invalid"
            return end, "ok"
    # Partial literal at end of input or before NUL padding.
    rem = text[i:].split("\x00", 1)[0]
    for lit in _LITERALS:
        if rem and lit.startswith(rem):
            return i + len(rem), "incomplete"
    return i, "invalid"


def _classify_prefix(text: str) -> Tuple[str, List[str], str]:
    """Classify *text* as a JSON document or JSON prefix.

    Returns (classification, open_container_stack, reason).

    ``CLOSABLE`` means the evidence is a proper prefix whose only deficiency is
    unclosed containers, so the closing sequence is uniquely determined.
    ``INCOMPLETE`` means content is genuinely unknown and must not be invented.
    """
    n = len(text)
    i = _skip_ws(text, 0)
    if i >= n or not text[i:].strip("\x00 \t\r\n"):
        return _INCOMPLETE, [], "input contains no JSON content"

    stack: List[str] = []
    # state: 'value' (a value may start here), 'key' (a member name or '}'),
    #        'colon' (':' required), 'sep' (',' or a closing bracket required),
    #        'done' (root container closed, only trailing whitespace/NUL padding permitted)
    state = "value"

    while True:
        if state == "done":
            i = _skip_ws(text, i)
            if i >= n or not text[i:].strip("\x00 \t\r\n"):
                return _COMPLETE, [], "complete JSON document"
            c = text[i]
            return _INVALID, [], f"unexpected extra data {c!r} after complete JSON document"

        if state == "value":
            i = _skip_ws(text, i)
            if i >= n or not text[i:].strip("\x00 \t\r\n"):
                # A further value could still appear, so it is unknown.
                return _INCOMPLETE, stack, "a JSON value was expected but the evidence ends"
            c = text[i]
            if c == "]" and stack and stack[-1] == "[":
                stack.pop()
                i += 1
                state = "sep" if stack else "done"
                continue
            if c == "{":
                if len(stack) >= 500:
                    return _INVALID, stack, "JSON nesting depth exceeds safety limit (500)"
                stack.append("{")
                i += 1
                state = "key"
                continue
            if c == "[":
                if len(stack) >= 500:
                    return _INVALID, stack, "JSON nesting depth exceeds safety limit (500)"
                stack.append("[")
                i += 1
                state = "value"
                continue
            if c == '"':
                i, st = _scan_string(text, i)
                if st != "ok":
                    return _INCOMPLETE, stack, "unterminated JSON string"
                state = "sep"
                continue
            if c in "tfn":
                i, st = _scan_literal(text, i)
                if st == "incomplete":
                    return _INCOMPLETE, stack, "truncated JSON literal"
                if st != "ok":
                    return _INVALID, stack, "malformed JSON literal"
                state = "sep"
                continue
            if c == "-" or c.isdigit():
                i, st = _scan_number(text, i)
                if st == "incomplete":
                    return _INCOMPLETE, stack, "truncated JSON number"
                if st != "ok":
                    return _INVALID, stack, "malformed JSON number"
                state = "sep"
                continue
            return _INVALID, stack, f"unexpected character {c!r} where a JSON value was expected"

        if state == "key":
            i = _skip_ws(text, i)
            if i >= n or not text[i:].strip("\x00 \t\r\n"):
                # The object may have been empty or may have held members; the
                # evidence cannot distinguish, so nothing is invented.
                return _INCOMPLETE, stack, "object body is unknown at end of evidence"
            if text[i] == "}":
                i += 1
                stack.pop()
                state = "sep" if stack else "done"
                continue
            if text[i] != '"':
                return _INVALID, stack, "expected a JSON member name"
            i, st = _scan_string(text, i)
            if st != "ok":
                return _INCOMPLETE, stack, "unterminated JSON member name"
            state = "colon"
            continue

        if state == "colon":
            i = _skip_ws(text, i)
            if i >= n or not text[i:].strip("\x00 \t\r\n"):
                return _INCOMPLETE, stack, "member value is unknown at end of evidence"
            if text[i] != ":":
                return _INVALID, stack, "expected ':' after a JSON member name"
            i += 1
            state = "value"
            continue

        # state == 'sep'
        if not stack:
            i = _skip_ws(text, i)
            if i >= n or not text[i:].strip("\x00 \t\r\n"):
                return _COMPLETE, [], "complete JSON document"
            c = text[i]
            return _INVALID, [], f"unexpected extra data {c!r} after complete JSON document"

        i = _skip_ws(text, i)
        if i >= n or not text[i:].strip("\x00 \t\r\n"):
            # A complete value finished inside an open container: the only
            # deficiency is the closing bytes, which are uniquely determined.
            return _CLOSABLE, stack, "JSON containers are unclosed"
        c = text[i]
        closer = "}" if stack[-1] == "{" else "]"
        if c == ",":
            i += 1
            state = "key" if stack[-1] == "{" else "value"
            continue
        if c == closer:
            i += 1
            stack.pop()
            state = "sep" if stack else "done"
            continue
        return _INVALID, stack, f"unexpected character {c!r} in JSON container"


def _strip_markers(data: bytes) -> Tuple[bytes, int, bool]:
    """Split synthetic harness markers off *data*.

    Returns (body_bytes, marker_overhead_bytes, had_markers).
    """
    start = data.find(SYNTHETIC_START_MARKER)
    end = data.find(SYNTHETIC_END_MARKER)
    if start == -1 and end == -1:
        return data, 0, False
    body_start = start + len(SYNTHETIC_START_MARKER) if start != -1 else 0
    body_end = end if end != -1 else len(data)
    return data[body_start:body_end], (body_end - body_start), True


def _result(
    *,
    status: str,
    success: bool,
    recovered: bytes,
    verified: int,
    reconstructed: int,
    missing: int,
    methods: List[str],
    details: dict,
    damage_regions: Optional[List[dict]] = None,
    validation_result=None,
    original_data: Optional[bytes] = None,
) -> ReconstructionResult:
    return ReconstructionResult(
        format="json",
        status=status,
        success=success,
        recovered_bytes=recovered,
        verified_bytes=verified,
        reconstructed_bytes=reconstructed,
        missing_bytes=missing,
        damage_regions=damage_regions or [],
        reconstruction_methods=methods,
        validation_result=validation_result,
        is_exact_match=(
            (hashlib.sha256(recovered).hexdigest() == hashlib.sha256(original_data).hexdigest())
            if original_data is not None
            else None
        ),
        details=details,
    )


def reconstruct_json(
    data: bytes,
    original_data: Optional[bytes] = None,
) -> ReconstructionResult:
    """Deterministically reconstruct damaged JSON evidence.

    Args:
        data: Surviving JSON evidence bytes, exactly as recovered.
        original_data: Optional ground truth. Used only to compute the
            ``is_exact_match`` diagnostic; it is never read to decide what the
            reconstruction contains.

    Returns:
        ReconstructionResult with honest verified/reconstructed/missing
        accounting and an explicit ``reconstruction_method``.

    Accounting contract for input slices:
        - Scanner-bounded candidates exclude external padding: when carving from
          evidence images, the candidate extent stops at the closing delimiter,
          and external sector padding bytes are excluded from the candidate without
          fabricating missing bytes.
        - Direct raw-buffer calls may count excluded padding in missing_bytes under
          the current input-conservation contract (verified_bytes + missing_bytes == len(data)),
          categorizing the trimmed padding as 'UNATTRIBUTED_PADDING'.
        - This accounting does not prove those padding bytes were original file content:
          the engine does not claim that external slack padding belonged to the original artifact.
        - Structural closure does not establish original identity: appending deterministic
          closing braces/brackets ensures syntactic validity, but cannot prove that the
          closed structure matches the original uncorrupted file (e.g. truncated containers
          may have originally contained additional elements or longer tokens).
    """
    data = bytes(data)

    if len(data) == 0:
        return _result(
            status="UNRECOVERABLE",
            success=False,
            recovered=b"",
            verified=0,
            reconstructed=0,
            missing=0,
            methods=[],
            details={
                "reason": "Evidence is empty",
                "notice": "No JSON evidence bytes were present, so nothing could be recovered.",
            },
        )

    body, marker_overhead, had_markers = _strip_markers(data)

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _result(
            status="UNRECOVERABLE",
            success=False,
            recovered=b"",
            verified=0,
            reconstructed=0,
            missing=len(data),
            methods=[],
            damage_regions=[
                {
                    "offset": 0,
                    "length": len(data),
                    "type": "INVALID_UTF8",
                    "status": "UNRECOVERABLE",
                    "details": str(exc),
                }
            ],
            details={
                "reason": f"JSON evidence is not valid UTF-8: {exc}",
                "notice": (
                    "The evidence cannot be decoded as UTF-8, so no JSON structure can be "
                    "established. Every byte is reported missing rather than guessed."
                ),
            },
            original_data=original_data,
        )

    classification, stack, reason = _classify_prefix(text)
    common = {
        "classification": classification,
        "prefix_reason": reason,
        "open_containers": list(stack),
        "evidence_bytes": len(data),
        "json_body_bytes": len(body),
    }

    # ── Case 1: intact, valid JSON ────────────────────────────────────────
    if classification == _COMPLETE:
        clean_text = text.rstrip("\x00 \t\r\n")
        clean_body = clean_text.encode("utf-8")
        padding_bytes = len(body) - len(clean_body)
        val = validate_json(clean_body)
        if val.valid:
            status = "FULLY_RECOVERED" if padding_bytes == 0 else "PARTIALLY_RECOVERED"
            damage_regions = []
            if padding_bytes > 0:
                damage_regions.append({
                    "offset": len(clean_body),
                    "length": padding_bytes,
                    "type": "UNATTRIBUTED_PADDING",
                    "status": "UNRECOVERABLE",
                    "details": f"Evidence contained {padding_bytes} byte(s) of trailing padding",
                })
            return _result(
                status=status,
                success=True,
                recovered=clean_body,
                verified=len(clean_body),
                reconstructed=0,
                missing=padding_bytes,
                methods=["JSON_STRUCTURAL_VALIDATION"],
                damage_regions=damage_regions,
                validation_result=val,
                details={
                    **common,
                    "reconstruction_method": "JSON_STRUCTURAL_VALIDATION",
                    "synthetic_markers": had_markers,
                    "marker_overhead_bytes": marker_overhead,
                    "trailing_padding_bytes": padding_bytes,
                    "output_sha256": hashlib.sha256(clean_body).hexdigest(),
                    "notice": (
                        "The evidence parses as complete JSON, so it is preserved byte for byte "
                        "with no reconstruction and nothing missing."
                        if padding_bytes == 0 else
                        f"The evidence parses as complete JSON ({len(clean_body)} bytes). Trailing {padding_bytes} byte(s) of padding are accounted as missing."
                    ),
                },
                original_data=original_data,
            )
        else:
            # Structural validation failed (corrupted syntax in complete-looking container)
            err_msg = "; ".join(val.errors) if val.errors else "Invalid JSON syntax"
            return _result(
                status="CORRUPTED",
                success=False,
                recovered=clean_body,
                verified=0,
                reconstructed=0,
                missing=len(data),
                methods=["JSON_SYNTAX_CORRUPTED"],
                damage_regions=[{
                    "offset": 0,
                    "length": len(clean_body),
                    "type": "CORRUPTED",
                    "status": "UNRECOVERABLE",
                    "details": f"JSON structural validation failed: {err_msg}",
                }],
                validation_result=val,
                details={
                    **common,
                    "reconstruction_method": "JSON_SYNTAX_CORRUPTED",
                    "validation_error": err_msg,
                    "synthetic_markers": had_markers,
                    "marker_overhead_bytes": marker_overhead,
                    "notice": (
                        f"The candidate structure appears bounded but failed RFC 8259 JSON validation: {err_msg}. "
                        "Because the syntax is corrupted, 0 bytes are claimed as verified."
                    ),
                },
                original_data=original_data,
            )

    # ── Case 2: deterministically closable prefix ─────────────────────────
    if classification == _CLOSABLE:
        clean_text = text.rstrip("\x00 \t\r\n")
        clean_body = clean_text.encode("utf-8")
        padding_bytes = len(body) - len(clean_body)
        closers = "".join("}" if c == "{" else "]" for c in reversed(stack))
        repaired_text = clean_text + closers
        try:
            json.loads(repaired_text)
        except json.JSONDecodeError as exc:
            # The forced closing sequence did not produce a valid document, so
            # the structure is not deterministically establishable after all.
            return _unestablished(
                data, body, text, had_markers, marker_overhead, common,
                reason=f"forced closing sequence did not yield valid JSON: {exc}",
                original_data=original_data,
            )

        repaired_bytes = repaired_text.encode("utf-8")
        val = validate_json(repaired_bytes)
        if not val.valid:
            return _unestablished(
                data, body, text, had_markers, marker_overhead, common,
                reason="repaired document did not pass JSON validation",
                original_data=original_data,
            )

        damage_regions = [
            {
                "offset": len(clean_body),
                "length": len(closers.encode("utf-8")),
                "type": "MISSING_STRUCTURAL_CLOSURE",
                "status": "RECONSTRUCTABLE",
                "details": f"Appended deterministic closing bytes {closers!r}",
            }
        ]
        if padding_bytes > 0:
            damage_regions.append({
                "offset": len(clean_body),
                "length": padding_bytes,
                "type": "UNATTRIBUTED_PADDING",
                "status": "UNRECOVERABLE",
                "details": f"Evidence contained {padding_bytes} byte(s) of trailing padding",
            })

        return _result(
            status="PARTIALLY_RECOVERED",
            success=True,
            recovered=repaired_bytes,
            verified=len(clean_body),
            reconstructed=len(closers.encode("utf-8")),
            missing=padding_bytes,
            methods=["JSON_STRUCTURAL_CLOSURE"],
            damage_regions=damage_regions,
            validation_result=val,
            details={
                **common,
                "reconstruction_method": "JSON_STRUCTURAL_CLOSURE",
                "appended_closers": closers,
                "synthetic_markers": had_markers,
                "marker_overhead_bytes": marker_overhead,
                "trailing_padding_bytes": padding_bytes,
                "output_sha256": hashlib.sha256(repaired_bytes).hexdigest(),
                "ambiguity": (
                    "The closing sequence is uniquely determined by the open container stack, "
                    "so exactly one structural repair exists for this evidence."
                ),
                "notice": (
                    f"Every JSON token in the evidence is complete and only the closing bytes "
                    f"{closers!r} were absent. Those {len(closers)} byte(s) are uniquely "
                    "determined by the open container stack and are reported as reconstructed, "
                    "not as verified evidence. The status is PARTIALLY_RECOVERED because "
                    "structural bytes were reconstructed."
                ),
            },
            original_data=original_data,
        )

    # ── Case 3: content is genuinely unknown ──────────────────────────────
    if classification == _INCOMPLETE:
        keep = _verified_prefix_length(text)
        retained = text[:keep].encode("utf-8")
        dropped = len(body) - len(retained)
        if not retained:
            return _result(
                status="UNRECOVERABLE",
                success=False,
                recovered=b"",
                verified=0,
                reconstructed=0,
                missing=len(data),
                methods=["JSON_UNRESOLVED_CONTENT"],
                details={
                    **common,
                    "reconstruction_method": "JSON_UNRESOLVED_CONTENT",
                    "synthetic_markers": had_markers,
                    "marker_overhead_bytes": marker_overhead,
                    "refused": "no JSON value could be established from the evidence",
                    "notice": (
                        "The evidence is a truncated JSON prefix whose missing content cannot "
                        "be determined. No property or value was invented and no closing bytes "
                        "were fabricated, so nothing is claimed as recovered."
                    ),
                },
                original_data=original_data,
            )

        return _result(
            status="PARTIALLY_RECOVERED",
            success=False,
            recovered=retained,
            verified=len(retained),
            reconstructed=0,
            missing=dropped,
            methods=["JSON_UNRESOLVED_CONTENT"],
            damage_regions=[
                {
                    "offset": len(retained),
                    "length": dropped,
                    "type": "UNRESOLVED_JSON_TAIL",
                    "status": "UNRECOVERABLE",
                    "details": reason,
                }
            ],
            details={
                **common,
                "reconstruction_method": "JSON_UNRESOLVED_CONTENT",
                "retained_prefix_bytes": len(retained),
                "unresolved_tail_bytes": dropped,
                "synthetic_markers": had_markers,
                "marker_overhead_bytes": marker_overhead,
                "refused": reason,
                "ambiguity": (
                    "The missing member or value is not determined by the evidence, so several "
                    "different documents remain consistent with it. The ambiguity is preserved "
                    "by refusing to select one."
                ),
                "notice": (
                    f"The evidence ends mid-structure ({reason}). The missing content cannot be "
                    f"established, so the {len(retained)} verified prefix byte(s) are preserved "
                    f"and the remaining {dropped} byte(s) are reported as missing. No property, "
                    "value or closing byte was invented."
                ),
            },
            original_data=original_data,
        )

    # ── Case 4: not a JSON prefix at all ──────────────────────────────────
    return _result(
        status="UNRECOVERABLE",
        success=False,
        recovered=b"",
        verified=0,
        reconstructed=0,
        missing=len(data),
        methods=["JSON_MALFORMED_REJECTED"],
        damage_regions=[
            {
                "offset": 0,
                "length": len(data),
                "type": "MALFORMED_JSON",
                "status": "UNRECOVERABLE",
                "details": reason,
            }
        ],
        details={
            **common,
            "reconstruction_method": "JSON_MALFORMED_REJECTED",
            "synthetic_markers": had_markers,
            "marker_overhead_bytes": marker_overhead,
            "refused": reason,
            "notice": (
                f"The evidence is not a JSON document or prefix ({reason}). It was rejected "
                "without interpretation as another format, and every byte is reported missing "
                "rather than guessed."
            ),
        },
        original_data=original_data,
    )


def _unestablished(
    data: bytes,
    body: bytes,
    text: str,
    had_markers: bool,
    marker_overhead: int,
    common: dict,
    *,
    reason: str,
    original_data: Optional[bytes],
) -> ReconstructionResult:
    """Report a prefix whose structure could not be deterministically closed."""
    keep = _verified_prefix_length(text)
    retained = text[:keep].encode("utf-8")
    dropped = len(body) - len(retained)
    return _result(
        status="PARTIALLY_RECOVERED" if retained else "UNRECOVERABLE",
        success=False,
        recovered=retained,
        verified=len(retained),
        reconstructed=0,
        missing=dropped,
        methods=["JSON_UNRESOLVED_CONTENT"],
        damage_regions=[
            {
                "offset": len(retained),
                "length": dropped,
                "type": "UNRESOLVED_JSON_TAIL",
                "status": "UNRECOVERABLE",
                "details": reason,
            }
        ],
        details={
            **common,
            "reconstruction_method": "JSON_UNRESOLVED_CONTENT",
            "retained_prefix_bytes": len(retained),
            "unresolved_tail_bytes": dropped,
            "synthetic_markers": had_markers,
            "marker_overhead_bytes": marker_overhead,
            "refused": reason,
            "notice": (
                f"The JSON structure could not be deterministically closed ({reason}). "
                f"The {len(retained)} verified prefix byte(s) are preserved and the remaining "
                f"{dropped} byte(s) are reported as missing. Nothing was invented."
            ),
        },
        original_data=original_data,
    )


def _verified_prefix_length(text: str) -> int:
    """Length of the leading *text* that is unambiguously established evidence.

    The retained prefix ends at the last position where a complete JSON value
    had just been completed inside a container, or at the last complete member.
    Trailing bytes belonging to an incomplete token are not established and are
    left out so they can be reported as missing.
    """
    stripped = text.rstrip("\x00 \t\r\n")
    if not stripped:
        return 0

    # Walk the same state machine and remember the furthest offset at which a
    # complete value had just finished.
    n = len(stripped)
    i = _skip_ws(stripped, 0)
    if i >= n:
        return 0
    stack: List[str] = []
    state = "value"
    best = 0

    while True:
        if state == "value":
            i = _skip_ws(stripped, i)
            if i >= n:
                return best
            c = stripped[i]
            if c == "{":
                if len(stack) >= 500:
                    return best
                stack.append("{")
                i += 1
                state = "key"
                continue
            if c == "[":
                if len(stack) >= 500:
                    return best
                stack.append("[")
                i += 1
                state = "value"
                continue
            if c == '"':
                i, st = _scan_string(stripped, i)
                if st != "ok":
                    return best
                best = max(best, i)
                state = "sep"
                continue
            if c in "tfn":
                i, st = _scan_literal(stripped, i)
                if st != "ok":
                    return best
                best = max(best, i)
                state = "sep"
                continue
            if c == "-" or c.isdigit():
                i, st = _scan_number(stripped, i)
                if st != "ok":
                    return best
                best = max(best, i)
                state = "sep"
                continue
            return best

        if state == "key":
            i = _skip_ws(stripped, i)
            if i >= n:
                return best
            if stripped[i] == "}":
                i += 1
                stack.pop()
                best = max(best, i)
                state = "sep" if stack else "done"
                continue
            if stripped[i] != '"':
                return best
            i, st = _scan_string(stripped, i)
            if st != "ok":
                return best
            state = "colon"
            continue

        if state == "colon":
            i = _skip_ws(stripped, i)
            if i >= n:
                return best
            if stripped[i] != ":":
                return best
            i += 1
            state = "value"
            continue

        if not stack:
            return max(best, i)
        i = _skip_ws(stripped, i)
        if i >= n:
            return best
        c = stripped[i]
        closer = "}" if stack[-1] == "{" else "]"
        if c == ",":
            i += 1
            state = "key" if stack[-1] == "{" else "value"
            continue
        if c == closer:
            i += 1
            stack.pop()
            best = max(best, i)
            state = "sep" if stack else "done"
            continue
        return best
