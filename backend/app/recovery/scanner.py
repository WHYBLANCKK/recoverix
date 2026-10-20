"""
scanner.py — Deterministic candidate-fragment scanner.

Accepts raw evidence bytes and scans for registered format signatures,
producing a list of Candidate objects representing detected artifact
regions across all 7 supported formats (TXT, CSV, JSON, XML, PNG, JPEG, PDF).

The scanner:
  - scans left to right, one byte at a time
  - records every signature match it finds
  - never reads outside the byte buffer
  - never mutates the input
  - produces deterministic results for identical input
  - does not crash on malformed or truncated evidence

For TXT/CSV/JSON/XML (synthetic boundary markers):
  - detects [SYNTHETIC_ARTIFACT_START]
  - locates the corresponding [SYNTHETIC_ARTIFACT_END]
  - differentiates TXT vs CSV vs JSON vs XML by content heuristics
  - records the candidate region including both markers

For PNG:
  - detects the 8-byte PNG magic signature (\x89PNG\r\n\x1a\n)
  - records the candidate start

For JPEG:
  - detects the 2-byte JPEG SOI signature (\xFF\xD8)
  - searches for EOI marker (\xFF\xD9) to calculate estimated end offset

For PDF:
  - detects the PDF header signature (%PDF-)
  - searches for trailer marker (%%EOF) to calculate estimated end offset

For direct XML:
  - detects '<?xml' header signature

This module does NOT perform recovery, carving, reconstruction,
confidence scoring, classification, or AI work.
"""

from __future__ import annotations

import json
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from backend.app.recovery.signatures import (
    SYNTHETIC_START_MARKER,
    SYNTHETIC_END_MARKER,
    PNG_SIGNATURE,
    JPEG_SOI,
    JPEG_EOI,
    PDF_HEADER_SIGNATURE,
    PDF_TRAILER_SIGNATURE,
    XML_HEADER_SIGNATURE,
    ZIP_LOCAL_HEADER,
    ZIP_EOCD_SIGNATURE,
)
from backend.app.recovery.xml_security import safe_parse_xml


@dataclass(frozen=True)
class CandidateRelationship:
    """Directional spatial relationship between two candidates."""

    target_candidate_id: str
    target_format: str
    relationship_type: str  # "COEXTENSIVE", "CONTAINS", "CONTAINED_BY", "OVERLAPS"


@dataclass(frozen=True)
class Candidate:
    """A detected candidate artifact region in the evidence.

    Attributes:
        candidate_id: Unique sequential identifier (``"cand-0"``, ``"cand-1"``, …).
        format: Detected format (``"txt"``, ``"csv"``, ``"json"``, ``"xml"``, ``"png"``, ``"jpeg"``, ``"pdf"``).
        mime_type: MIME type string.
        category: Human-readable category (``"text"``, ``"structured"``, ``"image"``, ``"document"``).
        offset: Byte offset of the detected header in the evidence.
        detected_header_length: Length of the header/signature that was matched.
        estimated_end_offset: Byte offset one past the last byte of the
            candidate region, or ``None`` if the end could not be determined.
        detection_method: Label describing how this candidate was found.
        relationships: Directional spatial relationships with other candidates.
    """

    candidate_id: str
    format: str
    mime_type: str
    category: str
    offset: int
    detected_header_length: int
    estimated_end_offset: Optional[int]
    detection_method: str
    relationships: tuple[CandidateRelationship, ...] = ()

    @property
    def evidence_start(self) -> int:
        """Physical start byte offset in the original evidence buffer."""
        return self.offset

    @property
    def evidence_end(self) -> Optional[int]:
        """Physical end byte offset in the original evidence buffer."""
        return self.estimated_end_offset


# ── Content heuristic for Synthetic Marker Payloads ──────────────────

def _classify_synthetic_content(body: bytes) -> tuple[str, str, str]:
    """Classify the content between synthetic markers as TXT, CSV, JSON, XML, PNG, JPEG, or PDF.

    Returns:
        Tuple of (format, mime_type, category).
    """
    # First check explicit FMT:<format>; header prefix in synthetic marker bodies
    if body.startswith(b"FMT:"):
        end_fmt = body.find(b";")
        if end_fmt != -1:
            tag = body[4:end_fmt].decode("utf-8", errors="ignore").lower()
            if tag == "png":
                return ("png", "image/png", "image")
            elif tag in ("jpeg", "jpg"):
                return ("jpeg", "image/jpeg", "image")
            elif tag == "pdf":
                return ("pdf", "application/pdf", "document")
            elif tag == "txt":
                return ("txt", "text/plain", "text")
            elif tag == "csv":
                return ("csv", "text/csv", "text")
            elif tag == "json":
                return ("json", "application/json", "structured")
            elif tag == "xml":
                return ("xml", "application/xml", "structured")
            elif tag == "zip":
                return ("zip", "application/zip", "archive")

    # Check magic byte signatures embedded in synthetic body
    if PNG_SIGNATURE in body:
        return ("png", "image/png", "image")
    if JPEG_SOI in body:
        return ("jpeg", "image/jpeg", "image")
    if PDF_HEADER_SIGNATURE in body:
        return ("pdf", "application/pdf", "document")
    if ZIP_LOCAL_HEADER in body:
        return ("zip", "application/zip", "archive")

    try:
        text = body.decode("utf-8", errors="replace").strip()
    except Exception:
        return ("txt", "text/plain", "text")

    if not text:
        return ("txt", "text/plain", "text")

    # Check JSON
    if text.startswith(("{", "[")):
        try:
            json.loads(text)
            return ("json", "application/json", "structured")
        except Exception:
            pass

    # Check XML
    if text.startswith(("<?xml", "<")):
        try:
            safe_parse_xml(text)
            return ("xml", "application/xml", "structured")
        except Exception:
            if text.startswith("<?xml"):
                return ("xml", "application/xml", "structured")

    # Check CSV
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "," in stripped:
            return ("csv", "text/csv", "text")
        break

    return ("txt", "text/plain", "text")


# ── Scanner ─────────────────────────────────────────────────────────

_METHOD_PRIORITY = {
    "synthetic_boundary": 6,
    "magic_bytes": 5,
    "syntax_boundary": 4,
    "direct_header": 3,
    "heuristic_json_container": 2,
    "heuristic_text_run": 1,
}

MAX_CANDIDATES = 250

_last_scan_metadata: dict[str, Any] = {
    "total_discovered_candidates": 0,
    "candidate_cap_enforced": False,
    "candidates_omitted": 0,
}


def get_last_scan_metadata() -> dict[str, Any]:
    """Return metadata from the most recent scan_evidence() execution."""
    return dict(_last_scan_metadata)


def _dedup_candidates(candidates: List[Candidate]) -> List[Candidate]:
    """Deduplicate candidates sharing exact same (offset, format).

    If duplicate (offset, format) pairs exist, deterministically select the one with:
      1. Known estimated_end_offset preferred over unknown.
      2. Larger known physical span (estimated_end_offset - offset).
      3. Larger detected_header_length.
      4. Higher detection_method priority.
      5. First-discovered insertion order tie-breaker.
    """
    groups: dict[tuple[int, str], list[tuple[int, Candidate]]] = {}
    for idx, c in enumerate(candidates):
        key = (c.offset, c.format)
        if key not in groups:
            groups[key] = []
        groups[key].append((idx, c))

    unique: List[Candidate] = []
    for key, items in groups.items():
        if len(items) == 1:
            unique.append(items[0][1])
        else:
            def _score_candidate(item: tuple[int, Candidate]) -> tuple[int, int, int, int, int]:
                idx, c = item
                has_end = 1 if c.estimated_end_offset is not None else 0
                span = (c.estimated_end_offset - c.offset) if c.estimated_end_offset is not None else 0
                hdr_len = c.detected_header_length
                method_pri = _METHOD_PRIORITY.get(c.detection_method, 0)
                return (has_end, span, hdr_len, method_pri, -idx)

            best_item = max(items, key=_score_candidate)
            unique.append(best_item[1])

    return unique


def _compute_candidate_relationships(candidates: List[Candidate]) -> List[Candidate]:
    """Compute spatial relationships between candidates when physical boundaries prove them.

    Both ends MUST be known (estimated_end_offset is not None) for:
      - COEXTENSIVE
      - CONTAINS
      - CONTAINED_BY
      - OVERLAPS

    If either candidate has an unknown end (estimated_end_offset is None),
    no relationship is asserted. Unknown is never replaced with len(data).
    """
    n = len(candidates)
    if n <= 1:
        return candidates

    rel_map: dict[str, list[CandidateRelationship]] = {c.candidate_id: [] for c in candidates}

    for i in range(n):
        c_a = candidates[i]
        for j in range(i + 1, n):
            c_b = candidates[j]

            # Both ends MUST be known to prove any spatial relationship
            if c_a.estimated_end_offset is None or c_b.estimated_end_offset is None:
                continue

            a_start, a_end = c_a.offset, c_a.estimated_end_offset
            b_start, b_end = c_b.offset, c_b.estimated_end_offset

            # Provably disjoint
            if a_end <= b_start or b_end <= a_start:
                continue

            # COEXTENSIVE: same start and same end
            if a_start == b_start and a_end == b_end:
                rel_map[c_a.candidate_id].append(
                    CandidateRelationship(c_b.candidate_id, c_b.format, "COEXTENSIVE")
                )
                rel_map[c_b.candidate_id].append(
                    CandidateRelationship(c_a.candidate_id, c_a.format, "COEXTENSIVE")
                )
                continue

            # CONTAINS / CONTAINED_BY: A.start <= B.start and B.end <= A.end with at least one strict inequality
            if a_start <= b_start and b_end <= a_end and (a_start < b_start or b_end < a_end):
                rel_map[c_a.candidate_id].append(
                    CandidateRelationship(c_b.candidate_id, c_b.format, "CONTAINS")
                )
                rel_map[c_b.candidate_id].append(
                    CandidateRelationship(c_a.candidate_id, c_a.format, "CONTAINED_BY")
                )
                continue

            if b_start <= a_start and a_end <= b_end and (b_start < a_start or a_end < b_end):
                rel_map[c_b.candidate_id].append(
                    CandidateRelationship(c_a.candidate_id, c_a.format, "CONTAINS")
                )
                rel_map[c_a.candidate_id].append(
                    CandidateRelationship(c_b.candidate_id, c_b.format, "CONTAINED_BY")
                )
                continue

            # OVERLAPS: ranges partially overlap without containment/coextensiveness
            if (a_start < b_start < a_end < b_end) or (b_start < a_start < b_end < a_end):
                rel_map[c_a.candidate_id].append(
                    CandidateRelationship(c_b.candidate_id, c_b.format, "OVERLAPS")
                )
                rel_map[c_b.candidate_id].append(
                    CandidateRelationship(c_a.candidate_id, c_a.format, "OVERLAPS")
                )

    result: List[Candidate] = []
    for c in candidates:
        rels = rel_map[c.candidate_id]
        rels.sort(key=lambda r: (r.target_candidate_id, r.relationship_type))
        result.append(
            Candidate(
                candidate_id=c.candidate_id,
                format=c.format,
                mime_type=c.mime_type,
                category=c.category,
                offset=c.offset,
                detected_header_length=c.detected_header_length,
                estimated_end_offset=c.estimated_end_offset,
                detection_method=c.detection_method,
                relationships=tuple(rels),
            )
        )
    return result


def scan_evidence(data: bytes) -> List[Candidate]:
    """Scan *data* for registered format signatures across 7 formats.

    Args:
        data: Raw evidence bytes.  Never mutated.

    Returns:
        An ordered list of Candidate objects, sorted deterministically by offset.
        Empty list if *data* is empty or contains no matches.
    """
    global _last_scan_metadata
    _last_scan_metadata = {
        "total_discovered_candidates": 0,
        "candidate_cap_enforced": False,
        "candidates_omitted": 0,
    }

    if len(data) == 0:
        return []

    candidates: List[Candidate] = []
    evidence_len = len(data)

    # ── Pass 1: scan for synthetic boundary markers ─────────────
    _scan_synthetic(data, evidence_len, candidates)

    # ── Pass 2: scan for PNG magic bytes ────────────────────────
    _scan_png(data, evidence_len, candidates)

    # ── Pass 3: scan for JPEG SOI bytes ─────────────────────────
    _scan_jpeg(data, evidence_len, candidates)

    # ── Pass 4: scan for PDF header bytes ────────────────────────
    _scan_pdf(data, evidence_len, candidates)

    # ── Pass 5: scan for direct XML headers ─────────────────────
    _scan_xml(data, evidence_len, candidates)

    # ── Pass 6: scan for blind JSON container documents ─────────
    _scan_json(data, evidence_len, candidates)

    # ── Pass 7: scan for blind TXT and CSV candidates ───────────
    _scan_text_and_csv(data, evidence_len, candidates)

    # ── Pass 8: scan for ZIP archives ───────────────────────────
    _scan_zip(data, evidence_len, candidates)

    # 1. Exact deduplication: (offset, format)
    unique_candidates = _dedup_candidates(candidates)

    # 2. Deterministic sorting
    unique_candidates.sort(
        key=lambda c: (
            c.offset,
            0 if c.estimated_end_offset is not None else 1,
            -(c.estimated_end_offset or 0),
            -c.detected_header_length,
            c.format,
            c.detection_method,
        )
    )

    # 3. Post-discovery processing cap (safety limit)
    total_discovered = len(unique_candidates)
    cap_enforced = total_discovered > MAX_CANDIDATES
    omitted = max(0, total_discovered - MAX_CANDIDATES)

    _last_scan_metadata = {
        "total_discovered_candidates": total_discovered,
        "candidate_cap_enforced": cap_enforced,
        "candidates_omitted": omitted,
    }

    if cap_enforced:
        retained = unique_candidates[:MAX_CANDIDATES]
    else:
        retained = unique_candidates

    # 4. Assign sequential candidate IDs
    preliminary: List[Candidate] = []
    for idx, c in enumerate(retained):
        preliminary.append(
            Candidate(
                candidate_id=f"cand-{idx}",
                format=c.format,
                mime_type=c.mime_type,
                category=c.category,
                offset=c.offset,
                detected_header_length=c.detected_header_length,
                estimated_end_offset=c.estimated_end_offset,
                detection_method=c.detection_method,
            )
        )

    # 5. Spatial relationship analysis
    final = _compute_candidate_relationships(preliminary)
    return final


def _scan_synthetic(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find all synthetic boundary-marker pairs in *data*."""
    start_marker = SYNTHETIC_START_MARKER
    end_marker = SYNTHETIC_END_MARKER
    start_len = len(start_marker)
    end_len = len(end_marker)

    search_from = 0

    while search_from <= evidence_len - start_len:
        pos = data.find(start_marker, search_from)
        if pos == -1:
            break

        body_start = pos + start_len
        end_pos = data.find(end_marker, body_start)

        if end_pos != -1:
            estimated_end = end_pos + end_len
            body = data[body_start:end_pos]
        else:
            estimated_end = None
            body = data[body_start:]

        fmt, mime_type, category = _classify_synthetic_content(body)

        candidates.append(
            Candidate(
                candidate_id="",
                format=fmt,
                mime_type=mime_type,
                category=category,
                offset=pos,
                detected_header_length=start_len,
                estimated_end_offset=estimated_end,
                detection_method="synthetic_boundary",
            )
        )

        search_from = pos + start_len


def _find_png_end(
    data: bytes,
    start_pos: int,
    territory_limit: int,
) -> Optional[int]:
    """Parse PNG chunks sequentially starting after PNG signature to find authentic IEND chunk.

    Returns the byte offset immediately following the 12-byte IEND chunk (estimated_end),
    or None if the PNG is truncated, malformed, or missing IEND within territory_limit.
    """
    sig_len = len(PNG_SIGNATURE)
    curr = start_pos + sig_len
    found_ihdr = False

    while curr + 8 <= territory_limit:
        chunk_len = struct.unpack(">I", data[curr : curr + 4])[0]
        chunk_type = data[curr + 4 : curr + 8]

        # Chunk type must consist of 4 ASCII letters (RFC 2083)
        if not (
            len(chunk_type) == 4
            and all(65 <= b <= 90 or 97 <= b <= 122 for b in chunk_type)
        ):
            return None

        # First chunk check: MUST be IHDR (length 13)
        if not found_ihdr:
            if chunk_type != b"IHDR" or chunk_len != 13:
                return None
            found_ihdr = True

        total_chunk_size = 12 + chunk_len
        chunk_end = curr + total_chunk_size

        if chunk_end > territory_limit:
            # Chunk data or CRC is truncated within territory
            return None

        if chunk_type == b"IEND":
            # IEND chunk must have length 0 per RFC 2083
            if chunk_len == 0:
                return chunk_end
            return None

        curr = chunk_end

    return None


def _scan_png(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find all PNG magic-byte signatures in *data* with bounded sequential chunk parsing."""
    sig = PNG_SIGNATURE
    sig_len = len(sig)

    raw_starts: List[int] = []
    search_from = 0
    while search_from <= evidence_len - sig_len:
        pos = data.find(sig, search_from)
        if pos == -1:
            break
        raw_starts.append(pos)
        search_from = pos + sig_len

    if not raw_starts:
        return

    # Preceding candidate starts to prevent crossing prior candidate boundaries
    other_starts = [c.offset for c in candidates]

    valid_cands: List[Candidate] = []
    for idx, pos in enumerate(raw_starts):
        # If this position falls inside the completed bounds of a preceding valid candidate, skip it
        if valid_cands and valid_cands[-1].estimated_end_offset is not None:
            if pos < valid_cands[-1].estimated_end_offset:
                continue

        # Territory limit: earliest candidate start ahead of pos
        next_raw_start = raw_starts[idx + 1] if idx + 1 < len(raw_starts) else evidence_len
        territory_limit = next_raw_start
        for o in other_starts:
            if o > pos and o < territory_limit:
                territory_limit = o

        estimated_end = _find_png_end(data, pos, territory_limit)

        cand = Candidate(
            candidate_id="",
            format="png",
            mime_type="image/png",
            category="image",
            offset=pos,
            detected_header_length=sig_len,
            estimated_end_offset=estimated_end,
            detection_method="magic_bytes",
        )
        valid_cands.append(cand)
        candidates.append(cand)


# Valid JPEG first marker bytes immediately following \xFF\xD8\xFF
VALID_JPEG_FIRST_MARKERS = frozenset({
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xFE,
})


def _find_jpeg_end(
    data: bytes,
    start_pos: int,
    territory_limit: int,
) -> Optional[int]:
    """Parse JPEG marker stream sequentially starting from SOI to locate authentic EOI marker.

    Returns the byte offset immediately following EOI (estimated_end),
    or None if the JPEG is truncated, malformed, or missing EOI within territory_limit.
    """
    curr = start_pos + 2
    found_eoi = False
    end_offset: Optional[int] = None

    while curr < territory_limit:
        if data[curr] != 0xFF:
            # Non-marker byte encountered before SOS
            break

        if curr + 1 >= territory_limit:
            break

        marker = data[curr + 1]

        # Handle 0xFF padding or 0x00 (stuffed byte)
        if marker == 0x00 or marker == 0xFF:
            curr += 1
            continue

        # EOI Marker (0xFFD9) encountered outside entropy scan
        if marker == 0xD9:
            found_eoi = True
            end_offset = curr + 2
            break

        # Standalone markers without length: RST0-RST7 (0xD0-0xD7), SOI (0xD8)
        if 0xD0 <= marker <= 0xD8:
            curr += 2
            continue

        # Markers with 2-byte length payload
        if curr + 4 > territory_limit:
            break

        segment_len = struct.unpack(">H", data[curr + 2 : curr + 4])[0]
        if segment_len < 2:
            break

        segment_end = curr + 2 + segment_len
        if segment_end > territory_limit:
            break

        # SOS marker (0xDA): Start of Scan
        if marker == 0xDA:
            # Scan header is of length segment_len.
            # Compressed entropy scan data starts at segment_end.
            # Search for EOI strictly within [segment_end, territory_limit].
            eoi_pos = data.find(JPEG_EOI, segment_end, territory_limit)
            if eoi_pos != -1:
                found_eoi = True
                end_offset = eoi_pos + len(JPEG_EOI)
            break

        curr = segment_end

    return end_offset


def _scan_jpeg(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find all JPEG SOI signatures in *data* with bounded marker stream parsing and territory scoping."""
    sig = JPEG_SOI
    sig_len = len(sig)

    raw_starts: List[int] = []
    search_from = 0
    while search_from <= evidence_len - sig_len:
        pos = data.find(sig, search_from)
        if pos == -1:
            break

        # A valid JPEG SOI must be immediately followed by 0xFF and a valid marker byte
        if pos + 3 < evidence_len and data[pos + 2] == 0xFF and data[pos + 3] in VALID_JPEG_FIRST_MARKERS:
            raw_starts.append(pos)

        search_from = pos + 1

    if not raw_starts:
        return

    # Preceding candidate starts to prevent crossing prior candidate boundaries
    other_starts = [c.offset for c in candidates]

    valid_cands: List[Candidate] = []
    for idx, pos in enumerate(raw_starts):
        # If this position falls inside the completed bounds of a preceding valid candidate, skip it
        if valid_cands and valid_cands[-1].estimated_end_offset is not None:
            if pos < valid_cands[-1].estimated_end_offset:
                continue

        # Territory limit: earliest candidate start ahead of pos
        next_raw_start = raw_starts[idx + 1] if idx + 1 < len(raw_starts) else evidence_len
        territory_limit = next_raw_start
        for o in other_starts:
            if o > pos and o < territory_limit:
                territory_limit = o

        estimated_end = _find_jpeg_end(data, pos, territory_limit)

        cand = Candidate(
            candidate_id="",
            format="jpeg",
            mime_type="image/jpeg",
            category="image",
            offset=pos,
            detected_header_length=sig_len + 2,
            estimated_end_offset=estimated_end,
            detection_method="magic_bytes",
        )
        valid_cands.append(cand)
        candidates.append(cand)



PDF_VERSIONED_HEADER_RE = re.compile(rb"%PDF-[0-9]\.[0-9](?:\r\n|\n\r|\r|\n)")


def _is_inside_unclosed_stream(data: bytes, base_offset: int, target_pos: int) -> bool:
    """Check if target_pos lies inside an unclosed stream block originating after base_offset."""
    stream_matches = list(re.finditer(rb"\bstream\r?\n", data[base_offset:target_pos]))
    if not stream_matches:
        return False
    last_stream_end = base_offset + stream_matches[-1].end()
    return data.find(b"endstream", last_stream_end, target_pos) == -1


def _is_inside_unclosed_object(data: bytes, base_offset: int, target_pos: int) -> bool:
    """Check if target_pos lies inside an unclosed indirect object block originating after base_offset."""
    obj_matches = list(re.finditer(rb"\b\d+\s+\d+\s+obj\b", data[base_offset:target_pos]))
    if not obj_matches:
        return False
    last_obj_end = base_offset + obj_matches[-1].end()
    return data.find(b"endobj", last_obj_end, target_pos) == -1


def _verify_trailer_matches_candidate(data: bytes, cand_start: int, eof_pos: int) -> bool:
    """Verify if the trailer at eof_pos belongs to cand_start via startxref pointer to xref."""
    window = data[max(cand_start, eof_pos - 128):eof_pos + 20]
    m = re.search(rb"startxref\s+(\d+)\s+%%EOF", window)
    if not m:
        return True
    reported_offset = int(m.group(1))
    target = cand_start + reported_offset
    if target + 4 > len(data):
        return False
    target_slice = data[target:target + 10]
    return target_slice.startswith(b"xref") or b"obj" in target_slice or b"/XRef" in target_slice


def _scan_pdf(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find all structurally qualified PDF candidates using stream/object filtering and territory scoping."""
    sig = PDF_HEADER_SIGNATURE
    sig_len = len(sig)

    # 1. Discover all candidate start positions (%PDF-[0-9].[0-9] followed by EOL marker)
    raw_starts = [m.start() for m in PDF_VERSIONED_HEADER_RE.finditer(data[:evidence_len])]
    if not raw_starts:
        return

    # Filter ghost headers residing inside active streams or active indirect objects
    filtered_starts: List[int] = []
    for pos in raw_starts:
        if not filtered_starts:
            filtered_starts.append(pos)
            continue
        last_start = filtered_starts[-1]
        if _is_inside_unclosed_stream(data, last_start, pos):
            continue
        if _is_inside_unclosed_object(data, last_start, pos):
            continue
        filtered_starts.append(pos)

    # 2. Sequential candidate discovery and territory-scoped trailer search
    valid_cands: List[Candidate] = []
    curr_i = 0
    while curr_i < len(filtered_starts):
        pos = filtered_starts[curr_i]

        # If this position falls inside the completed bounds of a preceding valid candidate, skip it
        if valid_cands and valid_cands[-1].estimated_end_offset is not None:
            if pos < valid_cands[-1].estimated_end_offset:
                curr_i += 1
                continue

        search_start = pos + sig_len
        next_cand_start = None
        for future_start in filtered_starts[curr_i + 1:]:
            next_cand_start = future_start
            break

        end_of_territory = next_cand_start if next_cand_start is not None else evidence_len

        # Search for %%EOF within [search_start : end_of_territory]
        estimated_end: Optional[int] = None
        curr_search_end = end_of_territory
        while curr_search_end > search_start:
            eof_pos = data.rfind(PDF_TRAILER_SIGNATURE, search_start, curr_search_end)
            if eof_pos == -1:
                break
            if not _is_inside_unclosed_stream(data, pos, eof_pos):
                if _verify_trailer_matches_candidate(data, pos, eof_pos):
                    end_pos = eof_pos + len(PDF_TRAILER_SIGNATURE)
                    if end_pos + 2 <= end_of_territory and data[end_pos:end_pos + 2] in (b"\r\n", b"\n\r"):
                        end_pos += 2
                    elif end_pos + 1 <= end_of_territory and data[end_pos:end_pos + 1] in (b"\n", b"\r"):
                        end_pos += 1
                    estimated_end = min(end_pos, end_of_territory)
                    break
            curr_search_end = eof_pos

        # If no trailer was found within initial territory and there is a next_cand_start,
        # verify if next_cand_start was actually a false start inside this document
        if estimated_end is None and next_cand_start is not None:
            extended_search_end = evidence_len
            while extended_search_end > next_cand_start:
                eof_pos = data.rfind(PDF_TRAILER_SIGNATURE, next_cand_start, extended_search_end)
                if eof_pos == -1:
                    break
                if not _is_inside_unclosed_stream(data, pos, eof_pos):
                    if _verify_trailer_matches_candidate(data, pos, eof_pos):
                        end_pos = eof_pos + len(PDF_TRAILER_SIGNATURE)
                        if end_pos + 2 <= evidence_len and data[end_pos:end_pos + 2] in (b"\r\n", b"\n\r"):
                            end_pos += 2
                        elif end_pos + 1 <= evidence_len and data[end_pos:end_pos + 1] in (b"\n", b"\r"):
                            end_pos += 1
                        estimated_end = end_pos
                        break
                extended_search_end = eof_pos

        valid_cands.append(
            Candidate(
                candidate_id="",
                format="pdf",
                mime_type="application/pdf",
                category="document",
                offset=pos,
                detected_header_length=sig_len,
                estimated_end_offset=estimated_end,
                detection_method="magic_bytes",
            )
        )
        curr_i += 1

    candidates.extend(valid_cands)


def _find_xml_closing_boundary(
    data: bytes,
    header_pos: int,
    max_window: int = 4 * 1024 * 1024,
) -> Optional[int]:
    """Find the exact closing boundary of the XML root element starting at *header_pos*.

    Handles:
      - XML declaration (<?xml ... ?>)
      - doctype declarations (<!DOCTYPE ... >)
      - comments (<!-- ... -->)
      - processing instructions (<? ... ?>)
      - self-closing root tag (<root ... />)
      - CDATA sections with fake closing tags (<![CDATA[ </root> ]]>)
      - comments with fake closing tags (<!-- </root> -->)
      - attribute quotes containing '>' or fake closing tags

    Returns:
        Byte offset one past the last byte of the root element (e.g. after '</root>'),
        or None if truncated or not found within max_window.
    """
    n = min(len(data), header_pos + max_window)
    next_xml = data.find(XML_HEADER_SIGNATURE, header_pos + len(XML_HEADER_SIGNATURE))
    if next_xml != -1 and next_xml < n:
        n = next_xml

    decl_end = data.find(b"?>", header_pos)
    if decl_end == -1 or decl_end > header_pos + 1024 or decl_end >= n:
        return None
    i = decl_end + 2

    root_tag = None
    while i < n:
        while i < n and data[i] in b" \t\r\n":
            i += 1
        if i >= n:
            break
        if data.startswith(b"<!--", i):
            c_end = data.find(b"-->", i + 4)
            if c_end == -1:
                return None
            i = c_end + 3
            continue
        if data.startswith(b"<?", i):
            pi_end = data.find(b"?>", i + 2)
            if pi_end == -1:
                return None
            i = pi_end + 2
            continue
        if data.startswith(b"<!DOCTYPE", i) or data.startswith(b"<!doctype", i):
            j = i + 9
            has_bracket = False
            while j < n:
                if data[j : j + 1] == b"[":
                    has_bracket = True
                elif data[j : j + 1] == b"]":
                    has_bracket = False
                elif data[j : j + 1] == b">" and not has_bracket:
                    i = j + 1
                    break
                j += 1
            else:
                return None
            continue
        if data[i : i + 1] == b"<":
            tag_start = i + 1
            if tag_start < n and (data[tag_start : tag_start + 1].isalpha() or data[tag_start : tag_start + 1] in b"_:"):
                j = tag_start
                while j < n and (data[j : j + 1].isalnum() or data[j : j + 1] in b"_.:-"):
                    j += 1
                root_tag = data[tag_start:j]
                i = j
                break
            else:
                return None
        else:
            return None

    if not root_tag:
        return None

    in_quote = None
    while i < n:
        b = data[i : i + 1]
        if in_quote:
            if b == in_quote:
                in_quote = None
            i += 1
            continue
        if b in (b'"', b"'"):
            in_quote = b
            i += 1
            continue
        if b == b"/":
            if i + 1 < n and data[i + 1 : i + 2] == b">":
                return i + 2
        if b == b">":
            i += 1
            break
        i += 1
    else:
        return -1

    in_quote = None
    in_tag = False
    closing_target = b"</" + root_tag
    opening_target = b"<" + root_tag
    root_depth = 1

    while i < n:
        if not in_tag:
            if data.startswith(b"<!--", i):
                c_end = data.find(b"-->", i + 4)
                if c_end == -1:
                    return -1
                i = c_end + 3
                continue
            if data.startswith(b"<![CDATA[", i):
                cd_end = data.find(b"]]>", i + 9)
                if cd_end == -1:
                    return -1
                i = cd_end + 3
                continue
            if data.startswith(closing_target, i):
                j = i + len(closing_target)
                while j < n and data[j : j + 1] in b" \t\r\n":
                    j += 1
                if j < n and data[j : j + 1] == b">":
                    root_depth -= 1
                    if root_depth == 0:
                        return j + 1
                    i = j + 1
                    continue
            if data.startswith(opening_target, i):
                next_b = data[i + len(opening_target) : i + len(opening_target) + 1]
                if next_b in b" \t\r\n/>":
                    k = i + len(opening_target)
                    tag_quote = None
                    is_self_closing = False
                    while k < n:
                        tb = data[k : k + 1]
                        if tag_quote:
                            if tb == tag_quote:
                                tag_quote = None
                            k += 1
                            continue
                        if tb in (b'"', b"'"):
                            tag_quote = tb
                            k += 1
                            continue
                        if tb == b"/":
                            if k + 1 < n and data[k + 1 : k + 2] == b">":
                                is_self_closing = True
                                k += 2
                                break
                        if tb == b">":
                            k += 1
                            break
                        k += 1
                    else:
                        return -1

                    if not is_self_closing:
                        root_depth += 1
                    i = k
                    continue
            if data[i : i + 1] == b"<":
                in_tag = True
                i += 1
                continue
            i += 1
        else:
            b = data[i : i + 1]
            if in_quote:
                if b == in_quote:
                    in_quote = None
                i += 1
                continue
            if b in (b'"', b"'"):
                in_quote = b
                i += 1
                continue
            if b == b">":
                in_tag = False
                i += 1
                continue
            i += 1

    return -1


def _scan_xml(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find direct XML header signatures in *data* with bounded end estimation."""
    sig = XML_HEADER_SIGNATURE
    sig_len = len(sig)

    search_from = 0

    while search_from <= evidence_len - sig_len:
        pos = data.find(sig, search_from)
        if pos == -1:
            break

        boundary_res = _find_xml_closing_boundary(data, pos)
        estimated_end = boundary_res if (boundary_res is not None and boundary_res != -1) else None

        candidates.append(
            Candidate(
                candidate_id="",
                format="xml",
                mime_type="application/xml",
                category="structured",
                offset=pos,
                detected_header_length=sig_len,
                estimated_end_offset=estimated_end,
                detection_method="magic_bytes",
            )
        )
        search_from = pos + sig_len


def _find_zip_end(
    data: bytes,
    start_pos: int,
    territory_limit: int,
) -> Optional[int]:
    """Locate authentic End of Central Directory (EOCD) for a ZIP archive candidate."""
    if territory_limit - start_pos < 22:
        return None

    search_slice = data[start_pos:territory_limit]
    eocd_rel = search_slice.rfind(ZIP_EOCD_SIGNATURE)
    if eocd_rel == -1:
        return None

    eocd_pos = start_pos + eocd_rel
    if eocd_pos + 22 > territory_limit:
        return None

    comment_len = struct.unpack("<H", data[eocd_pos + 20 : eocd_pos + 22])[0]
    total_end = eocd_pos + 22 + comment_len
    if total_end <= territory_limit:
        return total_end
    return None


def _scan_zip(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find ZIP local file headers in *data* with bounded sequential parsing."""
    sig = ZIP_LOCAL_HEADER
    sig_len = len(sig)

    raw_starts: List[int] = []
    search_from = 0
    while search_from <= evidence_len - sig_len:
        pos = data.find(sig, search_from)
        if pos == -1:
            break
        raw_starts.append(pos)
        search_from = pos + sig_len

    if not raw_starts:
        return

    other_starts = [c.offset for c in candidates]
    valid_cands: List[Candidate] = []

    for idx, pos in enumerate(raw_starts):
        if pos + 30 > evidence_len:
            continue
        fn_len = struct.unpack("<H", data[pos + 26 : pos + 28])[0]
        if fn_len == 0 or pos + 30 + fn_len > evidence_len:
            continue

        if valid_cands and valid_cands[-1].estimated_end_offset is not None:
            if pos < valid_cands[-1].estimated_end_offset:
                continue

        next_raw_start = raw_starts[idx + 1] if idx + 1 < len(raw_starts) else evidence_len
        territory_limit = next_raw_start
        for o in other_starts:
            if o > pos and o < territory_limit:
                territory_limit = o

        estimated_end = _find_zip_end(data, pos, territory_limit)

        cand = Candidate(
            candidate_id="",
            format="zip",
            mime_type="application/zip",
            category="archive",
            offset=pos,
            detected_header_length=sig_len,
            estimated_end_offset=estimated_end,
            detection_method="magic_bytes",
        )
        valid_cands.append(cand)
        candidates.append(cand)


_JSON_WS = " \t\n\r"
_JSON_LITERALS = ("true", "false", "null")


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in _JSON_WS:
        i += 1
    return i


def _scan_string(text: str, i: int) -> Tuple[int, str]:
    """Scan a JSON string starting at the opening quote.

    Returns (index_after_string, status) where status is "ok" or "unterminated".
    """
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c in "\r\n\x00":
            return j, "unterminated"
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
    if j < n and text[j] not in _JSON_WS and text[j] not in ",}]" and text[j] != "\x00":
        return j, "invalid"
    return j, "ok"


def _scan_literal(text: str, i: int) -> Tuple[int, str]:
    """Scan true/false/null.

    Returns (index_after_literal, status) where status is "ok", "incomplete", or "invalid".
    """
    n = len(text)
    for lit in _JSON_LITERALS:
        if text.startswith(lit, i):
            end = i + len(lit)
            if end < n and (text[end].isalnum() or text[end] == "_"):
                return end, "invalid"
            return end, "ok"
        rem = text[i:n]
        nul_idx = rem.find("\x00")
        if nul_idx != -1:
            rem = rem[:nul_idx]
        if rem and lit.startswith(rem):
            return i + len(rem), "incomplete"
    return i, "invalid"


def _find_json_container_extent(
    text: str,
    max_depth: int = 128,
) -> Tuple[Optional[int], bool, bool]:
    """Scan *text* starting at index 0 for a JSON object or array container.

    Returns:
        (end_char_index, is_complete, is_plausible_truncated)
        - If complete: (end_index, True, False)
        - If truncated but structurally plausible: (None, False, True)
        - If invalid/noise: (None, False, False)
    """
    i = _skip_ws(text, 0)
    if i >= len(text) or text[i] not in ("{", "["):
        return None, False, False
    opener = text[i]
    stack = [opener]
    i += 1
    state = "key" if opener == "{" else "value"
    has_content = False
    last_valid_i = i

    while i < len(text) and len(stack) <= max_depth:
        if state == "value":
            i = _skip_ws(text, i)
            if i >= len(text) or not text[i:].strip("\x00 \t\r\n"):
                return (last_valid_i, False, has_content) if has_content else (None, False, False)
            c = text[i]
            if c == "{":
                stack.append("{")
                i += 1
                state = "key"
                has_content = True
                continue
            if c == "[":
                stack.append("[")
                i += 1
                state = "value"
                has_content = True
                continue
            if c == "]" and stack[-1] == "[":
                i += 1
                stack.pop()
                last_valid_i = i
                if not stack:
                    return last_valid_i, True, False
                state = "sep"
                continue
            if c == '"':
                i, st = _scan_string(text, i)
                if st != "ok":
                    return (last_valid_i, False, has_content) if has_content else (None, False, False)
                has_content = True
                last_valid_i = i
                state = "sep"
                continue
            if c in "tfn":
                i, st = _scan_literal(text, i)
                if st == "incomplete":
                    return (last_valid_i, False, has_content) if has_content else (None, False, False)
                if st != "ok":
                    return None, False, False
                has_content = True
                last_valid_i = i
                state = "sep"
                continue
            if c == "-" or c.isdigit():
                i, st = _scan_number(text, i)
                if st == "incomplete":
                    return (last_valid_i, False, has_content) if has_content else (None, False, False)
                if st != "ok":
                    return None, False, False
                has_content = True
                last_valid_i = i
                state = "sep"
                continue
            return (last_valid_i, False, has_content) if (has_content and not text[i:].strip("\x00 \t\r\n")) else (None, False, False)

        if state == "key":
            i = _skip_ws(text, i)
            if i >= len(text) or not text[i:].strip("\x00 \t\r\n"):
                return (last_valid_i, False, has_content) if has_content else (None, False, False)
            if text[i] == "}" and stack[-1] == "{":
                i += 1
                stack.pop()
                last_valid_i = i
                if not stack:
                    return last_valid_i, True, False
                state = "sep"
                continue
            if text[i] != '"':
                return (last_valid_i, False, has_content) if (has_content and not text[i:].strip("\x00 \t\r\n")) else (None, False, False)
            i, st = _scan_string(text, i)
            if st != "ok":
                return (last_valid_i, False, has_content) if has_content else (None, False, False)
            has_content = True
            state = "colon"
            continue

        if state == "colon":
            i = _skip_ws(text, i)
            if i >= len(text) or not text[i:].strip("\x00 \t\r\n"):
                return (last_valid_i, False, has_content) if has_content else (None, False, False)
            if text[i] != ":":
                return (last_valid_i, False, has_content) if (has_content and not text[i:].strip("\x00 \t\r\n")) else (None, False, False)
            i += 1
            state = "value"
            continue

        if state == "sep":
            if not stack:
                return last_valid_i, True, False
            last_valid_i = i
            i = _skip_ws(text, i)
            if i >= len(text):
                return (last_valid_i, False, has_content) if has_content else (None, False, False)
            c = text[i]
            closer = "}" if stack[-1] == "{" else "]"
            if c == ",":
                i += 1
                state = "key" if stack[-1] == "{" else "value"
                continue
            if c == closer:
                i += 1
                stack.pop()
                last_valid_i = i
                if not stack:
                    return last_valid_i, True, False
                state = "sep"
                continue
            return (last_valid_i, False, has_content) if has_content else (None, False, False)

    return (last_valid_i, False, has_content) if has_content else (None, False, False)


def _scan_json(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find all blind JSON container documents (objects and arrays) in *data*."""
    MAX_JSON_WINDOW = 2 * 1024 * 1024  # 2 MiB bounded search window
    MAX_NESTING_DEPTH = 128
    search_from = 0

    while search_from < evidence_len:
        pos_brace = data.find(b"{", search_from)
        pos_bracket = data.find(b"[", search_from)

        if pos_brace == -1 and pos_bracket == -1:
            break
        if pos_brace != -1 and pos_bracket != -1:
            pos = min(pos_brace, pos_bracket)
        else:
            pos = pos_brace if pos_brace != -1 else pos_bracket

        # Avoid redundant duplicate detection inside already detected candidates
        in_prior_candidate = False
        for c in candidates:
            if c.detection_method == "synthetic_boundary":
                c_end = c.estimated_end_offset if c.estimated_end_offset is not None else evidence_len
                if c.offset <= pos < c_end:
                    in_prior_candidate = True
                    search_from = c_end
                    break
            elif c.format in ("png", "jpeg", "pdf", "xml", "zip") and c.estimated_end_offset is not None:
                if c.offset <= pos < c.estimated_end_offset:
                    in_prior_candidate = True
                    search_from = c.estimated_end_offset
                    break
        if in_prior_candidate:
            continue

        opener = data[pos : pos + 1]

        # Fast lookahead: inspect first non-whitespace byte
        k = pos + 1
        while k < evidence_len and data[k] in b" \t\r\n":
            k += 1

        if k >= evidence_len:
            search_from = pos + 1
            continue

        next_b = data[k : k + 1]
        if opener == b"{":
            if next_b not in (b'"', b"}"):
                search_from = pos + 1
                continue
        elif opener == b"[":
            if not (next_b in (b'"', b"{", b"[", b"]", b"-", b"t", b"f", b"n") or (b"0" <= next_b <= b"9")):
                search_from = pos + 1
                continue

        window_len = min(evidence_len - pos, MAX_JSON_WINDOW)
        slice_bytes = data[pos : pos + window_len]
        text = slice_bytes.decode("utf-8", errors="replace")

        end_char_index, is_complete, is_plausible_truncated = _find_json_container_extent(
            text, max_depth=MAX_NESTING_DEPTH
        )

        if is_complete and end_char_index is not None:
            doc_bytes = text[:end_char_index].encode("utf-8")
            byte_len = len(doc_bytes)
            estimated_end = pos + byte_len

            # Verify UTF-8 fidelity and validate JSON structure
            try:
                candidate_raw = data[pos:estimated_end]
                candidate_raw.decode("utf-8")
            except UnicodeDecodeError:
                search_from = pos + 1
                continue

            from backend.app.recovery.validators.json import validate_json

            val_res = validate_json(candidate_raw)
            if val_res.valid:
                candidates.append(
                    Candidate(
                        candidate_id="",
                        format="json",
                        mime_type="application/json",
                        category="structured",
                        offset=pos,
                        detected_header_length=1,
                        estimated_end_offset=estimated_end,
                        detection_method="syntax_boundary",
                    )
                )
                search_from = estimated_end
                continue
            else:
                search_from = pos + 1
                continue

        elif not is_complete and is_plausible_truncated:
            from backend.app.recovery.reconstructors.json import (
                _classify_prefix,
                _CLOSABLE,
                _INCOMPLETE,
            )

            prefix_text = text[:end_char_index] if end_char_index is not None else text
            cls_res, stack, _ = _classify_prefix(prefix_text)
            if cls_res in (_CLOSABLE, _INCOMPLETE) and len(stack) > 0:
                candidates.append(
                    Candidate(
                        candidate_id="",
                        format="json",
                        mime_type="application/json",
                        category="structured",
                        offset=pos,
                        detected_header_length=1,
                        estimated_end_offset=None,
                        detection_method="syntax_boundary",
                    )
                )
                prefix_bytes = prefix_text.encode("utf-8")
                search_from = pos + max(len(prefix_bytes), 1)
                continue
            else:
                search_from = pos + 1
                continue
        else:
            search_from = pos + 1
            continue


def _scan_text_and_csv(
    data: bytes,
    evidence_len: int,
    candidates: List[Candidate],
) -> None:
    """Find blind TXT and CSV candidate runs in *data* based on text-run heuristics and mandatory validation."""
    from backend.app.recovery.validators.csv import validate_csv
    from backend.app.recovery.validators.text import validate_txt

    MIN_CANDIDATE_LEN = 64
    MIN_PRINTABLE_DENSITY = 0.90
    MIN_LOGICAL_NEWLINES = 2

    # Collect ranges occupied by synthetic boundary candidates to preserve synthetic harness behavior
    synthetic_ranges = []
    for c in candidates:
        if c.detection_method == "synthetic_boundary":
            c_end = c.estimated_end_offset if c.estimated_end_offset is not None else evidence_len
            synthetic_ranges.append((c.offset, c_end))

    # Collect structured candidate boundaries from prior scanner passes (PDF, XML, JSON, PNG, JPEG)
    def _is_trustworthy_boundary(c: Candidate) -> bool:
        if c.estimated_end_offset is None:
            return False
        if c.format in ("pdf", "xml", "png", "jpeg", "zip"):
            return True
        if c.format == "json":
            # An independent JSON candidate acts as a text boundary if it starts at offset 0
            # or is preceded by a newline/NUL boundary (not embedded within a text line)
            pos = c.offset
            if pos == 0 or pos >= evidence_len:
                return True
            if data[pos - 1] in (0, 10, 13):
                return True
            k = pos - 1
            while k >= 0 and data[k] in b" \t":
                k -= 1
            if k < 0 or data[k] in (0, 10, 13):
                return True
            return False
        return False

    structured_candidates = [
        c for c in candidates
        if c.format in ("pdf", "xml", "json", "png", "jpeg", "zip")
    ]
    trustworthy_structured = [
        c for c in structured_candidates
        if _is_trustworthy_boundary(c)
    ]
    trustworthy_bounded_ranges = [
        (c.offset, c.estimated_end_offset)
        for c in trustworthy_structured
        if c.estimated_end_offset is not None and c.estimated_end_offset > c.offset
    ]
    trustworthy_starts = sorted(set(c.offset for c in trustworthy_structured))

    i = 0
    while i < evidence_len:
        # 1. Skip if current position is inside a synthetic candidate range
        in_synthetic = False
        for s_start, s_end in synthetic_ranges:
            if s_start <= i < s_end:
                i = s_end
                in_synthetic = True
                break
        if in_synthetic:
            continue

        # Skip if current position is inside a validated trustworthy structured candidate range
        in_structured = False
        for s_start, s_end in trustworthy_bounded_ranges:
            if s_start <= i < s_end:
                i = s_end
                in_structured = True
                break
        if in_structured:
            continue

        # Skip if current position is the exact start of an unclosed trustworthy structured candidate
        if any(c.offset == i for c in trustworthy_structured if c.estimated_end_offset is None):
            i += 1
            continue

        # 2. Skip non-text bytes to locate start of potential text run
        b = data[i]
        is_text_start = False
        step = 1

        if (0x20 <= b <= 0x7E) or b in (9, 10, 13):
            is_text_start = True
        elif 0xC2 <= b <= 0xF4:
            for s in (2, 3, 4):
                if i + s <= evidence_len:
                    try:
                        ch = data[i : i + s].decode("utf-8")
                        if ch.isprintable():
                            is_text_start = True
                            step = s
                            break
                    except UnicodeDecodeError:
                        pass

        if not is_text_start:
            i += 1
            continue

        # Found start of text run
        start = i
        j = i + step
        printable_bytes = step

        # Determine maximum allowable boundary for this text run:
        # A heuristic text run must not extend past the start of any trustworthy structured candidate ahead of start,
        # nor into any synthetic candidate range ahead of start.
        max_run_limit = evidence_len
        for s_off in trustworthy_starts:
            if s_off > start:
                max_run_limit = min(max_run_limit, s_off)
                break
        for s_start, _ in synthetic_ranges:
            if s_start > start:
                max_run_limit = min(max_run_limit, s_start)
                break

        # 3. Advance j until a run terminator is encountered
        terminated_on_invalid_utf8 = False
        while j < evidence_len:
            # Check candidate boundary collision (synthetic or structured)
            if j >= max_run_limit:
                break

            jb = data[j]
            # NUL byte is a hard terminator
            if jb == 0:
                break

            # Printable ASCII / whitespace
            if (0x20 <= jb <= 0x7E) or jb in (9, 10, 13):
                printable_bytes += 1
                j += 1
                continue

            # Multi-byte UTF-8
            if 0xC2 <= jb <= 0xF4:
                matched_multibyte = False
                for s in (2, 3, 4):
                    if j + s <= evidence_len:
                        try:
                            ch = data[j : j + s].decode("utf-8")
                            if ch.isprintable():
                                printable_bytes += s
                                j += s
                                matched_multibyte = True
                                break
                        except UnicodeDecodeError:
                            pass
                if matched_multibyte:
                    continue

            # 1-byte control character (not 9, 10, 13)
            if jb < 32 or jb == 127:
                curr_len = (j - start) + 1
                if (printable_bytes / curr_len) < MIN_PRINTABLE_DENSITY:
                    break
                # If two consecutive control bytes, terminate run
                if j + 1 < evidence_len and (data[j + 1] < 32 or data[j + 1] == 127) and data[j + 1] not in (9, 10, 13):
                    break
                j += 1
                continue

            # Any invalid UTF-8 byte terminates the run
            terminated_on_invalid_utf8 = True
            break

        # 4. Trim incomplete trailing UTF-8 sequences and trailing non-printable control bytes
        while j > start:
            try:
                data[start:j].decode("utf-8")
                break
            except UnicodeDecodeError:
                j -= 1

        while j > start and data[j - 1] < 32 and data[j - 1] not in (9, 10, 13):
            j -= 1

        # Trim trailing incomplete lines where appropriate
        if b"\n" in data[start:j]:
            last_nl = data[start:j].rfind(b"\n")
            trailing_segment = data[start + last_nl + 1 : j]
            if trailing_segment:
                has_non_printable = any(
                    (tb < 32 and tb not in (9, 10, 13)) or tb == 127
                    for tb in trailing_segment
                )
                if has_non_printable or terminated_on_invalid_utf8:
                    j = start + last_nl + 1

        run_bytes = data[start:j]
        run_len = len(run_bytes)

        # 5. Check heuristics
        if run_len >= MIN_CANDIDATE_LEN:
            # Standalone whole-buffer text files (no surrounding evidence boundaries)
            # are preserved for the canonical direct fallback recovery path.
            if start == 0 and j == evidence_len:
                i = max(j, i + 1)
                continue

            newlines = run_bytes.count(b"\n") + (run_bytes.count(b"\r") - run_bytes.count(b"\r\n"))
            density = printable_bytes / run_len if run_len > 0 else 0.0

            if newlines >= MIN_LOGICAL_NEWLINES and density >= MIN_PRINTABLE_DENSITY:
                first_nl = run_bytes.find(b"\n")
                first_line_len = (first_nl + 1) if first_nl != -1 else 1

                # 6. Mandatory Validation Gate
                # First test CSV
                val_csv = validate_csv(run_bytes)
                if val_csv.valid:
                    candidates.append(
                        Candidate(
                            candidate_id="",
                            format="csv",
                            mime_type="text/csv",
                            category="text",
                            offset=start,
                            detected_header_length=first_line_len,
                            estimated_end_offset=j,
                            detection_method="heuristic_text_run",
                        )
                    )

                # Then independently test TXT
                val_txt = validate_txt(run_bytes)
                if val_txt.valid:
                    candidates.append(
                        Candidate(
                            candidate_id="",
                            format="txt",
                            mime_type="text/plain",
                            category="text",
                            offset=start,
                            detected_header_length=first_line_len,
                            estimated_end_offset=j,
                            detection_method="heuristic_text_run",
                        )
                    )

        i = max(j, i + 1)
