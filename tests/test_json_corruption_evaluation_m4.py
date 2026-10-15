"""tests/test_json_corruption_evaluation_m4.py — Milestone 4 Realistic JSON Corruption Evaluation.

Evaluates Recoverix's behavior on realistic JSON corruption patterns across:
1. Intact JSON with harmless trailing padding.
2. JSON followed by unrelated binary noise.
3. JSON with corruption after a complete top-level value.
4. JSON with corruption inside a string.
5. JSON with corruption inside a number.
6. JSON with corruption inside a nested array or object.
7. Two independent JSON fragments separated by noise.
8. A structurally closable EOF-truncated document.
9. An EOF-truncated document whose original content cannot be inferred.
10. An entirely unrecoverable input.

Validates core forensic failure boundaries:
- Invalid tokens are not silently converted into fabricated values.
- Independent fragments are not incorrectly merged.
- Noise is not reported as a successful recovery.
- Valid fragments are not discarded merely because adjacent bytes are corrupt.
- Reconstructed output does not receive FULLY_RECOVERED without satisfying recovery invariants.
- Missing or unrecognized damage status does not inherit artifact-level reconstruction success.
- Existing non-JSON recovery paths remain unaffected.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Dict, Any, Tuple

import pytest

from backend.app.recovery.scanner import scan_evidence
from backend.app.recovery.tracer import (
    execute_traced_recovery,
    execute_traced_recoveries,
    _resolve_damage_region_status,
)
from backend.app.recovery.reconstructors.json import reconstruct_json
from backend.app.recovery.validators.json import validate_json
from benchmark.models import (
    BenchmarkGroundTruthManifest,
    PhysicalArtifactRecord,
    PhysicalDamageInterval,
    PhysicalPlacement,
)
from benchmark.run_baseline import run_pipeline_and_observe
from benchmark.evaluator import evaluate_scenario


# ══════════════════════════════════════════════════════════════════════════════
# Corpus Scenarios 1–10
# ══════════════════════════════════════════════════════════════════════════════

def test_corpus_s01_intact_with_trailing_padding():
    """Scenario 1: Intact JSON with harmless trailing sector padding.

    Expected: Candidate is discovered with exact bounds, trailing padding excluded,
    payload byte-exact (SHA-256 MATCH), status FULLY_RECOVERED, V=93, R=0, M=0.
    """
    orig_payload = b'{"app": "recoverix", "status": "online", "workers": 4, "metrics": {"cpu": 12.5, "mem": 45.2}}'
    padding = b"\x00" * 64
    evidence = orig_payload + padding

    cands = scan_evidence(evidence)
    assert len(cands) == 1
    cand = cands[0]
    assert cand.format == "json"
    assert cand.offset == 0
    assert cand.estimated_end_offset == len(orig_payload)

    runs = execute_traced_recoveries("corpus_s01.img", evidence)
    assert len(runs) == 1
    run = runs[0]
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(orig_payload)
    assert run.total_reconstructed_bytes == 0
    assert run.total_missing_bytes == 0
    recovered_bytes = bytes.fromhex(run.output["recovered_bytes"])
    assert recovered_bytes == orig_payload
    assert hashlib.sha256(recovered_bytes).hexdigest() == hashlib.sha256(orig_payload).hexdigest()


def test_corpus_s02_json_followed_by_unrelated_binary_noise():
    """Scenario 2: JSON followed by unrelated high-entropy binary noise.

    Expected: Scanner isolates JSON boundary at closing delimiter. Binary noise
    does not truncate or corrupt the valid candidate. Status FULLY_RECOVERED.
    """
    orig_payload = b'{"session_id": "sess-9941a", "authenticated": true, "timestamp": 1729000000}'
    # Non-structured high-entropy noise
    noise = bytes([(x * 37 + 13) % 255 + 1 for x in range(128)])
    prefix = b"\x00" * 256
    evidence = prefix + orig_payload + noise

    cands = scan_evidence(evidence)
    json_cands = [c for c in cands if c.format == "json"]
    assert len(json_cands) == 1
    cand = json_cands[0]
    assert cand.offset == 256
    assert cand.estimated_end_offset == 256 + len(orig_payload)

    runs = execute_traced_recoveries("corpus_s02.img", evidence)
    json_runs = [r for r in runs if r.format == "json"]
    assert len(json_runs) == 1
    run = json_runs[0]
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(orig_payload)
    assert run.total_reconstructed_bytes == 0
    assert run.total_missing_bytes == 0
    recovered = bytes.fromhex(run.output["recovered_bytes"])
    assert recovered == orig_payload
    assert hashlib.sha256(recovered).hexdigest() == hashlib.sha256(orig_payload).hexdigest()


def test_corpus_s03_corruption_after_complete_toplevel_value():
    """Scenario 3: JSON with corruption immediately following complete top-level value.

    Expected: When a raw slice containing trailing non-whitespace noise is evaluated directly,
    reconstruct_json classifies it as INVALID (unexpected extra data), reporting UNRECOVERABLE.
    When carved through scanner, scanner bounds at '}' and excludes the trailing garbage.
    """
    clean_json = b'{"record_id": 42, "valid": true}'
    corrupt_tail = b" trailing garbage !@#$"
    raw_buffer = clean_json + corrupt_tail

    # Direct reconstruction on uncarved buffer rejects trailing non-whitespace
    r_direct = reconstruct_json(raw_buffer)
    assert r_direct.status == "UNRECOVERABLE"
    assert r_direct.success is False
    assert r_direct.verified_bytes == 0
    assert r_direct.missing_bytes == len(raw_buffer)
    assert r_direct.reconstructed_bytes == 0

    # Scanned evidence isolates candidate before trailing garbage
    cands = scan_evidence(raw_buffer)
    assert len(cands) >= 1
    assert cands[0].offset == 0
    assert cands[0].estimated_end_offset == len(clean_json)


def test_corpus_s04_corruption_inside_string_token():
    """Scenario 4: JSON with corruption inside a string value (raw NUL or control bytes).

    RFC 8259 forbids unescaped control characters in strings.
    Expected: Engine rejects malformed string syntax; does not guess characters or strip
    corrupt bytes to fabricate a clean string. Status is CORRUPTED or UNRECOVERABLE.
    """
    corrupt_evidence = b'{"user": "alice", "bio": "developer \x00 admin", "active": true}'
    r = reconstruct_json(corrupt_evidence)
    assert r.status in ("CORRUPTED", "UNRECOVERABLE")
    assert r.status != "FULLY_RECOVERED"
    assert r.success is False
    # Verifies string was not silently sanitized by dropping NUL
    val = validate_json(r.recovered_bytes)
    assert val.valid is False


def test_corpus_s05_corruption_inside_number_token():
    """Scenario 5: JSON with corruption inside a number token (multiple decimals or non-digits).

    Expected: Scanner / reconstructor does not fabricate digits or truncate to a partial number.
    Status is UNRECOVERABLE, success is False.
    """
    # Case A: Multiple decimal points
    evidence_multi_dot = b'{"sensor": "temp", "reading": 23.45.67, "unit": "celsius"}'
    r1 = reconstruct_json(evidence_multi_dot)
    assert r1.status == "UNRECOVERABLE"
    assert r1.success is False
    assert r1.verified_bytes == 0

    # Case B: Embedded NUL in integer
    evidence_nul_num = b'{"port": 80\x0080}'
    r2 = reconstruct_json(evidence_nul_num)
    assert r2.status in ("UNRECOVERABLE", "CORRUPTED")
    assert r2.success is False


def test_corpus_s06_corruption_inside_nested_container():
    """Scenario 6: JSON with non-UTF8 corruption inside a nested array.

    Expected: Unrecoverable UTF-8 decoding failure. Every byte is accounted as missing
    with type INVALID_UTF8; no nested structures are invented.
    """
    corrupt_nested = b'{"matrix": [[1, 2], [3, \xff\xfe\xfd, 5]], "shape": [2, 3]}'
    r = reconstruct_json(corrupt_nested)
    assert r.status == "UNRECOVERABLE"
    assert r.success is False
    assert r.verified_bytes == 0
    assert r.missing_bytes == len(corrupt_nested)
    assert r.reconstructed_bytes == 0
    assert any(d["type"] == "INVALID_UTF8" for d in r.damage_regions)


def test_corpus_s07_two_independent_fragments_separated_by_noise():
    """Scenario 7: Two independent JSON documents separated by binary noise.

    Expected: Scanner detects BOTH independent candidates.
    Tracer recovers both candidates independently into separate RecoveryRun records.
    Neither candidate merges into the other. Status is FULLY_RECOVERED for both.
    """
    c1 = b'{"frag": 1, "data": "alpha"}'
    c2 = b'{"frag": 2, "data": "beta"}'
    noise = bytes([(i * 17) % 256 for i in range(1, 65)])
    evidence = (b"\x00" * 32) + c1 + noise + c2 + (b"\x00" * 32)

    cands = scan_evidence(evidence)
    assert len(cands) == 2
    assert cands[0].offset == 32
    assert cands[0].estimated_end_offset == 32 + len(c1)
    assert cands[1].offset == 32 + len(c1) + len(noise)
    assert cands[1].estimated_end_offset == 32 + len(c1) + len(noise) + len(c2)

    runs = execute_traced_recoveries("corpus_s07.img", evidence)
    assert len(runs) == 2
    assert all(r.status == "FULLY_RECOVERED" for r in runs)
    assert bytes.fromhex(runs[0].output["recovered_bytes"]) == c1
    assert bytes.fromhex(runs[1].output["recovered_bytes"]) == c2


def test_corpus_s08_structurally_closable_eof_truncated_pure():
    """Scenario 8: Structurally closable EOF-truncated document with only delimiters lost.

    Expected: Reconstructor appends deterministic closers (']}') uniquely determined
    by the container stack. Status is PARTIALLY_RECOVERED (R=2, M=0, V=45).
    """
    orig_payload = b'{"device": "probe-8", "readings": [10.1, 10.2]}'
    surviving_prefix = b'{"device": "probe-8", "readings": [10.1, 10.2'

    r = reconstruct_json(surviving_prefix, original_data=orig_payload)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.status != "FULLY_RECOVERED"
    assert r.verified_bytes == len(surviving_prefix)
    assert r.reconstructed_bytes == 2  # ']}'
    assert r.missing_bytes == 0
    assert r.recovered_bytes == orig_payload
    assert r.is_exact_match is True
    assert hashlib.sha256(r.recovered_bytes).hexdigest() == hashlib.sha256(orig_payload).hexdigest()


def test_corpus_s09_eof_truncated_content_loss_unresolvable():
    """Scenario 9: EOF-truncated document where original content was missing prior to truncation.

    Expected: Structural closure produces valid JSON, but engine cannot know the missing
    items. Engine reports M=0 (no guessing). Independent benchmark evaluator reports UNACCOUNTED_GAP.
    """
    orig_payload = b'{"device": "probe-9", "readings": [10.1, 10.2, 10.3, 10.4]}'
    surviving_prefix = b'{"device": "probe-9", "readings": [10.1, 10.2'
    gap_len = len(orig_payload) - len(surviving_prefix)  # 12 bytes lost

    r = reconstruct_json(surviving_prefix, original_data=orig_payload)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.verified_bytes == len(surviving_prefix)
    assert r.reconstructed_bytes == 2  # ']}'
    assert r.missing_bytes == 0  # not fabricated
    assert r.is_exact_match is False
    assert r.recovered_bytes == b'{"device": "probe-9", "readings": [10.1, 10.2]}'

    # Evaluator flags gap
    art = PhysicalArtifactRecord(
        artifact_id="art-s09",
        original_filename="probe_9.json",
        format="json",
        original_size_bytes=len(orig_payload),
        original_sha256=hashlib.sha256(orig_payload).hexdigest(),
        original_bytes_b64=base64.b64encode(orig_payload).decode("ascii"),
        header_evidence_offset=0,
        header_original_offset=0,
        placements=[PhysicalPlacement(fragment_index=0, evidence_offset=0, evidence_length=len(surviving_prefix), original_offset=0)],
        damage_intervals=[PhysicalDamageInterval(original_start=len(surviving_prefix), original_end=len(orig_payload), length=gap_len, damage_type="PHYSICAL_GAP", reconstruction_mode="RECONSTRUCTION_NONE")],
        is_deterministic_recovery=False,
    )
    manifest = BenchmarkGroundTruthManifest(
        manifest_version="1.0.0",
        scenario_id="s09-content-loss",
        evidence_buffer_id="s09.img",
        evidence_size_bytes=len(surviving_prefix),
        evidence_sha256=hashlib.sha256(surviving_prefix).hexdigest(),
        seed=42,
        artifacts=[art],
    )
    obs = run_pipeline_and_observe("s09.img", surviving_prefix)
    rep = evaluate_scenario(manifest, obs)
    assert any("UNACCOUNTED_GAP" in v for v in rep.forensic_violations)


def test_corpus_s10_entirely_unrecoverable_input():
    """Scenario 10: Entirely unrecoverable high-entropy noise.

    Expected: Scanner discovers 0 candidates. Direct reconstructor rejects with UNRECOVERABLE.
    Zero false positives.
    """
    noise = bytes([(i * 53 + 7) % 256 for i in range(256)])
    cands = scan_evidence(noise)
    json_cands = [c for c in cands if c.format == "json"]
    assert len(json_cands) == 0

    r = reconstruct_json(noise)
    assert r.status == "UNRECOVERABLE"
    assert r.success is False
    assert r.verified_bytes == 0
    assert r.missing_bytes == len(noise)
    assert r.reconstructed_bytes == 0


# ══════════════════════════════════════════════════════════════════════════════
# Failure Boundaries
# ══════════════════════════════════════════════════════════════════════════════

def test_boundary_invalid_tokens_never_fabricated():
    """Verify that invalid tokens are not silently converted into fabricated values."""
    # Truncated number with trailing dot
    r1 = reconstruct_json(b'{"count": 12.')
    assert r1.success is False
    assert r1.reconstructed_bytes == 0

    # Truncated boolean
    r2 = reconstruct_json(b'{"ready": fal')
    assert r2.success is False
    assert r2.reconstructed_bytes == 0


def test_boundary_independent_fragments_never_merged():
    """Verify independent fragments are never concatenated into a single malformed candidate."""
    cand_a = b'{"a": 1}'
    cand_b = b'{"b": 2}'
    evidence = cand_a + b"\x00" * 16 + cand_b
    cands = scan_evidence(evidence)
    assert len(cands) == 2
    assert cands[0].estimated_end_offset == len(cand_a)
    assert cands[1].offset == len(cand_a) + 16


def test_boundary_noise_never_reported_as_successful_recovery():
    """Verify random binary or HTML noise is never reported as successful recovery."""
    noise_html = b"<html><body><h1>Not JSON</h1></body></html>"
    cands = scan_evidence(noise_html)
    assert not any(c.format == "json" for c in cands)


def test_boundary_valid_fragment_adjacent_to_noise_preserved():
    """Verify a valid JSON fragment is not discarded merely because adjacent bytes are corrupt."""
    valid_json = b'{"status": "ok"}'
    corrupt_prefix = b"\xff\xfe\x00\x00" * 8
    evidence = corrupt_prefix + valid_json
    cands = scan_evidence(evidence)
    assert any(c.format == "json" and c.offset == len(corrupt_prefix) for c in cands)


def test_boundary_reconstructed_output_never_claims_fully_recovered():
    """Verify reconstructed output (R > 0) never claims FULLY_RECOVERED."""
    r = reconstruct_json(b'{"unclosed": [1, 2')
    assert r.reconstructed_bytes > 0
    assert r.status != "FULLY_RECOVERED"
    assert r.status == "PARTIALLY_RECOVERED"


def test_boundary_non_json_formats_unaffected():
    """Verify non-JSON format recovery (TXT, CSV) remains intact."""
    txt_content = b"Line 1: Recoverix\nLine 2: Integrity verified\n"
    run = execute_traced_recovery("sample.txt", txt_content)
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(txt_content)
    assert run.total_reconstructed_bytes == 0


def test_boundary_damage_status_fallback_never_overstates_recovery():
    """Verify missing, absent, or unrecognized damage statuses conservatively default to UNRECOVERABLE.

    Artifact-level reconstruction success must never be inherited by an unstated or unrecognized damage region.
    """
    # 1. Unrecognized status string
    assert _resolve_damage_region_status("BOGUS_STATUS", True) == "UNRECOVERABLE"
    assert _resolve_damage_region_status("BOGUS_STATUS", False) == "UNRECOVERABLE"

    # 2. Absent / None status
    assert _resolve_damage_region_status(None, True) == "UNRECOVERABLE"
    assert _resolve_damage_region_status(None, False) == "UNRECOVERABLE"

    # 3. Empty status
    assert _resolve_damage_region_status("", True) == "UNRECOVERABLE"

    # 4. Legitimate RECONSTRUCTABLE translates properly
    assert _resolve_damage_region_status("RECONSTRUCTABLE", True) == "RECONSTRUCTED"
    assert _resolve_damage_region_status("RECONSTRUCTABLE", False) == "UNRECOVERABLE"

    # 5. Legitimate terminal statuses preserved
    assert _resolve_damage_region_status("UNRECOVERABLE", True) == "UNRECOVERABLE"
    assert _resolve_damage_region_status("RECONSTRUCTED", True) == "RECONSTRUCTED"
    assert _resolve_damage_region_status("UNRESOLVED", True) == "UNRESOLVED"
    assert _resolve_damage_region_status("DETECTED", True) == "DETECTED"
