"""
test_json_recovery.py — Test suite for deterministic JSON Recovery.

Covers the required recovery cases:
  A. Intact JSON: full recovery, byte-exact, no reconstruction.
  B. Truncated but deterministically closable JSON: structural repair, R > 0,
     status is never FULLY_RECOVERED.
  C. Unknown missing content: no invented property/value, explicit M accounting,
     ambiguity preserved.
  D. Malformed / non-JSON evidence: safe rejection, never reinterpreted.
  E. Accounting identity: V + R + M == artifact budget; V + M == evidence size.
  F. No-FULLY rule: FULLY_RECOVERED only when R == 0 and M == 0.
  G. API surface: status, byte accounting, method, download, and safety.
  H. Detection: a .json artifact is never relabelled CSV/TXT.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.store import store
from backend.app.recovery.reconstructors.json import reconstruct_json
from backend.app.recovery.reconstruction import reconstruct_artifact
from backend.app.recovery.scanner import scan_evidence
from backend.app.recovery.tracer import execute_traced_recovery, execute_traced_recoveries

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    store.clear()
    yield
    store.clear()


# Canonical fixture (valid, moderately nested JSON).
FULL_JSON = (
    b'{"case":"recoverix","id":42,"tags":["a","b"],'
    b'"nested":{"k":"v","list":[1,2,3]}}'
)


def _acct(result):
    return result.verified_bytes + result.reconstructed_bytes + result.missing_bytes


# ── Case A: Intact JSON ─────────────────────────────────────────────

def test_a_intact_json_is_byte_exact_and_full():
    r = reconstruct_json(FULL_JSON)
    assert r.status == "FULLY_RECOVERED"
    assert r.success is True
    assert r.recovered_bytes == FULL_JSON
    assert r.verified_bytes == len(FULL_JSON)
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == 0
    # No ground truth was supplied, so the exact-match diagnostic stays unset:
    # the reconstruction never consulted an expected output.
    assert r.is_exact_match is None
    assert r.details["reconstruction_method"] == "JSON_STRUCTURAL_VALIDATION"
    # Output parses as JSON.
    json.loads(r.recovered_bytes)


def test_a_intact_json_via_dispatch():
    r = reconstruct_artifact("json", FULL_JSON)
    assert r.status == "FULLY_RECOVERED"
    assert r.recovered_bytes == FULL_JSON


# ── Case B: Deterministically closable truncation ───────────────────

def test_b_closable_prefix_appends_only_forced_closers():
    evidence = b'{"a":1,"b":[1,2,3'
    r = reconstruct_json(evidence)
    assert r.status == "PARTIALLY_RECOVERED"
    # The added bytes are exactly the forced closing sequence, nothing more.
    assert r.recovered_bytes == evidence + b"]}"
    assert r.details["appended_closers"] == "]}"
    assert r.reconstructed_bytes == len(b"]}")
    assert r.verified_bytes == len(evidence)
    assert r.missing_bytes == 0
    # The reconstruction yields valid JSON.
    assert json.loads(r.recovered_bytes) == {"a": 1, "b": [1, 2, 3]}
    # Structural reconstruction must not be reported as full recovery.
    assert r.status != "FULLY_RECOVERED"


def test_b_nested_closable_prefix():
    evidence = b'{"a":{"b":[1,2'
    r = reconstruct_json(evidence)
    assert r.status == "PARTIALLY_RECOVERED"
    # Stack is {,[,{ -> closers are emitted innermost-first: ]}}
    assert r.recovered_bytes == evidence + b"]}}"
    assert r.details["appended_closers"] == "]}}"
    assert r.reconstructed_bytes == 3
    json.loads(r.recovered_bytes)


def test_b_trailing_number_is_complete_not_truncated():
    # The trailing "12" is a whole value; the only deficiency is the closer.
    r = reconstruct_json(b'{"a":1.5,"b":12')
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.details["reconstruction_method"] == "JSON_STRUCTURAL_CLOSURE"
    assert r.reconstructed_bytes == 1
    assert json.loads(r.recovered_bytes) == {"a": 1.5, "b": 12}


# ── Case C: Unknown missing content (never invented) ────────────────

@pytest.mark.parametrize(
    "evidence, reason_fragment",
    [
        (b'{"a":1,"b":', "value"),
        (b'{"a":1,', "object body"),
        (b'{"ok":true,"x":tru', "literal"),
    ],
)
def test_c_unknown_content_is_not_invented(evidence, reason_fragment):
    r = reconstruct_json(evidence)
    # Never FULLY: something is unresolved.
    assert r.status != "FULLY_RECOVERED"
    # Explicit missing accounting: the unresolved tail is reported, not guessed.
    assert r.missing_bytes > 0
    # The verified prefix is preserved as-is; no structural bytes invented.
    assert r.reconstructed_bytes == 0
    assert r.recovered_bytes == evidence[: len(evidence) - r.missing_bytes]
    # Refusal is explained.
    assert r.details["reconstruction_method"] == "JSON_UNRESOLVED_CONTENT"
    assert "notice" in r.details
    assert reason_fragment in r.details["prefix_reason"] or reason_fragment in r.details["refused"]


def test_c_open_brace_only_is_unrecoverable_not_invented():
    # "{" alone is consistent with "{}" and with '{"a":1}'; do not pick one.
    r = reconstruct_json(b"{")
    assert r.status == "UNRECOVERABLE"
    assert r.recovered_bytes == b""
    assert r.verified_bytes == 0
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == 1


# ── Case D: Malformed / non-JSON evidence ───────────────────────────

@pytest.mark.parametrize(
    "data",
    [
        b"this is not json at all!!",
        b"{invalid json here",
        b"\xff\xfe\x00binary\x00",
    ],
)
def test_d_malformed_json_rejected_safely(data):
    r = reconstruct_json(data)
    assert r.status == "UNRECOVERABLE"
    assert r.success is False
    assert r.recovered_bytes == b""
    assert r.reconstructed_bytes == 0
    # Every evidence byte is accounted as missing (or as invalid), never guessed.
    assert r.verified_bytes + r.missing_bytes == len(data)


def test_d_empty_evidence():
    r = reconstruct_json(b"")
    assert r.status == "UNRECOVERABLE"
    assert r.recovered_bytes == b""


# ── Case E: Accounting identity ─────────────────────────────────────

@pytest.mark.parametrize(
    "evidence",
    [
        FULL_JSON,
        b'{"a":1,"b":[1,2,3',
        b'{"a":{"b":[1,2',
        b'{"a":1,"b":',
        b'{"a":1,',
        b'{"ok":true,"x":tru',
        b"{",
        b"not json",
        b"",
    ],
)
def test_e_accounting_identities_hold(evidence):
    r = reconstruct_json(evidence)
    emitted = len(r.recovered_bytes)
    # Every emitted byte is either verified evidence or structural repair.
    assert r.verified_bytes + r.reconstructed_bytes == emitted
    # Every input byte is either emitted as verified evidence or dropped missing.
    assert r.verified_bytes + r.missing_bytes == len(evidence)
    # The three-way artifact budget.
    assert _acct(r) == emitted + r.missing_bytes


# ── Case F: FULLY_RECOVERED only when nothing reconstructed/missing ──

@pytest.mark.parametrize(
    "evidence",
    [
        FULL_JSON,
        b'{"a":1,"b":[1,2,3',
        b'{"a":{"b":[1,2',
        b'{"a":1,"b":',
        b'{"a":1,',
        b"{",
        b"not json",
    ],
)
def test_f_full_recovery_never_overclaims(evidence):
    r = reconstruct_json(evidence)
    if r.reconstructed_bytes > 0 or r.missing_bytes > 0:
        assert r.status != "FULLY_RECOVERED"


# ── Case G: Tracer / API surface ────────────────────────────────────

def test_g_tracer_closable_json_status_and_method():
    evidence = b'{"a":1,"b":[1,2,3'
    run = execute_traced_recovery(filename="evidence.json", content=evidence)
    assert run.format == "json"
    assert run.status == "PARTIALLY_RECOVERED"
    assert run.total_reconstructed_bytes == 2
    assert run.total_missing_bytes == 0
    # The artifact budget identity holds at the run level.
    assert run.total_input_bytes == (
        run.total_verified_bytes
        + run.total_reconstructed_bytes
        + run.total_missing_bytes
    )
    # The method explicitly identifies JSON structural reconstruction.
    assert "JSON" in run.provenance["reconstruction_method"]
    # Provenance records the actual uploaded evidence size.
    assert run.provenance["evidence_size"] == len(evidence)


def test_g_tracer_intact_json_is_full_and_exact():
    run = execute_traced_recovery(filename="evidence.json", content=FULL_JSON)
    assert run.format == "json"
    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(FULL_JSON)
    assert run.total_reconstructed_bytes == 0
    assert run.total_missing_bytes == 0
    assert run.total_input_bytes == len(FULL_JSON)


def test_g_tracer_malformed_json_is_unrecoverable():
    run = execute_traced_recovery(filename="evidence.json", content=b"not json at all")
    assert run.format == "json"
    assert run.status == "UNRECOVERABLE"
    assert run.total_verified_bytes == 0
    assert run.total_reconstructed_bytes == 0
    assert run.total_missing_bytes == len(b"not json at all")


def test_g_api_closable_json_reports_partial_and_downloadable():
    evidence = b'{"a":1,"b":[1,2,3'
    response = client.post(
        "/api/recover-file",
        files={"file": ("evidence.json", evidence, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "json"
    assert data["status"] == "PARTIALLY_RECOVERED"
    # Structural reconstruction present and honestly reported.
    assert data["reconstructed_bytes"] == 2
    assert data["missing_bytes"] == 0
    assert "JSON" in data["reconstruction_method"]
    # Not falsely full.
    assert data["status"] != "FULLY_RECOVERED"
    assert data["is_downloadable"] is True


def test_g_api_closable_json_download_is_valid():
    evidence = b'{"a":1,"b":[1,2,3'
    response = client.post(
        "/api/recover-file",
        files={"file": ("evidence.json", evidence, "application/json")},
    )
    download_url = response.json()["download_url"]
    dl = client.get(download_url)
    assert dl.status_code == 200
    downloaded = dl.content
    assert downloaded == evidence + b"]}"
    # The recovered download is genuinely valid JSON.
    assert json.loads(downloaded) == {"a": 1, "b": [1, 2, 3]}


def test_g_api_unknown_content_reports_missing_and_not_full():
    evidence = b'{"a":1,"b":'
    response = client.post(
        "/api/recover-file",
        files={"file": ("evidence.json", evidence, "application/json")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == "json"
    assert data["status"] != "FULLY_RECOVERED"
    assert data["missing_bytes"] > 0
    assert data["reconstructed_bytes"] == 0


# ── Case H: A .json artifact is never relabelled CSV/TXT ─────────────

@pytest.mark.parametrize(
    "evidence",
    [
        b'{"a":1,"b":[1,2,3',
        b'{"a":1,"b":',
        b"not json at all",
    ],
)
def test_h_json_is_never_reinterpreted_as_other_formats(evidence):
    run = execute_traced_recovery(filename="evidence.json", content=evidence)
    # The run stays JSON regardless of what other validators might accept.
    assert run.format == "json"
    # Pass-through mislabeling would show V=R=len(content); we never do that.
    assert not (
        run.total_verified_bytes == len(evidence)
        and run.total_reconstructed_bytes == len(evidence)
    )


# ── JSON Scanner Boundary Integrity Milestone Tests ───────────────────────

def test_case1_complete_json_object_followed_by_nul_padding():
    payload = b'{"status": "ok", "count": 42}'
    evidence = payload + (b"\x00" * 32)
    # 1. Scanner finds exact boundary at closing '}'
    candidates = scan_evidence(evidence)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.format == "json"
    assert cand.offset == 0
    assert cand.estimated_end_offset == len(payload)

    # 2. Direct reconstruct_json accounts trailing NULs as missing/padding
    r = reconstruct_json(evidence)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.recovered_bytes == payload
    assert r.verified_bytes == len(payload)
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == 32
    assert any(d["type"] == "UNATTRIBUTED_PADDING" for d in r.damage_regions)

    # 3. Traced recovery correctly isolates candidate and fully recovers without fabricating missing bytes
    runs = execute_traced_recoveries("obj_nul.img", evidence)
    assert len(runs) == 1
    run = runs[0]
    assert run.status == "FULLY_RECOVERED"
    assert run.fragments[0].verified_bytes == len(payload)
    assert run.fragments[0].reconstructed_bytes == 0
    assert run.fragments[0].missing_bytes == 0


def test_case2_complete_json_array_followed_by_nul_padding():
    payload = b'[1, 2, "three", true, null]'
    evidence = payload + (b"\x00" * 48)
    candidates = scan_evidence(evidence)
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.format == "json"
    assert cand.offset == 0
    assert cand.estimated_end_offset == len(payload)

    r = reconstruct_json(evidence)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.recovered_bytes == payload
    assert r.verified_bytes == len(payload)
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == 48

    runs = execute_traced_recoveries("arr_nul.img", evidence)
    assert len(runs) == 1
    run = runs[0]
    assert run.status == "FULLY_RECOVERED"
    assert run.fragments[0].verified_bytes == len(payload)
    assert run.fragments[0].reconstructed_bytes == 0
    assert run.fragments[0].missing_bytes == 0


def test_case3_json_number_followed_by_valid_delimiter():
    cases = [
        (b'{"a": 100, "b": 200}', {"a": 100, "b": 200}),
        (b'{"a": 100}', {"a": 100}),
        (b'[100, 200]', [100, 200]),
        (b'[100]', [100]),
        (b'{"a": 100 \t\r\n}', {"a": 100}),
    ]
    for evidence, expected_json in cases:
        cands = scan_evidence(evidence)
        assert len(cands) == 1
        assert cands[0].format == "json"
        assert cands[0].estimated_end_offset == len(evidence.rstrip(b" \t\r\n")) or cands[0].estimated_end_offset == len(evidence)
        r = reconstruct_json(evidence)
        assert r.status == "FULLY_RECOVERED"
        assert json.loads(r.recovered_bytes) == expected_json


def test_case4_complete_json_number_at_candidate_boundary():
    surviving = b'{"port": 8080'
    evidence = surviving + (b"\x00" * 16)
    # 1. Scanner finds truncated candidate
    cands = scan_evidence(evidence)
    assert len(cands) == 1
    assert cands[0].format == "json"
    assert cands[0].estimated_end_offset is None

    # 2. Reconstructor appends deterministic closer '}' and attributes NULs as missing
    r = reconstruct_json(evidence)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.recovered_bytes == b'{"port": 8080}'
    assert r.verified_bytes == len(surviving)
    assert r.reconstructed_bytes == 1
    assert r.missing_bytes == 16
    assert json.loads(r.recovered_bytes) == {"port": 8080}

    # 3. Traced recovery produces valid closed JSON
    runs = execute_traced_recoveries("port_nul.img", evidence)
    assert len(runs) == 1
    assert runs[0].status == "PARTIALLY_RECOVERED"
    assert bytes.fromhex(runs[0].output["recovered_bytes"]) == b'{"port": 8080}'


def test_case5_number_token_genuinely_truncated_at_eof():
    cases = [
        b'{"val": 12.',
        b'{"val": -',
        b'{"val": 1e',
        b'{"val": 1e+',
    ]
    for evidence in cases:
        r = reconstruct_json(evidence)
        # Cannot be FULLY_RECOVERED or closable because the number token is incomplete
        assert r.status in ("PARTIALLY_RECOVERED", "UNRECOVERABLE")
        # No number digits or closing braces fabricated
        assert r.reconstructed_bytes == 0
        assert r.missing_bytes > 0
        assert not r.recovered_bytes.endswith(b"}")


def test_case6_invalid_number_leading_zero_forbidden():
    invalid_numbers = [
        b'{"val": 01}',
        b'{"val": -01}',
        b'{"val": 00}',
        b'{"val": -007}',
    ]
    for evidence in invalid_numbers:
        # Scanner rejects forbidden numbers
        cands = scan_evidence(evidence)
        assert len(cands) == 0

        # Reconstructor marks unrecoverable
        r = reconstruct_json(evidence)
        assert r.status == "UNRECOVERABLE"
        assert r.success is False
        assert r.verified_bytes == 0

    # Ensure valid zero forms are accepted
    valid_zeros = [
        (b'{"val": 0}', {"val": 0}),
        (b'{"val": 0.5}', {"val": 0.5}),
        (b'{"val": -0}', {"val": 0}),
    ]
    for evidence, expected_json in valid_zeros:
        cands = scan_evidence(evidence)
        assert len(cands) == 1
        r = reconstruct_json(evidence)
        assert r.status == "FULLY_RECOVERED"
        assert json.loads(r.recovered_bytes) == expected_json


def test_case7_nul_bytes_within_invalid_context():
    invalid_nul_cases = [
        b'{"port": \x00 8080}',
        b'{"port": 80\x0080}',
        b'{"po\x00rt": 8080}',
        b'{"port": 8080}\x00{"extra": 1}',
    ]
    for evidence in invalid_nul_cases:
        # Embedded corrupt NULs are rejected
        r = reconstruct_json(evidence)
        assert r.status in ("UNRECOVERABLE", "CORRUPTED")
        assert r.status != "FULLY_RECOVERED"


def test_case8_candidate_with_ambiguous_boundary():
    # Two truncated containers separated by padding
    evidence = b'{"cand1": 10' + (b"\x00" * 32) + b'{"cand2": 20' + (b"\x00" * 32)
    cands = scan_evidence(evidence)
    # Both independent candidates discovered
    assert len(cands) >= 2
    assert all(c.format == "json" for c in cands)

    runs = execute_traced_recoveries("ambig.img", evidence)
    assert len(runs) >= 2
    for run in runs:
        assert run.status == "PARTIALLY_RECOVERED"
        assert run.format == "json"


def test_case9_complete_marker_free_json_embedded_in_unrelated_padding():
    payload = b'{"config": "production", "retries": 3}'
    prefix = b"\xaa" * 128
    suffix = b"\x00" * 128
    evidence = prefix + payload + suffix

    cands = scan_evidence(evidence)
    assert len(cands) == 1
    cand = cands[0]
    assert cand.format == "json"
    assert cand.offset == len(prefix)
    assert cand.estimated_end_offset == len(prefix) + len(payload)

    runs = execute_traced_recoveries("embedded.img", evidence)
    assert len(runs) == 1
    run = runs[0]
    assert run.status == "FULLY_RECOVERED"
    assert bytes.fromhex(run.output["recovered_bytes"]) == payload
    assert run.fragments[0].verified_bytes == len(payload)
    assert run.fragments[0].reconstructed_bytes == 0
    assert run.fragments[0].missing_bytes == 0


def test_case10_candidate_boundary_handling_not_fabricating_missing_bytes():
    payload = b'{"items": [1, 2, 3], "total": 6}'
    evidence = payload + (b"\x00" * 256)

    # Scanner bounds candidate at closing brace, not at EOF
    cands = scan_evidence(evidence)
    assert len(cands) == 1
    assert cands[0].offset == 0
    assert cands[0].estimated_end_offset == len(payload)

    # Production recovery pipeline evaluates only the bounded candidate span
    runs = execute_traced_recoveries("bounds.img", evidence)
    assert len(runs) == 1
    run = runs[0]
    assert run.status == "FULLY_RECOVERED"
    assert run.fragments[0].verified_bytes == len(payload)
    assert run.fragments[0].reconstructed_bytes == 0
    # ZERO missing bytes fabricated for the external 256 padding bytes
    assert run.fragments[0].missing_bytes == 0
    assert bytes.fromhex(run.output["recovered_bytes"]) == payload


def test_case11_ambiguous_truncated_number_against_ground_truth():
    """Ambiguous truncated integer (e.g. 80 vs 8080) does not falsely claim byte-exact match."""
    orig = b'{"port": 8080}'
    surviving = b'{"port": 80'
    r = reconstruct_json(surviving, original_data=orig)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.status != "FULLY_RECOVERED"
    assert r.recovered_bytes == b'{"port": 80}'
    # Digits are not guessed or fabricated
    assert b"8080" not in r.recovered_bytes
    assert r.verified_bytes == len(surviving)
    assert r.reconstructed_bytes == 1  # only '}'
    assert r.missing_bytes == 0
    # Diagnostic reflects honest hash mismatch against ground truth
    assert r.is_exact_match is False


def test_case12_nested_arrays_and_objects_containing_numbers():
    """Deeply nested containers with floating point, negative, and zero numbers."""
    payload = b'{"matrix": [[1, -2], [3.5, -0.25]], "stats": {"zero": 0, "neg_zero": -0}}'
    cands = scan_evidence(payload)
    assert len(cands) == 1
    assert cands[0].offset == 0
    assert cands[0].estimated_end_offset == len(payload)

    r = reconstruct_json(payload)
    assert r.status == "FULLY_RECOVERED"
    assert r.recovered_bytes == payload
    assert r.verified_bytes == len(payload)
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == 0


def test_case13_reconstructor_and_evaluator_idempotence():
    """Repeated calls do not mutate state, inputs, or subsequent outputs."""
    evidence = b'{"items": [1, 2, 3'
    r1 = reconstruct_json(evidence)
    r2 = reconstruct_json(evidence)

    assert r1.status == r2.status == "PARTIALLY_RECOVERED"
    assert r1.recovered_bytes == r2.recovered_bytes == b'{"items": [1, 2, 3]}'
    assert r1.verified_bytes == r2.verified_bytes == len(evidence)
    assert r1.reconstructed_bytes == r2.reconstructed_bytes == 2
    assert r1.missing_bytes == r2.missing_bytes == 0
    assert r1.damage_regions == r2.damage_regions


# ══════════════════════════════════════════════════════════════════════════════
# Milestone 3 — JSON Content-Loss Accounting Regression Tests
# ══════════════════════════════════════════════════════════════════════════════

def test_m3_1_closable_json_prefix_no_known_physical_gap():
    """1. A closable JSON prefix with no known physical gap."""
    evidence = b'{"service": "auth", "port": 8080, "roles": ["admin"'
    r = reconstruct_json(evidence)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.status != "FULLY_RECOVERED"
    assert r.verified_bytes == len(evidence)
    assert r.reconstructed_bytes == 2  # appended ']}'
    assert r.missing_bytes == 0  # no gap present in evidence
    assert r.recovered_bytes == b'{"service": "auth", "port": 8080, "roles": ["admin"]}'
    parsed = json.loads(r.recovered_bytes)
    assert parsed["roles"] == ["admin"]
    assert len(r.damage_regions) == 1
    assert r.damage_regions[0]["type"] == "MISSING_STRUCTURAL_CLOSURE"


def test_m3_2_json_candidate_with_observed_known_length_missing_region():
    """2. A JSON candidate with an observed, known-length missing region (padding)."""
    clean_prefix = b'{"status": "ok", "tags": [1, 2'
    padding = b"\x00" * 32
    evidence = clean_prefix + padding

    r = reconstruct_json(evidence)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.verified_bytes == len(clean_prefix)
    assert r.reconstructed_bytes == 2  # ']}'
    assert r.missing_bytes == 32  # observed trailing padding accounted as missing
    assert r.verified_bytes + r.missing_bytes == len(evidence)

    # Damage regions contain structural closure and unrecoverable padding
    padding_dmgs = [d for d in r.damage_regions if d["type"] == "UNATTRIBUTED_PADDING"]
    assert len(padding_dmgs) == 1
    assert padding_dmgs[0]["length"] == 32
    assert padding_dmgs[0]["status"] == "UNRECOVERABLE"

    # Verify through tracer: UNRECOVERABLE status is preserved and not clobbered
    runs = execute_traced_recoveries("observed_gap.img", evidence)
    assert len(runs) >= 1
    run = runs[0]
    unrec_dmgs = [d for d in run.damage_regions if d.status == "UNRECOVERABLE"]
    assert len(unrec_dmgs) == 1
    assert unrec_dmgs[0].length == 32

    # Verify benchmark observation maps padding to MISSING segment, NOT RECONSTRUCTED
    from benchmark.run_baseline import run_pipeline_and_observe
    obs_manifest = run_pipeline_and_observe("observed_gap.img", evidence)
    rec = obs_manifest.recoveries[0]
    assert rec.total_verified_bytes == len(clean_prefix)
    assert rec.total_reconstructed_bytes == 2
    assert rec.total_missing_bytes == 32
    assert len(rec.missing_segments) == 1
    assert rec.missing_segments[0].evidence_start == len(clean_prefix)
    assert rec.missing_segments[0].evidence_end == len(evidence)

    # Deliberate status resolution: verify that arbitrary/unrecognized strings are not passed through
    from backend.app.recovery.tracer import _resolve_damage_region_status
    assert _resolve_damage_region_status("UNRECOVERABLE", True) == "UNRECOVERABLE"
    assert _resolve_damage_region_status("UNRECOVERABLE", False) == "UNRECOVERABLE"
    assert _resolve_damage_region_status("RECONSTRUCTED", True) == "RECONSTRUCTED"
    assert _resolve_damage_region_status("UNRESOLVED", True) == "UNRESOLVED"
    assert _resolve_damage_region_status("DETECTED", True) == "DETECTED"
    assert _resolve_damage_region_status("RECONSTRUCTABLE", True) == "RECONSTRUCTED"
    assert _resolve_damage_region_status("RECONSTRUCTABLE", False) == "UNRECOVERABLE"
    # Conservative fallback: artifact-level success never implies an unstated damage region was reconstructed
    assert _resolve_damage_region_status(None, True) == "UNRECOVERABLE"
    assert _resolve_damage_region_status(None, False) == "UNRECOVERABLE"
    assert _resolve_damage_region_status("", True) == "UNRECOVERABLE"
    assert _resolve_damage_region_status("INVALID_STATUS", True) == "UNRECOVERABLE"
    assert _resolve_damage_region_status("INVALID_STATUS", False) == "UNRECOVERABLE"


def test_m3_3_json_candidate_with_possible_gap_exact_size_unknown():
    """3. A JSON candidate with a possible gap whose exact size is unknown from evidence."""
    orig = b'{"readings": [1, 2, 3, 4, 5]}'
    surviving = b'{"readings": [1, 2'  # Truncated at EOF, missing 11 original bytes

    # Engine must NOT invent or guess missing bytes from thin air
    r = reconstruct_json(surviving, original_data=orig)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.verified_bytes == len(surviving)
    assert r.reconstructed_bytes == 2  # ']}'
    assert r.missing_bytes == 0  # cannot prove 11 bytes were lost from evidence alone
    assert r.is_exact_match is False

    # Independent benchmark evaluator detects UNACCOUNTED_GAP
    from benchmark.json_benchmark import build_truncated_closable_content_loss_scenario, evaluate_json_scenario
    gt_manifest, evidence_bytes = build_truncated_closable_content_loss_scenario(seed=42)
    eval_res = evaluate_json_scenario(gt_manifest, evidence_bytes)
    assert eval_res["passed"] is False
    assert any("UNACCOUNTED_GAP" in v for v in eval_res["forensic_violations"])


def test_m3_4_structural_closure_with_genuinely_missing_original_content():
    """4. Structural closure with genuinely missing original content."""
    orig = b'{"user": "alice", "items": ["item1", "item2", "item3"]}'
    surviving = b'{"user": "alice", "items": ["item1"'

    r = reconstruct_json(surviving, original_data=orig)
    assert r.status == "PARTIALLY_RECOVERED"
    assert r.status != "FULLY_RECOVERED"
    assert r.recovered_bytes == b'{"user": "alice", "items": ["item1"]}'

    # Syntactically valid JSON
    parsed = json.loads(r.recovered_bytes)
    assert parsed["user"] == "alice"
    assert parsed["items"] == ["item1"]

    # Original content 'item2' and 'item3' are permanently missing
    assert b"item2" not in r.recovered_bytes
    assert b"item3" not in r.recovered_bytes
    assert r.is_exact_match is False
    assert hashlib.sha256(r.recovered_bytes).hexdigest() != hashlib.sha256(orig).hexdigest()
    assert r.details["output_sha256"] != hashlib.sha256(orig).hexdigest()


def test_m3_5_incomplete_tokens_no_fabrication():
    """5. Incomplete tokens where content must not be fabricated."""
    # Case A: Incomplete number token
    r_num = reconstruct_json(b'{"ratio": 3.')
    assert r_num.success is False
    assert r_num.reconstructed_bytes == 0
    assert r_num.status in ("UNRECOVERABLE", "PARTIALLY_RECOVERED")

    # Case B: Unterminated member string
    r_str = reconstruct_json(b'{"incomplete_key')
    assert r_str.success is False
    assert r_str.reconstructed_bytes == 0

    # Case C: Truncated literal
    r_lit = reconstruct_json(b'{"active": tr')
    assert r_lit.success is False
    assert r_lit.reconstructed_bytes == 0


def test_m3_6_correct_separation_v_r_m_u():
    """6. Correct separation of V, R, M, and unresolved uncertainty."""
    # Case A: Complete JSON with trailing padding
    ev_complete = b'{"key": "val"}' + (b"\x00" * 10)
    r1 = reconstruct_json(ev_complete)
    assert r1.verified_bytes + r1.missing_bytes == len(ev_complete)
    assert r1.verified_bytes + r1.reconstructed_bytes == len(r1.recovered_bytes)
    assert r1.reconstructed_bytes == 0
    assert r1.missing_bytes == 10

    # Case B: Closable JSON with trailing padding
    ev_closable = b'{"key": "val"' + (b"\x00" * 10)
    r2 = reconstruct_json(ev_closable)
    assert r2.verified_bytes + r2.missing_bytes == len(ev_closable)
    assert r2.verified_bytes + r2.reconstructed_bytes == len(r2.recovered_bytes)
    assert r2.reconstructed_bytes == 1  # '}'
    assert r2.missing_bytes == 10

    # Case C: Truncated at EOF (uncertainty U)
    ev_eof = b'{"key": "val"'
    r3 = reconstruct_json(ev_eof)
    # Conservation holds on evidence coordinates
    assert r3.verified_bytes + r3.missing_bytes == len(ev_eof)
    assert r3.verified_bytes + r3.reconstructed_bytes == len(r3.recovered_bytes)
    # Uncertainty is not fabricated into M
    assert r3.missing_bytes == 0


def test_m3_7_correct_recovery_status_invariants():
    """7. Correct recovery status invariants."""
    # FULLY_RECOVERED requires valid JSON, R == 0, and M == 0
    r_clean = reconstruct_json(b'{"status": "ok"}')
    assert r_clean.status == "FULLY_RECOVERED"
    assert r_clean.reconstructed_bytes == 0
    assert r_clean.missing_bytes == 0

    # PARTIALLY_RECOVERED if R > 0
    r_closable = reconstruct_json(b'{"status": "ok"')
    assert r_closable.status == "PARTIALLY_RECOVERED"
    assert r_closable.status != "FULLY_RECOVERED"

    # PARTIALLY_RECOVERED if M > 0
    r_padded = reconstruct_json(b'{"status": "ok"}' + (b"\x00" * 8))
    assert r_padded.status == "PARTIALLY_RECOVERED"
    assert r_padded.status != "FULLY_RECOVERED"

    # UNRECOVERABLE if noise
    r_noise = reconstruct_json(b'{malformed-not-json')
    assert r_noise.status == "UNRECOVERABLE"
    assert r_noise.status != "FULLY_RECOVERED"


def test_m3_8_independent_evaluator_unaccounted_gap_detection():
    """8. Independent evaluator detection of content-loss accounting gap."""
    import hashlib
    from benchmark.json_benchmark import (
        build_truncated_closable_content_loss_scenario,
        build_truncated_closable_pure_scenario,
        evaluate_json_scenario,
    )

    # Content-loss scenario: gap is detected by benchmark evaluator
    gt_cl, ev_cl = build_truncated_closable_content_loss_scenario(seed=42)
    res_cl = evaluate_json_scenario(gt_cl, ev_cl)
    assert res_cl["passed"] is False
    assert any("UNACCOUNTED_GAP" in v for v in res_cl["forensic_violations"])

    # Pure delimiter scenario: closes deterministically with 0 violations
    gt_pure, ev_pure = build_truncated_closable_pure_scenario(seed=42)
    res_pure = evaluate_json_scenario(gt_pure, ev_pure)
    assert res_pure["passed"] is True
    assert len(res_pure["forensic_violations"]) == 0


def test_m5_json_syntax_corruption_accounting():
    """Verify that candidate-level syntax corruption (e.g. unescaped NUL in string)
    is accounted with verified_bytes=0, missing_bytes=len(data), status=CORRUPTED,
    and a distinct CORRUPTED damage region with status UNRECOVERABLE.
    """
    corrupt_evidence = b'{"user": "alice", "bio": "developer \x00 admin", "active": true}'
    r = reconstruct_json(corrupt_evidence)

    assert r.status == "CORRUPTED"
    assert r.success is False
    assert r.verified_bytes == 0
    assert r.reconstructed_bytes == 0
    assert r.missing_bytes == len(corrupt_evidence)
    # Conservation invariant: V + R + M == len(input)
    assert r.verified_bytes + r.reconstructed_bytes + r.missing_bytes == len(corrupt_evidence)
    assert len(r.damage_regions) == 1
    dmg = r.damage_regions[0]
    assert dmg["type"] == "CORRUPTED"
    assert dmg["status"] == "UNRECOVERABLE"
    assert dmg["offset"] == 0
    assert dmg["length"] == len(corrupt_evidence)
