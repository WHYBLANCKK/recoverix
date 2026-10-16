"""
test_fragment_pipeline.py — Milestone tests for the evidence-only TXT/CSV
fragment detection -> relationship -> bounded reconstruction -> accounting path.

Ground-truth data (FragmentCase / manifest / DamageScenario) is used ONLY inside
this test module to build evidence and to score results. The recovery engine must
never consult it, which is asserted by test_13_no_ground_truth_dependency.
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.store import store
from backend.app.generator.fragment_generator import (
    STANDARD_FIXTURES,
    generate_fragment_case,
)
from backend.app.recovery.fragment_detector import (
    MIN_FRAGMENT_BYTES,
    detect_text_fragments,
)
from backend.app.recovery.relationship import (
    MAX_GAP,
    MIN_GAP,
    assess_fragment_pair,
    select_fragment_pairs,
)
from backend.app.recovery.reconstruction import (
    reconstruct_artifact,
    reconstruct_fragment_pair,
    reconstruct_text,
)
from backend.app.recovery.bifragment import reconstruct_bifragment
from backend.app.recovery.validators.text import validate_txt
from backend.app.recovery.tracer import execute_traced_recovery

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_store():
    store.clear()
    yield
    store.clear()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

SEP = b"\x00"  # non-artifact separator bytes standing in for surrounding data


def sparse_evidence(original: bytes, first_len: int, gap_len: int) -> bytes:
    """Build evidence holding A, a run of unrelated non-text bytes, then B.

    The original artifact bytes in the gap are genuinely absent. The separator is
    unrelated data that occupies the same offsets; it is never emitted as output
    and never claimed as recovered artifact content.
    """
    return original[:first_len] + SEP * gap_len + original[first_len + gap_len :]


def build_sparse_case(fmt: str, filename: str, first_len: int, gap_len: int, seed: int = 42):
    fn, original = STANDARD_FIXTURES[fmt]
    case = generate_fragment_case(
        original, fmt=fmt, seed=seed, scenario="fragmented", original_filename=filename
    )
    return fn, original, sparse_evidence(original, first_len, gap_len), case


# ---------------------------------------------------------------------------
# 1-2. TXT / CSV detection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,first_len,gap_len", [("txt", 24, 209), ("csv", 233, 57)])
def test_01_detects_two_fragments_with_real_boundary_evidence(fmt, first_len, gap_len):
    _, original, evidence, _ = build_sparse_case(fmt, f"sample.{fmt}", first_len, gap_len)
    frags = detect_text_fragments(evidence, fmt)

    assert len(frags) == 2, [f.offset for f in frags]
    a, b = frags
    b_off = first_len + gap_len
    assert (a.offset, a.length) == (0, first_len)
    assert (b.offset, b.length) == (b_off, len(original) - b_off)
    assert a.data == original[:first_len]
    assert b.data == original[b_off:]
    # The real gap bytes are absent; only unrelated separator data is present.
    assert original[first_len:b_off] not in evidence


def test_02_physically_adjacent_text_is_not_invented_into_two_fragments():
    """A, then B with no boundary evidence is one text run. No seam is fabricated."""
    _, original = STANDARD_FIXTURES["txt"]
    a = original[:24]
    b = original[233:292]
    assert a.endswith(b"\n")

    frags = detect_text_fragments(a + b, "txt")
    assert len(frags) == 1, "a physically absent seam is undetectable from evidence alone"
    assert frags[0].data == a + b


def test_03_detector_ignores_sub_minimum_noise_runs():
    frags = detect_text_fragments(b"\x01\x02\x03" + SEP * 10 + b"abc", "txt")
    assert all(f.length >= MIN_FRAGMENT_BYTES for f in frags)


def test_04_detector_accepts_single_line_file_without_trailing_newline():
    content = b"Simple intact plain text file content for forensic testing."
    frags = detect_text_fragments(content, "txt")
    assert len(frags) == 1
    assert frags[0].data == content
    assert frags[0].ends_with_newline is False
    assert frags[0].is_truncated is True


# ---------------------------------------------------------------------------
# 5-8. relationship
# ---------------------------------------------------------------------------

def test_05_same_format_ordered_bounded_gap_is_joinable():
    _, _, evidence, _ = build_sparse_case("txt", "sample.txt", 24, 209)
    a, b = detect_text_fragments(evidence, "txt")
    rel = assess_fragment_pair(a, b)
    assert rel.is_joinable is True
    assert rel.observed_gap == 209
    assert rel.relationship_type == "BOUNDED_GAP"


def test_06_gap_beyond_maximum_is_not_joinable():
    assert (MIN_GAP, MAX_GAP) == (1, 4096)
    _, original = STANDARD_FIXTURES["txt"]
    far = original[:24] + SEP * 5000 + original[233:]
    frags = detect_text_fragments(far, "txt")
    assert len(frags) == 2
    rel = assess_fragment_pair(frags[0], frags[1])
    assert rel.observed_gap > MAX_GAP
    assert rel.is_joinable is False
    assert select_fragment_pairs(frags) == []


def test_07_csv_schema_mismatch_is_rejected():
    _, original = STANDARD_FIXTURES["csv"]
    header = original[: original.find(b"\n") + 1]
    # fragment A: header plus one well-formed row
    row_a = original[len(header) : original.find(b"\n", len(header)) + 1]
    # fragment B: a row with the wrong number of fields
    row_b = b"999,only-one-column\n"
    a = detect_text_fragments(header + row_a, "csv")[0]
    b = detect_text_fragments(row_b, "csv")[0]
    assert a.column_counts != b.column_counts

    rel = assess_fragment_pair(a, b)
    assert rel.schema_compatible is False
    assert rel.is_joinable is False
    assert select_fragment_pairs([a, b]) == []


def test_08_select_fragment_pairs_returns_ordered_joinable_pairs():
    _, _, evidence, _ = build_sparse_case("csv", "sample.csv", 233, 57)
    frags = detect_text_fragments(evidence, "csv")
    pairs = select_fragment_pairs(frags)
    assert len(pairs) == 1
    fa, fb, rel = pairs[0]
    assert (fa.offset, fb.offset) == (0, 290)
    assert rel.is_joinable is True
    assert rel.format == "csv"


# ---------------------------------------------------------------------------
# 9-12. bounded reconstruction + accounting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,first_len,gap_len", [("txt", 24, 209), ("csv", 233, 57)])
def test_09_pair_reconstruction_never_emits_gap_bytes(fmt, first_len, gap_len):
    _, original, evidence, _ = build_sparse_case(fmt, f"a.{fmt}", first_len, gap_len)
    frags = detect_text_fragments(evidence, fmt)
    res = reconstruct_fragment_pair(
        fmt, frags[0].data, frags[1].data, observed_gap=gap_len
    )

    assert res.success is True
    assert res.status == "PARTIALLY_RECOVERED"
    assert res.details["gap_bytes_emitted"] == 0
    # Output is exactly the surviving fragment bytes, concatenated, with no filler.
    assert res.recovered_bytes == frags[0].data + frags[1].data
    assert SEP not in res.recovered_bytes
    assert res.missing_bytes == gap_len
    # The artifact budget equals the true original size.
    assert (
        res.verified_bytes + res.reconstructed_bytes + res.missing_bytes
        == len(original)
    )


@pytest.mark.parametrize("fmt,first_len,gap_len", [("txt", 24, 209), ("csv", 233, 57)])
def test_10_ambiguous_gap_is_never_arbitrarily_resolved(fmt, first_len, gap_len):
    """DECISION 1: an ambiguous gap must stay unresolved, not be guessed.

    Plain TXT/CSV validate for every candidate gap, so the evidence cannot
    distinguish them. The search does find the smallest structurally valid gap,
    but adopting it would convert genuinely missing bytes into an arbitrary
    reconstruction and break forensic accounting. The pair result must therefore
    report no selected gap and keep the region missing.
    """
    _, original, evidence, _ = build_sparse_case(fmt, f"sample.{fmt}", first_len, gap_len)
    frags = detect_text_fragments(evidence, fmt)
    res = reconstruct_fragment_pair(
        fmt, frags[0].data, frags[1].data, observed_gap=gap_len
    )

    # The search really is ambiguous: every candidate is structurally valid.
    assert res.details["gap_candidates_tried"] == 4096
    assert res.details["valid_candidate_count"] == 4096
    assert res.details["search_discriminating"] is False

    # No arbitrary resolution.
    assert res.details["selected_gap_size"] is None
    assert res.details["gap_size_determined"] is False
    assert res.details["selected_gap_is_hypothesis_only"] is True
    # The candidate range is still recorded so the ambiguity is auditable.
    assert res.details["gap_range_searched"] == [MIN_GAP, MAX_GAP]

    # Critically: the missing count is NOT collapsed to the smallest candidate.
    assert res.missing_bytes != MIN_GAP, "ambiguous gap was resolved to the smallest candidate"
    assert res.missing_bytes == gap_len
    assert res.details["observed_gap"] == gap_len
    assert res.details["proven_minimum_missing"] == gap_len

    # Surviving fragments are preserved and the unresolved region is not emitted.
    assert res.recovered_bytes == frags[0].data + frags[1].data
    assert res.details["gap_bytes_emitted"] == 0
    assert res.is_exact_match is False
    assert res.status == "PARTIALLY_RECOVERED"

    # Accounting closes on the true artifact size, so no missing byte was hidden
    # by declining to pick a gap.
    assert (
        res.verified_bytes + res.reconstructed_bytes + res.missing_bytes == len(original)
    )


@pytest.mark.parametrize("fmt,first_len,gap_len", [("txt", 24, 209), ("csv", 233, 57)])
def test_10b_ambiguity_resolution_does_not_consult_ground_truth(fmt, first_len, gap_len):
    """Resolving (or declining to resolve) a gap must never read ground truth."""
    import inspect

    from backend.app.recovery import reconstruction as rc

    src = inspect.getsource(rc.reconstruct_fragment_pair)
    for token in ("original_data", "ground_truth", "original_sha256", "expected_"):
        assert token not in src, f"pair reconstruction references {token}"


def test_10c_uniquely_supported_gap_is_selected():
    """DECISION 1, first clause: a deterministically supported gap IS selected.

    Plain TXT/CSV validators accept every candidate, so this uses a strict
    validator that accepts exactly one gap length. When the evidence genuinely
    distinguishes a single size, that size must be reported rather than
    suppressed, and it must be the smallest among those that validate.
    """
    from backend.app.models.validation import ValidationResult

    a = b"alpha\n"
    b = b"omega\n"
    accepted = {3}

    def strict_validator(payload: bytes) -> ValidationResult:
        gap = len(payload) - len(a) - len(b)
        ok = gap in accepted
        return ValidationResult(
            valid=ok,
            format="txt",
            errors=[] if ok else [f"unexpected gap {gap}"],
            warnings=[],
            details={"gap": gap},
        )

    res = reconstruct_bifragment(a, b, validator=strict_validator)
    assert res.success is True
    assert res.valid_candidate_count == 1
    assert res.gap_size == 3, "the single deterministically supported gap must be selected"
    assert MIN_GAP <= res.gap_size <= MAX_GAP
    # The gap bytes are metadata only: the result reports fragment byte counts and
    # a missing-region description, never a gap payload.
    assert res.missing_byte_count == res.gap_size
    assert res.fragment_a_bytes == a
    assert res.fragment_b_bytes == b
    assert res.missing_region_metadata


def test_10c2_smallest_valid_gap_is_selected_when_evidence_narrows_it():
    """With several valid candidates but real elimination, the smallest wins."""
    from backend.app.models.validation import ValidationResult

    a = b"alpha\n"
    b = b"omega\n"

    def narrow_validator(payload: bytes) -> ValidationResult:
        gap = len(payload) - len(a) - len(b)
        ok = gap in {2, 5, 9}
        return ValidationResult(
            valid=ok,
            format="txt",
            errors=[] if ok else [f"unexpected gap {gap}"],
            warnings=[],
            details={"gap": gap},
        )

    res = reconstruct_bifragment(a, b, validator=narrow_validator)
    assert res.success is True
    assert res.valid_candidate_count == 3
    assert res.gap_size == 2, "smallest of the surviving candidates must be chosen"


def test_10d_deterministic_structural_repairs_still_work():
    """Uniquely solvable repairs must still be performed and accounted."""
    from backend.app.recovery.signatures import (
        SYNTHETIC_END_MARKER,
        SYNTHETIC_START_MARKER,
    )

    original = SYNTHETIC_START_MARKER + b"FORMAT=txt\nBody: intact\n" + SYNTHETIC_END_MARKER
    damaged = original[: original.find(SYNTHETIC_END_MARKER)]

    res = reconstruct_text(damaged)
    # The known end marker is deterministically restored...
    assert res.recovered_bytes == original
    # ...but restored bytes are reconstructed, never verified.
    assert res.reconstructed_bytes == len(SYNTHETIC_END_MARKER)
    assert res.verified_bytes == len(damaged)
    assert res.missing_bytes == 0
    # So the status must not claim full recovery.
    assert res.status == "PARTIALLY_RECOVERED"
    assert (
        res.verified_bytes + res.reconstructed_bytes + res.missing_bytes
        == len(res.recovered_bytes)
    )


def test_11_no_valid_gap_preserves_fragments_without_fabrication():
    """When no candidate gap validates, the fragments survive and nothing is invented."""
    a_bytes = b"name,value\nalpha,1\n"
    b_bytes = b'{"not":"csv"}\n'
    res = reconstruct_fragment_pair("csv", a_bytes, b_bytes, observed_gap=40)

    assert res.success is False
    assert res.reconstruction_methods[-1] == "BOUNDED_GAP_SEARCH_FAILED"
    assert res.details["valid_candidate_count"] == 0
    assert res.details["gap_bytes_emitted"] == 0
    # Fragment A survives verbatim. Fragment B is not parseable as CSV, so its
    # bytes are reported missing rather than guessed at or spliced in.
    assert res.recovered_bytes == a_bytes
    assert res.missing_bytes == 40 + len(b_bytes)
    assert res.status == "PARTIALLY_RECOVERED"
    # Accounting still closes exactly on the artifact budget: both fragments'
    # bytes plus the unobserved gap.
    assert (
        res.verified_bytes + res.reconstructed_bytes + res.missing_bytes
        == len(a_bytes) + len(b_bytes) + 40
    )


@pytest.mark.parametrize("fmt", ["txt", "csv"])
@pytest.mark.parametrize(
    "scenario", ["clean", "fragmented", "truncated", "corrupted", "unrecoverable"]
)
def test_12_accounting_and_status_are_honest_end_to_end(fmt, scenario):
    fn, original = STANDARD_FIXTURES[fmt]
    case = generate_fragment_case(
        original, fmt=fmt, seed=42, scenario=scenario, original_filename=fn
    )
    evidence = case.evidence_bytes
    if scenario == "fragmented":
        a, b = case.fragments
        evidence = original[: a.length] + SEP * case.gap_length + original[b.offset :]

    run = execute_traced_recovery(filename=fn, content=evidence)

    # The accounting identity holds exactly.
    assert run.total_input_bytes == (
        run.total_verified_bytes
        + run.total_reconstructed_bytes
        + run.total_missing_bytes
    )
    # FULLY_RECOVERED is forbidden when anything is reconstructed or missing.
    if run.total_missing_bytes or run.total_reconstructed_bytes:
        assert run.status != "FULLY_RECOVERED"
    # A clean file is recovered exactly, byte for byte.
    if scenario == "clean":
        assert run.status == "FULLY_RECOVERED"
        assert run.total_missing_bytes == 0
        assert run.total_reconstructed_bytes == 0
        assert run.total_verified_bytes == len(original)


def test_16_truncated_file_is_partially_recovered_never_full():
    """Truncated evidence is a real loss and must never read as fully recovered."""
    for fmt in ("txt", "csv"):
        fn, original = STANDARD_FIXTURES[fmt]
        case = generate_fragment_case(
            original, fmt=fmt, seed=42, scenario="truncated", original_filename=fn
        )
        run = execute_traced_recovery(filename=fn, content=case.evidence_bytes)

        assert run.status == "PARTIALLY_RECOVERED", fmt
        assert run.total_missing_bytes > 0, fmt
        assert run.total_verified_bytes < len(original), fmt
        # The dropped tail is reported missing, never emitted as recovered.
        assert run.total_input_bytes == (
            run.total_verified_bytes
            + run.total_reconstructed_bytes
            + run.total_missing_bytes
        )


def test_17_binary_garbage_is_never_falsely_recovered():
    """High-entropy binary noise must not be salvaged into 'recovered text' or falsely recognized."""
    import random

    # Deterministic high-entropy binary noise containing no format signatures or structural delimiters
    rng = random.Random(42)
    garbage_512 = bytes(b for b in rng.randbytes(1024) if b not in b"{}[]<%>,\r\n")[:512]
    for fmt in ("txt", "csv"):
        res = reconstruct_text(garbage_512)
        assert res.status == "UNRECOVERABLE", fmt
        assert res.success is False
        assert res.recovered_bytes == b""
        assert res.verified_bytes == 0
        assert res.missing_bytes == len(garbage_512)
        assert res.reconstruction_methods == []
        assert res.damage_regions, "the loss must be recorded as a damage region"

    garbage_256 = bytes(b for b in rng.randbytes(512) if b not in b"{}[]<%>,\r\n")[:256]
    run = execute_traced_recovery("garbage.bin", garbage_256)
    assert run.status == "UNRECOVERABLE"
    assert run.output is None
    assert run.total_verified_bytes == 0


def test_17b_legitimate_embedded_json_is_detected_in_noise():
    """Verify that an actual valid JSON container embedded inside binary noise IS discovered and carved."""
    noise_prefix = b"\xde\xad\xbe\xef" * 16
    valid_json = b'{"status": "ok", "evidence_id": 42}'
    noise_suffix = b"\xca\xfe\xba\xbe" * 16
    payload = noise_prefix + valid_json + noise_suffix

    run = execute_traced_recovery("embedded.bin", payload)
    assert run.status == "FULLY_RECOVERED"
    assert run.format == "json"
    assert bytes.fromhex(run.output["recovered_bytes"]) == valid_json
    assert run.total_verified_bytes == len(valid_json)
    assert run.total_missing_bytes == 0


def test_18_intact_file_has_no_phantom_reconstruction_step():
    """A clean file needs no reconstruction, so it must record no such step."""
    for fmt in ("txt", "csv"):
        fn, original = STANDARD_FIXTURES[fmt]
        run = execute_traced_recovery(filename=fn, content=original)

        assert run.status == "FULLY_RECOVERED", fmt
        assert run.reconstruction_steps == [], fmt
        assert run.total_reconstructed_bytes == 0
        assert run.total_missing_bytes == 0
        assert run.total_verified_bytes == len(original)
        # Nothing was damaged, so no damage may be claimed.
        assert run.damage_regions == [], fmt
        assert run.total_input_bytes == len(original)


def test_19_confidence_reflects_byte_coverage_not_just_structure():
    """Structural validity alone must not yield full confidence."""
    from fastapi.testclient import TestClient

    from backend.app.main import app

    c = TestClient(app)
    fn, original = STANDARD_FIXTURES["txt"]
    ev = original[:24] + SEP * 209 + original[233:]
    data = c.post(
        "/api/recover-file",
        files={"file": (fn, ev, "application/octet-stream")},
    ).json()

    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["score_breakdown"]["structural_score"] == 100.0
    assert data["score_breakdown"]["byte_coverage"] < 1.0
    assert data["confidence_score"] < 100.0

# ---------------------------------------------------------------------------
# 13. no ground-truth dependency
# ---------------------------------------------------------------------------

def test_13_no_ground_truth_dependency():
    """The recovery engine must never import or read the generator/manifest."""
    import ast

    import backend.app.recovery.fragment_detector as fd
    import backend.app.recovery.relationship as rl
    import backend.app.recovery.reconstruction as rc
    import backend.app.recovery.tracer as tr

    banned = {"backend.app.generator", "fragment_generator", "DamageScenario", "FragmentCase"}
    for mod in (fd, rl, rc, tr):
        tree = ast.parse(open(mod.__file__).read())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
                imported.update(f"{node.module or ''}.{a.name}" for a in node.names)
        for name in imported:
            for token in banned:
                assert token not in name, f"{mod.__name__} imports {name}"
        # The engine must also not read ground truth off disk at runtime.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"open", "read_bytes"}, (
                    f"{mod.__name__} reads files at runtime"
                )


# ---------------------------------------------------------------------------
# 14. API end-to-end
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,first_len,gap_len", [("txt", 24, 209), ("csv", 233, 57)])
def test_14_api_upload_download_round_trip(fmt, first_len, gap_len):
    fn, original, evidence, _ = build_sparse_case(fmt, f"sample.{fmt}", first_len, gap_len)
    frags = detect_text_fragments(evidence, fmt)
    expected = frags[0].data + frags[1].data

    response = client.post(
        "/api/recover-file",
        files={"file": (fn, evidence, "application/octet-stream")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["format"] == fmt
    assert data["status"] == "PARTIALLY_RECOVERED"
    assert data["is_downloadable"] is True
    assert data["missing_bytes"] == gap_len
    # Structural validity alone must not yield full confidence.
    assert data["confidence_score"] < 100.0
    assert data["score_breakdown"]["byte_coverage"] == pytest.approx(
        (first_len + (len(original) - first_len - gap_len)) / len(original), rel=1e-3
    )

    downloaded = client.get(data["download_url"])
    assert downloaded.status_code == 200
    body = downloaded.content
    assert body == expected
    assert SEP not in body
    assert len(body) == first_len + (len(original) - first_len - gap_len)


def test_15_clean_file_download_is_byte_exact():
    fn, original = STANDARD_FIXTURES["txt"]
    response = client.post(
        "/api/recover-file",
        files={"file": (fn, original, "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "FULLY_RECOVERED"
    downloaded = client.get(data["download_url"])
    assert downloaded.content == original
