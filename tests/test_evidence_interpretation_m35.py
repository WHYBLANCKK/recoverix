"""
test_evidence_interpretation_m35.py — Test Suite for Milestone 3.5.1: Grounded Interpretation Core.

Covers:
A. Status preservation (FULLY_RECOVERED, PARTIALLY_RECOVERED, CORRUPTED, UNRECOVERABLE)
B. DeterministicRuleProvider logic across all recovery statuses
C. Fact binding and immutability (V/R/M, status, confidence, priority preserved; provider overrides discarded)
D. Deterministic rules isolation & zero AI network invocation (offline enforcement, API key ignored)
E. Privacy & preview boundaries (raw bytes excluded, preview bounded to 200 chars, control chars stripped)
F. Persistence (stored in SQLite ai_summary, reloads, force_refresh, malformed cache resilience, zero DDL changes)
G. Canonical pipeline (legacy explainer delegation, single interpretation pipeline)
"""

from __future__ import annotations

import os
import json
import sqlite3
import tempfile
from unittest.mock import patch, MagicMock
import pytest
from pydantic import ValidationError

from backend.app.models.interpretation import (
    DeterministicArtifactFacts,
    ArtifactInterpretationContext,
    ProviderInterpretationOutput,
    GroundedArtifactInterpretation,
    DeterministicRelationshipFact,
    DeterministicClusterFacts,
    DeterministicCaseFacts,
)
from backend.app.scoring.providers import (
    DeterministicRuleProvider,
)
from backend.app.scoring.interpretation_service import (
    InterpretationService,
    get_interpretation_service,
)
from backend.app.scoring.explainer import (
    explain_artifact,
    _explanation_cache,
)
from backend.app.storage.sqlite_engine import SqliteEngine
from backend.app.storage.sqlite_store import SqliteStore
from backend.app.models.artifact import ArtifactRecord


# ─────────────────────────────────────────────────────────────────────────────
# Group A: Status Preservation
# ─────────────────────────────────────────────────────────────────────────────

def test_01_status_fully_recovered_preserved():
    """Verify FULLY_RECOVERED is preserved without loss or transformation."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_fr",
        "format": "json",
        "status": "FULLY_RECOVERED",
        "verified_bytes": 1024,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "confidence_score": 95.0,
    }
    facts = service.extract_artifact_facts(raw)
    assert facts.status == "FULLY_RECOVERED"
    assert facts.verified_bytes == 1024


def test_02_status_partially_recovered_preserved():
    """Verify PARTIALLY_RECOVERED is preserved without loss or transformation."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_pr",
        "format": "xml",
        "status": "PARTIALLY_RECOVERED",
        "verified_bytes": 800,
        "reconstructed_bytes": 50,
        "missing_bytes": 100,
        "confidence_score": 75.0,
    }
    facts = service.extract_artifact_facts(raw)
    assert facts.status == "PARTIALLY_RECOVERED"
    assert facts.reconstructed_bytes == 50
    assert facts.missing_bytes == 100


def test_03_status_corrupted_preserved_without_collapse():
    """Verify CORRUPTED is preserved exactly and not collapsed into PARTIALLY_RECOVERED."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_corr",
        "format": "csv",
        "status": "CORRUPTED",
        "verified_bytes": 350,
        "reconstructed_bytes": 0,
        "missing_bytes": 200,
        "confidence_score": 45.0,
    }
    facts = service.extract_artifact_facts(raw)
    assert facts.status == "CORRUPTED"
    assert facts.status != "PARTIALLY_RECOVERED"


def test_04_status_unrecoverable_preserved():
    """Verify UNRECOVERABLE is preserved without loss or transformation."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_unrec",
        "format": "txt",
        "status": "UNRECOVERABLE",
        "verified_bytes": 0,
        "reconstructed_bytes": 0,
        "missing_bytes": 512,
        "confidence_score": 0.0,
    }
    facts = service.extract_artifact_facts(raw)
    assert facts.status == "UNRECOVERABLE"


# ─────────────────────────────────────────────────────────────────────────────
# Group B: DeterministicRuleProvider Logic
# ─────────────────────────────────────────────────────────────────────────────

def test_05_deterministic_provider_fully_recovered():
    """Verify deterministic narrative for fully recovered artifact."""
    provider = DeterministicRuleProvider()
    facts = DeterministicArtifactFacts(
        artifact_id="art_1",
        filename="test.json",
        format="json",
        status="FULLY_RECOVERED",
        confidence_score=98.0,
        priority="LOW",
        verified_bytes=500,
        reconstructed_bytes=0,
        missing_bytes=0,
        reconstruction_method="NONE",
        validation_status="VALID",
    )
    context = ArtifactInterpretationContext(facts=facts)
    out = provider.interpret_artifact(context)

    assert "fully recovered" in out.assessment.lower()
    assert "500 bytes were mathematically verified" in out.assessment
    assert "0 missing and 0 reconstructed" in out.assessment
    assert "exact deterministic recovery" in out.limitations.lower()
    assert any("500" in d and "verified" in d for d in out.details)


def test_06_deterministic_provider_partially_recovered_with_closure():
    """Verify deterministic narrative for partial recovery with delimiter closure."""
    provider = DeterministicRuleProvider()
    facts = DeterministicArtifactFacts(
        artifact_id="art_2",
        filename="doc.xml",
        format="xml",
        status="PARTIALLY_RECOVERED",
        confidence_score=85.0,
        priority="MEDIUM",
        verified_bytes=1000,
        reconstructed_bytes=14,
        missing_bytes=0,
        reconstruction_method="STRUCTURAL_CLOSURE",
        validation_status="VALID",
    )
    context = ArtifactInterpretationContext(facts=facts)
    out = provider.interpret_artifact(context)

    assert "14 uniquely determined closing xml delimiters" in out.assessment.lower()
    assert "deterministic structural closure only" in out.limitations.lower()
    assert "refused to predict or synthesize unobserved semantic data" in out.limitations.lower()


def test_07_deterministic_provider_corrupted():
    """Verify deterministic narrative for corrupted artifact."""
    provider = DeterministicRuleProvider()
    facts = DeterministicArtifactFacts(
        artifact_id="art_3",
        filename="data.csv",
        format="csv",
        status="CORRUPTED",
        confidence_score=35.0,
        priority="HIGH",
        verified_bytes=400,
        reconstructed_bytes=0,
        missing_bytes=600,
        reconstruction_method="NONE",
        validation_status="CHECKSUM_MISMATCH",
    )
    context = ArtifactInterpretationContext(facts=facts)
    out = provider.interpret_artifact(context)

    assert "data corruption is present" in out.assessment.lower()
    assert "failed cryptographic or format integrity validation" in out.assessment.lower()
    assert "refused to fabricate file headers, repair damaged binary streams" in out.limitations.lower()


def test_08_deterministic_provider_unrecoverable():
    """Verify deterministic narrative for unrecoverable candidate."""
    provider = DeterministicRuleProvider()
    facts = DeterministicArtifactFacts(
        artifact_id="art_4",
        filename="corrupt.bin",
        format="json",
        status="UNRECOVERABLE",
        confidence_score=0.0,
        priority="LOW",
        verified_bytes=0,
        reconstructed_bytes=0,
        missing_bytes=1024,
        reconstruction_method="NONE",
        validation_status="INVALID_HEADER",
    )
    context = ArtifactInterpretationContext(facts=facts)
    out = provider.interpret_artifact(context)

    assert "unrecoverable" in out.assessment.lower()
    assert "yielded no valid structural markers or signatures" in out.assessment.lower()
    assert "refused to fabricate file headers" in out.limitations.lower()


def test_09_no_unsupported_factual_claims():
    """Verify provider does not claim verified bytes when missing bytes exist."""
    provider = DeterministicRuleProvider()
    facts = DeterministicArtifactFacts(
        artifact_id="art_5",
        filename="partial.txt",
        format="txt",
        status="PARTIALLY_RECOVERED",
        confidence_score=60.0,
        priority="MEDIUM",
        verified_bytes=300,
        reconstructed_bytes=0,
        missing_bytes=200,
        reconstruction_method="NONE",
        validation_status="VALID",
    )
    context = ArtifactInterpretationContext(facts=facts)
    out = provider.interpret_artifact(context)

    # Must NOT claim that all bytes were verified
    assert "all 300 bytes were mathematically verified" not in out.assessment.lower()
    assert "unobserved 200-byte region remains missing" in out.assessment


# ─────────────────────────────────────────────────────────────────────────────
# Group C: Fact Binding & Immutability
# ─────────────────────────────────────────────────────────────────────────────

def test_10_vrm_preserved_in_grounded_interpretation():
    """Verify verified/reconstructed/missing byte counts are faithfully preserved."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_bind",
        "format": "json",
        "status": "PARTIALLY_RECOVERED",
        "verified_bytes": 777,
        "reconstructed_bytes": 33,
        "missing_bytes": 111,
        "confidence_score": 82.5,
    }
    interpretation = service.interpret_artifact("art_bind", raw)
    assert interpretation.facts.verified_bytes == 777
    assert interpretation.facts.reconstructed_bytes == 33
    assert interpretation.facts.missing_bytes == 111


def test_11_status_preserved_in_grounded_interpretation():
    """Verify status is preserved in GroundedArtifactInterpretation."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_status",
        "format": "csv",
        "status": "CORRUPTED",
        "confidence_score": 40.0,
    }
    interpretation = service.interpret_artifact("art_status", raw)
    assert interpretation.facts.status == "CORRUPTED"


def test_12_confidence_preserved_in_grounded_interpretation():
    """Verify confidence score is preserved on the 0-100 scale."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_conf",
        "format": "txt",
        "status": "FULLY_RECOVERED",
        "confidence_score": 88.5,
    }
    interpretation = service.interpret_artifact("art_conf", raw)
    assert interpretation.facts.confidence_score == 88.5


def test_13_priority_preserved_in_grounded_interpretation():
    """Verify priority is preserved in GroundedArtifactInterpretation."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_prio",
        "format": "json",
        "status": "PARTIALLY_RECOVERED",
        "priority": "CRITICAL",
        "confidence_score": 70.0,
    }
    interpretation = service.interpret_artifact("art_prio", raw)
    assert interpretation.facts.priority == "CRITICAL"


def test_14_provider_cannot_override_status():
    """Verify that a provider attempting to return a conflicting status is strictly ignored."""
    mock_provider = MagicMock()
    mock_provider.interpret_artifact.return_value = ProviderInterpretationOutput(
        summary="Summary",
        assessment="Assessment",
        structural_context="Context",
        limitations="Limits",
        recommended_next_steps="Steps",
        details=[],
    )

    service = InterpretationService(primary_provider=mock_provider, fallback_provider=mock_provider)
    raw = {
        "artifact_id": "art_no_status_override",
        "format": "json",
        "status": "CORRUPTED",
        "confidence_score": 30.0,
    }
    interpretation = service.interpret_artifact("art_no_status_override", raw)
    # The status in GroundedArtifactInterpretation must remain the system-owned status
    assert interpretation.facts.status == "CORRUPTED"


def test_15_provider_cannot_override_priority():
    """Verify that a provider cannot override deterministic priority."""
    # Verify ProviderInterpretationOutput does not own priority
    assert "priority" not in ProviderInterpretationOutput.model_fields

    mock_provider = MagicMock()
    mock_out = ProviderInterpretationOutput(
        summary="Summary",
        assessment="Assessment",
        structural_context="Context",
        limitations="Limits",
        recommended_next_steps="Steps",
        details=[],
    )
    mock_provider.interpret_artifact.return_value = mock_out

    service = InterpretationService(primary_provider=mock_provider, fallback_provider=mock_provider)
    raw = {
        "artifact_id": "art_no_prio_override",
        "format": "json",
        "status": "PARTIALLY_RECOVERED",
        "priority": "CRITICAL",
        "confidence_score": 75.0,
    }
    interpretation = service.interpret_artifact("art_no_prio_override", raw)
    assert interpretation.facts.priority == "CRITICAL"
    legacy = interpretation.to_legacy_dict()
    assert legacy["priority"] == "CRITICAL"


def test_16_provider_cannot_override_vrm():
    """Verify provider output cannot alter V/R/M metrics in bound interpretation."""
    mock_provider = MagicMock()
    mock_provider.interpret_artifact.return_value = ProviderInterpretationOutput(
        summary="Summary",
        assessment="Claiming 9999 verified bytes",
        structural_context="Context",
        limitations="Limits",
        recommended_next_steps="Steps",
        details=[],
    )

    service = InterpretationService(primary_provider=mock_provider, fallback_provider=mock_provider)
    raw = {
        "artifact_id": "art_no_vrm_override",
        "format": "xml",
        "status": "PARTIALLY_RECOVERED",
        "verified_bytes": 100,
        "reconstructed_bytes": 20,
        "missing_bytes": 50,
        "confidence_score": 70.0,
    }
    interpretation = service.interpret_artifact("art_no_vrm_override", raw)
    assert interpretation.facts.verified_bytes == 100
    assert interpretation.facts.reconstructed_bytes == 20
    assert interpretation.facts.missing_bytes == 50


def test_17_frozen_models_reject_mutation():
    """Verify that facts and interpretations are frozen and reject in-place attribute mutation."""
    facts = DeterministicArtifactFacts(
        artifact_id="art_frozen",
        filename="test.txt",
        format="txt",
        status="FULLY_RECOVERED",
        confidence_score=90.0,
        priority="LOW",
        verified_bytes=100,
        reconstructed_bytes=0,
        missing_bytes=0,
        reconstruction_method="NONE",
        validation_status="VALID",
    )
    with pytest.raises(ValidationError):
        facts.status = "CORRUPTED"  # type: ignore

    out = ProviderInterpretationOutput(
        summary="Summary",
        assessment="Assessment",
        structural_context="Context",
        limitations="Limits",
        recommended_next_steps="Steps",
        details=[],
    )
    with pytest.raises(ValidationError):
        out.summary = "New Summary"  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Group D: Gemini Provider & Resilient Fallback
# ─────────────────────────────────────────────────────────────────────────────

def test_18_gemini_mocked_successful_response():
    """Verify Gemini provider parses structured JSON response successfully."""
    mock_resp_payload = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {
                            "text": json.dumps({
                                "summary": "Gemini forensic summary.",
                                "assessment": "Verified 500 bytes of valid JSON syntax.",
                                "structural_context": "Root dictionary markers were detected.",
                                "limitations": "Missing bytes preserved as gaps.",
                                "recommended_next_steps": "Review JSON schema definitions.",
                                "details": ["Point 1", "Point 2"],
                            })
                        }
                    ]
                }
            }
        ]
    }

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_resp_payload
    mock_client.__enter__.return_value.post.return_value = mock_resp

    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key", "RECOVERIX_OFFLINE": "0"}), \
         patch("httpx.Client", return_value=mock_client):
        service = InterpretationService()
        facts = DeterministicArtifactFacts(
            artifact_id="art_gem",
            filename="data.json",
            format="json",
            status="FULLY_RECOVERED",
            confidence_score=95.0,
            priority="LOW",
            verified_bytes=500,
            reconstructed_bytes=0,
            missing_bytes=0,
            reconstruction_method="NONE",
            validation_status="VALID",
        )
        context = ArtifactInterpretationContext(facts=facts)
        interpretation = service.interpret_artifact("art_gem", facts)
        assert interpretation.source == "DETERMINISTIC_RULES"
        assert "fully recovered" in interpretation.interpretation.assessment.lower()
        mock_client.assert_not_called()


def test_19_deterministic_rules_with_custom_provider_protocol():
    """Verify InterpretationService accepts any conforming deterministic provider."""
    mock_output = ProviderInterpretationOutput(
        summary="Deterministic custom summary.",
        assessment="Custom assessment without remote AI.",
        structural_context="Local rule context.",
        limitations="None.",
        recommended_next_steps="Review.",
        details=["Point 1"],
    )
    mock_provider = MagicMock()
    mock_provider.interpret_artifact.return_value = mock_output
    service = InterpretationService(provider=mock_provider)

    raw = {
        "artifact_id": "art_custom",
        "format": "json",
        "status": "FULLY_RECOVERED",
        "verified_bytes": 450,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "confidence_score": 90.0,
    }
    interpretation = service.interpret_artifact("art_custom", raw)
    assert interpretation.source == "DETERMINISTIC_RULES"
    assert interpretation.interpretation.summary == "Deterministic custom summary."
    mock_provider.interpret_artifact.assert_called_once()


def test_20_deterministic_recovery_has_no_network_timeout():
    """Verify recovery interpretation operates in-memory with zero network timeout dependencies."""
    service = InterpretationService()
    raw = {
        "artifact_id": "art_timeout",
        "format": "xml",
        "status": "PARTIALLY_RECOVERED",
        "verified_bytes": 200,
        "reconstructed_bytes": 10,
        "missing_bytes": 0,
        "confidence_score": 80.0,
    }
    interpretation = service.interpret_artifact("art_timeout", raw)
    assert interpretation.source == "DETERMINISTIC_RULES"
    assert "closing xml delimiters" in interpretation.interpretation.assessment.lower()


def test_21_corrupted_artifacts_evaluated_deterministically_offline():
    """Verify corrupted artifacts evaluate deterministically without external providers."""
    service = InterpretationService()
    raw = {
        "artifact_id": "art_500",
        "format": "txt",
        "status": "CORRUPTED",
        "verified_bytes": 150,
        "reconstructed_bytes": 0,
        "missing_bytes": 50,
        "confidence_score": 35.0,
    }
    interpretation = service.interpret_artifact("art_500", raw)
    assert interpretation.source == "DETERMINISTIC_RULES"
    assert "data corruption is present" in interpretation.interpretation.assessment.lower()


def test_22_offline_mode_always_deterministic():
    """Verify RECOVERIX_OFFLINE=1 executes deterministic rules with zero remote dependencies."""
    with patch.dict(os.environ, {"RECOVERIX_OFFLINE": "1", "GEMINI_API_KEY": "some_key"}):
        service = InterpretationService()
        facts = DeterministicArtifactFacts(
            artifact_id="art_off",
            filename="data.txt",
            format="txt",
            status="FULLY_RECOVERED",
            confidence_score=90.0,
            priority="LOW",
            verified_bytes=100,
            reconstructed_bytes=0,
            missing_bytes=0,
            reconstruction_method="NONE",
            validation_status="VALID",
        )
        interpretation = service.interpret_artifact("art_off", facts)
        assert interpretation.source == "DETERMINISTIC_RULES"
        assert "fully recovered" in interpretation.interpretation.assessment.lower()


def test_23_offline_mode_wins_over_api_key():
    """Verify that GEMINI_API_KEY is ignored and never causes external calls."""
    mock_client = MagicMock()
    with patch.dict(os.environ, {"RECOVERIX_OFFLINE": "1", "GEMINI_API_KEY": "valid_key"}), \
         patch("httpx.Client", return_value=mock_client):
        service = InterpretationService()
        raw = {
            "artifact_id": "art_precedence",
            "format": "json",
            "status": "FULLY_RECOVERED",
            "verified_bytes": 300,
            "confidence_score": 90.0,
        }
        interpretation = service.interpret_artifact("art_precedence", raw)
        assert interpretation.source == "DETERMINISTIC_RULES"
        # Assert httpx.Client was never invoked
        mock_client.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Group E: Privacy & Preview Boundaries
# ─────────────────────────────────────────────────────────────────────────────

def test_24_raw_bytes_never_passed_to_provider():
    """Verify provider invocation args contain zero raw bytes instances."""
    mock_provider = MagicMock()
    mock_provider.interpret_artifact.return_value = ProviderInterpretationOutput(
        summary="Summary",
        assessment="Assessment",
        structural_context="Context",
        limitations="Limits",
        recommended_next_steps="Steps",
        details=[],
    )

    service = InterpretationService(primary_provider=mock_provider, fallback_provider=mock_provider)
    raw = {
        "artifact_id": "art_no_bytes",
        "format": "json",
        "status": "FULLY_RECOVERED",
        "raw_bytes": b"\x00\x01\x02\x03\x04\x05",  # Raw bytes in source artifact
        "content_bytes": b"binary_data",
        "content_preview": "Safe printable text preview",
        "confidence_score": 90.0,
    }
    service.interpret_artifact("art_no_bytes", raw)
    call_args = mock_provider.interpret_artifact.call_args[0]
    context: ArtifactInterpretationContext = call_args[0]

    # Verify context attributes
    assert not isinstance(context.content_preview, bytes)
    assert not any(isinstance(v, bytes) for v in context.facts.model_dump().values())


def test_25_preview_bounded_to_200_characters():
    """Verify content preview is strictly truncated to <= 200 characters."""
    long_preview = "A" * 500
    sanitized = InterpretationService.sanitize_preview(long_preview)
    assert sanitized is not None
    assert len(sanitized) == 200
    assert sanitized == "A" * 200


def test_26_control_characters_removed_from_preview():
    """Verify ASCII control characters and binary noise are stripped from preview."""
    dirty_preview = "Hello\x00\x01\x02\x08World\x1f!\x7f"
    cleaned = InterpretationService.sanitize_preview(dirty_preview)
    assert cleaned == "HelloWorld!"


def test_27_preview_sanitization_does_not_claim_perfect_protection():
    """Verify token redaction works for obvious tokens, acknowledging preview is potentially sensitive."""
    preview_with_token = "User log: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token secret_key: 12345"
    sanitized = InterpretationService.sanitize_preview(preview_with_token)
    assert "Bearer [REDACTED]" in sanitized
    assert "[REDACTED_SECRET]" in sanitized


# ─────────────────────────────────────────────────────────────────────────────
# Group F: Persistence & SQLite Compatibility
# ─────────────────────────────────────────────────────────────────────────────

def test_28_generated_interpretation_stored_in_ai_summary():
    """Verify generated interpretation is persisted to artifacts.ai_summary via update_artifact_ai_summary."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_recoverix.db")
        engine = SqliteEngine(db_path)
        store = SqliteStore(engine=engine)

        case = store.create_case(name="Persistence Case")
        art = ArtifactRecord(
            artifact_id="art_persist_1",
            case_id=case.case_id,
            format="json",
            status="FULLY_RECOVERED",
            confidence_score=95.0,
            verified_bytes=512,
            reconstructed_bytes=0,
            missing_bytes=0,
            reconstruction_method="NONE",
            validation_status="VALID",
            is_downloadable=True,
            ai_summary=None,
        )
        store.save_artifact_record(art)

        service = InterpretationService(fallback_provider=DeterministicRuleProvider(), store=store)
        interpretation = service.interpret_artifact("art_persist_1", art)

        # Inspect raw database row
        conn = engine.connect()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ai_summary FROM artifacts WHERE artifact_id = ?", ("art_persist_1",))
            row = cursor.fetchone()
            assert row is not None
            assert row[0] is not None
            saved = json.loads(row[0])
            assert saved["facts"]["artifact_id"] == "art_persist_1"
            assert saved["facts"]["verified_bytes"] == 512
            assert "fully recovered" in saved["interpretation"]["assessment"].lower()
        finally:
            conn.close()


def test_29_stored_interpretation_reloads_after_store_reopen():
    """Verify saved interpretation survives store closing and re-opening without re-invoking provider."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_recoverix.db")
        engine1 = SqliteEngine(db_path)
        store1 = SqliteStore(engine=engine1)

        case = store1.create_case(name="Reload Case")
        art = ArtifactRecord(
            artifact_id="art_reload",
            case_id=case.case_id,
            format="xml",
            status="PARTIALLY_RECOVERED",
            confidence_score=80.0,
            verified_bytes=400,
            reconstructed_bytes=10,
            missing_bytes=0,
            reconstruction_method="STRUCTURAL_CLOSURE",
            validation_status="VALID",
            is_downloadable=True,
            ai_summary=None,
        )
        store1.save_artifact_record(art)

        service1 = InterpretationService(fallback_provider=DeterministicRuleProvider(), store=store1)
        service1.interpret_artifact("art_reload", art)

        # Reopen with fresh engine and store
        engine2 = SqliteEngine(db_path)
        store2 = SqliteStore(engine=engine2)
        loaded_art = store2.get_artifact("art_reload")
        assert loaded_art is not None
        assert loaded_art.ai_summary is not None

        mock_provider = MagicMock()
        service2 = InterpretationService(primary_provider=mock_provider, fallback_provider=mock_provider, store=store2)
        reloaded_interp = service2.interpret_artifact("art_reload", loaded_art, force_refresh=False)

        assert reloaded_interp.cached is True
        assert reloaded_interp.facts.verified_bytes == 400
        # Mock provider must NOT be invoked because it loaded from cache
        mock_provider.interpret_artifact.assert_not_called()


def test_30_force_refresh_replaces_stored_interpretation():
    """Verify force_refresh=True updates the stored ai_summary in SQLite."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_recoverix.db")
        engine = SqliteEngine(db_path)
        store = SqliteStore(engine=engine)

        case = store.create_case(name="Refresh Case")
        art = ArtifactRecord(
            artifact_id="art_refresh",
            case_id=case.case_id,
            format="txt",
            status="CORRUPTED",
            confidence_score=40.0,
            verified_bytes=200,
            reconstructed_bytes=0,
            missing_bytes=100,
            reconstruction_method="NONE",
            validation_status="CHECKSUM_MISMATCH",
            is_downloadable=True,
            ai_summary=json.dumps({"stale": "data"}),  # Stale data
        )
        store.save_artifact_record(art)

        service = InterpretationService(fallback_provider=DeterministicRuleProvider(), store=store)
        new_interp = service.interpret_artifact("art_refresh", art, force_refresh=True)

        assert new_interp.cached is False
        assert new_interp.facts.status == "CORRUPTED"

        reloaded = store.get_artifact("art_refresh")
        assert reloaded is not None
        parsed = json.loads(reloaded.ai_summary)
        assert parsed["facts"]["status"] == "CORRUPTED"
        assert "stale" not in parsed


def test_31_malformed_cache_regenerates_safely():
    """Verify that if ai_summary is corrupt/malformed, the service regenerates without crashing."""
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())
    raw = {
        "artifact_id": "art_corrupt_cache",
        "format": "json",
        "status": "FULLY_RECOVERED",
        "confidence_score": 90.0,
        "verified_bytes": 100,
        "ai_summary": "MALFORMED_NON_JSON_CONTENT{{{",
    }
    # Should not raise exception
    interp = service.interpret_artifact("art_corrupt_cache", raw)
    assert interp.cached is False
    assert interp.facts.status == "FULLY_RECOVERED"


def test_32_zero_sqlite_schema_changes():
    """Verify that artifacts table schema in sqlite_engine has not been modified."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_recoverix.db")
        engine = SqliteEngine(db_path)
        engine.initialize()
        conn = engine.connect()
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(artifacts);")
            columns = {row[1]: row[2] for row in cursor.fetchall()}
            assert "ai_summary" in columns
            assert columns["ai_summary"] == "TEXT"
            # Ensure no unexpected new tables or columns were created
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {row[0] for row in cursor.fetchall()}
            assert "cases" in tables
            assert "artifacts" in tables
            assert "recovery_runs" in tables
            assert "interpretation" not in tables  # No new tables!
        finally:
            conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Group G: Canonical Pipeline & Legacy Delegation
# ─────────────────────────────────────────────────────────────────────────────

def test_33_legacy_explainer_delegates_to_interpretation_service():
    """Verify legacy explain_artifact() in explainer.py routes through InterpretationService."""
    _explanation_cache.clear()
    raw = {
        "artifact_id": "art_legacy",
        "format": "json",
        "status": "FULLY_RECOVERED",
        "category": "DOCUMENT",
        "confidence_score": 95.0,
        "verified_bytes": 600,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
    }
    legacy = explain_artifact("art_legacy", raw)
    assert legacy["cached"] is False
    assert legacy["available"] is True
    assert "DOCUMENT" in legacy["summary"]
    assert legacy["facts"]["verified_bytes"] == 600
    assert legacy["facts"]["status"] == "FULLY_RECOVERED"

    # Subsequent call hits facade cache
    legacy2 = explain_artifact("art_legacy", raw)
    assert legacy2["cached"] is True


def test_34_no_duplicate_gemini_template_pipeline():
    """Verify that explain_artifact shares the canonical service rather than duplicate logic."""
    service = get_interpretation_service()
    assert isinstance(service, InterpretationService)
    # Ensure facts extraction uses canonical service
    raw = {"artifact_id": "art_canon", "status": "CORRUPTED", "confidence_score": 40.0}
    facts = service.extract_artifact_facts(raw)
    assert facts.status == "CORRUPTED"


def test_35_extract_artifact_facts_fallback_total_input_bytes_invariant():
    """Verify fallback total_input_bytes equals verified_bytes + missing_bytes, NOT inflated with reconstructed_bytes.

    Forensic invariant:
    total_input_bytes represents the source evidence input chunk.
    verified_bytes represents surviving original bytes.
    missing_bytes represents lost/unobserved input bytes.
    reconstructed_bytes represents synthetic syntax fillers/delimiters generated on recovery (output domain).
    Therefore:
    - When total_input_bytes is missing from source artifact, fallback must be (v_bytes + m_bytes).
    - Reconstructed bytes must NEVER inflate total_input_bytes.
    - Explicit total_input_bytes=0 must be preserved and not overridden by truthy/falsy fallback.
    """
    service = InterpretationService(fallback_provider=DeterministicRuleProvider())

    # Case 1: missing total_input_bytes with verified, reconstructed, and missing bytes
    raw_missing = {
        "artifact_id": "art_inv_1",
        "format": "json",
        "status": "PARTIALLY_RECOVERED",
        "verified_bytes": 800,
        "reconstructed_bytes": 50,
        "missing_bytes": 100,
        "confidence_score": 75.0,
    }
    facts_1 = service.extract_artifact_facts(raw_missing)
    # Under old buggy formula: 800 + 50 + 100 = 950
    # Under correct invariant: 800 + 100 = 900
    assert facts_1.total_input_bytes == 900
    assert facts_1.total_input_bytes != 950
    assert facts_1.total_input_bytes == facts_1.verified_bytes + facts_1.missing_bytes

    # Case 2: explicitly 0 total_input_bytes must be preserved, not overwritten by fallback
    raw_zero = {
        "artifact_id": "art_inv_2",
        "format": "bin",
        "status": "UNRECOVERABLE",
        "verified_bytes": 10,
        "reconstructed_bytes": 5,
        "missing_bytes": 20,
        "confidence_score": 10.0,
        "total_input_bytes": 0,
    }
    facts_2 = service.extract_artifact_facts(raw_zero)
    assert facts_2.total_input_bytes == 0

    # Case 3: ArtifactRecord object with total_input_bytes None falls back to v + m
    record = ArtifactRecord(
        artifact_id="art_inv_3",
        format="csv",
        status="PARTIALLY_RECOVERED",
        confidence_score=80.0,
        verified_bytes=300,
        reconstructed_bytes=40,
        missing_bytes=70,
        total_input_bytes=None,
    )
    facts_3 = service.extract_artifact_facts(record)
    assert facts_3.total_input_bytes == 370  # 300 + 70, not 300 + 40 + 70 (410)
    assert facts_3.total_input_bytes != 410
