"""
tests/test_zero_ai_guarantee.py — Strict Offline & Zero-AI Invariant Verification

Verifies that Recoverix operates 100% deterministically and offline:
1. Setting GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, or any other environment variable
   never triggers outbound network sockets, HTTP requests, or subprocess executions.
2. Interpretation generation (artifact, cluster, case) always returns source="DETERMINISTIC_RULES".
3. Full recovery pipeline and FastAPI endpoints execute completely offline without remote calls.
4. No external generative AI client libraries are loaded into sys.modules.
"""

import os
import sys
import socket
import urllib.request
import http.client
import subprocess
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.scoring.interpretation_service import InterpretationService
from backend.app.scoring.explainer import explain_artifact
from backend.app.recovery.tracer import execute_traced_recovery
from backend.app.models.interpretation import (
    DeterministicArtifactFacts,
    DeterministicClusterFacts,
    DeterministicCaseFacts,
    ArtifactInterpretationContext,
    ClusterInterpretationContext,
    CaseInterpretationContext,
)


class ForbiddenOutboundCallError(AssertionError):
    """Raised whenever forbidden outbound network or subprocess execution is attempted."""
    pass


def _forbidden_socket_connect(*args, **kwargs):
    raise ForbiddenOutboundCallError(
        f"Outbound socket connection strictly forbidden in Recoverix! Args: {args}, Kwargs: {kwargs}"
    )


def _forbidden_urlopen(*args, **kwargs):
    raise ForbiddenOutboundCallError(
        f"Outbound urllib urlopen strictly forbidden in Recoverix! Args: {args}, Kwargs: {kwargs}"
    )


def _forbidden_http_connect(*args, **kwargs):
    raise ForbiddenOutboundCallError(
        f"Outbound HTTPConnection strictly forbidden in Recoverix! Args: {args}, Kwargs: {kwargs}"
    )


def _forbidden_subprocess(*args, **kwargs):
    raise ForbiddenOutboundCallError(
        f"Subprocess invocation strictly forbidden in Recoverix! Args: {args}, Kwargs: {kwargs}"
    )


@pytest.fixture(autouse=True)
def guard_outbound_network_and_subprocesses():
    """Network and subprocess guard preventing any external network or shell execution."""
    with patch.object(socket.socket, "connect", side_effect=_forbidden_socket_connect), \
         patch.object(urllib.request, "urlopen", side_effect=_forbidden_urlopen), \
         patch.object(http.client.HTTPConnection, "connect", side_effect=_forbidden_http_connect), \
         patch.object(subprocess, "Popen", side_effect=_forbidden_subprocess), \
         patch.object(subprocess, "run", side_effect=_forbidden_subprocess):
        yield


@pytest.fixture
def adversarial_env():
    """Environment simulating presence of multiple AI/LLM API keys and online mode."""
    env_vars = {
        "GEMINI_API_KEY": "AIzaSyFakeKeyAdversarialTest1234567890",
        "OPENAI_API_KEY": "sk-proj-FakeOpenAIKeyForOfflineAudit1234567890",
        "ANTHROPIC_API_KEY": "sk-ant-FakeAnthropicKeyForOfflineAudit1234567890",
        "RECOVERIX_OFFLINE": "0",  # Deliberately attempt to disable offline flag
    }
    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars


def test_zero_ai_modules_in_runtime():
    """Ensure no third-party generative AI packages are imported in Recoverix."""
    forbidden_modules = [
        "google.generativeai",
        "google.ai.generativelanguage",
        "openai",
        "anthropic",
        "langchain",
        "llama_index",
    ]
    for mod in forbidden_modules:
        assert mod not in sys.modules, f"Forbidden AI module '{mod}' is imported in sys.modules!"


def test_interpretation_service_artifact_zero_network(adversarial_env):
    """Artifact interpretation must never invoke network or external models."""
    service = InterpretationService()
    facts = DeterministicArtifactFacts(
        artifact_id="art_test_offline",
        filename="financial_audit.json",
        format="json",
        status="FULLY_RECOVERED",
        confidence_score=98.0,
        priority="HIGH",
        verified_bytes=1024,
        reconstructed_bytes=0,
        missing_bytes=0,
        reconstruction_method="NONE",
        validation_status="VALID",
    )
    interp = service.interpret_artifact("art_test_offline", facts, force_refresh=True)

    assert interp.source == "DETERMINISTIC_RULES"
    assert "fully recovered" in interp.interpretation.assessment.lower()
    assert interp.facts.verified_bytes == 1024
    assert interp.facts.missing_bytes == 0


def test_interpretation_service_cluster_zero_network(adversarial_env):
    """Cluster interpretation must never invoke network or external models."""
    service = InterpretationService()
    facts = DeterministicClusterFacts(
        cluster_id="cluster_audit_1",
        case_id="case_offline_cluster",
        relationship_classification="COEXTENSIVE_SET",
        has_ambiguity=False,
        total_nodes=2,
        member_formats=["json", "txt"],
        member_node_ids=["node_1", "node_2"],
        candidate_aggregate_verified_bytes=2048,
        candidate_aggregate_reconstructed_bytes=0,
        candidate_aggregate_missing_bytes=0,
        unique_physical_bytes=1024,
        bounded_physical_bytes=1024,
        max_confidence_score=95.0,
        highest_priority="HIGH",
        cluster_start=0,
        cluster_end=1024,
        status_distribution={"FULLY_RECOVERED": 2},
    )
    context = ClusterInterpretationContext(facts=facts)
    interp = service._invoke_cluster_with_fallback(context)

    output, source = interp
    assert source == "DETERMINISTIC_RULES"
    assert "coextensive" in output.assessment.lower() or "competing" in output.assessment.lower()


def test_interpretation_service_case_zero_network(adversarial_env):
    """Case interpretation must never invoke network or external models."""
    service = InterpretationService()
    facts = DeterministicCaseFacts(
        case_id="case_offline_audit",
        total_evidence_buffers=1,
        total_artifacts=1,
        total_nodes=1,
        total_clusters=1,
        case_physical_coverage_bytes=512,
        case_coverage_is_complete=True,
        candidate_aggregate_verified_bytes=512,
        candidate_aggregate_reconstructed_bytes=0,
        candidate_aggregate_missing_bytes=0,
        unscoped_candidate_count=0,
        unscoped_aggregate_verified_bytes=0,
        format_distribution={"JSON": 1},
        status_distribution={"FULLY_RECOVERED": 1},
        priority_distribution={"HIGH": 1},
        cluster_classification_distribution={"ISOLATED": 1},
        candidate_cap_enforced=False,
        total_discovered_candidates=1,
        candidates_omitted=0,
        graph_is_complete=True,
    )
    context = CaseInterpretationContext(facts=facts)
    output, source = service._invoke_case_with_fallback(context)

    assert source == "DETERMINISTIC_RULES"
    assert "investigation case" in output.assessment.lower()


def test_legacy_explainer_facade_zero_network(adversarial_env):
    """Legacy explain_artifact facade must remain completely offline and deterministic."""
    raw_artifact = {
        "artifact_id": "art_legacy_offline",
        "filename": "server_access.csv",
        "format": "csv",
        "status": "FULLY_RECOVERED",
        "verified_bytes": 256,
        "reconstructed_bytes": 0,
        "missing_bytes": 0,
        "confidence_score": 100.0,
        "priority": "LOW",
        "category": "DATABASE_LOG",
    }
    result = explain_artifact("art_legacy_offline", raw_artifact, force_refresh=True)

    assert result["source"] == "DETERMINISTIC_RULES"
    assert "256 verified bytes" in result["details"][0]


def test_tracer_recover_single_file_zero_network(adversarial_env):
    """Full recovery engine single file execution must execute strictly offline."""
    valid_json = b'{"status": "ok", "evidence_verified": true, "timestamp": 1700000000}'
    run = execute_traced_recovery(
        filename="evidence.json",
        content=valid_json,
    )

    assert run.status == "FULLY_RECOVERED"
    assert run.total_verified_bytes == len(valid_json)
    assert run.total_missing_bytes == 0


def test_fastapi_endpoints_zero_network(adversarial_env):
    """FastAPI recovery and interpretation endpoints must execute strictly offline without socket calls."""
    client = TestClient(app)

    # 1. POST /api/recover-file
    valid_json = b'{"user": "investigator_01", "action": "login", "authenticated": true}'
    resp = client.post(
        "/api/recover-file",
        files={"file": ("evidence.json", valid_json, "application/json")},
        data={"case_name": "Offline Case"},
    )
    assert resp.status_code == 200, resp.text
    file_id = resp.json()["file_id"]

    # 2. GET /api/recover-file/{file_id}
    resp_get = client.get(f"/api/recover-file/{file_id}")
    assert resp_get.status_code == 200
    assert resp_get.json()["status"] == "FULLY_RECOVERED"
    assert resp_get.json()["is_downloadable"] is True
    assert resp_get.json()["verified_bytes"] == len(valid_json)
    assert resp_get.json()["missing_bytes"] == 0

    # 3. POST /api/recover-file/{file_id}/explain
    resp_explain = client.post(f"/api/recover-file/{file_id}/explain")
    assert resp_explain.status_code == 200
    explain_data = resp_explain.json()
    assert explain_data["source"] == "DETERMINISTIC_RULES"
