"""
test_cluster_case_interpretation_m352.py — Comprehensive test suite for Recoverix Milestone 3.5.2.

Milestone 3.5.2: Cluster + Case Synthesis.
Validates:
1. Physical coverage model (1D interval-union sweep, bounding span vs unique physical bytes)
2. Competing hypothesis semantics (COEXTENSIVE_SET, CONTAINMENT_TREE, OVERLAP_SPAN, MIXED, ISOLATED)
3. Case-level byte accounting (scoped buffer boundaries, multi-buffer summing, unscoped candidates)
4. Deterministic graph fingerprints and bounded LRU cache invalidation
5. Offline mode (RECOVERIX_OFFLINE=1) and graceful Gemini fallback
6. Immutability of grounded models and fact preservation
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional, List
from unittest.mock import patch, MagicMock

import pytest
from pydantic import ValidationError

from backend.app.models.recovery_run import RecoveryRun
from backend.app.models.evidence_graph import (
    GraphNode,
    GraphEdge,
    ArtifactCluster,
    EvidenceGraph,
)
from backend.app.models.interpretation import (
    DeterministicClusterFacts,
    DeterministicCaseFacts,
    ClusterInterpretationContext,
    CaseInterpretationContext,
    GroundedClusterInterpretation,
    GroundedCaseInterpretation,
    ProviderInterpretationOutput,
)
from backend.app.recovery.graph import build_evidence_graph_from_runs
from backend.app.scoring.interpretation_service import (
    InterpretationService,
    compute_interval_union_bytes,
    compute_cluster_fingerprint,
    compute_case_graph_fingerprint,
)
from backend.app.scoring.providers import (
    InterpretationProvider,
    DeterministicRuleProvider,
)


def make_run(
    run_id: str,
    format: str = "json",
    evidence_start: int = 0,
    evidence_end: Optional[int] = 100,
    evidence_file_id: Optional[str] = "ev_01",
    candidate_id: Optional[str] = None,
    artifact_id: Optional[str] = None,
    status: str = "FULLY_RECOVERED",
    confidence_score: float = 95.0,
    verified_bytes: int = 100,
    reconstructed_bytes: int = 0,
    missing_bytes: int = 0,
    detection_method: str = "magic_bytes",
    case_id: Optional[str] = "case_test_01",
    filename: str = "evidence.bin",
) -> RecoveryRun:
    """Helper to construct canonical RecoveryRun models with physical coordinates."""
    prov = {
        "evidence_start": evidence_start,
        "coordinate_system": (
            "physical_evidence_offsets"
            if evidence_end is not None
            else "whole_buffer_fallback"
        ),
        "detection_method": detection_method,
    }
    if evidence_end is not None:
        prov["evidence_end"] = evidence_end
    if evidence_file_id is not None:
        prov["evidence_file_id"] = evidence_file_id
    if case_id is not None:
        prov["case_id"] = case_id

    now = datetime.now(timezone.utc)
    return RecoveryRun(
        run_id=run_id,
        case_id=case_id,
        artifact_id=artifact_id,
        candidate_id=candidate_id,
        filename=filename,
        format=format,
        status=status,
        started_at=now,
        completed_at=now,
        total_input_bytes=verified_bytes + reconstructed_bytes + missing_bytes,
        total_verified_bytes=verified_bytes,
        total_reconstructed_bytes=reconstructed_bytes,
        total_missing_bytes=missing_bytes,
        confidence={"total": confidence_score},
        provenance=prov,
    )


# ==============================================================================
# 1. 1D Interval-Union Sweep Tests
# ==============================================================================

class TestIntervalUnionSweep:
    def test_empty_intervals(self):
        assert compute_interval_union_bytes([]) == 0

    def test_adjacent_intervals(self):
        # [0, 100) and [100, 200) -> union is [0, 200), size = 200
        assert compute_interval_union_bytes([(0, 100), (100, 200)]) == 200

    def test_overlapping_intervals(self):
        # [0, 150) and [100, 250) -> union is [0, 250), size = 250
        assert compute_interval_union_bytes([(0, 150), (100, 250)]) == 250

    def test_nested_intervals(self):
        # [0, 500) and [100, 200) -> union is [0, 500), size = 500
        assert compute_interval_union_bytes([(0, 500), (100, 200)]) == 500

    def test_disjoint_intervals(self):
        # [0, 100) and [200, 300) -> union size = 200
        assert compute_interval_union_bytes([(0, 100), (200, 300)]) == 200

    def test_complex_mixed_intervals(self):
        # [0, 50), [40, 100), [150, 200), [180, 220), [300, 400)
        # Unions: [0, 100) (size 100), [150, 220) (size 70), [300, 400) (size 100)
        # Total = 270
        intervals = [(0, 50), (40, 100), (150, 200), (180, 220), (300, 400)]
        assert compute_interval_union_bytes(intervals) == 270


# ==============================================================================
# 2. Critical Test Cases from Approved Design
# ==============================================================================

class TestCriticalCases:
    @pytest.fixture(autouse=True)
    def ensure_offline(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")

    def test_critical_case_a_coextensive(self):
        """CASE A — COEXTENSIVE:
        A: JSON [1000, 5000), verified=4000
        B: TXT  [1000, 5000), verified=4000
        Expected:
        - same physical region
        - competing interpretations
        - unique_physical_bytes = 4000
        - candidate_aggregate_verified_bytes = 8000
        - must never be described as 8000 physical recovered bytes
        """
        run_a = make_run("run_a", format="json", evidence_start=1000, evidence_end=5000, verified_bytes=4000)
        run_b = make_run("run_b", format="txt", evidence_start=1000, evidence_end=5000, verified_bytes=4000)
        graph = build_evidence_graph_from_runs([run_a, run_b], case_id="case_coext")

        assert len(graph.clusters) == 1
        cluster = graph.clusters[0]
        assert cluster.relationship_classification == "COEXTENSIVE_SET"

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp = service.interpret_cluster("case_coext", cluster.cluster_id, graph=graph)

        facts = interp.facts
        assert facts.bounding_span_bytes == 4000
        assert facts.unique_physical_bytes == 4000
        assert facts.candidate_aggregate_verified_bytes == 8000
        assert facts.coextensive_candidate_count == 2
        assert facts.competing_format_count == 2
        assert set(facts.member_formats) == {"json", "txt"}

        # Double counting protection verification:
        # Check that the interpretation explicitly states 4000 unique physical bytes vs 8000 aggregate bytes
        out = interp.interpretation
        assert "4000" in out.details[0]
        assert "8000" in out.details[1]
        assert "must NOT be treated as 8000 physical disk bytes" in out.limitations

    def test_critical_case_b_containment(self):
        """CASE B — CONTAINMENT:
        A: ZIP [0, 10000), verified=10000
        B: PNG [2000, 4000), verified=2000
        Expected:
        - two artifacts
        - unique_physical_bytes = 10000
        - candidate aggregate verified bytes = 12000
        - not automatically two competing hypotheses
        """
        run_a = make_run("run_zip", format="zip", evidence_start=0, evidence_end=10000, verified_bytes=10000)
        run_b = make_run("run_png", format="png", evidence_start=2000, evidence_end=4000, verified_bytes=2000)
        graph = build_evidence_graph_from_runs([run_a, run_b], case_id="case_cont")

        assert len(graph.clusters) == 1
        cluster = graph.clusters[0]
        assert cluster.relationship_classification == "CONTAINMENT_TREE"

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp = service.interpret_cluster("case_cont", cluster.cluster_id, graph=graph)

        facts = interp.facts
        assert facts.bounding_span_bytes == 10000
        assert facts.unique_physical_bytes == 10000
        assert facts.candidate_aggregate_verified_bytes == 12000
        assert facts.containment_edge_count == 1
        assert "Embedded inner artifacts represent nested payloads rather than competing format hypotheses" in interp.interpretation.structural_context

    def test_critical_case_c_disjoint(self):
        """CASE C — DISJOINT:
        A: TXT  [0, 1000), verified=1000
        B: JSON [2000, 3000), verified=1000
        Expected:
        - disjoint clusters in same buffer
        - bounding span envelope = 3000
        - unique physical bytes = 2000
        - do not report 3000 as unique physical coverage
        """
        run_a = make_run("run_txt", format="txt", evidence_start=0, evidence_end=1000, verified_bytes=1000)
        run_b = make_run("run_json", format="json", evidence_start=2000, evidence_end=3000, verified_bytes=1000)
        graph = build_evidence_graph_from_runs([run_a, run_b], case_id="case_disjoint")

        # Disjoint runs produce 2 isolated clusters in 3.4
        assert len(graph.clusters) == 2
        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        case_interp = service.interpret_case("case_disjoint", graph=graph)

        case_facts = case_interp.facts
        assert case_facts.case_physical_coverage_bytes == 2000
        assert case_facts.candidate_aggregate_verified_bytes == 2000

        # Verify buffer-level envelope vs physical coverage
        buf = graph.evidence_buffers[0]
        assert buf.total_byte_span == 3000  # coordinate envelope: max(3000) - min(0)
        assert case_facts.case_physical_coverage_bytes == 2000  # physical union!

    def test_critical_case_d_overlap(self):
        """CASE D — OVERLAP:
        A: [0, 5000), verified=5000
        B: [3000, 8000), verified=5000
        Expected:
        - unique_physical_bytes = 8000
        - intersection = 2000
        - candidates may or may not be competing depending on existing graph semantics
        - do not invent certainty
        """
        run_a = make_run("run_doc", format="docx", evidence_start=0, evidence_end=5000, verified_bytes=5000)
        run_b = make_run("run_sql", format="sqlite", evidence_start=3000, evidence_end=8000, verified_bytes=5000)
        graph = build_evidence_graph_from_runs([run_a, run_b], case_id="case_overlap")

        assert len(graph.clusters) == 1
        cluster = graph.clusters[0]
        assert cluster.relationship_classification == "OVERLAP_SPAN"

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp = service.interpret_cluster("case_overlap", cluster.cluster_id, graph=graph)

        facts = interp.facts
        assert facts.bounding_span_bytes == 8000
        assert facts.unique_physical_bytes == 8000
        assert facts.candidate_aggregate_verified_bytes == 10000
        assert facts.overlap_edge_count == 1
        assert "Spatial boundary conflict detected" in interp.interpretation.assessment
        assert "Recoverix strictly refused to guess whether overlapping bytes represent fragmentation" in interp.interpretation.limitations

    def test_critical_case_e_unbounded_end(self):
        """CASE E — UNKNOWN END:
        A: [0, None), verified=500
        Expected:
        - bounded physical union cannot be fully calculated
        - do not fabricate an end offset
        - unique_physical_bytes = None
        - bounding_span_bytes = None
        - bounded_physical_bytes remains available (0)
        """
        run_a = make_run("run_raw", format="bin", evidence_start=0, evidence_end=None, verified_bytes=500, status="PARTIALLY_RECOVERED")
        graph = build_evidence_graph_from_runs([run_a], case_id="case_unbounded")

        assert len(graph.clusters) == 1
        cluster = graph.clusters[0]

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp = service.interpret_cluster("case_unbounded", cluster.cluster_id, graph=graph)

        facts = interp.facts
        assert facts.cluster_end is None
        assert facts.bounding_span_bytes is None
        assert facts.unique_physical_bytes is None
        assert facts.bounded_physical_bytes == 0
        assert facts.has_unbounded_candidate is True
        assert facts.candidate_aggregate_verified_bytes == 500

        case_interp = service.interpret_case("case_unbounded", graph=graph)
        assert case_interp.facts.case_physical_coverage_bytes is None
        assert case_interp.facts.case_coverage_is_complete is False

    def test_critical_case_f_two_evidence_files(self):
        """CASE F — TWO EVIDENCE FILES:
        File 1: [0, 5000), verified=5000
        File 2: [0, 5000), verified=5000
        Expected:
        - separate evidence scopes
        - case physical coverage = 10000, not 5000
        - preserve evidence-file boundaries
        """
        run_1 = make_run("run_f1", evidence_file_id="file_alpha.raw", evidence_start=0, evidence_end=5000, verified_bytes=5000)
        run_2 = make_run("run_f2", evidence_file_id="file_beta.raw", evidence_start=0, evidence_end=5000, verified_bytes=5000)
        graph = build_evidence_graph_from_runs([run_1, run_2], case_id="case_multifile")

        assert len(graph.evidence_buffers) == 2
        assert len(graph.clusters) == 2

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        case_interp = service.interpret_case("case_multifile", graph=graph)

        assert case_interp.facts.total_evidence_buffers == 2
        assert case_interp.facts.case_physical_coverage_bytes == 10000
        assert case_interp.facts.candidate_aggregate_verified_bytes == 10000


# ==============================================================================
# 3. Cluster Classifications & Topology
# ==============================================================================

class TestClusterClassifications:
    @pytest.fixture(autouse=True)
    def ensure_offline(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")

    def test_isolated_cluster(self):
        run = make_run("run_single", format="pdf", evidence_start=100, evidence_end=2000, verified_bytes=1900)
        graph = build_evidence_graph_from_runs([run], case_id="case_iso")

        cluster = graph.clusters[0]
        assert cluster.relationship_classification == "ISOLATED"

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp = service.interpret_cluster("case_iso", cluster.cluster_id, graph=graph)

        facts = interp.facts
        assert facts.relationship_classification == "ISOLATED"
        assert facts.total_nodes == 1
        assert facts.coextensive_candidate_count == 0
        assert facts.containment_edge_count == 0
        assert facts.overlap_edge_count == 0
        assert "Uncontested extraction" in interp.interpretation.structural_context

    def test_mixed_topology_cluster(self):
        # A container containing B, and B partially overlapping C
        # A: [0, 10000)
        # B: [2000, 6000) (contained by A)
        # C: [4000, 8000) (contained by A, overlaps B)
        run_a = make_run("run_a", format="tar", evidence_start=0, evidence_end=10000, verified_bytes=10000)
        run_b = make_run("run_b", format="json", evidence_start=2000, evidence_end=6000, verified_bytes=4000)
        run_c = make_run("run_c", format="txt", evidence_start=4000, evidence_end=8000, verified_bytes=4000)
        graph = build_evidence_graph_from_runs([run_a, run_b, run_c], case_id="case_mix")

        assert len(graph.clusters) == 1
        cluster = graph.clusters[0]
        assert cluster.relationship_classification == "MIXED"

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp = service.interpret_cluster("case_mix", cluster.cluster_id, graph=graph)

        facts = interp.facts
        assert facts.relationship_classification == "MIXED"
        assert facts.containment_edge_count > 0
        assert facts.overlap_edge_count > 0
        assert "Complex hybrid spatial topology" in interp.interpretation.assessment


# ==============================================================================
# 4. Cache Correctness, Fingerprints, and Invalidation
# ==============================================================================

class TestCacheCorrectnessAndFingerprints:
    @pytest.fixture(autouse=True)
    def ensure_offline(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")

    def test_cluster_cache_hit_identical_fingerprint(self):
        run = make_run("run_cache", evidence_start=0, evidence_end=500, verified_bytes=500)
        graph = build_evidence_graph_from_runs([run], case_id="case_cache")
        cluster = graph.clusters[0]

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())

        interp1 = service.interpret_cluster("case_cache", cluster.cluster_id, graph=graph)
        assert interp1.cached is False

        interp2 = service.interpret_cluster("case_cache", cluster.cluster_id, graph=graph)
        assert interp2.cached is True
        assert interp1.cluster_fingerprint == interp2.cluster_fingerprint

    def test_cluster_cache_invalidation_when_node_changes(self):
        run_v1 = make_run("run_cache", evidence_start=0, evidence_end=500, verified_bytes=500)
        graph_v1 = build_evidence_graph_from_runs([run_v1], case_id="case_cache")
        cluster_v1 = graph_v1.clusters[0]

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp1 = service.interpret_cluster("case_cache", cluster_v1.cluster_id, graph=graph_v1)
        assert interp1.cached is False

        # Now simulate run updating verified bytes from 500 to 450
        run_v2 = make_run("run_cache", evidence_start=0, evidence_end=500, verified_bytes=450, reconstructed_bytes=50)
        graph_v2 = build_evidence_graph_from_runs([run_v2], case_id="case_cache")
        cluster_v2 = graph_v2.clusters[0]

        fp1 = compute_cluster_fingerprint(cluster_v1, graph_v1)
        fp2 = compute_cluster_fingerprint(cluster_v2, graph_v2)
        assert fp1 != fp2

        interp2 = service.interpret_cluster("case_cache", cluster_v2.cluster_id, graph=graph_v2)
        assert interp2.cached is False
        assert interp2.facts.candidate_aggregate_verified_bytes == 450

    def test_case_cache_hit_and_invalidation(self):
        run_1 = make_run("run_1", evidence_file_id="ev_1", evidence_start=0, evidence_end=100)
        run_2 = make_run("run_2", evidence_file_id="ev_2", evidence_start=0, evidence_end=200)
        graph_v1 = build_evidence_graph_from_runs([run_1, run_2], case_id="case_c")

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        case_interp1 = service.interpret_case("case_c", graph=graph_v1)
        assert case_interp1.cached is False

        case_interp2 = service.interpret_case("case_c", graph=graph_v1)
        assert case_interp2.cached is True

        # Modify run_2: changes case fingerprint
        run_2_mod = make_run("run_2", evidence_file_id="ev_2", evidence_start=0, evidence_end=300, verified_bytes=300)
        graph_v2 = build_evidence_graph_from_runs([run_1, run_2_mod], case_id="case_c")

        case_interp3 = service.interpret_case("case_c", graph=graph_v2)
        assert case_interp3.cached is False
        assert case_interp3.facts.case_physical_coverage_bytes == 400

    def test_force_refresh_bypasses_cache(self):
        run = make_run("run_rf", evidence_start=0, evidence_end=500, verified_bytes=500)
        graph = build_evidence_graph_from_runs([run], case_id="case_rf")
        cluster = graph.clusters[0]

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        interp1 = service.interpret_cluster("case_rf", cluster.cluster_id, graph=graph)
        assert interp1.cached is False

        # Force refresh must return freshly generated interpretation
        interp_refresh = service.interpret_cluster("case_rf", cluster.cluster_id, graph=graph, force_refresh=True)
        assert interp_refresh.cached is False

    def test_bounded_cache_eviction(self):
        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        service._max_cluster_cache_size = 2

        # Create dummy interpretations
        mock_output = ProviderInterpretationOutput(
            summary="s", assessment="a", structural_context="sc",
            limitations="l", recommended_next_steps="r", details=[]
        )
        def dummy_interp(cid: str) -> GroundedClusterInterpretation:
            facts = DeterministicClusterFacts(
                cluster_id=cid, case_id="c", cluster_start=0, relationship_classification="ISOLATED",
                has_ambiguity=False, total_nodes=1, member_formats=["json"], member_node_ids=["n1"],
                max_confidence_score=90.0, highest_priority="LOW", candidate_aggregate_verified_bytes=100
            )
            return GroundedClusterInterpretation(
                facts=facts, interpretation=mock_output, source="DETERMINISTIC_RULES",
                cached=False, generated_at="2026-01-01T00:00:00", cluster_fingerprint=f"fp_{cid}"
            )

        k1 = ("c", "cl_1", "fp_cl_1")
        k2 = ("c", "cl_2", "fp_cl_2")
        k3 = ("c", "cl_3", "fp_cl_3")

        service._put_cluster_cache(k1, dummy_interp("cl_1"))
        service._put_cluster_cache(k2, dummy_interp("cl_2"))
        assert len(service._cluster_cache) == 2

        # Adding 3rd should evict k1
        service._put_cluster_cache(k3, dummy_interp("cl_3"))
        assert len(service._cluster_cache) == 2
        assert k1 not in service._cluster_cache
        assert k2 in service._cluster_cache
        assert k3 in service._cluster_cache


# ==============================================================================
# 5. Case-Level Accounting & Budget Caps
# ==============================================================================

class TestCaseAccountingAndCaps:
    @pytest.fixture(autouse=True)
    def ensure_offline(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")

    def test_case_facts_with_unscoped_nodes(self):
        # One scoped node and one unscoped node (evidence_file_id is None)
        run_scoped = make_run("run_sc", evidence_file_id="buf_01", evidence_start=0, evidence_end=1000, verified_bytes=1000)
        run_unscoped = make_run("run_unsc", evidence_file_id=None, evidence_start=0, evidence_end=500, verified_bytes=500)
        graph = build_evidence_graph_from_runs([run_scoped, run_unscoped], case_id="case_unsc")

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        case_interp = service.interpret_case("case_unsc", graph=graph)

        facts = case_interp.facts
        assert facts.total_nodes == 2
        # Unscoped candidate must be excluded from physical coverage
        assert facts.case_physical_coverage_bytes == 1000
        assert facts.unscoped_candidate_count == 1
        assert facts.unscoped_aggregate_verified_bytes == 500
        assert facts.candidate_aggregate_verified_bytes == 1500
        assert "Unscoped Candidates: 1 candidate(s)" in case_interp.interpretation.details[-1]

    def test_case_facts_with_candidate_cap_enforced(self):
        run = make_run("run_cap", evidence_start=0, evidence_end=1000, verified_bytes=1000)
        cap_meta = {
            "candidate_cap_enforced": True,
            "total_discovered_candidates": 50,
            "candidates_omitted": 49,
        }
        graph = build_evidence_graph_from_runs([run], case_id="case_cap", candidate_cap_metadata=cap_meta)

        service = InterpretationService(fallback_provider=DeterministicRuleProvider())
        case_interp = service.interpret_case("case_cap", graph=graph)

        facts = case_interp.facts
        assert facts.candidate_cap_enforced is True
        assert facts.candidates_omitted == 49
        assert facts.graph_is_complete is False

        # Verify warning in briefing details and limitations
        details_text = " ".join(case_interp.interpretation.details)
        assert "Candidate Budget Cap: ENFORCED (49 candidate(s) omitted" in details_text
        assert "Candidate cap was enforced: 49 candidate(s) were omitted" in case_interp.interpretation.limitations


# ==============================================================================
# 6. Offline Mode & Provider Fallbacks
# ==============================================================================

class TestOfflineModeAndFallback:
    def test_deterministic_cluster_interpretation_ignores_api_key(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")
        monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")

        provider = DeterministicRuleProvider()
        run = make_run("run_off", evidence_start=0, evidence_end=100)
        graph = build_evidence_graph_from_runs([run], case_id="c_off")
        cluster = graph.clusters[0]

        facts = InterpretationService.extract_cluster_facts(cluster, graph, "c_off")
        ctx = ClusterInterpretationContext(facts=facts)
        out = provider.interpret_cluster(ctx)
        assert "Grounded cluster synthesis" in out.summary

    def test_interpretation_service_deterministic_cluster_and_case(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")
        monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")

        service = InterpretationService()
        run = make_run("run_fb", evidence_start=0, evidence_end=100)
        graph = build_evidence_graph_from_runs([run], case_id="c_fb")
        cluster = graph.clusters[0]

        cluster_interp = service.interpret_cluster("c_fb", cluster.cluster_id, graph=graph)
        assert cluster_interp.source == "DETERMINISTIC_RULES"

        case_interp = service.interpret_case("c_fb", graph=graph)
        assert case_interp.source == "DETERMINISTIC_RULES"

    def test_custom_provider_protocol_mock(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "0")
        monkeypatch.setenv("GEMINI_API_KEY", "dummy_key")

        mock_provider = MagicMock(spec=InterpretationProvider)
        mock_output = ProviderInterpretationOutput(
            summary="Custom synthesized cluster.",
            assessment="No corrupted regions found.",
            structural_context="Valid JSON container.",
            limitations="No speculative data.",
            recommended_next_steps="Export artifact.",
            details=["Point 1", "Point 2"],
        )
        mock_provider.interpret_cluster.return_value = mock_output

        service = InterpretationService(provider=mock_provider)

        run = make_run("run_gem", evidence_start=0, evidence_end=100)
        graph = build_evidence_graph_from_runs([run], case_id="c_gem")
        cluster = graph.clusters[0]

        cluster_interp = service.interpret_cluster("c_gem", cluster.cluster_id, graph=graph)
        assert cluster_interp.source == "DETERMINISTIC_RULES"
        assert cluster_interp.interpretation.summary == "Custom synthesized cluster."


# ==============================================================================
# 7. Model Immutability & Fact Protection
# ==============================================================================

class TestModelImmutability:
    def test_cluster_facts_frozen(self):
        facts = DeterministicClusterFacts(
            cluster_id="cl_1",
            case_id="case_1",
            cluster_start=0,
            relationship_classification="ISOLATED",
            has_ambiguity=False,
            total_nodes=1,
            member_formats=["json"],
            member_node_ids=["n1"],
            max_confidence_score=90.0,
            highest_priority="LOW",
            candidate_aggregate_verified_bytes=100,
        )
        with pytest.raises(ValidationError):
            facts.total_nodes = 5  # type: ignore[misc]

    def test_case_facts_frozen(self):
        facts = DeterministicCaseFacts(
            case_id="case_1",
            total_evidence_buffers=1,
            total_artifacts=1,
            total_nodes=1,
            total_clusters=1,
            candidate_aggregate_verified_bytes=100,
        )
        with pytest.raises(ValidationError):
            facts.case_physical_coverage_bytes = 9999  # type: ignore[misc]


# ==============================================================================
# 8. Additional Robustness & Edge Cases
# ==============================================================================

class TestDeterministicProviderAndRobustness:
    def test_deterministic_cluster_synthesis_constraints(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")
        provider = DeterministicRuleProvider()

        run = make_run("run_1", evidence_start=1000, evidence_end=5000, verified_bytes=4000)
        graph = build_evidence_graph_from_runs([run], case_id="c_cluster_facts")
        cluster = graph.clusters[0]

        facts = InterpretationService.extract_cluster_facts(cluster, graph, "c_cluster_facts")
        ctx = ClusterInterpretationContext(facts=facts)
        out = provider.interpret_cluster(ctx)

        assert "Grounded cluster synthesis" in out.summary
        assert "Zero heuristic spatial assumptions" in out.limitations

    def test_deterministic_case_synthesis_constraints(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")
        provider = DeterministicRuleProvider()

        run = make_run("run_1", evidence_start=0, evidence_end=1000, verified_bytes=1000)
        graph = build_evidence_graph_from_runs([run], case_id="c_case_facts")

        facts = InterpretationService.extract_case_facts(graph, "c_case_facts")
        ctx = CaseInterpretationContext(facts=facts)
        out = provider.interpret_case(ctx)

        assert "Executive forensic briefing" in out.summary
        assert "investigation reporting" in out.recommended_next_steps

    def test_deterministic_service_ignores_external_ai_env(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "0")
        monkeypatch.setenv("GEMINI_API_KEY", "test_key")

        mock_client = MagicMock()
        with patch("httpx.Client", return_value=mock_client):
            service = InterpretationService()
            run = make_run("run_bad", evidence_start=0, evidence_end=100)
            graph = build_evidence_graph_from_runs([run], case_id="c_bad_json")
            cluster = graph.clusters[0]

            interp = service.interpret_cluster("c_bad_json", cluster.cluster_id, graph=graph)
            assert interp.source == "DETERMINISTIC_RULES"
            mock_client.assert_not_called()

    def test_empty_case_synthesis(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")
        graph = build_evidence_graph_from_runs([], case_id="c_empty")
        service = InterpretationService(fallback_provider=DeterministicRuleProvider())

        case_interp = service.interpret_case("c_empty", graph=graph)
        assert case_interp.facts.total_nodes == 0
        assert case_interp.facts.total_clusters == 0
        assert case_interp.facts.case_physical_coverage_bytes == 0
        assert case_interp.source == "DETERMINISTIC_RULES"

    def test_cluster_not_found_raises_key_error(self, monkeypatch):
        monkeypatch.setenv("RECOVERIX_OFFLINE", "1")
        run = make_run("run_1", evidence_start=0, evidence_end=100)
        graph = build_evidence_graph_from_runs([run], case_id="c_kf")
        service = InterpretationService(fallback_provider=DeterministicRuleProvider())

        with pytest.raises(KeyError, match="Cluster 'cluster_non_existent' not found"):
            service.interpret_cluster("c_kf", "cluster_non_existent", graph=graph)
