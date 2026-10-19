"""
interpretation_service.py — Canonical Grounded Evidence Interpretation Service.

Milestone 3.5.1: The single canonical interpretation pipeline for Recoverix.
Enforces that deterministic recovery facts are strictly immutable and system-owned,
coordinates provider dispatch, handles safe fallback, and persists interpretations to SQLite.
"""

from __future__ import annotations

import os
import re
import json
import logging
import hashlib
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from backend.app.models.interpretation import (
    DeterministicArtifactFacts,
    DeterministicRelationshipFact,
    DeterministicClusterFacts,
    DeterministicCaseFacts,
    ArtifactInterpretationContext,
    ClusterInterpretationContext,
    CaseInterpretationContext,
    ProviderInterpretationOutput,
    GroundedArtifactInterpretation,
    GroundedClusterInterpretation,
    GroundedCaseInterpretation,
    AuthoritativeRecoveryStatus,
)
from backend.app.models.evidence_graph import (
    EvidenceGraph,
    ArtifactCluster,
    GraphNode,
    GraphEdge,
)
from backend.app.scoring.providers import (
    InterpretationProvider,
    DeterministicRuleProvider,
)
from backend.app.scoring.priority import determine_priority
from backend.app.scoring.classifier import classify_artifact

logger = logging.getLogger(__name__)

_GLOBAL_SERVICE: Optional[InterpretationService] = None


def compute_interval_union_bytes(intervals: List[Tuple[int, int]]) -> int:
    """Compute the total byte length of the union of half-open intervals [start, end).

    Deterministic, handles adjacent, overlapping, nested, and disjoint intervals.
    """
    if not intervals:
        return 0
    valid = [iv for iv in intervals if iv[1] > iv[0]]
    if not valid:
        return 0
    sorted_intervals = sorted(valid, key=lambda x: (x[0], x[1]))

    total_bytes = 0
    cur_start, cur_end = sorted_intervals[0]

    for s, e in sorted_intervals[1:]:
        if s <= cur_end:
            # Overlapping or adjacent: extend current interval
            if e > cur_end:
                cur_end = e
        else:
            # Disjoint gap: commit previous interval and advance
            total_bytes += (cur_end - cur_start)
            cur_start, cur_end = s, e

    total_bytes += (cur_end - cur_start)
    return total_bytes


def compute_cluster_fingerprint(cluster: ArtifactCluster, graph: EvidenceGraph) -> str:
    """Compute a deterministic SHA-256 fingerprint for a spatial cluster in an evidence graph."""
    c_node_ids = set(cluster.node_ids)
    member_nodes = sorted(
        [n for n in graph.nodes if n.node_id in c_node_ids],
        key=lambda n: n.node_id,
    )
    node_tuples = [
        (
            n.node_id,
            n.run_id,
            n.format,
            n.status,
            float(n.confidence_score),
            int(n.verified_bytes),
            int(n.reconstructed_bytes),
            int(n.missing_bytes),
            n.evidence_start,
            n.evidence_end,
            bool(n.is_ambiguous),
        )
        for n in member_nodes
    ]

    internal_edges = sorted(
        [
            e
            for e in graph.edges
            if e.source_node_id in c_node_ids and e.target_node_id in c_node_ids
        ],
        key=lambda e: e.edge_id,
    )
    edge_tuples = [
        (
            e.edge_id,
            e.source_node_id,
            e.target_node_id,
            e.relationship_type,
            e.overlap_start,
            e.overlap_end,
            int(e.overlap_bytes),
        )
        for e in internal_edges
    ]

    cluster_meta = (
        cluster.cluster_id,
        cluster.evidence_file_id,
        cluster.cluster_start,
        cluster.cluster_end,
        cluster.relationship_classification,
        bool(cluster.has_ambiguity),
        cluster.total_nodes,
        sorted(list(cluster.formats)),
    )

    payload = {
        "cluster": cluster_meta,
        "nodes": node_tuples,
        "edges": edge_tuples,
    }
    canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()[:16]


def compute_case_graph_fingerprint(graph: EvidenceGraph) -> str:
    """Compute a deterministic SHA-256 fingerprint for an entire case evidence graph."""
    cluster_fps = sorted(
        [
            (c.cluster_id, compute_cluster_fingerprint(c, graph))
            for c in graph.clusters
        ],
        key=lambda x: x[0],
    )
    buffer_tuples = [
        (
            b.evidence_file_id,
            b.total_nodes,
            b.total_edges,
            b.total_clusters,
            b.total_byte_span,
            b.candidate_cap_enforced,
            b.total_discovered_candidates,
            b.candidates_omitted,
            b.buffer_is_complete,
        )
        for b in sorted(graph.evidence_buffers, key=lambda x: x.evidence_file_id)
    ]
    meta_tuple = (
        graph.metadata.case_id,
        graph.metadata.total_evidence_buffers,
        graph.metadata.total_nodes,
        graph.metadata.total_edges,
        graph.metadata.total_clusters,
        graph.metadata.candidate_cap_enforced,
        graph.metadata.total_discovered_candidates,
        graph.metadata.candidates_omitted,
        graph.metadata.graph_is_complete,
    )
    payload = {
        "clusters": cluster_fps,
        "buffers": buffer_tuples,
        "meta": meta_tuple,
    }
    canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()[:16]


class InterpretationService:
    """Canonical service for grounded evidence interpretation."""

    def __init__(
        self,
        provider: Optional[InterpretationProvider] = None,
        fallback_provider: Optional[InterpretationProvider] = None,
        store: Any = None,
        *,
        primary_provider: Optional[InterpretationProvider] = None,
    ):
        self._provider = provider or primary_provider or fallback_provider or DeterministicRuleProvider()
        self._fallback_provider = self._provider
        self._primary_provider = self._provider
        self._store = store
        self._cluster_cache: OrderedDict[Tuple[str, str, str], GroundedClusterInterpretation] = OrderedDict()
        self._case_cache: OrderedDict[Tuple[str, str], GroundedCaseInterpretation] = OrderedDict()
        self._max_cluster_cache_size = 1000
        self._max_case_cache_size = 100

    def _put_cluster_cache(
        self, key: Tuple[str, str, str], value: GroundedClusterInterpretation
    ) -> None:
        self._cluster_cache[key] = value
        self._cluster_cache.move_to_end(key)
        if len(self._cluster_cache) > self._max_cluster_cache_size:
            self._cluster_cache.popitem(last=False)

    def _put_case_cache(
        self, key: Tuple[str, str], value: GroundedCaseInterpretation
    ) -> None:
        self._case_cache[key] = value
        self._case_cache.move_to_end(key)
        if len(self._case_cache) > self._max_case_cache_size:
            self._case_cache.popitem(last=False)

    @staticmethod
    def sanitize_preview(raw_preview: Optional[str]) -> Optional[str]:
        """Sanitize and truncate content preview.

        Security boundary disclosure:
        - Bounded to maximum 200 characters.
        - Binary noise and ASCII control characters are stripped.
        - Obvious token and high-entropy secret patterns are redacted.
        - Sanitization reduces obvious leakage patterns but does NOT guarantee detection
          or removal of every sensitive datum. Content preview remains potentially sensitive.
        """
        if not raw_preview:
            return None

        # Truncate strictly to <= 200 chars
        truncated = str(raw_preview)[:200]

        # Strip unprintable binary and ASCII control characters
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]", "", truncated)

        # Redact common token and secret patterns
        cleaned = re.sub(r"Bearer\s+[A-Za-z0-9_\-\.]+", "Bearer [REDACTED]", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"(?:api[_-]?key|password|secret[_-]?key|secret|private[_-]?key)\s*[:=]\s*[^\s]+", "[REDACTED_SECRET]", cleaned, flags=re.IGNORECASE)

        return cleaned.strip()

    @staticmethod
    def extract_artifact_facts(artifact: Any, artifact_id: Optional[str] = None) -> DeterministicArtifactFacts:
        """Extract immutable deterministic facts safely from any artifact/run/dict structure."""
        if isinstance(artifact, dict):
            d = artifact
        elif hasattr(artifact, "model_dump"):
            d = artifact.model_dump()
        elif hasattr(artifact, "__dict__"):
            d = artifact.__dict__
        else:
            d = {}

        art_id = str(
            artifact_id
            or getattr(artifact, "artifact_id", None)
            or getattr(artifact, "node_id", None)
            or getattr(artifact, "candidate_id", None)
            or getattr(artifact, "file_id", None)
            or d.get("artifact_id")
            or d.get("node_id")
            or d.get("candidate_id")
            or d.get("file_id")
            or "unknown_artifact"
        )
        run_id = getattr(artifact, "run_id", None) or d.get("run_id")
        case_id = getattr(artifact, "case_id", None) or d.get("case_id")

        fmt = str(getattr(artifact, "format", None) or d.get("format") or "unknown").lower()
        filename = str(
            getattr(artifact, "filename", None)
            or getattr(artifact, "original_filename", None)
            or getattr(artifact, "recovered_filename", None)
            or d.get("filename")
            or d.get("original_filename")
            or d.get("recovered_filename")
            or f"evidence.{fmt}"
        )

        preview = str(getattr(artifact, "content_preview", None) or d.get("content_preview") or "")

        # Category
        category = getattr(artifact, "category", None) or d.get("category")
        if not category:
            category = classify_artifact(fmt, preview)
        category = str(category)

        # Authoritative Status
        raw_status = str(getattr(artifact, "status", None) or d.get("status") or "UNRECOVERABLE").upper()
        if raw_status in ("FULLY_RECOVERED", "PARTIALLY_RECOVERED", "CORRUPTED", "UNRECOVERABLE"):
            status: AuthoritativeRecoveryStatus = raw_status  # type: ignore[assignment]
        else:
            status = "UNRECOVERABLE"

        # Byte Accounting ($V, R, M$) and Provenance
        prov = getattr(artifact, "provenance", None) or d.get("provenance")
        v_bytes = 0
        r_bytes = 0
        m_bytes = 0
        method = "NONE"
        validation_status = "PASSED" if status != "UNRECOVERABLE" else "FAILED"
        ev_file_id = None
        ev_start = None
        ev_end = None

        if prov is not None:
            if isinstance(prov, dict):
                v_bytes = prov.get("verified_bytes") or 0
                r_bytes = prov.get("reconstructed_bytes") or 0
                m_bytes = prov.get("missing_bytes") or 0
                method = prov.get("reconstruction_method") or "NONE"
                validation_status = (
                    prov.get("validation_status")
                    or ("PASSED" if status != "UNRECOVERABLE" else "FAILED")
                )
                ev_file_id = prov.get("evidence_file_id")
                ev_start = prov.get("evidence_start")
                ev_end = prov.get("evidence_end")
            else:
                v_bytes = getattr(prov, "verified_bytes", 0) or 0
                r_bytes = getattr(prov, "reconstructed_bytes", 0) or 0
                m_bytes = getattr(prov, "missing_bytes", 0) or 0
                method = getattr(prov, "reconstruction_method", "NONE") or "NONE"
                validation_status = (
                    getattr(prov, "validation_status", None)
                    or ("PASSED" if status != "UNRECOVERABLE" else "FAILED")
                )
                ev_file_id = getattr(prov, "evidence_file_id", None)
                ev_start = getattr(prov, "evidence_start", None)
                ev_end = getattr(prov, "evidence_end", None)

        if not v_bytes:
            v_bytes = (
                getattr(artifact, "verified_bytes", None)
                or getattr(artifact, "total_verified_bytes", None)
                or d.get("verified_bytes")
                or d.get("total_verified_bytes")
                or 0
            )
        if not r_bytes:
            r_bytes = (
                getattr(artifact, "reconstructed_bytes", None)
                or getattr(artifact, "total_reconstructed_bytes", None)
                or d.get("reconstructed_bytes")
                or d.get("total_reconstructed_bytes")
                or 0
            )
        if not m_bytes:
            m_bytes = (
                getattr(artifact, "missing_bytes", None)
                or getattr(artifact, "total_missing_bytes", None)
                or d.get("missing_bytes")
                or d.get("total_missing_bytes")
                or 0
            )
        if not method or method == "NONE":
            method = (
                getattr(artifact, "reconstruction_method", None)
                or d.get("reconstruction_method")
                or (d.get("reconstruction_steps", [{}])[0].get("method") if d.get("reconstruction_steps") else "NONE")
            )
        if not validation_status:
            validation_status = (
                getattr(artifact, "validation_status", None)
                or d.get("validation_status")
                or ("PASSED" if status != "UNRECOVERABLE" else "FAILED")
            )

        v_bytes = int(v_bytes)
        r_bytes = int(r_bytes)
        m_bytes = int(m_bytes)
        method = str(method)
        validation_status = str(validation_status)

        total_input_bytes = (
            getattr(artifact, "total_input_bytes", None)
            or d.get("total_input_bytes")
            or (v_bytes + r_bytes + m_bytes if (v_bytes + r_bytes + m_bytes) > 0 else None)
        )
        if total_input_bytes is not None:
            total_input_bytes = int(total_input_bytes)

        # Coordinates and metadata
        if not ev_file_id:
            ev_file_id = getattr(artifact, "evidence_file_id", None) or d.get("evidence_file_id")
        if ev_start is None:
            ev_start = getattr(artifact, "evidence_start", None) or d.get("evidence_start")
        if ev_end is None:
            ev_end = getattr(artifact, "evidence_end", None) or d.get("evidence_end")

        # Confidence Score (0.0 to 100.0)
        score: Any = 0
        if hasattr(artifact, "confidence_score") and artifact.confidence_score is not None:
            score = artifact.confidence_score
        elif hasattr(artifact, "confidence") and isinstance(artifact.confidence, dict):
            score = artifact.confidence.get("total", 0)
        elif hasattr(artifact, "confidence") and isinstance(artifact.confidence, (int, float)):
            score = artifact.confidence
        elif "confidence_score" in d and d["confidence_score"] is not None:
            score = d["confidence_score"]
        elif "confidence" in d and isinstance(d["confidence"], dict):
            score = d["confidence"].get("total", 0)
        elif "confidence" in d and isinstance(d["confidence"], (int, float)):
            score = d["confidence"]

        try:
            score_float = float(score)
            if score_float < 0.0:
                score_float = 0.0
            elif score_float > 100.0:
                score_float = 100.0
        except (ValueError, TypeError):
            score_float = 0.0

        # Deterministic Priority
        priority = getattr(artifact, "priority", None) or d.get("priority")
        if not priority or priority == "Unknown":
            priority = determine_priority(category, preview, status)
            if status == "PARTIALLY_RECOVERED" and m_bytes > 0 and priority != "CRITICAL":
                priority = "HIGH"
            elif status == "FULLY_RECOVERED" and priority not in ("CRITICAL", "HIGH"):
                priority = "LOW"
            elif status == "UNRECOVERABLE":
                priority = "LOW"

        priority_str = str(priority).upper()
        if priority_str not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            priority_str = "LOW"


        damage_regions = getattr(artifact, "damage_regions", None) or d.get("damage_regions") or []
        damage_count = len(damage_regions) if isinstance(damage_regions, list) else 0

        is_ambiguous = bool(getattr(artifact, "is_ambiguous", None) or d.get("is_ambiguous") or False)

        return DeterministicArtifactFacts(
            artifact_id=art_id,
            run_id=run_id,
            case_id=case_id,
            evidence_file_id=ev_file_id,
            filename=filename,
            format=fmt,
            category=category,
            status=status,
            confidence_score=score_float,
            priority=priority_str,  # type: ignore[arg-type]
            verified_bytes=v_bytes,
            reconstructed_bytes=r_bytes,
            missing_bytes=m_bytes,
            total_input_bytes=total_input_bytes,
            reconstruction_method=method,
            validation_status=validation_status,
            damage_region_count=damage_count,
            is_ambiguous=is_ambiguous,
            evidence_start=int(ev_start) if ev_start is not None else None,
            evidence_end=int(ev_end) if ev_end is not None else None,
        )

    def _invoke_with_fallback(
        self, context: ArtifactInterpretationContext
    ) -> Tuple[ProviderInterpretationOutput, str]:
        """Invoke deterministic provider."""
        output = self._provider.interpret_artifact(context)
        return output, "DETERMINISTIC_RULES"

    def interpret_artifact(
        self,
        artifact_id: str,
        artifact: Any,
        force_refresh: bool = False,
        include_preview: bool = True,
    ) -> GroundedArtifactInterpretation:
        """Interpret a single artifact with caching, persistence, and safe fallback."""
        # 1. Check existing persistence or cache if refresh is not forced
        if not force_refresh:
            existing_summary = getattr(artifact, "ai_summary", None)
            if existing_summary:
                try:
                    data = (
                        json.loads(existing_summary)
                        if isinstance(existing_summary, str)
                        else existing_summary
                    )
                    if isinstance(data, dict) and "facts" in data and "interpretation" in data:
                        return GroundedArtifactInterpretation.model_validate(data).with_cached(True)
                except Exception as e:
                    logger.warning(
                        f"Persisted ai_summary for artifact '{artifact_id}' was malformed: {e}. "
                        "Regenerating interpretation safely without crashing."
                    )

        # 2. Extract immutable deterministic facts
        facts = self.extract_artifact_facts(artifact, artifact_id=artifact_id)

        # 3. Sanitize preview (strictly bounded to <= 200 chars; never raw bytes)
        raw_preview = getattr(artifact, "content_preview", None)
        if raw_preview is None and isinstance(artifact, dict):
            raw_preview = artifact.get("content_preview")
        preview = self.sanitize_preview(raw_preview) if include_preview else None

        # 4. Build context
        context = ArtifactInterpretationContext(facts=facts, content_preview=preview)

        # 5. Invoke provider with fallback
        output, source = self._invoke_with_fallback(context)

        # 6. Fact binding: system facts strictly bound, discarding any provider overrides
        interpretation = GroundedArtifactInterpretation(
            facts=facts,
            interpretation=output,
            source=source,  # type: ignore[arg-type]
            cached=False,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        # 7. Persist to SQLite if store is available
        if self._store is not None and hasattr(self._store, "update_artifact_ai_summary"):
            try:
                self._store.update_artifact_ai_summary(
                    artifact_id=artifact_id,
                    ai_summary=json.dumps(interpretation.model_dump()),
                )
            except Exception as e:
                logger.warning(f"Failed to persist ai_summary to SQLite for artifact '{artifact_id}': {e}")

        # Update in-memory artifact object if attribute exists
        if hasattr(artifact, "ai_summary"):
            try:
                artifact.ai_summary = json.dumps(interpretation.model_dump())
            except Exception:
                pass

        return interpretation

    @classmethod
    def extract_cluster_facts(
        cls, cluster: ArtifactCluster, graph: EvidenceGraph, case_id: str
    ) -> DeterministicClusterFacts:
        """Extract immutable deterministic facts for an artifact cluster."""
        c_node_ids = set(cluster.node_ids)
        member_nodes = [n for n in graph.nodes if n.node_id in c_node_ids]
        internal_edges = [
            e
            for e in graph.edges
            if e.source_node_id in c_node_ids and e.target_node_id in c_node_ids
        ]

        # Intervals & Physical bounds
        bounded_intervals = [
            (n.evidence_start, n.evidence_end)
            for n in member_nodes
            if n.evidence_end is not None
        ]
        has_unbounded = any(n.evidence_end is None for n in member_nodes)

        bounded_bytes = compute_interval_union_bytes(bounded_intervals)

        if has_unbounded:
            bounding_span = None
            unique_phys = None
        else:
            bounding_span = (
                (cluster.cluster_end - cluster.cluster_start)
                if cluster.cluster_end is not None
                else None
            )
            unique_phys = bounded_bytes

        # Hypothesis classifications & counts
        rel_class = cluster.relationship_classification
        if rel_class == "COEXTENSIVE_SET":
            coext_count = len(member_nodes)
        else:
            coext_nodes: Set[str] = set()
            for e in internal_edges:
                if e.relationship_type == "COEXTENSIVE":
                    coext_nodes.add(e.source_node_id)
                    coext_nodes.add(e.target_node_id)
            coext_count = len(coext_nodes)

        containment_pairs = {
            frozenset([e.source_node_id, e.target_node_id])
            for e in internal_edges
            if e.relationship_type in ("CONTAINS", "CONTAINED_BY")
        }
        cont_edges = len(containment_pairs)

        overlap_pairs = {
            frozenset([e.source_node_id, e.target_node_id])
            for e in internal_edges
            if e.relationship_type == "OVERLAPS"
        }
        ovlp_edges = len(overlap_pairs)

        if rel_class == "COEXTENSIVE_SET":
            competing_fmts = len(set(cluster.formats))
        else:
            conflict_nodes: Set[str] = set()
            for e in internal_edges:
                if e.relationship_type in ("COEXTENSIVE", "OVERLAPS"):
                    conflict_nodes.add(e.source_node_id)
                    conflict_nodes.add(e.target_node_id)
            conflict_fmts = {
                n.format for n in member_nodes if n.node_id in conflict_nodes
            }
            competing_fmts = len(conflict_fmts)

        # Status and Priority Rollup
        status_dist: Dict[str, int] = {}
        for n in member_nodes:
            status_dist[n.status] = status_dist.get(n.status, 0) + 1

        member_art_facts = [cls.extract_artifact_facts(n) for n in member_nodes]
        priorities = [af.priority for af in member_art_facts]

        priority_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        highest_prio = "LOW"
        highest_val = 0
        for p in priorities:
            val = priority_order.get(p, 1)
            if val > highest_val:
                highest_val = val
                highest_prio = p

        max_conf = max((n.confidence_score for n in member_nodes), default=0.0)
        total_damage = sum(af.damage_region_count for af in member_art_facts)

        # Candidate aggregate volumes
        agg_v = sum(n.verified_bytes for n in member_nodes)
        agg_r = sum(n.reconstructed_bytes for n in member_nodes)
        agg_m = sum(n.missing_bytes for n in member_nodes)

        return DeterministicClusterFacts(
            cluster_id=cluster.cluster_id,
            case_id=case_id,
            evidence_file_id=cluster.evidence_file_id,
            cluster_start=cluster.cluster_start,
            cluster_end=cluster.cluster_end,
            bounding_span_bytes=bounding_span,
            unique_physical_bytes=unique_phys,
            bounded_physical_bytes=bounded_bytes,
            has_unbounded_candidate=has_unbounded,
            relationship_classification=rel_class,  # type: ignore[arg-type]
            has_ambiguity=cluster.has_ambiguity,
            total_nodes=cluster.total_nodes,
            coextensive_candidate_count=coext_count,
            containment_edge_count=cont_edges,
            overlap_edge_count=ovlp_edges,
            competing_format_count=competing_fmts,
            member_formats=sorted(list(set(cluster.formats))),
            member_node_ids=sorted(list(cluster.node_ids)),
            max_confidence_score=float(max_conf),
            highest_priority=highest_prio,  # type: ignore[arg-type]
            candidate_aggregate_verified_bytes=agg_v,
            candidate_aggregate_reconstructed_bytes=agg_r,
            candidate_aggregate_missing_bytes=agg_m,
            status_distribution=status_dist,
            total_damage_regions=total_damage,
        )

    @classmethod
    def extract_case_facts(
        cls, graph: EvidenceGraph, case_id: str
    ) -> DeterministicCaseFacts:
        """Extract immutable deterministic facts aggregated across an entire case."""
        total_buffers = len(graph.evidence_buffers)
        total_artifacts = len(graph.nodes)
        total_nodes = len(graph.nodes)
        total_clusters = len(graph.clusters)

        # Buffer-by-buffer physical coverage
        clusters_by_file: Dict[Optional[str], List[ArtifactCluster]] = {}
        for c in graph.clusters:
            clusters_by_file.setdefault(c.evidence_file_id, []).append(c)

        case_phys_cov: Optional[int] = 0
        case_cov_complete = True

        for ev_file_id, clusters in clusters_by_file.items():
            if ev_file_id is None:
                # Unscoped candidates are excluded from physical coverage!
                continue
            for c in clusters:
                c_facts = cls.extract_cluster_facts(c, graph, case_id=case_id)
                if c_facts.unique_physical_bytes is None:
                    case_cov_complete = False
                    case_phys_cov = None
                elif case_phys_cov is not None:
                    case_phys_cov += c_facts.unique_physical_bytes

        # Unscoped tracking
        unscoped_nodes = [n for n in graph.nodes if n.evidence_file_id is None]
        unscoped_count = len(unscoped_nodes)
        unscoped_v = sum(n.verified_bytes for n in unscoped_nodes)

        # Candidate aggregate metrics across all nodes
        agg_v = sum(n.verified_bytes for n in graph.nodes)
        agg_r = sum(n.reconstructed_bytes for n in graph.nodes)
        agg_m = sum(n.missing_bytes for n in graph.nodes)

        # Distributions
        fmt_dist: Dict[str, int] = {}
        for n in graph.nodes:
            fmt_dist[n.format] = fmt_dist.get(n.format, 0) + 1

        status_dist: Dict[str, int] = {}
        for n in graph.nodes:
            status_dist[n.status] = status_dist.get(n.status, 0) + 1

        member_art_facts = [cls.extract_artifact_facts(n) for n in graph.nodes]
        priority_dist: Dict[str, int] = {}
        for af in member_art_facts:
            priority_dist[af.priority] = priority_dist.get(af.priority, 0) + 1

        cluster_dist: Dict[str, int] = {}
        for c in graph.clusters:
            cluster_dist[c.relationship_classification] = (
                cluster_dist.get(c.relationship_classification, 0) + 1
            )

        # Metadata
        cap_enforced = graph.metadata.candidate_cap_enforced
        disc_candidates = graph.metadata.total_discovered_candidates
        omitted_candidates = graph.metadata.candidates_omitted
        complete_graph = graph.metadata.graph_is_complete

        return DeterministicCaseFacts(
            case_id=case_id,
            total_evidence_buffers=total_buffers,
            total_artifacts=total_artifacts,
            total_nodes=total_nodes,
            total_clusters=total_clusters,
            case_physical_coverage_bytes=case_phys_cov,
            case_coverage_is_complete=case_cov_complete,
            candidate_aggregate_verified_bytes=agg_v,
            candidate_aggregate_reconstructed_bytes=agg_r,
            candidate_aggregate_missing_bytes=agg_m,
            unscoped_candidate_count=unscoped_count,
            unscoped_aggregate_verified_bytes=unscoped_v,
            format_distribution=fmt_dist,
            status_distribution=status_dist,
            priority_distribution=priority_dist,
            cluster_classification_distribution=cluster_dist,
            candidate_cap_enforced=cap_enforced,
            total_discovered_candidates=disc_candidates,
            candidates_omitted=omitted_candidates,
            graph_is_complete=complete_graph,
        )

    def _invoke_cluster_with_fallback(
        self, context: ClusterInterpretationContext
    ) -> Tuple[ProviderInterpretationOutput, str]:
        """Invoke deterministic provider for cluster."""
        output = self._provider.interpret_cluster(context)
        return output, "DETERMINISTIC_RULES"

    def _invoke_case_with_fallback(
        self, context: CaseInterpretationContext
    ) -> Tuple[ProviderInterpretationOutput, str]:
        """Invoke deterministic provider for case."""
        output = self._provider.interpret_case(context)
        return output, "DETERMINISTIC_RULES"

    def interpret_cluster(
        self,
        case_id: str,
        cluster_id: str,
        graph: Optional[EvidenceGraph] = None,
        force_refresh: bool = False,
    ) -> GroundedClusterInterpretation:
        """Interpret a spatial cluster with fingerprint caching and safe fallback."""
        if graph is None:
            from backend.app.recovery.graph import build_case_evidence_graph
            store_to_use = self._store
            if store_to_use is None:
                from backend.app.store import store as default_store
                store_to_use = default_store
            graph = build_case_evidence_graph(case_id=case_id, store=store_to_use)

        cluster = next((c for c in graph.clusters if c.cluster_id == cluster_id), None)
        if cluster is None:
            raise KeyError(f"Cluster '{cluster_id}' not found in case '{case_id}'")

        cluster_fp = compute_cluster_fingerprint(cluster, graph)
        cache_key = (case_id, cluster_id, cluster_fp)

        # 1. Check cache if not force_refresh
        if not force_refresh and cache_key in self._cluster_cache:
            self._cluster_cache.move_to_end(cache_key)
            return self._cluster_cache[cache_key].with_cached(True)

        # 2. Extract facts
        facts = self.extract_cluster_facts(cluster, graph, case_id=case_id)

        # 3. Context
        c_node_ids = set(cluster.node_ids)
        member_nodes = [n for n in graph.nodes if n.node_id in c_node_ids]
        node_facts = [self.extract_artifact_facts(n) for n in member_nodes]

        internal_edges = [
            e
            for e in graph.edges
            if e.source_node_id in c_node_ids and e.target_node_id in c_node_ids
        ]
        rel_facts = [
            DeterministicRelationshipFact(
                edge_id=e.edge_id,
                source_node_id=e.source_node_id,
                target_node_id=e.target_node_id,
                relationship_type=e.relationship_type,  # type: ignore[arg-type]
                evidence_file_id=e.evidence_file_id,
                evidence_basis=e.evidence_basis,
                overlap_start=e.overlap_start,
                overlap_end=e.overlap_end,
                overlap_bytes=e.overlap_bytes,
            )
            for e in internal_edges
        ]

        context = ClusterInterpretationContext(
            facts=facts,
            nodes=node_facts,
            relationships=rel_facts,
        )

        # 4. Invoke provider with fallback
        output, source = self._invoke_cluster_with_fallback(context)

        # 5. Build model
        interpretation = GroundedClusterInterpretation(
            facts=facts,
            relationships=rel_facts,
            interpretation=output,
            source=source,  # type: ignore[arg-type]
            cached=False,
            generated_at=datetime.now(timezone.utc).isoformat(),
            cluster_fingerprint=cluster_fp,
        )

        # 6. Put in cache
        self._put_cluster_cache(cache_key, interpretation)
        return interpretation

    def interpret_case(
        self,
        case_id: str,
        graph: Optional[EvidenceGraph] = None,
        force_refresh: bool = False,
    ) -> GroundedCaseInterpretation:
        """Interpret an entire case with graph fingerprint caching and safe fallback."""
        if graph is None:
            from backend.app.recovery.graph import build_case_evidence_graph
            store_to_use = self._store
            if store_to_use is None:
                from backend.app.store import store as default_store
                store_to_use = default_store
            graph = build_case_evidence_graph(case_id=case_id, store=store_to_use)

        case_fp = compute_case_graph_fingerprint(graph)
        cache_key = (case_id, case_fp)

        # 1. Check cache if not force_refresh
        if not force_refresh and cache_key in self._case_cache:
            self._case_cache.move_to_end(cache_key)
            return self._case_cache[cache_key].with_cached(True)

        # 2. Extract facts
        facts = self.extract_case_facts(graph, case_id=case_id)
        cluster_facts = [
            self.extract_cluster_facts(c, graph, case_id=case_id)
            for c in graph.clusters
        ]

        context = CaseInterpretationContext(
            facts=facts,
            cluster_facts=cluster_facts,
        )

        # 3. Invoke provider with fallback
        output, source = self._invoke_case_with_fallback(context)

        # 4. Build model
        interpretation = GroundedCaseInterpretation(
            facts=facts,
            interpretation=output,
            source=source,  # type: ignore[arg-type]
            cached=False,
            generated_at=datetime.now(timezone.utc).isoformat(),
            case_graph_fingerprint=case_fp,
        )

        # 5. Put in cache
        self._put_case_cache(cache_key, interpretation)
        return interpretation


def get_interpretation_service(store: Any = None) -> InterpretationService:
    """Retrieve or initialize the global InterpretationService singleton."""
    global _GLOBAL_SERVICE
    if _GLOBAL_SERVICE is None:
        from backend.app.store import store as default_store
        _GLOBAL_SERVICE = InterpretationService(store=store or default_store)
    elif store is not None and _GLOBAL_SERVICE._store is None:
        _GLOBAL_SERVICE._store = store
    return _GLOBAL_SERVICE
