"""
explainer.py — Backward-compatible facade for Grounded Evidence Interpretation.

Milestone 3.5.1: Refactored into a thin facade delegating to the canonical
InterpretationService, ensuring a single interpretation pipeline across Recoverix.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional

from backend.app.scoring.interpretation_service import get_interpretation_service

logger = logging.getLogger(__name__)

# Maintained strictly for backward compatibility with Stage 11 tests and API clients
_explanation_cache: Dict[str, Dict[str, Any]] = {}


def _extract_facts(artifact: Any) -> Dict[str, Any]:
    """Backward-compatible facts extraction delegating to canonical service."""
    service = get_interpretation_service()
    facts = service.extract_artifact_facts(artifact)
    return {
        "filename": facts.filename,
        "format": facts.format,
        "status": facts.status,
        "category": facts.category,
        "priority": facts.priority,
        "confidence_score": (
            int(facts.confidence_score)
            if float(facts.confidence_score).is_integer()
            else round(facts.confidence_score, 2)
        ),
        "verified_bytes": facts.verified_bytes,
        "reconstructed_bytes": facts.reconstructed_bytes,
        "missing_bytes": facts.missing_bytes,
        "reconstruction_method": facts.reconstruction_method,
        "validation_status": facts.validation_status,
        "content_preview": getattr(artifact, "content_preview", "") or "",
    }


def explain_artifact(artifact_id: str, artifact: Any, force_refresh: bool = False) -> Dict[str, Any]:
    """Generate grounded evidence interpretation strictly from deterministic artifact facts.

    Delegates directly to the canonical InterpretationService.
    """
    if not force_refresh and artifact_id in _explanation_cache:
        cached_exp = dict(_explanation_cache[artifact_id])
        cached_exp["cached"] = True
        return cached_exp

    service = get_interpretation_service()
    interpretation = service.interpret_artifact(
        artifact_id=artifact_id,
        artifact=artifact,
        force_refresh=force_refresh,
        include_preview=True,
    )

    legacy_dict = interpretation.to_legacy_dict()
    _explanation_cache[artifact_id] = legacy_dict
    return legacy_dict
