"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  GroundedClusterInterpretation,
  AuthoritativeClusterClassification,
} from "@/lib/types";
import {
  getClusterInterpretation,
  generateClusterInterpretation,
  ApiError,
} from "@/lib/api";
import { PriorityBadge } from "@/components/dashboard/PriorityBadge";
import {
  BrainCircuit,
  RefreshCw,
  Zap,
  Clock,
  Cpu,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Layers,
  ChevronRight,
} from "lucide-react";

interface ClusterInterpretationCardProps {
  caseId: string;
  clusterId?: string;
  nodeToArtifactMap?: Record<string, string>;
  onClusterChange?: (clusterId: string) => void;
  className?: string;
}

function formatGeneratedTime(isoString: string): string {
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return isoString;
    return date.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZoneName: "short",
    });
  } catch {
    return isoString;
  }
}

function ClassificationBadge({
  classification,
}: {
  classification: AuthoritativeClusterClassification | string;
}) {
  const styles: Record<string, string> = {
    ISOLATED: "bg-slate-100 text-slate-800 border-slate-300",
    COEXTENSIVE_SET: "bg-purple-50 text-purple-800 border-purple-300",
    CONTAINMENT_TREE: "bg-indigo-50 text-indigo-800 border-indigo-300",
    OVERLAP_SPAN: "bg-amber-50 text-amber-800 border-amber-300",
    MIXED: "bg-rose-50 text-rose-800 border-rose-300",
  };
  const style = styles[classification] || "bg-slate-100 text-slate-700 border-slate-300";

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-xs font-semibold border ${style}`}
    >
      <Layers className="w-3 h-3 shrink-0" />
      <span>{classification}</span>
    </span>
  );
}

function getClassificationDescription(
  classification: AuthoritativeClusterClassification | string
): string {
  switch (classification) {
    case "ISOLATED":
      return "Single candidate hypothesis isolated from other candidates with no spatial overlaps.";
    case "COEXTENSIVE_SET":
      return "Multiple coextensive candidate hypotheses occupying identical byte coordinate intervals.";
    case "CONTAINMENT_TREE":
      return "Hierarchical container-child candidate relationship where candidates enclose other candidates.";
    case "OVERLAP_SPAN":
      return "Candidates sharing partially overlapping byte coordinate intervals.";
    case "MIXED":
      return "Complex multi-candidate topological configuration with mixed containment and overlap relations.";
    default:
      return "Spatial candidate relationship cluster.";
  }
}

export function ClusterInterpretationCard({
  caseId,
  clusterId = "cluster_0",
  nodeToArtifactMap,
  onClusterChange,
  className = "",
}: ClusterInterpretationCardProps) {
  const [prevClusterId, setPrevClusterId] = useState<string>(clusterId);
  const [selectedClusterId, setSelectedClusterId] = useState<string>(clusterId);
  const [customClusterInput, setCustomClusterInput] = useState<string>(clusterId);
  const [isEditingCluster, setIsEditingCluster] = useState<boolean>(false);

  if (prevClusterId !== clusterId) {
    setPrevClusterId(clusterId);
    setSelectedClusterId(clusterId);
    setCustomClusterInput(clusterId);
  }

  const activeClusterId = selectedClusterId || clusterId || "cluster_0";

  const [interpretation, setInterpretation] = useState<GroundedClusterInterpretation | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isNotGenerated, setIsNotGenerated] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [isActionLoading, setIsActionLoading] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const loadInterpretation = useCallback(async () => {
    if (!caseId || !activeClusterId) return;
    setIsLoading(true);
    setLoadError(null);
    setIsNotGenerated(false);
    setActionError(null);

    try {
      const data = await getClusterInterpretation(caseId, activeClusterId);
      setInterpretation(data);
      setIsNotGenerated(false);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 404) {
        setIsNotGenerated(true);
        setInterpretation(null);
      } else {
        const msg = err instanceof Error ? err.message : "Unable to load cluster interpretation.";
        setLoadError(msg);
        setInterpretation(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, [caseId, activeClusterId]);

  useEffect(() => {
    let ignore = false;
    if (!caseId || !activeClusterId) return;

    getClusterInterpretation(caseId, activeClusterId)
      .then((data) => {
        if (!ignore) {
          setInterpretation(data);
          setIsNotGenerated(false);
          setIsLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!ignore) {
          if (err instanceof ApiError && err.status === 404) {
            setIsNotGenerated(true);
            setInterpretation(null);
          } else {
            const msg = err instanceof Error ? err.message : "Unable to load cluster interpretation.";
            setLoadError(msg);
            setInterpretation(null);
          }
          setIsLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [caseId, activeClusterId]);

  const handleClusterSwitch = (newId: string) => {
    const trimmed = newId.trim();
    if (!trimmed) return;
    setSelectedClusterId(trimmed);
    setCustomClusterInput(trimmed);
    setIsEditingCluster(false);
    if (onClusterChange) {
      onClusterChange(trimmed);
    }
  };

  const handleGenerate = async () => {
    if (!caseId || !activeClusterId || isActionLoading) return;
    setIsActionLoading(true);
    setActionError(null);

    try {
      const data = await generateClusterInterpretation(caseId, activeClusterId, false);
      setInterpretation(data);
      setIsNotGenerated(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unable to generate cluster interpretation.";
      setActionError(msg);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleRefresh = async () => {
    if (!caseId || !activeClusterId || isActionLoading) return;
    setIsActionLoading(true);
    setActionError(null);

    try {
      const data = await generateClusterInterpretation(caseId, activeClusterId, true);
      setInterpretation(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unable to refresh cluster interpretation.";
      setActionError(msg);
    } finally {
      setIsActionLoading(false);
    }
  };

  // 1. Initial Loading State
  if (isLoading) {
    return (
      <div
        className={`bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 font-mono shadow-xs space-y-4 ${className}`}
        role="status"
        aria-live="polite"
      >
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-purple-600 animate-pulse" />
            <div>
              <h2 className="text-xl font-bold text-slate-900">Cluster Interpretation</h2>
              <p className="text-xs text-slate-500 font-sans mt-0.5">
                Target: {activeClusterId} (Case: {caseId})
              </p>
            </div>
          </div>
        </div>
        <div className="space-y-3 py-8">
          <div className="flex items-center justify-center gap-2 text-slate-500 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-purple-600" />
            <span>Loading cluster interpretation…</span>
          </div>
          <div className="h-4 bg-slate-100 rounded animate-pulse w-3/4 mx-auto" />
          <div className="h-4 bg-slate-100 rounded animate-pulse w-1/2 mx-auto" />
        </div>
      </div>
    );
  }

  // 2. Load Error State (Non-404)
  if (loadError) {
    return (
      <div
        className={`bg-white border border-rose-200 rounded-2xl p-6 sm:p-8 font-mono shadow-xs space-y-4 ${className}`}
        role="alert"
      >
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-rose-600" />
            <div>
              <h2 className="text-xl font-bold text-slate-900">Cluster Interpretation</h2>
              <p className="text-xs text-slate-500 font-sans mt-0.5">
                Target: {activeClusterId} (Case: {caseId})
              </p>
            </div>
          </div>
        </div>
        <div className="bg-rose-50 border border-rose-200 rounded-xl p-4 text-xs text-rose-800 space-y-2">
          <div className="flex items-center gap-2 font-semibold">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>Unable to load cluster interpretation</span>
          </div>
          <p className="text-rose-700 font-sans">{loadError}</p>
          <button
            type="button"
            onClick={loadInterpretation}
            className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 bg-white border border-rose-300 text-rose-800 hover:bg-rose-100/50 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3 h-3" /> Retry
          </button>
        </div>
      </div>
    );
  }

  // 3. Not Generated State (404 on GET)
  if (isNotGenerated || !interpretation) {
    return (
      <div
        className={`bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 font-mono shadow-xs space-y-5 ${className}`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-slate-400" />
            <div>
              <h2 className="text-xl font-bold text-slate-900">Cluster Interpretation</h2>
              <div className="flex items-center gap-2 mt-0.5 text-xs text-slate-500">
                <span>Cluster:</span>
                <span className="font-semibold text-slate-800 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                  {activeClusterId}
                </span>
                <span>(Case: {caseId})</span>
              </div>
            </div>
          </div>

          {/* Cluster Switcher */}
          <div className="flex items-center gap-2 text-xs">
            {isEditingCluster ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleClusterSwitch(customClusterInput);
                }}
                className="flex items-center gap-1.5"
              >
                <input
                  type="text"
                  value={customClusterInput}
                  onChange={(e) => setCustomClusterInput(e.target.value)}
                  placeholder="cluster_0"
                  aria-label="Cluster ID"
                  className="px-2.5 py-1 text-xs border border-slate-300 rounded-lg bg-slate-50 text-slate-900 focus:outline-none focus:border-purple-500 font-mono w-32"
                />
                <button
                  type="submit"
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                >
                  Go
                </button>
                <button
                  type="button"
                  onClick={() => setIsEditingCluster(false)}
                  className="px-2 py-1 text-slate-500 hover:text-slate-800 text-xs transition-colors cursor-pointer"
                >
                  Cancel
                </button>
              </form>
            ) : (
              <button
                type="button"
                onClick={() => setIsEditingCluster(true)}
                className="px-2.5 py-1 text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 rounded-lg font-medium transition-colors cursor-pointer"
              >
                Switch Cluster
              </button>
            )}
          </div>
        </div>

        {actionError && (
          <div
            className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-xl flex items-start gap-2"
            role="alert"
          >
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold block">Unable to generate cluster interpretation</span>
              <span className="font-sans block text-rose-700">{actionError}</span>
            </div>
          </div>
        )}

        <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 text-center space-y-3">
          <p className="text-xs text-slate-700 font-sans font-medium leading-relaxed">
            No grounded interpretation has been generated for this cluster yet.
          </p>
          <p className="text-[11px] text-slate-400 font-sans max-w-lg mx-auto">
            Click below to generate a grounded interpretation based on the deterministic recovery results
            for cluster <code className="font-mono text-slate-600">{activeClusterId}</code>.
          </p>
          <div className="pt-2">
            <button
              type="button"
              onClick={handleGenerate}
              disabled={isActionLoading}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-xs font-bold rounded-lg transition-colors shadow-2xs disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isActionLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Generating interpretation…</span>
                </>
              ) : (
                <>
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Generate Interpretation</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // 4. Grounded Interpretation Display State
  const { facts, relationships, interpretation: output, cached, generated_at, cluster_fingerprint } =
    interpretation;

  return (
    <div
      className={`bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 font-mono shadow-xs space-y-6 ${className}`}
    >
      {/* Header and Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-purple-600" />
            <h2 className="text-xl font-bold text-slate-900">Cluster Interpretation</h2>
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-slate-500">
            <span>Cluster:</span>
            <span className="font-semibold text-slate-800 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
              {facts.cluster_id}
            </span>
            <span>(Case: {facts.case_id})</span>
            {facts.evidence_file_id && (
              <span className="text-slate-400 font-sans">
                • Buffer: {facts.evidence_file_id}
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Cluster Switcher */}
          {isEditingCluster ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleClusterSwitch(customClusterInput);
              }}
              className="flex items-center gap-1.5"
            >
              <input
                type="text"
                value={customClusterInput}
                onChange={(e) => setCustomClusterInput(e.target.value)}
                placeholder="cluster_0"
                aria-label="Cluster ID"
                className="px-2.5 py-1 text-xs border border-slate-300 rounded-lg bg-slate-50 text-slate-900 focus:outline-none focus:border-purple-500 font-mono w-28"
              />
              <button
                type="submit"
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
              >
                Go
              </button>
              <button
                type="button"
                onClick={() => setIsEditingCluster(false)}
                className="px-2 py-1 text-slate-500 hover:text-slate-800 text-xs transition-colors cursor-pointer"
              >
                Cancel
              </button>
            </form>
          ) : (
            <button
              type="button"
              onClick={() => setIsEditingCluster(true)}
              className="px-2.5 py-1 text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 rounded-lg font-medium transition-colors cursor-pointer"
            >
              Switch Cluster
            </button>
          )}

          {/* Refresh Action */}
          <button
            type="button"
            onClick={handleRefresh}
            disabled={isActionLoading}
            aria-label="Refresh Interpretation"
            className="inline-flex items-center gap-1.5 px-3 py-1 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs rounded-lg transition-colors shadow-2xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            <RefreshCw className={`w-3 h-3 ${isActionLoading ? "animate-spin text-purple-600" : ""}`} />
            <span>{isActionLoading ? "Refreshing interpretation…" : "Refresh"}</span>
          </button>
        </div>
      </div>

      {/* Metadata Row: Source, Cache Status, Fingerprint, and Generation Timestamp */}
      <div className="flex flex-wrap items-center gap-2.5 pb-4 border-b border-slate-100 text-xs">
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md font-semibold bg-slate-100 text-slate-700 border border-slate-300">
          <Cpu className="w-3 h-3 text-slate-500" />
          Deterministic interpretation
        </span>

        <span
          className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md font-semibold border ${
            cached
              ? "bg-slate-50 text-slate-600 border-slate-200"
              : "bg-emerald-50 text-emerald-700 border-emerald-200"
          }`}
        >
          {cached ? (
            <>
              <Clock className="w-3 h-3 text-slate-400" />
              <span>Cached</span>
            </>
          ) : (
            <>
              <Zap className="w-3 h-3 text-emerald-500" />
              <span>Generated</span>
            </>
          )}
        </span>

        {cluster_fingerprint && (
          <span
            title={`Full cluster fingerprint: ${cluster_fingerprint}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-50 text-slate-600 border border-slate-200 text-[11px] font-mono"
          >
            <span className="text-slate-400">FP:</span>
            <span>{cluster_fingerprint.slice(0, 10)}…</span>
          </span>
        )}

        <span className="text-[11px] text-slate-400 font-sans ml-auto">
          Generated: {formatGeneratedTime(generated_at)}
        </span>
      </div>

      {/* Action Error Banner if Refresh Failed */}
      {actionError && (
        <div
          className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-xl flex items-start gap-2"
          role="alert"
        >
          <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold block">Unable to refresh cluster interpretation</span>
            <span className="font-sans block text-rose-700">{actionError}</span>
          </div>
        </div>
      )}

      {/* 1. Summary */}
      <div className="bg-slate-50 p-4 rounded-xl border border-slate-200">
        <h3 className="text-xs font-bold text-slate-500 mb-2 uppercase tracking-wider">Summary</h3>
        <p className="text-slate-800 text-sm font-sans leading-relaxed">{output.summary}</p>
      </div>

      {/* 2. Assessment */}
      <div className="space-y-1.5">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Assessment</h3>
        <p className="text-slate-700 text-xs font-sans leading-relaxed">{output.assessment}</p>
      </div>

      {/* 3. Physical Evidence Coverage vs Candidate Volume (Milestone 3.5.2 Semantics) */}
      <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
        <div className="bg-slate-100/80 px-4 py-2 border-b border-slate-200 text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-slate-600" />
            <span>Physical Footprint & Candidate Hypotheses Volume</span>
          </div>
          <span className="text-[10px] text-slate-500 font-normal font-sans">
            Deterministic Lebesgue Union vs. Candidate Sum
          </span>
        </div>
        <div className="p-4 bg-white space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Physical Evidence Coverage */}
            <div className="p-3.5 bg-emerald-50/50 border border-emerald-200 rounded-lg space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase text-emerald-800 tracking-wider">
                  Physical Evidence Coverage
                </span>
                <span className="text-[10px] bg-emerald-100 text-emerald-800 px-1.5 py-0.5 rounded font-mono">
                  Unique Footprint
                </span>
              </div>
              <div className="text-xl font-bold font-mono text-emerald-950">
                {facts.unique_physical_bytes !== null && facts.unique_physical_bytes !== undefined
                  ? `${facts.unique_physical_bytes.toLocaleString()} B`
                  : `${facts.bounded_physical_bytes.toLocaleString()} B (lower bound)`}
              </div>
              <p className="text-xs text-emerald-800/80 font-sans">
                Unique physical bytes occupied by this cluster in the evidence container.
              </p>
              {facts.has_unbounded_candidate && (
                <p className="text-[11px] text-amber-700 font-sans font-medium flex items-center gap-1 mt-1">
                  <AlertTriangle className="w-3 h-3 shrink-0" />
                  Contains unbounded candidate (evidence end unobserved)
                </p>
              )}
            </div>

            {/* Coordinate Bounding Span */}
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase text-slate-700 tracking-wider">
                  Coordinate Bounding Span
                </span>
                <span className="text-[10px] bg-slate-200 text-slate-700 px-1.5 py-0.5 rounded font-mono">
                  max(end) - min(start)
                </span>
              </div>
              <div className="text-xl font-bold font-mono text-slate-900">
                {facts.bounding_span_bytes !== null && facts.bounding_span_bytes !== undefined
                  ? `${facts.bounding_span_bytes.toLocaleString()} B`
                  : "Unbounded Span"}
              </div>
              <p className="text-xs text-slate-600 font-sans">
                Continuous coordinate envelope from offset {facts.cluster_start.toLocaleString()} B
                {facts.cluster_end !== null && facts.cluster_end !== undefined
                  ? ` to ${facts.cluster_end.toLocaleString()} B.`
                  : " onwards."}
              </p>
            </div>
          </div>

          {/* Candidate Evaluation Volume Strip */}
          <div>
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block mb-2">
              Candidate Evaluation Volume (Hypothesis Aggregate)
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-slate-200 border border-slate-200 rounded-lg bg-slate-50/50 text-xs">
              <div className="p-3">
                <span className="text-slate-500 block text-[10px] uppercase font-semibold">
                  Candidate Verified Volume
                </span>
                <span className="font-bold text-slate-900 font-mono text-sm block mt-0.5">
                  {facts.candidate_aggregate_verified_bytes.toLocaleString()} B
                </span>
                <span className="text-[10px] text-slate-500 font-sans">
                  Aggregate verified bytes across candidates
                </span>
              </div>
              <div className="p-3">
                <span className="text-slate-500 block text-[10px] uppercase font-semibold">
                  Candidate Reconstructed Volume
                </span>
                <span className="font-bold text-slate-900 font-mono text-sm block mt-0.5">
                  {facts.candidate_aggregate_reconstructed_bytes.toLocaleString()} B
                </span>
                <span className="text-[10px] text-slate-500 font-sans">
                  Aggregate grammar-derived bytes
                </span>
              </div>
              <div className="p-3">
                <span className="text-slate-500 block text-[10px] uppercase font-semibold">
                  Candidate Missing Volume
                </span>
                <span className="font-bold text-amber-700 font-mono text-sm block mt-0.5">
                  {facts.candidate_aggregate_missing_bytes.toLocaleString()} B
                </span>
                <span className="text-[10px] text-slate-500 font-sans">
                  Aggregate unobserved gap bytes
                </span>
              </div>
            </div>
            <p className="text-[11px] text-slate-500 font-sans mt-2">
              Candidate aggregate volume represents the sum across all candidate hypotheses and must not be
              conflated with the unique physical evidence footprint.
            </p>
          </div>
        </div>
      </div>

      {/* 4. Topological Classification & Competing Hypotheses */}
      <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
        <div className="bg-slate-100/80 px-4 py-2 border-b border-slate-200 text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center justify-between">
          <span>Topology & Competing Hypotheses</span>
          <span className="text-[10px] text-slate-500 font-normal font-sans">
            Deterministic Graph Classification
          </span>
        </div>
        <div className="p-4 bg-white space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] uppercase font-bold text-slate-500">Classification:</span>
                <ClassificationBadge classification={facts.relationship_classification} />
              </div>
              <p className="text-xs text-slate-600 font-sans">
                {getClassificationDescription(facts.relationship_classification)}
              </p>
            </div>

            {/* Ambiguity Indicator */}
            <div>
              {facts.has_ambiguity ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-50 text-amber-800 border border-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                  <span>Ambiguous Competing Hypotheses</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>Unambiguous Candidate Hypothesis</span>
                </span>
              )}
            </div>
          </div>

          {/* Grid of topological facts */}
          <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-y divide-slate-200 border border-slate-200 rounded-lg text-xs">
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Candidate Nodes</span>
              <span className="font-bold text-slate-800 text-sm">{facts.total_nodes}</span>
            </div>
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Coextensive Candidates</span>
              <span className="font-bold text-slate-800 text-sm">{facts.coextensive_candidate_count}</span>
            </div>
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Containment Edges</span>
              <span className="font-bold text-slate-800 text-sm">{facts.containment_edge_count}</span>
            </div>
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Overlap Edges</span>
              <span className="font-bold text-slate-800 text-sm">{facts.overlap_edge_count}</span>
            </div>
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Competing Formats</span>
              <span className="font-bold text-slate-800 text-sm">
                {facts.competing_format_count}
                {facts.member_formats.length > 0 && ` (${facts.member_formats.join(", ").toUpperCase()})`}
              </span>
            </div>
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Max Confidence</span>
              <span className="font-bold text-emerald-600 text-sm">{facts.max_confidence_score}/100</span>
            </div>
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Highest Priority</span>
              <div className="mt-0.5">
                <PriorityBadge priority={facts.highest_priority} />
              </div>
            </div>
            <div className="p-3">
              <span className="text-slate-400 block text-[10px] uppercase">Damage Regions</span>
              <span className="font-bold text-slate-800 text-sm">{facts.total_damage_regions}</span>
            </div>
          </div>

          {facts.has_ambiguity && (
            <p className="text-[11px] text-amber-800/90 font-sans bg-amber-50/70 border border-amber-200/80 p-2.5 rounded-lg">
              Multiple valid candidate hypotheses exist for this physical coordinate span. Deterministic
              recovery preserves all candidates without arbitrary winner selection.
            </p>
          )}
        </div>
      </div>

      {/* 5. Status Distribution (if present) */}
      {facts.status_distribution && Object.keys(facts.status_distribution).length > 0 && (
        <div className="space-y-1.5">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
            Candidate Status Distribution
          </h3>
          <div className="flex flex-wrap gap-2 text-xs">
            {Object.entries(facts.status_distribution).map(([statusKey, count]) => (
              <div
                key={statusKey}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-700"
              >
                <span className="font-mono text-[10px] uppercase font-bold text-slate-500">
                  {statusKey}:
                </span>
                <span className="font-bold text-slate-900">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 6. Member Candidates */}
      {facts.member_node_ids && facts.member_node_ids.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
              Member Candidates ({facts.member_node_ids.length})
            </h3>
            <span className="text-[10px] text-slate-400 font-sans">
              Graph Candidate Nodes
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {facts.member_node_ids.map((nodeId) => {
              const mappedArtifactId = nodeToArtifactMap?.[nodeId];
              return mappedArtifactId ? (
                <Link
                  key={nodeId}
                  href={`/artifacts/${encodeURIComponent(mappedArtifactId)}`}
                  className="flex items-center justify-between p-2.5 bg-slate-50 hover:bg-slate-100 border border-slate-200 rounded-lg text-xs transition-colors group cursor-pointer"
                >
                  <div className="truncate mr-2">
                    <span className="font-mono font-semibold text-slate-800 block truncate">
                      {nodeId}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      Artifact: {mappedArtifactId}
                    </span>
                  </div>
                  <span className="text-emerald-700 text-[11px] font-semibold inline-flex items-center gap-0.5 group-hover:underline shrink-0">
                    Inspect <ChevronRight className="w-3.5 h-3.5" />
                  </span>
                </Link>
              ) : (
                <div
                  key={nodeId}
                  className="flex items-center justify-between p-2.5 bg-slate-50/70 border border-slate-200 rounded-lg text-xs"
                >
                  <div className="truncate mr-2">
                    <span className="font-mono font-semibold text-slate-700 block truncate">
                      {nodeId}
                    </span>
                    <span className="text-[10px] text-slate-400 font-sans block">
                      Candidate Reference
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200 shrink-0">
                    Candidate
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 7. Verified Spatial Relationships */}
      {relationships && relationships.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
            Verified Spatial Relationships ({relationships.length})
          </h3>
          <div className="border border-slate-200 rounded-xl overflow-hidden bg-white divide-y divide-slate-100">
            {relationships.map((rel) => (
              <div
                key={rel.edge_id}
                className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
              >
                <div className="flex items-center gap-2 font-mono">
                  <span className="font-bold text-slate-800">{rel.source_node_id}</span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200">
                    {rel.relationship_type}
                  </span>
                  <span className="font-bold text-slate-800">{rel.target_node_id}</span>
                </div>
                <div className="flex items-center gap-3 text-slate-500 text-[11px] font-sans">
                  <span>Basis: {rel.evidence_basis}</span>
                  <span>Overlap: {rel.overlap_bytes.toLocaleString()} B</span>
                  {rel.overlap_start !== null &&
                    rel.overlap_start !== undefined &&
                    rel.overlap_end !== null &&
                    rel.overlap_end !== undefined && (
                      <span className="font-mono text-[10px]">
                        [{rel.overlap_start} - {rel.overlap_end}]
                      </span>
                    )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 8. Structural Context */}
      <div className="space-y-1.5">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Structural Context</h3>
        <p className="text-slate-700 text-xs font-sans leading-relaxed">{output.structural_context}</p>
      </div>

      {/* 9. Limitations */}
      <div className="bg-amber-50/70 p-3.5 rounded-lg border border-amber-200/80 space-y-1">
        <h3 className="text-xs font-bold text-amber-900 uppercase tracking-wider flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
          <span>Limitations</span>
        </h3>
        <p className="text-amber-900/90 text-xs font-sans leading-relaxed">{output.limitations}</p>
      </div>

      {/* 10. Recommended Next Steps */}
      <div className="bg-sky-50/70 p-3.5 rounded-lg border border-sky-200/80 space-y-1">
        <h3 className="text-xs font-bold text-sky-900 uppercase tracking-wider flex items-center gap-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-sky-600 shrink-0" />
          <span>Recommended Next Steps</span>
        </h3>
        <p className="text-sky-900/90 text-xs font-sans leading-relaxed">
          {output.recommended_next_steps}
        </p>
      </div>

      {/* 11. Details (rendered only when array contains entries) */}
      {output.details && output.details.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Details</h3>
          <ul className="space-y-2 font-sans">
            {output.details.map((detail, idx) => (
              <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-700">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-600 mt-1.5 shrink-0" aria-hidden="true" />
                <span className="leading-relaxed">{detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
