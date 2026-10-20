"use client";

import { useState, useEffect, useCallback } from "react";
import {
  GroundedCaseInterpretation,
  PriorityLevel,
  Artifact,
} from "@/lib/types";
import {
  getCaseInterpretation,
  generateCaseInterpretation,
  buildDeterministicCaseInterpretation,
  ApiError,
  RawBackendArtifact,
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
  FileCheck2,
} from "lucide-react";

interface CaseInterpretationCardProps {
  caseId: string;
  onCaseChange?: (caseId: string) => void;
  className?: string;
  artifacts?: Artifact[];
  recoveryRuns?: RawBackendArtifact[];
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

function getCachedCaseInterpretation(caseId: string): GroundedCaseInterpretation | null {
  if (typeof window !== "undefined") {
    const cached = localStorage.getItem(`recoverix_case_interp_${caseId}`);
    if (cached) {
      try {
        return JSON.parse(cached);
      } catch {}
    }
  }
  return null;
}

export function CaseInterpretationCard({
  caseId,
  onCaseChange,
  className = "",
  artifacts = [],
  recoveryRuns = [],
}: CaseInterpretationCardProps) {
  const [prevCaseId, setPrevCaseId] = useState<string>(caseId);
  const [selectedCaseId, setSelectedCaseId] = useState<string>(caseId);
  const [customCaseInput, setCustomCaseInput] = useState<string>(caseId);
  const [isEditingCase, setIsEditingCase] = useState<boolean>(false);

  if (prevCaseId !== caseId) {
    setPrevCaseId(caseId);
    setSelectedCaseId(caseId);
    setCustomCaseInput(caseId);
  }

  const activeCaseId = selectedCaseId || caseId || "case_001";

  const [interpretation, setInterpretation] = useState<GroundedCaseInterpretation | null>(
    () => getCachedCaseInterpretation(activeCaseId)
  );
  const [isLoading, setIsLoading] = useState<boolean>(() => !getCachedCaseInterpretation(activeCaseId));
  const [isNotGenerated, setIsNotGenerated] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [isActionLoading, setIsActionLoading] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const loadInterpretation = useCallback(async () => {
    if (!activeCaseId) return;
    setIsLoading(true);
    setLoadError(null);
    setIsNotGenerated(false);
    setActionError(null);

    try {
      const data = await getCaseInterpretation(activeCaseId);
      setInterpretation(data);
      setIsNotGenerated(false);
    } catch (err: unknown) {
      if (typeof window !== "undefined") {
        const cached = localStorage.getItem(`recoverix_case_interp_${activeCaseId}`);
        if (cached) {
          try {
            setInterpretation(JSON.parse(cached));
            setIsNotGenerated(false);
            setIsLoading(false);
            return;
          } catch {}
        }
      }
      if (err instanceof ApiError && err.status === 404) {
        setIsNotGenerated(true);
        setInterpretation(null);
      } else {
        const msg = err instanceof Error ? err.message : "Unable to load case interpretation.";
        setLoadError(msg);
        setInterpretation(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, [activeCaseId]);

  useEffect(() => {
    let ignore = false;
    if (!activeCaseId) return;

    getCaseInterpretation(activeCaseId)
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
            const msg = err instanceof Error ? err.message : "Unable to load case interpretation.";
            setLoadError(msg);
            setInterpretation(null);
          }
          setIsLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [activeCaseId]);

  const handleCaseSwitch = (newId: string) => {
    const trimmed = newId.trim();
    if (!trimmed) return;
    setSelectedCaseId(trimmed);
    setCustomCaseInput(trimmed);
    setIsEditingCase(false);
    if (onCaseChange) {
      onCaseChange(trimmed);
    }
  };

  const handleGenerate = async () => {
    if (!activeCaseId || isActionLoading) return;
    setIsActionLoading(true);
    setActionError(null);

    try {
      const data = await generateCaseInterpretation(activeCaseId, false);
      setInterpretation(data);
      setIsNotGenerated(false);
      if (typeof window !== "undefined") {
        localStorage.setItem(`recoverix_case_interp_${activeCaseId}`, JSON.stringify(data));
      }
    } catch {
      // Deterministic evidence-grounded fallback for unseeded cases
      try {
        const localData = buildDeterministicCaseInterpretation(activeCaseId, recoveryRuns, artifacts);
        setInterpretation(localData);
        setIsNotGenerated(false);
        if (typeof window !== "undefined") {
          localStorage.setItem(`recoverix_case_interp_${activeCaseId}`, JSON.stringify(localData));
        }
      } catch (innerErr) {
        const msg = innerErr instanceof Error ? innerErr.message : "Unable to generate case interpretation.";
        setActionError(msg);
      }
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleRefresh = async () => {
    if (!activeCaseId || isActionLoading) return;
    setIsActionLoading(true);
    setActionError(null);

    try {
      const data = await generateCaseInterpretation(activeCaseId, true);
      setInterpretation(data);
      if (typeof window !== "undefined") {
        localStorage.setItem(`recoverix_case_interp_${activeCaseId}`, JSON.stringify(data));
      }
    } catch {
      try {
        const localData = buildDeterministicCaseInterpretation(activeCaseId, recoveryRuns, artifacts);
        setInterpretation(localData);
        if (typeof window !== "undefined") {
          localStorage.setItem(`recoverix_case_interp_${activeCaseId}`, JSON.stringify(localData));
        }
      } catch (innerErr) {
        const msg = innerErr instanceof Error ? innerErr.message : "Unable to refresh case interpretation.";
        setActionError(msg);
      }
    } finally {
      setIsActionLoading(false);
    }
  };

  // 1. Initial Loading State
  if (isLoading) {
    return (
      <div
        className={`bg-white border border-slate-200 rounded-xl p-6 font-mono shadow-xs space-y-4 ${className}`}
        role="status"
        aria-live="polite"
      >
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-emerald-600 animate-pulse" />
            <div>
              <h2 className="text-xl font-bold text-slate-900">Case Forensic Synthesis</h2>
              <p className="text-xs text-slate-500 font-sans mt-0.5">
                Case: {activeCaseId}
              </p>
            </div>
          </div>
        </div>
        <div className="space-y-3 py-8">
          <div className="flex items-center justify-center gap-2 text-slate-500 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-emerald-600" />
            <span>Loading case interpretation…</span>
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
        className={`bg-white border border-rose-200 rounded-xl p-6 font-mono shadow-xs space-y-4 ${className}`}
        role="alert"
      >
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-rose-600" />
            <div>
              <h2 className="text-xl font-bold text-slate-900">Case Forensic Synthesis</h2>
              <p className="text-xs text-slate-500 font-sans mt-0.5">
                Case: {activeCaseId}
              </p>
            </div>
          </div>
        </div>
        <div className="bg-rose-50 border border-rose-200 rounded-xl p-4 text-xs text-rose-800 space-y-2">
          <div className="flex items-center gap-2 font-semibold">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>Unable to load case interpretation</span>
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
        className={`bg-white border border-slate-200 rounded-xl p-6 font-mono shadow-xs space-y-5 ${className}`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-slate-400" />
            <div>
              <h2 className="text-xl font-bold text-slate-900">Case Forensic Synthesis</h2>
              <div className="flex items-center gap-2 mt-0.5 text-xs text-slate-500">
                <span>Case:</span>
                <span className="font-semibold text-slate-800 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                  {activeCaseId}
                </span>
              </div>
            </div>
          </div>

          {/* Case Switcher */}
          <div className="flex items-center gap-2 text-xs">
            {isEditingCase ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleCaseSwitch(customCaseInput);
                }}
                className="flex items-center gap-1.5"
              >
                <input
                  type="text"
                  value={customCaseInput}
                  onChange={(e) => setCustomCaseInput(e.target.value)}
                  placeholder="case_001"
                  aria-label="Case ID"
                  className="px-2.5 py-1 text-xs border border-slate-300 rounded-lg bg-slate-50 text-slate-900 focus:outline-none focus:border-emerald-500 font-mono w-28"
                />
                <button
                  type="submit"
                  className="px-2.5 py-1 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                >
                  Go
                </button>
                <button
                  type="button"
                  onClick={() => setIsEditingCase(false)}
                  className="px-2 py-1 text-slate-500 hover:text-slate-800 text-xs transition-colors cursor-pointer"
                >
                  Cancel
                </button>
              </form>
            ) : (
              <button
                type="button"
                onClick={() => setIsEditingCase(true)}
                className="px-2.5 py-1 text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 rounded-lg font-medium transition-colors cursor-pointer"
              >
                Switch Case
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
              <span className="font-semibold block">Unable to generate case interpretation</span>
              <span className="font-sans block text-rose-700">{actionError}</span>
            </div>
          </div>
        )}

        <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 text-center space-y-3">
          <p className="text-xs text-slate-700 font-sans font-medium leading-relaxed">
            No grounded interpretation has been generated for this case yet.
          </p>
          <p className="text-[11px] text-slate-400 font-sans max-w-lg mx-auto">
            Click below to generate an executive forensic briefing and cross-cluster evidence synthesis based
            on the deterministic recovery results for case <code className="font-mono text-slate-600">{activeCaseId}</code>.
          </p>
          <div className="pt-2">
            <button
              type="button"
              onClick={handleGenerate}
              disabled={isActionLoading}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-lg transition-colors shadow-2xs disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isActionLoading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Generating case synthesis…</span>
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
  const { facts, interpretation: output, cached, generated_at, case_graph_fingerprint } =
    interpretation;

  // Determine ambiguity indicator across case clusters
  const coextensiveCount = facts.cluster_classification_distribution?.["COEXTENSIVE_SET"] || 0;
  const overlapCount = facts.cluster_classification_distribution?.["OVERLAP_SPAN"] || 0;
  const mixedCount = facts.cluster_classification_distribution?.["MIXED"] || 0;
  const hasAmbiguousClusters = coextensiveCount > 0 || overlapCount > 0 || mixedCount > 0;

  return (
    <div
      className={`bg-white border border-slate-200 rounded-xl p-6 font-mono shadow-xs space-y-6 ${className}`}
    >
      {/* Header and Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-emerald-600" />
            <h2 className="text-xl font-bold text-slate-900">Case Forensic Synthesis</h2>
          </div>
          <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-slate-500">
            <span>Case:</span>
            <span className="font-semibold text-slate-800 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
              {facts.case_id}
            </span>
            <span>• Evidence Buffers: {facts.total_evidence_buffers}</span>
            <span>• Clusters: {facts.total_clusters}</span>
            <span>• Discovered Nodes: {facts.total_nodes}</span>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Case Switcher */}
          {isEditingCase ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleCaseSwitch(customCaseInput);
              }}
              className="flex items-center gap-1.5"
            >
              <input
                type="text"
                value={customCaseInput}
                onChange={(e) => setCustomCaseInput(e.target.value)}
                placeholder="case_001"
                aria-label="Case ID"
                className="px-2.5 py-1 text-xs border border-slate-300 rounded-lg bg-slate-50 text-slate-900 focus:outline-none focus:border-emerald-500 font-mono w-28"
              />
              <button
                type="submit"
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold transition-colors cursor-pointer"
              >
                Go
              </button>
              <button
                type="button"
                onClick={() => setIsEditingCase(false)}
                className="px-2 py-1 text-slate-500 hover:text-slate-800 text-xs transition-colors cursor-pointer"
              >
                Cancel
              </button>
            </form>
          ) : (
            <button
              type="button"
              onClick={() => setIsEditingCase(true)}
              className="px-2.5 py-1 text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200 rounded-lg font-medium transition-colors cursor-pointer"
            >
              Switch Case
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
            <RefreshCw className={`w-3 h-3 ${isActionLoading ? "animate-spin text-emerald-600" : ""}`} />
            <span>{isActionLoading ? "Refreshing synthesis…" : "Refresh"}</span>
          </button>
        </div>
      </div>

      {/* Metadata Row: Source, Cache Status, Case Fingerprint, and Generation Timestamp */}
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

        {case_graph_fingerprint && (
          <span
            title={`Full case graph fingerprint: ${case_graph_fingerprint}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-slate-50 text-slate-600 border border-slate-200 text-[11px] font-mono"
          >
            <span className="text-slate-400">FP:</span>
            <span>{case_graph_fingerprint.slice(0, 10)}…</span>
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
            <span className="font-semibold block">Unable to refresh case interpretation</span>
            <span className="font-sans block text-rose-700">{actionError}</span>
          </div>
        </div>
      )}

      {/* Candidate Cap Enforcement Notice if Enforced */}
      {facts.candidate_cap_enforced && (
        <div
          className="p-3.5 bg-amber-50 border border-amber-200 rounded-xl text-xs space-y-1"
          role="alert"
        >
          <div className="flex items-center gap-2 text-amber-900 font-bold uppercase tracking-wider">
            <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
            <span>Candidate Evaluation Cap Enforced</span>
          </div>
          <p className="text-amber-800 font-sans leading-relaxed">
            The candidate evaluation ceiling was reached. {facts.total_discovered_candidates} candidates were discovered
            across evidence buffers; {facts.candidates_omitted} candidates were omitted from graph processing.
            Graph completeness: <strong className="font-mono">{facts.graph_is_complete ? "Complete" : "Incomplete"}</strong>.
          </p>
        </div>
      )}

      {/* 1. Executive Summary */}
      <div className="bg-slate-50 p-4 rounded-xl border border-slate-200">
        <h3 className="text-xs font-bold text-slate-500 mb-2 uppercase tracking-wider">Executive Summary</h3>
        <p className="text-slate-800 text-sm font-sans leading-relaxed">{output.summary}</p>
      </div>

      {/* 2. Assessment */}
      <div className="space-y-1.5">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Forensic Assessment</h3>
        <p className="text-slate-700 text-xs font-sans leading-relaxed">{output.assessment}</p>
      </div>

      {/* 3. Physical Evidence Coverage vs Candidate Volume (Milestone 3.5.2 Semantics) */}
      <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
        <div className="bg-slate-100/80 px-4 py-2 border-b border-slate-200 text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-slate-600" />
            <span>Case Physical Footprint & Candidate Hypotheses Volume</span>
          </div>
          <span className="text-[10px] text-slate-500 font-normal font-sans">
            Unique Physical Footprint vs. Candidate Sum
          </span>
        </div>
        <div className="p-4 bg-white space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Case Physical Evidence Coverage */}
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
                {facts.case_physical_coverage_bytes !== null && facts.case_physical_coverage_bytes !== undefined
                  ? `${facts.case_physical_coverage_bytes.toLocaleString()} B`
                  : "Partial / Incomplete Coverage"}
              </div>
              <p className="text-xs text-emerald-800/80 font-sans">
                Unique physical evidence coverage across all scoped evidence buffers in this case.
              </p>
              {!facts.case_coverage_is_complete && (
                <p className="text-[11px] text-amber-700 font-sans font-medium flex items-center gap-1 mt-1">
                  <AlertTriangle className="w-3 h-3 shrink-0" />
                  Coverage incomplete: one or more candidate hypotheses have unobserved endpoints.
                </p>
              )}
            </div>

            {/* Evidence Buffers Analyzed */}
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase text-slate-700 tracking-wider">
                  Evidence Buffers Analyzed
                </span>
                <span className="text-[10px] bg-slate-200 text-slate-700 px-1.5 py-0.5 rounded font-mono">
                  Independent Coordinates
                </span>
              </div>
              <div className="text-xl font-bold font-mono text-slate-900">
                {facts.total_evidence_buffers} {facts.total_evidence_buffers === 1 ? "Buffer" : "Buffers"}
              </div>
              <p className="text-xs text-slate-600 font-sans">
                Coordinate offsets are strictly intra-buffer and never conflated across buffer boundaries.
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
                  Aggregate verified bytes across all candidates
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
              Candidate aggregate volume represents the sum across all evaluated candidate hypotheses in the case
              and must not be interpreted as unique physical evidence bytes.
            </p>
          </div>

          {/* Unscoped Candidates Tracking if Present */}
          {facts.unscoped_candidate_count > 0 && (
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-700 uppercase text-[10px] tracking-wider">
                  Unscoped Candidates ({facts.unscoped_candidate_count})
                </span>
                <span className="font-mono text-slate-900 font-bold">
                  {facts.unscoped_aggregate_verified_bytes.toLocaleString()} B verified
                </span>
              </div>
              <p className="text-slate-500 text-[11px] font-sans">
                Excluded from physical evidence coverage because no buffer coordinate association is available.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* 4. Topologies & Competing Hypotheses Breakdown */}
      <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
        <div className="bg-slate-100/80 px-4 py-2 border-b border-slate-200 text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center justify-between">
          <span>Topology & Competing Hypotheses</span>
          <span className="text-[10px] text-slate-500 font-normal font-sans">
            Cross-Cluster Topologies
          </span>
        </div>
        <div className="p-4 bg-white space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-50 border border-slate-200 rounded-lg">
            <div className="space-y-1">
              <span className="text-[10px] uppercase font-bold text-slate-500 block">Hypothesis State:</span>
              <div className="text-xs text-slate-700 font-sans">
                {hasAmbiguousClusters
                  ? "Multiple candidate hypotheses exist with overlapping or coextensive coordinate bounds."
                  : "All candidate clusters adhere to isolated, non-overlapping spatial intervals."}
              </div>
            </div>

            {/* Ambiguity Indicator */}
            <div>
              {hasAmbiguousClusters ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-50 text-amber-800 border border-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
                  <span>Ambiguous Competing Hypotheses</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-50 text-emerald-800 border border-emerald-300">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                  <span>Unambiguous Candidate Topologies</span>
                </span>
              )}
            </div>
          </div>

          {/* Cluster Classification Distribution */}
          {facts.cluster_classification_distribution &&
            Object.keys(facts.cluster_classification_distribution).length > 0 && (
              <div className="space-y-2">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">
                  Cluster Topological Classifications
                </span>
                <div className="flex flex-wrap gap-2 text-xs">
                  {Object.entries(facts.cluster_classification_distribution).map(([cls, count]) => (
                    <div
                      key={cls}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-700"
                    >
                      <Layers className="w-3 h-3 text-slate-400" />
                      <span className="font-mono text-[10px] uppercase font-bold text-slate-600">{cls}:</span>
                      <span className="font-bold text-slate-900">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          {/* Status Distribution */}
          {facts.status_distribution && Object.keys(facts.status_distribution).length > 0 && (
            <div className="space-y-2">
              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">
                Recovery Status Distribution
              </span>
              <div className="flex flex-wrap gap-2 text-xs">
                {Object.entries(facts.status_distribution).map(([statusKey, count]) => (
                  <div
                    key={statusKey}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-50 border border-slate-200 text-slate-700"
                  >
                    <FileCheck2 className="w-3 h-3 text-slate-400" />
                    <span className="font-mono text-[10px] uppercase font-bold text-slate-600">
                      {statusKey}:
                    </span>
                    <span className="font-bold text-slate-900">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Format & Priority Distributions Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
            {facts.format_distribution && Object.keys(facts.format_distribution).length > 0 && (
              <div className="p-3 bg-slate-50/60 border border-slate-200 rounded-lg space-y-2">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">
                  Format Distribution
                </span>
                <div className="flex flex-wrap gap-1.5 text-xs">
                  {Object.entries(facts.format_distribution).map(([fmt, count]) => (
                    <span
                      key={fmt}
                      className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700 font-mono text-[11px]"
                    >
                      {fmt.toUpperCase()}: <strong className="text-slate-900">{count}</strong>
                    </span>
                  ))}
                </div>
              </div>
            )}

            {facts.priority_distribution && Object.keys(facts.priority_distribution).length > 0 && (
              <div className="p-3 bg-slate-50/60 border border-slate-200 rounded-lg space-y-2">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">
                  Priority Distribution
                </span>
                <div className="flex flex-wrap gap-1.5 text-xs">
                  {Object.entries(facts.priority_distribution).map(([prio, count]) => (
                    <div key={prio} className="flex items-center gap-1">
                      <PriorityBadge priority={prio as PriorityLevel} />
                      <span className="text-[11px] font-bold text-slate-800">×{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 5. Structural Context */}
      <div className="space-y-1.5">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Structural Context</h3>
        <p className="text-slate-700 text-xs font-sans leading-relaxed">{output.structural_context}</p>
      </div>

      {/* 6. Limitations */}
      <div className="bg-amber-50/70 p-3.5 rounded-lg border border-amber-200/80 space-y-1">
        <h3 className="text-xs font-bold text-amber-900 uppercase tracking-wider flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
          <span>Limitations</span>
        </h3>
        <p className="text-amber-900/90 text-xs font-sans leading-relaxed">{output.limitations}</p>
      </div>

      {/* 7. Recommended Next Steps */}
      <div className="bg-sky-50/70 p-3.5 rounded-lg border border-sky-200/80 space-y-1">
        <h3 className="text-xs font-bold text-sky-900 uppercase tracking-wider flex items-center gap-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-sky-600 shrink-0" />
          <span>Recommended Next Steps</span>
        </h3>
        <p className="text-sky-900/90 text-xs font-sans leading-relaxed">
          {output.recommended_next_steps}
        </p>
      </div>

      {/* 8. Details (rendered only when array contains entries) */}
      {output.details && output.details.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Details</h3>
          <ul className="space-y-2 font-sans">
            {output.details.map((detail, idx) => (
              <li key={idx} className="flex items-start gap-2.5 text-xs text-slate-700">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 mt-1.5 shrink-0" aria-hidden="true" />
                <span className="leading-relaxed">{detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
