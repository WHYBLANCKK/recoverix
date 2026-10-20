"use client";

import { useState, useEffect, useCallback } from "react";
import { Artifact, GroundedArtifactInterpretation } from "@/lib/types";
import { getArtifactInterpretation, generateArtifactInterpretation, ApiError } from "@/lib/api";
import { PriorityBadge, StatusBadge } from "@/components/dashboard/PriorityBadge";
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
} from "lucide-react";

interface ForensicEvidenceBriefProps {
  artifact?: Artifact;
  artifactId?: string;
  initialBrief?: unknown;
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

export function ForensicEvidenceBrief({ artifact, artifactId }: ForensicEvidenceBriefProps) {
  const targetId = artifactId || artifact?.id;

  const [interpretation, setInterpretation] = useState<GroundedArtifactInterpretation | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isNotGenerated, setIsNotGenerated] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [isActionLoading, setIsActionLoading] = useState<boolean>(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchAndApply = useCallback(async (id: string) => {
    setIsLoading(true);
    setLoadError(null);
    setIsNotGenerated(false);
    setActionError(null);

    try {
      const data = await getArtifactInterpretation(id);
      setInterpretation(data);
      setIsNotGenerated(false);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 404) {
        setIsNotGenerated(true);
        setInterpretation(null);
      } else {
        const msg = err instanceof Error ? err.message : "Unable to load interpretation.";
        setLoadError(msg);
        setInterpretation(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    if (!targetId) return;

    getArtifactInterpretation(targetId)
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
            const msg = err instanceof Error ? err.message : "Unable to load interpretation.";
            setLoadError(msg);
            setInterpretation(null);
          }
          setIsLoading(false);
        }
      });

    return () => {
      ignore = true;
    };
  }, [targetId]);

  const handleRetry = () => {
    if (targetId) {
      fetchAndApply(targetId);
    }
  };

  const handleGenerate = async () => {
    if (!targetId || isActionLoading) return;
    setIsActionLoading(true);
    setActionError(null);

    try {
      const data = await generateArtifactInterpretation(targetId, false);
      setInterpretation(data);
      setIsNotGenerated(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unable to generate interpretation.";
      setActionError(msg);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleRefresh = async () => {
    if (!targetId || isActionLoading) return;
    setIsActionLoading(true);
    setActionError(null);

    try {
      const data = await generateArtifactInterpretation(targetId, true);
      setInterpretation(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unable to refresh interpretation.";
      setActionError(msg);
    } finally {
      setIsActionLoading(false);
    }
  };

  // 1. Initial Loading State
  if (isLoading) {
    return (
      <div
        className="bg-white border border-slate-200/90 rounded-xl p-6 font-mono shadow-xs space-y-4"
        role="status"
        aria-live="polite"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-emerald-600 animate-pulse" />
            <h2 className="text-xl font-bold text-slate-900">Forensic Interpretation</h2>
          </div>
        </div>
        <div className="space-y-3 py-6">
          <div className="flex items-center justify-center gap-2 text-slate-500 text-xs">
            <Loader2 className="w-4 h-4 animate-spin text-emerald-600" />
            <span>Loading interpretation…</span>
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
        className="bg-white border border-rose-200 rounded-xl p-6 font-mono shadow-xs space-y-4"
        role="alert"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-rose-600" />
            <h2 className="text-xl font-bold text-slate-900">Forensic Interpretation</h2>
          </div>
        </div>
        <div className="bg-rose-50 border border-rose-200 rounded-lg p-4 text-xs text-rose-800 space-y-2">
          <div className="flex items-center gap-2 font-semibold">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>Unable to load interpretation</span>
          </div>
          <p className="text-rose-700 font-sans">{loadError}</p>
          <button
            type="button"
            onClick={handleRetry}
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
      <div className="bg-white border border-slate-200/90 rounded-xl p-6 font-mono shadow-xs space-y-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <BrainCircuit className="w-6 h-6 text-slate-400" />
            <h2 className="text-xl font-bold text-slate-900">Forensic Interpretation</h2>
          </div>
        </div>

        {actionError && (
          <div
            className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-lg flex items-start gap-2"
            role="alert"
          >
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold block">Unable to generate interpretation</span>
              <span className="font-sans block text-rose-700">{actionError}</span>
            </div>
          </div>
        )}

        <div className="bg-slate-50 border border-slate-200 rounded-xl p-5 text-center space-y-3">
          <p className="text-xs text-slate-600 font-sans leading-relaxed">
            No grounded interpretation has been generated for this artifact yet.
          </p>
          <p className="text-[11px] text-slate-400 font-sans">
            Click below to generate a grounded interpretation based on the deterministic recovery results.
          </p>
          <div>
            <button
              type="button"
              onClick={handleGenerate}
              disabled={isActionLoading}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-lg transition-colors shadow-2xs disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
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
  const { facts, interpretation: output, cached, generated_at } = interpretation;

  return (
    <div className="bg-white border border-slate-200/90 rounded-xl p-6 font-mono shadow-xs space-y-6">
      {/* Header and Refresh Action */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <BrainCircuit className="w-6 h-6 text-emerald-600" />
          <h2 className="text-xl font-bold text-slate-900">Forensic Interpretation</h2>
        </div>
        <button
          type="button"
          onClick={handleRefresh}
          disabled={isActionLoading}
          aria-label="Refresh Interpretation"
          className="inline-flex items-center gap-1.5 px-3 py-1 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs rounded-lg transition-colors shadow-2xs font-semibold disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
        >
          <RefreshCw className={`w-3 h-3 ${isActionLoading ? "animate-spin text-emerald-600" : ""}`} />
          <span>{isActionLoading ? "Refreshing interpretation…" : "Refresh"}</span>
        </button>
      </div>

      {/* Metadata Row: Source, Cache Status, and Generation Timestamp */}
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

        <span className="text-[11px] text-slate-400 font-sans ml-auto">
          Generated: {formatGeneratedTime(generated_at)}
        </span>
      </div>

      {/* Action Error Banner if Refresh Failed */}
      {actionError && (
        <div
          className="p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded-lg flex items-start gap-2"
          role="alert"
        >
          <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-semibold block">Unable to refresh interpretation</span>
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

      {/* 3. Deterministic Recovery Facts */}
      <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
        <div className="bg-slate-100/80 px-4 py-2 border-b border-slate-200 text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center justify-between">
          <span>Recovery Facts</span>
          <span className="text-[10px] text-slate-500 font-normal font-sans">Grounded Recovery Values</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 divide-x divide-y divide-slate-200 bg-white text-xs">
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Format</span>
            <span className="font-bold text-slate-800">{facts.format.toUpperCase()}</span>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Status</span>
            <div className="mt-0.5">
              <StatusBadge status={facts.status} />
            </div>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Confidence</span>
            <span className="font-bold text-emerald-600">{facts.confidence_score}/100</span>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Verified</span>
            <span className="font-bold text-slate-800">{facts.verified_bytes.toLocaleString()} B</span>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Reconstructed</span>
            <span className="font-bold text-slate-800">{facts.reconstructed_bytes.toLocaleString()} B</span>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Missing</span>
            <span className="font-bold text-slate-800">{facts.missing_bytes.toLocaleString()} B</span>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Priority</span>
            <div className="mt-0.5">
              <PriorityBadge priority={facts.priority} />
            </div>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Validation Status</span>
            <span className="font-semibold text-slate-700">{facts.validation_status}</span>
          </div>
          <div className="p-3">
            <span className="text-slate-400 block text-[10px] uppercase">Reconstruction Method</span>
            <span className="font-semibold text-slate-700">{facts.reconstruction_method}</span>
          </div>
        </div>
      </div>

      {/* 4. Structural Context */}
      <div className="space-y-1.5">
        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">Structural Context</h3>
        <p className="text-slate-700 text-xs font-sans leading-relaxed">{output.structural_context}</p>
      </div>

      {/* 5. Limitations */}
      <div className="bg-amber-50/70 p-3.5 rounded-lg border border-amber-200/80 space-y-1">
        <h3 className="text-xs font-bold text-amber-900 uppercase tracking-wider flex items-center gap-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0" />
          <span>Limitations</span>
        </h3>
        <p className="text-amber-900/90 text-xs font-sans leading-relaxed">{output.limitations}</p>
      </div>

      {/* 6. Recommended Next Steps */}
      <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200 space-y-1">
        <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
          <span>Recommended Next Steps</span>
        </h3>
        <p className="text-slate-700 text-xs font-sans leading-relaxed">{output.recommended_next_steps}</p>
      </div>

      {/* 7. Details (rendered only when array contains entries) */}
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
