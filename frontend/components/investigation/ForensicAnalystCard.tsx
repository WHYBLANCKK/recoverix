"use client";

import { useState, useEffect } from "react";
import { AIExplanation, PriorityLevel, SingleFileRecoveryResult } from "@/lib/types";
import { fetchInvestigationExplanation, generateLocalGroundedExplanation } from "@/lib/api";
import {
  BrainCircuit,
  RefreshCw,
  Zap,
  AlertCircle,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  FileSearch,
  ArrowRight,
} from "lucide-react";

interface ForensicAnalystCardProps {
  fileId: string;
  evidenceFacts?: Record<string, unknown> | SingleFileRecoveryResult | null;
  initialBrief?: AIExplanation | null;
}

export function ForensicAnalystCard({
  fileId,
  evidenceFacts,
  initialBrief,
}: ForensicAnalystCardProps) {
  const [brief, setBrief] = useState<AIExplanation | null>(initialBrief || null);
  const [loading, setLoading] = useState(!initialBrief);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const factsObj = evidenceFacts as Record<string, unknown> | undefined;
  const verifiedBytes = Number(factsObj?.verified_bytes ?? brief?.facts?.verified_bytes ?? 0);
  const reconstructedBytes = Number(factsObj?.reconstructed_bytes ?? brief?.facts?.reconstructed_bytes ?? 0);
  const missingBytes = Number(factsObj?.missing_bytes ?? brief?.facts?.missing_bytes ?? 0);
  const reconstructionMethod = String(factsObj?.reconstruction_method ?? brief?.facts?.reconstruction_method ?? "NONE");

  useEffect(() => {
    let isMounted = true;
    async function loadAnalysis() {
      if (initialBrief) {
        setBrief(initialBrief);
        setLoading(false);
        return;
      }
      setLoading(true);
      try {
        const res = await fetchInvestigationExplanation(fileId, factsObj);
        if (isMounted) {
          setBrief(res);
        }
      } catch (err) {
        console.warn("Failed to load forensic evidence interpretation", err);
        if (isMounted) {
          if (factsObj) {
            setBrief(generateLocalGroundedExplanation(fileId, factsObj));
          } else {
            setBrief({
              summary: "Forensic interpretation could not be generated.",
              details: ["Deterministic recovery results remain available."],
              available: false,
              assessment:
                "Deterministic recovery results remain available. Forensic interpretation could not be generated.",
              priority: "MEDIUM",
              why_it_matters: "Backend interpretation service is unavailable or returned an error.",
              recovery_limitation:
                "Forensic interpretation could not be retrieved. Deterministic evidence is unaffected.",
              recommended_next_step:
                "Rely on deterministic findings and verify evidence byte offsets manually.",
              cached: false,
            });
          }
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    }

    loadAnalysis();
    return () => {
      isMounted = false;
    };
  }, [fileId, factsObj, initialBrief]);

  const handleRefresh = async () => {
    setLoading(true);
    try {
      const fresh = await fetchInvestigationExplanation(fileId, factsObj, true);
      setBrief(fresh);
    } catch (err) {
      console.warn("Failed to refresh forensic evidence interpretation", err);
    } finally {
      setLoading(false);
    }
  };

  const isUnavailable = brief?.available === false;

  const priorityColor = (lvl?: PriorityLevel) => {
    switch (lvl) {
      case "CRITICAL":
        return "bg-rose-50 text-rose-700 border-rose-300";
      case "HIGH":
        return "bg-amber-50 text-amber-800 border-amber-300";
      case "MEDIUM":
        return "bg-slate-100 text-slate-800 border-slate-300";
      case "LOW":
      default:
        return "bg-slate-100 text-slate-700 border-slate-300";
    }
  };

  return (
    <section
      id="analyst"
      className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xs font-mono"
    >
      {/* ===================================================================== */}
      {/* HEADER SECTION */}
      {/* ===================================================================== */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 border-b border-slate-100 pb-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
              <BrainCircuit className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base sm:text-lg font-bold uppercase tracking-wider text-slate-900">
                Forensic Evidence Analyst
              </h3>
            </div>
          </div>
          <div className="text-xs text-slate-500 font-sans flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3 pt-1">
            <span className="text-emerald-700 font-medium">
              ✓ Interpretation generated from deterministic recovery facts.
            </span>
            <span className="hidden sm:inline text-slate-300">•</span>
            <span className="text-slate-500">
              Interpretation cannot modify recovered evidence.
            </span>
          </div>
        </div>

        {/* Status Pill & Action */}
        <div className="flex items-center gap-2 self-start sm:self-auto text-xs">
          {!isUnavailable ? (
            <span
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg border font-semibold text-[11px] ${
                brief?.cached
                  ? "bg-slate-100 text-slate-700 border-slate-200"
                  : "bg-emerald-50 text-emerald-800 border-emerald-300"
              }`}
            >
              <Zap className="w-3.5 h-3.5 text-emerald-600" />
              <span>{brief?.cached ? "CACHED ANALYSIS" : "GROUNDED INTERPRETATION"}</span>
            </span>
          ) : (
            <span className="flex items-center gap-1.5 px-3 py-1 rounded-lg border border-amber-300 bg-amber-50 text-amber-800 font-semibold text-[11px]">
              <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
              <span>STATUS: UNAVAILABLE</span>
            </span>
          )}

          <button
            onClick={handleRefresh}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs rounded-lg transition-colors font-semibold shadow-2xs disabled:opacity-50"
            title="Re-query forensic evidence interpretation"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin text-emerald-600" : ""}`} />
            <span>{loading ? "Analyzing..." : "Refresh"}</span>
          </button>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* BODY SECTION: LOADING / UNAVAILABLE / STRUCTURED ANALYST */}
      {/* ===================================================================== */}
      {loading && !brief ? (
        <div className="py-12 flex flex-col items-center justify-center space-y-3 text-slate-500">
          <RefreshCw className="w-6 h-6 animate-spin text-emerald-600" />
          <p className="text-xs uppercase font-semibold tracking-wider">
            Synthesizing Grounded Evidence Brief...
          </p>
        </div>
      ) : isUnavailable ? (
        /* SAFE FAILURE CARD */
        <div className="bg-amber-50/60 border border-amber-200/80 rounded-xl p-5 sm:p-6 space-y-3 text-xs">
          <div className="flex items-center gap-2 text-amber-900 font-bold uppercase tracking-wider text-xs">
            <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
            <span>FORENSIC EVIDENCE ANALYST · STATUS: UNAVAILABLE</span>
          </div>
          <p className="text-slate-800 font-sans leading-relaxed text-sm">
            Deterministic recovery results remain available. Forensic interpretation could not be generated.
          </p>
          <div className="pt-2 text-[11px] text-slate-600 border-t border-amber-200/60 flex items-center gap-2">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            <span>
              All deterministic byte accounting (V/R/M), fragment relationships, and raw evidence downloads remain 100% operational.
            </span>
          </div>
        </div>
      ) : (
        /* ACTIVE STRUCTURED FORENSIC ANALYST */
        <div className="space-y-5">
          {/* Deterministic Fact Bar */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex flex-wrap items-center gap-2 sm:gap-3">
              <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                DETERMINISTIC FACTS:
              </span>
              <span className="bg-emerald-50 text-emerald-800 border border-emerald-200 px-2.5 py-0.5 rounded font-mono font-semibold">
                Verified: {verifiedBytes} B
              </span>
              <span
                className={`border px-2.5 py-0.5 rounded font-mono font-semibold ${
                  reconstructedBytes > 0
                    ? "bg-slate-100 text-slate-800 border-slate-300 font-bold"
                    : "bg-slate-100 text-slate-600 border-slate-200"
                }`}
              >
                Reconstructed: {reconstructedBytes} B
              </span>
              <span
                className={`border px-2.5 py-0.5 rounded font-mono font-semibold ${
                  missingBytes > 0
                    ? "bg-amber-50 text-amber-800 border-amber-300"
                    : "bg-slate-100 text-slate-600 border-slate-200"
                }`}
              >
                Missing: {missingBytes} B
              </span>
            </div>
            <div className="text-[11px] text-slate-600 font-mono">
              Method: <strong className="text-slate-900">{reconstructionMethod}</strong>
            </div>
          </div>

          {/* Safety Notice: Reconstructed vs Preserved Missing */}
          {reconstructedBytes > 0 ? (
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-3 text-xs text-slate-900 font-sans flex items-start gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
              <div>
                <strong>Why this reconstruction is safe:</strong> The{" "}
                {reconstructedBytes} reconstructed bytes were derived strictly from observed container structure and format grammar rules rather than predicted semantic content.
              </div>
            </div>
          ) : missingBytes > 0 ? (
            <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-3 text-xs text-amber-950 font-sans flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <strong>Forensic preservation:</strong> Missing bytes could not be deterministically established and were preserved as missing rather than filled with synthetic speculation.
              </div>
            </div>
          ) : null}

          {/* Top Row: Assessment & Priority */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            {/* A. ASSESSMENT (Cols 1-3) */}
            <div className="lg:col-span-3 bg-slate-50 border border-slate-200 p-5 rounded-xl space-y-2">
              <span className="text-[10px] text-slate-500 uppercase font-semibold tracking-wider block">
                A. FORENSIC ASSESSMENT
              </span>
              <p className="text-slate-900 font-sans text-sm leading-relaxed font-normal">
                {brief?.assessment || brief?.summary || "No assessment generated."}
              </p>
            </div>

            {/* B. PRIORITY (Col 4) */}
            <div className="bg-slate-50 border border-slate-200 p-5 rounded-xl flex flex-col justify-between space-y-3">
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-semibold tracking-wider block mb-2">
                  B. INVESTIGATIVE PRIORITY
                </span>
                <span
                  className={`inline-block px-3 py-1 rounded-md text-xs font-bold border tracking-wider ${priorityColor(
                    brief?.priority
                  )}`}
                >
                  {brief?.priority || "MEDIUM"}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-snug">
                Prioritization ground truth is derived from deterministic damage severity and file type.
              </p>
            </div>
          </div>

          {/* Middle Row: Why this matters & Recovery limitation */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* C. WHY THIS MATTERS */}
            <div className="bg-slate-50 border border-slate-200 p-5 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-slate-700 font-semibold uppercase text-[11px] tracking-wider">
                <FileSearch className="w-4 h-4 text-slate-600" />
                <span>C. Why This Matters</span>
              </div>
              <p className="text-slate-800 font-sans leading-relaxed text-xs">
                {brief?.why_it_matters ||
                  "The recovered evidence preserves validated structural boundaries for evidence review."}
              </p>
            </div>

            {/* D. RECOVERY LIMITATION */}
            <div className="bg-slate-50 border border-slate-200 p-5 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-slate-700 font-semibold uppercase text-[11px] tracking-wider">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                <span>D. Forensic Recovery Limitation</span>
              </div>
              <p className="text-slate-800 font-sans leading-relaxed text-xs">
                {brief?.recovery_limitation ||
                  "Recoverix strictly refused to hallucinate or fabricate missing byte regions."}
              </p>
            </div>
          </div>

          {/* E. RECOMMENDED NEXT STEP */}
          <div className="bg-emerald-50/50 border border-emerald-200/80 p-5 rounded-xl space-y-2 text-xs">
            <div className="flex items-center gap-2 text-emerald-900 font-bold uppercase text-[11px] tracking-wider">
              <ArrowRight className="w-4 h-4 text-emerald-600" />
              <span>E. Recommended Next Investigation Step</span>
            </div>
            <p className="text-slate-800 font-sans leading-relaxed text-xs">
              {brief?.recommended_next_step ||
                "Review the original evidence source or examine adjacent unallocated clusters for matching fragments."}
            </p>
          </div>

          {/* Optional: Grounded Reasoning Details Toggle */}
          {brief?.details && brief.details.length > 0 && (
            <div className="border border-slate-200 rounded-xl overflow-hidden bg-white text-xs">
              <button
                onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
                className="w-full px-4 py-3 flex items-center justify-between text-slate-600 hover:text-slate-900 transition-colors bg-slate-50/50 text-[11px] font-semibold"
              >
                <span>View Grounded Evaluation Statements ({brief.details.length})</span>
                {showTechnicalDetails ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>

              {showTechnicalDetails && (
                <div className="p-4 border-t border-slate-200 space-y-2.5 bg-slate-50/30 font-sans text-xs">
                  {brief.details.map((detail, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-slate-700">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 mt-1.5 shrink-0" />
                      <span className="leading-relaxed">{detail}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
