"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import {
  Shield,
  Download,
  FileText,
  Copy,
  Check,
  ArrowLeft,
  Loader2,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  AlertCircle,
  FileCode,
  ExternalLink,
} from "lucide-react";
import {
  API_BASE,
  fetchRecoveredFile,
  fetchRecoveryRun,
  fetchArtifactById,
  adaptRecoveryRunToInvestigationResult,
  adaptArtifactToInvestigationResult,
  sanitizeDownloadUrl,
} from "@/lib/api";
import { SingleFileRecoveryResult, InvestigationContext } from "@/lib/types";
import { FragmentGraph } from "@/components/investigation/FragmentGraph";
import { ByteEvidenceMap } from "@/components/investigation/ByteEvidenceMap";
import { ForensicAnalystCard } from "@/components/investigation/ForensicAnalystCard";
import { ClusterInterpretationCard } from "@/components/investigation/ClusterInterpretationCard";
import { RecoverixLogo } from "@/components/ui/RecoverixLogo";

export default function InvestigationPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const resolvedParams = use(params);
  const fileId = resolvedParams.id;

  const [result, setResult] = useState<SingleFileRecoveryResult | null>(null);
  const [context, setContext] = useState<InvestigationContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [isExpired, setIsExpired] = useState(false);
  const [errorType, setErrorType] = useState<"NOT_FOUND" | "NETWORK_ERROR" | null>(null);
  const [copiedPreview, setCopiedPreview] = useState(false);
  const [showRubricDetails, setShowRubricDetails] = useState(false);
  const [activeSection, setActiveSection] = useState<
    "overview" | "fragments" | "cluster" | "map" | "preview" | "provenance" | "analyst"
  >("overview");
  const [activeCaseId, setActiveCaseId] = useState<string>("case_001");
  const [activeClusterId, setActiveClusterId] = useState<string>("cluster_0");

  useEffect(() => {
    async function loadInvestigation() {
      setLoading(true);

      // 1. Try local storage cache for instant hydration
      let cachedResult: SingleFileRecoveryResult | null = null;
      let cachedContext: InvestigationContext | null = null;

      if (typeof window !== "undefined") {
        const storedResult = localStorage.getItem(`recoverix_result_${fileId}`);
        if (storedResult) {
          try {
            cachedResult = JSON.parse(storedResult);
            setResult(cachedResult);
          } catch (e) {
            console.warn("Failed to parse cached result", e);
          }
        }

        const storedContext = localStorage.getItem(`recoverix_context_${fileId}`);
        if (storedContext) {
          try {
            cachedContext = JSON.parse(storedContext);
            setContext(cachedContext);
          } catch (e) {
            console.warn("Failed to parse cached context", e);
          }
        }

        const sp = new URLSearchParams(window.location.search);
        const urlCaseId = sp.get("case_id");
        const urlClusterId = sp.get("cluster_id");
        const localCaseId = localStorage.getItem("recoverix_active_case_id");
        if (urlCaseId) {
          setActiveCaseId(urlCaseId);
        } else if (localCaseId) {
          setActiveCaseId(localCaseId);
        }
        if (urlClusterId) {
          setActiveClusterId(urlClusterId);
        }
      }

      // 2. Query real live backend across supported lookup paths
      try {
        let liveResult: SingleFileRecoveryResult | null = null;

        // Path 1: Standalone single-file recovery store
        liveResult = await fetchRecoveredFile(fileId);

        // Path 2: Recovery run trace store (lookup by run_id or artifact_id)
        if (!liveResult) {
          const run = await fetchRecoveryRun(fileId);
          if (run) {
            liveResult = adaptRecoveryRunToInvestigationResult(run);
          }
        }

        // Path 3: Case artifact store (lookup by artifact_id)
        if (!liveResult) {
          try {
            const artifact = await fetchArtifactById(fileId);
            if (artifact) {
              liveResult = adaptArtifactToInvestigationResult(artifact);
            }
          } catch {
            // Identifier not in artifact store
          }
        }

        // Path 4: Enrichment from run_id if fragments or damage regions are unpopulated
        if (liveResult && (!liveResult.fragments || liveResult.fragments.length === 0) && liveResult.run_id) {
          const run = await fetchRecoveryRun(liveResult.run_id);
          if (run) {
            liveResult.fragments = run.fragments;
            liveResult.damage_regions = run.damage_regions;
            liveResult.reconstruction_steps = run.reconstruction_steps;
            if (!liveResult.total_input_bytes && run.total_input_bytes) {
              liveResult.total_input_bytes = run.total_input_bytes;
            }
          }
        }

        if (liveResult) {
          // Enforce strict download safety invariants
          liveResult.download_url = sanitizeDownloadUrl(liveResult.download_url, liveResult.file_id);
          const isPermitted = liveResult.status === "FULLY_RECOVERED" || liveResult.status === "PARTIALLY_RECOVERED";
          liveResult.is_downloadable = Boolean(
            liveResult.is_downloadable === true &&
            isPermitted &&
            liveResult.validation_status === "PASSED" &&
            liveResult.download_url
          );

          setResult(liveResult);
          setIsExpired(false);
          setErrorType(null);
          if (typeof window !== "undefined") {
            localStorage.setItem(`recoverix_result_${fileId}`, JSON.stringify(liveResult));
          }
        } else {
          // No live record found on backend
          if (cachedResult) {
            // Artifact purged from backend memory (24h retention) but available in local session
            setIsExpired(true);
            setResult({
              ...cachedResult,
              is_downloadable: false, // Expired server files cannot be downloaded
            });
          } else {
            setResult(null);
            setErrorType("NOT_FOUND");
          }
        }
      } catch (err) {
        console.error("Failed to query live backend:", err);
        if (cachedResult) {
          setIsExpired(true);
          setResult({
            ...cachedResult,
            is_downloadable: false,
          });
        } else {
          setResult(null);
          setErrorType("NETWORK_ERROR");
        }
      } finally {
        setLoading(false);
      }
    }

    loadInvestigation();
  }, [fileId]);

  const handleCopyPreview = () => {
    if (result?.content_preview) {
      navigator.clipboard.writeText(result.content_preview);
      setCopiedPreview(true);
      setTimeout(() => setCopiedPreview(false), 2000);
    }
  };

  if (loading && !result) {
    return (
      <main className="min-h-screen bg-[#F8FAFC] flex flex-col items-center justify-center text-slate-600 font-mono">
        <Loader2 className="w-10 h-10 text-emerald-600 animate-spin mb-4" />
        <p className="text-xs uppercase tracking-wider font-semibold">Hydrating Forensic Investigation Workspace...</p>
      </main>
    );
  }

  if (!result) {
    if (errorType === "NETWORK_ERROR") {
      return (
        <main className="min-h-screen bg-[#F8FAFC] text-slate-800 py-16 px-6 font-mono text-center space-y-4">
          <AlertCircle className="w-12 h-12 text-rose-500 mx-auto mb-2" />
          <h2 className="text-xl font-bold text-slate-900 uppercase tracking-wider">RECOVERY ENGINE UNREACHABLE</h2>
          <p className="text-xs text-slate-600 max-w-md mx-auto font-sans leading-relaxed">
            Could not connect to the Recoverix backend engine to load investigation <code className="text-slate-800 font-bold">{fileId}</code>. Please verify your connection or backend service status.
          </p>
          <div className="pt-4 flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold px-5 py-2.5 rounded-lg text-xs transition-colors shadow-xs"
            >
              Retry Connection
            </button>
            <Link
              href="/"
              className="bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 font-bold px-5 py-2.5 rounded-lg text-xs transition-colors shadow-2xs"
            >
              Return Home
            </Link>
          </div>
        </main>
      );
    }

    return (
      <main className="min-h-screen bg-[#F8FAFC] text-slate-800 py-16 px-6 font-mono text-center space-y-4">
        <h2 className="text-xl font-bold text-slate-900 uppercase tracking-wider">INVESTIGATION NOT FOUND OR EXPIRED</h2>
        <p className="text-xs text-slate-600 max-w-md mx-auto font-sans leading-relaxed">
          No active recovery run or artifact records match identifier <code className="text-emerald-700 font-bold">{fileId}</code>. Standalone recovery sessions are automatically purged after 24 hours.
        </p>
        <div className="pt-4 flex items-center justify-center gap-3">
          <Link
            href="/"
            className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold px-6 py-2.5 rounded-lg text-xs inline-block transition-colors shadow-xs"
          >
            Upload Evidence (Home)
          </Link>
          <Link
            href="/setup"
            className="bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 font-bold px-5 py-2.5 rounded-lg text-xs inline-block transition-colors shadow-2xs"
          >
            Detailed Intake
          </Link>
        </div>
      </main>
    );
  }

  const caseName = context?.case_name || result.case_name || "Direct File Intake";
  const investigatorName = context?.investigator || result.investigator || "Unassigned Investigator";
  const fileHash = context?.sha256 || null;

  const totalInput = result.total_input_bytes && result.total_input_bytes > 0
    ? result.total_input_bytes
    : (result.verified_bytes + result.missing_bytes);
  const totalOutput = result.verified_bytes + result.reconstructed_bytes;
  const verifiedPct = totalInput > 0 ? Math.round((result.verified_bytes / totalInput) * 100) : 0;
  const missingPct = totalInput > 0 ? Math.max(0, 100 - verifiedPct) : 0;
  const reconPct = totalOutput > 0 ? Math.round((result.reconstructed_bytes / totalOutput) * 100) : 0;

  const isPermittedStatus = result.status === "FULLY_RECOVERED" || result.status === "PARTIALLY_RECOVERED";
  const isDownloadable = Boolean(
    result.is_downloadable === true &&
    isPermittedStatus &&
    result.validation_status === "PASSED" &&
    result.download_url &&
    !isExpired
  );

  const fragments = result.fragments || [];
  const damageRegions = result.damage_regions || [];
  const reconstructionSteps = result.reconstruction_steps || [];

  return (
    <main className="min-h-screen bg-[#F8FAFC] text-slate-900 py-8 px-4 sm:px-6 font-mono selection:bg-emerald-500/20 selection:text-emerald-950">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Expired Session Notice */}
        {isExpired && (
          <div className="p-4 rounded-xl bg-amber-50 border border-amber-300 text-amber-900 text-xs font-mono flex items-start gap-3 shadow-2xs">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-amber-800 uppercase tracking-wide">
                Server Session Expired (24h Retention Limit)
              </div>
              <p className="text-[11px] text-amber-800 font-sans leading-relaxed">
                This recovered artifact has been purged from backend memory under the 24-hour retention policy. Evidence metrics below are preserved from your local session audit, but downloads are unavailable. To re-download, please upload your file again.
              </p>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* WORKSPACE HEADER BAR */}
        {/* ========================================================================= */}
        <div className="bg-white border border-slate-200/90 rounded-2xl p-6 shadow-xs space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-100 pb-5">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <Link
                  href="/"
                  className="hover:text-slate-900 transition-colors flex items-center gap-1.5 text-[11px]"
                  aria-label="Recoverix Home"
                >
                  <RecoverixLogo size={14} showText={false} markOnly />
                  <span className="font-bold">RECOVERIX</span>
                </Link>
                <span>/</span>
                <Link
                  href="/"
                  className="hover:text-slate-900 transition-colors flex items-center gap-1 text-[11px]"
                >
                  <ArrowLeft className="w-3 h-3" /> Home
                </Link>
                <span>/</span>
                <span className="text-emerald-700 font-bold uppercase">{caseName}</span>
                <span>/</span>
                <span className="text-slate-400 font-mono text-[10px]">ID: {result.file_id}</span>
              </div>

              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 flex items-center gap-3">
                <span>{result.recovered_filename}</span>
                <span className="text-xs px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-slate-700 font-semibold">
                  {result.format.toUpperCase()}
                </span>
              </h1>
            </div>

            {/* Quick Actions & Download Header Button */}
            <div className="flex flex-wrap items-center gap-3 self-start lg:self-auto">
              {isDownloadable ? (
                <a
                  href={result.download_url}
                  download={result.recovered_filename}
                  className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold text-xs px-4 py-2.5 rounded-xl shadow-xs transition-all flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  <span>DOWNLOAD ARTIFACT</span>
                </a>
              ) : (
                <div
                  className="bg-slate-100 text-slate-400 border border-slate-200 font-mono text-xs px-3 py-2 rounded-xl flex items-center gap-2 cursor-not-allowed"
                  title={
                    isExpired
                      ? "Artifact expired from server memory"
                      : result.status === "UNRECOVERABLE"
                      ? "Artifact is unrecoverable"
                      : "Structural validation failed"
                  }
                >
                  <Download className="w-3.5 h-3.5 text-slate-400" />
                  <span>
                    DOWNLOAD UNAVAILABLE ({isExpired ? "EXPIRED" : result.status === "UNRECOVERABLE" ? "UNRECOVERABLE" : "VALIDATION FAILED"})
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Investigation Metadata Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">INVESTIGATOR</span>
              <span className="text-slate-900 font-bold truncate block">{investigatorName}</span>
            </div>
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">SOURCE EVIDENCE</span>
              <span className="text-slate-900 font-bold truncate block">{result.original_filename}</span>
            </div>
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">RECOVERY METHOD</span>
              <span className="text-sky-700 font-bold truncate block">{result.reconstruction_method}</span>
            </div>
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">RECOVERY RUN ID</span>
              <span className="text-slate-700 font-bold truncate block">{result.run_id || result.file_id}</span>
            </div>
            <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
              <span className="text-[10px] text-slate-500 uppercase font-semibold block">TOTAL INPUT BYTES</span>
              <span className="text-slate-900 font-bold block">{totalInput.toLocaleString()} B</span>
            </div>
          </div>

          {/* Investigation Notes if present */}
          {(result.notes || context?.notes) && (
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono">
              <span className="text-[10px] uppercase font-bold text-slate-500 block mb-0.5">
                Investigation Notes
              </span>
              <p className="text-slate-700 font-sans text-xs">
                {result.notes || context?.notes}
              </p>
            </div>
          )}

          {/* Investigation Navigation Tabs */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-100 text-xs font-mono">
            {[
              { id: "overview", label: "Overview" },
              { id: "fragments", label: "Fragments" },
              { id: "cluster", label: "Cluster Interpretation" },
              { id: "map", label: "Evidence Map" },
              { id: "preview", label: "Recovery" },
              { id: "provenance", label: "Provenance" },
              { id: "analyst", label: "Forensic Analyst" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveSection(tab.id as any);
                  const el = document.getElementById(tab.id);
                  if (el) {
                    el.scrollIntoView({ behavior: "smooth" });
                  }
                }}
                className={`px-3 py-1.5 rounded-lg transition-colors font-medium cursor-pointer ${
                  activeSection === tab.id
                    ? "bg-purple-50 text-purple-800 border border-purple-300 font-bold shadow-2xs"
                    : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* ========================================================================= */}
        {/* SECTION 1 — RECOVERY SUMMARY & 3 CORE ACCOUNTING BLOCKS */}
        {/* ========================================================================= */}
        <section className="space-y-4">
          <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 shadow-xs space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-100 pb-6">
              {/* Large Status */}
              <div>
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-1">
                  RECOVERY STATUS CLASSIFICATION
                </span>
                <div className="flex flex-wrap items-center gap-2.5 sm:gap-3">
                  <span
                    className={`text-xl sm:text-2xl font-bold px-4 py-1.5 rounded-xl border ${
                      result.status === "FULLY_RECOVERED"
                        ? "bg-emerald-50 text-emerald-700 border-emerald-300"
                        : result.status === "PARTIALLY_RECOVERED"
                        ? "bg-amber-50 text-amber-800 border-amber-300"
                        : "bg-rose-50 text-rose-700 border-rose-300"
                    }`}
                  >
                    {result.status.replace("_", " ")}
                  </span>
                  <span className="text-xs bg-slate-100 text-slate-700 border border-slate-200 px-3 py-1.5 rounded-xl font-mono font-semibold">
                    METHOD: {result.reconstruction_method}
                  </span>
                  <span
                    className={`text-xs px-3 py-1.5 rounded-xl font-mono font-semibold border ${
                      result.validation_status === "PASSED"
                        ? "bg-emerald-50 text-emerald-800 border-emerald-300"
                        : "bg-rose-50 text-rose-800 border-rose-300"
                    }`}
                  >
                    VALIDATION: {result.validation_status}
                  </span>
                </div>
              </div>

              {/* Confidence Meter */}
              <div className="text-left md:text-right">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold block mb-0.5">
                  OBJECTIVE FORENSIC SCORE
                </span>
                <div className="text-3xl sm:text-4xl font-bold text-slate-900 tracking-tight">
                  {result.confidence_score.toFixed(2)}%
                  <span className="text-xs text-slate-500 font-normal ml-1">CONFIDENCE</span>
                </div>
                <div className="text-[11px] text-emerald-700 font-sans mt-0.5 font-medium">
                  100-Point Deterministic Rubric Evaluated
                </div>
              </div>
            </div>

            {/* Three Highly Visible Core Metrics (V/R/M) */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-600 uppercase tracking-wider font-semibold">
                  Deterministic Byte Accounting (V/R/M Standard)
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  Evidence Size: {totalInput.toLocaleString()} bytes
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {/* VERIFIED BYTES */}
                <div className="bg-white border border-emerald-300 p-5 rounded-xl relative overflow-hidden shadow-2xs">
                  <div className="text-[11px] uppercase font-bold text-emerald-700 flex items-center justify-between mb-2">
                    <span>[VERIFIED (V)]</span>
                    <span className="bg-emerald-50 text-emerald-800 border border-emerald-200 px-2 py-0.5 rounded text-[10px]">
                      {verifiedPct}%
                    </span>
                  </div>
                  <div className="text-3xl font-bold text-emerald-600 font-mono">
                    {result.verified_bytes.toLocaleString()}
                    <span className="text-sm font-normal text-emerald-700 ml-1">B</span>
                  </div>
                  <p className="text-xs text-slate-600 font-sans mt-1">
                    Exact evidence verified structurally intact without mutation.
                  </p>
                </div>

                {/* RECONSTRUCTED BYTES */}
                <div className="bg-white border border-sky-300 p-5 rounded-xl relative overflow-hidden shadow-2xs">
                  <div className="text-[11px] uppercase font-bold text-sky-700 flex items-center justify-between mb-2">
                    <span>[RECONSTRUCTED (R)]</span>
                    <span className="bg-sky-50 text-sky-800 border border-sky-200 px-2 py-0.5 rounded text-[10px]">
                      {reconPct}%
                    </span>
                  </div>
                  <div className="text-3xl font-bold text-sky-600 font-mono">
                    {result.reconstructed_bytes.toLocaleString()}
                    <span className="text-sm font-normal text-sky-700 ml-1">B</span>
                  </div>
                  <p className="text-xs text-slate-600 font-sans mt-1">
                    Repaired via deterministic structural inference & container syntax.
                  </p>
                </div>

                {/* MISSING BYTES */}
                <div className="bg-white border border-rose-300 p-5 rounded-xl relative overflow-hidden shadow-2xs">
                  <div className="text-[11px] uppercase font-bold text-rose-700 flex items-center justify-between mb-2">
                    <span>[MISSING (M)]</span>
                    <span className="bg-rose-50 text-rose-800 border border-rose-200 px-2 py-0.5 rounded text-[10px]">
                      {missingPct}%
                    </span>
                  </div>
                  <div className="text-3xl font-bold text-rose-600 font-mono">
                    {result.missing_bytes.toLocaleString()}
                    <span className="text-sm font-normal text-rose-700 ml-1">B</span>
                  </div>
                  <p className="text-xs text-slate-600 font-sans mt-1">
                    Unobserved evidence gaps preserved without synthetic fabrication.
                  </p>
                </div>
              </div>

              <p className="text-[11px] text-slate-400 font-mono text-center pt-1">
                Mathematical Proof: V + R = {totalOutput.toLocaleString()} bytes recovered · V + M = {totalInput.toLocaleString()} bytes evidence input
              </p>
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* SECTION 2 — REAL FRAGMENT RELATIONSHIP GRAPH */}
        {/* ========================================================================= */}
        <section id="fragments" className="space-y-4">
          <FragmentGraph
            filename={result.original_filename}
            totalBytes={totalInput}
            verifiedBytes={result.verified_bytes}
            reconstructedBytes={result.reconstructed_bytes}
            missingBytes={result.missing_bytes}
            fragments={fragments}
            damageRegions={damageRegions}
            reconstructionSteps={reconstructionSteps}
            status={result.status}
            format={result.format}
            reconstructionMethod={result.reconstruction_method}
            validationStatus={result.validation_status}
          />
        </section>

        {/* ========================================================================= */}
        {/* SECTION 2.5 — CLUSTER-LEVEL GROUNDED INTERPRETATION */}
        {/* ========================================================================= */}
        <section id="cluster" className="space-y-4">
          <ClusterInterpretationCard
            caseId={activeCaseId}
            clusterId={activeClusterId}
            onClusterChange={setActiveClusterId}
          />
        </section>

        {/* ========================================================================= */}
        {/* SECTION 3 — BYTE-LEVEL EVIDENCE MAP */}
        {/* ========================================================================= */}
        <section id="map" className="space-y-4">
          <ByteEvidenceMap
            totalBytes={totalInput}
            verifiedBytes={result.verified_bytes}
            reconstructedBytes={result.reconstructed_bytes}
            missingBytes={result.missing_bytes}
            fragments={fragments}
            damageRegions={damageRegions}
            reconstructionSteps={reconstructionSteps}
          />
        </section>

        {/* ========================================================================= */}
        {/* SECTION 6 — WHAT RECOVERIX COULD NOT RECOVER (UNRECOVERED EVIDENCE) */}
        {/* ========================================================================= */}
        {result.missing_bytes > 0 && (
          <section className="bg-amber-50 border border-amber-200 rounded-2xl p-6 sm:p-8 space-y-3">
            <div className="flex items-center gap-2 text-amber-800 text-xs font-bold uppercase tracking-wider">
              <AlertTriangle className="w-5 h-5 shrink-0 text-amber-600" />
              <span>UNRECOVERED EVIDENCE — FORENSIC INTEGRITY NOTICE</span>
            </div>
            <p className="text-sm text-slate-800 leading-relaxed font-sans">
              <strong>{result.missing_bytes.toLocaleString()} bytes</strong> could not be deterministically established and were preserved as missing.
            </p>
            <p className="text-xs text-slate-600 font-sans leading-relaxed">
              Unobserved bytes remain strictly classified as missing evidence to maintain byte-accurate auditability. Recoverix guarantees that missing regions are never backfilled with guessed or synthetic filler.
            </p>
          </section>
        )}

        {/* ========================================================================= */}
        {/* SECTION 4 & 5 — ARTIFACT PREVIEW & PROVENANCE PANEL */}
        {/* ========================================================================= */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* SECTION 4: ARTIFACT PREVIEW (Cols 1-7) */}
          <section id="preview" className="lg:col-span-7 bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-xs">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-emerald-600" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
                  Recovered Artifact Preview
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyPreview}
                  className="flex items-center gap-1 text-[11px] text-slate-600 hover:text-slate-900 transition-colors bg-white px-2.5 py-1 rounded border border-slate-300 shadow-2xs"
                >
                  {copiedPreview ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-600" /> Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" /> Copy Bytes
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Structural Reconstruction Callout (When R > 0) */}
            {result.reconstructed_bytes > 0 && (
              <div className="bg-sky-50 border border-sky-200 rounded-xl p-3.5 text-xs text-sky-950 font-mono space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sky-800 flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-sky-500 animate-pulse" />
                    STRUCTURAL RECONSTRUCTION ACTIVE (R &gt; 0)
                  </span>
                  <span className="text-[10px] bg-sky-100 text-sky-800 px-2 py-0.5 rounded font-bold">
                    +{result.reconstructed_bytes} B APPENDED
                  </span>
                </div>
                <p className="text-[11px] text-slate-700 font-sans">
                  Recoverix deterministically repaired missing structural closing syntax using format grammar (<code className="font-mono text-sky-700 font-semibold">{result.reconstruction_method}</code>). The resulting byte buffer passed schema and parser validation.
                </p>
              </div>
            )}

            {/* Content Preview */}
            {result.format === "pdf" ? (
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 text-center space-y-4">
                <div className="w-16 h-16 rounded-2xl bg-rose-50 border border-rose-200 flex items-center justify-center mx-auto text-rose-600">
                  <FileText className="w-8 h-8" />
                </div>
                <div className="space-y-1">
                  <div className="text-slate-900 font-bold text-sm tracking-wide">RECOVERED PDF DOCUMENT</div>
                  <div className="text-xs text-slate-600 font-sans">
                    {result.recovered_filename} · {(result.verified_bytes + result.reconstructed_bytes).toLocaleString()} Bytes
                  </div>
                  <div className={`text-[11px] font-mono font-semibold ${
                    result.validation_status === "PASSED" ? "text-emerald-700" : "text-rose-700"
                  }`}>
                    {result.validation_status === "PASSED"
                      ? "✓ Valid PDF Structure · Cross-Reference (xref) Verified"
                      : "✗ Structural Validation Failed · PDF Format Incomplete"}
                  </div>
                </div>
                {result.is_downloadable && !isExpired && (
                  <div className="pt-2">
                    <a
                      href={sanitizeDownloadUrl(result.download_url, fileId)}
                      target="_blank"
                      rel="noopener noreferrer"
                      download={result.recovered_filename}
                      className="inline-flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-white font-bold px-6 py-2.5 rounded-xl text-xs transition-all shadow-xs"
                    >
                      <ExternalLink className="w-4 h-4" />
                      <span>OPEN / DOWNLOAD RECOVERED PDF</span>
                    </a>
                  </div>
                )}
              </div>
            ) : result.format === "png" || result.format === "jpeg" ? (
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-6 text-center space-y-4">
                <div className="w-16 h-16 rounded-2xl bg-sky-50 border border-sky-200 flex items-center justify-center mx-auto text-sky-600">
                  <FileCode className="w-8 h-8" />
                </div>
                <div className="space-y-1">
                  <div className="text-slate-900 font-bold text-sm tracking-wide">RECOVERED {result.format.toUpperCase()} IMAGE</div>
                  <div className="text-xs text-slate-600 font-sans">
                    {result.recovered_filename} · {(result.verified_bytes + result.reconstructed_bytes).toLocaleString()} Bytes
                  </div>
                  <div className={`text-[11px] font-mono font-semibold ${
                    result.validation_status === "PASSED" ? "text-emerald-700" : "text-rose-700"
                  }`}>
                    {result.validation_status === "PASSED"
                      ? "✓ Authoritative Signature & Chunks Validated"
                      : "✗ Structural Validation Failed · Image Corrupted or Incomplete"}
                  </div>
                </div>
                {isDownloadable && (
                  <div className="pt-2">
                    <a
                      href={sanitizeDownloadUrl(result.download_url, fileId)}
                      download={result.recovered_filename}
                      className="inline-flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-white font-bold px-6 py-2.5 rounded-xl text-xs transition-all shadow-xs"
                    >
                      <Download className="w-4 h-4" />
                      <span>DOWNLOAD RECOVERED IMAGE</span>
                    </a>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-1.5">
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs overflow-x-auto max-h-64 scrollbar-thin">
                  <pre className="text-slate-100 whitespace-pre-wrap break-all leading-relaxed font-mono">
                    {result.content_preview || "[No text preview available for binary stream]"}
                  </pre>
                </div>
                {result.reconstructed_bytes > 0 && (
                  <div className="text-[11px] text-slate-500 flex items-center justify-between px-1 font-mono">
                    <span>Observed Input: <strong>{result.verified_bytes} B</strong></span>
                    <span className="text-sky-700 font-semibold">Reconstructed Syntax: <strong>+{result.reconstructed_bytes} B</strong></span>
                    <span>Total Artifact: <strong>{result.verified_bytes + result.reconstructed_bytes} B</strong></span>
                  </div>
                )}
              </div>
            )}

            {/* Download CTA Bar */}
            <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-4 border-t border-slate-100">
              <div className="text-xs text-slate-600">
                <span>Output File: <strong className="text-slate-900">{result.recovered_filename}</strong></span>
              </div>

              {isDownloadable ? (
                <a
                  href={sanitizeDownloadUrl(result.download_url, fileId)}
                  download={result.recovered_filename}
                  className="w-full sm:w-auto bg-emerald-500 hover:bg-emerald-600 text-white font-bold text-xs py-2.5 px-6 rounded-xl transition-all flex items-center justify-center gap-2 shadow-xs"
                >
                  <Download className="w-4 h-4" />
                  <span>DOWNLOAD RECOVERED ARTIFACT</span>
                </a>
              ) : (
                <div className="w-full sm:w-auto bg-slate-100 text-slate-500 font-bold text-xs py-2.5 px-6 rounded-xl flex items-center justify-center gap-2 border border-slate-200 cursor-not-allowed">
                  <AlertCircle className="w-3.5 h-3.5 text-slate-400" />
                  <span>
                    DOWNLOAD UNAVAILABLE ({
                      isExpired
                        ? "SESSION EXPIRED"
                        : result.status === "UNRECOVERABLE"
                        ? "EVIDENCE UNRECOVERABLE"
                        : result.status === "CORRUPTED"
                        ? "INTEGRITY CORRUPTED"
                        : result.validation_status !== "PASSED"
                        ? "VALIDATION FAILED"
                        : "NOT GENERATED"
                    })
                  </span>
                </div>
              )}
            </div>
          </section>

          {/* SECTION 5: PROVENANCE PANEL (Cols 8-12) */}
          <section id="provenance" className="lg:col-span-5 bg-white border border-slate-200/90 rounded-2xl p-6 space-y-4 shadow-xs">
            <div className="border-b border-slate-100 pb-4 flex items-center justify-between">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900 flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-600" />
                <span>Evidence Provenance</span>
              </h3>
              <span className="text-[10px] text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-semibold">
                BYTE PROVENANCE
              </span>
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="flex justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 uppercase font-semibold">Verified Bytes:</span>
                <span className="text-emerald-700 font-bold">{result.verified_bytes.toLocaleString()} B</span>
              </div>
              <div className="flex justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 uppercase font-semibold">Reconstructed Bytes:</span>
                <span className="text-sky-700 font-bold">{result.reconstructed_bytes.toLocaleString()} B</span>
              </div>
              <div className="flex justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 uppercase font-semibold">Missing Bytes:</span>
                <span className="text-amber-700 font-bold">{result.missing_bytes.toLocaleString()} B</span>
              </div>
              <div className="flex justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 uppercase font-semibold">Recovery Method:</span>
                <span className="text-slate-900 font-semibold truncate">{result.reconstruction_method}</span>
              </div>
              <div className="flex justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 uppercase font-semibold">Validation Status:</span>
                <span className={`font-bold ${result.validation_status === "PASSED" ? "text-emerald-700" : "text-rose-700"}`}>{result.validation_status}</span>
              </div>
              <div className="flex justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200">
                <span className="text-slate-500 uppercase font-semibold">Format Spec:</span>
                <span className="text-slate-900 font-semibold">{result.format.toUpperCase()}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                <span className="text-slate-500 uppercase text-[10px] font-semibold block">Evidence SHA-256:</span>
                <span className="text-slate-700 font-mono text-[10px] break-all select-all block">
                  {fileHash || "[Not recorded during intake]"}
                </span>
              </div>
            </div>
          </section>
        </div>

        {/* ========================================================================= */}
        {/* SECTION 7 — RECOVERY EXPLANATION (DETERMINISTIC FINDINGS) */}
        {/* ========================================================================= */}
        <section className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 space-y-4 shadow-xs">
          <div className="flex items-center justify-between border-b border-slate-100 pb-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
              Recovery Analysis & Findings
            </h3>
            <span className="text-[10px] text-slate-500 uppercase font-semibold">
              DETERMINISTIC FINDINGS ONLY
            </span>
          </div>

          <div className="space-y-3 text-xs leading-relaxed">
            {/* Deterministic Findings */}
            <div className="bg-slate-50 border border-sky-200 p-4 rounded-xl space-y-2">
              <div className="text-sky-800 font-bold uppercase flex items-center gap-2">
                <span>[DETERMINISTIC STRUCTURAL FINDINGS]</span>
              </div>
              <p className="text-slate-700 font-sans">
                Evidence file <strong className="text-slate-900 font-mono">{result.original_filename}</strong> was evaluated across format-specific structural parsers. Header signature validated. Structural validation executed via <code className="text-sky-700 font-mono font-semibold">{result.reconstruction_method}</code> returning <span className={`font-bold ${result.validation_status === "PASSED" ? "text-emerald-700" : "text-rose-700"}`}>{result.validation_status}</span>.
              </p>
              <div className="text-[11px] text-slate-500 pt-1">
                Zero synthetic predictions were used to generate or alter raw evidence byte offsets.
              </div>
            </div>

            {/* Rubric Breakdown Toggle */}
            <div className="border border-slate-200 rounded-xl overflow-hidden bg-white">
              <button
                onClick={() => setShowRubricDetails(!showRubricDetails)}
                className="w-full px-4 py-3 flex items-center justify-between text-xs text-slate-600 hover:text-slate-900 transition-colors bg-slate-50/50"
              >
                <span className="font-semibold">100-Point Forensic Rubric Component Breakdown</span>
                {showRubricDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>

              {showRubricDetails && (
                <div className="p-4 border-t border-slate-200 space-y-4">
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center">
                    <div className="bg-slate-50 border border-slate-200 p-2 rounded-lg">
                      <span className="text-slate-500 text-[9px] uppercase font-semibold block">Header (20)</span>
                      <span className="text-slate-900 font-bold">{result.score_breakdown.header_validity.toFixed(1)}</span>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 p-2 rounded-lg">
                      <span className="text-slate-500 text-[9px] uppercase font-semibold block">Footer (20)</span>
                      <span className="text-slate-900 font-bold">{result.score_breakdown.footer_validity.toFixed(1)}</span>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 p-2 rounded-lg">
                      <span className="text-slate-500 text-[9px] uppercase font-semibold block">Structure (30)</span>
                      <span className="text-slate-900 font-bold">{result.score_breakdown.structural_validation.toFixed(1)}</span>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 p-2 rounded-lg">
                      <span className="text-slate-500 text-[9px] uppercase font-semibold block">Size (15)</span>
                      <span className="text-slate-900 font-bold">{result.score_breakdown.size_plausibility.toFixed(1)}</span>
                    </div>
                    <div className="bg-slate-50 border border-slate-200 p-2 rounded-lg">
                      <span className="text-slate-500 text-[9px] uppercase font-semibold block">Integrity (15)</span>
                      <span className="text-slate-900 font-bold">{result.score_breakdown.reconstruction_integrity.toFixed(1)}</span>
                    </div>
                  </div>

                  {result.validation_details && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-1">
                        Format Validation Metadata
                      </span>
                      <pre className="bg-slate-900 border border-slate-800 p-3 rounded-lg text-[11px] text-slate-200 overflow-x-auto">
                        {JSON.stringify(result.validation_details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ========================================================================= */}
        {/* SECTION 8 — FORENSIC EVIDENCE ANALYST (INTERPRETATION LAYER) */}
        {/* ========================================================================= */}
        <ForensicAnalystCard fileId={fileId} evidenceFacts={result} />

        {/* Bottom Investigation Footer */}
        <div className="text-center pt-4 pb-12">
          <Link
            href="/"
            className="text-xs text-slate-500 hover:text-slate-800 transition-colors inline-flex items-center gap-1.5 font-medium"
          >
            ← Close Investigation & Return Home
          </Link>
        </div>
      </div>
    </main>
  );
}
