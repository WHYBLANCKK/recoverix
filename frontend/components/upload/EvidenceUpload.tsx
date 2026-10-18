"use client";

import { useState, useRef, DragEvent } from "react";
import { useRouter } from "next/navigation";
import {
  UploadCloud,
  Loader2,
  CheckCircle,
  Download,
  FileCode,
  ShieldCheck,
  AlertCircle,
  AlertTriangle,
  RefreshCw,
  FileText,
  Terminal,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Layers,
  FileCheck,
} from "lucide-react";
import { createCase, uploadEvidence, analyzeCase, recoverSingleFile } from "../../lib/api";
import { SingleFileRecoveryResult } from "../../lib/types";

const SINGLE_FILE_PIPELINE = [
  { stage: "INGEST", label: "Reading raw evidence byte buffer & calculating SHA-256 baseline" },
  { stage: "IDENTIFY", label: "Scanning format magic signatures & candidate boundaries" },
  { stage: "RECOVER", label: "Executing contiguous carving & deterministic gap reconstruction" },
  { stage: "VALIDATE", label: "Running strict format structural parser & bounds check" },
  { stage: "CLASSIFY", label: "Computing 100-point deterministic confidence score" },
  { stage: "REPORT", label: "Synthesizing verified, reconstructed & missing byte provenance" },
];

const DISK_IMAGE_PIPELINE = [
  { stage: "INGEST", label: "Reading image stream & computing SHA-256 baseline hash" },
  { stage: "SCAN", label: "Scanning 4096-byte sectors for format candidate signatures" },
  { stage: "CARVE", label: "Contiguous carving & bounded bifragment reconstruction (MAX_GAP=4096)" },
  { stage: "SCORE", label: "Running structural validation & 100-point forensic confidence scoring" },
];

export default function EvidenceUpload() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<"single" | "disk">("single");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [singleResult, setSingleResult] = useState<SingleFileRecoveryResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [copiedPreview, setCopiedPreview] = useState(false);
  const [showTechDetails, setShowTechDetails] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const diskInputRef = useRef<HTMLInputElement>(null);

  const executeSingleFileRecovery = async (file: File) => {
    setIsAnalyzing(true);
    setCurrentStep(0);
    setErrorMsg(null);
    setSingleResult(null);

    const stepInterval = setInterval(() => {
      setCurrentStep((prev) => (prev < SINGLE_FILE_PIPELINE.length - 1 ? prev + 1 : prev));
    }, 380);

    try {
      const res = await recoverSingleFile(file);
      clearInterval(stepInterval);
      setCurrentStep(SINGLE_FILE_PIPELINE.length);
      setSingleResult(res);
    } catch (e: any) {
      console.error("Recovery execution failed:", e);
      clearInterval(stepInterval);
      setErrorMsg(e.message || "Forensic analysis failed to recover evidence");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const executeDiskPipeline = async (file: File, caseName: string) => {
    setIsAnalyzing(true);
    setCurrentStep(0);
    setErrorMsg(null);

    const interval = setInterval(() => {
      setCurrentStep((prev) => (prev < DISK_IMAGE_PIPELINE.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      const newCase = await createCase(caseName);
      await uploadEvidence(newCase.id, file);
      await analyzeCase(newCase.id);

      clearInterval(interval);
      setCurrentStep(DISK_IMAGE_PIPELINE.length);

      localStorage.setItem("recoverix_active_case_id", newCase.id);
      setTimeout(() => {
        router.push(`/dashboard?case_id=${newCase.id}`);
      }, 400);
    } catch (e: any) {
      console.error("Disk analysis pipeline error:", e);
      clearInterval(interval);
      setErrorMsg(e.message || "Disk image processing failed");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSingleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      executeSingleFileRecovery(file);
    }
  };

  const handleDiskUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      executeDiskPipeline(file, `Evidence Case: ${file.name}`);
    }
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      if (activeTab === "single") {
        executeSingleFileRecovery(file);
      } else {
        executeDiskPipeline(file, `Evidence Case: ${file.name}`);
      }
    }
  };

  const handleCopyPreview = () => {
    if (singleResult?.content_preview) {
      navigator.clipboard.writeText(singleResult.content_preview);
      setCopiedPreview(true);
      setTimeout(() => setCopiedPreview(false), 2000);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "FULLY_RECOVERED":
        return {
          label: "FULLY RECOVERED",
          classes: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
          desc: "Original content and structure verified intact",
        };
      case "PARTIALLY_RECOVERED":
        return {
          label: "PARTIALLY RECOVERED",
          classes: "bg-amber-500/10 text-amber-400 border-amber-500/30",
          desc: "Valid fragments recovered; unobserved gaps isolated",
        };
      case "CORRUPTED":
        return {
          label: "CORRUPTED EVIDENCE",
          classes: "bg-rose-500/10 text-rose-400 border-rose-500/30",
          desc: "Severe structural corruption detected",
        };
      default:
        return {
          label: "UNRECOVERABLE",
          classes: "bg-slate-500/10 text-slate-400 border-slate-500/30",
          desc: "Evidence insufficient for deterministic salvage",
        };
    }
  };

  // Byte calculations
  const totalReportedBytes = singleResult
    ? singleResult.verified_bytes + singleResult.reconstructed_bytes + singleResult.missing_bytes
    : 0;

  const verifiedPercent = totalReportedBytes > 0
    ? Math.round((singleResult!.verified_bytes / totalReportedBytes) * 100)
    : 0;

  const reconstructedPercent = totalReportedBytes > 0
    ? Math.round((singleResult!.reconstructed_bytes / totalReportedBytes) * 100)
    : 0;

  const missingPercent = totalReportedBytes > 0
    ? Math.max(0, 100 - verifiedPercent - reconstructedPercent)
    : 0;

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      {/* Workspace Header & Integrity Posture */}
      <div className="text-center space-y-3">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#111827] border border-[#1E293B] text-[11px] font-mono text-slate-400 mb-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
          <span>DETERMINISTIC FORENSIC WORKSTATION</span>
          <span className="text-slate-600">|</span>
          <span className="text-emerald-400 font-semibold">ZERO SYNTHETIC HALLUCINATION</span>
        </div>

        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white font-mono">
          EVIDENCE RECOVERY WORKSPACE
        </h1>
        <p className="text-sm text-slate-400 max-w-2xl mx-auto">
          Recover what can be proven. Account for what is missing. Strictly separates verified
          evidence from structural repair without fabricating unobserved bytes.
        </p>

        {/* Technical Status Badges */}
        <div className="flex flex-wrap items-center justify-center gap-2 pt-1 font-mono text-[11px]">
          <span className="bg-[#0D131F] text-slate-400 border border-[#1E293B] px-2.5 py-1 rounded">
            INTEGRITY: <strong className="text-slate-200">SHA-256 AUDIT</strong>
          </span>
          <span className="bg-[#0D131F] text-slate-400 border border-[#1E293B] px-2.5 py-1 rounded">
            ACCOUNTING: <strong className="text-emerald-400">V/R/M MODEL</strong>
          </span>
          <span className="bg-[#0D131F] text-slate-400 border border-[#1E293B] px-2.5 py-1 rounded">
            FORMATS: <strong className="text-cyan-400">7 SPEC TYPES</strong>
          </span>
        </div>
      </div>

      {/* Mode Selector Tabs */}
      <div className="grid grid-cols-2 bg-[#0B0F19] p-1 rounded-xl border border-[#1E293B] font-mono text-xs">
        <button
          onClick={() => {
            setActiveTab("single");
            setSingleResult(null);
            setErrorMsg(null);
          }}
          className={`py-2.5 px-4 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 ${
            activeTab === "single"
              ? "bg-[#161F30] text-emerald-400 border border-emerald-500/30 shadow-sm"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#111827]"
          }`}
        >
          <FileCheck className="w-4 h-4" />
          <span>SINGLE FILE RECONSTRUCTION</span>
        </button>
        <button
          onClick={() => {
            setActiveTab("disk");
            setSingleResult(null);
            setErrorMsg(null);
          }}
          className={`py-2.5 px-4 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 ${
            activeTab === "disk"
              ? "bg-[#161F30] text-cyan-400 border border-cyan-500/30 shadow-sm"
              : "text-slate-400 hover:text-slate-200 hover:bg-[#111827]"
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>DISK IMAGE FORENSIC CASE</span>
        </button>
      </div>

      {/* Main Container */}
      <div className="bg-[#0B0F19] border border-[#1E293B] rounded-2xl p-6 sm:p-8 shadow-2xl relative">
        {/* Error Alert Display */}
        {errorMsg && (
          <div className="mb-6 bg-rose-500/10 border border-rose-500/30 text-rose-300 p-4 rounded-xl flex items-start gap-3 text-xs font-mono">
            <AlertCircle className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold uppercase tracking-wider text-rose-400">
                [ FORENSIC ANALYSIS FAILED ]
              </div>
              <p className="text-slate-300">{errorMsg}</p>
              <p className="text-[11px] text-slate-500">
                Recoverix does not fabricate recovery scores when evidence processing fails. Please verify the backend connection and evidence file.
              </p>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* TAB 1: SINGLE FILE RESULT VIEW (RECOVER -> PROVE -> UNDERSTAND) */}
        {/* ========================================================================= */}
        {activeTab === "single" && singleResult ? (
          <div className="space-y-6 text-left">
            {/* Header & Status */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1E293B] pb-5">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <div className="w-7 h-7 rounded bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 font-mono text-xs font-bold">
                    {singleResult.format.toUpperCase()}
                  </div>
                  <h2 className="text-lg font-bold font-mono text-white tracking-tight">
                    {singleResult.recovered_filename}
                  </h2>
                </div>
                <div className="flex items-center gap-3 font-mono text-xs text-slate-400">
                  <span>Source: <strong className="text-slate-200">{singleResult.original_filename}</strong></span>
                  <span>•</span>
                  <span>Input: <strong className="text-slate-200">{totalReportedBytes.toLocaleString()} bytes</strong></span>
                  {singleResult.run_id && (
                    <>
                      <span>•</span>
                      <span className="text-slate-500">Run: {singleResult.run_id}</span>
                    </>
                  )}
                </div>
              </div>

              {/* Status Badge & Confidence Score */}
              <div className="flex items-center gap-3 self-start md:self-auto">
                <div className="text-right">
                  <div className="text-[10px] font-mono uppercase text-slate-500">Confidence Score</div>
                  <div className="font-mono text-xl font-bold text-white">
                    {singleResult.confidence_score.toFixed(1)}
                    <span className="text-xs text-slate-500 font-normal"> / 100</span>
                  </div>
                </div>

                <div
                  className={`px-3 py-2 rounded-lg border font-mono text-xs font-bold tracking-wider ${
                    getStatusBadge(singleResult.status).classes
                  }`}
                >
                  {getStatusBadge(singleResult.status).label}
                </div>
              </div>
            </div>

            {/* 3 Core Accounting Blocks (VERIFIED / RECONSTRUCTED / MISSING) */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span className="uppercase tracking-wider">Forensic Byte Allocation (V/R/M)</span>
                <span>Total Evidence: {totalReportedBytes.toLocaleString()} B</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* VERIFIED BYTES */}
                <div className="bg-[#090D14] border border-emerald-500/30 p-4 rounded-xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 transform translate-x-2 -translate-y-2 w-16 h-16 bg-emerald-500/5 rounded-full blur-xl pointer-events-none" />
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-emerald-400">
                      [VERIFIED BYTES]
                    </span>
                    <span className="font-mono text-[10px] text-emerald-400/80 bg-emerald-500/10 px-1.5 py-0.5 rounded">
                      {verifiedPercent}%
                    </span>
                  </div>
                  <div className="font-mono text-2xl font-bold text-emerald-400">
                    {singleResult.verified_bytes.toLocaleString()}
                    <span className="text-xs text-emerald-400/70 ml-1">B</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Exact evidence verified structurally intact without mutation.
                  </p>
                </div>

                {/* RECONSTRUCTED BYTES */}
                <div className="bg-[#090D14] border border-cyan-500/30 p-4 rounded-xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 transform translate-x-2 -translate-y-2 w-16 h-16 bg-cyan-500/5 rounded-full blur-xl pointer-events-none" />
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-cyan-400">
                      [RECONSTRUCTED]
                    </span>
                    <span className="font-mono text-[10px] text-cyan-400/80 bg-cyan-500/10 px-1.5 py-0.5 rounded">
                      {reconstructedPercent}%
                    </span>
                  </div>
                  <div className="font-mono text-2xl font-bold text-cyan-400">
                    {singleResult.reconstructed_bytes.toLocaleString()}
                    <span className="text-xs text-cyan-400/70 ml-1">B</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Repaired via deterministic structural inference & container syntax.
                  </p>
                </div>

                {/* MISSING BYTES */}
                <div className="bg-[#090D14] border border-amber-500/30 p-4 rounded-xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 transform translate-x-2 -translate-y-2 w-16 h-16 bg-amber-500/5 rounded-full blur-xl pointer-events-none" />
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-[10px] uppercase font-bold tracking-wider text-amber-400">
                      [MISSING BYTES]
                    </span>
                    <span className="font-mono text-[10px] text-amber-400/80 bg-amber-500/10 px-1.5 py-0.5 rounded">
                      {missingPercent}%
                    </span>
                  </div>
                  <div className="font-mono text-2xl font-bold text-amber-400">
                    {singleResult.missing_bytes.toLocaleString()}
                    <span className="text-xs text-amber-400/70 ml-1">B</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1">
                    Unobserved evidence gaps preserved without synthetic fabrication.
                  </p>
                </div>
              </div>

              {/* V/R/M Proportional Visual Bar */}
              <div className="w-full bg-[#111827] h-2 rounded-full overflow-hidden flex border border-[#1E293B] mt-2">
                <div
                  style={{ width: `${verifiedPercent}%` }}
                  className="bg-emerald-500 h-full transition-all"
                  title={`Verified: ${singleResult.verified_bytes}B (${verifiedPercent}%)`}
                />
                <div
                  style={{ width: `${reconstructedPercent}%` }}
                  className="bg-cyan-500 h-full transition-all"
                  title={`Reconstructed: ${singleResult.reconstructed_bytes}B (${reconstructedPercent}%)`}
                />
                <div
                  style={{ width: `${missingPercent}%` }}
                  className="bg-amber-500 h-full transition-all"
                  title={`Missing: ${singleResult.missing_bytes}B (${missingPercent}%)`}
                />
              </div>
            </div>

            {/* UNRECOVERED EVIDENCE NOTICE (If missing bytes > 0 or not FULLY_RECOVERED) */}
            {singleResult.missing_bytes > 0 && (
              <div className="bg-amber-500/[0.06] border border-amber-500/30 p-4 rounded-xl flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 shrink-0 text-amber-400 mt-0.5" />
                <div className="space-y-1 font-mono text-xs">
                  <div className="font-bold text-amber-400 uppercase tracking-wider">
                    EVIDENCE INTEGRITY NOTICE: {singleResult.missing_bytes.toLocaleString()} BYTES UNRECOVERED
                  </div>
                  <p className="text-slate-300">
                    {singleResult.missing_bytes.toLocaleString()} bytes could not be deterministically established from the supplied evidence buffer.
                  </p>
                  <p className="text-[11px] text-slate-400">
                    <strong>Integrity Standard:</strong> Recoverix does NOT invent unobserved data to fill missing gaps. Unobserved bytes remain strictly classified as missing evidence to maintain byte-accurate auditability.
                  </p>
                </div>
              </div>
            )}

            {/* WHAT RECOVERIX FOUND — FORENSIC EXPLANATION */}
            <div className="bg-[#090D14] border border-[#1E293B] p-4 rounded-xl space-y-3 font-mono text-xs">
              <div className="flex items-center gap-2 text-slate-200 font-bold uppercase tracking-wider">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Forensic Recovery Findings</span>
              </div>

              <div className="space-y-2 text-slate-300 leading-relaxed">
                <div className="p-2.5 rounded bg-[#0E1522] border border-[#1E293B]">
                  <strong className="text-cyan-400">[DETERMINISTIC FINDING]</strong>{" "}
                  {singleResult.format.toUpperCase()} container processed via{" "}
                  <code className="text-slate-200 bg-black/40 px-1 py-0.5 rounded">
                    {singleResult.reconstruction_method}
                  </code>
                  . Format structural validation returned{" "}
                  <span className="text-emerald-400 font-semibold">{singleResult.validation_status}</span>.{" "}
                  {singleResult.verified_bytes.toLocaleString()} bytes preserved as original intact evidence.
                </div>

                <div className="p-2.5 rounded bg-[#0E1522] border border-[#1E293B]">
                  <strong className="text-emerald-400">[EVIDENCE CLASSIFICATION]</strong>{" "}
                  Classified as{" "}
                  <span className="text-slate-100 font-semibold">
                    {singleResult.status.replace("_", " ")}
                  </span>{" "}
                  with an objective forensic score of{" "}
                  <span className="text-emerald-400 font-semibold">{singleResult.confidence_score.toFixed(1)}/100</span>.{" "}
                  Evaluated across 5 deterministic criteria (Header, Footer, Structure, Size, Integrity).
                </div>
              </div>
            </div>

            {/* Evidence Provenance Panel */}
            <div className="bg-[#090D14] border border-[#1E293B] p-4 rounded-xl space-y-3">
              <div className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                Evidence Provenance & Technical Audit
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
                <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                  <div className="text-slate-500 text-[10px] uppercase">Format Spec</div>
                  <div className="text-white font-bold truncate">{singleResult.format.toUpperCase()}</div>
                </div>
                <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                  <div className="text-slate-500 text-[10px] uppercase">Recovery Method</div>
                  <div className="text-cyan-400 font-bold truncate">{singleResult.reconstruction_method}</div>
                </div>
                <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                  <div className="text-slate-500 text-[10px] uppercase">Validation Status</div>
                  <div className="text-emerald-400 font-bold truncate">{singleResult.validation_status}</div>
                </div>
                <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                  <div className="text-slate-500 text-[10px] uppercase">Synthetic Infill</div>
                  <div className="text-slate-300 font-bold truncate">0 BYTES (PROHIBITED)</div>
                </div>
              </div>
            </div>

            {/* Recovered Content / Hex Byte Preview */}
            {singleResult.content_preview && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2 text-slate-400">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span className="uppercase tracking-wider">Recovered Evidence Byte Stream</span>
                  </div>
                  <button
                    onClick={handleCopyPreview}
                    className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors bg-[#111827] px-2 py-0.5 rounded border border-[#1E293B]"
                  >
                    {copiedPreview ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-400" /> Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" /> Copy Stream
                      </>
                    )}
                  </button>
                </div>

                <div className="bg-[#070A0F] border border-[#1E293B] rounded-xl p-3 font-mono text-xs overflow-x-auto max-h-48 scrollbar-thin">
                  <pre className="text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
                    {singleResult.content_preview}
                  </pre>
                </div>
              </div>
            )}

            {/* Collapsible Technical Details (Rubric Breakdown & Validation metadata) */}
            <div className="border border-[#1E293B] rounded-xl overflow-hidden bg-[#090D14]">
              <button
                onClick={() => setShowTechDetails(!showTechDetails)}
                className="w-full px-4 py-3 flex items-center justify-between text-xs font-mono text-slate-400 hover:text-slate-200 hover:bg-[#0E1522] transition-colors"
              >
                <span className="flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  <span>100-Point Forensic Rubric Breakdown & Validation Metadata</span>
                </span>
                {showTechDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>

              {showTechDetails && (
                <div className="p-4 border-t border-[#1E293B] space-y-4">
                  {/* 5-Criteria Rubric Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-mono text-center">
                    <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                      <div className="text-slate-500 text-[10px] uppercase">Header (20)</div>
                      <div className="text-white font-bold text-sm">
                        {singleResult.score_breakdown.header_validity.toFixed(1)}
                      </div>
                    </div>
                    <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                      <div className="text-slate-500 text-[10px] uppercase">Footer (20)</div>
                      <div className="text-white font-bold text-sm">
                        {singleResult.score_breakdown.footer_validity.toFixed(1)}
                      </div>
                    </div>
                    <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                      <div className="text-slate-500 text-[10px] uppercase">Structure (30)</div>
                      <div className="text-white font-bold text-sm">
                        {singleResult.score_breakdown.structural_validation.toFixed(1)}
                      </div>
                    </div>
                    <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                      <div className="text-slate-500 text-[10px] uppercase">Size (15)</div>
                      <div className="text-white font-bold text-sm">
                        {singleResult.score_breakdown.size_plausibility.toFixed(1)}
                      </div>
                    </div>
                    <div className="bg-[#0E1522] border border-[#1E293B] p-2.5 rounded-lg">
                      <div className="text-slate-500 text-[10px] uppercase">Integrity (15)</div>
                      <div className="text-white font-bold text-sm">
                        {singleResult.score_breakdown.reconstruction_integrity.toFixed(1)}
                      </div>
                    </div>
                  </div>

                  {/* Validation Details JSON */}
                  {singleResult.validation_details && (
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono uppercase text-slate-500">
                        Format Structural Audit Details
                      </div>
                      <pre className="bg-[#070A0F] border border-[#1E293B] p-3 rounded-lg text-[11px] font-mono text-slate-400 overflow-x-auto">
                        {JSON.stringify(singleResult.validation_details, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Action Bar: Download File & Reset */}
            <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
              {singleResult.is_downloadable ? (
                <a
                  href={singleResult.download_url}
                  download={singleResult.recovered_filename}
                  className="w-full sm:flex-1 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-mono text-xs font-bold py-3 px-6 rounded-xl shadow-lg transition-all inline-flex items-center justify-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  DOWNLOAD RECOVERED EVIDENCE ({singleResult.recovered_filename})
                </a>
              ) : (
                <div className="w-full sm:flex-1 bg-slate-900 border border-slate-800 text-slate-500 font-mono text-xs py-3 px-4 rounded-xl text-center">
                  EVIDENCE UNRECOVERABLE — DOWNLOAD DISABLED
                </div>
              )}

              <button
                onClick={() => setSingleResult(null)}
                className="w-full sm:w-auto bg-[#111827] hover:bg-[#1E293B] border border-[#1E293B] text-slate-300 font-mono text-xs font-medium py-3 px-5 rounded-xl transition-all inline-flex items-center justify-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Analyze Another File
              </button>
            </div>
          </div>
        ) : activeTab === "single" ? (
          /* ========================================================================= */
          /* TAB 1: DROPZONE VIEW */
          /* ========================================================================= */
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`text-center py-8 px-4 border-2 border-dashed rounded-xl transition-all ${
              isDragging
                ? "border-emerald-500/60 bg-emerald-500/[0.03]"
                : "border-[#1E293B] hover:border-slate-700 bg-[#090D14]/50"
            }`}
          >
            <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mx-auto mb-4 text-emerald-400">
              <UploadCloud className="w-7 h-7" />
            </div>

            <h2 className="text-xl font-bold font-mono tracking-tight text-white mb-2">
              DROP EVIDENCE FILE HERE OR BROWSE
            </h2>

            <p className="text-xs text-slate-400 max-w-md mx-auto mb-6">
              Upload damaged, fragmented, or corrupted evidence. Recoverix executes in-memory deterministic carving, format validation, and byte-level accounting.
            </p>

            <input
              type="file"
              ref={fileInputRef}
              onChange={handleSingleFileUpload}
              className="hidden"
            />

            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={isAnalyzing}
              className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-mono text-xs font-bold px-6 py-3 rounded-xl shadow-lg transition-all inline-flex items-center gap-2 disabled:opacity-50"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  RECONSTRUCTING EVIDENCE...
                </>
              ) : (
                <>
                  <FileText className="w-4 h-4" />
                  SELECT EVIDENCE FILE & RECOVER
                </>
              )}
            </button>

            {/* Supported Formats Strip */}
            <div className="mt-8 pt-6 border-t border-[#1E293B] space-y-2">
              <div className="text-[11px] font-mono text-slate-500 uppercase tracking-wider">
                Supported Reconstruction Formats & Specs
              </div>
              <div className="flex flex-wrap items-center justify-center gap-1.5 font-mono text-xs text-slate-300">
                {["TXT", "CSV", "JSON", "PNG", "JPEG", "PDF", "XML"].map((fmt) => (
                  <span
                    key={fmt}
                    className="bg-[#111827] border border-[#1E293B] px-2.5 py-1 rounded text-slate-300 font-semibold"
                  >
                    {fmt}
                  </span>
                ))}
              </div>
              <p className="text-[11px] font-mono text-slate-500 mt-2">
                Buffer limit: 5 MiB · Processed strictly in-memory · Zero synthetic hallucination
              </p>
            </div>
          </div>
        ) : (
          /* ========================================================================= */
          /* TAB 2: DISK IMAGE CASE VIEW */
          /* ========================================================================= */
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`text-center py-8 px-4 border-2 border-dashed rounded-xl transition-all ${
              isDragging
                ? "border-cyan-500/60 bg-cyan-500/[0.03]"
                : "border-[#1E293B] hover:border-slate-700 bg-[#090D14]/50"
            }`}
          >
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mx-auto mb-4 text-cyan-400">
              <FileCode className="w-7 h-7" />
            </div>

            <h2 className="text-xl font-bold font-mono tracking-tight text-white mb-2">
              UPLOAD RAW DISK IMAGE (.img / .dd / .raw)
            </h2>

            <p className="text-xs text-slate-400 max-w-md mx-auto mb-6">
              Load an unpartitioned or raw disk dump up to 5 MiB for multi-artifact carving, bifragment gap assembly, and full case triage.
            </p>

            <input
              type="file"
              ref={diskInputRef}
              onChange={handleDiskUpload}
              className="hidden"
              accept=".img,.raw,.dd,.bin"
            />

            <button
              onClick={() => diskInputRef.current?.click()}
              disabled={isAnalyzing}
              className="bg-cyan-500 hover:bg-cyan-600 text-slate-950 font-mono text-xs font-bold px-6 py-3 rounded-xl shadow-lg transition-all inline-flex items-center gap-2 disabled:opacity-50"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  ANALYZING DISK CASE...
                </>
              ) : (
                <>
                  <Layers className="w-4 h-4" />
                  SELECT DISK IMAGE & ANALYZE
                </>
              )}
            </button>

            <div className="mt-8 pt-6 border-t border-[#1E293B] font-mono text-[11px] text-slate-500 space-y-1">
              <div>Accepted: .img, .dd, .raw, .bin forensic dumps (max 5 MiB)</div>
              <div>Carves contiguous artifacts & reconstructs bifragment gaps within MAX_GAP=4096</div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* FORENSIC PIPELINE EXECUTION MODAL / OVERLAY */}
        {/* ========================================================================= */}
        {isAnalyzing && (
          <div className="fixed inset-0 bg-[#070A0F]/85 backdrop-blur-md flex items-center justify-center z-50 p-4">
            <div className="bg-[#0B0F19] border border-[#1E293B] rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-2xl space-y-6">
              <div className="flex items-center justify-between border-b border-[#1E293B] pb-4">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                    <Loader2 className="w-4 h-4 animate-spin" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider">
                      {activeTab === "single" ? "FORENSIC RECOVERY IN PROGRESS" : "PROCESSING DISK IMAGE"}
                    </h3>
                    <p className="text-[11px] font-mono text-slate-400">
                      Executing deterministic pipeline stages
                    </p>
                  </div>
                </div>
                <div className="font-mono text-xs text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                  STAGE {Math.min(currentStep + 1, activeTab === "single" ? SINGLE_FILE_PIPELINE.length : DISK_IMAGE_PIPELINE.length)} / {activeTab === "single" ? SINGLE_FILE_PIPELINE.length : DISK_IMAGE_PIPELINE.length}
                </div>
              </div>

              {/* Pipeline Step List */}
              <div className="space-y-3 font-mono text-xs">
                {(activeTab === "single" ? SINGLE_FILE_PIPELINE : DISK_IMAGE_PIPELINE).map((step, idx) => {
                  const isDone = idx < currentStep;
                  const isCurrent = idx === currentStep;
                  return (
                    <div
                      key={step.stage}
                      className={`flex items-start gap-3 p-2.5 rounded-lg border transition-all ${
                        isDone
                          ? "bg-emerald-500/[0.04] border-emerald-500/20 text-slate-300"
                          : isCurrent
                          ? "bg-cyan-500/[0.06] border-cyan-500/30 text-white shadow-sm"
                          : "border-transparent text-slate-600"
                      }`}
                    >
                      <div className="mt-0.5 shrink-0">
                        {isDone ? (
                          <CheckCircle className="w-4 h-4 text-emerald-400" />
                        ) : isCurrent ? (
                          <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                        ) : (
                          <div className="w-4 h-4 rounded-full border border-slate-700" />
                        )}
                      </div>
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span
                            className={`font-bold text-[11px] ${
                              isDone ? "text-emerald-400" : isCurrent ? "text-cyan-400" : "text-slate-600"
                            }`}
                          >
                            [{step.stage}]
                          </span>
                        </div>
                        <p className="text-[11px] leading-relaxed text-slate-400">
                          {step.label}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="text-[11px] font-mono text-center text-slate-500 pt-2 border-t border-[#1E293B]">
                In-memory execution · Verified byte auditing · Anti-hallucination policy
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
