"use client";

import { useState, useRef, ChangeEvent, DragEvent } from "react";
import Link from "next/link";
import {
  Shield,
  ArrowRight,
  FileCheck,
  Cpu,
  Layers,
  Search,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Terminal,
  Lock,
  GitBranch,
  UploadCloud,
  Loader2,
  Download,
  Copy,
  Check,
  RefreshCw,
  AlertCircle,
  FileText,
  Archive,
  Image as ImageIcon,
} from "lucide-react";
import { recoverSingleFile } from "@/lib/api";
import { SingleFileRecoveryResult } from "@/lib/types";

const RECOVERY_STAGES = [
  "Reading byte buffer & calculating SHA-256",
  "Scanning format magic signatures & boundaries",
  "Executing deterministic container reconstruction",
  "Validating structural integrity & RFC compliance",
  "Auditing verified, reconstructed & missing byte invariants",
  "Finalizing court-ready recovery package",
];

// Presets for instant 1-click live browser evaluation
const FIXTURE_JSON = '{"case":"IR-99","status":"active","tags":["malware","network"';
const FIXTURE_TXT =
  "Subject: Security Incident Escalation\nTo: Operations Team\n\n" +
  "\x00".repeat(48) +
  "Action Taken: Contained affected workstation and isolated host.\n";
const FIXTURE_CSV =
  "id,name,role,department\n" +
  "101,Alice Vance,Forensics Lead,Incident Response\n" +
  "102,Bob Miller,Security Analyst,SOC\n" +
  "103,Charlie Chen,Malware Engineer,Reverse Eng\n";
const FIXTURE_XML =
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<audit_log id="LOG-884">\n' +
  '  <source>firewall-edge-01</source>\n' +
  '  <event status="blocked">Unauthorized access attempt</event>\n';
const FIXTURE_JPEG_B64 = "/9j/wAARCAAQABADAREAAhEBAxEB/9oADAMBAAIRAxEAPwAAf//Z";

export default function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [result, setResult] = useState<SingleFileRecoveryResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copiedPreview, setCopiedPreview] = useState(false);
  const [showScoreDetails, setShowScoreDetails] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const executeRecovery = async (evidenceFile: File) => {
    setFile(evidenceFile);
    setIsAnalyzing(true);
    setCurrentStageIdx(0);
    setErrorMessage(null);
    setResult(null);

    const stageInterval = setInterval(() => {
      setCurrentStageIdx((prev) => (prev < RECOVERY_STAGES.length - 1 ? prev + 1 : prev));
    }, 400);

    try {
      const res = await recoverSingleFile(evidenceFile);
      clearInterval(stageInterval);
      setCurrentStageIdx(RECOVERY_STAGES.length - 1);
      setResult(res);

      if (typeof window !== "undefined") {
        localStorage.setItem(`recoverix_result_${res.file_id}`, JSON.stringify(res));
      }
    } catch (err: any) {
      clearInterval(stageInterval);
      console.error("Recovery error:", err);
      setErrorMessage(err.message || "Forensic analysis failed to recover file.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (selected) {
      executeRecovery(selected);
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
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) {
      executeRecovery(dropped);
    }
  };

  const loadTextPreset = (name: string, content: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const presetFile = new File([blob], name, { type: mimeType });
    executeRecovery(presetFile);
  };

  const loadBinaryPreset = (name: string, b64Data: string, mimeType: string) => {
    const binary = atob(b64Data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: mimeType });
    const presetFile = new File([blob], name, { type: mimeType });
    executeRecovery(presetFile);
  };

  const handleReset = () => {
    setFile(null);
    setResult(null);
    setErrorMessage(null);
    setIsAnalyzing(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleCopyPreview = () => {
    if (result?.content_preview) {
      navigator.clipboard.writeText(result.content_preview);
      setCopiedPreview(true);
      setTimeout(() => setCopiedPreview(false), 2000);
    }
  };

  // V/R/M calculations
  const totalInput = result?.total_input_bytes ?? (result ? result.verified_bytes + result.missing_bytes : 0);
  const totalOutput = result ? result.verified_bytes + result.reconstructed_bytes : 0;
  const verifiedPct = totalInput > 0 ? Math.round((result!.verified_bytes / totalInput) * 100) : 0;
  const missingPct = totalInput > 0 ? Math.max(0, 100 - verifiedPct) : 0;
  const reconPct = totalOutput > 0 ? Math.round((result!.reconstructed_bytes / totalOutput) * 100) : 0;

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 flex flex-col font-sans selection:bg-emerald-500/20 selection:text-emerald-950">
      {/* Hero Section */}
      <section className="relative overflow-hidden pt-12 pb-20 md:pt-16 md:pb-28 border-b border-slate-200/80 bg-gradient-to-b from-white via-[#F8FAFC] to-[#F1F5F9]">
        {/* Subtle grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#E2E8F0_1px,transparent_1px),linear-gradient(to_bottom,#E2E8F0_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none opacity-60" />

        <div className="max-w-5xl mx-auto px-4 sm:px-6 relative z-10 text-center space-y-6">
          {/* Eyebrow Badge */}
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white border border-slate-200 shadow-xs text-xs font-mono text-emerald-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="font-semibold uppercase tracking-wider">Public File Recovery Engine</span>
            <span className="text-slate-300">|</span>
            <span className="text-slate-600 font-sans">Deterministic V/R/M Standard</span>
          </div>

          {/* Hero Headline */}
          <div className="space-y-4 max-w-3xl mx-auto">
            <h1 className="text-3xl sm:text-5xl md:text-6xl font-bold tracking-tight text-slate-900 font-mono leading-tight">
              Recover What Can Be <span className="text-emerald-600 underline decoration-emerald-500/40 underline-offset-8">Proven</span>.
            </h1>
            <p className="text-base sm:text-lg text-slate-600 max-w-2xl mx-auto font-sans leading-relaxed">
              Upload damaged or corrupted files from your phone or laptop. Recoverix deterministically
              salvages valid data, isolates unobserved gaps, and never invents missing content.
            </p>
          </div>

          {/* Supported Formats Pills */}
          <div className="flex flex-wrap items-center justify-center gap-2 text-xs font-mono pt-1">
            {["PDF", "JSON", "CSV", "TXT", "XML", "PNG", "JPEG", "ZIP"].map((fmt) => (
              <span
                key={fmt}
                className="px-2.5 py-1 rounded-md bg-white border border-slate-200 text-slate-700 font-semibold shadow-2xs"
              >
                .{fmt.toLowerCase()}
              </span>
            ))}
            <span className="text-slate-400 text-[11px] self-center ml-1">· max 5 MiB</span>
          </div>

          {/* ============================================================== */}
          {/* THE 1-STEP RECOVERY CARD */}
          {/* ============================================================== */}
          <div className="pt-4 max-w-3xl mx-auto text-left">
            {!result && !isAnalyzing && (
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`group relative cursor-pointer border-2 border-dashed rounded-2xl p-8 sm:p-12 text-center transition-all bg-white shadow-md ${
                  isDragging
                    ? "border-emerald-500 bg-emerald-50/50 scale-[1.01]"
                    : "border-slate-300 hover:border-emerald-500/70 hover:bg-slate-50/50"
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileInputChange}
                  accept=".pdf,.json,.csv,.txt,.xml,.png,.jpg,.jpeg,.zip"
                  className="hidden"
                />

                <div className="flex flex-col items-center justify-center space-y-4">
                  <div className="w-16 h-16 rounded-2xl bg-emerald-50 border border-emerald-200 text-emerald-600 flex items-center justify-center group-hover:scale-105 transition-transform shadow-xs">
                    <UploadCloud className="w-8 h-8" />
                  </div>

                  <div className="space-y-1">
                    <div className="text-lg font-bold font-mono text-slate-900">
                      Drop damaged file here or <span className="text-emerald-600 underline">browse</span>
                    </div>
                    <p className="text-xs text-slate-500 font-sans">
                      Select any corrupted PDF, JSON, CSV, TXT, XML, PNG, JPG/JPEG, or ZIP file
                    </p>
                  </div>

                  <div className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-100 px-3 py-1 rounded-full">
                    <span>Client-to-Engine TLS Encrypted</span>
                    <span>·</span>
                    <span>Automatic 24h Purge</span>
                  </div>
                </div>

                {/* Instant Try Presets */}
                <div
                  className="mt-8 pt-6 border-t border-slate-100 flex flex-wrap items-center justify-center gap-2 text-xs font-mono"
                  onClick={(e) => e.stopPropagation()}
                >
                  <span className="text-slate-400 mr-1 text-[11px]">Instant live test:</span>
                  <button
                    type="button"
                    onClick={() => loadTextPreset("damaged_event.json", FIXTURE_JSON, "application/json")}
                    className="px-2.5 py-1 rounded-md bg-slate-100 hover:bg-emerald-50 hover:text-emerald-700 text-slate-700 border border-slate-200 transition-colors"
                  >
                    Truncated JSON
                  </button>
                  <button
                    type="button"
                    onClick={() => loadTextPreset("incident_escalation.txt", FIXTURE_TXT, "text/plain")}
                    className="px-2.5 py-1 rounded-md bg-slate-100 hover:bg-emerald-50 hover:text-emerald-700 text-slate-700 border border-slate-200 transition-colors"
                  >
                    Fragmented TXT
                  </button>
                  <button
                    type="button"
                    onClick={() => loadTextPreset("damaged_audit.xml", FIXTURE_XML, "application/xml")}
                    className="px-2.5 py-1 rounded-md bg-slate-100 hover:bg-emerald-50 hover:text-emerald-700 text-slate-700 border border-slate-200 transition-colors"
                  >
                    Truncated XML
                  </button>
                  <button
                    type="button"
                    onClick={() => loadBinaryPreset("salvaged_photo.jpg", FIXTURE_JPEG_B64, "image/jpeg")}
                    className="px-2.5 py-1 rounded-md bg-slate-100 hover:bg-emerald-50 hover:text-emerald-700 text-slate-700 border border-slate-200 transition-colors"
                  >
                    Damaged JPEG
                  </button>
                </div>
              </div>
            )}

            {/* Error Message */}
            {errorMessage && (
              <div className="mt-4 bg-rose-50 border border-rose-200 text-rose-800 p-4 rounded-xl flex items-start justify-between gap-3 font-mono text-xs">
                <div className="flex items-start gap-3">
                  <AlertCircle className="w-5 h-5 shrink-0 text-rose-600 mt-0.5" />
                  <div>
                    <strong className="block font-bold uppercase tracking-wider text-rose-700">
                      Recovery Error
                    </strong>
                    <span>{errorMessage}</span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleReset}
                  className="px-3 py-1 bg-white border border-rose-300 text-rose-700 rounded-lg hover:bg-rose-100 transition-colors shrink-0"
                >
                  Try Again
                </button>
              </div>
            )}

            {/* Analyzing Progress State */}
            {isAnalyzing && (
              <div className="bg-white border border-slate-200 rounded-2xl p-8 sm:p-10 shadow-lg text-center space-y-6 font-mono">
                <div className="w-16 h-16 mx-auto rounded-2xl bg-emerald-50 border border-emerald-200 text-emerald-600 flex items-center justify-center animate-spin">
                  <Loader2 className="w-8 h-8" />
                </div>

                <div className="space-y-2">
                  <div className="text-xs uppercase font-bold tracking-wider text-emerald-700">
                    STAGE {currentStageIdx + 1} OF {RECOVERY_STAGES.length}
                  </div>
                  <h3 className="text-xl font-bold text-slate-900">
                    {RECOVERY_STAGES[currentStageIdx]}
                  </h3>
                  <p className="text-xs text-slate-500 font-sans">
                    Analyzing byte structures without synthetic guessing...
                  </p>
                </div>

                <div className="w-full bg-slate-100 h-2 rounded-full overflow-hidden border border-slate-200">
                  <div
                    className="bg-emerald-500 h-full transition-all duration-300 ease-out"
                    style={{
                      width: `${((currentStageIdx + 1) / RECOVERY_STAGES.length) * 100}%`,
                    }}
                  />
                </div>
              </div>
            )}

            {/* ============================================================== */}
            {/* HONEST 4-POINT VERIFICATION CARD */}
            {/* ============================================================== */}
            {result && !isAnalyzing && (
              <div className="bg-white border border-slate-200 rounded-2xl shadow-xl overflow-hidden divide-y divide-slate-100">
                {/* 1. Header & Verdict */}
                <div className="p-6 sm:p-8 bg-slate-50/50">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 font-mono">
                          Forensic Result
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-slate-200 text-slate-800">
                          {result.format}
                        </span>
                      </div>
                      <h2 className="text-xl sm:text-2xl font-bold font-mono text-slate-900 truncate max-w-md">
                        {result.original_filename}
                      </h2>
                    </div>

                    <div className="flex items-center gap-2 self-start sm:self-auto">
                      <button
                        type="button"
                        onClick={handleReset}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 text-slate-700 text-xs font-mono hover:bg-slate-100 transition-colors"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Recover Another</span>
                      </button>
                    </div>
                  </div>

                  {/* Status Banner */}
                  <div className="mt-4">
                    {result.status === "FULLY_RECOVERED" && (
                      <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex items-start gap-3">
                        <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                        <div>
                          <div className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-800">
                            Status: Fully Recovered (100% Proven)
                          </div>
                          <p className="text-xs text-slate-600 font-sans mt-0.5">
                            Original file verified intact. Zero reconstructed bytes required. All content is mathematically proven from original evidence.
                          </p>
                        </div>
                      </div>
                    )}
                    {result.status === "PARTIALLY_RECOVERED" && (
                      <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 flex items-start gap-3">
                        <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                        <div>
                          <div className="text-xs font-mono font-bold uppercase tracking-wider text-amber-800">
                            Status: Partially Recovered (Honest Bounding)
                          </div>
                          <p className="text-xs text-slate-600 font-sans mt-0.5">
                            Valid structural fragments salvaged. Unobserved byte gaps or synthesized container closures are strictly labeled below.
                          </p>
                        </div>
                      </div>
                    )}
                    {result.status === "UNRECOVERABLE" && (
                      <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 flex items-start gap-3">
                        <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                        <div>
                          <div className="text-xs font-mono font-bold uppercase tracking-wider text-rose-800">
                            Status: Unrecoverable (Zero Invention Guarantee)
                          </div>
                          <p className="text-xs text-slate-600 font-sans mt-0.5">
                            The evidence buffer does not contain sufficient surviving structure for deterministic recovery. Recoverix does not fabricate missing data.
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* 2. The Honest V/R/M Byte Audit */}
                <div className="p-6 sm:p-8 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-500" />
                      <span>Point 1: Byte Provenance Audit (V/R/M Standard)</span>
                    </h3>
                    <span className="text-[11px] font-mono text-slate-400">
                      Total Evidence: {totalInput.toLocaleString()} bytes
                    </span>
                  </div>

                  {/* Multi-Segment Provenance Bar */}
                  <div className="w-full h-4 bg-slate-200 rounded-md overflow-hidden flex border border-slate-300">
                    <div
                      style={{ width: `${verifiedPct}%` }}
                      className="bg-emerald-500 h-full"
                      title={`Verified: ${result.verified_bytes} bytes (${verifiedPct}%)`}
                    />
                    <div
                      style={{ width: `${reconPct}%` }}
                      className="bg-sky-500 h-full"
                      title={`Reconstructed: ${result.reconstructed_bytes} bytes (${reconPct}%)`}
                    />
                    <div
                      style={{ width: `${missingPct}%` }}
                      className="bg-rose-400 h-full"
                      title={`Missing: ${result.missing_bytes} bytes (${missingPct}%)`}
                    />
                  </div>

                  {/* 3 Metric Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                    <div className="p-3 bg-emerald-50/60 border border-emerald-200 rounded-xl">
                      <div className="text-[10px] text-emerald-800 uppercase font-bold">
                        Verified (V)
                      </div>
                      <div className="text-lg font-bold text-slate-900 mt-1">
                        {result.verified_bytes.toLocaleString()}{" "}
                        <span className="text-xs font-normal text-slate-500">bytes</span>
                      </div>
                      <p className="text-[11px] text-slate-500 font-sans mt-0.5">
                        Observed original bytes
                      </p>
                    </div>

                    <div className="p-3 bg-sky-50/60 border border-sky-200 rounded-xl">
                      <div className="text-[10px] text-sky-800 uppercase font-bold">
                        Reconstructed (R)
                      </div>
                      <div className="text-lg font-bold text-slate-900 mt-1">
                        {result.reconstructed_bytes.toLocaleString()}{" "}
                        <span className="text-xs font-normal text-slate-500">bytes</span>
                      </div>
                      <p className="text-[11px] text-slate-500 font-sans mt-0.5">
                        Synthesized container framing
                      </p>
                    </div>

                    <div className="p-3 bg-rose-50/60 border border-rose-200 rounded-xl">
                      <div className="text-[10px] text-rose-800 uppercase font-bold">
                        Missing (M)
                      </div>
                      <div className="text-lg font-bold text-slate-900 mt-1">
                        {result.missing_bytes.toLocaleString()}{" "}
                        <span className="text-xs font-normal text-slate-500">bytes</span>
                      </div>
                      <p className="text-[11px] text-slate-500 font-sans mt-0.5">
                        Unobserved corrupted spans
                      </p>
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-400 font-mono text-center">
                    Mathematical Proof: V + R = {totalOutput.toLocaleString()} bytes recovered · V + M = {totalInput.toLocaleString()} bytes input
                  </p>
                </div>

                {/* 3. Forensic Confidence Score & Parser Verification */}
                <div className="p-6 sm:p-8 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-sky-500" />
                      <span>Point 2: Objective 100-Point Confidence Score</span>
                    </h3>
                    <button
                      type="button"
                      onClick={() => setShowScoreDetails(!showScoreDetails)}
                      className="text-xs font-mono text-emerald-700 hover:text-emerald-800 underline"
                    >
                      {showScoreDetails ? "Hide Rubric" : "View Rubric"}
                    </button>
                  </div>

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-50 border border-slate-200">
                    <div className="flex items-center gap-4">
                      <div className="w-14 h-14 rounded-xl bg-white border border-slate-200 flex flex-col items-center justify-center font-mono">
                        <span className="text-xl font-bold text-slate-900">
                          {Math.round(result.confidence_score)}
                        </span>
                        <span className="text-[9px] text-slate-400">/ 100</span>
                      </div>
                      <div>
                        <div className="text-xs font-mono font-bold text-slate-900">
                          Structural Validation:{" "}
                          <span
                            className={
                              result.validation_status === "PASSED"
                                ? "text-emerald-700"
                                : "text-rose-700"
                            }
                          >
                            {result.validation_status}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                          Method: {result.reconstruction_method || "Direct Contiguous Extraction"}
                        </div>
                      </div>
                    </div>

                    <div className="text-xs font-mono text-slate-500 self-start sm:self-auto">
                      Format: <span className="text-slate-900 font-bold uppercase">{result.format}</span>
                    </div>
                  </div>

                  {showScoreDetails && result.score_breakdown && (
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2 font-mono text-[11px]">
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                        <div className="text-slate-400 text-[10px]">HEADER (20)</div>
                        <div className="text-sm font-bold text-slate-900 mt-1">
                          {result.score_breakdown.header_validity} / 20
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                        <div className="text-slate-400 text-[10px]">FOOTER (20)</div>
                        <div className="text-sm font-bold text-slate-900 mt-1">
                          {result.score_breakdown.footer_validity} / 20
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                        <div className="text-slate-400 text-[10px]">STRUCTURE (30)</div>
                        <div className="text-sm font-bold text-slate-900 mt-1">
                          {result.score_breakdown.structural_validation} / 30
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                        <div className="text-slate-400 text-[10px]">SIZE (15)</div>
                        <div className="text-sm font-bold text-slate-900 mt-1">
                          {result.score_breakdown.size_plausibility} / 15
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-white border border-slate-200">
                        <div className="text-slate-400 text-[10px]">INTEGRITY (15)</div>
                        <div className="text-sm font-bold text-slate-900 mt-1">
                          {result.score_breakdown.reconstruction_integrity} / 15
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* 4. Content Preview & Download Actions */}
                <div className="p-6 sm:p-8 space-y-4 bg-slate-50/30">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-amber-500" />
                      <span>Point 3: Content Preview & Download</span>
                    </h3>
                    {result.content_preview && (
                      <button
                        type="button"
                        onClick={handleCopyPreview}
                        className="inline-flex items-center gap-1 text-xs font-mono text-slate-600 hover:text-slate-900"
                      >
                        {copiedPreview ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                            <span className="text-emerald-600">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Preview</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>

                  {result.content_preview ? (
                    <div className="relative rounded-xl bg-slate-900 text-slate-100 p-4 font-mono text-xs overflow-x-auto max-h-56 shadow-inner">
                      <pre className="whitespace-pre-wrap leading-relaxed">
                        {result.content_preview}
                      </pre>
                    </div>
                  ) : (
                    <div className="p-4 rounded-xl bg-slate-100 border border-slate-200 font-mono text-xs text-slate-500 text-center">
                      Binary artifact recovered ({result.format.toUpperCase()} format, {totalOutput.toLocaleString()} bytes). Content preview not rendered in text mode.
                    </div>
                  )}

                  {/* Primary Download Button */}
                  <div className="pt-2 flex flex-col sm:flex-row items-center gap-3">
                    {result.is_downloadable ? (
                      <a
                        href={result.download_url}
                        download={result.recovered_filename}
                        className="w-full sm:w-auto flex-1 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-mono font-bold text-sm px-6 py-4 rounded-xl shadow-md hover:shadow-emerald-500/20 transition-all flex items-center justify-center gap-2"
                      >
                        <Download className="w-4 h-4" />
                        <span>DOWNLOAD RECOVERED FILE ({result.recovered_filename})</span>
                      </a>
                    ) : (
                      <button
                        disabled
                        className="w-full sm:w-auto flex-1 bg-slate-200 text-slate-400 font-mono font-bold text-sm px-6 py-4 rounded-xl cursor-not-allowed flex items-center justify-center gap-2"
                      >
                        <Download className="w-4 h-4" />
                        <span>DOWNLOAD UNAVAILABLE (UNRECOVERABLE)</span>
                      </button>
                    )}

                    <Link
                      href={`/investigation/${result.file_id}`}
                      className="w-full sm:w-auto px-4 py-4 rounded-xl border border-slate-300 hover:border-slate-400 text-slate-700 font-mono text-xs text-center transition-colors hover:bg-slate-50"
                    >
                      Deep Forensic Trace →
                    </Link>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Product Principles Section */}
      <section id="platform" className="py-20 border-b border-slate-200/80 bg-white">
        <div className="max-w-6xl mx-auto px-6 space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-600">
              Core Principles
            </h2>
            <h3 className="text-2xl sm:text-3xl font-bold font-mono text-slate-900">
              The Forensic Standard for Data Recovery
            </h3>
            <p className="text-sm text-slate-600">
              Traditional recovery tools either crash on damaged files or invent plausible filler to mask corruption.
              Recoverix establishes a mathematically verifiable alternative.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono">
            {/* Principle 1: RECOVER */}
            <div className="bg-[#F8FAFC] border border-slate-200 p-6 rounded-2xl space-y-4 hover:border-slate-300 transition-colors shadow-xs">
              <div className="w-10 h-10 rounded-xl bg-emerald-100 border border-emerald-300 flex items-center justify-center text-emerald-700">
                <FileCheck className="w-5 h-5" />
              </div>
              <h4 className="text-lg font-bold text-slate-900 tracking-tight">RECOVER</h4>
              <p className="text-xs text-slate-600 leading-relaxed font-sans">
                Recover usable evidence from damaged or fragmented files. Carves candidates using authoritative signatures
                and re-assembles bifragment boundaries without risking data corruption.
              </p>
            </div>

            {/* Principle 2: PROVE */}
            <div className="bg-[#F8FAFC] border border-slate-200 p-6 rounded-2xl space-y-4 hover:border-slate-300 transition-colors shadow-xs">
              <div className="w-10 h-10 rounded-xl bg-sky-100 border border-sky-300 flex items-center justify-center text-sky-700">
                <Cpu className="w-5 h-5" />
              </div>
              <h4 className="text-lg font-bold text-slate-900 tracking-tight">PROVE</h4>
              <p className="text-xs text-slate-600 leading-relaxed font-sans">
                Track verified, reconstructed, and missing bytes. Every single byte is audited under our strict V/R/M model,
                preserving exact offsets and continuous chain of custody.
              </p>
            </div>

            {/* Principle 3: UNDERSTAND */}
            <div className="bg-[#F8FAFC] border border-slate-200 p-6 rounded-2xl space-y-4 hover:border-slate-300 transition-colors shadow-xs">
              <div className="w-10 h-10 rounded-xl bg-amber-100 border border-amber-300 flex items-center justify-center text-amber-700">
                <GitBranch className="w-5 h-5" />
              </div>
              <h4 className="text-lg font-bold text-slate-900 tracking-tight">UNDERSTAND</h4>
              <p className="text-xs text-slate-600 leading-relaxed font-sans">
                Present relationships, confidence, and forensic context. Interactive fragment relationship graphs visualize
                observed boundaries and unobserved gaps cleanly.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Supported Evidence Section: 8 Formats Matrix */}
      <section id="evidence" className="py-20 border-b border-slate-200/80 bg-[#F8FAFC]">
        <div className="max-w-6xl mx-auto px-6 space-y-12">
          <div className="text-center space-y-3 max-w-2xl mx-auto">
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-500">
              Evidence Matrix
            </h2>
            <h3 className="text-2xl sm:text-3xl font-bold font-mono text-slate-900">
              8 Supported Evidence Formats
            </h3>
            <p className="text-sm text-slate-600">
              Deterministic parsing, structural validation, and signature carving across modern evidence types.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
            {/* Format 1: PDF */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">PDF</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  DOCUMENT
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                Trailer salvage, cross-reference (xref) rebuild, object tree un-shuffling.
              </p>
            </div>

            {/* Format 2: JSON */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">JSON</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  STRUCTURED
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                Token balancing, syntax repair, deterministic closable gap isolation.
              </p>
            </div>

            {/* Format 3: CSV */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">CSV</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  TABULAR
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                RFC-4180 parsing, delimiter auto-detection, column alignment audit.
              </p>
            </div>

            {/* Format 4: TXT */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">TXT</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  TEXT
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                UTF-8 boundary normalization, trailing byte trimming, gap bounding.
              </p>
            </div>

            {/* Format 5: XML */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">XML</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  MARKUP
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                Well-formedness check, tag-stack balancing, entity injection defense.
              </p>
            </div>

            {/* Format 6: PNG */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">PNG</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  IMAGE
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                IHDR/IDAT chunk validation, zlib decompression check, IEND synthesis.
              </p>
            </div>

            {/* Format 7: JPEG */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">JPEG / JPG</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  IMAGE
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                SOI/SOF0/SOS validation, trailing garbage trim, deterministic EOI synthesis.
              </p>
            </div>

            {/* Format 8: ZIP */}
            <div className="p-4 bg-white rounded-xl border border-slate-200 shadow-2xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-900">ZIP</span>
                <span className="text-[10px] bg-emerald-50 text-emerald-700 font-semibold px-2 py-0.5 rounded border border-emerald-200">
                  ARCHIVE
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-sans leading-relaxed">
                Central Directory & EOCD synthesis, CRC-32 testing, Zip-Slip prevention.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer id="about" className="py-12 bg-white text-xs font-mono text-slate-500 border-t border-slate-200">
        <div className="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-600" />
            <span className="text-slate-900 font-bold">RECOVERIX</span>
            <span>— Deterministic Digital Evidence Recovery</span>
          </div>
          <div className="flex items-center gap-6">
            <Link href="/setup" className="hover:text-slate-900 transition-colors">
              Case Setup
            </Link>
            <Link href="/cases" className="hover:text-slate-900 transition-colors">
              Case History
            </Link>
            <Link href="/dashboard" className="hover:text-slate-900 transition-colors">
              Metrics
            </Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
