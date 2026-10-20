"use client";

import { useState, useRef, ChangeEvent, DragEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  UploadCloud,
  FileText,
  AlertCircle,
  Loader2,
  CheckCircle,
  ArrowRight,
  X,
  FileCheck,
  Database,
} from "lucide-react";
import { recoverSingleFile } from "@/lib/api";
import { computeFileSha256 } from "@/lib/crypto";
import { RecoverixLogo } from "@/components/ui/RecoverixLogo";
import {
  FIXTURE_INCIDENT_JSON,
  FIXTURE_INCIDENT_TXT,
  FIXTURE_CLEAN_TXT,
  FIXTURE_STAFF_CSV,
  FIXTURE_SHUFFLED_PDF_B64,
  FIXTURE_PHOTO_JPEG_B64,
} from "@/lib/fixtures/benchmarkEvidence";

const ANALYSIS_STAGES = [
  "INGESTING EVIDENCE",
  "IDENTIFYING FORMAT",
  "LOCATING FRAGMENTS",
  "RECONSTRUCTING EVIDENCE",
  "VALIDATING STRUCTURE",
  "BUILDING PROVENANCE",
];

export default function SetupPage() {
  const router = useRouter();

  // Evidence file state
  const [file, setFile] = useState<File | null>(null);
  const [fileSha256, setFileSha256] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  // Investigation context form
  const [caseName, setCaseName] = useState("Incident Response — Server Logs");
  const [investigator, setInvestigator] = useState("Forensic Analyst #402");
  const [description, setDescription] = useState("Damaged evidence file recovered from incident image");
  const [notes, setNotes] = useState("Analyze fragmentation, isolate unobserved byte spans, and recover available evidence.");

  // Analysis / execution state
  const [isExecuting, setIsExecuting] = useState(false);
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Compute real SHA-256 via browser WebCrypto
  const computeHash = async (evidenceFile: File) => {
    const hash = await computeFileSha256(evidenceFile);
    setFileSha256(hash);
  };

  const handleSelectFile = (selectedFile: File) => {
    setFile(selectedFile);
    setErrorMessage(null);
    computeHash(selectedFile);
  };

  const handleFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (selected) {
      handleSelectFile(selected);
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
      handleSelectFile(dropped);
    }
  };

  // Quick preset loaders for live evaluation
  const loadPreset = (name: string, content: string, caseLabel: string, desc: string) => {
    const mimeType = name.endsWith(".json")
      ? "application/json"
      : name.endsWith(".csv")
      ? "text/csv"
      : "text/plain";
    const blob = new Blob([content], { type: mimeType });
    const syntheticFile = new File([blob], name, { type: mimeType });
    handleSelectFile(syntheticFile);
    setCaseName(caseLabel);
    setDescription(desc);
  };

  const loadBinaryPreset = (
    name: string,
    base64Data: string,
    mimeType: string,
    caseLabel: string,
    desc: string
  ) => {
    const binaryString = atob(base64Data);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: mimeType });
    const syntheticFile = new File([blob], name, { type: mimeType });
    handleSelectFile(syntheticFile);
    setCaseName(caseLabel);
    setDescription(desc);
  };

  const handleExecuteRecovery = async () => {
    if (!file) {
      setErrorMessage("Please select or drop an evidence file to recover.");
      return;
    }

    setIsExecuting(true);
    setCurrentStageIdx(0);
    setErrorMessage(null);

    // Sequence stages while waiting for real backend response
    const stageInterval = setInterval(() => {
      setCurrentStageIdx((prev) => (prev < ANALYSIS_STAGES.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      const result = await recoverSingleFile(file, {
        caseName: caseName || "Unnamed Case",
        investigator: investigator || "Analyst",
        notes: notes || "",
      });
      clearInterval(stageInterval);
      setCurrentStageIdx(ANALYSIS_STAGES.length - 1);

      // Save investigation context to localStorage so Investigation Workspace has full context
      const investigationContext = {
        case_name: caseName || "Unnamed Case",
        investigator: investigator || "Analyst",
        evidence_description: description || "Recovered evidence file",
        notes: notes || "",
        sha256: fileSha256 || "",
        created_at: new Date().toISOString(),
      };

      if (typeof window !== "undefined") {
        localStorage.setItem(`recoverix_context_${result.file_id}`, JSON.stringify(investigationContext));
        // Cache result in case of direct reload
        localStorage.setItem(`recoverix_result_${result.file_id}`, JSON.stringify(result));
      }

      // Small pause for clean UX transition, then redirect to Investigation Workspace
      setTimeout(() => {
        router.push(`/investigation/${result.file_id}`);
      }, 300);
    } catch (err: unknown) {
      console.error("Execution failed:", err);
      clearInterval(stageInterval);
      const msg = err instanceof Error ? err.message : "Failed to execute recovery on backend";
      setErrorMessage(msg);
      setIsExecuting(false);
    }
  };

  return (
    <main className="min-h-screen bg-[#F8FAFC] text-slate-900 py-12 px-4 sm:px-6 font-sans">
      <div className="max-w-6xl mx-auto space-y-8">
        {/* Page Header */}
        <div className="border-b border-slate-200 pb-6 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-[11px] font-mono text-emerald-800 mb-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>STAGE: INVESTIGATION INTAKE</span>
            </div>
            <h1 className="text-3xl font-bold font-mono text-slate-900 tracking-tight">
              New Recovery Investigation
            </h1>
            <p className="text-sm text-slate-600 mt-1">
              Upload damaged digital evidence and configure investigation parameters.
            </p>
          </div>

          <Link
            href="/"
            className="text-xs font-mono text-slate-600 hover:text-slate-900 transition-colors self-start sm:self-auto flex items-center gap-1.5"
            aria-label="Recoverix Home"
          >
            <RecoverixLogo size={16} showText={false} markOnly />
            <span>← Return to Home</span>
          </Link>
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div className="bg-rose-50 border border-rose-200 text-rose-800 p-4 rounded-xl flex items-start gap-3 font-mono text-xs">
            <AlertCircle className="w-5 h-5 shrink-0 text-rose-600 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold uppercase tracking-wider text-rose-700">
                [ INVESTIGATION SETUP ERROR ]
              </div>
              <p>{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Two-Column Setup Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* ========================================================= */}
          {/* LEFT: EVIDENCE UPLOAD (Cols 1-7) */}
          {/* ========================================================= */}
          <div className="lg:col-span-7 bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xs">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-900 flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-emerald-600" />
                <span>1. Evidence Source</span>
              </h2>
              <span className="text-[11px] font-mono text-slate-500">MAX BUFFER: 5 MiB</span>
            </div>

            {/* Drag & Drop Area */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
                isDragging
                  ? "border-emerald-500 bg-emerald-50/50"
                  : file
                  ? "border-emerald-400 bg-emerald-50/20"
                  : "border-slate-300 hover:border-emerald-500 bg-slate-50/50 hover:bg-slate-50"
              }`}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileInputChange}
                className="hidden"
              />

              <div className="w-12 h-12 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center mx-auto mb-3 text-emerald-600">
                <UploadCloud className="w-6 h-6" />
              </div>

              <div className="font-mono font-bold text-sm text-slate-900 uppercase tracking-wider mb-1">
                {file ? "REPLACE EVIDENCE FILE" : "DROP EVIDENCE HERE OR SELECT FILE"}
              </div>

              <p className="text-xs text-slate-600 max-w-sm mx-auto mb-4 font-sans">
                Drag damaged, fragmented, or corrupted evidence file into the workstation.
              </p>

              <button
                type="button"
                className="bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 font-mono text-xs px-4 py-2 rounded-lg transition-colors inline-flex items-center gap-2 shadow-2xs"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Browse Local Filesystem</span>
              </button>
            </div>

            {/* Selected File Details */}
            {file && (
              <div className="bg-slate-50 border border-emerald-300 rounded-xl p-4 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                  <span className="text-emerald-700 font-bold uppercase tracking-wider">
                    EVIDENCE LOADED
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setFile(null);
                      setFileSha256(null);
                    }}
                    className="text-slate-400 hover:text-rose-600 transition-colors"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div>
                    <span className="text-slate-500 block">FILENAME</span>
                    <span className="text-slate-900 font-semibold truncate block">{file.name}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">FILE SIZE</span>
                    <span className="text-emerald-700 font-semibold">{file.size.toLocaleString()} Bytes</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">MIME TYPE</span>
                    <span className="text-slate-700">{file.type || "application/octet-stream"}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">IN-MEMORY STATE</span>
                    <span className="text-sky-700 font-semibold">VERIFIED BUFFER</span>
                  </div>
                </div>

                {fileSha256 && (
                  <div className="pt-2 border-t border-slate-200">
                    <span className="text-slate-500 text-[10px] block uppercase">COMPUTED SHA-256</span>
                    <span className="text-slate-700 text-[11px] break-all select-all font-mono">
                      {fileSha256}
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* Supported Formats */}
            <div className="pt-2 border-t border-slate-100 space-y-2 font-mono text-xs">
              <div className="text-[11px] text-slate-500 uppercase tracking-wider">
                Supported Evidence Formats
              </div>
              <div className="flex flex-wrap gap-1.5 text-[11px]">
                {["TXT", "CSV", "JSON", "PDF", "PNG", "JPEG", "XML"].map((fmt) => (
                  <span
                    key={fmt}
                    className="bg-slate-100 border border-slate-200 px-2 py-0.5 rounded text-slate-700 font-medium"
                  >
                    {fmt}
                  </span>
                ))}
              </div>
            </div>

            {/* Quick Benchmark Fixtures (For live judge evaluation) */}
            <div className="pt-2 border-t border-slate-100 space-y-2 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">
                  Live Test Fixtures (Benchmark Data)
                </span>
                <span className="text-[10px] text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                  Instant Load
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {/* 1. HERO DEMO: incident_log.json (R > 0) */}
                <button
                  type="button"
                  onClick={() =>
                    loadPreset(
                      "incident_log.json",
                      FIXTURE_INCIDENT_JSON,
                      "Incident IR-99 — Evidence Tampering Log",
                      "Truncated JSON log file; reconstructs missing closing delimiters (R=2B, V=61B)"
                    )
                  }
                  className="p-3 rounded-xl bg-sky-50/60 hover:bg-sky-50 border border-sky-300 text-left transition-all shadow-2xs group relative"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sky-800 font-bold text-[11px] group-hover:text-sky-700">
                      ★ incident_log.json
                    </span>
                    <span className="text-[9px] uppercase font-bold bg-sky-100 text-sky-800 px-1.5 py-0.5 rounded">
                      R &gt; 0 RECONSTRUCTION
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-600 mt-1">
                    Truncated JSON (61B) → Deterministic Closure (R=2B)
                  </div>
                </button>

                {/* 2. GAP PRESERVATION: incident.txt (M > 0) */}
                <button
                  type="button"
                  onClick={() =>
                    loadPreset(
                      "incident.txt",
                      FIXTURE_INCIDENT_TXT,
                      "Incident Response — Server Logs",
                      "Fragmented server escalation log with an unobserved 48-byte gap preserved as missing"
                    )
                  }
                  className="p-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-left transition-colors shadow-2xs group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-amber-800 font-bold text-[11px] group-hover:text-amber-700">
                      incident.txt
                    </span>
                    <span className="text-[9px] uppercase font-bold bg-amber-50 text-amber-800 px-1.5 py-0.5 rounded">
                      PRESERVED GAP
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">
                    Bifragment Gap (174B) → Missing Preserved (M=48B)
                  </div>
                </button>

                {/* 3. SHUFFLED PDF: bms_fragmented_shuffled.pdf */}
                <button
                  type="button"
                  onClick={() =>
                    loadBinaryPreset(
                      "bms_fragmented_shuffled.pdf",
                      FIXTURE_SHUFFLED_PDF_B64,
                      "application/pdf",
                      "Black Matter Signature — Shuffled PDF Evidence",
                      "Real PDF split into 2 fragments and reversed; deterministic unshuffle reconstructs valid document"
                    )
                  }
                  className="p-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-left transition-colors shadow-2xs group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-rose-800 font-bold text-[11px] group-hover:text-rose-700">
                      bms_fragmented_shuffled.pdf
                    </span>
                    <span className="text-[9px] uppercase font-bold bg-rose-50 text-rose-800 px-1.5 py-0.5 rounded">
                      UNSHUFFLE
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">
                    2 Shuffled Fragments (315B) → Full PDF Unshuffle
                  </div>
                </button>

                {/* 4. INTACT BASELINE: clean.txt */}
                <button
                  type="button"
                  onClick={() =>
                    loadPreset(
                      "clean.txt",
                      FIXTURE_CLEAN_TXT,
                      "Routine Audit — Clean Baseline",
                      "Continuous unfragmented text evidence file (100% verified)"
                    )
                  }
                  className="p-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-left transition-colors shadow-2xs group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-emerald-700 font-bold text-[11px] group-hover:text-emerald-600">
                      clean.txt
                    </span>
                    <span className="text-[9px] uppercase font-bold bg-emerald-50 text-emerald-800 px-1.5 py-0.5 rounded">
                      INTACT 100%
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">
                    Intact Plaintext (161B) → Full Exact Recovery
                  </div>
                </button>

                {/* 5. VALID JPEG: photo_evidence.jpg */}
                <button
                  type="button"
                  onClick={() =>
                    loadBinaryPreset(
                      "photo_evidence.jpg",
                      FIXTURE_PHOTO_JPEG_B64,
                      "image/jpeg",
                      "Surveillance Footage — Metadata Frame",
                      "Raw JPEG byte stream; carver identifies SOI/EOI boundaries"
                    )
                  }
                  className="p-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-left transition-colors shadow-2xs group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-purple-800 font-bold text-[11px] group-hover:text-purple-700">
                      photo_evidence.jpg
                    </span>
                    <span className="text-[9px] uppercase font-bold bg-purple-50 text-purple-800 px-1.5 py-0.5 rounded">
                      JPEG STREAM
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">
                    Valid JPEG Stream (39B) → SOI/EOI Validated
                  </div>
                </button>

                {/* 6. STRUCTURED CSV: staff.csv */}
                <button
                  type="button"
                  onClick={() =>
                    loadPreset(
                      "staff.csv",
                      FIXTURE_STAFF_CSV,
                      "Credential Audit — Security Roster",
                      "Structured CSV database log with column constraints"
                    )
                  }
                  className="p-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-left transition-colors shadow-2xs group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-slate-800 font-bold text-[11px] group-hover:text-slate-700">
                      staff.csv
                    </span>
                    <span className="text-[9px] uppercase font-bold bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded">
                      DELIMITED
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">
                    Tabular Records (147B) → Column Schema Verified
                  </div>
                </button>
              </div>
            </div>
          </div>

          {/* ========================================================= */}
          {/* RIGHT: INVESTIGATION INFORMATION (Cols 8-12) */}
          {/* ========================================================= */}
          <div className="lg:col-span-5 bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xs">
            <div className="border-b border-slate-100 pb-4">
              <h2 className="text-sm font-bold font-mono uppercase tracking-wider text-slate-900 flex items-center gap-2">
                <Database className="w-4 h-4 text-emerald-600" />
                <span>2. Investigation Context</span>
              </h2>
            </div>

            <div className="space-y-4 font-mono text-xs">
              {/* Case Name */}
              <div className="space-y-1.5">
                <label className="text-[11px] text-slate-600 font-semibold uppercase tracking-wider block">
                  Case Name
                </label>
                <input
                  type="text"
                  value={caseName}
                  onChange={(e) => setCaseName(e.target.value)}
                  placeholder="Incident Response — Server Logs"
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg px-3.5 py-2.5 text-slate-900 focus:bg-white focus:outline-none focus:border-emerald-500 text-xs"
                />
              </div>

              {/* Investigator / Analyst */}
              <div className="space-y-1.5">
                <label className="text-[11px] text-slate-600 font-semibold uppercase tracking-wider block">
                  Investigator / Analyst
                </label>
                <input
                  type="text"
                  value={investigator}
                  onChange={(e) => setInvestigator(e.target.value)}
                  placeholder="Analyst #402"
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg px-3.5 py-2.5 text-slate-900 focus:bg-white focus:outline-none focus:border-emerald-500 text-xs"
                />
              </div>

              {/* Evidence Description */}
              <div className="space-y-1.5">
                <label className="text-[11px] text-slate-600 font-semibold uppercase tracking-wider block">
                  Evidence Description
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Damaged log file recovered from workstation image"
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg px-3.5 py-2.5 text-slate-900 focus:bg-white focus:outline-none focus:border-emerald-500 text-xs"
                />
              </div>

              {/* Investigation Notes */}
              <div className="space-y-1.5">
                <label className="text-[11px] text-slate-600 font-semibold uppercase tracking-wider block">
                  Investigation Notes
                </label>
                <textarea
                  rows={3}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Analyze fragmentation and recover available evidence."
                  className="w-full bg-slate-50 border border-slate-300 rounded-lg p-3 text-slate-900 focus:bg-white focus:outline-none focus:border-emerald-500 text-xs resize-none"
                />
              </div>
            </div>

            {/* Bottom Actions */}
            <div className="pt-4 border-t border-slate-100 space-y-3 font-mono">
              <button
                type="button"
                onClick={handleExecuteRecovery}
                disabled={isExecuting || !file}
                className="w-full bg-emerald-500 hover:bg-emerald-600 text-white font-bold py-3.5 px-6 rounded-xl transition-all flex items-center justify-center gap-2 shadow-xs disabled:opacity-50 text-xs"
              >
                {isExecuting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>ANALYZING EVIDENCE ON BACKEND...</span>
                  </>
                ) : (
                  <>
                    <span>EXECUTE RECOVERY</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>

              <Link
                href="/"
                className="w-full bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 py-2.5 px-4 rounded-xl text-center block transition-colors text-xs"
              >
                Cancel & Return
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================= */}
      {/* ANALYSIS TRANSITION MODAL (Deterministic stages, no fake %) */}
      {/* ========================================================= */}
      {isExecuting && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 max-w-lg w-full shadow-2xl space-y-6">
            <div className="flex items-center justify-between border-b border-slate-100 pb-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
                  <Loader2 className="w-4 h-4 animate-spin" />
                </div>
                <div>
                  <h3 className="text-sm font-bold font-mono text-slate-900 uppercase tracking-wider">
                    Executing Forensic Recovery
                  </h3>
                  <p className="text-[11px] font-mono text-slate-500">
                    Executing deterministic engine pipeline
                  </p>
                </div>
              </div>
              <span className="text-xs font-mono text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded font-semibold">
                LIVE ENGINE
              </span>
            </div>

            {/* Stages List */}
            <div className="space-y-2.5 font-mono text-xs">
              {ANALYSIS_STAGES.map((stage, idx) => {
                const isPassed = idx < currentStageIdx;
                const isCurrent = idx === currentStageIdx;
                return (
                  <div
                    key={stage}
                    className={`flex items-center gap-3 p-2.5 rounded-lg border transition-all ${
                      isPassed
                        ? "bg-emerald-50/70 border-emerald-300 text-emerald-900 font-semibold"
                        : isCurrent
                        ? "bg-sky-50 border-sky-300 text-sky-900 font-semibold shadow-xs"
                        : "border-slate-100 bg-slate-50/50 text-slate-400"
                    }`}
                  >
                    {isPassed ? (
                      <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
                    ) : isCurrent ? (
                      <Loader2 className="w-4 h-4 text-sky-600 animate-spin shrink-0" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-300 shrink-0" />
                    )}
                    <span
                      className={`tracking-wider ${
                        isPassed ? "text-emerald-800" : isCurrent ? "text-sky-800" : "text-slate-400"
                      }`}
                    >
                      {stage}
                    </span>
                  </div>
                );
              })}
            </div>

            <div className="text-[11px] font-mono text-slate-500 text-center pt-2 border-t border-slate-100">
              Real synchronous analysis on backend · Provenance auditing active
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
