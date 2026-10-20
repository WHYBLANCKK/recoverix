"use client";

import { useState } from "react";
import Link from "next/link";
import {
  UploadCloud,
  FileCheck,
  CheckCircle2,
  AlertTriangle,
  Download,
  Loader2,
  FileCode,
  ArrowRight,
  ExternalLink,
  RotateCcw,
  Sparkles,
  Info,
  Check,
  Copy,
} from "lucide-react";
import {
  FIXTURE_JSON,
  FIXTURE_CSV,
  FIXTURE_TXT,
  FIXTURE_XML,
  FIXTURE_JPEG_B64,
} from "@/lib/fixtures/benchmarkEvidence";
import { recoverSingleFile } from "@/lib/api";
import { computeFileSha256 } from "@/lib/crypto";
import { SingleFileRecoveryResult } from "@/lib/types";

export interface DemoScenario {
  id: string;
  title: string;
  filename: string;
  format: "JSON" | "CSV" | "TXT" | "XML" | "JPEG";
  mimeType: string;
  badge: string;
  description: string;
  engineExplanation: string;
  inputBytes: number;
  isBinary: boolean;
  textContent?: string;
  binaryContent?: string;
}

export const DEMO_SCENARIOS: DemoScenario[] = [
  {
    id: "json",
    title: "Truncated JSON",
    filename: "damaged_event.json",
    format: "JSON",
    mimeType: "application/json",
    badge: "Structural Repair",
    description: "Abruptly truncated JSON payload missing closing array and object delimiters.",
    engineExplanation: "Applies deterministic JSON structural closure without hallucinating values.",
    inputBytes: 61,
    isBinary: false,
    textContent: FIXTURE_JSON,
  },
  {
    id: "csv",
    title: "Truncated CSV",
    filename: "contacts_ragged.csv",
    format: "CSV",
    mimeType: "text/csv",
    badge: "Tabular Normalization",
    description: "Multi-row CSV with ragged lines and missing field delimiters.",
    engineExplanation: "Parses record grammar, normalizes column counts, and preserves verified fields.",
    inputBytes: 155,
    isBinary: false,
    textContent: FIXTURE_CSV,
  },
  {
    id: "txt",
    title: "Fragmented TXT",
    filename: "incident_escalation.txt",
    format: "TXT",
    mimeType: "text/plain",
    badge: "Bifragment Gap",
    description: "Plaintext audit log corrupted with 48 null bytes in the middle of the text.",
    engineExplanation: "Bifragment gap analysis isolates valid spans and accounts for the missing null gap.",
    inputBytes: 171,
    isBinary: false,
    textContent: FIXTURE_TXT,
  },
  {
    id: "xml",
    title: "Truncated XML",
    filename: "damaged_audit.xml",
    format: "XML",
    mimeType: "application/xml",
    badge: "Tag Hierarchy",
    description: "Security audit event truncated mid-stream, leaving open element hierarchy.",
    engineExplanation: "Calculates open-tag stack and applies deterministic closing tags.",
    inputBytes: 162,
    isBinary: false,
    textContent: FIXTURE_XML,
  },
  {
    id: "jpeg",
    title: "Damaged JPEG",
    filename: "salvaged_photo.jpg",
    format: "JPEG",
    mimeType: "image/jpeg",
    badge: "Binary Marker Check",
    description: "Carved JPEG segment with SOI, SOF0, SOS, and EOI marker boundaries.",
    engineExplanation: "Validates binary marker sequence, color components, and image geometry.",
    inputBytes: 39,
    isBinary: true,
    binaryContent: FIXTURE_JPEG_B64,
  },
];

interface RecoveryEntryExperienceProps {
  onSelectUpload: () => void;
  isModal?: boolean;
}

export function RecoveryEntryExperience({
  onSelectUpload,
  isModal = false,
}: RecoveryEntryExperienceProps) {
  const [selectedScenario, setSelectedScenario] = useState<DemoScenario | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [demoResult, setDemoResult] = useState<SingleFileRecoveryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedPreview, setCopiedPreview] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  const handleRunScenario = async (scenario: DemoScenario) => {
    setSelectedScenario(scenario);
    setIsRunning(true);
    setError(null);
    setDemoResult(null);

    try {
      let file: File;
      if (scenario.isBinary) {
        const binary = atob(scenario.binaryContent!);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: scenario.mimeType });
        file = new File([blob], scenario.filename, { type: scenario.mimeType });
      } else {
        const blob = new Blob([scenario.textContent!], { type: scenario.mimeType });
        file = new File([blob], scenario.filename, { type: scenario.mimeType });
      }

      const fileHash = (await computeFileSha256(file)) || "";

      const res = await recoverSingleFile(file, {
        caseName: `[Sample Demo] ${scenario.title}`,
        investigator: "Recoverix Automated Test Harness",
        notes: "Pre-configured sample file for live recovery demonstration. Genuine deterministic engine output.",
      });

      setDemoResult(res);

      if (typeof window !== "undefined") {
        localStorage.setItem(`recoverix_result_${res.file_id}`, JSON.stringify(res));
        const investigationContext = {
          case_name: `[Sample Demo] ${scenario.title}`,
          investigator: "Recoverix Automated Test Harness",
          evidence_description: `Demo execution of ${scenario.filename}`,
          notes: "Pre-configured sample file for live recovery demonstration. Genuine deterministic engine output.",
          sha256: fileHash,
          created_at: new Date().toISOString(),
          is_demo: true,
        };
        localStorage.setItem(
          `recoverix_context_${res.file_id}`,
          JSON.stringify(investigationContext)
        );
      }
    } catch (err: unknown) {
      console.error("Demo recovery error:", err);
      const msg =
        err instanceof Error
          ? err.message
          : "Live demo engine failed to analyze sample file.";
      setError(msg);
    } finally {
      setIsRunning(false);
    }
  };

  const handleDownload = async () => {
    if (!demoResult || !demoResult.is_downloadable || !demoResult.download_url) return;
    setIsDownloading(true);
    try {
      const res = await fetch(demoResult.download_url);
      if (!res.ok) throw new Error(`Download failed with status ${res.status}`);
      const blob = await res.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const tempLink = document.createElement("a");
      tempLink.href = objectUrl;
      tempLink.download = demoResult.recovered_filename || "recovered_demo.bin";
      document.body.appendChild(tempLink);
      tempLink.click();
      setTimeout(() => {
        window.URL.revokeObjectURL(objectUrl);
        if (tempLink.parentNode) {
          tempLink.parentNode.removeChild(tempLink);
        }
      }, 1000);
    } catch (err) {
      console.error("Download error:", err);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleCopyPreview = () => {
    if (demoResult?.content_preview) {
      navigator.clipboard.writeText(demoResult.content_preview);
      setCopiedPreview(true);
      setTimeout(() => setCopiedPreview(false), 2000);
    }
  };

  return (
    <div className={`space-y-6 ${isModal ? "p-6 sm:p-8" : "max-w-4xl mx-auto py-8 px-4 sm:px-6"}`}>
      {/* Header / Intro */}
      <div className="space-y-2 text-left border-b border-slate-200 pb-5">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs font-mono font-semibold">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Recovery Entry Flow</span>
        </div>
        <h2 className="text-xl sm:text-2xl font-bold font-mono text-slate-900 tracking-tight">
          How would you like to start?
        </h2>
        <p className="text-sm text-slate-600 font-sans leading-relaxed">
          Explore Recoverix using genuine sample scenarios or skip directly to uploading your own damaged file.
        </p>
      </div>

      {/* Primary Choices Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* OPTION B: Upload My Own File */}
        <div className="order-1 md:order-2 border-2 border-slate-200 hover:border-emerald-500 bg-white rounded-xl p-5 transition-all flex flex-col justify-between shadow-2xs group">
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center group-hover:scale-105 transition-transform">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono uppercase tracking-wider text-emerald-700 font-bold mb-1">
                Option B — Direct Intake
              </div>
              <h3 className="text-base font-bold text-slate-900 font-mono">
                Upload my own file
              </h3>
              <p className="text-xs text-slate-500 font-sans mt-1.5 leading-relaxed">
                Skip sample scenarios. Go directly to the file dropzone to recover your own file with TLS encryption and automatic 24h purge.
              </p>
            </div>
            <div className="flex flex-wrap gap-1.5 pt-1 text-[11px] font-mono text-slate-600">
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">PDF</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">JSON</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">CSV</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">TXT</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">XML</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">PNG</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">JPEG</span>
              <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200">ZIP</span>
            </div>
          </div>
          <div className="pt-4 mt-4 border-t border-slate-100">
            <button
              type="button"
              onClick={onSelectUpload}
              className="w-full bg-emerald-600 hover:bg-emerald-700 text-white font-mono font-bold text-xs px-4 py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2 cursor-pointer shadow-xs"
            >
              <span>Go to Upload Dropzone</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* OPTION A: Try a Live Demo */}
        <div className="order-2 md:order-1 border-2 border-slate-200 bg-slate-50/70 rounded-xl p-5 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-lg bg-slate-200/80 border border-slate-300 text-slate-700 flex items-center justify-center">
              <FileCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono uppercase tracking-wider text-slate-600 font-bold mb-1">
                Option A — Guided Evaluation
              </div>
              <h3 className="text-base font-bold text-slate-900 font-mono">
                Try a live demo
              </h3>
              <p className="text-xs text-slate-600 font-sans mt-1.5 leading-relaxed">
                Test the real deterministic recovery engine using pre-configured sample files with known damage patterns.
              </p>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span>5 real engine sample scenarios ready</span>
            </div>
          </div>
          <div className="pt-4 mt-4 border-t border-slate-200/60 text-xs font-sans text-slate-500">
            Select a scenario below to run live analysis.
          </div>
        </div>
      </div>

      {/* Demo Scenarios Section */}
      <div className="border border-slate-200 rounded-xl bg-white p-5 space-y-4 shadow-2xs">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-emerald-600" />
            <h4 className="text-sm font-bold font-mono text-slate-900 uppercase tracking-wide">
              Sample Demo Scenarios
            </h4>
          </div>
          <span className="text-[11px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
            Genuine Engine Execution
          </span>
        </div>

        <p className="text-xs text-slate-600 font-sans leading-relaxed">
          These are pre-configured sample files demonstrating how Recoverix parses damaged evidence, performs deterministic repairs, and produces mathematically verifiable outputs.
        </p>

        {/* Scenario Selection Grid */}
        {!demoResult && !isRunning && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {DEMO_SCENARIOS.map((scenario) => (
              <button
                key={scenario.id}
                type="button"
                onClick={() => handleRunScenario(scenario)}
                className="text-left border border-slate-200 hover:border-emerald-500 hover:bg-emerald-50/30 bg-white p-3.5 rounded-lg transition-all space-y-2 group cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-xs text-slate-900 group-hover:text-emerald-700">
                    {scenario.title}
                  </span>
                  <span className="text-[10px] font-mono uppercase bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded">
                    .{scenario.format.toLowerCase()}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 font-sans line-clamp-2 leading-relaxed">
                  {scenario.description}
                </p>
                <div className="pt-1 flex items-center justify-between text-[11px] font-mono text-emerald-700 font-medium">
                  <span>Run Live Demo</span>
                  <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                </div>
              </button>
            ))}
          </div>
        )}

        {/* Running State */}
        {isRunning && selectedScenario && (
          <div className="py-8 text-center space-y-3 bg-slate-50 rounded-lg border border-slate-200">
            <Loader2 className="w-8 h-8 text-emerald-600 animate-spin mx-auto" />
            <div className="space-y-1">
              <div className="text-xs font-mono font-bold text-slate-900">
                Running Live Recovery on {selectedScenario.filename}...
              </div>
              <p className="text-xs text-slate-500 font-sans max-w-md mx-auto">
                Submitting sample buffer to Recoverix engine. Executing deterministic grammar parser and cryptographic verification...
              </p>
            </div>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="p-4 bg-rose-50 border border-rose-200 rounded-lg text-rose-800 text-xs font-mono space-y-2">
            <div className="flex items-center gap-2 font-bold">
              <AlertTriangle className="w-4 h-4 text-rose-600" />
              <span>Demo execution encountered an error</span>
            </div>
            <p className="font-sans text-rose-700">{error}</p>
            <button
              type="button"
              onClick={() => {
                setError(null);
                setSelectedScenario(null);
              }}
              className="px-3 py-1 bg-white border border-rose-300 rounded text-rose-800 text-xs font-mono hover:bg-rose-100"
            >
              Try Another Scenario
            </button>
          </div>
        )}

        {/* Live Demo Result Display */}
        {demoResult && selectedScenario && !isRunning && (
          <div className="border border-slate-200 rounded-xl bg-slate-50/50 p-4 sm:p-5 space-y-4">
            {/* Demo Notice Banner */}
            <div className="flex items-start gap-2.5 p-3 rounded-lg bg-emerald-50/80 border border-emerald-200 text-emerald-900 text-xs font-mono">
              <Info className="w-4 h-4 text-emerald-700 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold uppercase tracking-wider block text-[11px] text-emerald-800">
                  Genuine Engine Output · Sample Fixture Demonstration
                </span>
                <span className="font-sans text-xs text-emerald-800 leading-relaxed block mt-0.5">
                  This recovery result was computed live by the Recoverix deterministic engine for{" "}
                  <strong>{selectedScenario.filename}</strong>. It is not mixed with your case evidence.
                </span>
              </div>
            </div>

            {/* Metrics Header */}
            <div className="bg-white border border-slate-200 rounded-lg p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-900">
                      {demoResult.original_filename}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600">
                      .{demoResult.format}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    Method: {demoResult.reconstruction_method || "DIRECT"}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                      demoResult.status === "FULLY_RECOVERED"
                        ? "bg-emerald-50 text-emerald-800 border-emerald-300"
                        : "bg-amber-50 text-amber-800 border-amber-300"
                    }`}
                  >
                    {demoResult.status.replace("_", " ")}
                  </span>
                  <span className="px-2.5 py-1 rounded text-xs font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    <span>VALIDATION {demoResult.validation_status}</span>
                  </span>
                </div>
              </div>

              {/* V/R/M Byte Accounting */}
              <div className="grid grid-cols-3 gap-2 text-center text-xs font-mono">
                <div className="bg-emerald-50/70 border border-emerald-200 p-2 rounded">
                  <div className="text-[10px] text-emerald-800 uppercase font-semibold">Verified</div>
                  <div className="text-base font-bold text-emerald-950 mt-0.5">
                    {demoResult.verified_bytes} B
                  </div>
                </div>
                <div className="bg-amber-50/70 border border-amber-200 p-2 rounded">
                  <div className="text-[10px] text-amber-800 uppercase font-semibold">Reconstructed</div>
                  <div className="text-base font-bold text-amber-950 mt-0.5">
                    {demoResult.reconstructed_bytes} B
                  </div>
                </div>
                <div className="bg-slate-100 border border-slate-200 p-2 rounded">
                  <div className="text-[10px] text-slate-600 uppercase font-semibold">Missing</div>
                  <div className="text-base font-bold text-slate-800 mt-0.5">
                    {demoResult.missing_bytes} B
                  </div>
                </div>
              </div>

              {/* Content Preview */}
              {demoResult.content_preview && (
                <div className="space-y-1.5 pt-2">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span>Recovered Content Preview:</span>
                    <button
                      type="button"
                      onClick={handleCopyPreview}
                      className="inline-flex items-center gap-1 text-slate-500 hover:text-slate-800 cursor-pointer"
                    >
                      {copiedPreview ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-600" />
                          <span className="text-emerald-600 font-bold">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="bg-slate-900 text-slate-100 p-3 rounded-lg text-xs font-mono overflow-x-auto max-h-48 whitespace-pre-wrap">
                    {demoResult.content_preview}
                  </pre>
                </div>
              )}
            </div>

            {/* Demo Actions */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setDemoResult(null);
                    setSelectedScenario(null);
                  }}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 bg-white hover:bg-slate-100 text-slate-700 text-xs font-mono font-medium flex items-center gap-1.5 cursor-pointer"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Choose Another Scenario</span>
                </button>
                {demoResult.is_downloadable && (
                  <button
                    type="button"
                    onClick={handleDownload}
                    disabled={isDownloading}
                    className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-mono font-bold flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>{isDownloading ? "Downloading..." : "Download File"}</span>
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2">
                <Link
                  href={`/investigation/${demoResult.file_id}`}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 hover:border-slate-400 bg-white text-slate-800 text-xs font-mono font-medium flex items-center gap-1.5"
                >
                  <span>Full Investigation Report</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </Link>
                <button
                  type="button"
                  onClick={onSelectUpload}
                  className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-mono font-bold flex items-center gap-1.5 cursor-pointer"
                >
                  <span>Upload My Own File</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
