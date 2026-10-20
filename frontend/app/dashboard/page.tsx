"use client";

import { useEffect, useState, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { fetchCase, fetchRecoveryRuns, normalizeBackendArtifact, RawBackendArtifact } from "@/lib/api";
import { ArtifactTable } from "@/components/dashboard/ArtifactTable";
import { CaseInterpretationCard } from "@/components/case/CaseInterpretationCard";
import { Loader2, Download, ShieldCheck, FileText } from "lucide-react";
import { Case, Artifact } from "@/lib/types";
import { RecoverixLogo } from "@/components/ui/RecoverixLogo";

function DashboardContent() {
  const searchParams = useSearchParams();
  const [data, setData] = useState<{
    caseData: Case | null;
    artifacts: Artifact[];
    rawRuns: RawBackendArtifact[];
  }>({ caseData: null, artifacts: [], rawRuns: [] });
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setIsLoading(true);
      const urlId = searchParams.get('case_id');
      const localId = typeof window !== 'undefined' ? localStorage.getItem('recoverix_active_case_id') : null;
      const requestedCaseId = urlId || localId || null;

      try {
        const [runs, c] = await Promise.all([
          fetchRecoveryRuns().catch(() => []),
          requestedCaseId ? fetchCase(requestedCaseId).catch(() => null) : Promise.resolve(null),
        ]);

        const runArtifacts = (runs || []).map(normalizeBackendArtifact);
        const caseArtifacts = c?.artifacts || [];

        // Combine into unified artifact list without duplicate IDs
        const map = new Map<string, Artifact>();
        for (const art of runArtifacts) {
          map.set(art.id, art);
        }
        for (const art of caseArtifacts) {
          if (!map.has(art.id)) {
            map.set(art.id, art);
          }
        }
        const combined = Array.from(map.values());

        setData({
          caseData: c || (combined.length > 0 ? {
            id: requestedCaseId || 'session_evidence',
            name: requestedCaseId ? `Case ${requestedCaseId}` : 'Session Evidence Workspace',
            description: 'Canonical recovery runs and forensic evidence workspace',
            artifacts: combined,
          } : null),
          artifacts: combined,
          rawRuns: runs || [],
        });
      } catch (err) {
        console.error("Failed to load dashboard data:", err);
        setData({ caseData: null, artifacts: [], rawRuns: [] });
      } finally {
        setIsLoading(false);
      }
    }
    loadData();
  }, [searchParams]);

  if (isLoading) {
    return (
      <main className="min-h-screen bg-[#F8FAFC] flex items-center justify-center">
        <Loader2 className="w-12 h-12 text-emerald-600 animate-spin" />
      </main>
    );
  }

  const { caseData, artifacts, rawRuns } = data;
  const activeCaseId = caseData?.id || searchParams.get('case_id') || 'session_evidence';

  if (artifacts.length === 0) {
    return (
      <main className="min-h-screen bg-[#F8FAFC] text-slate-900 py-8 px-6 font-mono selection:bg-emerald-500/20 selection:text-emerald-950">
        <div className="max-w-7xl mx-auto space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-4">
              <Link href="/" className="inline-flex items-center text-xs font-mono text-slate-700 hover:text-slate-900 transition-colors bg-white hover:bg-slate-50 border border-slate-300 px-3.5 py-2 rounded-lg shadow-2xs font-semibold" aria-label="Recoverix Home">
                <RecoverixLogo size={16} showText={false} markOnly className="mr-2" /> Evidence Workspace
              </Link>
              <h1 className="text-xl font-bold font-mono tracking-tight text-slate-900 border-l border-slate-200 pl-4">
                RECOVERY RUNS & CASE ARTIFACTS
              </h1>
            </div>
            <Link
              href="/setup"
              className="inline-flex items-center text-xs font-mono text-slate-700 hover:text-slate-900 transition-colors bg-white hover:bg-slate-50 border border-slate-300 px-3.5 py-2 rounded-lg shadow-2xs font-semibold"
            >
              <FileText className="w-4 h-4 mr-2 text-slate-500" /> New Investigation
            </Link>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-12 sm:p-16 text-center space-y-4 max-w-lg mx-auto shadow-xs">
            <div className="w-12 h-12 rounded-2xl bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center mx-auto shadow-2xs">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div className="space-y-1.5">
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                No Recorded Cases in this Session
              </h2>
              <p className="text-xs text-slate-500 font-sans leading-relaxed">
                Recoverix enforces strict per-session cryptographic data isolation. Your uploads and recoveries are private to your browser session and automatically purged within 24 hours. Because no evidence has been processed in this session yet, no case artifacts exist.
              </p>
            </div>
            <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
              <Link
                href="/#upload"
                className="inline-flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-mono font-bold px-4 py-2.5 rounded-lg text-xs transition-all shadow-xs"
              >
                <span>Upload & Recover a File</span>
              </Link>
              <Link
                href="/setup"
                className="inline-flex items-center gap-2 bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 font-mono font-semibold px-4 py-2.5 rounded-lg text-xs transition-all shadow-2xs"
              >
                <span>New Investigation Setup</span>
              </Link>
            </div>
          </div>
        </div>
      </main>
    );
  }

  const totalArts = artifacts.length;
  const fullyRec = artifacts.filter(a => a.status === 'FULLY_RECOVERED').length;
  const partialRec = artifacts.filter(a => a.status === 'PARTIALLY_RECOVERED' || a.status === 'CORRUPTED').length;
  const unrecoverable = artifacts.filter(a => a.status === 'UNRECOVERABLE').length;

  const totalVerifiedBytes = artifacts.reduce((acc, a) => acc + (a.verified_bytes || 0), 0);
  const totalReconstructedBytes = artifacts.reduce((acc, a) => acc + (a.reconstructed_bytes || 0), 0);
  const totalMissingBytes = artifacts.reduce((acc, a) => acc + (a.missing_bytes || 0), 0);
  const totalObservedInputBytes = totalVerifiedBytes + totalMissingBytes;
  const verifiedBytePercentage = totalObservedInputBytes > 0
    ? Math.round((totalVerifiedBytes / totalObservedInputBytes) * 100)
    : 100;

  return (
    <main className="min-h-screen bg-[#F8FAFC] text-slate-900 py-8 px-6 font-sans selection:bg-emerald-500/20 selection:text-emerald-950">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Compact Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <Link href="/" className="inline-flex items-center text-xs font-mono text-slate-700 hover:text-slate-900 transition-colors bg-white hover:bg-slate-50 border border-slate-300 px-3.5 py-2 rounded-lg shadow-2xs font-semibold" aria-label="Recoverix Home">
              <RecoverixLogo size={16} showText={false} markOnly className="mr-2" /> Evidence Workspace
            </Link>
            <h1 className="text-xl font-bold font-mono tracking-tight text-slate-900 border-l border-slate-200 pl-4">
              RECOVERY RUNS & CASE ARTIFACTS
            </h1>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/setup"
              className="inline-flex items-center text-xs font-mono text-slate-700 hover:text-slate-900 transition-colors bg-white hover:bg-slate-50 border border-slate-300 px-3.5 py-2 rounded-lg shadow-2xs font-semibold"
            >
              <FileText className="w-4 h-4 mr-2 text-slate-500" /> New Investigation
            </Link>
            <button
              onClick={() => {
                const report = {
                  report_type: "Recoverix Forensic Recovery Report",
                  version: "1.0.0",
                  case_id: activeCaseId,
                  case_name: caseData?.name || "Evidence Workspace",
                  generated_at: new Date().toISOString(),
                  summary: {
                    total_artifacts: totalArts,
                    fully_recovered: fullyRec,
                    partially_recovered: partialRec,
                    unrecoverable: unrecoverable,
                    total_verified_bytes: totalVerifiedBytes,
                    total_reconstructed_bytes: totalReconstructedBytes,
                    total_missing_bytes: totalMissingBytes,
                    verified_byte_percentage: verifiedBytePercentage,
                    mathematical_invariants: {
                      conservation_law: "total_verified_bytes + total_reconstructed_bytes == recovered_bytes; total_verified_bytes + total_missing_bytes == input_bytes",
                      total_observed_input_bytes: totalObservedInputBytes,
                    },
                  },
                  artifacts: artifacts.map(a => ({
                    id: a.id,
                    filename: a.filename,
                    format: a.mime_type,
                    status: a.status,
                    confidence_score: a.confidence_score,
                    validation_status: a.validation_status,
                    verified_bytes: a.verified_bytes,
                    reconstructed_bytes: a.reconstructed_bytes,
                    missing_bytes: a.missing_bytes,
                    reconstruction_method: a.reconstruction_method,
                    fragments: a.fragments,
                    ai_summary: a.ai_summary,
                  })),
                  raw_recovery_runs: rawRuns,
                };
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
                const anchor = document.createElement('a');
                anchor.href = dataStr;
                anchor.download = `recoverix_report_${activeCaseId}_${Date.now()}.json`;
                anchor.click();
              }}
              disabled={artifacts.length === 0}
              className="inline-flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-mono px-3.5 py-2 rounded-lg transition-colors shadow-2xs disabled:opacity-50 font-semibold cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" /> Export JSON Report
            </button>
          </div>
        </div>

        {/* 4-column Stat Strip */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 grid grid-cols-2 md:grid-cols-4 divide-x divide-slate-100 font-mono shadow-xs">
          <div className="px-4">
            <div className="flex items-center gap-1.5 mb-1">
              <div className="w-2 h-2 rounded-full bg-slate-400" />
              <span className="text-[10px] text-slate-500 font-semibold uppercase tracking-wider">Total Runs</span>
            </div>
            <p className="text-2xl font-bold text-slate-900">{totalArts}</p>
          </div>
          <div className="px-4">
            <div className="flex items-center gap-1.5 mb-1">
              <div className="w-2 h-2 rounded-full bg-emerald-500" />
              <span className="text-[10px] text-emerald-700 font-semibold uppercase tracking-wider">Fully Recovered</span>
            </div>
            <p className="text-2xl font-bold text-emerald-600">{fullyRec}</p>
          </div>
          <div className="px-4">
            <div className="flex items-center gap-1.5 mb-1">
              <div className="w-2 h-2 rounded-full bg-amber-500" />
              <span className="text-[10px] text-amber-700 font-semibold uppercase tracking-wider">Partial / Repaired</span>
            </div>
            <p className="text-2xl font-bold text-amber-600">{partialRec}</p>
          </div>
          <div className="px-4">
            <div className="flex items-center gap-1.5 mb-1">
              <div className="w-2 h-2 rounded-full bg-rose-500" />
              <span className="text-[10px] text-rose-700 font-semibold uppercase tracking-wider">Unrecoverable</span>
            </div>
            <p className="text-2xl font-bold text-rose-600">{unrecoverable}</p>
          </div>
        </div>

        {/* Truthful Byte Accounting Summary Bar */}
        <div className="bg-slate-900 text-white rounded-xl p-4 font-mono text-xs shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
            <div>
              <p className="font-semibold text-slate-200">
                Deterministic Byte Provenance: {totalVerifiedBytes.toLocaleString()} B Verified / {totalObservedInputBytes.toLocaleString()} B Input ({verifiedBytePercentage}%)
              </p>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Reconstructed Syntax: {totalReconstructedBytes.toLocaleString()} B • Preserved Gaps: {totalMissingBytes.toLocaleString()} B • Zero Heuristic Hallucination
              </p>
            </div>
          </div>
          <div className="text-[11px] text-emerald-400/90 bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700/60 font-mono self-start sm:self-auto">
            Invariant: V + R = recovered; V + M = input
          </div>
        </div>

        {/* Grounded Case Interpretation */}
        <CaseInterpretationCard
          caseId={activeCaseId}
          artifacts={artifacts}
          recoveryRuns={rawRuns}
        />

        {/* Artifacts Table */}
        <ArtifactTable artifacts={artifacts} />
      </div>
    </main>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={
      <main className="min-h-screen bg-[#F8FAFC] flex items-center justify-center">
        <Loader2 className="w-12 h-12 text-emerald-600 animate-spin" />
      </main>
    }>
      <DashboardContent />
    </Suspense>
  );
}
