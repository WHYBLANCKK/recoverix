"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Layers,
  Search,
  ArrowRight,
  ChevronRight,
  Terminal,
  ExternalLink,
  Trash2,
  ShieldCheck,
} from "lucide-react";
import { fetchRecoveryRuns, deleteRecoveryRun } from "@/lib/api";
import { RecoverixLogo } from "@/components/ui/RecoverixLogo";
import { ForensicFragment, DamageRegion, ReconstructionStep } from "@/lib/types";

interface RecoveryRunEvent {
  event_id: string;
  sequence: number;
  event_type: string;
  timestamp: string;
  message: string;
  payload?: Record<string, unknown>;
}

interface RecoveryRunItem {
  run_id: string;
  artifact_id?: string;
  filename: string;
  format: string;
  status: string;
  started_at: string;
  completed_at?: string;
  total_input_bytes: number;
  total_verified_bytes: number;
  total_reconstructed_bytes: number;
  total_missing_bytes: number;
  fragments?: ForensicFragment[];
  damage_regions?: DamageRegion[];
  reconstruction_steps?: ReconstructionStep[];
  events?: RecoveryRunEvent[];
  confidence?: {
    total: number;
  };
}

export default function CasesPage() {
  const [runs, setRuns] = useState<RecoveryRunItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [formatFilter, setFormatFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedRun, setSelectedRun] = useState<RecoveryRunItem | null>(null);
  const [isDeletingRun, setIsDeletingRun] = useState(false);
  const [showDeleteRunConfirm, setShowDeleteRunConfirm] = useState(false);

  const handleDeleteRun = async (runId: string) => {
    if (isDeletingRun) return;
    setIsDeletingRun(true);
    try {
      const ok = await deleteRecoveryRun(runId);
      if (ok) {
        const nextRuns = runs.filter((r) => r.run_id !== runId);
        setRuns(nextRuns);
        setSelectedRun(nextRuns[0] || null);
        setShowDeleteRunConfirm(false);
      }
    } catch (e) {
      console.error("Failed to delete run:", e);
    } finally {
      setIsDeletingRun(false);
    }
  };

  useEffect(() => {
    async function loadRuns() {
      setLoading(true);
      try {
        const liveRuns = await fetchRecoveryRuns();
        if (liveRuns && liveRuns.length > 0) {
          const mappedRuns: RecoveryRunItem[] = liveRuns.map((r) => ({
            run_id: String(r.run_id || r.id || ""),
            artifact_id: r.artifact_id,
            filename: String(r.filename || "evidence.bin"),
            format: String(r.format || "UNKNOWN"),
            status: String(r.status || "UNRECOVERABLE"),
            started_at: String(r.started_at || r.created_at || new Date().toISOString()),
            completed_at: r.completed_at ? String(r.completed_at) : undefined,
            total_input_bytes: Number(r.total_input_bytes ?? 0),
            total_verified_bytes: Number(r.total_verified_bytes ?? r.verified_bytes ?? 0),
            total_reconstructed_bytes: Number(r.total_reconstructed_bytes ?? r.reconstructed_bytes ?? 0),
            total_missing_bytes: Number(r.total_missing_bytes ?? r.missing_bytes ?? 0),
            fragments: r.fragments as ForensicFragment[] | undefined,
            damage_regions: r.damage_regions,
            reconstruction_steps: r.reconstruction_steps,
            events: r.events as RecoveryRunEvent[] | undefined,
            confidence: r.confidence as { total: number } | undefined,
          }));
          // Sort most recent first
          mappedRuns.sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
          setRuns(mappedRuns);
          setSelectedRun(mappedRuns[0]);
        }
      } catch (e) {
        console.error("Failed to load recovery runs:", e);
      } finally {
        setLoading(false);
      }
    }
    loadRuns();
  }, []);

  const filteredRuns = runs.filter((run) => {
    const matchesSearch =
      run.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
      run.run_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (run.artifact_id && run.artifact_id.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesFormat = formatFilter === "all" || run.format.toLowerCase() === formatFilter.toLowerCase();
    const matchesStatus = statusFilter === "all" || run.status.toLowerCase() === statusFilter.toLowerCase();
    return matchesSearch && matchesFormat && matchesStatus;
  });

  const fullyRecoveredCount = runs.filter((r) => r.status === "FULLY_RECOVERED").length;
  const partiallyRecoveredCount = runs.filter((r) => r.status === "PARTIALLY_RECOVERED").length;
  const unrecoverableCount = runs.filter((r) => r.status === "UNRECOVERABLE").length;

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 flex flex-col font-mono selection:bg-emerald-500/20 selection:text-emerald-950">
      {/* Top Banner */}
      <div className="border-b border-slate-200 bg-white px-6 py-8">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <Link href="/" className="hover:text-slate-900 transition-colors flex items-center gap-1.5" aria-label="Recoverix Home">
                <RecoverixLogo size={16} showText={false} markOnly />
                <span className="font-bold">RECOVERIX</span>
              </Link>
              <span>/</span>
              <span className="text-emerald-700 font-bold">SESSION AUDIT LOG</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 flex items-center gap-3">
              <span>Evidence Case Ledger (This Session)</span>
              <span className="text-xs bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded font-semibold">
                {runs.length} RUNS IN SESSION
              </span>
            </h1>
            <p className="text-xs text-slate-600 font-sans max-w-2xl">
              Private, session-isolated audit ledger of evidence files analyzed in your current browser session. Because Recoverix enforces strict per-session cryptographic isolation, runs from other users are never visible to you, and your evidence is never visible to others.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/setup"
              className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold px-4 py-2.5 rounded-lg text-xs transition-all flex items-center gap-2 shadow-xs"
            >
              <span>NEW RECOVERY RUN</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="max-w-7xl mx-auto px-6 py-8 w-full space-y-8 flex-1">
        {/* Metric Cards Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 p-4 rounded-xl space-y-1 shadow-2xs">
            <div className="text-[10px] text-slate-500 uppercase font-semibold tracking-wider">TOTAL CASES</div>
            <div className="text-2xl font-bold text-slate-900">{runs.length}</div>
          </div>
          <div className="bg-white border border-emerald-300 p-4 rounded-xl space-y-1 shadow-2xs">
            <div className="text-[10px] text-emerald-700 uppercase font-semibold tracking-wider">FULLY RECOVERED</div>
            <div className="text-2xl font-bold text-emerald-600">{fullyRecoveredCount}</div>
          </div>
          <div className="bg-white border border-amber-300 p-4 rounded-xl space-y-1 shadow-2xs">
            <div className="text-[10px] text-amber-700 uppercase font-semibold tracking-wider">PARTIAL RECOVERIES</div>
            <div className="text-2xl font-bold text-amber-600">{partiallyRecoveredCount}</div>
          </div>
          <div className="bg-white border border-rose-300 p-4 rounded-xl space-y-1 shadow-2xs">
            <div className="text-[10px] text-rose-700 uppercase font-semibold tracking-wider">UNRECOVERABLE</div>
            <div className="text-2xl font-bold text-rose-600">{unrecoverableCount}</div>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-white border border-slate-200 p-4 rounded-xl text-xs shadow-2xs">
          <div className="flex items-center gap-2 w-full sm:w-80 bg-slate-50 border border-slate-300 px-3 py-2 rounded-lg">
            <Search className="w-4 h-4 text-slate-400 shrink-0" />
            <input
              type="text"
              id="cases-search-input"
              name="search_term"
              aria-label="Search filename or Case ID"
              placeholder="Search filename or Case ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-transparent border-none outline-none text-slate-900 placeholder:text-slate-400 w-full font-mono text-xs"
            />
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            {/* Format Filter */}
            <div className="flex items-center gap-1.5">
              <label htmlFor="cases-format-filter" className="text-slate-500 font-semibold text-[11px]">FORMAT:</label>
              <select
                id="cases-format-filter"
                name="format_filter"
                aria-label="Filter evidence by format"
                value={formatFilter}
                onChange={(e) => setFormatFilter(e.target.value)}
                className="bg-slate-50 border border-slate-300 text-slate-800 rounded px-2.5 py-1.5 outline-none font-mono text-xs"
              >
                <option value="all">ALL FORMATS</option>
                <option value="txt">TXT</option>
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
                <option value="pdf">PDF</option>
                <option value="png">PNG</option>
                <option value="jpeg">JPEG</option>
                <option value="xml">XML</option>
                <option value="zip">ZIP</option>
              </select>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-1.5">
              <label htmlFor="cases-status-filter" className="text-slate-500 font-semibold text-[11px]">STATUS:</label>
              <select
                id="cases-status-filter"
                name="status_filter"
                aria-label="Filter evidence by recovery status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-50 border border-slate-300 text-slate-800 rounded px-2.5 py-1.5 outline-none font-mono text-xs"
              >
                <option value="all">ALL STATUSES</option>
                <option value="FULLY_RECOVERED">FULLY RECOVERED</option>
                <option value="PARTIALLY_RECOVERED">PARTIALLY RECOVERED</option>
                <option value="UNRECOVERABLE">UNRECOVERABLE</option>
              </select>
            </div>
          </div>
        </div>

        {/* Two-Column Layout: Cases Table (Left 60%) + Audit Trail Detail (Right 40%) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Cases Table */}
          <div className="lg:col-span-8 bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="p-4 border-b border-slate-100 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <Layers className="w-4 h-4 text-emerald-600" />
                <span>Recorded Evidence Runs ({filteredRuns.length})</span>
              </span>
              <span className="text-[10px] text-slate-500 font-medium">SELECT ROW FOR AUDIT TRAIL</span>
            </div>

            {loading ? (
              <div className="p-12 text-center text-slate-500 text-xs">
                Loading session case repository...
              </div>
            ) : runs.length === 0 ? (
              <div className="p-16 text-center space-y-4 max-w-lg mx-auto">
                <div className="w-12 h-12 rounded-2xl bg-emerald-50 border border-emerald-200 text-emerald-700 flex items-center justify-center mx-auto shadow-2xs">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <div className="space-y-1.5">
                  <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wider">
                    No Recorded Cases in this Session
                  </h3>
                  <p className="text-xs text-slate-500 font-sans leading-relaxed">
                    Recoverix enforces strict per-session data isolation. Your uploads are cryptographically bound to your browser session and automatically purged within 24 hours. Runs from other sessions are never accessible.
                  </p>
                </div>
                <div className="pt-2">
                  <Link
                    href="/"
                    className="inline-flex items-center gap-2 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-mono font-bold px-4 py-2.5 rounded-lg text-xs transition-all shadow-xs"
                  >
                    <span>Upload & Recover a File</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>
            ) : filteredRuns.length === 0 ? (
              <div className="p-12 text-center space-y-3">
                <div className="text-slate-500 text-xs">No recorded recovery runs match current filters.</div>
                <button
                  type="button"
                  onClick={() => {
                    setSearchTerm("");
                    setFormatFilter("all");
                    setStatusFilter("all");
                  }}
                  className="inline-block bg-emerald-50 text-emerald-700 border border-emerald-300 px-4 py-2 rounded-lg text-xs hover:bg-emerald-100 font-semibold"
                >
                  Reset Filters
                </button>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-500 bg-slate-50/70 text-[10px] uppercase font-semibold tracking-wider">
                      <th className="py-3 px-4">Case / Run ID</th>
                      <th className="py-3 px-4">Evidence</th>
                      <th className="py-3 px-2">Fmt</th>
                      <th className="py-3 px-3">Status</th>
                      <th className="py-3 px-3">Score</th>
                      <th className="py-3 px-4">Accounting (V/R/M)</th>
                      <th className="py-3 px-4 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredRuns.map((run) => {
                      const isSelected = selectedRun?.run_id === run.run_id;
                      const confScore = run.confidence?.total ?? 0;
                      const targetId = run.artifact_id || run.run_id;

                      return (
                        <tr
                          key={run.run_id}
                          onClick={() => setSelectedRun(run)}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? "bg-emerald-50/60 border-l-4 border-l-emerald-500"
                              : "hover:bg-slate-50"
                          }`}
                        >
                          <td className="py-3.5 px-4 font-bold text-slate-900 truncate max-w-[120px]">
                            {run.run_id.replace("run_", "CASE-")}
                          </td>
                          <td className="py-3.5 px-4 text-slate-700 font-sans truncate max-w-[160px]" title={run.filename}>
                            {run.filename}
                          </td>
                          <td className="py-3.5 px-2">
                            <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-[10px] text-slate-800 uppercase font-bold">
                              {run.format}
                            </span>
                          </td>
                          <td className="py-3.5 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                run.status === "FULLY_RECOVERED"
                                  ? "bg-emerald-50 text-emerald-700 border-emerald-300"
                                  : run.status === "PARTIALLY_RECOVERED"
                                  ? "bg-amber-50 text-amber-800 border-amber-300"
                                  : "bg-rose-50 text-rose-700 border-rose-300"
                              }`}
                            >
                              {run.status.replace("_RECOVERED", "")}
                            </span>
                          </td>
                          <td className="py-3.5 px-3 font-mono font-bold text-slate-800">
                            {confScore.toFixed(1)}%
                          </td>
                          <td className="py-3.5 px-4 text-[11px] font-mono">
                            <span className="text-emerald-700 font-bold">{run.total_verified_bytes}B</span>
                            <span className="text-slate-400 mx-1">/</span>
                            <span className="text-slate-700 font-bold">{run.total_reconstructed_bytes}B</span>
                            <span className="text-slate-400 mx-1">/</span>
                            <span className="text-amber-700 font-bold">{run.total_missing_bytes}B</span>
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            <Link
                              href={`/investigation/${targetId}`}
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-50 hover:bg-emerald-100 text-emerald-800 border border-emerald-300 text-[10px] font-semibold transition-colors"
                            >
                              <span>INVESTIGATE</span>
                              <ChevronRight className="w-3 h-3" />
                            </Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Right Column: Deterministic Audit Trail Inspector */}
          <div className="lg:col-span-4 bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs space-y-4 p-5">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-600" />
                <span>Audit Trail & Event Log</span>
              </span>
              {selectedRun && (
                <span className="text-[10px] text-slate-500 font-mono">
                  {selectedRun.run_id}
                </span>
              )}
            </div>

            {selectedRun ? (
              <div className="space-y-4">
                {/* Run Metadata Header */}
                <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 font-medium">EVIDENCE ARTIFACT</span>
                    <span className="text-slate-900 font-bold truncate max-w-[180px]">{selectedRun.filename}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 font-medium">TOTAL INPUT BYTES</span>
                    <span className="text-slate-800 font-semibold">{selectedRun.total_input_bytes} Bytes</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 font-medium">ACQUISITION TIME</span>
                    <span className="text-slate-600 text-[10px]">
                      {new Date(selectedRun.started_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="pt-2 border-t border-slate-200 flex flex-col gap-2">
                    <Link
                      href={`/investigation/${selectedRun.artifact_id || selectedRun.run_id}`}
                      className="w-full bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold py-2 rounded-lg text-center text-xs transition-colors flex items-center justify-center gap-1.5 shadow-2xs"
                    >
                      <span>OPEN FULL INVESTIGATION WORKSPACE</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </Link>

                    {!showDeleteRunConfirm ? (
                      <button
                        type="button"
                        onClick={() => setShowDeleteRunConfirm(true)}
                        className="w-full border border-rose-200 text-rose-700 hover:bg-rose-50 py-1.5 rounded-lg text-center text-xs font-semibold transition-colors flex items-center justify-center gap-1.5"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>DELETE THIS CASE RECORD</span>
                      </button>
                    ) : (
                      <div className="bg-rose-50 border border-rose-200 p-2 rounded-lg text-center space-y-1.5">
                        <span className="text-[11px] text-rose-900 block font-sans">
                          Permanently delete run and blobs?
                        </span>
                        <div className="flex items-center justify-center gap-2">
                          <button
                            type="button"
                            onClick={() => handleDeleteRun(selectedRun.run_id)}
                            disabled={isDeletingRun}
                            className="bg-rose-600 hover:bg-rose-700 text-white font-bold px-3 py-1 rounded text-[10px] uppercase transition-colors disabled:opacity-50"
                          >
                            {isDeletingRun ? "Deleting..." : "Confirm Delete"}
                          </button>
                          <button
                            type="button"
                            onClick={() => setShowDeleteRunConfirm(false)}
                            disabled={isDeletingRun}
                            className="text-slate-600 hover:text-slate-900 px-2 py-1 text-[10px] underline"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Event Log Stream */}
                <div className="space-y-2">
                  <div className="text-[10px] text-slate-500 uppercase font-bold tracking-wider">
                    Sequential Forensic Events ({selectedRun.events?.length || 0})
                  </div>
                  <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
                    {selectedRun.events && selectedRun.events.length > 0 ? (
                      selectedRun.events.map((evt: RecoveryRunEvent) => (
                        <div
                          key={evt.event_id}
                          className="bg-slate-50 border border-slate-200 p-2.5 rounded-lg text-[11px] space-y-1"
                        >
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-emerald-800 font-bold">
                              #{evt.sequence} · {evt.event_type}
                            </span>
                            <span className="text-slate-400 font-mono text-[9px]">
                              {evt.timestamp ? new Date(evt.timestamp).toISOString().split("T")[1].replace("Z", "") : ""}
                            </span>
                          </div>
                          <div className="text-slate-700 font-sans leading-relaxed text-[11px]">
                            {evt.message}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-slate-500 text-xs py-4 text-center">
                        No individual event traces attached.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-slate-500 text-xs py-8 text-center">
                Select a case from the table to inspect its deterministic audit trail.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
