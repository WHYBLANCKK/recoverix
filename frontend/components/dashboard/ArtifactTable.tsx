"use client";

import { useState } from "react";
import Link from "next/link";
import { Artifact, PriorityLevel, ArtifactCategory } from "@/lib/types";
import { PriorityBadge, StatusBadge } from "./PriorityBadge";
import { Search, Filter, ChevronRight, File } from "lucide-react";

export function ArtifactTable({ artifacts }: { artifacts: Artifact[] }) {
  const [filterPriority, setFilterPriority] = useState<PriorityLevel | "ALL">("ALL");
  const [filterCategory, setFilterCategory] = useState<ArtifactCategory | "ALL">("ALL");
  const [search, setSearch] = useState("");

  const filtered = artifacts.filter(a => {
    if (filterPriority !== "ALL" && a.priority !== filterPriority) return false;
    if (filterCategory !== "ALL" && a.category !== filterCategory) return false;
    if (search && !a.filename.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
      {/* Table Toolbar */}
      <div className="p-4 border-b border-slate-100 flex flex-col sm:flex-row gap-4 justify-between items-center bg-white">
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input 
            type="text" 
            placeholder="Search filename..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-50 border border-slate-300 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-900 focus:outline-none focus:border-emerald-500 focus:bg-white"
          />
        </div>
        <div className="flex gap-4 w-full sm:w-auto font-mono text-xs">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <select 
              value={filterPriority}
              onChange={(e) => setFilterPriority(e.target.value as PriorityLevel | "ALL")}
              className="bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-emerald-500"
            >
              <option value="ALL">All Priorities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
          <select 
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value as ArtifactCategory | "ALL")}
            className="bg-slate-50 border border-slate-300 rounded-lg px-3 py-2 text-xs text-slate-800 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Categories</option>
            <option value="DOCUMENT">Document</option>
            <option value="DATABASE_LOG">Database Log</option>
            <option value="PHOTO_MEDIA">Photo Media</option>
            <option value="SYSTEM_TRACE">System Trace</option>
            <option value="BINARY_ARCHIVE">Binary Archive</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-50/70 border-b border-slate-200 text-slate-500 font-mono text-xs uppercase font-semibold">
            <tr>
              <th className="px-6 py-3.5 font-medium">File</th>
              <th className="px-6 py-3.5 font-medium">Status</th>
              <th className="px-6 py-3.5 font-medium">Priority</th>
              <th className="px-6 py-3.5 font-medium">Confidence</th>
              <th className="px-6 py-3.5 font-medium">Size</th>
              <th className="px-6 py-3.5 font-medium"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 font-mono text-xs">
            {filtered.map(artifact => (
              <tr key={artifact.id} className="hover:bg-slate-50 transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <File className="w-5 h-5 text-slate-400 shrink-0" />
                    <div>
                      <p className="font-semibold text-slate-900 font-sans">{artifact.filename}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5 font-mono">
                        {artifact.category}
                      </p>
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <StatusBadge status={artifact.status} />
                </td>
                <td className="px-6 py-4">
                  <PriorityBadge priority={artifact.priority} />
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-slate-800 w-8">{artifact.confidence_score}%</span>
                    <div className="w-24 h-2 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
                      <div 
                        className={`h-full rounded-full ${
                          artifact.confidence_score > 80 ? 'bg-emerald-500' :
                          artifact.confidence_score > 50 ? 'bg-amber-500' : 'bg-rose-500'
                        }`}
                        style={{ width: `${artifact.confidence_score}%` }}
                      />
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 text-xs text-slate-600">
                  {artifact.verified_bytes} B verified
                </td>
                <td className="px-6 py-4 text-right">
                  <Link 
                    href={`/artifacts/${artifact.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-700 hover:text-emerald-800 transition-colors bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 px-2.5 py-1 rounded-md"
                  >
                    Inspect <ChevronRight className="w-3.5 h-3.5" />
                  </Link>
                </td>
              </tr>
            ))}
            
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-slate-500 text-xs">
                  {artifacts.length === 0 
                    ? "No artifacts recovered yet. Upload a file to begin analysis."
                    : "No artifacts match the current filters."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
