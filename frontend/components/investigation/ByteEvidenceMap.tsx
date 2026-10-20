"use client";

import { useState } from "react";
import { ForensicFragment, DamageRegion, ReconstructionStep } from "@/lib/types";

interface ByteEvidenceMapProps {
  totalBytes: number;
  verifiedBytes: number;
  reconstructedBytes: number;
  missingBytes: number;
  fragments: ForensicFragment[];
  damageRegions: DamageRegion[];
  reconstructionSteps: ReconstructionStep[];
}

interface TimelineSegment {
  id: string;
  name: string;
  start: number;
  end: number;
  length: number;
  type: "VERIFIED" | "RECONSTRUCTED" | "MISSING";
  description: string;
}

export function ByteEvidenceMap({
  totalBytes,
  verifiedBytes,
  reconstructedBytes,
  missingBytes,
  fragments,
  damageRegions,
}: ByteEvidenceMapProps) {
  const [hoveredSegment, setHoveredSegment] = useState<TimelineSegment | null>(null);

  // Compute ordered timeline segments from real backend forensic metadata
  const effectiveTotal = Math.max(totalBytes, verifiedBytes + reconstructedBytes + missingBytes, 1);

  const segments: TimelineSegment[] = [];

  if (fragments.length > 0) {
    // Add verified fragments
    fragments.forEach((f, idx) => {
      const vLen = f.verified_bytes > 0 ? f.verified_bytes : f.length;
      if (vLen > 0 && f.status !== "MISSING") {
        segments.push({
          id: f.fragment_id,
          name: idx === 0 ? "Fragment A (Header)" : idx === 1 ? "Fragment B (Trailer)" : `Fragment ${idx + 1}`,
          start: f.offset,
          end: f.offset + vLen,
          length: vLen,
          type: "VERIFIED",
          description: "Exact evidence bytes observed and validated intact without modification.",
        });
      }
    });

    // Add damage regions (distinguishing RECONSTRUCTED closures from MISSING gaps)
    damageRegions.forEach((d, idx) => {
      const isRecon =
        d.status === "RECONSTRUCTED" ||
        d.type?.toUpperCase().includes("STRUCTURAL") ||
        d.type?.toUpperCase().includes("CLOSURE");

      segments.push({
        id: d.region_id,
        name: isRecon ? `Reconstructed Closure (${d.length} B)` : `Evidence Gap ${idx + 1} (${d.length} B)`,
        start: d.start_offset,
        end: d.end_offset,
        length: d.length,
        type: isRecon ? "RECONSTRUCTED" : "MISSING",
        description: isRecon
          ? "Deterministic structural syntax closure appended by parser. Derived strictly from grammar rules."
          : "Unobserved evidence gap. Not deterministically recoverable; zero hallucinated filler.",
      });
    });

    // If reconstructedBytes > 0 and no damage region was marked RECONSTRUCTED, append reconstructed segment
    const hasReconSegment = segments.some((s) => s.type === "RECONSTRUCTED");
    if (!hasReconSegment && reconstructedBytes > 0) {
      segments.push({
        id: "recon-closure-auto",
        name: `Reconstructed Structural Closure (${reconstructedBytes} B)`,
        start: verifiedBytes,
        end: verifiedBytes + reconstructedBytes,
        length: reconstructedBytes,
        type: "RECONSTRUCTED",
        description: "Deterministic syntax closure delimiters appended to restore format validity.",
      });
    }

    // Sort by start offset
    segments.sort((a, b) => a.start - b.start);
  } else {
    // Fallback based on aggregate V/R/M
    if (verifiedBytes > 0) {
      segments.push({
        id: "v-all",
        name: "Contiguous Verified Evidence",
        start: 0,
        end: verifiedBytes,
        length: verifiedBytes,
        type: "VERIFIED",
        description: "Original evidence buffer validated intact.",
      });
    }
    if (reconstructedBytes > 0) {
      segments.push({
        id: "r-all",
        name: "Deterministic Structural Reconstruction",
        start: verifiedBytes,
        end: verifiedBytes + reconstructedBytes,
        length: reconstructedBytes,
        type: "RECONSTRUCTED",
        description: "Deterministic syntax reconstruction derived from format grammar.",
      });
    }
    if (missingBytes > 0) {
      segments.push({
        id: "m-all",
        name: "Unobserved Missing Evidence",
        start: verifiedBytes + reconstructedBytes,
        end: verifiedBytes + reconstructedBytes + missingBytes,
        length: missingBytes,
        type: "MISSING",
        description: "Unobserved evidence gap in source file.",
      });
    }
  }

  const vPercent = Math.round((verifiedBytes / effectiveTotal) * 100);
  const rPercent = Math.round((reconstructedBytes / effectiveTotal) * 100);
  const mPercent = Math.max(0, 100 - vPercent - rPercent);

  return (
    <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xs font-mono">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
              EVIDENCE BYTE MAP
            </h3>
          </div>
          <p className="text-xs text-slate-600 font-sans mt-0.5">
            Exact horizontal byte mapping showing verified boundaries, repaired syntax, and unobserved gaps.
          </p>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-4 text-xs font-semibold">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded bg-emerald-500" />
            <span className="text-slate-700">VERIFIED ({vPercent}%)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded bg-slate-600" />
            <span className="text-slate-700">RECONSTRUCTED ({rPercent}%)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded bg-amber-500" />
            <span className="text-slate-700">MISSING ({mPercent}%)</span>
          </div>
        </div>
      </div>

      {/* Interactive Horizontal Timeline */}
      <div className="space-y-3 pt-2">
        {/* Boundary Ticks Top */}
        <div className="flex justify-between text-[11px] text-slate-500 px-1 font-semibold">
          <span>0 B (OFFSET START)</span>
          <span className="hidden sm:inline">EVIDENCE BUFFER: {effectiveTotal.toLocaleString()} B</span>
          <span>{effectiveTotal.toLocaleString()} B (OFFSET END)</span>
        </div>

        {/* The Main Segmented Bar */}
        <div className="w-full h-12 rounded-xl bg-slate-100 border border-slate-300 flex overflow-hidden p-1 gap-0.5 shadow-inner">
          {segments.map((seg) => {
            const widthPct = Math.max((seg.length / effectiveTotal) * 100, 4);
            const isHovered = hoveredSegment?.id === seg.id;

            return (
              <div
                key={seg.id}
                onMouseEnter={() => setHoveredSegment(seg)}
                onMouseLeave={() => setHoveredSegment(null)}
                style={{ width: `${widthPct}%` }}
                className={`h-full rounded-lg cursor-pointer transition-all relative flex items-center justify-center text-[10px] font-bold ${
                  seg.type === "VERIFIED"
                    ? isHovered
                      ? "bg-emerald-600 text-white ring-2 ring-emerald-400 shadow-sm"
                      : "bg-emerald-500 text-white hover:bg-emerald-600"
                    : seg.type === "RECONSTRUCTED"
                    ? isHovered
                      ? "bg-slate-700 text-white ring-2 ring-slate-400 shadow-sm"
                      : "bg-slate-600 text-white hover:bg-slate-700"
                    : isHovered
                    ? "bg-amber-600 text-white ring-2 ring-amber-400 shadow-sm"
                    : "bg-amber-500 text-white hover:bg-amber-600"
                }`}
              >
                <span className="truncate px-1 hidden md:inline">
                  {seg.type === "VERIFIED" ? `VERIFIED (${seg.length}B)` : seg.type === "MISSING" ? `GAP (${seg.length}B)` : `RECON (${seg.length}B)`}
                </span>
              </div>
            );
          })}
        </div>

        {/* Hover Inspector Tooltip / Info Bar */}
        <div className="min-h-[50px] bg-slate-50 border border-slate-200 rounded-xl p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          {hoveredSegment ? (
            <>
              <div className="flex items-center gap-3">
                <span
                  className={`px-2.5 py-0.5 rounded font-bold text-[10px] border ${
                    hoveredSegment.type === "VERIFIED"
                      ? "bg-emerald-100 text-emerald-800 border-emerald-300"
                      : hoveredSegment.type === "MISSING"
                      ? "bg-amber-100 text-amber-800 border-amber-300"
                      : "bg-slate-100 text-slate-800 border-slate-300"
                  }`}
                >
                  {hoveredSegment.name}
                </span>
                <span className="text-slate-900 font-bold">
                  Offset {hoveredSegment.start} B → {hoveredSegment.end} B ({hoveredSegment.length} Bytes)
                </span>
              </div>
              <p className="text-[11px] text-slate-600 font-sans truncate">
                {hoveredSegment.description}
              </p>
            </>
          ) : (
            <div className="text-slate-500 text-xs italic flex items-center gap-2">
              <span>Hover over any timeline segment above to inspect exact forensic byte offsets and validation status.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
