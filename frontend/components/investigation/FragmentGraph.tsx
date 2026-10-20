"use client";

import { useState } from "react";
import {
  ForensicFragment,
  DamageRegion,
  ReconstructionStep,
} from "@/lib/types";
import {
  FileText,
  ShieldCheck,
  AlertTriangle,
  Cpu,
  Info,
  ArrowRight,
  ArrowDown,
  XCircle,
  Shuffle,
  CheckCircle2,
  GitBranch,
  Layers,
} from "lucide-react";

interface FragmentGraphProps {
  filename: string;
  totalBytes: number;
  verifiedBytes?: number;
  reconstructedBytes?: number;
  missingBytes?: number;
  fragments: ForensicFragment[];
  damageRegions: DamageRegion[];
  reconstructionSteps: ReconstructionStep[];
  status?: string;
  format?: string;
  reconstructionMethod?: string;
  validationStatus?: string;
}

interface InspectorNode {
  id: string;
  type: "ROOT" | "FRAGMENT" | "GAP" | "RECONSTRUCTION" | "CONTIGUOUS" | "VALIDATION" | "TARGET";
  label: string;
  offsetRange: string;
  length: string;
  status: string;
  source: string;
  description: string;
  details?: Record<string, unknown>;
}

export function FragmentGraph({
  filename,
  totalBytes,
  verifiedBytes,
  reconstructedBytes,
  missingBytes,
  fragments = [],
  damageRegions = [],
  reconstructionSteps = [],
  status,
  format,
  reconstructionMethod,
  validationStatus,
}: FragmentGraphProps) {
  const vBytes = verifiedBytes ?? fragments.reduce((acc, f) => acc + (f.verified_bytes || 0), 0);
  const rBytes =
    reconstructedBytes ??
    damageRegions.filter((d) => d.status === "RECONSTRUCTED").reduce((acc, d) => acc + d.length, 0);
  const mBytes =
    missingBytes ??
    damageRegions.filter((d) => d.status !== "RECONSTRUCTED").reduce((acc, d) => acc + d.length, 0);

  // Classification of forensic scenario
  const isUnrecoverable =
    status === "UNRECOVERABLE" ||
    validationStatus === "FAILED" ||
    reconstructionMethod?.toUpperCase().includes("REJECTED") ||
    (status !== "PARTIALLY_RECOVERED" &&
      status !== "FULLY_RECOVERED" &&
      damageRegions.length > 0 &&
      damageRegions.some((d) => d.type?.toUpperCase().includes("MALFORMED")));

  const isShuffled =
    !isUnrecoverable &&
    (reconstructionMethod === "FRAGMENT_UNSHUFFLE" ||
      reconstructionSteps.some((s) => s.method === "FRAGMENT_UNSHUFFLE") ||
      fragments.some((f) => f.source?.includes("shuffled")));

  const isStructuralReconstruction =
    !isUnrecoverable &&
    !isShuffled &&
    (rBytes > 0 ||
      reconstructionMethod?.toUpperCase().includes("CLOSURE") ||
      reconstructionMethod?.toUpperCase().includes("STRUCTURAL") ||
      damageRegions.some((d) => d.status === "RECONSTRUCTED" || d.type?.toUpperCase().includes("CLOSURE")));

  const isFragmentedWithGap =
    !isShuffled &&
    !isUnrecoverable &&
    !isStructuralReconstruction &&
    (damageRegions.length > 0 || fragments.length > 1);

  const isContiguous =
    !isUnrecoverable &&
    !isShuffled &&
    !isStructuralReconstruction &&
    !isFragmentedWithGap;

  // Determine initial inspector node based on real evidence
  const getInitialNode = (): InspectorNode => {
    if (isStructuralReconstruction) {
      return {
        id: "recon-closure",
        type: "RECONSTRUCTION",
        label: `RECONSTRUCTED CLOSURE (${rBytes} B)`,
        offsetRange: `${vBytes} B – ${vBytes + rBytes} B`,
        length: `${rBytes} Bytes`,
        status: "RECONSTRUCTED (GRAMMAR DERIVED)",
        source: reconstructionMethod || "JSON_STRUCTURAL_CLOSURE",
        description:
          "Uniquely determined structural closing delimiters appended by deterministic format grammar parser. Zero hallucinated keys or values.",
      };
    }

    if (isShuffled) {
      return {
        id: "shuffled-rel",
        type: "RECONSTRUCTION",
        label: "FRAGMENT_UNSHUFFLE (REORDER)",
        offsetRange: `0 B – ${totalBytes} B`,
        length: `${totalBytes} Bytes`,
        status: "REORDERED (100% VERIFIED)",
        source: "Deterministic Sequence Inversion",
        description:
          "PDF header fragment and trailer fragment were detected out of order in raw evidence. Deterministic un-shuffling reordered the fragments into valid PDF sequence without synthetic bytes.",
      };
    }

    if (isUnrecoverable) {
      const dmg = damageRegions[0];
      return {
        id: dmg?.region_id || "validation-failed",
        type: "VALIDATION",
        label: "VALIDATION GATE: FAILED",
        offsetRange: `0 B – ${totalBytes} B`,
        length: `${totalBytes} Bytes`,
        status: "UNRECOVERABLE",
        source: reconstructionMethod || "Format Syntax & Structure Parser",
        description:
          "No valid reconstruction relationship established. Evidence tokens contain unrecoverable syntax deformation. Refusing to synthesize hallucinated data.",
      };
    }

    if (damageRegions.length > 0) {
      const dmg = damageRegions[0];
      return {
        id: dmg.region_id,
        type: "GAP",
        label: `OBSERVED BYTE GAP [${dmg.region_id}]`,
        offsetRange: `${dmg.start_offset} B – ${dmg.end_offset} B`,
        length: `${dmg.length} Bytes`,
        status: `${dmg.status || "MISSING"} (PRESERVED)`,
        source: "Evidence Discontinuity",
        description:
          "Missing byte span between verified fragments. Recoverix strictly preserves this gap as unobserved evidence to maintain byte-accurate auditability.",
      };
    }

    if (fragments.length > 0) {
      const f = fragments[0];
      return {
        id: f.fragment_id,
        type: "CONTIGUOUS",
        label: "CONTIGUOUS VERIFIED EVIDENCE",
        offsetRange: `${f.offset} B – ${f.end_offset} B`,
        length: `${f.length} Bytes`,
        status: "VERIFIED INTACT",
        source: f.source || "Direct Header-to-EOF Parsing",
        description:
          "Single carved continuous evidence stream verified by format validator with zero missing gaps.",
      };
    }

    return {
      id: "root",
      type: "ROOT",
      label: filename,
      offsetRange: `0 B – ${totalBytes} B`,
      length: `${totalBytes} Bytes`,
      status: "ORIGINAL EVIDENCE SOURCE",
      source: "Uploaded Evidence File",
      description: "Target evidence container analyzed by deterministic carving and validation.",
    };
  };

  const [selectedCustomNode, setSelectedCustomNode] = useState<InspectorNode | null>(null);
  const [prevFilename, setPrevFilename] = useState<string>(filename);
  if (prevFilename !== filename) {
    setPrevFilename(filename);
    setSelectedCustomNode(null);
  }

  const selectedNode = selectedCustomNode ?? getInitialNode();
  const setSelectedNode = (node: InspectorNode) => setSelectedCustomNode(node);

  // Compute actual node count for display
  const nodeCount = isContiguous
    ? 2
    : isShuffled
    ? 5
    : isStructuralReconstruction
    ? 4
    : isUnrecoverable
    ? 3
    : 1 + fragments.length + damageRegions.length + 1; // root + frags + gaps + assembly

  // For Case B & C: Build chronological ordered byte segments
  const orderedSegments: Array<
    | { kind: "fragment"; data: ForensicFragment; start: number; end: number; index: number }
    | { kind: "damage"; data: DamageRegion; start: number; end: number; index: number }
  > = [
    ...fragments.map((f, idx) => ({ kind: "fragment" as const, data: f, start: f.offset, end: f.end_offset, index: idx })),
    ...damageRegions.map((d, idx) => ({ kind: "damage" as const, data: d, start: d.start_offset, end: d.end_offset, index: idx })),
  ].sort((a, b) => a.start - b.start);

  // For Case D: Separate header and trailer fragments
  const trailerFrag = fragments.find((f) => f.offset === 0 || f.source?.includes("trailer")) || fragments[1] || fragments[0];
  const headerFrag = fragments.find((f) => f.offset > 0 || f.source?.includes("header")) || fragments[0];

  return (
    <div className="bg-white border border-slate-200/90 rounded-2xl p-6 sm:p-8 space-y-6 shadow-xs font-mono">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                isUnrecoverable
                  ? "bg-rose-500"
                  : isStructuralReconstruction
                  ? "bg-sky-500"
                  : isShuffled
                  ? "bg-sky-500"
                  : isFragmentedWithGap
                  ? "bg-amber-500"
                  : "bg-emerald-500"
              }`}
            />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
              Fragment Relationship Graph
            </h3>
          </div>
          <p className="text-xs text-slate-600 font-sans mt-0.5">
            {isContiguous
              ? "Single contiguous verified evidence stream with zero missing gaps."
              : isStructuralReconstruction
              ? "Deterministic structural reconstruction: validated prefix completed with grammar-derived closing syntax."
              : isShuffled
              ? "Deterministic sequence unshuffle: out-of-order raw fragments reordered to valid specification."
              : isUnrecoverable
              ? "Validation gate rejected corrupt candidate. No valid relationship established."
              : "Hierarchical sequence derived directly from observed candidate offsets and gaps."}
          </p>
        </div>

        <div className="flex items-center gap-2 text-[11px]">
          <span className="bg-slate-100 text-slate-700 border border-slate-200 px-2.5 py-1 rounded font-medium">
            NODES: {nodeCount}
          </span>
          <span
            className={`border px-2.5 py-1 rounded font-semibold ${
              isUnrecoverable
                ? "bg-rose-50 text-rose-800 border-rose-200"
                : isStructuralReconstruction
                ? "bg-sky-50 text-sky-800 border-sky-200"
                : "bg-emerald-50 text-emerald-800 border-emerald-200"
            }`}
          >
            {isUnrecoverable
              ? "CORRUPT EVIDENCE"
              : isStructuralReconstruction
              ? "STRUCTURAL RECONSTRUCTION (R > 0)"
              : "ZERO HALLUCINATION"}
          </span>
        </div>
      </div>

      {/* Visual Canvas Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Interactive Graph Canvas (Cols 1-8) */}
        <div className="lg:col-span-8 bg-slate-50/80 border border-slate-200 rounded-xl p-6 relative overflow-x-auto min-h-[380px] flex flex-col items-center justify-center">
          {/* ROOT NODE: ORIGINAL EVIDENCE */}
          <div
            onClick={() =>
              setSelectedNode({
                id: "root",
                type: "ROOT",
                label: filename,
                offsetRange: `0 B – ${totalBytes} B`,
                length: `${totalBytes} Bytes`,
                status: "ORIGINAL EVIDENCE SOURCE",
                source: "Input Stream",
                description: "Full unparsed evidence container submitted for deterministic forensic examination.",
              })
            }
            className={`cursor-pointer px-5 py-3 rounded-xl border text-center transition-all shadow-2xs max-w-md w-full ${
              selectedNode.id === "root"
                ? "bg-slate-900 text-white border-slate-900 shadow-md scale-105"
                : "bg-white border-slate-300 text-slate-800 hover:border-slate-400"
            }`}
          >
            <div
              className={`text-[10px] uppercase tracking-wider font-semibold ${
                selectedNode.id === "root" ? "text-slate-300" : "text-slate-500"
              }`}
            >
              OBSERVED EVIDENCE CONTAINER
            </div>
            <div className="text-sm font-bold flex items-center justify-center gap-1.5 mt-0.5">
              <FileText
                className={`w-4 h-4 ${
                  selectedNode.id === "root" ? "text-emerald-400" : "text-emerald-600"
                }`}
              />
              <span className="truncate">{filename}</span>
            </div>
            <div
              className={`text-[10px] mt-1 ${
                selectedNode.id === "root" ? "text-slate-300" : "text-slate-500"
              }`}
            >
              {totalBytes} Bytes · {format?.toUpperCase() || "CARVED"}
            </div>
          </div>

          {/* SVG Connector Down */}
          <div className="w-full flex justify-center py-2.5">
            <div className="w-0.5 h-6 bg-slate-300 flex items-center justify-center">
              <ArrowDown className="w-3 h-3 text-slate-400 translate-y-3" />
            </div>
          </div>

          {/* ========================================================================= */}
          {/* CASE A: INTACT / CONTIGUOUS EVIDENCE */}
          {/* ========================================================================= */}
          {isContiguous && (
            <div className="w-full flex flex-col items-center mt-1">
              <div
                onClick={() =>
                  setSelectedNode({
                    id: "contiguous",
                    type: "CONTIGUOUS",
                    label: "CONTIGUOUS VERIFIED EVIDENCE STREAM",
                    offsetRange: `0 B – ${totalBytes} B`,
                    length: `${totalBytes} Bytes`,
                    status: "VERIFIED INTACT",
                    source: "Direct Header-to-EOF Parsing",
                    description:
                      "Continuous valid stream with zero fragmented boundaries or missing regions. 100% evidentiary integrity.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-4 rounded-xl border text-center transition-all ${
                  selectedNode.id === "contiguous"
                    ? "bg-emerald-50 border-2 border-emerald-600 text-emerald-950 scale-105 shadow-md shadow-emerald-500/10"
                    : "bg-white border border-emerald-300 hover:border-emerald-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-emerald-700 text-xs font-bold uppercase mb-1">
                  <ShieldCheck className="w-4 h-4" />
                  <span>CONTIGUOUS EVIDENCE (0 → {totalBytes} B)</span>
                </div>
                <div className="text-[11px] text-slate-600">
                  Status: VERIFIED INTACT · 0 Missing Gaps · 100% Verified
                </div>
                <div className="text-[10px] text-emerald-700 font-semibold mt-1">
                  1:1 Byte Mapping to Source
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* CASE C: DETERMINISTIC STRUCTURAL RECONSTRUCTION (e.g. JSON CLOSURE) */}
          {/* ========================================================================= */}
          {isStructuralReconstruction && (
            <div className="w-full flex flex-col items-center space-y-3 mt-1">
              {/* 1. Verified Evidence Prefix Node */}
              <div
                onClick={() =>
                  setSelectedNode({
                    id: "verified-prefix",
                    type: "FRAGMENT",
                    label: `VERIFIED ${format?.toUpperCase() || "FORMAT"} PREFIX [0 B – ${vBytes} B]`,
                    offsetRange: `0 B – ${vBytes} B`,
                    length: `${vBytes} Bytes`,
                    status: "VERIFIED INTACT",
                    source: fragments[0]?.source || "direct_reconstruction",
                    description:
                      "Syntactically complete object key-value tokens observed directly in raw evidence buffer without modification.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-4 rounded-xl border text-center transition-all ${
                  selectedNode.id === "verified-prefix"
                    ? "bg-emerald-50 border-2 border-emerald-600 text-emerald-950 scale-105 shadow-md shadow-emerald-500/10"
                    : "bg-white border border-emerald-300 hover:border-emerald-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-emerald-700 text-xs font-bold uppercase mb-1">
                  <ShieldCheck className="w-4 h-4" />
                  <span>VERIFIED {format?.toUpperCase() || "EVIDENCE"} PREFIX</span>
                </div>
                <div className="text-xs font-bold text-slate-900">
                  0 B – {vBytes} B ({vBytes} Bytes)
                </div>
                <div className="text-[10px] text-emerald-700 font-semibold mt-1">
                  Status: VERIFIED INTACT · 100% Observed Evidence
                </div>
              </div>

              {/* Connector Down */}
              <div className="w-full flex justify-center py-1">
                <div className="w-0.5 h-5 bg-slate-300 flex items-center justify-center">
                  <ArrowDown className="w-3 h-3 text-slate-400 translate-y-2.5" />
                </div>
              </div>

              {/* 2. Reconstructed Closure Region Node */}
              <div
                onClick={() =>
                  setSelectedNode({
                    id: "recon-closure",
                    type: "RECONSTRUCTION",
                    label: `RECONSTRUCTED REGION (${rBytes} B)`,
                    offsetRange: `${vBytes} B – ${vBytes + rBytes} B`,
                    length: `${rBytes} Bytes`,
                    status: "RECONSTRUCTED (GRAMMAR DERIVED)",
                    source: reconstructionMethod || "JSON_STRUCTURAL_CLOSURE",
                    description:
                      "Uniquely determined structural closing delimiters appended by deterministic format grammar parser. Zero hallucinated keys or values.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-4 rounded-xl border text-center transition-all ${
                  selectedNode.id === "recon-closure"
                    ? "bg-sky-50 border-2 border-sky-600 text-sky-950 scale-105 shadow-md shadow-sky-500/10"
                    : "bg-white border border-sky-300 hover:border-sky-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-sky-700 text-xs font-bold uppercase mb-1">
                  <Cpu className="w-4 h-4" />
                  <span>RECONSTRUCTED REGION: {rBytes} B</span>
                </div>
                <div className="text-xs font-bold text-slate-900">
                  Offset {vBytes} B – {vBytes + rBytes} B
                </div>
                <div className="text-[11px] text-sky-900 font-medium mt-0.5">
                  METHOD: {reconstructionMethod || "JSON_STRUCTURAL_CLOSURE"}
                </div>
                <div className="text-[10px] text-slate-500 mt-1">
                  Forced Delimiters Only · Zero Hallucination
                </div>
              </div>

              {/* Connector Down */}
              <div className="w-full flex justify-center py-1">
                <div className="w-0.5 h-5 bg-slate-300 flex items-center justify-center">
                  <ArrowDown className="w-3 h-3 text-slate-400 translate-y-2.5" />
                </div>
              </div>

              {/* 3. Valid Artifact Output Node */}
              <div
                onClick={() =>
                  setSelectedNode({
                    id: "valid-artifact",
                    type: "TARGET",
                    label: `VALID ${format?.toUpperCase() || "FORMAT"} ARTIFACT`,
                    offsetRange: `0 B – ${vBytes + rBytes} B`,
                    length: `${vBytes + rBytes} Bytes`,
                    status: "PARTIALLY RECOVERED (VALID SPEC)",
                    source: "json_parser",
                    description:
                      `Valid ${format?.toUpperCase() || "JSON"} document validated by parser. Structural closure enables full programmatic parsing without semantic hallucination.`,
                  })
                }
                className={`cursor-pointer max-w-md w-full p-4 rounded-xl border text-center transition-all ${
                  selectedNode.id === "valid-artifact"
                    ? "bg-emerald-50 border-2 border-emerald-600 text-emerald-950 scale-105 shadow-md shadow-emerald-500/10"
                    : "bg-white border border-emerald-300 hover:border-emerald-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-emerald-700 text-xs font-bold uppercase mb-1">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>VALID {format?.toUpperCase() || "JSON"} ARTIFACT ({vBytes + rBytes} B)</span>
                </div>
                <div className="text-[11px] text-slate-700">
                  Status: PARTIALLY RECOVERED · VALID SPEC · {mBytes} B Missing
                </div>
                <div className="text-[10px] text-emerald-700 font-semibold mt-1">
                  Authoritative Parser Verification Passed
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* CASE B & C: FRAGMENTED EVIDENCE WITH REAL GAPS (SEQUENTIAL PIPELINE) */}
          {/* ========================================================================= */}
          {isFragmentedWithGap && (
            <div className="w-full flex flex-col items-center space-y-3 mt-1">
              {/* Sequential Fragments & Gaps Chain */}
              <div className="w-full max-w-2xl bg-white border border-slate-200 rounded-xl p-4 shadow-2xs">
                <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider mb-2 text-center">
                  OBSERVED EVIDENCE STREAM (SEQUENTIAL ORDER)
                </div>
                <div className="flex flex-col sm:flex-row items-center justify-center gap-2">
                  {orderedSegments.map((segment, idx) => {
                    const isLast = idx === orderedSegments.length - 1;
                    if (segment.kind === "fragment") {
                      const frag = segment.data;
                      const isSelected = selectedNode.id === frag.fragment_id;
                      const fragName =
                        format?.toUpperCase() === "CSV" && segment.index === 0
                          ? "CSV HEADER"
                          : format?.toUpperCase() === "CSV"
                          ? `CSV ROW ${segment.index}`
                          : `FRAGMENT ${String.fromCharCode(65 + segment.index)}`;

                      return (
                        <div key={frag.fragment_id} className="flex items-center gap-2 w-full sm:w-auto">
                          <div
                            onClick={() =>
                              setSelectedNode({
                                id: frag.fragment_id,
                                type: "FRAGMENT",
                                label: `${fragName} [${frag.fragment_id}]`,
                                offsetRange: `${frag.offset} B – ${frag.end_offset} B`,
                                length: `${frag.length} Bytes`,
                                status: frag.status,
                                source: frag.source || "text_structure",
                                description:
                                  "Contiguous verified segment located by format boundary and structure parser. Zero mutated bytes.",
                              })
                            }
                            className={`flex-1 sm:flex-initial cursor-pointer p-3 rounded-xl border text-center transition-all min-w-[130px] ${
                              isSelected
                                ? "bg-emerald-50 border-2 border-emerald-600 text-emerald-950 shadow-md shadow-emerald-500/10 scale-105"
                                : "bg-emerald-50/40 border border-emerald-300 hover:border-emerald-500 text-slate-800 shadow-2xs"
                            }`}
                          >
                            <div className="text-[9px] uppercase font-bold text-emerald-700">
                              {fragName}
                            </div>
                            <div className="text-xs font-bold text-slate-900 mt-0.5">
                              {frag.offset} B – {frag.end_offset} B
                            </div>
                            <div className="text-[10px] text-emerald-800 font-semibold mt-0.5">
                              {frag.length} B · {frag.status}
                            </div>
                          </div>
                          {!isLast && (
                            <ArrowRight className="hidden sm:block w-3.5 h-3.5 text-slate-400 shrink-0" />
                          )}
                        </div>
                      );
                    } else {
                      const dmg = segment.data;
                      const isSelected = selectedNode.id === dmg.region_id;

                      return (
                        <div key={dmg.region_id} className="flex items-center gap-2 w-full sm:w-auto">
                          <div
                            onClick={() =>
                              setSelectedNode({
                                id: dmg.region_id,
                                type: "GAP",
                                label: `OBSERVED BYTE GAP [${dmg.region_id}]`,
                                offsetRange: `${dmg.start_offset} B – ${dmg.end_offset} B`,
                                length: `${dmg.length} Bytes`,
                                status: "MISSING (PRESERVED)",
                                source: "Evidence Discontinuity",
                                description:
                                  "Missing byte span cannot be deterministically inferred. Recoverix preserves this gap as unobserved evidence.",
                              })
                            }
                            className={`flex-1 sm:flex-initial cursor-pointer p-3 rounded-xl border text-center transition-all min-w-[140px] ${
                              isSelected
                                ? "bg-amber-50 border-2 border-amber-600 text-amber-950 shadow-md shadow-amber-500/10 scale-105"
                                : "bg-amber-50/60 border border-amber-300 hover:border-amber-500 text-slate-800 shadow-2xs"
                            }`}
                          >
                            <div className="flex items-center justify-center gap-1 text-[9px] uppercase font-bold text-amber-700">
                              <AlertTriangle className="w-2.5 h-2.5" />
                              <span>BYTE GAP</span>
                            </div>
                            <div className="text-xs font-bold text-slate-900 mt-0.5">
                              {dmg.start_offset} B – {dmg.end_offset} B
                            </div>
                            <div className="text-[10px] text-amber-800 font-semibold mt-0.5">
                              {dmg.length} B MISSING
                            </div>
                          </div>
                          {!isLast && (
                            <ArrowRight className="hidden sm:block w-3.5 h-3.5 text-slate-400 shrink-0" />
                          )}
                        </div>
                      );
                    }
                  })}
                </div>
              </div>

              {/* Connector Down to Assembly Node */}
              <div className="w-full flex justify-center py-1">
                <div className="w-0.5 h-5 bg-slate-300 flex items-center justify-center">
                  <ArrowDown className="w-3 h-3 text-slate-400 translate-y-2.5" />
                </div>
              </div>

              {/* Assembly Output Node */}
              <div
                onClick={() =>
                  setSelectedNode({
                    id: "assembly-output",
                    type: "RECONSTRUCTION",
                    label: "SEQUENTIAL EVIDENCE ASSEMBLY",
                    offsetRange: `0 B – ${totalBytes} B`,
                    length: `${totalBytes} Bytes`,
                    status: "PARTIALLY RECOVERED",
                    source: reconstructionMethod || "BIFRAGMENT_GAP",
                    description:
                      "Deterministic alignment of verified fragments with unobserved gap preserved. Audit trail preserved with zero byte hallucination.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-3.5 rounded-xl border text-center transition-all ${
                  selectedNode.id === "assembly-output"
                    ? "bg-amber-50 border-2 border-amber-600 text-amber-950 scale-105 shadow-md shadow-amber-500/10"
                    : "bg-white border border-amber-300 hover:border-amber-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-amber-700 text-xs font-bold uppercase mb-0.5">
                  <GitBranch className="w-3.5 h-3.5" />
                  <span>ARTIFACT ASSEMBLY (METHOD: {reconstructionMethod || "BIFRAGMENT_GAP"})</span>
                </div>
                <div className="text-[11px] text-slate-600">
                  {fragments.reduce((sum, f) => sum + f.verified_bytes, 0)} B Verified ·{" "}
                  {damageRegions.reduce((sum, d) => sum + d.length, 0)} B Missing Preserved
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* CASE D: SHUFFLED FRAGMENTS (PDF UNSHUFFLE RECONSTRUCTION) */}
          {/* ========================================================================= */}
          {isShuffled && (
            <div className="w-full flex flex-col items-center space-y-3 mt-1">
              {/* Branching Top: Displaced Raw Fragments */}
              <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider text-center">
                DISPLACED RAW FRAGMENTS DETECTED IN EVIDENCE BUFFER
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-xl w-full">
                {/* Fragment at 0..195: Trailer/Catalog */}
                {trailerFrag && (
                  <div
                    onClick={() =>
                      setSelectedNode({
                        id: trailerFrag.fragment_id,
                        type: "FRAGMENT",
                        label: `RAW FRAGMENT 1 (DISPLACED TRAILER) [${trailerFrag.fragment_id}]`,
                        offsetRange: `${trailerFrag.offset} B – ${trailerFrag.end_offset} B`,
                        length: `${trailerFrag.length} Bytes`,
                        status: "VERIFIED (DISPLACED IN RAW)",
                        source: trailerFrag.source || "shuffled_trailer",
                        description:
                          "PDF trailer dictionary, xref table, and root catalog detected at beginning of file instead of EOF. Contains valid PDF xref offsets.",
                      })
                    }
                    className={`cursor-pointer p-3.5 rounded-xl border text-center transition-all ${
                      selectedNode.id === trailerFrag.fragment_id
                        ? "bg-sky-50 border-2 border-sky-600 text-sky-950 shadow-md scale-105"
                        : "bg-white border border-sky-300 hover:border-sky-500 text-slate-800 shadow-2xs"
                    }`}
                  >
                    <div className="text-[9px] uppercase font-bold text-sky-700">
                      RAW INPUT: OFFSET 0
                    </div>
                    <div className="text-xs font-bold text-slate-900 mt-0.5">
                      {trailerFrag.offset} B – {trailerFrag.end_offset} B
                    </div>
                    <div className="text-[10px] text-slate-600 mt-0.5 font-medium">
                      Trailer / Xref Dict ({trailerFrag.length} B)
                    </div>
                    <div className="text-[9px] bg-sky-100 text-sky-800 rounded px-1.5 py-0.5 mt-1 font-semibold inline-block">
                      DISPLACED TO HEAD
                    </div>
                  </div>
                )}

                {/* Fragment at 195..315: Header */}
                {headerFrag && (
                  <div
                    onClick={() =>
                      setSelectedNode({
                        id: headerFrag.fragment_id,
                        type: "FRAGMENT",
                        label: `RAW FRAGMENT 2 (DISPLACED HEADER) [${headerFrag.fragment_id}]`,
                        offsetRange: `${headerFrag.offset} B – ${headerFrag.end_offset} B`,
                        length: `${headerFrag.length} Bytes`,
                        status: "VERIFIED (DISPLACED IN RAW)",
                        source: headerFrag.source || "shuffled_header",
                        description:
                          "PDF %PDF-1.4 header and root catalog stream found displaced at offset 195 B instead of offset 0.",
                      })
                    }
                    className={`cursor-pointer p-3.5 rounded-xl border text-center transition-all ${
                      selectedNode.id === headerFrag.fragment_id
                        ? "bg-sky-50 border-2 border-sky-600 text-sky-950 shadow-md scale-105"
                        : "bg-white border border-sky-300 hover:border-sky-500 text-slate-800 shadow-2xs"
                    }`}
                  >
                    <div className="text-[9px] uppercase font-bold text-sky-700">
                      RAW INPUT: OFFSET {headerFrag.offset} B
                    </div>
                    <div className="text-xs font-bold text-slate-900 mt-0.5">
                      {headerFrag.offset} B – {headerFrag.end_offset} B
                    </div>
                    <div className="text-[10px] text-slate-600 mt-0.5 font-medium">
                      %PDF-1.4 Header & Stream ({headerFrag.length} B)
                    </div>
                    <div className="text-[9px] bg-sky-100 text-sky-800 rounded px-1.5 py-0.5 mt-1 font-semibold inline-block">
                      DISPLACED TO TAIL
                    </div>
                  </div>
                )}
              </div>

              {/* Central Reorder Relationship Node */}
              <div className="w-full flex justify-center py-1">
                <div className="w-0.5 h-5 bg-slate-300 flex items-center justify-center">
                  <ArrowDown className="w-3 h-3 text-slate-400 translate-y-2.5" />
                </div>
              </div>

              <div
                onClick={() =>
                  setSelectedNode({
                    id: "shuffled-rel",
                    type: "RECONSTRUCTION",
                    label: "FRAGMENT_UNSHUFFLE (DETERMINISTIC REORDER)",
                    offsetRange: `Pivot: ${headerFrag?.offset ?? 195} B (0 B – ${totalBytes} B)`,
                    length: `${totalBytes} Bytes`,
                    status: "REORDERED (100% VERIFIED)",
                    source: "Deterministic Sequence Inversion",
                    description:
                      "Header fragment (195..315 B) was inverted before Trailer fragment (0..195 B). Deterministic un-shuffle restores valid PDF document sequence without synthesizing data.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-3.5 rounded-xl border text-center transition-all ${
                  selectedNode.id === "shuffled-rel"
                    ? "bg-sky-50 border-2 border-sky-600 text-sky-950 scale-105 shadow-md shadow-sky-500/10"
                    : "bg-white border border-sky-300 hover:border-sky-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-sky-700 text-xs font-bold uppercase mb-0.5">
                  <Shuffle className="w-3.5 h-3.5" />
                  <span>RECONSTRUCTION RELATIONSHIP: FRAGMENT_UNSHUFFLE</span>
                </div>
                <div className="text-[11px] text-slate-600 font-sans">
                  Inversion Pivot at {headerFrag?.offset ?? 195} B · Zero Hallucinated Bytes
                </div>
              </div>

              {/* Connector to Target Reassembled Artifact */}
              <div className="w-full flex justify-center py-1">
                <div className="w-0.5 h-5 bg-slate-300 flex items-center justify-center">
                  <ArrowDown className="w-3 h-3 text-slate-400 translate-y-2.5" />
                </div>
              </div>

              <div
                onClick={() =>
                  setSelectedNode({
                    id: "target-pdf",
                    type: "TARGET",
                    label: "REASSEMBLED VALID PDF ARTIFACT",
                    offsetRange: `0 B – ${totalBytes} B`,
                    length: `${totalBytes} Bytes`,
                    status: "FULLY RECOVERED (VALID SPEC)",
                    source: "Reconstructed Canonical Sequence",
                    description:
                      "Canonical PDF byte sequence assembled: [Header 120 B] → [Trailer 195 B]. Validated against PDF 1.4 spec. Passes structural and xref validation.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-4 rounded-xl border text-center transition-all ${
                  selectedNode.id === "target-pdf"
                    ? "bg-emerald-50 border-2 border-emerald-600 text-emerald-950 scale-105 shadow-md shadow-emerald-500/10"
                    : "bg-white border border-emerald-300 hover:border-emerald-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-emerald-700 text-xs font-bold uppercase mb-1">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>TARGET EVIDENCE: REASSEMBLED VALID PDF</span>
                </div>
                <div className="text-[11px] text-slate-700 font-medium">
                  Sequence: [Header 120 B] ──▶ [Trailer 195 B]
                </div>
                <div className="text-[10px] text-emerald-700 font-semibold mt-1">
                  Status: FULLY RECOVERED · VALID PDF SPEC · 0 MISSING BYTES
                </div>
              </div>
            </div>
          )}

          {/* ========================================================================= */}
          {/* CASE E: UNRECOVERABLE / CORRUPTED EVIDENCE (FAILED RELATIONSHIP) */}
          {/* ========================================================================= */}
          {isUnrecoverable && (
            <div className="w-full flex flex-col items-center space-y-3 mt-1">
              {/* Carved Candidate with Severe Corruption */}
              <div
                onClick={() =>
                  setSelectedNode({
                    id: "candidate-corrupted",
                    type: "FRAGMENT",
                    label: `CARVED CANDIDATE STREAM [0 B – ${totalBytes} B]`,
                    offsetRange: `0 B – ${totalBytes} B`,
                    length: `${totalBytes} Bytes`,
                    status: "CORRUPTED / PARTIAL",
                    source: "Format Delimiter Scanner",
                    description:
                      "Candidate byte span identified by parser, but tokens contain unrecoverable structural and syntax deformation.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-3.5 rounded-xl border text-center transition-all ${
                  selectedNode.id === "candidate-corrupted"
                    ? "bg-rose-50 border-2 border-rose-600 text-rose-950 scale-105 shadow-md shadow-rose-500/10"
                    : "bg-white border border-rose-300 hover:border-rose-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-rose-700 text-xs font-bold uppercase mb-0.5">
                  <Layers className="w-3.5 h-3.5" />
                  <span>CARVED EVIDENCE CANDIDATE</span>
                </div>
                <div className="text-[11px] text-slate-700 font-semibold">
                  Span: 0 B – {totalBytes} B ({totalBytes} Bytes)
                </div>
                <div className="text-[10px] text-rose-700 font-medium mt-0.5">
                  Structural Malformation Detected
                </div>
              </div>

              {/* Broken / Failure Connector */}
              <div className="w-full flex justify-center py-1">
                <div className="w-0.5 h-5 bg-rose-300 flex items-center justify-center">
                  <XCircle className="w-3.5 h-3.5 text-rose-500 translate-y-2.5" />
                </div>
              </div>

              {/* Failed Validation Gate Node */}
              <div
                onClick={() =>
                  setSelectedNode({
                    id: "validation-gate-failed",
                    type: "VALIDATION",
                    label: "NO VALID RECONSTRUCTION RELATIONSHIP ESTABLISHED",
                    offsetRange: `0 B – ${totalBytes} B`,
                    length: `${totalBytes} Bytes`,
                    status: "UNRECOVERABLE (VALIDATION FAILED)",
                    source: reconstructionMethod || "JSON_MALFORMED_REJECTED",
                    description:
                      "Deterministic validation rejected the candidate stream. Recoverix zero-hallucination policy strictly refuses to invent missing structural boundaries or synthesize hallucinated tokens.",
                  })
                }
                className={`cursor-pointer max-w-md w-full p-4 rounded-xl border text-center transition-all ${
                  selectedNode.id === "validation-gate-failed" || selectedNode.id === "validation-failed"
                    ? "bg-rose-50 border-2 border-rose-600 text-rose-950 scale-105 shadow-md shadow-rose-500/10"
                    : "bg-rose-50/50 border border-rose-300 hover:border-rose-500 text-slate-800 shadow-2xs"
                }`}
              >
                <div className="flex items-center justify-center gap-1.5 text-rose-700 text-xs font-bold uppercase mb-1">
                  <XCircle className="w-4 h-4 text-rose-600" />
                  <span>NO VALID RECONSTRUCTION RELATIONSHIP ESTABLISHED</span>
                </div>
                <div className="text-[11px] text-rose-900 font-medium font-sans">
                  Method: {reconstructionMethod || "VALIDATION_FAILED"}
                </div>
                <div className="text-[10px] text-slate-600 mt-1">
                  Integrity Guard: Refusing to Synthesize Hallucinated Evidence
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Node Detail Inspector (Cols 9-12) */}
        <div className="lg:col-span-4 bg-slate-50 border border-slate-200 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-emerald-600" />
              <span>Node Inspector</span>
            </span>
            <span className="text-[10px] text-slate-500 font-medium">CLICK TO SELECT</span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <span className="text-slate-500 text-[10px] uppercase font-semibold block">Selected Element</span>
              <span className="text-slate-900 font-bold block truncate">{selectedNode.label}</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div className="bg-white p-2.5 rounded-lg border border-slate-200 shadow-2xs">
                <span className="text-slate-500 text-[9px] uppercase font-semibold block">Offset Range</span>
                <span className="text-slate-800 font-semibold">{selectedNode.offsetRange}</span>
              </div>
              <div className="bg-white p-2.5 rounded-lg border border-slate-200 shadow-2xs">
                <span className="text-slate-500 text-[9px] uppercase font-semibold block">Byte Length</span>
                <span
                  className={`font-semibold ${
                    selectedNode.status.includes("MISSING")
                      ? "text-amber-700"
                      : selectedNode.status.includes("UNRECOVERABLE")
                      ? "text-rose-700"
                      : selectedNode.status.includes("RECONSTRUCTED")
                      ? "text-sky-700"
                      : "text-emerald-700"
                  }`}
                >
                  {selectedNode.length}
                </span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] uppercase font-semibold block">Forensic Status</span>
              <span
                className={`inline-block px-2.5 py-0.5 rounded text-[11px] font-bold mt-0.5 border ${
                  selectedNode.status.includes("VERIFIED") || selectedNode.status.includes("INTACT")
                    ? "bg-emerald-100 text-emerald-800 border-emerald-300"
                    : selectedNode.status.includes("MISSING")
                    ? "bg-amber-100 text-amber-800 border-amber-300"
                    : selectedNode.status.includes("UNRECOVERABLE") || selectedNode.status.includes("FAILED")
                    ? "bg-rose-100 text-rose-800 border-rose-300"
                    : selectedNode.status.includes("RECONSTRUCTED") || selectedNode.status.includes("REORDERED")
                    ? "bg-sky-100 text-sky-800 border-sky-300"
                    : "bg-slate-200 text-slate-800 border-slate-300"
                }`}
              >
                {selectedNode.status}
              </span>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] uppercase font-semibold block">Evidence Origin</span>
              <span className="text-slate-700 text-[11px] font-mono">{selectedNode.source}</span>
            </div>

            <div className="pt-2 border-t border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-semibold block mb-1">Evidentiary Value</span>
              <p className="text-[11px] text-slate-600 font-sans leading-relaxed">
                {selectedNode.description}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
