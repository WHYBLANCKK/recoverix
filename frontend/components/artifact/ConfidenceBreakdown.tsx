import { Artifact } from "@/lib/types";
import { StatusBadge } from "@/components/dashboard/PriorityBadge";
import { AlertTriangle } from "lucide-react";

export function ConfidenceBreakdown({ artifact }: { artifact: Artifact }) {
  const bd = artifact.confidence_breakdown;
  const metrics = [
    { label: "Header Validity", value: bd.header_validity, max: 20 },
    { label: "Footer / End Marker", value: bd.footer_validity, max: 20 },
    { label: "Structural Validation", value: bd.structural_validation, max: 30 },
    { label: "Size Plausibility", value: bd.size_plausibility, max: 15 },
    { label: "Reconstruction Integrity", value: bd.reconstruction_integrity, max: 15 },
  ];

  return (
    <div className="bg-white border border-slate-200/90 rounded-xl p-6 font-mono shadow-xs">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-xl font-bold text-slate-900">Deterministic Confidence</h2>
          <p className="text-sm text-slate-500 mt-1">
            Overall Score: <span className="text-emerald-600 font-bold text-lg">{artifact.confidence_score}/100</span>
          </p>
        </div>
        <StatusBadge status={artifact.status} />
      </div>

      <div className="space-y-4 mb-6">
        {metrics.map((m, idx) => {
          const pct = (m.value / m.max) * 100;
          return (
            <div key={idx}>
              <div className="flex justify-between text-xs mb-1 text-slate-700 font-medium">
                <span>{m.label}</span>
                <span className="text-slate-500">{m.value} / {m.max} pts</span>
              </div>
              <div className="w-full h-2 bg-slate-100 border border-slate-200 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full ${pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-slate-500' : 'bg-amber-500'}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-slate-50 p-4 rounded-lg border border-slate-200 text-xs text-slate-600 flex flex-wrap gap-x-4 gap-y-2 mb-2">
        <span className="font-semibold text-slate-800">85-100: FULLY_RECOVERED</span>
        <span className="font-semibold text-slate-800">50-84: PARTIALLY_RECOVERED</span>
        <span className="font-semibold text-slate-800">20-49: CORRUPTED</span>
        <span className="font-semibold text-slate-800">0-19: UNRECOVERABLE</span>
      </div>
      <p className="text-[11px] text-slate-400 italic mb-4">
        Note: These status thresholds (85–100, 50–84, 20–49, 0–19) are our prototype policy, not an established forensic standard.
      </p>

      {artifact.reconstructed_bytes > 0 && (
        <div className="bg-amber-50 border border-amber-300 text-amber-800 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-amber-600" />
          <p className="text-xs leading-relaxed">
            <span className="font-bold block mb-1 uppercase tracking-wider text-amber-900">Forensic Invariant Enforced</span>
            Because reconstructed_bytes &gt; 0, status is capped at PARTIALLY_RECOVERED and cannot be FULLY_RECOVERED.
          </p>
        </div>
      )}
    </div>
  );
}
