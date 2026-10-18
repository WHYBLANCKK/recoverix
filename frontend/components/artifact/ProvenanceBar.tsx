import { Artifact } from "@/lib/types";
import { ShieldCheck, Server, AlertOctagon } from "lucide-react";

export function ProvenanceBar({ artifact }: { artifact: Artifact }) {
  const totalExpected = artifact.verified_bytes + artifact.reconstructed_bytes + artifact.missing_bytes;
  
  const getPct = (val: number) => {
    if (totalExpected === 0) return 0;
    return (val / totalExpected) * 100;
  };

  const vPct = getPct(artifact.verified_bytes);
  const rPct = getPct(artifact.reconstructed_bytes);
  const mPct = getPct(artifact.missing_bytes);

  return (
    <div className="bg-white border border-slate-200/90 rounded-xl p-6 font-mono shadow-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-6 gap-4">
        <h2 className="text-xl font-bold text-slate-900">Forensic Byte Allocation (V/R/M)</h2>
        <div className="flex gap-2">
          <span className="px-2.5 py-1 bg-slate-100 border border-slate-200 rounded-lg text-xs font-mono text-slate-700 font-semibold">
            {artifact.reconstruction_method}
          </span>
          <span className={`px-2.5 py-1 rounded-lg text-xs font-semibold border ${artifact.validation.valid ? 'bg-emerald-50 text-emerald-800 border-emerald-300' : 'bg-rose-50 text-rose-800 border-rose-300'}`}>
            {artifact.validation.valid ? 'VALIDATION PASSED' : 'VALIDATION FAILED'}
          </span>
        </div>
      </div>

      <div className="w-full h-4 rounded-full overflow-hidden flex mb-6 bg-slate-100 border border-slate-300 shadow-inner">
        <div style={{ width: `${vPct}%` }} className="h-full bg-emerald-500" title={`Verified: ${vPct.toFixed(1)}%`} />
        <div style={{ width: `${rPct}%` }} className="h-full bg-sky-500" title={`Reconstructed: ${rPct.toFixed(1)}%`} />
        <div style={{ width: `${mPct}%` }} className="h-full bg-amber-500" title={`Missing: ${mPct.toFixed(1)}%`} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-white p-4 rounded-xl border border-emerald-300 shadow-2xs">
          <div className="flex items-center gap-2 mb-2">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            <span className="text-xs uppercase font-bold text-emerald-700">[VERIFIED BYTES]</span>
          </div>
          <p className="text-2xl font-bold text-emerald-600 font-mono">{artifact.verified_bytes.toLocaleString()} B</p>
          <p className="text-xs text-slate-500 mt-1">{vPct.toFixed(1)}% of total</p>
        </div>
        <div className="bg-white p-4 rounded-xl border border-sky-300 shadow-2xs">
          <div className="flex items-center gap-2 mb-2">
            <Server className="w-4 h-4 text-sky-600" />
            <span className="text-xs uppercase font-bold text-sky-700">[RECONSTRUCTED]</span>
          </div>
          <p className="text-2xl font-bold text-sky-600 font-mono">{artifact.reconstructed_bytes.toLocaleString()} B</p>
          <p className="text-xs text-slate-500 mt-1">{rPct.toFixed(1)}% of total</p>
        </div>
        <div className="bg-white p-4 rounded-xl border border-amber-300 shadow-2xs">
          <div className="flex items-center gap-2 mb-2">
            <AlertOctagon className="w-4 h-4 text-amber-600" />
            <span className="text-xs uppercase font-bold text-amber-700">[MISSING BYTES]</span>
          </div>
          <p className="text-2xl font-bold text-amber-600 font-mono">{artifact.missing_bytes.toLocaleString()} B</p>
          <p className="text-xs text-slate-500 mt-1">{mPct.toFixed(1)}% of total</p>
        </div>
      </div>

      <div className="mb-6">
        <h3 className="text-sm font-semibold text-slate-900 mb-3">Fragment Provenance Map</h3>
        <div className="overflow-x-auto border border-slate-200 rounded-lg">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 text-xs uppercase font-semibold">
              <tr>
                <th className="px-4 py-2 font-medium">Fragment ID</th>
                <th className="px-4 py-2 font-medium">Offset Range</th>
                <th className="px-4 py-2 font-medium">Length</th>
                <th className="px-4 py-2 font-medium">Classification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700 text-xs">
              {artifact.fragments.map(f => {
                const len = f.end_offset - f.start_offset;
                return (
                  <tr key={f.id} className="hover:bg-slate-50 transition-colors">
                    <td className="px-4 py-2 font-mono text-slate-900 font-semibold">{f.id}</td>
                    <td className="px-4 py-2 font-mono">{f.start_offset} - {f.end_offset}</td>
                    <td className="px-4 py-2 font-mono">{len} bytes</td>
                    <td className="px-4 py-2">
                      <span className={`text-xs px-2 py-0.5 rounded font-semibold border ${
                        f.type === 'VERIFIED' ? 'bg-emerald-50 text-emerald-800 border-emerald-300' :
                        f.type === 'RECONSTRUCTED_GAP' ? 'bg-sky-50 text-sky-800 border-sky-300' :
                        'bg-amber-50 text-amber-800 border-amber-300'
                      }`}>
                        {f.type}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-slate-50 border border-slate-200 text-slate-600 rounded-lg p-3.5 text-xs text-center">
        <span className="font-semibold text-slate-900">Zero Synthetic Byte Fabrication:</span> Missing evidence bytes are never guessed, infilled, or fabricated.
      </div>
    </div>
  );
}
