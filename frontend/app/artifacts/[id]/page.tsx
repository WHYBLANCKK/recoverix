"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import { fetchArtifactById, fetchArtifacts, getArtifactDownloadUrl } from "@/lib/api";
import { ArrowLeft, FileText, File, Loader2, Download } from "lucide-react";
import { PriorityBadge, StatusBadge } from "@/components/dashboard/PriorityBadge";
import { ConfidenceBreakdown } from "@/components/artifact/ConfidenceBreakdown";
import { ProvenanceBar } from "@/components/artifact/ProvenanceBar";
import { ValidationResults } from "@/components/artifact/ValidationResults";
import { ForensicEvidenceBrief } from "@/components/artifact/ForensicEvidenceBrief";
import { Artifact } from "@/lib/types";

export default function ArtifactPage({ params }: { params: Promise<{ id: string }> }) {
  const resolvedParams = use(params);
  const artifactId = resolvedParams.id;
  const [data, setData] = useState<{ artifact: Artifact; relatedArtifacts: Artifact[] } | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    async function loadData() {
      try {
        const artifact = await fetchArtifactById(artifactId);
        
        const localCaseId = typeof window !== 'undefined' ? localStorage.getItem('recoverix_active_case_id') : null;
        const activeCaseId = localCaseId || 'case_001';
        
        const allArtifacts = await fetchArtifacts(activeCaseId);
        const relatedArtifacts = allArtifacts.filter(a => a.id !== artifact.id).slice(0, 3);
        
        setData({ artifact, relatedArtifacts });
      } catch (err) {
        console.error(err);
        setError(true);
      }
    }
    loadData();
  }, [artifactId]);

  if (error) {
    return (
      <main className="min-h-screen bg-[#F8FAFC] flex flex-col items-center justify-center text-slate-800 font-mono">
        <h2 className="text-xl font-bold mb-4 text-slate-900">ARTIFACT NOT FOUND</h2>
        <Link href="/dashboard" className="text-xs text-emerald-700 hover:underline font-semibold">Return to Case Dashboard</Link>
      </main>
    );
  }

  if (!data) {
    return (
      <main className="min-h-screen bg-[#F8FAFC] flex items-center justify-center">
        <Loader2 className="w-10 h-10 text-emerald-600 animate-spin" />
      </main>
    );
  }

  const { artifact, relatedArtifacts } = data;

  return (
    <main className="min-h-screen bg-[#F8FAFC] text-slate-900 py-8 px-6 selection:bg-emerald-500/20 selection:text-emerald-950 font-mono">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Top Navigation & Header */}
        <div>
          <Link href="/dashboard" className="inline-flex items-center text-xs text-slate-600 hover:text-slate-900 mb-6 transition-colors font-medium">
            <ArrowLeft className="w-4 h-4 mr-2" /> Back to Dashboard
          </Link>

          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div>
              <div className="flex items-center gap-3 mb-3">
                <FileText className="w-8 h-8 text-emerald-600" />
                <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900">
                  {artifact.filename}
                </h1>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-xs">
                <span className="bg-slate-100 px-2.5 py-1 rounded border border-slate-200 text-slate-700 font-semibold">
                  {artifact.mime_type}
                </span>
                <span className="bg-slate-100 px-2.5 py-1 rounded border border-slate-200 text-slate-700 font-semibold">
                  {artifact.category}
                </span>
                <PriorityBadge priority={artifact.priority} />
                <StatusBadge status={artifact.status} />
              </div>
            </div>

            <a
              href={getArtifactDownloadUrl(artifact.id)}
              download
              className="bg-emerald-500 hover:bg-emerald-600 text-white font-bold text-xs px-5 py-2.5 rounded-xl shadow-xs transition-all inline-flex items-center gap-2 self-start md:self-auto"
            >
              <Download className="w-4 h-4" /> DOWNLOAD RECOVERED FILE
            </a>
          </div>
        </div>

        {/* Layout Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
          <div className="space-y-8">
            <ProvenanceBar artifact={artifact} />
            <ConfidenceBreakdown artifact={artifact} />
            <ValidationResults artifact={artifact} />
          </div>
          <div className="space-y-8">
            {/* Forensic Interpretation */}
            <ForensicEvidenceBrief artifact={artifact} />
            
            {/* Recovered Byte Preview */}
            <div className="bg-white border border-slate-200/90 rounded-xl p-6 shadow-xs">
              <h2 className="text-xl font-bold text-slate-900 mb-4">Recovered Byte Preview</h2>
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 overflow-x-auto shadow-inner">
                <pre className="text-xs text-slate-100 whitespace-pre-wrap break-all leading-relaxed font-mono">
                  {artifact.preview_text}
                </pre>
              </div>
            </div>
          </div>
        </div>

        {/* Related Evidence */}
        {relatedArtifacts.length > 0 && (
          <div className="pt-8 border-t border-slate-200">
            <h2 className="text-base font-bold text-slate-900 mb-4 uppercase tracking-wider">Related Evidence in Case</h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {relatedArtifacts.map(related => (
                <Link key={related.id} href={`/artifacts/${related.id}`} className="block">
                  <div className="bg-white border border-slate-200 hover:border-emerald-500 rounded-xl p-4 transition-colors shadow-2xs">
                    <div className="flex items-center gap-2 mb-2">
                      <File className="w-4 h-4 text-slate-400" />
                      <span className="font-bold text-slate-900 truncate text-xs font-mono">{related.filename}</span>
                    </div>
                    <div className="flex gap-2">
                      <StatusBadge status={related.status} />
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        )}

      </div>
    </main>
  );
}
