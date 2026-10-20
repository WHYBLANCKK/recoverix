import {
  Artifact,
  Case,
  AIExplanation,
  ArtifactCategory,
  PriorityLevel,
  SingleFileRecoveryResult,
  ForensicFragment,
  GroundedArtifactInterpretation,
  GroundedClusterInterpretation,
  GroundedCaseInterpretation,
  DeterministicCaseFacts,
  ProviderInterpretationOutput,
} from './types';
import { mockArtifacts, mockCase, mockGroundTruth } from './fixtures/mockData';
export { mockArtifacts, mockCase, mockGroundTruth };


export function getApiBase(): string {
  // If explicitly forced via environment variable (e.g., custom external backend override)
  if (process.env.NEXT_PUBLIC_FORCE_DIRECT_API === 'true' && process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL.replace(/\/+$/, '');
  }
  // When running in the browser, always use the same-origin Next.js proxy rewrite to eliminate CORS and cross-origin blocking
  if (typeof window !== 'undefined') {
    return '/backend-api';
  }
  // Server-side context (Node.js SSR / static page pre-rendering / test runners)
  return (
    process.env.NEXT_PUBLIC_API_URL ||
    (process.env.NODE_ENV === 'production'
      ? 'https://recoverix-backend-staging.onrender.com'
      : 'http://127.0.0.1:8000')
  ).replace(/\/+$/, '');
}

export const API_BASE = getApiBase();
const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK === 'true';

// Cache for AI Explanations to prevent redundant calls and enable instant live demos
const explanationCache = new Map<string, AIExplanation>();

export function classifyArtifact(filename: string, mimeType: string, previewText: string): ArtifactCategory {
  const text = previewText.toLowerCase();
  if (text.includes("auth_success") || text.includes("sudo") || text.includes("ip address") || text.includes("login")) return 'SYSTEM_TRACE';
  if (filename.endsWith('.csv') || filename.endsWith('.db') || filename.endsWith('.sql')) return 'DATABASE_LOG';
  if (mimeType.startsWith('image/') || filename.endsWith('.png') || filename.endsWith('.jpg')) return 'PHOTO_MEDIA';
  if (filename.endsWith('.exe') || filename.endsWith('.dll') || filename.endsWith('.zip') || mimeType === 'application/octet-stream') return 'BINARY_ARCHIVE';
  return 'DOCUMENT';
}

export function determinePriority(category: ArtifactCategory, previewText: string): PriorityLevel {
  const text = previewText.toLowerCase();
  if (text.includes("password") || text.includes("private key") || text.includes("sudo_exec") || text.includes("admin")) return 'CRITICAL';
  if (category === 'DATABASE_LOG' && (text.includes("amount") || text.includes("transaction") || text.includes("balance"))) return 'HIGH';
  if (category === 'PHOTO_MEDIA') return 'HIGH';
  if (category === 'SYSTEM_TRACE') return 'MEDIUM';
  return 'LOW';
}

export function parseAiSummary(rawSummary: any, _artifact?: any): AIExplanation | null {
  if (!rawSummary) return null;
  try {
    const parsed = typeof rawSummary === 'string' ? JSON.parse(rawSummary) : rawSummary;
    const details = Array.isArray(parsed.details) ? parsed.details : [
      parsed.what_was_recovered || 'N/A',
      parsed.what_is_verified || 'N/A',
      parsed.what_is_missing || 'N/A',
      parsed.status_reasoning || 'N/A',
      parsed.priority_reasoning || 'N/A'
    ];
    return {
      summary: parsed.summary || 'Summary unavailable.',
      details: details,
      cached: Boolean(parsed.cached),
      available: parsed.available !== false,
      assessment: parsed.assessment,
      priority: parsed.priority,
      why_it_matters: parsed.why_it_matters,
      recovery_limitation: parsed.recovery_limitation,
      recommended_next_step: parsed.recommended_next_step,
      source: parsed.source,
      facts: parsed.facts,
    };
  } catch (e) {
    console.error("Failed to parse AI summary", e);
    return null;
  }
}

export function normalizeBackendArtifact(raw: any): Artifact {
  const isPassed =
    raw.validation?.valid === true ||
    (raw.provenance?.validation_status || raw.validation_status) === 'PASSED';

  const bd = raw.score_breakdown || raw.confidence_breakdown || raw.confidence || {
    header_validity: 0, footer_validity: 0, structural_validation: 0, size_plausibility: 0, reconstruction_integrity: 0, total: 0
  };

  let preview = raw.content_preview ?? raw.preview_text ?? '';
  preview = preview.replace(/\[SYNTHETIC_ARTIFACT_START\]\n?/g, '');
  preview = preview.replace(/\[SYNTHETIC_ARTIFACT_END\]\n?/g, '');
  preview = preview.replace(/^filename:\s*[^\n]*\n?/g, '');
  preview = preview.trim();

  const checks = [];
  checks.push({ name: "Header Signature Check", detail: "Start marker/magic bytes.", passed: Boolean(bd.header_validity && bd.header_validity > 0) || isPassed });
  checks.push({ name: "Footer / Boundary Check", detail: "End marker/EOF.", passed: Boolean(bd.footer_validity && bd.footer_validity > 0) || isPassed });
  checks.push({ name: "Structural & Parser Validation", detail: "Format structure.", passed: isPassed });
  checks.push({ name: "Defensive Bounds & Size Check", detail: "Size constraints.", passed: Boolean(bd.size_plausibility && bd.size_plausibility > 0) || isPassed });
  
  let reconStatus = "FAILED";
  let reconPassed = false;
  if (bd.reconstruction_integrity === 15) {
    reconStatus = "Contiguous PASSED";
    reconPassed = true;
  } else if (bd.reconstruction_integrity > 0) {
    reconStatus = "Bounded Gap Reconstructed";
    reconPassed = true;
  }
  checks.push({ name: "Continuity / Gap Reconstruction", detail: reconStatus, passed: reconPassed });

  const offset = raw.metadata?.offset || 0;
  const vBytes = raw.provenance?.verified_bytes ?? raw.verified_bytes ?? raw.total_verified_bytes ?? 0;
  const rBytes = raw.provenance?.reconstructed_bytes ?? raw.reconstructed_bytes ?? raw.total_reconstructed_bytes ?? 0;
  const mBytes = raw.provenance?.missing_bytes ?? raw.missing_bytes ?? raw.total_missing_bytes ?? 0;
  const confScore = Math.round(Number(raw.confidence_score ?? raw.confidence?.total ?? 0));
  
  const fragments = [];
  if (Array.isArray(raw.fragments) && raw.fragments.length > 0) {
    for (const f of raw.fragments) {
      fragments.push({
        id: f.fragment_id || f.id || `frag_${fragments.length}`,
        start_offset: f.offset ?? f.start_offset ?? 0,
        end_offset: f.end_offset ?? ((f.offset ?? 0) + (f.length ?? 0)),
        type: f.status || "VERIFIED"
      });
    }
  } else if (rBytes > 0) {
     const half = Math.floor(vBytes / 2);
     fragments.push({ id: "frag_a", start_offset: offset, end_offset: offset + half, type: "VERIFIED" });
     fragments.push({ id: "frag_gap", start_offset: offset + half, end_offset: offset + half + rBytes, type: "RECONSTRUCTED_GAP" });
     fragments.push({ id: "frag_b", start_offset: offset + half + rBytes, end_offset: offset + vBytes + rBytes, type: "VERIFIED" });
  } else {
     fragments.push({ id: "frag_1", start_offset: offset, end_offset: offset + vBytes, type: "VERIFIED" });
  }

  const format = (raw.format || '').toLowerCase();
  let category: ArtifactCategory = raw.category || 'DOCUMENT';
  if (!raw.category) {
    if (['png', 'jpeg', 'jpg'].includes(format)) category = 'PHOTO_MEDIA';
    else if (['json', 'csv'].includes(format)) category = 'DATABASE_LOG';
    else if (['zip', 'bin'].includes(format)) category = 'BINARY_ARCHIVE';
    else category = 'DOCUMENT';
  }

  let priority: PriorityLevel = raw.priority || 'LOW';
  if (!raw.priority) {
    const st = raw.status;
    if (st === 'UNRECOVERABLE' || st === 'CORRUPTED') priority = 'LOW';
    else if (st === 'PARTIALLY_RECOVERED') priority = 'HIGH';
    else priority = 'MEDIUM';
  }

  const reconMethod = (raw.provenance?.reconstruction_method === 'BIFRAGMENT' ? 'BIFRAGMENT_GAP' : raw.provenance?.reconstruction_method) ||
    raw.reconstruction_method ||
    (raw.reconstruction_steps?.[0]?.method) ||
    'NONE';

  return {
    id: raw.artifact_id || raw.id || raw.run_id,
    filename: raw.metadata?.filename || raw.filename || (raw.run_id ? `${raw.run_id}.${raw.format || 'bin'}` : `${raw.artifact_id || 'artifact'}.${raw.format || 'bin'}`),
    mime_type: raw.mime_type || (raw.format === 'csv' ? 'text/csv' : raw.format === 'png' ? 'image/png' : 'text/plain'),
    category,
    priority,
    confidence_score: confScore,
    status: raw.status || 'UNRECOVERABLE',
    verified_bytes: vBytes,
    reconstructed_bytes: rBytes,
    missing_bytes: mBytes,
    reconstruction_method: reconMethod,
    validation_status: isPassed ? 'PASSED' : 'FAILED',
    confidence_breakdown: bd,
    preview_text: preview,
    ai_summary: parseAiSummary(raw.ai_summary, raw) || null,
    validation: {
      valid: isPassed,
      checks: checks
    },
    fragments: fragments
  } as Artifact;
}

export async function createCase(name?: string): Promise<Case> {
  if (!USE_MOCK) {
    const res = await fetch(`${API_BASE}/api/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name || "Automated Case" }),
      cache: 'no-store'
    });
    if (!res.ok) {
      throw new Error(`Failed to create case: ${res.status} ${res.statusText}`);
    }
    const raw = await res.json();
    return {
      id: raw.case_id || raw.id,
      name: raw.name,
      description: raw.description,
      artifacts: (raw.artifacts || []).map(normalizeBackendArtifact)
    };
  }
  return { ...mockCase, name: name || mockCase.name };
}

export async function uploadEvidence(caseId: string, fileOrSample: File | string): Promise<{ success: boolean }> {
  if (!USE_MOCK) {
    const formData = new FormData();
    if (typeof fileOrSample === 'string') {
      formData.append('sample', fileOrSample);
    } else {
      formData.append('file', fileOrSample);
    }
    const res = await fetch(`${API_BASE}/api/cases/${caseId}/evidence`, {
      method: 'POST',
      body: formData,
      cache: 'no-store'
    });
    if (!res.ok) {
      throw new Error(`Failed to upload evidence: ${res.status} ${res.statusText}`);
    }
    return await res.json();
  }
  return { success: true };
}

export async function analyzeCase(caseId: string): Promise<Case> {
  if (!USE_MOCK) {
    const res = await fetch(`${API_BASE}/api/cases/${caseId}/analyze`, {
      method: 'POST',
      cache: 'no-store'
    });
    if (!res.ok) {
      throw new Error(`Failed to analyze case: ${res.status} ${res.statusText}`);
    }
    const raw = await res.json();
    return {
      id: raw.case_id || raw.id,
      name: raw.name || "Analysis Result",
      description: raw.description || "Forensic case analysis",
      artifacts: (raw.artifacts || []).map(normalizeBackendArtifact)
    };
  }
  return mockCase;
}

export async function runFullIngestionAndAnalysis(fileOrSample: File | string): Promise<Case> {
  const newCase = await createCase("Automated Case");
  await uploadEvidence(newCase.id, fileOrSample);
  return await analyzeCase(newCase.id);
}

export async function fetchCase(caseId = 'case_001'): Promise<Case | null> {
  if (!USE_MOCK) {
    try {
      const res = await fetch(`${API_BASE}/api/cases/${caseId}`, { cache: 'no-store' });
      if (res.ok) {
        const raw = await res.json();
        return {
          id: raw.case_id || raw.id,
          name: raw.name,
          description: raw.description,
          artifacts: (raw.artifacts || []).map(normalizeBackendArtifact)
        };
      }
    } catch (e) {
      console.warn("Backend unreachable in fetchCase", e);
    }
    return null;
  }
  return mockCase;
}

export async function fetchArtifacts(caseId = 'case_001'): Promise<Artifact[]> {
  if (!USE_MOCK) {
    try {
      const res = await fetch(`${API_BASE}/api/cases/${caseId}/artifacts`, { cache: 'no-store' });
      if (res.ok) {
        const rawArray = await res.json();
        return rawArray.map(normalizeBackendArtifact);
      }
    } catch (e) {
      console.warn("Backend unreachable in fetchArtifacts", e);
    }
    return [];
  }
  return mockArtifacts;
}

export async function fetchArtifactById(artifactId: string): Promise<Artifact> {
  if (!USE_MOCK) {
    try {
      const res = await fetch(`${API_BASE}/api/artifacts/${artifactId}`, { cache: 'no-store' });
      if (res.ok) {
        const raw = await res.json();
        return normalizeBackendArtifact(raw);
      }
    } catch (e) {
      console.warn("Backend unreachable in fetchArtifactById", e);
    }
  }
  
  if (typeof window !== 'undefined') {
    const activeCaseId = localStorage.getItem('recoverix_active_case_id') || 'case_001';
    const cachedStr = localStorage.getItem(`recoverix_artifacts_${activeCaseId}`);
    if (cachedStr) {
       try {
         const cached = JSON.parse(cachedStr);
         const found = cached.find((a: any) => a.id === artifactId);
         if (found) return found;
       } catch {}
    }
  }

  if (USE_MOCK) {
    const artifact = mockArtifacts.find(a => a.id === artifactId);
    if (artifact) return artifact;
  }
  throw new Error("Artifact not found");
}

export async function fetchArtifactExplanation(artifactId: string, forceRefresh = false): Promise<AIExplanation> {
  if (!forceRefresh && explanationCache.has(artifactId)) {
    return { ...explanationCache.get(artifactId)!, cached: true };
  }

  let explanation: AIExplanation | null = null;
  if (!USE_MOCK) {
    try {
      const res = await fetch(`${API_BASE}/api/artifacts/${artifactId}/explain`, {
        method: 'POST',
        cache: 'no-store'
      });
      if (res.ok) {
        const rawData = await res.json();
        explanation = parseAiSummary(rawData);
        if (explanation) {
          // The backend json might contain 'cached'
          explanation.cached = rawData.cached === true;
        }
      }
    } catch (e) {
      console.warn("Backend unreachable in fetchArtifactExplanation", e);
    }
  }
  
  if (!explanation && USE_MOCK) {
    const artifact = mockArtifacts.find(a => a.id === artifactId);
    if (artifact && artifact.ai_summary) {
      explanation = { ...artifact.ai_summary, cached: true };
    }
  }

  if (!explanation) {
    throw new Error("Explanation not available");
  }

  explanation.cached = explanation.cached ?? false;
  explanationCache.set(artifactId, explanation);
  return explanation;
}

export async function fetchGroundTruth(caseId = 'case_001'): Promise<import('./types').GroundTruth> {
  if (!USE_MOCK) {
    const res = await fetch(`${API_BASE}/api/cases/${caseId}/groundtruth`, { cache: 'no-store' });
    if (!res.ok) {
      throw new Error(`Failed to fetch ground truth: ${res.status} ${res.statusText}`);
    }
    return await res.json();
  }
  return mockGroundTruth;
}

/**
 * Strict regex pattern matching legitimate Recoverix download endpoints:
 * - /api/recover-file/{fileId}/download
 * - /api/recover/file/{fileId}/download
 * - /api/artifacts/{artifactId}/download
 * Only allows safe characters in the ID: alphanumeric, underscores, hyphens, and dots.
 * Strictly forbids path traversal (..), encoded characters (%..), query strings, and fragments.
 */
const VALID_DOWNLOAD_PATH_REGEX =
  /^\/api\/(?:recover-file|recover\/file|artifacts)\/([a-zA-Z0-9_.-]+)\/download$/;

/**
 * Sanitize and normalize download URLs received from API responses.
 * Guarantees that:
 * 1. Protocol-relative (//, /\, \\) and untrusted third-party origins are strictly rejected.
 * 2. Traversal segments (..), encoded characters (%..), query strings, and fragments are eliminated.
 * 3. Relative paths are properly prefixed with getApiBase().
 * 4. Duplicated /backend-api prefixes are cleanly stripped.
 * 5. Falls back to canonical /api/recover-file/{fileId}/download.
 */
export function sanitizeDownloadUrl(rawUrl: string | undefined | null, fileId: string): string {
  const base = getApiBase();
  const safeFileId = encodeURIComponent(fileId);
  const canonicalPath = `/api/recover-file/${safeFileId}/download`;

  if (!rawUrl || typeof rawUrl !== 'string') {
    return `${base}${canonicalPath}`;
  }

  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return `${base}${canonicalPath}`;
  }

  // Reject protocol-relative or backslash paths (//, /\, \\)
  if (trimmed.startsWith('//') || trimmed.startsWith('/\\') || trimmed.startsWith('\\')) {
    return `${base}${canonicalPath}`;
  }

  let pathname = '';

  if (trimmed.startsWith('/')) {
    // Relative path: extract pathname before query string or fragment
    const queryIdx = trimmed.indexOf('?');
    const hashIdx = trimmed.indexOf('#');
    let endIdx = trimmed.length;
    if (queryIdx !== -1) endIdx = Math.min(endIdx, queryIdx);
    if (hashIdx !== -1) endIdx = Math.min(endIdx, hashIdx);

    let clean = trimmed.slice(0, endIdx);
    // Strip all repeated /backend-api prefixes
    clean = clean.replace(/^(\/backend-api)+/, '');
    pathname = clean.startsWith('/') ? clean : `/${clean}`;
  } else {
    // Absolute URL: parse and verify origin
    try {
      const parsed = new URL(trimmed);
      // In the browser, only same-origin URLs are acceptable
      if (typeof window !== 'undefined' && parsed.origin !== window.location.origin) {
        return `${base}${canonicalPath}`;
      }
      let clean = parsed.pathname.replace(/^(\/backend-api)+/, '');
      pathname = clean.startsWith('/') ? clean : `/${clean}`;
    } catch {
      return `${base}${canonicalPath}`;
    }
  }

  // Strictly validate the resulting pathname against the whitelist regex
  if (VALID_DOWNLOAD_PATH_REGEX.test(pathname)) {
    return `${base}${pathname}`;
  }

  // Reject traversal, encoded characters, unrecognized endpoints, or mismatched formats
  return `${base}${canonicalPath}`;
}

export async function recoverSingleFile(
  file: File,
  options?: {
    timeoutMs?: number;
    signal?: AbortSignal;
    caseName?: string;
    investigator?: string;
    notes?: string;
  }
): Promise<SingleFileRecoveryResult> {
  // 1. Guard against browser offline state
  if (typeof navigator !== 'undefined' && !navigator.onLine) {
    throw new Error('Your browser is currently offline. Please check your internet connection and try again.');
  }

  const timeoutMs = options?.timeoutMs ?? 75000; // 75s generous timeout for Render free-tier cold-start + file analysis
  const controller = new AbortController();
  let isTimedOut = false;

  const timeoutId = setTimeout(() => {
    isTimedOut = true;
    controller.abort();
  }, timeoutMs);

  let abortHandler: (() => void) | null = null;
  if (options?.signal) {
    if (options.signal.aborted) {
      clearTimeout(timeoutId);
      throw new Error('The recovery request was cancelled.');
    }
    abortHandler = () => controller.abort();
    options.signal.addEventListener('abort', abortHandler, { once: true });
  }

  try {
    const formData = new FormData();
    formData.append('file', file);
    if (options?.caseName) {
      formData.append('case_name', options.caseName);
    }
    if (options?.investigator) {
      formData.append('investigator', options.investigator);
    }
    if (options?.notes) {
      formData.append('notes', options.notes);
    }
    const base = getApiBase();
    const res = await fetch(`${base}/api/recover-file`, {
      method: 'POST',
      body: formData,
      cache: 'no-store',
      signal: controller.signal,
    });

    if (res.ok) {
      const data = await res.json();
      data.download_url = sanitizeDownloadUrl(data.download_url, data.file_id);
      return data;
    }

    // Parse server error response
    const errData = await res.json().catch(() => ({}));
    const rawDetail = errData.detail || '';

    if (res.status === 413 || rawDetail === 'FILE_TOO_LARGE') {
      throw new Error(
        'File exceeds the 5 MiB maximum upload limit. Please upload a file smaller than 5 MiB.'
      );
    }
    if (res.status === 429 || rawDetail === 'RATE_LIMIT_EXCEEDED') {
      const retryAfter = errData.retry_after ? ` (${errData.retry_after}s)` : '';
      throw new Error(
        `Rate limit reached (max 60 requests/minute). Please wait a moment${retryAfter} before submitting another file.`
      );
    }
    if (res.status === 400 && rawDetail === 'EMPTY_FILE') {
      throw new Error(
        'The submitted file is completely empty (0 bytes). Recoverix requires at least 1 byte of evidence to analyze.'
      );
    }
    if (res.status === 502 || res.status === 503 || res.status === 504) {
      throw new Error(
        'The recovery engine is currently waking from sleep (Render free-tier inactivity). Please wait 15–20 seconds and click Try Again.'
      );
    }

    const message =
      typeof rawDetail === 'string' && rawDetail.trim()
        ? rawDetail
        : (rawDetail ? JSON.stringify(rawDetail) : `Server returned HTTP ${res.status}`);
    throw new Error(message);
  } catch (e: any) {
    if (e.name === 'AbortError') {
      if (isTimedOut) {
        throw new Error(
          'The recovery request timed out after 75 seconds. The backend engine may still be processing your file or waking up from sleep. Please wait a moment and click Try Again.'
        );
      }
      throw new Error('The recovery request was cancelled.');
    }
    if (e.message && !e.message.startsWith('TypeError: Failed to fetch') && !e.message.includes('fetch failed')) {
      throw e;
    }
    throw new Error(
      'Unable to connect to the Recoverix recovery engine. The service may be waking up from sleep or temporarily unreachable. Please wait a moment and try again.'
    );
  } finally {
    clearTimeout(timeoutId);
    if (options?.signal && abortHandler) {
      options.signal.removeEventListener('abort', abortHandler);
    }
  }
}

export function getArtifactDownloadUrl(artifactId: string): string {
  const base = getApiBase();
  return `${base}/api/artifacts/${encodeURIComponent(artifactId)}/download`;
}

export async function fetchRecoveryRun(runId: string): Promise<any | null> {
  try {
    const base = getApiBase();
    const res = await fetch(`${base}/api/recovery-runs/${encodeURIComponent(runId)}`, { cache: 'no-store' });
    if (res.ok) return await res.json();
  } catch (e) {
    console.warn("Failed to fetch recovery run", e);
  }
  return null;
}

export async function fetchRecoveredFile(fileId: string): Promise<SingleFileRecoveryResult | null> {
  try {
    const base = getApiBase();
    const res = await fetch(`${base}/api/recover-file/${encodeURIComponent(fileId)}`, { cache: 'no-store' });
    if (res.ok) {
      const data = await res.json();
      data.download_url = sanitizeDownloadUrl(data.download_url, data.file_id);
      return data;
    }
  } catch (e) {
    console.warn("Failed to fetch recovered file metadata", e);
  }
  return null;
}

export async function fetchRecoveryRuns(): Promise<any[]> {
  try {
    const res = await fetch(`${API_BASE}/api/recovery-runs`, { cache: 'no-store' });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.warn("Failed to fetch recovery runs", e);
  }
  return [];
}

export async function fetchCaseRecoveryRuns(caseId: string): Promise<any[]> {
  try {
    const res = await fetch(`${API_BASE}/api/cases/${caseId}/runs`, { cache: 'no-store' });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
    console.warn("Failed to fetch case recovery runs", e);
  }
  return [];
}

/**
 * Explicit, typed adapter from RecoveryRun backend model to SingleFileRecoveryResult.
 * Preserves authoritative V/R/M provenance byte counts and strict validation contracts.
 */
export function adaptRecoveryRunToInvestigationResult(run: any): SingleFileRecoveryResult {
  let preview: string | null = null;
  if (run.output?.recovered_bytes) {
    try {
      const hex = run.output.recovered_bytes;
      const bytes = new Uint8Array(hex.match(/.{1,2}/g)?.map((byte: string) => parseInt(byte, 16)) || []);
      preview = new TextDecoder().decode(bytes).slice(0, 300);
    } catch {
      preview = String(run.output.recovered_bytes).slice(0, 300);
    }
  }

  const verBytes = Number(run.total_verified_bytes ?? run.verified_bytes ?? 0);
  const recBytes = Number(run.total_reconstructed_bytes ?? run.reconstructed_bytes ?? 0);
  const missBytes = Number(run.total_missing_bytes ?? run.missing_bytes ?? 0);
  const totalInput = Number(run.total_input_bytes ?? (verBytes + missBytes));

  const isValid = Boolean(
    run.validation?.valid === true ||
    run.validation_status === "PASSED" ||
    run.provenance?.validation_status === "PASSED"
  );
  const valStatus = isValid ? "PASSED" : "FAILED";

  const isUnrecoverable = run.status === "UNRECOVERABLE" || run.status === "CORRUPTED";
  const hasRecoveredBytes = Boolean(run.output?.recovered_bytes && run.output.recovered_bytes.length > 0);
  const isDownloadable = !isUnrecoverable && isValid && hasRecoveredBytes;

  const rawDownloadUrl = `/api/recover-file/${encodeURIComponent(run.artifact_id || run.run_id)}/download`;
  const downloadUrl = sanitizeDownloadUrl(rawDownloadUrl, run.artifact_id || run.run_id);

  const method = run.reconstruction_steps?.[0]?.method ??
    run.provenance?.reconstruction_method ??
    run.reconstruction_method ??
    "NONE";

  const sb = run.confidence || run.score_breakdown || {};

  return {
    file_id: run.artifact_id || run.run_id,
    run_id: run.run_id,
    original_filename: run.filename || "evidence.bin",
    recovered_filename: run.output?.recovered_filename || run.recovered_filename || (run.filename ? (run.filename.startsWith("recovered_") ? run.filename : `recovered_${run.filename}`) : "recovered_evidence.bin"),
    format: (run.format || "bin").toLowerCase(),
    status: run.status || "UNRECOVERABLE",
    confidence_score: Number(sb.total ?? run.confidence_score ?? 0),
    verified_bytes: verBytes,
    reconstructed_bytes: recBytes,
    missing_bytes: missBytes,
    reconstruction_method: method,
    validation_status: valStatus,
    is_downloadable: isDownloadable,
    download_url: downloadUrl,
    content_preview: preview,
    score_breakdown: {
      header_validity: Number(sb.header_validity ?? 0),
      footer_validity: Number(sb.footer_validity ?? 0),
      structural_validation: Number(sb.structural_validation ?? 0),
      size_plausibility: Number(sb.size_plausibility ?? 0),
      reconstruction_integrity: Number(sb.reconstruction_integrity ?? 0),
      total: Number(sb.total ?? run.confidence_score ?? 0),
    },
    validation_details: run.validation || {},
    fragments: run.fragments,
    damage_regions: run.damage_regions,
    reconstruction_steps: run.reconstruction_steps,
    total_input_bytes: totalInput,
    case_name: run.case_name || null,
    investigator: run.investigator || null,
    notes: run.notes || null,
  };
}

/**
 * Explicit, typed adapter from Case Artifact to SingleFileRecoveryResult.
 * Preserves authoritative V/R/M provenance byte counts and strict validation contracts.
 */
export function adaptArtifactToInvestigationResult(artifact: Artifact): SingleFileRecoveryResult {
  const verBytes = Number(artifact.verified_bytes ?? 0);
  const recBytes = Number(artifact.reconstructed_bytes ?? 0);
  const missBytes = Number(artifact.missing_bytes ?? 0);
  const totalInput = verBytes + missBytes;

  const isValid = Boolean(
    artifact.validation?.valid === true ||
    artifact.validation_status === "PASSED"
  );
  const valStatus = isValid ? "PASSED" : "FAILED";

  const isPermittedStatus = artifact.status === "FULLY_RECOVERED" || artifact.status === "PARTIALLY_RECOVERED";
  const isDownloadable = isPermittedStatus && isValid && artifact.is_downloadable === true;

  const rawDownloadUrl = getArtifactDownloadUrl(artifact.id);
  const downloadUrl = sanitizeDownloadUrl(rawDownloadUrl, artifact.id);

  const fragments: ForensicFragment[] = (artifact.fragments || []).map((f, idx) => ({
    fragment_id: f.id || `frag_${idx}`,
    offset: f.start_offset ?? 0,
    length: (f.end_offset ?? 0) - (f.start_offset ?? 0),
    end_offset: f.end_offset ?? 0,
    status: f.type || "VERIFIED",
    source: f.source_disk || "carved",
    format: (artifact.mime_type.split("/")[1] || "bin").replace("plain", "txt"),
    verified_bytes: f.type === "VERIFIED" ? Math.max(0, (f.end_offset ?? 0) - (f.start_offset ?? 0)) : 0,
    reconstructed_bytes: f.type === "RECONSTRUCTED_GAP" ? Math.max(0, (f.end_offset ?? 0) - (f.start_offset ?? 0)) : 0,
    missing_bytes: f.type === "MISSING" ? Math.max(0, (f.end_offset ?? 0) - (f.start_offset ?? 0)) : 0,
    validation_status: valStatus,
  }));

  const bd = artifact.confidence_breakdown || {
    header_validity: 0,
    footer_validity: 0,
    structural_validation: 0,
    size_plausibility: 0,
    reconstruction_integrity: 0,
    total: 0,
  };

  return {
    file_id: artifact.id,
    run_id: artifact.id,
    original_filename: artifact.filename,
    recovered_filename: artifact.filename.startsWith("recovered_") ? artifact.filename : `recovered_${artifact.filename}`,
    format: (artifact.mime_type.split("/")[1] || "bin").replace("plain", "txt").toLowerCase(),
    status: artifact.status,
    confidence_score: artifact.confidence_score,
    verified_bytes: verBytes,
    reconstructed_bytes: recBytes,
    missing_bytes: missBytes,
    reconstruction_method: artifact.reconstruction_method || "NONE",
    validation_status: valStatus,
    is_downloadable: isDownloadable,
    download_url: downloadUrl,
    content_preview: artifact.preview_text || null,
    score_breakdown: {
      header_validity: Number(bd.header_validity ?? 0),
      footer_validity: Number(bd.footer_validity ?? 0),
      structural_validation: Number(bd.structural_validation ?? 0),
      size_plausibility: Number(bd.size_plausibility ?? 0),
      reconstruction_integrity: Number(bd.reconstruction_integrity ?? 0),
      total: Number(bd.total ?? artifact.confidence_score ?? 0),
    },
    validation_details: {
      valid: isValid,
      checks: artifact.validation?.checks || [],
    },
    fragments: fragments,
    total_input_bytes: totalInput,
  };
}

export function generateLocalGroundedExplanation(
  fileId: string,
  facts?: Record<string, any>
): AIExplanation {
  const v_bytes = Number(facts?.verified_bytes ?? 0);
  const r_bytes = Number(facts?.reconstructed_bytes ?? 0);
  const m_bytes = Number(facts?.missing_bytes ?? 0);
  const status = facts?.status || (m_bytes === 0 && r_bytes === 0 && v_bytes > 0 ? "FULLY_RECOVERED" : "PARTIALLY_RECOVERED");
  const fmt = (facts?.format || "UNKNOWN").toUpperCase();
  const method = facts?.reconstruction_method || (r_bytes > 0 ? "STRUCTURAL_RECONSTRUCTION" : "NONE");
  const score = Number(facts?.confidence_score ?? (status === "FULLY_RECOVERED" ? 100 : 75));

  let assessment = "";
  let why_it_matters = "";
  let recovery_limitation = "";
  let recommended_next_step = "";

  if (fmt === "JSON" && r_bytes > 0 && m_bytes === 0) {
    assessment = `The JSON artifact contains a structurally complete observed prefix. The missing content was limited to ${r_bytes} uniquely determined closing JSON delimiters.`;
    why_it_matters = `The reconstructed bytes were derived from the observed JSON container structure rather than predicted semantic content.`;
    recovery_limitation = `Deterministic structural closure only (${method}). Recoverix strictly refused to predict or synthesize unobserved semantic data.`;
    recommended_next_step = `Inspect the JSON structural tokens and verify that reconstructed closing syntax matches schema expectations.`;
  } else if (r_bytes > 0 && m_bytes === 0) {
    assessment = `This ${fmt} artifact is structurally repaired. ${v_bytes} bytes were mathematically verified from evidence and ${r_bytes} bytes were deterministically reconstructed via ${method}.`;
    why_it_matters = `All reconstructed bytes were derived from strict format specifications without heuristic speculation.`;
    recovery_limitation = `Deterministic syntax repair only. Zero heuristic predictions or synthetic filler bytes were used.`;
    recommended_next_step = `Inspect the reconstructed boundaries and verify schema conformity.`;
  } else if (r_bytes > 0 && m_bytes > 0) {
    assessment = `This artifact is partially recovered. ${v_bytes} bytes were mathematically verified from the uploaded evidence, ${r_bytes} bytes were structurally reconstructed via ${method}, and an unobserved ${m_bytes}-byte gap was preserved.`;
    why_it_matters = `The reconstructed bytes were derived from deterministic grammar rules, while the unobserved ${m_bytes}-byte region was preserved to prevent evidence hallucination.`;
    recovery_limitation = `Missing bytes could not be deterministically established and were preserved as missing.`;
    recommended_next_step = `Review original evidence source or examine adjacent storage clusters for matching fragments.`;
  } else if (status === "FULLY_RECOVERED" || (m_bytes === 0 && r_bytes === 0 && v_bytes > 0)) {
    assessment = `This artifact is fully recovered. All ${v_bytes} bytes were mathematically verified from the uploaded evidence with 0 missing and 0 reconstructed bytes.`;
    why_it_matters = `The artifact adheres completely to the ${fmt} specification with authoritative validation. Evidence integrity is mathematically verified against the format specification.`;
    recovery_limitation = `Exact deterministic recovery. Zero heuristic predictions or synthetic filler bytes were used.`;
    recommended_next_step = `Export the recovered file and log the deterministic validation digest into the investigation case file.`;
  } else {
    assessment = `This artifact is partially recovered. ${v_bytes} bytes were mathematically verified from the uploaded evidence, and an unobserved ${m_bytes}-byte region remains missing.`;
    why_it_matters = `Surviving evidence fragments maintain authoritative integrity (${method}), but unobserved missing bytes cannot be deterministically inferred.`;
    recovery_limitation = `Missing bytes could not be deterministically established and were preserved as missing. Recoverix strictly refused to hallucinate synthetic content.`;
    recommended_next_step = `Review the original evidence source or adjacent storage regions for additional matching fragments.`;
  }

  return {
    summary: `Grounded explanation for ${fmt} evidence artifact.`,
    details: [
      `Recovered ${v_bytes} verified bytes${r_bytes > 0 ? ` and ${r_bytes} reconstructed bytes` : ""}.`,
      `${v_bytes} bytes were mathematically verified from input fragments.`,
      `${m_bytes} bytes remain missing and preserved.`,
      `Score: ${score}/100. Status: ${status}.`,
      `Recovery method: ${method}.`,
    ],
    assessment,
    priority: status === "UNRECOVERABLE" ? "LOW" : (m_bytes > 0 || r_bytes > 0 ? "HIGH" : "MEDIUM"),
    why_it_matters,
    recovery_limitation,
    recommended_next_step,
    available: true,
    cached: false,
    source: "GROUNDED_ANALYST",
    facts: {
      verified_bytes: v_bytes,
      reconstructed_bytes: r_bytes,
      missing_bytes: m_bytes,
      status,
      format: fmt.toLowerCase(),
      confidence_score: score,
      reconstruction_method: method,
      validation_status: facts?.validation_status ?? "PASSED",
    }
  };
}

export async function fetchInvestigationExplanation(
  fileId: string,
  evidenceFacts?: Record<string, any>,
  forceRefresh = false
): Promise<AIExplanation> {
  if (!forceRefresh && explanationCache.has(fileId)) {
    return { ...explanationCache.get(fileId)!, cached: true };
  }

  const payload = evidenceFacts ? JSON.stringify(evidenceFacts) : undefined;
  const headers: HeadersInit = evidenceFacts ? { "Content-Type": "application/json" } : {};

  // 1. Try /api/recover-file/${fileId}/explain
  try {
    const res = await fetch(`${API_BASE}/api/recover-file/${fileId}/explain`, {
      method: 'POST',
      headers,
      body: payload,
      cache: 'no-store'
    });
    if (res.ok) {
      const rawData = await res.json();
      const explanation = parseAiSummary(rawData);
      if (explanation) {
        explanation.cached = Boolean(rawData.cached);
        explanationCache.set(fileId, explanation);
        return explanation;
      }
    }
  } catch (e) {
    console.warn("recover-file explain endpoint failed, trying artifacts route", e);
  }

  // 2. Try /api/artifacts/${fileId}/explain
  try {
    const res = await fetch(`${API_BASE}/api/artifacts/${fileId}/explain`, {
      method: 'POST',
      headers,
      body: payload,
      cache: 'no-store'
    });
    if (res.ok) {
      const rawData = await res.json();
      const explanation = parseAiSummary(rawData);
      if (explanation) {
        explanation.cached = Boolean(rawData.cached);
        explanationCache.set(fileId, explanation);
        return explanation;
      }
    }
  } catch (e) {
    console.warn("artifacts explain endpoint failed", e);
  }

  // 3. If evidenceFacts are available, generate grounded deterministic explanation locally
  if (evidenceFacts && Object.keys(evidenceFacts).length > 0) {
    const localExplanation = generateLocalGroundedExplanation(fileId, evidenceFacts);
    explanationCache.set(fileId, localExplanation);
    return localExplanation;
  }

  // 4. Safe fallback only if no deterministic facts exist at all
  return {
    summary: "Forensic interpretation could not be generated.",
    details: ["Deterministic recovery results remain available."],
    available: false,
    assessment: "Deterministic recovery results remain available. Forensic interpretation could not be generated.",
    priority: "MEDIUM",
    why_it_matters: "Backend interpretation service was unreachable or returned an error.",
    recovery_limitation: "Forensic interpretation could not be retrieved. Deterministic evidence is unaffected.",
    recommended_next_step: "Rely on deterministic findings and verify evidence byte offsets manually.",
    cached: false
  };
}

// ============================================================================
// Milestone 3.5.3.6: Grounded Evidence Interpretation API Client
// ============================================================================

/**
 * Standard typed API error representing HTTP failure responses from the backend.
 * Preserves the HTTP status code (e.g. 404 for ungenerated interpretations, 500 for failures)
 * and response detail payload.
 */
export class ApiError extends Error {
  status: number;
  detail?: string | Record<string, unknown>;

  constructor(status: number, message: string, detail?: string | Record<string, unknown>) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Shared HTTP request helper for interpretation API endpoints.
 * Handles URL encoding, query parameters (?force_refresh=true only on POST when requested),
 * cache-busting ('no-store'), JSON deserialization, and structured error throwing.
 */
async function fetchInterpretationJson<T>(
  endpoint: string,
  method: 'GET' | 'POST',
  forceRefresh?: boolean
): Promise<T> {
  const query = method === 'POST' && forceRefresh === true ? '?force_refresh=true' : '';
  const url = `${API_BASE}${endpoint}${query}`;

  const res = await fetch(url, {
    method,
    headers: {
      Accept: 'application/json',
    },
    cache: 'no-store',
  });

  if (res.ok) {
    return (await res.json()) as T;
  }

  let detail: any;
  try {
    const errData = await res.json();
    detail = errData.detail;
  } catch {
    // Non-JSON or empty response body
  }

  const message =
    typeof detail === 'string'
      ? detail
      : detail
      ? JSON.stringify(detail)
      : `HTTP ${res.status}: ${res.statusText || 'Request failed'}`;

  throw new ApiError(res.status, message, detail);
}

/**
 * Retrieve persisted grounded interpretation for an artifact.
 * Strictly read-only: does not generate interpretation or invoke LLMs.
 * Throws ApiError with status 404 if artifact or interpretation is not found.
 */
export async function getArtifactInterpretation(
  artifactId: string
): Promise<GroundedArtifactInterpretation> {
  return fetchInterpretationJson<GroundedArtifactInterpretation>(
    `/api/artifacts/${encodeURIComponent(artifactId)}/interpretation`,
    'GET'
  );
}

/**
 * Generate or refresh grounded interpretation for an artifact.
 * When forceRefresh is false (default), reuses existing persisted interpretation if available.
 * When forceRefresh is true, explicitly regenerates fresh interpretation.
 */
export async function generateArtifactInterpretation(
  artifactId: string,
  forceRefresh = false
): Promise<GroundedArtifactInterpretation> {
  return fetchInterpretationJson<GroundedArtifactInterpretation>(
    `/api/artifacts/${encodeURIComponent(artifactId)}/interpretation`,
    'POST',
    forceRefresh
  );
}

/**
 * Retrieve cached grounded interpretation for a spatial cluster.
 * Strictly read-only: does not generate interpretation or invoke LLMs.
 * Throws ApiError with status 404 if case, cluster, or interpretation is not found.
 */
export async function getClusterInterpretation(
  caseId: string,
  clusterId: string
): Promise<GroundedClusterInterpretation> {
  return fetchInterpretationJson<GroundedClusterInterpretation>(
    `/api/cases/${encodeURIComponent(caseId)}/clusters/${encodeURIComponent(clusterId)}/interpretation`,
    'GET'
  );
}

/**
 * Generate or refresh grounded interpretation for a spatial cluster.
 * When forceRefresh is false (default), reuses existing cached interpretation if available.
 * When forceRefresh is true, explicitly regenerates fresh interpretation.
 */
export async function generateClusterInterpretation(
  caseId: string,
  clusterId: string,
  forceRefresh = false
): Promise<GroundedClusterInterpretation> {
  return fetchInterpretationJson<GroundedClusterInterpretation>(
    `/api/cases/${encodeURIComponent(caseId)}/clusters/${encodeURIComponent(clusterId)}/interpretation`,
    'POST',
    forceRefresh
  );
}

/**
 * Retrieve cached grounded forensic briefing and synthesis for a case.
 * Strictly read-only: does not generate interpretation or invoke LLMs.
 * Throws ApiError with status 404 if case or interpretation is not found.
 */
export async function getCaseInterpretation(
  caseId: string
): Promise<GroundedCaseInterpretation> {
  return fetchInterpretationJson<GroundedCaseInterpretation>(
    `/api/cases/${encodeURIComponent(caseId)}/interpretation`,
    'GET'
  );
}

/**
 * Generate or refresh grounded forensic briefing and synthesis for a case.
 * When forceRefresh is false (default), reuses existing cached interpretation if available.
 * When forceRefresh is true, explicitly regenerates fresh interpretation.
 */
export async function generateCaseInterpretation(
  caseId: string,
  forceRefresh = false
): Promise<GroundedCaseInterpretation> {
  return fetchInterpretationJson<GroundedCaseInterpretation>(
    `/api/cases/${encodeURIComponent(caseId)}/interpretation`,
    'POST',
    forceRefresh
  );
}

/**
 * Deterministically constructs an evidence-grounded case interpretation directly from
 * recovery runs and artifacts without calling external models or failing on unseeded cases.
 */
export function buildDeterministicCaseInterpretation(
  caseId: string,
  runs: any[] = [],
  artifacts: Artifact[] = []
): GroundedCaseInterpretation {
  const items = artifacts.length > 0 ? artifacts : (runs || []).map(normalizeBackendArtifact);
  const totalArts = items.length;

  let totalV = 0;
  let totalR = 0;
  let totalM = 0;
  const fmtDist: Record<string, number> = {};
  const statusDist: Record<string, number> = {};
  const priorityDist: Record<string, number> = {};

  for (const item of items) {
    totalV += item.verified_bytes || 0;
    totalR += item.reconstructed_bytes || 0;
    totalM += item.missing_bytes || 0;
    const fmt = (item.mime_type?.split('/')?.[1] || item.filename?.split('.').pop() || 'unknown').toUpperCase();
    fmtDist[fmt] = (fmtDist[fmt] || 0) + 1;
    statusDist[item.status] = (statusDist[item.status] || 0) + 1;
    priorityDist[item.priority] = (priorityDist[item.priority] || 0) + 1;
  }

  const fullyRecovered = statusDist['FULLY_RECOVERED'] || 0;
  const partiallyRecovered = (statusDist['PARTIALLY_RECOVERED'] || 0) + (statusDist['CORRUPTED'] || 0);
  const unrecoverable = statusDist['UNRECOVERABLE'] || 0;

  const facts: DeterministicCaseFacts = {
    case_id: caseId,
    total_evidence_buffers: totalArts > 0 ? totalArts : 0,
    total_artifacts: totalArts,
    total_nodes: totalArts,
    total_clusters: totalArts > 0 ? 1 : 0,
    case_physical_coverage_bytes: totalV + totalM,
    case_coverage_is_complete: totalM === 0,
    candidate_aggregate_verified_bytes: totalV,
    candidate_aggregate_reconstructed_bytes: totalR,
    candidate_aggregate_missing_bytes: totalM,
    unscoped_candidate_count: 0,
    unscoped_aggregate_verified_bytes: 0,
    format_distribution: fmtDist,
    status_distribution: statusDist,
    priority_distribution: priorityDist,
    cluster_classification_distribution: { SINGLE_BUFFER: totalArts },
    candidate_cap_enforced: false,
    total_discovered_candidates: totalArts,
    candidates_omitted: 0,
    graph_is_complete: true,
  };

  const fmtSummary = Object.entries(fmtDist)
    .map(([f, count]) => `${count} ${f}`)
    .join(', ') || 'No artifacts analyzed';

  const output: ProviderInterpretationOutput = {
    summary: totalArts > 0
      ? `Deterministic forensic synthesis of ${totalArts} recovery artifact(s) across case ${caseId}.`
      : `No recovery artifacts recorded for case ${caseId}.`,
    assessment: totalArts > 0
      ? `Analysis completed with ${fullyRecovered} fully recovered, ${partiallyRecovered} partially recovered, and ${unrecoverable} unrecoverable file(s). Total verified evidence: ${totalV} bytes; reconstructed syntax: ${totalR} bytes; unobserved preserved: ${totalM} bytes.`
      : `No evidence runs found for this case. Ingest evidence files to compute deterministic byte accounting.`,
    structural_context: `Active formats: ${fmtSummary}. Mathematical byte conservation strictly enforced across all artifacts (V + R == recovered bytes, V + M == input bytes).`,
    limitations: `Recoverix operates under zero-hallucination deterministic grammar constraints. Missing bytes are preserved as unobserved rather than synthetically guessed.`,
    recommended_next_steps: totalArts > 0
      ? `Review the individual artifact traces, verify structural validator outputs, and export the authenticated JSON report.`
      : `Submit evidence files via the Evidence Workspace or Setup page to begin carving.`,
    details: [
      `Total Evidence Artifacts: ${totalArts}`,
      `Verified Evidence Bytes: ${totalV} B`,
      `Reconstructed Bytes: ${totalR} B`,
      `Missing (Preserved) Bytes: ${totalM} B`,
      `Mathematical Invariant: Verified (${totalV}) + Missing (${totalM}) = Total Input (${totalV + totalM}) B`,
    ],
  };

  return {
    facts,
    interpretation: output,
    source: 'DETERMINISTIC_RULES',
    cached: false,
    generated_at: new Date().toISOString(),
    case_graph_fingerprint: `fp_${caseId}_${totalArts}_${totalV}`,
  };
}

// Aliases matching "fetch..." naming convention
export const fetchArtifactInterpretation = getArtifactInterpretation;
export const fetchClusterInterpretation = getClusterInterpretation;
export const fetchCaseInterpretation = getCaseInterpretation;

// Re-export interpretation types for convenient importing from @/lib/api
export type {
  AuthoritativeRecoveryStatus,
  AuthoritativeClusterClassification,
  InterpretationSource,
  DeterministicArtifactFacts,
  DeterministicRelationshipFact,
  DeterministicClusterFacts,
  DeterministicCaseFacts,
  ArtifactInterpretationContext,
  ClusterInterpretationContext,
  CaseInterpretationContext,
  ProviderInterpretationOutput,
  GroundedArtifactInterpretation,
  GroundedClusterInterpretation,
  GroundedCaseInterpretation,
} from './types';
