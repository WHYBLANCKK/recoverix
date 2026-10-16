import {
  Artifact,
  Case,
  AIExplanation,
  ArtifactCategory,
  PriorityLevel,
  SingleFileRecoveryResult,
  GroundedArtifactInterpretation,
  GroundedClusterInterpretation,
  GroundedCaseInterpretation,
} from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
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
  const isPassed = (raw.provenance?.validation_status || raw.validation_status) === 'PASSED';
  const bd = raw.score_breakdown || raw.confidence_breakdown || {
    header_validity: 0, footer_validity: 0, structural_validation: 0, size_plausibility: 0, reconstruction_integrity: 0, total: 0
  };

  let preview = raw.content_preview ?? raw.preview_text ?? '';
  preview = preview.replace(/\[SYNTHETIC_ARTIFACT_START\]\n?/g, '');
  preview = preview.replace(/\[SYNTHETIC_ARTIFACT_END\]\n?/g, '');
  preview = preview.replace(/^filename:\s*[^\n]*\n?/g, '');
  preview = preview.trim();

  const checks = [];
  checks.push({ name: "Header Signature Check", detail: "Start marker/magic bytes.", passed: bd.header_validity > 0 });
  checks.push({ name: "Footer / Boundary Check", detail: "End marker/EOF.", passed: bd.footer_validity > 0 });
  checks.push({ name: "Structural & Parser Validation", detail: "Format structure.", passed: bd.structural_validation > 0 });
  checks.push({ name: "Defensive Bounds & Size Check", detail: "Size constraints.", passed: bd.size_plausibility > 0 });
  
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
  const vBytes = raw.provenance?.verified_bytes ?? raw.verified_bytes ?? 0;
  const rBytes = raw.provenance?.reconstructed_bytes ?? raw.reconstructed_bytes ?? 0;
  
  const fragments = [];
  if (rBytes > 0) {
     const half = Math.floor(vBytes / 2);
     fragments.push({ id: "frag_a", start_offset: offset, end_offset: offset + half, type: "VERIFIED" });
     fragments.push({ id: "frag_gap", start_offset: offset + half, end_offset: offset + half + rBytes, type: "RECONSTRUCTED_GAP" });
     fragments.push({ id: "frag_b", start_offset: offset + half + rBytes, end_offset: offset + vBytes + rBytes, type: "VERIFIED" });
  } else {
     fragments.push({ id: "frag_1", start_offset: offset, end_offset: offset + vBytes, type: "VERIFIED" });
  }

  return {
    id: raw.artifact_id || raw.id,
    filename: raw.metadata?.filename || raw.filename || `${raw.artifact_id || 'artifact'}.${raw.format || 'bin'}`,
    mime_type: raw.mime_type || (raw.format === 'csv' ? 'text/csv' : raw.format === 'png' ? 'image/png' : 'text/plain'),
    category: raw.category || 'DOCUMENT',
    priority: raw.priority || 'LOW',
    confidence_score: raw.confidence_score ?? 0,
    status: raw.status || 'UNRECOVERABLE',
    verified_bytes: vBytes,
    reconstructed_bytes: rBytes,
    missing_bytes: raw.provenance?.missing_bytes ?? raw.missing_bytes ?? 0,
    reconstruction_method: (raw.provenance?.reconstruction_method === 'BIFRAGMENT' ? 'BIFRAGMENT_GAP' : raw.provenance?.reconstruction_method) || raw.reconstruction_method || 'NONE',
    validation_status: raw.provenance?.validation_status || raw.validation_status || 'PASSED',
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

export const mockArtifacts: Artifact[] = [
  {
    // Scenario 4: Bifragment gap ledger.csv
    id: "artifact_001",
    filename: "ledger.csv",
    mime_type: "text/csv",
    category: "DATABASE_LOG",
    priority: "HIGH",
    confidence_score: 78,
    confidence_breakdown: {
      header_validity: 20,
      footer_validity: 0,
      structural_validation: 28,
      size_plausibility: 15,
      reconstruction_integrity: 15,
      total: 78
    },
    status: "PARTIALLY_RECOVERED",
    verified_bytes: 8400,
    reconstructed_bytes: 1200,
    missing_bytes: 400,
    reconstruction_method: "BIFRAGMENT_GAP",
    validation: {
      valid: true,
      checks: [
        { name: "Header Signature", detail: "Valid CSV header found.", passed: true },
        { name: "Row Integrity", detail: "Some rows span gap boundaries, partially recovered.", passed: true }
      ]
    },
    fragments: [
      { id: "frag_1", start_offset: 0, end_offset: 8400, type: "VERIFIED" },
      { id: "frag_2", start_offset: 8400, end_offset: 9600, type: "RECONSTRUCTED_GAP" }
    ],
    preview_text: "id,amount,date,status\n1,500.00,2026-09-21,COMPLETED\n2,250.00,2026-09-22,PENDING\n...",
    ai_summary: {
      summary: "Financial ledger with missing trailing records.",
      details: [
        "Recovered: Core transaction history (8400 bytes).",
        "Verified: CSV headers and contiguous block.",
        "Missing: Expected footer/EOF marker (400 bytes missing).",
        "Status reasoning: Received score 78 due to bifragment gap reconstruction.",
        "Priority reasoning: HIGH due to financial nature of the logs."
      ]
    }
  },
  {
    // Scenario 1: Clean/contiguous TXT
    id: "artifact_002",
    filename: "auth_trace.txt",
    mime_type: "text/plain",
    category: "SYSTEM_TRACE",
    priority: "CRITICAL",
    confidence_score: 92,
    confidence_breakdown: {
      header_validity: 20,
      footer_validity: 20,
      structural_validation: 22,
      size_plausibility: 15,
      reconstruction_integrity: 15,
      total: 92
    },
    status: "FULLY_RECOVERED",
    verified_bytes: 1500,
    reconstructed_bytes: 0,
    missing_bytes: 0,
    reconstruction_method: "CONTIGUOUS",
    validation: {
      valid: true,
      checks: [
        { name: "Contiguous Block", detail: "All bytes in single valid block.", passed: true }
      ]
    },
    fragments: [
      { id: "frag_1", start_offset: 0, end_offset: 1500, type: "VERIFIED" }
    ],
    preview_text: "2026-09-21T08:15:02Z AUTH_SUCCESS user=admin\n2026-09-21T08:15:05Z SUDO_EXEC cmd=/bin/sh\n...",
    ai_summary: {
      summary: "Critical authentication logs fully recovered.",
      details: [
        "Recovered: Complete authentication trace.",
        "Verified: Entire 1500 byte file is contiguous and intact.",
        "Missing: None.",
        "Status reasoning: 92/100 score as fully recovered, contiguous block.",
        "Priority reasoning: CRITICAL due to evidence of privileged execution."
      ]
    }
  },
  {
    // Scenario 5: Corrupted PNG with bounds check failure
    id: "artifact_003",
    filename: "evidence_capture.png",
    mime_type: "image/png",
    category: "PHOTO_MEDIA",
    priority: "HIGH",
    confidence_score: 34,
    confidence_breakdown: {
      header_validity: 20,
      footer_validity: 0,
      structural_validation: 14,
      size_plausibility: 0,
      reconstruction_integrity: 0,
      total: 34
    },
    status: "CORRUPTED",
    verified_bytes: 2000,
    reconstructed_bytes: 1000,
    missing_bytes: 500,
    reconstruction_method: "NONE",
    validation: {
      valid: false,
      error: "declared chunk exceeds remaining evidence",
      checks: [
        { name: "PNG Header", detail: "Valid PNG magic bytes.", passed: true },
        { name: "IHDR Chunk", detail: "Image header parsed.", passed: true },
        { name: "IDAT Chunk bounds", detail: "Declared chunk exceeds remaining evidence.", passed: false }
      ]
    },
    fragments: [
      { id: "frag_1", start_offset: 0, end_offset: 2000, type: "VERIFIED" },
      { id: "frag_2", start_offset: 2000, end_offset: 2500, type: "MISSING" }
    ],
    preview_text: "<PNG binary data unrenderable>",
    ai_summary: {
      summary: "Corrupted image file with truncated payload.",
      details: [
        "Recovered: Partial image headers.",
        "Verified: Valid PNG magic bytes.",
        "Missing: Image payload and footer.",
        "Status reasoning: CORRUPTED due to invalid IDAT bounds check.",
        "Priority reasoning: HIGH as potential photo evidence."
      ]
    }
  },
  {
    // Scenario 6: Unrecoverable fragment
    id: "artifact_004",
    filename: "damaged_sector.txt",
    mime_type: "text/plain",
    category: "DOCUMENT",
    priority: "LOW",
    confidence_score: 12,
    confidence_breakdown: {
      header_validity: 0,
      footer_validity: 0,
      structural_validation: 12,
      size_plausibility: 0,
      reconstruction_integrity: 0,
      total: 12
    },
    status: "UNRECOVERABLE",
    verified_bytes: 100,
    reconstructed_bytes: 0,
    missing_bytes: 900,
    reconstruction_method: "NONE",
    validation: {
      valid: false,
      error: "no valid header found",
      checks: [
        { name: "Magic Bytes", detail: "No valid header found.", passed: false }
      ]
    },
    fragments: [
      { id: "frag_1", start_offset: 0, end_offset: 100, type: "VERIFIED" }
    ],
    preview_text: "\\x00\\x00\\x00... (unintelligible sector noise)",
    ai_summary: {
      summary: "Completely unrecoverable damaged sector.",
      details: [
        "Recovered: None.",
        "Verified: 100 bytes of raw data, completely unrecognizable.",
        "Missing: Essentially all content (900 expected bytes).",
        "Status reasoning: UNRECOVERABLE due to lack of headers and structure.",
        "Priority reasoning: LOW because no intelligible data exists."
      ]
    }
  },
  {
    // Scenario 2: Deleted TXT with boundary note
    id: "artifact_005",
    filename: "deleted_notes.txt",
    mime_type: "text/plain",
    category: "DOCUMENT",
    priority: "MEDIUM",
    confidence_score: 86,
    confidence_breakdown: {
      header_validity: 20,
      footer_validity: 20,
      structural_validation: 16,
      size_plausibility: 15,
      reconstruction_integrity: 15,
      total: 86
    },
    status: "FULLY_RECOVERED",
    verified_bytes: 350,
    reconstructed_bytes: 0,
    missing_bytes: 0,
    reconstruction_method: "CONTIGUOUS",
    validation: {
      valid: true,
      checks: [
        { name: "File Structure", detail: "Recovered via contiguous carving.", passed: true }
      ]
    },
    fragments: [
      { id: "frag_1", start_offset: 0, end_offset: 350, type: "VERIFIED" }
    ],
    preview_text: "[SYNTHETIC_ARTIFACT_START]\nMeet at 9PM to discuss the transfer.\n[SYNTHETIC_ARTIFACT_END]",
    ai_summary: {
      summary: "Deleted text document recovered successfully.",
      details: [
        "Recovered: Complete text content.",
        "Verified: Carved using synthetic start and end markers.",
        "Missing: None.",
        "Status reasoning: 86/100 score, fully recovered.",
        "Priority reasoning: MEDIUM due to suspicious meeting note."
      ]
    }
  },
  {
    // Scenario 3: Fragmented CSV
    id: "artifact_006",
    filename: "contacts.csv",
    mime_type: "text/csv",
    category: "DATABASE_LOG",
    priority: "MEDIUM",
    confidence_score: 65,
    confidence_breakdown: {
      header_validity: 20,
      footer_validity: 0,
      structural_validation: 20,
      size_plausibility: 10,
      reconstruction_integrity: 15,
      total: 65
    },
    status: "PARTIALLY_RECOVERED",
    verified_bytes: 2048,
    reconstructed_bytes: 1024,
    missing_bytes: 1024,
    reconstruction_method: "BIFRAGMENT_GAP",
    validation: {
      valid: true,
      checks: [
        { name: "Header Signature", detail: "Valid CSV header found.", passed: true },
        { name: "Row Integrity", detail: "Some rows corrupted across fragmented gap.", passed: false }
      ]
    },
    fragments: [
      { id: "frag_1", start_offset: 0, end_offset: 1024, type: "VERIFIED" },
      { id: "frag_2", start_offset: 1024, end_offset: 2048, type: "RECONSTRUCTED_GAP" },
      { id: "frag_3", start_offset: 2048, end_offset: 3072, type: "VERIFIED" }
    ],
    preview_text: "name,email,phone\nJohn Doe,john@example.com,555-0101\n...<GAP>...Jane Doe,jane@example.com,555-0102\n",
    ai_summary: {
      summary: "Fragmented contacts list.",
      details: [
        "Recovered: Most contact rows.",
        "Verified: Header and trailing block.",
        "Missing: Middle gap containing ~1024 bytes.",
        "Status reasoning: 65/100 score due to significant unrecovered gap.",
        "Priority reasoning: MEDIUM for PII discovery."
      ]
    }
  }
];

export const mockCase: Case = {
  id: "case_001",
  name: "Operation Phantom",
  description: "Investigation into unauthorized access.",
  artifacts: mockArtifacts
};

export async function createCase(name?: string): Promise<Case> {
  if (!USE_MOCK) {
    try {
      const res = await fetch(`${API_BASE}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name || "Automated Case" }),
        cache: 'no-store'
      });
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
      console.warn("Backend unreachable, falling back to mock createCase", e);
    }
  }
  return { ...mockCase, name: name || mockCase.name };
}

export async function uploadEvidence(caseId: string, fileOrSample: File | string): Promise<{ success: boolean }> {
  if (!USE_MOCK) {
    try {
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
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Backend unreachable, falling back to mock uploadEvidence", e);
    }
  }
  return { success: true };
}

export async function analyzeCase(caseId: string): Promise<Case> {
  if (!USE_MOCK) {
    try {
      const res = await fetch(`${API_BASE}/api/cases/${caseId}/analyze`, {
        method: 'POST',
        cache: 'no-store'
      });
      if (res.ok) {
        const raw = await res.json();
        return {
          id: raw.case_id || raw.id,
          name: raw.name || mockCase.name,
          description: raw.description || mockCase.description,
          artifacts: (raw.artifacts || []).map(normalizeBackendArtifact)
        };
      }
    } catch (e) {
      console.warn("Backend unreachable, falling back to mock analyzeCase", e);
    }
  }
  return mockCase;
}

export async function runFullIngestionAndAnalysis(fileOrSample: File | string): Promise<Case> {
  const newCase = await createCase("Automated Case");
  await uploadEvidence(newCase.id, fileOrSample);
  return await analyzeCase(newCase.id);
}

export async function fetchCase(caseId = 'case_001'): Promise<Case> {
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
      console.warn("Backend unreachable, falling back to mock fetchCase", e);
    }
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
      console.warn("Backend unreachable, falling back to mock fetchArtifacts", e);
    }
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
      console.warn("Backend unreachable, falling back to mock fetchArtifactById", e);
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

  const artifact = mockArtifacts.find(a => a.id === artifactId);
  if (!artifact) throw new Error("Artifact not found");
  return artifact;
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
      console.warn("Backend unreachable, falling back to mock fetchArtifactExplanation", e);
    }
  }
  
  if (!explanation) {
    const artifact = mockArtifacts.find(a => a.id === artifactId);
    if (!artifact || !artifact.ai_summary) throw new Error("Explanation not available");
    explanation = { ...artifact.ai_summary, cached: true };
  } else if (explanation.cached === undefined) {
    explanation.cached = false;
  }

  // Pre-warm/set cache
  explanationCache.set(artifactId, explanation);
  return explanation;
}

export const mockGroundTruth: import('./types').GroundTruth = {
  case_id: "case_001",
  image_filename: "phantom_disk.img",
  expected_artifacts: [
    {
      id: "artifact_002",
      filename: "auth_trace.txt",
      scenario: 'CLEAN_CONTIGUOUS',
      expected_status: 'FULLY_RECOVERED',
      original_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      total_bytes: 1500
    },
    {
      id: "artifact_005",
      filename: "deleted_notes.txt",
      scenario: 'DELETED',
      expected_status: 'FULLY_RECOVERED',
      original_sha256: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
      total_bytes: 350
    },
    {
      id: "artifact_006",
      filename: "contacts.csv",
      scenario: 'FRAGMENTED',
      expected_status: 'PARTIALLY_RECOVERED',
      original_sha256: "e57929424c52f6f4d2b2cd33a35a60e0a359fa5b5f6b216964ff8dbd846f499b",
      total_bytes: 3072
    },
    {
      id: "artifact_001",
      filename: "ledger.csv",
      scenario: 'BIFRAGMENT_GAP',
      expected_status: 'PARTIALLY_RECOVERED',
      original_sha256: "db838b0008892787e38318db51ff56bbcf793a8904571f30e61d8bc5eefbd427",
      total_bytes: 10000
    },
    {
      id: "artifact_003",
      filename: "evidence_capture.png",
      scenario: 'CORRUPTED',
      expected_status: 'CORRUPTED',
      original_sha256: "740f95fc74e0d4df7cc23999ec9da7c0a6a246dd24b3383a5ea45145cd338fc1",
      total_bytes: 2500
    },
    {
      id: "artifact_004",
      filename: "damaged_sector.txt",
      scenario: 'UNRECOVERABLE',
      expected_status: 'UNRECOVERABLE',
      original_sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      total_bytes: 1000
    }
  ]
};

export async function fetchGroundTruth(caseId = 'case_001'): Promise<import('./types').GroundTruth> {
  if (!USE_MOCK) {
    try {
      const res = await fetch(`${API_BASE}/api/cases/${caseId}/groundtruth`, { cache: 'no-store' });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Backend unreachable, falling back to mock fetchGroundTruth", e);
    }
  }
  return mockGroundTruth;
}

export async function recoverSingleFile(file: File): Promise<SingleFileRecoveryResult> {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/recover-file`, {
      method: 'POST',
      body: formData,
      cache: 'no-store'
    });
    if (res.ok) {
      const data = await res.json();
      // Ensure absolute download_url if needed
      if (data.download_url && data.download_url.startsWith('/')) {
        data.download_url = `${API_BASE}${data.download_url}`;
      }
      return data;
    }
    const errData = await res.json().catch(() => ({}));
    const message = typeof errData.detail === 'string' ? errData.detail : (errData.detail ? JSON.stringify(errData.detail) : `Server returned ${res.status}`);
    throw new Error(message);
  } catch (e: any) {
    if (e.message && !e.message.startsWith('TypeError: Failed to fetch') && !e.message.includes('fetch failed')) {
      throw e;
    }
    throw new Error(
      `Recovery backend unavailable at ${API_BASE}. No result is shown because verified, ` +
      `reconstructed and missing byte counts must come from the live forensic engine.`
    );
  }
}

export function getArtifactDownloadUrl(artifactId: string): string {
  return `${API_BASE}/api/artifacts/${artifactId}/download`;
}

export async function fetchRecoveryRun(runId: string): Promise<any | null> {
  try {
    const res = await fetch(`${API_BASE}/api/recovery-runs/${runId}`, { cache: 'no-store' });
    if (res.ok) return await res.json();
  } catch (e) {
    console.warn("Failed to fetch recovery run", e);
  }
  return null;
}

export async function fetchRecoveredFile(fileId: string): Promise<SingleFileRecoveryResult | null> {
  try {
    const res = await fetch(`${API_BASE}/api/recover-file/${fileId}`, { cache: 'no-store' });
    if (res.ok) {
      const data = await res.json();
      if (data.download_url && data.download_url.startsWith('/')) {
        data.download_url = `${API_BASE}${data.download_url}`;
      }
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
    recovery_limitation = `Deterministic syntax repair only. Zero heuristic AI predictions or synthetic filler bytes were used.`;
    recommended_next_step = `Inspect the reconstructed boundaries and verify schema conformity.`;
  } else if (r_bytes > 0 && m_bytes > 0) {
    assessment = `This artifact is partially recovered. ${v_bytes} bytes were mathematically verified from the uploaded evidence, ${r_bytes} bytes were structurally reconstructed via ${method}, and an unobserved ${m_bytes}-byte gap was preserved.`;
    why_it_matters = `The reconstructed bytes were derived from deterministic grammar rules, while the unobserved ${m_bytes}-byte region was preserved to prevent evidence hallucination.`;
    recovery_limitation = `Missing bytes could not be deterministically established and were preserved as missing.`;
    recommended_next_step = `Review original evidence source or examine adjacent storage clusters for matching fragments.`;
  } else if (status === "FULLY_RECOVERED" || (m_bytes === 0 && r_bytes === 0 && v_bytes > 0)) {
    assessment = `This artifact is fully recovered. All ${v_bytes} bytes were mathematically verified from the uploaded evidence with 0 missing and 0 reconstructed bytes.`;
    why_it_matters = `The artifact adheres completely to the ${fmt} specification with authoritative validation. Evidence integrity is verified for judicial chain of custody.`;
    recovery_limitation = `Exact deterministic recovery. Zero heuristic AI predictions or synthetic filler bytes were used.`;
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
    summary: "AI interpretation could not be generated.",
    details: ["Deterministic recovery results remain available."],
    available: false,
    assessment: "Deterministic recovery results remain available. AI interpretation could not be generated.",
    priority: "MEDIUM",
    why_it_matters: "Backend AI service was unreachable or returned an error.",
    recovery_limitation: "AI interpretation could not be retrieved. Deterministic evidence is unaffected.",
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
