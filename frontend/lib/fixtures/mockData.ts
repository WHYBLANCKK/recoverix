import { Artifact, Case, GroundTruth } from '../types';

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

export const mockGroundTruth: GroundTruth = {
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
