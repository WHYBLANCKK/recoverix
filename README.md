# Recoverix

### Deterministic Digital Evidence Recovery and Analysis

Recoverix is an open-source digital evidence recovery and analysis engine designed to identify, validate, and reconstruct damaged, fragmented, and partially corrupted files.

It combines deterministic file carving, structural validation, byte-level provenance ($V/R/M$), recovery confidence scoring, and grounded analysis to make recovery results transparent, verifiable, and understandable.

Recoverix distinguishes strictly between information directly proven by the available evidence, information reconstructed through deterministic structural procedures, and information that remains missing.

> **Recoverix does not guess what was lost. It reconstructs what the evidence supports and makes uncertainty explicit.**

---

## Table of Contents

- [Public Beta (v0.1.0-beta.1)](#public-beta-v010-beta1)
- [Problem Statement](#problem-statement)
- [Our Approach](#our-approach)
- [Core Architecture](#core-architecture)
- [Key Features](#key-features)
- [Deterministic Recovery](#deterministic-recovery)
- [Byte-Level Provenance ($V / R / M$)](#byte-level-provenance-v--r--m)
- [Recovery Classification](#recovery-classification)
- [Supported File Formats (All 8 Formats)](#supported-file-formats-all-8-formats)
- [AI Evidence Analyst](#ai-evidence-analyst)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Command-Line Interface (CLI)](#command-line-interface-cli)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Synthetic Evaluation & Benchmarks](#synthetic-evaluation--benchmarks)
- [Security and Deployment Model](#security-and-deployment-model)
- [Current Deployment Status (Staging Candidate)](#current-deployment-status-staging-candidate)
- [Limitations & Non-Claims](#limitations--non-claims)
- [Design Principles](#design-principles)
- [Contributing](#contributing)
- [License](#license)

---

## Public Beta (v0.1.0-beta.1)

Recoverix `v0.1.0-beta.1` is a controlled public beta release intended for digital forensic researchers, reverse engineers, developers, and users seeking reliable recovery of damaged files.

### Scope and Guiding Principles

> **"Recoverix does not guess what was lost. It proves what can be recovered."**

Recoverix operates on strict deterministic principles:
- **No Hallucinated Evidence:** The engine never invents missing file bytes or uses generative AI prediction to complete missing payload data.
- **Explicit Provenance ($V / R / M$):** Reconstructed structural repairs are strictly accounted for and separated from verified evidence bytes.
- **Defensive Bounds:** Memory consumption is strictly bounded during file carving, stream processing, and HTTP transfers.

### Core Capabilities

1. **Eight Supported File Formats:**
   - **PDF:** Reconstructs broken cross-reference (`xref`) tables and missing trailers; validates object hierarchies and document catalogs.
   - **JSON:** Detects syntax boundaries and deterministically closes unclosed container delimiters (`}`, `]`) without synthetic markers.
   - **CSV:** Detects delimiter integrity, balances cell boundaries, and normalizes ragged trailing records.
   - **TXT:** Enforces strict UTF-8 multi-byte boundary alignment and isolates corrupted non-text byte sequences.
   - **XML:** Reconstructs unclosed nested tag hierarchies, synthesizes root element wrappers, and enforces strict defenses against XML External Entity (XXE) attacks.
   - **PNG:** Validates chunk CRC checksums, verifies chunk sequences (`IHDR`, `IDAT`), and reconstructs missing `IEND` footer chunks.
   - **JPEG / JPG:** Validates Start of Image (`SOI`), parses Start of Scan (`SOS`) streams, and restores missing End of Image (`EOI`, `0xFF 0xD9`) markers.
   - **ZIP:** Parses local file headers, validates member checksums, reconstructs missing or truncated Central Directories and End of Central Directory (EOCD) records, and rejects directory traversal (Zip-Slip) attacks.
2. **Transparent Byte Accounting ($V / R / M$):**
   Every recovery produces a breakdown satisfying $\text{Total Logical Bytes} = V + R + M$:
   - $V$ (Verified): Bytes present in and directly proven by the evidence.
   - $R$ (Reconstructed): Deterministic structural repairs added to make the file parser-compliant.
   - $M$ (Missing): Unrecovered damaged or omitted regions.
3. **Consumer Web Interface & Case Investigation:**
   - A Next.js (App Router) frontend with Tailwind CSS providing single-file drag-and-drop recovery, instant $V/R/M$ forensic accounting display, and verified file downloads.
   - Case investigation dashboards for multi-artifact disk image analysis.
4. **Standalone CLI (`recoverix`):**
   Bounded, non-destructive file carving and reconstruction directly from the terminal without running web services.

### Critical Operational Constraints & Disclaimers

- **Input Size Bounds:**
  - The standalone CLI and case ingestion pipeline enforce a strict maximum input size limit of **5 MiB** (`5,242,880 bytes`).
  - The single-file web recovery endpoint (`/api/recover-file`) enforces a maximum upload limit of **32 MiB** (`33,554,432 bytes`).
  - Empty (0-byte) files or files exceeding these bounds are rejected immediately with clear error messages.
- **Local Workstation Security:** Recoverix contains **no built-in user authentication or multi-tenant authorization**. It is configured by default for single-user local loopback operation (`127.0.0.1`). Network deployments require an authenticating reverse proxy and network isolation.
- **Verified vs. Reconstructed Bytes:** Reconstructed bytes ($R$) represent structural repairs (such as regenerated xref tables, closing brackets, or container headers), not original verified evidence.
- **PDF Object Stream Limitation:** Compressed object streams (`/ObjStm`) and compressed cross-reference streams (`/XRef`) introduced in PDF 1.5+ are not decompressed by the lightweight validator and remain an unsupported structure limitation.
- **Explicit Non-Claims:** Recoverix makes no claim of universal file recovery, legal admissibility in judicial proceedings, or forensic soundness for unsupported formats. It is an engineering and research prototype.

---

## Problem Statement

Damaged or fragmented digital files can contain intact data, corrupted regions, missing fragments, or structures that are only partially recoverable.

Finding a file signature or generating an output file does not mean that the original information was recovered correctly. Many conventional file carving tools either produce truncated files that crash viewer applications, or claim 100% recovery without disclosing that large segments of data were silently lost or filled with garbage.

A reliable recovery workflow must answer several questions:

- What artifacts were identified?
- Which bytes are directly supported by the available evidence?
- Which bytes were reconstructed to restore structural integrity?
- Which information remains missing?
- Did the reconstructed artifact pass independent structural validation?
- Where does uncertainty remain?

Recoverix addresses these questions through deterministic recovery, structural validation, explicit byte accounting, and transparent reporting.

---

## Our Approach

Recoverix follows three core stages:

```
Evidence Input ──> [1. Recover] ──> [2. Prove] ──> [3. Understand] ──> Verified Output
```

### 1. Recover
Identify candidate artifacts, locate surviving fragments, and attempt reconstruction when the available evidence supports a defined, reproducible recovery procedure.

### 2. Prove
Validate recovery candidates against independent, format-specific structural validators and record the strict accounting distinction between verified ($V$), reconstructed ($R$), and missing ($M$) bytes.

### 3. Understand
Classify and prioritize artifacts, present recovery results with visual byte maps, and provide natural-language explanations grounded strictly in deterministic analysis.

The recovery engine remains authoritative. AI-assisted explanations do not replace recovery algorithms or structural validation.

---

## Core Architecture

```text
Evidence Input (Upload or CLI)
      │
      ▼
Evidence Ingestion & Size Check
      │
      ▼
Format Identification (Magic Bytes / Signatures)
      │
      ▼
Candidate Detection & Boundary Isolation
      │
      ▼
Fragment and Structure Analysis
      │
      ▼
Deterministic Reconstruction (Format Reconstructors)
      │
      ▼
Structural Validation (Independent Format Parsers)
      │
      ▼
Byte-Level Provenance Accounting (V / R / M)
      │
      ▼
Recovery Scoring and Status Classification
      │
      ▼
Artifact Prioritization & Explanations
      │
      ▼
Investigation Interface / Direct File Download
```

Each stage has a distinct responsibility. Recovery decisions and byte accounting are established by the deterministic pipeline before any explanation layer interprets the results.

---

## Key Features

### Evidence Ingestion
- Accept evidence files via the web UI or CLI.
- Maintain evidence metadata (original filename, MIME type, byte size).
- Calculate SHA-256 digests for verification tracking.
- Enforce strict upload size limits (32 MiB for web single-file recovery, 5 MiB for CLI).

### File Identification and Candidate Detection
- Identify supported file formats using robust magic bytes and signature heuristics.
- Locate candidate artifacts and fragments within larger data streams.
- Track candidate offsets and sizes.
- Apply format-specific boundary detection.
- Isolate candidates to reduce accidental overlap and cross-candidate contamination.

### Deterministic Reconstruction
- Attempt bounded bifragment reconstruction when two fragments share continuity.
- Apply supported format-specific structural reconstruction (e.g. closing unclosed XML tags, rebuilding PDF xref tables, reconstructing ZIP Central Directories).
- Reject invalid reconstruction results.
- Preserve ambiguity when the evidence does not establish a unique result.
- Avoid combining unrelated candidates merely because they share a format.

### Structural Validation
- Validate candidates using independent, format-specific checks (e.g. `PIL/Pillow` for PNG/JPEG, `xml.etree` for XML, `zipfile` for ZIP, `json` parser for JSON).
- Reject invalid reconstruction results.
- Handle malformed and truncated input safely without crashing.
- Distinguish successful structural validation from proof that every original byte was recovered.

### Byte-Level Provenance ($V / R / M$)
Record the exact contribution of verified ($V$), reconstructed ($R$), and missing ($M$) bytes for every recovery operation.

### Recovery Scoring and Classification
Evaluate recovery results using the prototype's scoring policy and classify artifacts according to the available recovery evidence.

### Consumer-Ready Workflow
- Single-file upload, instant recovery processing, and direct download of recovered files.
- Visual byte maps showing the physical layout of intact, reconstructed, and damaged regions.
- Plain-English explanations of what was recovered, what structural framing was repaired, and what limitations exist.

---

## Deterministic Recovery

Recoverix uses evidence-driven recovery procedures rather than heuristic guesswork.

### Bounded Bifragment Reconstruction

When two fragments may belong to the same artifact, the reconstruction engine evaluates possible gap sizes within a configured search range:

```text
Fragment A          Unknown Gap          Fragment B
[Available Bytes]   [Missing Region]     [Available Bytes]
```

The engine evaluates candidate reconstructions using applicable validation rules:
- A uniquely validated candidate may be selected.
- Multiple valid candidates remain flagged as ambiguous.
- Unrelated candidates remain separate when the evidence does not support combining them.
- A failed reconstruction attempt is never presented as a successful recovery.

### Structural Reconstruction

Some formats permit deterministic reconstruction of structural framing bytes:
- An incomplete JSON structure may have missing closing braces and brackets deterministically appended.
- A truncated PDF file with missing xref table and trailer can have its xref table regenerated from surviving indirect objects.
- A truncated ZIP file with missing Central Directory can have its Central Directory reconstructed from surviving local file headers.
- A truncated PNG file with missing `IEND` chunk can have its `IEND` footer appended.
- A truncated JPEG file missing its `0xFF 0xD9` (`EOI`) marker can have its end-of-image marker restored.

**Any bytes added by such a procedure are recorded strictly as Reconstructed ($R$), never as Verified ($V$).** Recoverix does not claim to recover arbitrary overwritten or unknowable content.

---

## Byte-Level Provenance ($V / R / M$)

Recoverix distinguishes three categories of artifact bytes:

| Symbol | Category | Meaning | Example |
|:---:|---|---|---|
| **$V$** | **Verified** | Bytes directly present in and proven by the uploaded evidence | Intact text, image scanlines, surviving objects |
| **$R$** | **Reconstructed** | Deterministic structural bytes added to restore parser compliance | Synthesized xref table, closing `]}` brackets, `IEND` chunk |
| **$M$** | **Missing** | Bytes that cannot be established from the available evidence | Corrupted gap between fragments, truncated payload data |

The fundamental accounting identity is:

$$\text{Total Logical Artifact Bytes} = V + R + M$$

- The accounting model must not imply that reconstructed bytes were present in the original evidence.
- A structurally valid output is not proof of complete recovery if $M > 0$ or $R > 0$.
- When $M > 0$, Recoverix makes missing byte counts explicit rather than pretending the file is complete.

---

## Recovery Classification

Recoverix uses a prototype confidence-scoring policy to classify recovery results:

| Score Range | Status | Meaning |
|:---:|---|---|
| **85–100** | `FULLY_RECOVERED` | Intact or near-intact artifact; all bytes verified ($V$), 0 missing ($M=0$), and 0 reconstructed ($R=0$). |
| **50–84** | `PARTIALLY_RECOVERED` | Validated artifact with reconstructed structural framing ($R > 0$) or known missing bytes ($M > 0$). |
| **20–49** | `CORRUPTED` | Detected candidate artifact that failed structural validation or contains unrecoverable corruption zones. |
| **0–19** | `UNRECOVERABLE` | Random noise, unsupported corruption, or fragments insufficient to form a valid artifact. |

*Note*: These thresholds are application heuristics designed for investigative triage, not a formal legal or forensic standard.

---

## Supported File Formats (All 8 Formats)

Recoverix provides dedicated detection, carving, validation, and reconstruction logic for eight major file formats:

| Format | Extension | Deterministic Recovery Actions | Structural Validation Method | Known Limitations |
|---|---|---|---|---|
| **PDF** | `.pdf` | Rebuilds broken cross-reference (`xref`) tables; synthesizes missing trailer dictionaries; validates indirect object hierarchies. | Object catalog verification; xref table parse check. | Compressed object streams (`/ObjStm`) and xref streams (`/XRef`) introduced in PDF 1.5+ are not decompressed. |
| **JSON** | `.json` | Detects syntax boundaries; balances and closes unclosed container delimiters (`}`, `]`) deterministically. | Strict JSON parser validation (`json.loads`). | Truncated string values, cut-off numeric literals, or corrupted key tokens are safely rejected without guessing. |
| **CSV** | `.csv` | Detects row/column delimiters; normalizes ragged trailing rows; isolates corrupted records. | Dialect sniffing and tabular column count validation. | Missing intermediate columns cannot be inferred or synthesized. |
| **TXT** | `.txt` | Detects text continuity; trims truncated multi-byte UTF-8 boundaries; isolates binary corruption zones. | Strict UTF-8 / ASCII encoding validation. | Corrupted intermediate bytes cannot be restored to original codepoints. |
| **XML** | `.xml` | Parses tag nesting; closes unclosed element stacks; synthesizes root element wrappers if missing. | Strict `xml.etree.ElementTree` validation with entity restrictions. | Corrupted tag names or missing attribute values cannot be guessed; DTD entities blocked for security. |
| **PNG** | `.png` | Validates chunk headers (`IHDR`, `IDAT`); checks CRC checksums; deterministically restores missing `IEND` footer chunks. | Strict Pillow image header and stream validation. | Corrupted `IDAT` compressed scanline streams cannot be repaired without original DEFLATE stream data. |
| **JPEG** | `.jpg`, `.jpeg` | Verifies Start of Image (`0xFF 0xD8`, `SOI`); parses Start of Scan (`SOS`) markers; appends missing End of Image (`0xFF 0xD9`, `EOI`) markers. | Strict Pillow image decoding and marker verification. | Corrupted entropy-coded scan data cannot be reconstructed without original DCT coefficients. |
| **ZIP** | `.zip` | Scans local file headers; verifies CRC32 checksums; deterministically rebuilds missing or truncated Central Directory and EOCD records. | Strict `zipfile.ZipFile` integrity checks with path traversal defenses. | Corrupted or truncated compressed member streams cannot be decompressed. |

---

## AI Evidence Analyst

The AI evidence analyst operates as an interpretation and explanation layer over deterministic recovery results.

Depending on configuration, it provides:
- Human-readable recovery summaries.
- Plain-English explanations of detected damage and structural repairs.
- Clear itemization of verified vs. reconstructed vs. missing data.
- Investigator-oriented context.

### Safety Invariants of the AI Layer
The AI analyst must **never**:
- Invent or predict missing file content.
- Present synthetic predictions as recovered evidence.
- Override deterministic validation results.
- Alter $V$, $R$, or $M$ byte counts.
- Independently declare a damaged file valid.

AI explanations remain grounded in the output of the deterministic recovery engine.

---

## Technology Stack

- **Backend Framework**: Python 3.10+, FastAPI, Uvicorn
- **Recovery Engine**: Custom deterministic stream carvers, format reconstructors, structural validators, and byte provenance counters
- **Database & Storage**: SQLite with ephemeral container storage and 24-hour TTL purge lifecycle
- **Frontend Framework**: Next.js 16 (App Router), React, TypeScript, Tailwind CSS, Lucide Icons
- **Testing & Quality Assurance**: Pytest (1,334 passing tests), TypeScript compiler (`tsc`), Pillow, AnyIO
- **Deployment Infrastructure**: Docker, Render Free Web Service Blueprint (`render.yaml`), Vercel Hobby

---

## Project Structure

```text
recoverix/
├── backend/
│   ├── app/
│   │   ├── api/                 # FastAPI routes (/api/recover-file, /api/cases, /health)
│   │   ├── generator/           # Synthetic evidence and disk image generator
│   │   ├── ingestion/           # Evidence reader, chunker, and metadata extractor
│   │   ├── models/              # Pydantic schemas (artifact, case, confidence, V/R/M)
│   │   ├── recovery/            # Core deterministic recovery engine
│   │   │   ├── reconstructors/  # Format reconstructors (PDF, JSON, CSV, TXT, XML, PNG, JPEG, ZIP)
│   │   │   ├── validators/      # Format validators and security guards (XXE, Zip-Slip)
│   │   │   ├── bifragment.py    # Bounded bifragment gap analysis
│   │   │   ├── carver.py        # Stream carving and candidate boundary detection
│   │   │   ├── scanner.py       # Signature scanner & magic byte detection
│   │   │   └── signatures.py    # Format signatures and header/footer definitions
│   │   ├── scoring/             # Confidence scoring policy and byte provenance accounting
│   │   ├── storage/             # SQLite store and 24-hour TTL purge worker
│   │   └── main.py              # Application entrypoint, CORS & proxy security middleware
│   ├── cli.py                   # Standalone CLI entrypoint (recoverix)
│   └── generate_case.py         # Synthetic case generator script
├── frontend/                    # Next.js 16 (App Router) + Tailwind CSS web interface
│   ├── app/                     # App router pages (/, /cases, /dashboard, /investigation)
│   ├── components/              # React components (EvidenceUpload, ByteEvidenceMap, AIEvidenceAnalyst)
│   ├── lib/                     # API client, types, and byte-level provenance helpers
│   ├── next.config.ts           # Dynamic backend API rewrite configuration
│   └── vercel.json              # Next.js framework preset declaration
├── benchmark/                   # Forensic evaluation benchmarks & synthetic test suites
├── docs/                        # Architectural documentation, deployment guides, release notes
├── tests/                       # 1,334+ automated regression, parser, and security tests
├── Dockerfile.backend           # Hardened container for backend on dynamic $PORT
├── Dockerfile.frontend          # Multi-stage production container for frontend
├── render.yaml                  # Render free-tier Infrastructure-as-Code Blueprint
├── pyproject.toml               # Python package configuration and CLI console script
└── README.md                    # Project documentation
```

---

## Getting Started

### Prerequisites

- **Python**: Version 3.10, 3.11, 3.12, 3.13, or 3.14
- **Node.js**: Version 18.x, 20.x, or 22.x
- **npm**: Version 9.x+

### 1. Clone the Repository

```bash
git clone https://github.com/c-zerooo/recoverix.git
cd recoverix
```

### 2. Set Up and Start the Backend

From the repository root:

```bash
# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .

# Start the FastAPI backend
python3 -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify that the backend is running by opening:
```text
http://127.0.0.1:8000/health
```
Expected response:
```json
{"status": "ok", "service": "recoverix-backend", "engine": "forensic-carver"}
```

### 3. Set Up and Start the Frontend

In a second terminal window:

```bash
cd frontend

# Install npm dependencies
npm install

# Start the Next.js development server
npm run dev
```

Open your browser to:
```text
http://127.0.0.1:3000
```

---

## Command-Line Interface (CLI)

Recoverix provides a standalone CLI that enables direct file carving, deterministic reconstruction, structural validation, and artifact export without running web services:

```bash
# Run via python module
python3 -m backend.cli recover damaged_doc.pdf --out ./recovered

# Or via installed console script
recoverix recover damaged_image.png -o ./recovered_artifacts
```

### Exit Codes

| Exit Code | Meaning | Description |
|:---:|---|---|
| `0` | Recovery Successful | A valid artifact was recovered (`FULLY_RECOVERED` or `PARTIALLY_RECOVERED`) and written to disk. |
| `1` | Unrecoverable | The evidence is unrecoverable from available bytes; no output file is written. |
| `2` | Operational Error | Input file not found, permission denied, file exceeds 5 MiB limit, target file already exists, path traversal detected, or invalid arguments. |

### Safety Invariants of the CLI

- **Non-Overwrite Guarantee:** To prevent accidental evidence loss, the CLI will refuse to overwrite an existing file.
- **Path Traversal Protection:** Input filenames are strictly sanitized to basenames before constructing destination paths.
- **No Artifact on Failure:** If recovery status is `UNRECOVERABLE`, no file is written to disk.

---

## Testing & Quality Assurance

Recoverix maintains a comprehensive automated test suite covering format reconstructors, independent third-party parsers, boundary isolation, CORS security, proxy spoofing defenses, and data retention lifecycles.

```bash
# 1. Run the complete pytest suite (1,334 passed)
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/ -q

# 2. Run the 8-format independent parser & validation test suite
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/test_independent_parsers_8_formats.py tests/test_file_recovery.py -v

# 3. Run the security, CORS, and proxy anti-spoofing test suite
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/test_cors_and_api_exposure.py -v

# 4. Run the frontend production build and TypeScript check
cd frontend && npm run build
```

---

## Synthetic Evaluation & Benchmarks

Recoverix evaluates its recovery algorithms against reproducible synthetic evidence images with mathematically known ground-truth placements.

> [!NOTE]
> All evaluation fixtures are synthetic, deterministic controls with mathematically known ground truth. Recoverix does NOT represent synthetic fixtures as real-world evidence and makes no claim of general real-world accuracy without measured evidence from genuine external corpora.

### 1. Baseline Recovery Benchmark (`benchmark.run_baseline`)
Evaluates candidate detection, boundary isolation, and byte-level provenance across 6 core scenarios:
```bash
python3 -m benchmark.run_baseline
```
*Result:* **6 / 6 passed**, 0 forensic accounting violations.

### 2. Marker-Free JSON Benchmark (`benchmark.json_benchmark`)
Evaluates syntax-boundary candidate discovery, bracket-closure reconstruction, and noise resistance without synthetic framing delimiters:
```bash
python3 -m benchmark.json_benchmark
```
*Result:* **6 / 7 scenarios passed**, 1 documented limitation (`UNACCOUNTED_GAP` on content loss).

### 3. Empirical Validation Corpus Benchmark (`benchmark.run_realworld`)
Evaluates multi-format file recovery, structural validation, and strict $V/R/M$ accounting across 15 controlled scenarios:
```bash
python3 -m benchmark.run_realworld --manifest benchmark/evaluation_corpus/manifest.json
```
*Result:* **15 / 15 status matched (100% accuracy)**, **4 / 4 exact hash matches on intact evidence**, 0 false positives, 0 false negatives.

---

## Security and Deployment Model

Recoverix is architected as a **local single-user recovery workstation tool**. It does **not** provide built-in user accounts, passwords, API tokens, session management, or role-based access controls (RBAC).

### Supported Deployment Modes

1. **Local Workstation (Default & Recommended)**
   - Backend runs on `127.0.0.1:8000`, frontend runs on `127.0.0.1:3000`.
   - CORS is restricted by default to local loopback origins (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:8000`, `http://127.0.0.1:8000`).
   - Browsers prevent arbitrary third-party websites from reading evidence data or executing cross-origin API calls.

2. **Container Deployment (`docker compose`)**
   - Services are published on the host loopback adapter (`127.0.0.1:8000` and `127.0.0.1:3000`), preventing port exposure across LAN or public network interfaces.

3. **Network-Accessible Deployment (Shared Server or Cloud)**
   - **Important:** Recoverix does not implement authentication. Binding the backend to `0.0.0.0` or exposing port 8000 directly to a network allows anyone with network connectivity to view cases, upload evidence, and download recovered payloads.
   - Exposing Recoverix to an untrusted network requires an external security perimeter:
     - **Authenticating Reverse Proxy:** Deploy an identity-aware proxy (e.g. OAuth2-Proxy, Cloudflare Access, AWS ALB OIDC, or Nginx with HTTP Basic/mTLS).
     - **Network Isolation:** Restrict access via VPN (e.g. WireGuard, Tailscale) or firewall rules.
     - **TLS Termination:** Terminate HTTPS at the gateway.
     - **Request Size Limiting:** Enforce reverse-proxy upload size limits.
     - **CORS Configuration:** Explicitly configure `RECOVERIX_CORS_ORIGINS` to the domain of the deployed frontend.

### CORS Security Invariants

- **Whitelisted Origins Only:** Configured via `RECOVERIX_CORS_ORIGINS`.
- **Wildcard Origins Strictly Rejected:** Wildcard origins (`*`) are rejected by the origin validator. Setting `RECOVERIX_CORS_ORIGINS=*` will not enable unrestricted CORS; it will be rejected as invalid and fall back safely to loopback defaults.
- **CORS Is Not Authentication:** CORS protects browsers against cross-origin scripting; it provides zero protection against direct HTTP clients (`curl`, scripts) having network connectivity to the port.

### Anti-Spoofing Proxy Resolution

To prevent clients from spoofing their IP address via forged `X-Forwarded-For` headers to bypass rate limiting, Recoverix implements strict proxy trust verification:
- `RECOVERIX_TRUSTED_PROXIES=private` strictly verifies client IPs against RFC 1918 / RFC 4193 private network address ranges before trusting forwarded headers.
- Untrusted direct connections are evaluated using their direct socket address, preventing rate-limit evasion.

---

## Current Deployment Status (Staging Candidate)

> [!IMPORTANT]
> **Staging Deployment in Progress**: Recoverix is an evolving open-source project. The application is configured for deployment on zero-cost ($0/month) cloud infrastructure, but the public staging URLs are **currently in progress and unverified** (returning HTTP 404 pending final dashboard configuration steps). Do not treat public staging URLs as verified production services until formal verification is complete.

### Staging Architecture Overview

| Component | Target Provider | Plan | Intended Domain | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend** | Vercel | Hobby ($0/month) | `https://recoverix-staging.vercel.app` | **Unverified / 404** (Pending Vercel production branch configuration) |
| **Backend** | Render | Free Web Service ($0/month) | `https://recoverix-backend-staging.onrender.com` | **Live & Verified** (Health check OK; all 8 formats verified end-to-end) |
| **Storage** | Render Container | Ephemeral SQLite ($0/month) | `/app/data/recoverix.db` | Ephemeral container storage with 24-hr TTL purge |

### Free-Tier Hosting Limitations & Operational Reality

Recoverix is architected to run within a strict $0/month budget. This introduces specific operational constraints:

1. **Ephemeral File Storage**:
   - Render free web services do **not** provide persistent disks.
   - Uploaded files, recovered artifacts, and SQLite database records reside in the container's temporary local filesystem.
   - When the container restarts, redeploys, or spins down, stored records and unexported files are erased.
   - **Recoverix is not a permanent storage vault**. Users must download recovered files immediately upon completion.
2. **Idle Spin-Down and Cold Starts**:
   - Render free containers automatically spin down to 0 instances after 15 minutes of inactivity.
   - The first request after an idle period triggers a cold start that typically takes **45 to 60 seconds** while the container starts. Subsequent requests respond in standard sub-second time.
3. **24-Hour Time-to-Live (TTL) Purge**:
   - To keep storage bounded within free-tier container limits, the backend automatically purges uploaded files and recovery artifacts older than 24 hours (`store.purge_expired_recovered_files(ttl_hours=24)`).
4. **Input Size Bounds**:
   - Web uploads are constrained to 32 MiB.
   - Ingestion rate limiting is enforced per client IP address (60 requests/minute).

---

## Limitations & Non-Claims

Recoverix is an evolving engineering and research prototype, not a validated commercial or judicial forensic platform.

Current limitations include:
- **No Content Hallucination**: Missing payload data cannot be guessed. If unobserved data was destroyed, it remains missing.
- **Format-Specific Boundaries**: Recovery depends strictly on implemented deterministic procedures. Unsupported corruption patterns remain unrecoverable.
- **Compressed PDF Streams**: Compressed object streams (`/ObjStm`) and xref streams (`/XRef`) introduced in PDF 1.5+ are not decompressed.
- **Severe Corruption**: Overwritten data sectors, heavily truncated payloads, or zeroed-out blocks cannot be restored.
- **Reconstruction Ambiguity**: Some damaged fragments may produce multiple plausible reconstructions; Recoverix preserves ambiguity rather than making an unverified guess.
- **Not Admissible as Legal Testimony**: Recoverix makes no claim of legal admissibility in judicial proceedings or formal compliance with forensic laboratory standards.

---

## Design Principles

1. **Deterministic First**: Recovery decisions must be grounded in mathematical evidence and reproducible algorithms.
2. **No Invented Evidence**: Missing bytes must never be fabricated and represented as original content.
3. **Explicit Provenance**: Every output must clearly distinguish verified ($V$), reconstructed ($R$), and missing ($M$) bytes.
4. **Preserve Ambiguity**: When evidence cannot distinguish between valid alternatives, preserve the uncertainty rather than guessing.
5. **Validate Before Accepting**: Candidate reconstructions must pass independent structural validation before being declared valid.
6. **Isolate Independent Candidates**: Independent candidate artifacts must not be combined merely because they appear near one another.
7. **Honest Reporting**: Communicate limitations clearly and avoid claiming capabilities that have not been implemented and proven.

---

## Contributing

Contributions to Recoverix are welcome. As an open-source forensic engineering project, we follow strict quality, safety, and evidence-preservation guidelines:

1. **Deterministic First**: Contributions must not introduce generative prediction, probabilistic guessing, or hallucinated content to fill missing file bytes.
2. **Strict $V/R/M$ Accounting**: Every recovery algorithm must strictly account for verified evidence bytes ($V$), reconstructed structural repairs ($R$), and unrecoverable missing bytes ($M$).
3. **Safety & Security Invariants**:
   - Reconstructors must guard against memory exhaustion, recursive parsing, and parser bombs.
   - Archive parsers must defend against path traversal (Zip-Slip).
   - Markup parsers must reject external entity expansion (XXE).
   - Input filenames must be sanitized to safe basenames.
4. **Comprehensive Test Coverage**:
   - New reconstructors or validators must include tests with synthetic intact, damaged/repairable, and unrecoverable control fixtures.
   - The entire regression test suite (`pytest tests/`) must pass cleanly.
5. **How to Contribute**:
   - Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
   - Run tests and lint checks locally.
   - Submit a Pull Request targeting `recoverix/staging-candidate` (or `main`) with a detailed explanation of your changes and test evidence.

---

## License

Recoverix is open-source software licensed under the [MIT License](LICENSE).
