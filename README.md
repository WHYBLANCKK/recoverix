<p align="center">
  <img src="docs/assets/recoverix-banner.png" alt="Recoverix — Deterministic Digital Evidence Recovery" width="680" style="max-width: 100%; height: auto;" />
</p>

<p align="center">
  <strong>Deterministic Digital Evidence Recovery &amp; Structural Reconstruction Engine</strong>
  <br />
  <em>Recoverix does not guess what was lost. It proves what can be recovered.</em>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10+-brightgreen.svg" alt="Python: 3.10+" /></a>
  <a href="https://nextjs.org/"><img src="https://img.shields.io/badge/Next.js-16-black.svg" alt="Next.js: 16" /></a>
  <a href="tests/"><img src="https://img.shields.io/badge/Tests-Passing-success.svg" alt="Tests: Passing" /></a>
</p>

Recoverix is an open-source digital evidence recovery and analysis engine designed to identify, validate, and reconstruct damaged, fragmented, and partially corrupted files without synthetic guessing or probabilistic hallucination.

The engine combines deterministic stream carving, format-specific structural reconstruction, independent third-party validator verification, and strict byte-level provenance ($V / R / M$) accounting to make recovery outcomes verifiable, reproducible, and transparent.

- **Live Staging Website**: [https://recoverix-staging.vercel.app/](https://recoverix-staging.vercel.app/)
- **GitHub Repository**: [https://github.com/WHYBLANCKK/recoverix](https://github.com/WHYBLANCKK/recoverix)

---

## Core Product Principle

> **"Recoverix does not guess what was lost. It proves what can be recovered."**

Recoverix operates on strict deterministic principles:
1. **No Fabricated Content**: Missing payload data is never invented, synthesized, or predicted using probabilistic heuristics or generative language models.
2. **Explicit Provenance ($V / R / M$)**: Every byte of recovered output is categorized into verified evidence ($V$), reconstructed structural framing ($R$), or unrecovered missing space ($M$).
3. **Independent Validation**: Recovery candidates must pass rigorous independent third-party parsing (e.g. `Pillow` for PNG/JPEG, `xml.etree` for XML, `zipfile` for ZIP, `json` for JSON) before being classified as valid.
4. **Defensive Bounds**: Memory consumption, upload payloads, and parser execution depths are strictly bounded to prevent Denial-of-Service and parser bomb attacks.

---

## Table of Contents

- [Problem Statement](#problem-statement)
- [How Recovery and Validation Work](#how-recovery-and-validation-work)
- [Byte-Level Provenance Accounting ($V / R / M$)](#byte-level-provenance-accounting-v--r--m)
- [Supported Formats & Capabilities](#supported-formats--capabilities)
- [Core Architecture](#core-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started & Local Development](#getting-started--local-development)
- [Command-Line Interface (CLI)](#command-line-interface-cli)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Synthetic Evaluation & Benchmarks](#synthetic-evaluation--benchmarks)
- [Security & Privacy Considerations](#security--privacy-considerations)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [Sponsorship](#sponsorship)
- [License](#license)

---

## Problem Statement

When digital files are corrupted or truncated—due to interrupted network transfers, sudden power failures, drive corruption, or incomplete storage carving—standard tools typically exhibit one of two failure modes:
1. **Fragile Rejection**: The file is rejected entirely because a header, cross-reference table, or closing delimiter is missing, even if 99% of the underlying payload is intact.
2. **Silent Corruption / False Recovery**: The tool dumps raw bytes or pads corrupted data, producing files that crash viewer software or falsely report complete recovery without disclosing that critical internal blocks were destroyed.

A reliable recovery workflow must provide definitive answers to essential questions:
- Which bytes originate directly from surviving evidence?
- Which bytes were added as structural framing to restore file readability?
- Which regions remain unrecovered or missing?
- Did the repaired structure pass strict, format-compliant parser validation?
- Where does uncertainty remain?

Recoverix answers these questions through deterministic reconstruction, strict mathematical accounting, and independent parser validation.

---

## How Recovery and Validation Work

Recoverix processes evidence through three disciplined, reproducible phases:

```text
Evidence Input ───► [1. Identify & Carve] ───► [2. Deterministic Reconstruct] ───► [3. Validate & Audit] ───► Output ($V/R/M$)
```

### 1. Identify & Carve
- Scans input streams for authentic format magic bytes and structural signatures.
- Resolves candidate start and end boundaries without cross-candidate contamination.
- Isolates candidate fragments and records physical file offsets.

### 2. Deterministic Reconstruct
- Evaluates candidate integrity against format specifications.
- Restores missing structural framing when deterministically derivable:
  - Closes unclosed JSON container delimiters (`}`, `]`) based on open bracket stacks.
  - Reconstructs missing PDF cross-reference (`xref`) tables and trailer dictionaries from surviving indirect objects.
  - Synthesizes missing ZIP Central Directories and End of Central Directory (`EOCD`) records from surviving local file headers.
  - Restores missing container footers (PNG `IEND`, JPEG `EOI`).
  - Normalizes ragged CSV trailing records and UTF-8 multi-byte boundaries.
- Rejects candidate reconstruction when essential structural markers are irrecoverable.

### 3. Validate & Audit
- Tests recovered candidates against independent third-party parsers (`Pillow`, `zipfile`, `xml.etree`, `json`).
- Verifies checksums (CRC-32 for PNG and ZIP members).
- Audits verified ($V$), reconstructed ($R$), and missing ($M$) byte counts against physical evidence inputs.

---

## Byte-Level Provenance Accounting ($V / R / M$)

To ensure total transparency, Recoverix categorizes every byte into one of three strict classifications:

| Symbol | Classification | Definition | Examples |
| :---: | :--- | :--- | :--- |
| **$V$** | **Verified Bytes** | Original bytes directly present in and proven by the uploaded evidence. | Surviving image scanlines, intact text records, genuine PDF indirect objects, intact compressed DEFLATE blocks. |
| **$R$** | **Reconstructed Bytes** | Deterministic structural framing bytes added by the engine to restore parser compliance. | Synthesized xref tables, appended closing brackets (`]}`), restored `IEND` or `EOI` markers. |
| **$M$** | **Missing Bytes** | Original payload bytes that were unobserved, truncated, or overwritten and cannot be established from evidence. | Destroyed sectors between fragments, truncated payload blocks, lost rows. |

### Mathematical Invariants

Every recovery operation enforces two strict conservation identities:

$$\text{Total Input Bytes} = V + M$$

$$\text{Total Output Bytes} = V + R$$

- **Reconstructed bytes ($R$) are NOT original evidence**: Structural additions allow applications to open the file, but they do not recover unobserved data.
- **Structural validity does NOT imply completeness**: A file may be structurally valid and open cleanly in an application while still missing internal data ($M > 0$).
- **No Hallucinated Fill**: When bytes are missing ($M > 0$), Recoverix does not fabricate replacement contents. The missing region is explicitly documented in the recovery report.

---

## Supported Formats & Capabilities

Recoverix implements dedicated reconstruction algorithms and independent validators for eight file formats:

| Format | Extension | Deterministic Recovery Actions | Independent Validation Method | Format-Specific Limitations |
| :--- | :--- | :--- | :--- | :--- |
| **PDF** | `.pdf` | Rebuilds missing or broken cross-reference (`xref`) tables from indirect objects; synthesizes missing `/Trailer` dictionaries. | Object catalog verification; xref table parse check. | Compressed object streams (`/ObjStm`) and cross-reference streams (`/XRef`) introduced in PDF 1.5+ are not decompressed. |
| **JSON** | `.json` | Analyzes delimiter stack; deterministically appends required closing delimiters (`]`, `}`) to balance truncated container structures. | Strict standard library `json.loads` parsing. | Truncated string values, cut-off numeric literals, or corrupted keys cannot be guessed and are safely rejected. |
| **CSV** | `.csv` | Detects cell/row delimiters; balances ragged trailing rows; isolates non-tabular noise. | Dialect sniffing and uniform column-count validation. | Missing intermediate columns or destroyed cell values cannot be inferred. |
| **TXT** | `.txt` | Detects text continuity; trims incomplete multi-byte UTF-8 sequences; isolates binary garbage zones. | Strict UTF-8 / ASCII encoding compliance. | Corrupted intermediate characters cannot be restored to original codepoints. |
| **XML** | `.xml` | Parses nested element hierarchies; closes unclosed element stacks; synthesizes root element wrappers if omitted. | Strict `xml.etree.ElementTree` parsing with external entity expansion disabled. | Corrupted tag names or missing attributes cannot be guessed; external DTD entities rejected for safety. |
| **PNG** | `.png` | Validates chunk headers (`IHDR`, `IDAT`); validates CRC-32 checksums; appends missing `IEND` footer chunks. | Strict `Pillow` image header and stream parsing. | Corrupted `IDAT` compressed scanline streams cannot be repaired without original DEFLATE stream blocks. |
| **JPEG** | `.jpg`, `.jpeg` | Validates Start of Image (`SOI`, `0xFF 0xD8`); parses Start of Scan (`SOS`) streams; appends missing End of Image (`EOI`, `0xFF 0xD9`) markers. | Strict `Pillow` image decoding and marker verification. | Corrupted entropy-coded scan data cannot be reconstructed without original DCT coefficients. |
| **ZIP** | `.zip` | Parses local file headers; verifies member CRC-32 checksums; deterministically synthesizes missing Central Directory and `EOCD` records from intact local headers. | Strict `zipfile.ZipFile` verification with Zip-Slip path traversal defense. | Truncated or corrupted member payload streams cannot be decompressed. |

---

## Core Architecture

```text
User Request (Browser or CLI)
      │
      ▼
Input Validation & Size Guard (Max 5 MiB)
      │
      ▼
Format Identification (Magic Signatures & Boundaries)
      │
      ▼
Candidate Isolation & Boundary Analysis
      │
      ▼
Deterministic Reconstruction Engine
  ├── PDF: XRef & Trailer Synthesizer
  ├── JSON: Delimiter Stack Balancer
  ├── CSV: Tabular Normalizer
  ├── TXT: UTF-8 Boundary Aligner
  ├── XML: Element Stack Balancer
  ├── PNG / JPEG: Header / Footer Reconstructor
  └── ZIP: Central Directory Synthesizer
      │
      ▼
Independent Validator Verification (Pillow / zipfile / xml / json)
      │
      ▼
Byte-Level Provenance Accounting (V / R / M Verification)
      │
      ▼
Confidence Scoring & Classification (FULLY_RECOVERED, PARTIALLY_RECOVERED, UNRECOVERABLE)
      │
      ▼
Output Delivery (Direct Web Download / CLI Export)
```

---

## Technology Stack

- **Backend Runtime**: Python 3.10+, FastAPI, Uvicorn, Pydantic v2
- **Forensic Parsers & Validators**: Standard Library (`zipfile`, `xml.etree`, `json`, `csv`, `zlib`), Pillow (`PIL`)
- **Storage & Lifecycle**: Ephemeral container SQLite (`/app/data/recoverix.db`), 24-hour retention purge worker
- **Frontend Framework**: Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Lucide Icons
- **Deployment Topology**: Vercel (Next.js Frontend) + Render Free Tier (FastAPI Docker Backend)

---

## Project Structure

```text
recoverix/
├── backend/
│   ├── app/
│   │   ├── api/                 # FastAPI endpoints (/api/recover-file, /health, /api/cases)
│   │   ├── forensics/           # Core forensic recovery pipeline & tracing
│   │   ├── models/              # Pydantic data models (artifacts, provenance, recovery run)
│   │   ├── recovery/            # Deterministic format reconstructors & validators
│   │   │   ├── reconstructors/  # Format-specific reconstructors (PDF, JSON, CSV, TXT, XML, PNG, JPEG, ZIP)
│   │   │   └── validators/      # Independent structural validators & security guards
│   │   ├── storage/             # SQLite store and 24-hour TTL purge lifecycle
│   │   └── main.py              # Application entrypoint & CORS security configuration
│   └── cli.py                   # Standalone CLI entrypoint (`recoverix`)
├── frontend/                    # Next.js 16 (App Router) Web Interface
│   ├── app/                     # App router routes (/, /cases, /dashboard, /investigation)
│   ├── components/              # UI components (EvidenceUpload, visual byte maps)
│   ├── lib/                     # API client, download URL sanitizer, and types
│   └── next.config.ts           # Dynamic same-origin proxy rewrite configuration (/backend-api)
├── benchmark/                   # Forensic evaluation benchmarks & synthetic test suites
├── docs/                        # Deployment guides and technical documentation
├── tests/                       # Automated unit, regression, parser, and security test suites
├── Dockerfile.backend           # Container configuration for FastAPI backend
├── render.yaml                  # Render Infrastructure-as-Code Blueprint
├── pyproject.toml               # Python package configuration and CLI console script
└── README.md                    # Project documentation
```

---

## Getting Started & Local Development

### Prerequisites

- **Python**: Version 3.10, 3.11, 3.12, 3.13, or 3.14
- **Node.js**: Version 18.x, 20.x, or 22.x
- **npm**: Version 9.x+

### 1. Clone the Repository

```bash
git clone https://github.com/WHYBLANCKK/recoverix.git
cd recoverix
```

### 2. Set Up and Run the Backend

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package and dependencies in editable mode
pip install -e ".[dev]"

# Start the backend server on local loopback
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify backend health at:
```text
http://127.0.0.1:8000/health
```

### 3. Set Up and Run the Frontend

In a separate terminal:

```bash
cd frontend

# Install dependencies
npm install

# Start Next.js development server
npm run dev
```

Open your browser to:
```text
http://127.0.0.1:3000
```

---

## Command-Line Interface (CLI)

Recoverix includes a standalone command-line interface for offline evidence carving, structural reconstruction, and artifact export:

```bash
# Run via python module
python3 -m backend.cli recover damaged_doc.pdf --out ./recovered

# Or run via installed console script
recoverix recover damaged_image.png -o ./recovered_artifacts
```

### CLI Arguments & Options

```text
usage: recoverix recover [-h] [-o OUT] [--json] file_path

positional arguments:
  file_path             Path to damaged evidence file to carve and reconstruct

options:
  -h, --help            show this help message and exit
  -o OUT, --out OUT     Destination directory for recovered files (default: current directory)
  --json                Output recovery results and V/R/M byte accounting in JSON format
```

### Exit Codes

| Exit Code | Classification | Meaning |
| :---: | :--- | :--- |
| `0` | `SUCCESS` | File was successfully recovered (`FULLY_RECOVERED` or `PARTIALLY_RECOVERED`) and written to disk. |
| `1` | `UNRECOVERABLE` | Evidence is unrecoverable from available bytes; no output file is written. |
| `2` | `OPERATIONAL_ERROR` | File not found, permission error, input exceeds 5 MiB limit, destination file exists, or invalid arguments. |

### CLI Safety Guarantees

- **No Overwrite**: The CLI will never overwrite existing destination files.
- **Path Traversal Defense**: Output paths are sanitized to strict basenames.
- **Zero Artifact on Failure**: If evidence is unrecoverable, no partial or corrupted file is created on disk.

---

## Testing & Quality Assurance

Recoverix maintains a comprehensive automated test suite verifying format reconstructors, independent third-party parsers, boundary isolation, CORS security, proxy spoofing defenses, and retention lifecycles:

```bash
# 1. Run the full Python test suite
PYTHONDONTWRITEBYTECODE=1 pytest tests/ -q

# 2. Run the 8-format matrix and consumer web workflow tests
pytest tests/test_consumer_web_workflow.py -v

# 3. Run CORS and API network exposure security tests
pytest tests/test_cors_and_api_exposure.py -v

# 4. Run the frontend TypeScript type check
npx --prefix frontend tsc -p frontend/tsconfig.json --noEmit

# 5. Run the frontend production build
npm --prefix frontend run build
```

---

## Synthetic Evaluation & Benchmarks

Recoverix evaluates its algorithms against reproducible synthetic control images with mathematically established ground truth.

> [!NOTE]
> All evaluation fixtures are synthetic, deterministic controls with known ground truth. Recoverix does not represent synthetic control fixtures as real-world evidence and makes no claim of universal real-world performance without measured validation on genuine external corpora.

### 1. Baseline Recovery Benchmark (`benchmark.run_baseline`)
Evaluates candidate detection, boundary isolation, and spatial provenance across 6 core scenarios:
```bash
python3 -m benchmark.run_baseline
```
*Result:* **6 / 6 scenarios passed**, 0 forensic accounting violations.

### 2. Marker-Free JSON Benchmark (`benchmark.json_benchmark`)
Evaluates syntax-boundary candidate discovery, bracket-closure reconstruction, and noise resistance without synthetic framing delimiters:
```bash
python3 -m benchmark.json_benchmark
```
*Result:* **6 / 7 scenarios passed**, 1 documented limitation (`UNACCOUNTED_GAP` on physical loss).

### 3. Empirical Validation Corpus Benchmark (`benchmark.run_realworld`)
Evaluates multi-format file recovery, structural validation, and strict $V/R/M$ accounting across 15 controlled scenarios:
```bash
python3 -m benchmark.run_realworld --manifest benchmark/evaluation_corpus/manifest.json
```
*Result:* **15 / 15 status matched (100% accuracy)**, **4 / 4 exact hash matches on intact evidence**, 0 false positives, 0 false negatives.

---

## Security & Privacy Considerations

Recoverix is architected as an open-source recovery tool. Deployments must consider the following technical security parameters:

### Authentication & Authorization Disclosures
- **No Built-In Authentication**: Recoverix contains **no built-in user accounts, passwords, API keys, or session management**.
- **Public Network Exposure**: Binding the backend to `0.0.0.0` or exposing port 8000 directly to the public internet allows any network client to upload files and download recovered artifacts. Network deployments must be protected by an authenticating reverse proxy (e.g. Cloudflare Access, OAuth2-Proxy, Nginx with mTLS or HTTP Basic Auth) and TLS termination.

### Recovered-Artifact SHA-256 Integrity & Provenance Semantics
- **Creation Hashes vs. Legacy Backfilled Hashes**: For newly recovered artifacts (Pipeline A case analysis and Pipeline B standalone file recovery), SHA-256 digests are computed and persisted at creation time directly over the recovered binary payload before storage. For legacy pre-Step 6 database records where `sha256` was `NULL`, schema initialization performs a deterministic, snapshot-in-time backfill from persisted blobs (strictly prioritizing canonical `artifact:{id}` keys over unmigrated keys, and rejecting ambiguous collisions with evidence files).
- **Integrity Verification vs. Authorization Boundary**: Recovered artifact SHA-256 verification provides cryptographic payload tampering and bit-rot detection at download time (fail-closed HTTP 404 with detail `Integrity verification failed for artifact '{id}'` if persisted bytes diverge from the recorded digest). **SHA-256 integrity verification is not user authentication or tenant/case authorization**. Any network client with access to an artifact ID or case ID can request its download; access isolation must be enforced by upstream authenticating proxies.

### Input Bounds & Defense Against Resource Exhaustion
- **Input Size Bound**: Strictly enforced at **5 MiB (5,242,880 bytes)** across both the CLI and web endpoints. Files exceeding this limit are rejected immediately with HTTP 413 (`FILE_TOO_LARGE`).
- **Empty File Rejection**: 0-byte submissions are rejected immediately with HTTP 400 (`EMPTY_FILE`).
- **Rate Limiting**: The public API enforces an IP-based rate limit of 60 requests per minute to prevent resource exhaustion.
- **XXE Defense**: The XML validator parses content with external entity resolution strictly disabled.
- **Zip-Slip Defense**: The ZIP parser and CLI sanitize extracted filenames to prevent directory traversal outside destination folders.

### Data Storage & Retention Lifecycle
- **Ephemeral Storage**: Uploaded files and recovered artifacts are stored in an ephemeral SQLite database (`/app/data/recoverix.db`) on the container filesystem. Render free-tier containers do not use persistent disks; container redeployments, restarts, and host recycling reset the local storage.
- **24-Hour Time-to-Live (TTL) Purge**: The backend runs an automated purge worker on startup and hourly during execution (`store.purge_expired_recovered_files(ttl_hours=24)`) that deletes standalone artifacts older than 24 hours.
- **Best-Effort Deletion**: Deletion is handled via periodic batch sweeps within the 24-hour retention window. Recoverix is not a permanent storage vault; users must download recovered files immediately upon completion.

---

## Known Limitations

Recoverix is an evolving open-source engineering prototype. Key limitations include:

1. **No Content Hallucination**: Missing text, data, or media cannot be guessed. If unobserved data was destroyed, it remains missing ($M$).
2. **Compressed PDF Streams**: Compressed object streams (`/ObjStm`) and cross-reference streams (`/XRef`) introduced in PDF 1.5+ are not decompressed.
3. **Severe Payload Corruption**: Overwritten disk sectors, zeroed-out blocks, or heavily truncated media streams cannot be restored.
4. **Reconstruction Ambiguity**: When multiple distinct reconstructions are mathematically possible, Recoverix preserves ambiguity rather than making an arbitrary choice.
5. **No Formal Legal Admissibility**: Recoverix makes no claim of legal admissibility in judicial proceedings or formal compliance with forensic laboratory accreditation standards (e.g. ISO/IEC 17025).

---

## Contributing

Contributions to Recoverix are welcome. As an evidence-driven open-source project, all contributions must adhere to our core standards:

1. **Deterministic First**: PRs must not introduce probabilistic guessing, heuristic content generation, or generative AI models to fill missing bytes.
2. **Strict $V / R / M$ Accounting**: New reconstructors must accurately track verified evidence ($V$), reconstructed framing ($R$), and missing bytes ($M$).
3. **Security Invariants**:
   - Reconstructors must be bounded against infinite loops, recursive stack overflows, and memory bombs.
   - All input paths and filenames must be sanitized to safe basenames.
4. **Test Requirements**:
   - New reconstructors or validators must include unit tests covering intact, repairable, and unrecoverable fixtures.
   - The full test suite (`pytest tests/`) and frontend build (`npm run build`) must pass cleanly.
5. **Contribution Workflow**:
   - Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
   - Run tests locally before submitting.
   - Open a Pull Request targeting `recoverix/staging-candidate` (or `main`) with a clear description of the change and test verification evidence.

---

## Sponsorship

If you find Recoverix valuable for digital forensics, incident response, or verifiable file recovery research, consider supporting ongoing development through GitHub Sponsors:

- **GitHub Sponsors**: [https://github.com/sponsors/WHYBLANCKK](https://github.com/sponsors/WHYBLANCKK)

Sponsorship supports ongoing maintenance, format parser improvements, automated test infrastructure, and research into non-probabilistic evidence recovery.

---

## License

Recoverix is open-source software licensed under the [MIT License](LICENSE).
