# Recoverix

### Deterministic Digital Evidence Recovery and Analysis

Recoverix is a digital evidence recovery and analysis prototype designed to identify, validate, and reconstruct damaged, fragmented, and partially corrupted files.

It combines deterministic recovery algorithms, structural validation, byte-level provenance, recovery scoring, and AI-assisted explanations to make recovery results easier to understand and evaluate.

Recoverix distinguishes between information directly supported by the available evidence, information reconstructed through deterministic procedures, and information that remains missing.

> Recoverix does not guess what was lost. It reconstructs what the evidence supports and makes uncertainty explicit.

## Table of Contents

- [Problem Statement](#problem-statement)
- [Our Approach](#our-approach)
- [Core Architecture](#core-architecture)
- [Key Features](#key-features)
- [Deterministic Recovery](#deterministic-recovery)
- [Byte-Level Provenance](#byte-level-provenance)
- [Recovery Classification](#recovery-classification)
- [Supported File Formats](#supported-file-formats)
- [AI Evidence Analyst](#ai-evidence-analyst)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Command-Line Interface (CLI)](#command-line-interface-cli)
- [Testing](#testing)
- [Synthetic Evaluation](#synthetic-evaluation)
- [Security and Deployment Model](#security-and-deployment-model)
- [Limitations](#limitations)
- [Design Principles](#design-principles)
- [Future Improvements](#future-improvements)
- [License](#license)

## Problem Statement

Damaged or fragmented digital evidence can contain intact data, corrupted regions, missing fragments, or structures that are only partially recoverable.

Finding a file signature or producing an output file does not necessarily mean that the original information has been recovered correctly.

A reliable recovery workflow must answer several questions:

- What artifacts were identified?
- Which bytes are directly supported by the available evidence?
- Which bytes were reconstructed?
- Which information remains missing?
- Did the reconstructed artifact pass structural validation?
- Where does uncertainty remain?

Recoverix addresses these questions through deterministic recovery, structural validation, explicit byte accounting, and transparent recovery reporting.

## Our Approach

Recoverix follows three core stages.

### 1. Recover

Identify candidate artifacts, locate surviving fragments, and attempt reconstruction when the available evidence supports a defined recovery procedure.

### 2. Prove

Validate recovery candidates and record the distinction between verified, reconstructed, and missing bytes.

### 3. Understand

Classify and prioritize artifacts, present recovery results, and provide explanations grounded in deterministic analysis.

The recovery engine remains authoritative. AI-assisted explanations do not replace recovery algorithms or structural validation.

## Core Architecture

```text
Evidence Input
      |
      v
Evidence Ingestion
      |
      v
Format Identification
      |
      v
Candidate Detection
      |
      v
Fragment and Boundary Analysis
      |
      v
Deterministic Recovery
      |
      v
Structural Validation
      |
      v
Byte-Level Provenance (V/R/M)
      |
      v
Recovery Scoring and Classification
      |
      v
Artifact Prioritization
      |
      v
AI-Assisted Explanation
      |
      v
Investigation Interface
```

Each stage has a distinct responsibility. Recovery decisions and byte accounting are established by the deterministic pipeline before the AI explanation layer interprets the results.

## Key Features

### Evidence Ingestion

- Accept evidence files through the application's ingestion workflow.
- Maintain evidence metadata.
- Calculate SHA-256 metadata where implemented.
- Apply configured evidence-size limits.

### File Identification and Candidate Detection

- Identify supported file formats.
- Locate candidate artifacts and fragments.
- Track candidate offsets and sizes.
- Apply format-specific boundary detection.
- Isolate candidates to reduce accidental overlap and cross-candidate contamination.

### Deterministic Reconstruction

- Attempt bounded bifragment reconstruction.
- Apply supported format-specific structural reconstruction.
- Validate reconstruction candidates.
- Preserve ambiguity when the evidence does not establish a unique result.
- Avoid automatically combining unrelated candidates merely because they share a format.

### Structural Validation

- Validate candidates using format-specific checks.
- Reject invalid reconstruction results.
- Handle malformed and truncated input.
- Distinguish successful structural validation from proof that every original byte has been recovered.

### Byte-Level Provenance

Record the contribution of verified, reconstructed, and missing bytes where supported by the recovery pipeline.

### Recovery Scoring and Classification

Evaluate recovery results using the prototype's scoring policy and classify artifacts according to the available recovery evidence.

### Artifact Prioritization

Organize artifacts using the application's classification and prioritization mechanisms.

### AI-Assisted Explanation

Generate natural-language explanations from deterministic analysis results. The AI layer is intended to explain recovery findings rather than generate recovered evidence.

## Deterministic Recovery

Recoverix uses evidence-driven recovery procedures.

### Bounded Bifragment Reconstruction

When two fragments may belong to the same artifact, the reconstruction engine can evaluate possible gap sizes within a configured search range.

```text
Fragment A          Unknown Gap          Fragment B
[Available Bytes]   [Missing Region]     [Available Bytes]
```

The engine evaluates candidate reconstructions using applicable validation rules.

- A uniquely validated candidate may be selected.
- Multiple valid candidates may remain ambiguous.
- Unrelated candidates should remain separate when the evidence does not support combining them.
- A failed reconstruction attempt must not be presented as a successful recovery.

The current implementation supports specific reconstruction scenarios rather than arbitrary reconstruction of all file formats.

### Structural Reconstruction

Some formats permit limited deterministic reconstruction of structural bytes.

For example, an incomplete JSON structure may be eligible for a structural-closure attempt when the implemented recovery rules support it.

Any bytes added by such a procedure must be recorded as reconstructed, not verified.

Recoverix does not claim to recover arbitrary overwritten or unknowable content.

## Byte-Level Provenance

Recoverix distinguishes three categories of artifact bytes.

| Symbol | Category | Meaning |
|---|---|---|
| V | Verified | Bytes directly supported by the available evidence |
| R | Reconstructed | Bytes added by an implemented deterministic reconstruction procedure |
| M | Missing | Bytes that cannot be established from the available evidence |

The logical accounting model is:

```text
Total Logical Artifact Bytes = V + R + M
```

The accounting must not imply that reconstructed bytes were present in the original evidence.

A structurally valid output is not, by itself, proof of complete recovery.

## Recovery Classification

Recoverix uses a prototype confidence-scoring policy to classify recovery results.

| Score | Prototype Status |
|---:|---|
| 85–100 | FULLY_RECOVERED |
| 50–84 | PARTIALLY_RECOVERED |
| 20–49 | CORRUPTED |
| 0–19 | UNRECOVERABLE |

These thresholds are application-specific heuristics, not an established forensic standard.

The final status must also respect recovery completeness. An artifact containing reconstructed or missing bytes must not be classified as fully recovered merely because its output passes structural validation.

## Supported File Formats

The recovery framework includes handling for the following formats:

| Format | Extension | Notes |
|---|---|---|
| Plain Text | TXT | Candidate detection and supported text recovery procedures |
| Comma-Separated Values | CSV | Candidate detection and supported CSV recovery procedures |
| JavaScript Object Notation | JSON | Structural validation and supported structural reconstruction |
| Extensible Markup Language | XML | Format detection and structural validation |
| Portable Network Graphics | PNG | Image signature and bounded image-boundary analysis |
| JPEG Image | JPEG/JPG | Image signature and bounded image-boundary analysis |
| Portable Document Format | PDF | PDF candidate detection and supported recovery procedures |

Support does not mean that every damaged file can be reconstructed.

Detection, carving, validation, and reconstruction capabilities vary by format. Recovery results depend on the available evidence and the specific recovery procedure implemented for that format.

## AI Evidence Analyst

The AI evidence analyst operates as an interpretation layer over deterministic recovery results.

Depending on the implemented integration, it may help provide:

- Recovery summaries.
- Explanations of detected damage.
- Artifact descriptions.
- Classification context.
- Investigator-oriented interpretations of recovery findings.

The AI layer must not:

- Invent recovered evidence bytes.
- Predict missing file contents and present them as recovered.
- Override deterministic validation results.
- Modify verified, reconstructed, or missing byte accounting.
- Independently declare a reconstruction valid.

AI explanations should remain grounded in the results supplied by the deterministic pipeline.

## Technology Stack

### Frontend

- Next.js
- React
- TypeScript
- Tailwind CSS

### Backend

- Python
- FastAPI
- Uvicorn

### Recovery Engine

- Custom deterministic scanners.
- File-format validators.
- Fragment analysis.
- Bounded reconstruction algorithms.
- Recovery scoring and provenance logic.

### Testing and Development

- Pytest
- TypeScript compiler checks.
- Automated recovery regression tests.
- Synthetic evidence generation.
- Git and GitHub.

The exact runtime requirements and optional integrations are determined by the repository's dependency and configuration files.

## Project Structure

```text
recoverix/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── generator/
│   │   ├── ingestion/
│   │   ├── models/
│   │   ├── recovery/
│   │   ├── scoring/
│   │   ├── main.py
│   │   └── store.py
│   ├── generate_case.py
│   └── ...
├── frontend/
│   ├── app/
│   ├── components/
│   ├── lib/
│   └── ...
├── tests/
├── docs/
├── .gitignore
└── README.md
```

This is a high-level overview. Individual modules and filenames may change as development continues.

## Getting Started

### Prerequisites

Install the versions of Python, Node.js, and npm supported by the repository's dependency and configuration files.

### 1. Clone the Repository

```bash
git clone https://github.com/c-zerooo/recoverix.git
cd recoverix
```

### 2. Start the Backend

From the repository root, run:

```bash
python3 -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend is expected to be available at:

```text
http://127.0.0.1:8000
```

### 3. Start the Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend is expected to be available at:

```text
http://127.0.0.1:3000
```

### 4. Run the Tests

From the repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/ -v
```

The `PYTHONDONTWRITEBYTECODE=1` setting prevents Python from writing new bytecode files during the test run.

Consult the repository configuration and dependency files if additional setup is required.

## Command-Line Interface (CLI)

Recoverix provides a standalone command-line interface (`recoverix` / `python3 -m backend.cli`) that enables direct file carving, deterministic reconstruction, structural validation, and artifact export without running FastAPI, Uvicorn, or the Next.js frontend.

### Installation and Invocation

You can run the CLI directly from the repository using Python, or as an installed console script:

```bash
# Direct module invocation from repo root
python3 -m backend.cli --help

# Or via installed console script
python3 -m pip install -e .
recoverix --help
```

### Basic Usage

Carve and recover a damaged evidence file to a destination directory:

```bash
# Recover a damaged PDF (auto-reconstructs xref tables and missing trailers)
python3 -m backend.cli recover damaged_doc.pdf --out ./recovered

# Recover a damaged JSON file with short flag -o
python3 -m backend.cli recover corrupted_data.json -o ./recovered_artifacts

# Output machine-readable JSON summary for automated pipelines
python3 -m backend.cli recover evidence.dat -o ./output --json
```

### Exit Codes

The CLI returns standard exit codes suitable for CI/CD pipelines, shell scripts, and automated ingestion workflows:

| Exit Code | Meaning | Description |
|:---:|---|---|
| `0` | Recovery Successful | A valid artifact was recovered (`FULLY_RECOVERED` or `PARTIALLY_RECOVERED`) and written to the output directory. |
| `1` | Unrecoverable / Corrupted | The evidence is unrecoverable from available bytes; no artifact file is written. |
| `2` | Operational Error | Input file not found, permission denied, file empty or exceeds 5 MiB limit, target output file already exists, path traversal detected, or invalid arguments. |

### Output Files and Safety Invariants

- **Non-Overwrite Guarantee:** Recoverix writes recovered artifacts as `recovered_<original_filename>` inside the specified `--out` directory. To prevent accidental evidence loss or tampering, the CLI will refuse to overwrite an existing file (exiting with code `2`).
- **Path Traversal Protection:** Input filenames are strictly sanitized to basenames before constructing the destination path. Attempts to traverse outside the target directory are rejected.
- **Bounded Ingestion:** Evidence files are bounded by `MAX_EVIDENCE_SIZE` (5 MiB). Files larger than 5 MiB or 0-byte files are rejected before processing.
- **No Artifact on Failure:** If recovery status is `UNRECOVERABLE` or zero recoverable bytes are produced, no output file is written.

### Understanding the Recovery Summary

Upon execution, Recoverix displays a forensic accounting summary:

```text
════════════════════════════════════════════════════════════════════════
  RECOVERIX — FORENSIC FILE RECOVERY SUMMARY
════════════════════════════════════════════════════════════════════════
  Input File         : damaged_doc.pdf (1,420 bytes)
  Detected Format    : pdf
  Recovery Status    : PARTIALLY_RECOVERED
  Validation Status  : PASSED
  Verified Bytes     : 1,218 bytes (intact evidence bytes)
  Reconstructed Bytes: 202 bytes (structural repair bytes)
  Missing Bytes      : 0 bytes (unrecovered damage)
  Reconstruction     : RECONSTRUCT_PDF_XREF
  Output File        : /path/to/recovered/recovered_damaged_doc.pdf (1,420 bytes written)
────────────────────────────────────────────────────────────────────────
  Notice: Artifact was partially recovered. Reconstructed or missing bytes exist;
  reconstructed bytes represent structural repairs (e.g. delimiters, xref tables),
  not original verified content. Inspect output before forensic reliance.
════════════════════════════════════════════════════════════════════════
```

> **Forensic Notice:** Reconstructed bytes ($R$) represent synthetically repaired structural elements (such as regenerated PDF cross-reference tables or closed JSON delimiters), not verified original payload bytes ($V$). Always inspect recovered artifacts before relying on them for forensic investigations.

## Testing

Recoverix includes automated tests covering areas such as:

- Evidence generation.
- Evidence ingestion.
- Format identification.
- Fragment scanning.
- Candidate-boundary isolation.
- Contiguous carving.
- Structural validation.
- Bifragment reconstruction.
- Reconstruction ambiguity.
- Byte-level provenance.
- Recovery scoring.
- PDF recovery.
- Text and CSV recovery.
- JSON structural reconstruction.
- API behavior.
- Malformed and truncated input.
- Recovery failure handling.

Regression tests are particularly important for preventing unrelated candidates from being combined and for ensuring that malformed files do not cause recovery logic to claim unsupported bytes.

Run the complete backend test suite with:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/ -v
```

## Synthetic Evaluation

Recoverix uses controlled synthetic evidence scenarios to evaluate recovery behavior.

Example scenario categories include:

- Clean evidence.
- Deleted artifacts.
- Fragmented artifacts.
- Bifragmented artifacts.
- Corrupted artifacts.
- Unrecoverable artifacts.

Synthetic generation and ground-truth information are intended for testing and evaluation. Ground truth must remain separate from the production recovery decisions.

Evaluation results should be reported with the command, seed, scenario coverage, and test results used to obtain them. A successful synthetic benchmark does not establish performance on every real-world evidence source.

## Security and Deployment Model

Recoverix is architected as a **local single-user forensic recovery workstation tool**. It does **not** provide built-in user accounts, passwords, API tokens, session management, or role-based access controls (RBAC).

### Supported Deployment Modes

1. **Local Development / Single-User Workstation (Recommended)**
   - The backend runs on loopback (`http://127.0.0.1:8000`) and the frontend runs on loopback (`http://127.0.0.1:3000`).
   - CORS is restricted by default to local origins (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:8000`, `http://127.0.0.1:8000`).
   - Browsers prevent arbitrary third-party websites from reading evidence data or executing cross-origin API calls.

2. **Local Desktop / Container Deployment (`docker compose`)**
   - Services are published on the host loopback adapter (`127.0.0.1:8000` and `127.0.0.1:3000`), preventing port exposure across LAN or public network interfaces.
   - CORS origins are configured via `RECOVERIX_CORS_ORIGINS`.

3. **Network-Accessible Deployment (Shared Server or Cloud)**
   - **Important:** Recoverix does not implement authentication. Binding the backend to `0.0.0.0` or exposing port 8000 directly to a local network or the internet allows anyone with network connectivity to view cases, upload evidence, and download recovered payloads.
   - Exposing Recoverix to an untrusted or multi-user network requires an external security perimeter:
     - **Authenticating Reverse Proxy:** Deploy an identity-aware proxy (e.g. OAuth2-Proxy, Cloudflare Access, AWS ALB OIDC, or Nginx with HTTP Basic/mTLS) in front of the API.
     - **Network Isolation:** Restrict access via VPN (e.g. WireGuard, Tailscale) or firewall rules.
     - **TLS Termination:** Terminate HTTPS at the gateway.
     - **Request Size Limiting:** Enforce reverse-proxy upload size limits (`client_max_body_size 6m` in Nginx).
     - **CORS Configuration:** Explicitly configure `RECOVERIX_CORS_ORIGINS` to the domain of the deployed frontend.

### CORS Configuration and Invariants

Browser cross-origin requests are governed by the `RECOVERIX_CORS_ORIGINS` environment variable:
- **Default Loopback Origins:** If unset or blank, Recoverix defaults safely to local loopback origins (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:8000`, `http://127.0.0.1:8000`).
- **Configuring Explicit Origins:** Specify allowed origins as a comma-separated list or JSON array of `scheme://host[:port]` entries with no path, query, or fragment:
  - `RECOVERIX_CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000`
  - `RECOVERIX_CORS_ORIGINS='["http://localhost:3000", "https://forensics.corp.internal"]'`
- **Disabling CORS:** Setting `RECOVERIX_CORS_ORIGINS=none` (or `disabled`, `false`, `0`) disables browser cross-origin requests entirely by omitting CORS headers.
- **Malformed Entry Handling:** Invalid origin formats (e.g., missing scheme, containing path like `/api`, or containing query strings) are filtered out individually.
- **Fallback Behavior:** If all configured entries are malformed or invalid, Recoverix falls back safely to the local loopback defaults rather than failing open or producing an empty/broken state.
- **Wildcard Origins Strictly Rejected:** Wildcard origins (`*`) are rejected by the origin validator. Configuring `RECOVERIX_CORS_ORIGINS=*` will not enable unrestricted CORS; it will be rejected as invalid and fall back to the loopback defaults.
- **CORS Is Not Authentication:** CORS is enforced solely by web browsers to restrict cross-origin JavaScript execution. It provides zero protection against direct HTTP clients (`curl`, scripts) or unauthorized users with network connectivity to the port.
- **No Built-in Authentication:** The API contains no authentication or authorization. Wildcard CORS or exposing the API port to untrusted networks without an authenticating reverse proxy and network isolation must never be permitted.

## Limitations

Recoverix is an evolving prototype, not a validated production forensic platform.

Current limitations include:

- Evidence processing is subject to configured size limits.
- Recovery depends on supported formats and deterministic procedures.
- Arbitrarily overwritten or unknowable bytes cannot be recovered reliably.
- Some reconstruction candidates may remain ambiguous.
- Reconstruction capabilities differ across file formats.
- Confidence thresholds are prototype heuristics, not forensic standards.
- Synthetic evaluation does not establish general real-world recovery accuracy.
- Production deployment requires further security hardening, authentication, storage design, audit controls, scalability work, and independent validation.

Recoverix should not be treated as a substitute for established forensic procedures or tools.

## Design Principles

### Deterministic First

Recovery decisions must be grounded in evidence and reproducible procedures.

### No Invented Evidence

Missing bytes must not be fabricated and represented as original recovered content.

### Explicit Provenance

Recovery results should distinguish verified, reconstructed, and missing information.

### Preserve Ambiguity

When the available evidence cannot distinguish between valid alternatives, the system should preserve that uncertainty.

### Validate Before Accepting

Candidate reconstructions must pass the applicable validation rules before being accepted.

### Isolate Independent Candidates

Candidates should not be combined solely because they share a format or appear near one another.

### Honest Reporting

The system should communicate its limitations and avoid claiming capabilities that have not been implemented and validated.

## Future Improvements

Potential areas for continued development include:

- Making repeated case-analysis requests idempotent.
- Expanding benchmark coverage across file formats.
- Improving evaluation criteria and status-matching checks.
- Extending format-specific reconstruction capabilities.
- Strengthening API security and access controls.
- Improving performance for larger evidence files.
- Adding more reproducible evaluation scenarios.
- Expanding documentation and contributor guidance.

These are development directions, not claims that the features are already implemented.

## Core Statement

> Recoverix does not guess what was lost. It reconstructs only what the available evidence supports, validates the result, and makes the remaining uncertainty explicit.

## License

Recoverix is open-source software licensed under the [MIT License](LICENSE).
