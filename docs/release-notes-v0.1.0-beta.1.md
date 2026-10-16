# Recoverix v0.1.0-beta.1 Release Notes

**Release Name:** Recoverix v0.1.0-beta.1 (Controlled Public Beta)  
**Date:** October 2026  
**License:** MIT  
**Guiding Principle:** *"Recoverix does not guess what was lost. It proves what can be recovered."*

---

## 1. Overview

Recoverix `v0.1.0-beta.1` is the first public beta release of Recoverix, a deterministic digital evidence recovery, structural reconstruction, and analysis framework. 

Unlike conventional carving tools that rely on guessing, heuristics, or predictive text models to fill damaged regions, Recoverix is built on mathematical forensic accounting. Every recovered byte is classified as **Verified** ($V$), **Reconstructed** ($R$), or **Missing** ($M$), strictly bounded by the invariant:

$$\text{Total Logical Bytes} = V + R + M$$

Reconstructed bytes represent structural repairs (e.g., synthetically regenerated cross-reference tables or closed container delimiters) necessary to make evidence readable by standard parsers. Recoverix never claims reconstructed bytes as original evidence.

---

## 2. Key Capabilities in Beta 1

### Standalone Recovery CLI (`recoverix`)
Carve, reconstruct, and validate damaged files directly without running web servers or background processes:
```bash
# Recover a damaged PDF (auto-reconstructs broken xref tables)
recoverix recover damaged_doc.pdf --out ./recovered_files

# Recover a damaged JSON file with JSON machine-readable summary output
recoverix recover corrupted_data.json -o ./output --json
```

**CLI Safety Invariants:**
* **Non-Overwrite Guarantee:** Never overwrites existing destination files (exits with code 2).
* **Path Traversal Resistance:** Sanitizes input filenames to safe basenames.
* **Bounded Ingestion:** Refuses files larger than 5 MiB or empty files.
* **Failure Guard:** Never writes partial or corrupted files to disk on recovery failure.

### Deterministic Format Reconstruction
* **PDF:** Detects `%PDF-` headers and `%%EOF` markers, parses object streams, reconstructs corrupted cross-reference (`xref`) tables, rebuilds missing trailers, and verifies document hierarchy.
* **JSON:** Discovers candidates using syntax boundaries (without synthetic framing delimiters) and repairs unclosed arrays/objects deterministically.
* **CSV & Plain Text:** Carves contiguous content, verifies delimiter distributions and newline consistency, and isolates damaged sectors.
* **Image & Structured Containers (PNG, JPEG, XML):** Performs signature detection, chunk boundary inspection, and structural validation.

### Full-Stack Investigation Interface
* **FastAPI Backend:** Provides REST endpoints for evidence ingestion, single-file recovery, and SQLite persistence.
* **Next.js Dashboard:** Interactive visual dashboard for browsing evidence cases, inspecting byte provenance graphs, and viewing analysis reports.

### Automated Continuous Integration
* Production GitHub Actions CI (`.github/workflows/ci.yml`) testing on Ubuntu Linux with Python 3.11 and Node.js 20 LTS.
* Automated wheel and source distribution verification on every push and pull request to `main`.

---

## 3. Quickstart & Installation

### Option A: Direct Installation from Wheel or Source
```bash
# Install package and dependencies in editable mode
python3 -m pip install -e ".[dev]"

# Verify CLI
recoverix --help
```

### Option B: Local Full-Stack Development
```bash
# Terminal 1: Backend API
python3 -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2: Frontend Dashboard
cd frontend
npm ci
npm run dev
# Open http://127.0.0.1:3000
```

---

## 4. Verification Suite

The beta release is backed by 1,234 automated tests and reproducible benchmark evaluations:

```bash
# Run pytest regression suite
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest tests/ -q
# Result: 1,234 passed

# Run baseline multi-scenario benchmark
PYTHONDONTWRITEBYTECODE=1 python3 -m benchmark.run_baseline
# Result: 6 / 6 scenarios passed, 0 violations

# Run marker-free JSON recovery benchmark
PYTHONDONTWRITEBYTECODE=1 python3 -m benchmark.json_benchmark
# Result: 6 / 7 scenarios passed, 1 documented limitation (UNACCOUNTED_GAP)
```

---

## 5. Operational Constraints and Disclaimers

1. **5 MiB Ingestion Limit:** Ingestion streams and CLI commands enforce a strict maximum size limit of **5 MiB** (`5,242,880 bytes`).
2. **Local Single-User Security Model:** Recoverix contains no built-in user authentication or role-based access controls. It must run on local loopback (`127.0.0.1`). Any deployment to shared or cloud networks requires an external authenticating reverse proxy and network isolation.
3. **Verified ($V$) vs. Reconstructed ($R$) Bytes:** Structural repairs ($R$) are mathematically and forensically distinct from verified evidence bytes ($V$). Investigators must inspect recovered artifacts before relying on them.
4. **Documented Gap:** The marker-free JSON benchmark retains a documented limitation (`UNACCOUNTED_GAP`) in scenarios where content is lost prior to closers.
5. **No Unsupported Claims:** Recoverix is an open-source research prototype. It does not claim universal file recovery, legal admissibility in court proceedings, or forensic soundness for unvalidated file types.
