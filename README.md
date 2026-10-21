<p align="center">
  <img src="docs/assets/recoverix-banner.png" alt="Recoverix — Deterministic Digital Evidence Recovery" width="680" style="max-width: 100%; height: auto;" />
</p>

<p align="center">
  <strong>Deterministic Digital Evidence Recovery &amp; Structural Reconstruction Engine</strong>
  <br />
  <em>Recoverix does not guess what was lost. It proves what can be recovered.</em>
</p>

<p align="center">
  <a href="https://github.com/WHYBLANCKK/recoverix/actions/workflows/ci.yml"><img src="https://github.com/WHYBLANCKK/recoverix/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10+-brightgreen.svg" alt="Python: 3.10+" /></a>
  <a href="https://nextjs.org/"><img src="https://img.shields.io/badge/Next.js-16-black.svg" alt="Next.js: 16" /></a>
</p>

<p align="center">
  <a href="https://recoverix-staging.vercel.app/"><strong>Live Staging</strong></a> •
  <a href="https://github.com/WHYBLANCKK/recoverix"><strong>GitHub Repository</strong></a> •
  <a href="https://github.com/sponsors/WHYBLANCKK"><strong>Sponsor Recoverix</strong></a>
</p>

---

## What Is Recoverix?

Recoverix is an open-source digital forensics and file recovery tool designed to inspect damaged or truncated files and deterministically reconstruct readable structures when surviving evidence supports it. When a file transfer drops, a process terminates mid-write, or filesystem corruption occurs, critical structural framing—such as closing brackets, cross-reference tables, or container headers—is often lost while the underlying data remains intact.

Unlike conventional carving tools or generative models that attempt to guess missing content or emit silent corruption, Recoverix operates on strict mathematical accounting. It never invents or hallucinates missing payload bytes. Every recovered file is validated against native format parsers, and the engine explicitly discloses what was verified from original evidence, what was reconstructed for parser compliance, and what remains unrecoverable.

---

## How It Works

Recoverix processes evidence through three disciplined, reproducible steps:

1. **Identify:** Scan the raw input stream for authentic format magic bytes, structural signatures, and candidate boundaries without cross-format contamination.
2. **Reconstruct:** Deterministically restore broken structural framing (such as unclosed JSON/XML container delimiters, missing PDF cross-reference tables, or truncated archive headers) strictly derived from surviving metadata.
3. **Validate & Report:** Verify the candidate with independent third-party parsers, compute SHA-256 integrity digests, and generate an exact $V / R / M$ byte accounting breakdown.

---

## Supported Formats

Recoverix provides dedicated reconstruction engines and independent validators for eight formats:

| Format | Extension | Supported Deterministic Recovery Behavior |
| :--- | :--- | :--- |
| **PDF** | `.pdf` | Rebuilds missing or broken cross-reference (`xref`) tables and trailer dictionaries from surviving indirect objects. |
| **JSON** | `.json` | Analyzes nesting stacks and deterministically appends required closing delimiters (`]`, `}`) to balance truncated structures. |
| **CSV** | `.csv` | Sniffs delimiters, repairs unclosed quotes, balances ragged trailing rows, and strips non-tabular noise. |
| **TXT** | `.txt` | Carves contiguous text spans, normalizes line endings, and cleanly preserves surviving multi-byte UTF-8 boundaries. |
| **XML** | `.xml` | Balances open tag hierarchies and synthesizes missing closing tags while enforcing strict XXE entity defenses. |
| **PNG** | `.png` | Validates `IHDR`/`IDAT` chunk streams, recalculates CRCs, drops corrupt ancillary chunks, and synthesizes missing `IEND` footers. |
| **JPEG** | `.jpg`, `.jpeg` | Validates `SOI` and `SOF` frame headers, trims trailing garbage after `SOS` image scans, and appends missing `EOI` markers. |
| **ZIP** | `.zip` | Reconstructs missing Central Directory and `EOCD` records from surviving local file headers with Zip-Slip path protection. |

> Detailed format audit reports and boundary verification specs are documented in [`docs/reports/recoverix_step6c_engine_audit_report.md`](docs/reports/recoverix_step6c_engine_audit_report.md).

---

## Transparent Recovery: V / R / M

Recoverix categorizes every byte into one of three strict classifications:

- **$V$ (Verified):** Original bytes directly present in and proven by the submitted evidence.
- **$R$ (Reconstructed):** Minimal structural framing added deterministically by the engine to satisfy parser compliance. *Reconstructed bytes are not original evidence.*
- **$M$ (Missing):** Unobserved, destroyed, or truncated bytes that cannot be established from the evidence.

These categories satisfy dual conservation identities:

$$\text{Total Input Bytes} = V + M \qquad\text{and}\qquad \text{Total Output Bytes} = V + R$$

> [!NOTE]
> Structural validity does not imply semantic completeness. A file may parse cleanly in an application while still missing internal data ($M > 0$). Recoverix explicitly documents unrecovered gaps rather than synthesizing speculative content.

---

## Quick Start

### Prerequisites
- **Python**: 3.10+
- **Node.js**: 18+ (for frontend workspace)

### 1. Local Setup

```bash
# Clone the repository
git clone https://github.com/WHYBLANCKK/recoverix.git
cd recoverix

# Set up and start the backend server
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000

# In a separate terminal, start the Next.js frontend
cd frontend
npm install
npm run dev
```

The web workspace is available at `http://127.0.0.1:3000`.

### 2. Standalone CLI

Recoverix can also be run entirely offline from the command line:

```bash
# Recover a damaged file directly
recoverix recover damaged_doc.pdf --out ./recovered

# Export machine-readable JSON recovery metadata
recoverix recover corrupted_data.json -o ./output --json
```

For zero-cost staging deployment instructions (Vercel + Render), see the [Staging Deployment Guide](docs/DEPLOYMENT_GUIDE.md).

---

## Limitations and Security

- **No Content Guessing:** Overwritten disk sectors, zeroed-out blocks, or heavily truncated media streams cannot be recreated. If authentic data was destroyed, it remains missing ($M$).
- **Format Limitations:** Compressed PDF object streams (`/ObjStm`) and cross-reference streams (`/XRef`) introduced in PDF 1.5+ are not decompressed. Severely corrupted image scanlines cannot be repaired without surviving entropy-coded blocks.
- **Deployment Security:** Recoverix does not include multi-tenant user authentication or account management. Deployments on untrusted networks must use an authenticating reverse proxy with TLS.
- **Bounded Ingestion:** Requests are strictly capped at 5 MiB (`MAX_EVIDENCE_SIZE`) with rate limiting and automated 24-hour ephemeral retention purges.
- **No Formal Accreditation:** Recoverix is an open-source engineering tool and makes no claim of formal judicial admissibility or ISO/IEC 17025 laboratory accreditation.

---

## Testing

Run the automated backend test suite and frontend production checks:

```bash
# Run backend unit, integration, and security tests
pytest tests/ -q

# Run frontend linting, type checking, and production build
cd frontend
npm run lint
npx tsc --noEmit
npm run build
```

Synthetic benchmarks and empirical evaluation corpus runners are available in `benchmark/` (`python3 -m benchmark.run_baseline` and `python3 -m benchmark.run_realworld`).

---

## Contributing

Contributions are welcome. Pull requests must adhere to our core engineering standards:

1. **Deterministic Reconstruction:** No probabilistic guessing, heuristic generation, or generative AI models to fill missing bytes.
2. **Strict $V / R / M$ Accounting:** Accurately classify verified evidence, reconstructed syntax, and missing gaps.
3. **Defensive Bounds:** Enforce bounded execution against recursion bombs and sanitize all output filenames to safe basenames.
4. **Test Verification:** Include tests for intact, repairable, and unrecoverable fixtures. Ensure `pytest tests/` and `npm run build` pass before opening a PR against `main`.

---

## Sponsorship

If you find Recoverix valuable for digital forensics, incident response, or verifiable file recovery research, consider supporting ongoing development:

👉 **[Sponsor @WHYBLANCKK on GitHub Sponsors](https://github.com/sponsors/WHYBLANCKK)**

Sponsorship directly supports maintenance, format parser enhancements, CI test infrastructure, and research into non-probabilistic evidence recovery.

---

## License

Recoverix is open-source software licensed under the [MIT License](LICENSE).
