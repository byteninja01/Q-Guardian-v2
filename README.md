# Q-Guardian v2 — Post-Quantum Cryptographic Risk & Migration Platform

Q-Guardian is an enterprise platform that inventories an organisation's real
cryptographic footprint, scores each asset against quantum-era threats, maps
the risk to a migration timeline, and produces a standards-aligned
Cryptographic Bill of Materials (CBOM). It is built for regulated sectors —
banking first — where cryptography must be proven, not assumed.

The platform answers four questions:

1. What cryptography actually exists across our network, source code,
   container images, and compiled binaries?
2. Which assets will break first when a cryptographically relevant quantum
   computer (CRQC) arrives?
3. When must each migration happen, and what does a compliant path look like?
4. Does what we declare about our crypto match what is really deployed?

Unlike manifest-only inventory tools, Q-Guardian scans four independent
evidence vectors — live TLS endpoints, source code, container images, and raw
binaries — then reconciles them into one logical asset inventory. A package
manager may declare a modern OpenSSL, while a compiled binary still embeds a
legacy MD5 table; Q-Guardian surfaces that "declared vs actual" divergence
instead of trusting the SBOM.

---

## Feature Overview

### Multi-source cryptographic discovery

| Source vector | Engine | What it detects |
|---|---|---|
| Network (live TLS) | `discovery.py`, `port_scanner.py`, `active_discovery.py` | Subdomains from certificate-transparency logs (crt.sh), real TLS handshake metadata (protocol, cipher suite, key size, forward secrecy, certificate validity), open TCP ports, and discovered API surface (OpenAPI/Swagger specs, JS-crawled routes, banking-path fuzzing) |
| Static source | `static_analysis.py`, `source_scanner.py`, `rules/crypto.yml` | Cryptographic API calls in source trees with file + line evidence. Native AST/regex engine plus a real Semgrep ruleset derived from the OWASP community crypto rules and extended with algorithm names, key sizes, AES-ECB, and hardcoded-key patterns |
| Container image | `container_scanner.py` | OS/package manifests via Trivy (`trivy fs` / `trivy image`, DB-free offline mode) with Syft and a heuristic layer as fallbacks. Every package/version is cross-checked against a quantum-readiness table (for example OpenSSL >= 3.2.0 and pyca/cryptography >= 42.0.0 are PQC-capable floors) |
| Binary | `binary_scanner.py` | Compiled artifacts (ELF / PE / Mach-O) via LIEF plus byte-level constant matching in `.rodata`: ML-KEM-768 NTT zeta constants (FIPS 203), AES S-box tables, MD5 IV constants, and liboqs PQC interface strings — including in stripped binaries, with evidence offsets |

### Declared-vs-actual reconciliation

Every scan job writes findings into a unified asset schema tagged with its
source (`network-tls`, `static-source`, `container-image`, `binary`).
`reconciler.py` correlates assets across sources, normalises hostnames, and
flags divergence — for example a container that ships modern OpenSSL while
the bundled binary still executes legacy MD5 (`DIV_CONTAINER_MODERN_VS_BINARY_MD5`).
The GUI exposes the divergence filter, an amber topology hub, and a
before/after CBOM diff across the two most recent scan runs.

### Risk scoring and timelines

- **Q-TRI (Quantum Transition Resilience Index)** — a 0-100 score per asset,
  weighted by RBI sensitivity tier (S1-S5). Legacy algorithm families (MD5,
  SHA-1, DES/3DES/RC4, AES-ECB) cap the score via a quantum-signal guard so a
  modern-looking TLS wrapper cannot mask a weak primitive.
- **Mosca countdown engine** — implements the Mosca inequality `X + Y > Z`
  (migration complexity + data shelf life vs. time to CRQC), with fully
  deterministic inputs derived from the real scanned surface. Outputs
  CRITICAL / WARNING / SAFE risk states.
- **Enterprise cyber rating** — a roll-up 0-1000 rating with letter bands
  (A / B-C / D / F) for board-level reporting.
- **HNDL exposure model** — Harvest-Now-Decrypt-Later exposure estimates for
  endpoints without perfect forward secrecy, grounded in tiered traffic
  baselines, with clear advisories that figures are model ceilings, not
  telemetry measurements.

### Cryptographic Bill of Materials (CBOM)

- Native **CycloneDX 1.6 JSON** export generated with `cyclonedx-python-lib`,
  using the ECMA-424 crypto extension (`cryptoProperties`: asset type,
  primitive, algorithm, OID, classical and NIST quantum security levels,
  parameter-set identifiers) per component.
- Every component is source-tagged and carries its evidence (file, line, or
  binary offset), Q-TRI score, PQC flag, and divergence flag as properties.
- PDF export and a run-history diff (added/removed components per source
  vector) for showing improvement between audit runs.

### Compliance mapping

| Framework | Coverage |
|---|---|
| RBI Cyber Security Framework 2.0 | Cryptographic controls mapped only against assets that genuinely carry the relevant primitive (for example TLS findings are limited to TLS-bearing assets) |
| NIST IR 8547 (Nov 2025) | PQC transition milestones T1-T4 with planning deadline chips (discovery/inventory by Dec 2027 through full migration by 2033) |
| India DST National Quantum Mission / TEC | NQM 2023-2031 horizon and TEC quantum-safe cryptography guidance flags |

### Migration playbooks

`migration.py` maps every surfaced algorithm family (MD5/SHA-1, RSA, ECDSA,
ECDH, DES/3DES, RC4, AES-ECB, TLS 1.0/1.1) to a concrete, standards-aligned
PQC transition path (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA),
with ordered rule matching and per-asset recommendations rendered in the GUI.

### Analyst and reporting tools

- **Live threat intelligence feed** — RSS aggregation from quantum-computing
  and cybersecurity sources (IBM, NIST, Google, CSO) with impact tagging that
  recalculates Mosca clocks or updates compliance mappings where relevant.
- **Board brief PDF** — ReportLab-generated executive report with the rating,
  risk distribution, and recommendation summaries.
- **Chatbot with local RAG** — a rule-based security advisor that falls back
  to a fully offline retrieval-augmented engine (LangChain + FAISS with a
  deterministic hashing embedder) grounded on the knowledge base and the live
  asset inventory. No external LLM, no API keys, no network — safe for
  air-gapped deployments.

---

## Architecture

```
q-guardian-v2/
├── run.ps1                          Launch backend + frontend (uses backend/.venv when present)
│
├── backend/                         FastAPI application
│   ├── app/
│   │   ├── main.py                  API routes and scan orchestration
│   │   ├── auth.py                  JWT auth, SECRET_KEY startup validation
│   │   ├── database.py              SQLModel ORM (DBAsset, DBScanJob, DBCBOMHistory)
│   │   ├── settings.py              Environment config, CORS, scan limits
│   │   └── engines/
│   │       ├── discovery.py            Network discovery + TLS handshake scanning
│   │       ├── active_discovery.py     API surface mapping (specs, JS crawl, fuzzing)
│   │       ├── port_scanner.py         Async TCP port scanner
│   │       ├── api_scanner.py          OWASP API Top 10 deep scan
│   │       ├── static_analysis.py      AST/regex static source scanning
│   │       ├── source_scanner.py       Semgrep crypto rule execution
│   │       ├── container_scanner.py    Trivy / Syft / heuristic container scanning
│   │       ├── binary_scanner.py       LIEF + constant-signature binary scanning
│   │       ├── sample_binary.py        Deterministic demo binary generator
│   │       ├── reconciler.py           Cross-source divergence detection
│   │       ├── mosca.py                Mosca X + Y > Z timeline engine
│   │       ├── scoring.py              Q-TRI scoring + enterprise rating
│   │       ├── hndl.py                 Harvest-Now-Decrypt-Later model
│   │       ├── cbom.py                 CycloneDX 1.6 CBOM generation + PDF export
│   │       ├── migration.py            PQC migration playbooks
│   │       ├── compliance.py           RBI CSF 2.0 / NIST IR 8547 / India DST-TEC mapping
│   │       ├── reporting.py            Board brief PDF
│   │       ├── chatbot.py              Rule-based security advisor
│   │       ├── rag_advisor.py          Offline RAG (LangChain + FAISS) grounded answers
│   │       └── threat_intel.py         Quantum/cyber RSS aggregation
│   ├── rules/crypto.yml            Semgrep crypto ruleset
│   ├── .env.example                Configuration template
│   └── requirements.txt
│
├── frontend/                        React + Vite SPA
│   └── src/
│       ├── App.jsx                 Tab shell and routing
│       ├── components/             Header, LoginPage, Dashboard (Posture), AssetTable,
│       │                           SourceScanner (Multi-source), ApiScanner, HNDLSimulator,
│       │                           DependencyGraph (Topology), ComplianceMapper (Cert-IN),
│       │                           CBOMViewer, Chatbot, PlaybookModal, Toast, ErrorBoundary
│       └── index.css               Tailwind design system
│
└── demo/                           Offline demo seeding and runbook
    ├── seed_demo.py                Deterministic canonical-state seeder (real engines)
    ├── DEMO.md                     Scripted demo walkthrough + fallback plan
    └── fallback/                   Recorded artifacts of the canonical demo state
```

---

## Technology Stack

**Backend**

| Component | Technology |
|---|---|
| API framework | FastAPI, Uvicorn |
| ORM / database | SQLModel (SQLAlchemy + Pydantic), SQLite by default, PostgreSQL via `DATABASE_URL` |
| Auth | python-jose (JWT), passlib/bcrypt |
| Scanners | Semgrep (bundled ruleset), Trivy (portable, DB-free mode), Syft, LIEF, tree-sitter |
| Standards | cyclonedx-python-lib (CycloneDX 1.6 / ECMA-424 crypto), ReportLab |
| RAG (optional) | langchain-core, FAISS (`faiss-cpu`) — degrades gracefully when absent |

**Frontend**

| Component | Technology |
|---|---|
| Framework | React 18, Vite 5 |
| Styling | TailwindCSS 3 with a navy/cobalt enterprise design system |
| Visualisation | Recharts, react-force-graph-2d, d3 |
| UX | Framer Motion, Lucide icons |

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

External scanners: Semgrep is installed via `requirements.txt`. Trivy runs in
DB-free SBOM mode and is downloaded to `backend/.tools/` automatically when
missing — no Docker daemon or vulnerability-database download is required for
the offline path. Network scans require outbound internet (crt.sh, live TLS);
everything else runs locally.

### 1. Install

```bash
git clone <repo-url>
cd q-guardian-v2

# Backend
cd backend
python -m venv .venv
# Windows: .\.venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### 2. Configure the backend

```bash
cd backend
cp .env.example .env
```

Set a strong `SECRET_KEY` (32+ random characters) and replace
`ADMIN_PASSWORD_HASH` with a real bcrypt hash of your admin password:

```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'YourPasswordHere', bcrypt.gensalt()).decode())"
```

On startup the API validates this configuration and refuses to boot with a
missing or placeholder secret.

### 3. Run

From the repository root:

```powershell
.\run.ps1
```

Or manually:

```bash
# Terminal 1 — backend (http://localhost:8000)
cd backend && uvicorn app.main:app --reload --port 8000

# Terminal 2 — frontend (http://localhost:5173)
cd frontend && npm run dev
```

- Frontend UI: http://localhost:5173
- API: http://localhost:8000
- OpenAPI docs (dev only): http://localhost:8000/docs

Default demo credentials (set these in `.env` for any real use):
`qguardian_admin` / `QGuardian@2026`.

### 4. Seed the canonical demo state (optional)

`demo/seed_demo.py` drives the real Semgrep, Trivy, container, and LIEF
engines against the bundled fixtures to produce a deterministic inventory
(12 assets, 1 divergence, Level 3 crypto-agility, rating 509 / B-C):

```bash
# stop the backend first
cd backend
./.venv/Scripts/python.exe ../demo/seed_demo.py --wipe
```

The scripted walkthrough and the pre-recorded fallback artifacts live in
`demo/DEMO.md` and `demo/fallback/`.

---

## Platform Walkthrough

| Tab | Purpose |
|---|---|
| Posture | Enterprise cyber rating, risk-state chart, metric cards, threat-intelligence feed |
| Inventory | Unified asset table across all four source vectors, with evidence (file/line/offset), Q-TRI, source badges, and the DIVERGENT filter |
| Multi-source | Run static (AST), Semgrep, container, and binary scans against local paths |
| API Scanner | Deep OWASP API Top 10 assessment of a target endpoint |
| HNDL | Harvest-Now-Decrypt-Later exposure analysis and grounding advisory |
| Topology | Force-directed graph of assets and primitives, coloured by discovery vector, with an amber divergence hub |
| Cert-IN | Cross-framework compliance viewer (RBI, NIST IR 8547, India DST/TEC) |
| CBOM Export | CycloneDX 1.6 JSON / PDF export, run-history diff, reconcile action |

A floating assistant answers questions about findings, frameworks, and
migration guidance from the offline knowledge base and your live inventory.

---

## API Reference

All routes except `/api/v1/auth/login` require `Authorization: Bearer <token>`.

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/login` | Authenticate and receive a JWT |
| POST | `/api/v1/scan/trigger` | Full network scan (discovery, ports, TLS, analytics) for a domain |
| GET | `/api/v1/scan/{job_id}/status` | Poll scan progress |
| POST | `/api/v1/scan/api` | OWASP API Top 10 scan of an endpoint URL |
| POST | `/api/v1/scan/source` | AST static scan of a local file/directory |
| POST | `/api/v1/scan/semgrep` | Semgrep crypto-ruleset scan of a local path |
| POST | `/api/v1/scan/container` | Container/image scan (image tag, tarball, or path) |
| POST | `/api/v1/scan/binary` | Binary scan of an ELF/PE/Mach-O file (`SAMPLE` generates a demo binary) |
| POST | `/api/v1/cbom/reconcile` | Cross-source divergence detection |
| GET | `/api/v1/assets` | Unified asset inventory |
| GET | `/api/v1/enterprise/rating` | Roll-up cyber rating |
| GET | `/api/v1/migration/{asset_id}/playbook` | PQC migration playbook for an asset |
| GET | `/api/v1/cbom/export/cyclonedx` | Native CycloneDX 1.6 CBOM JSON |
| GET | `/api/v1/cbom/export/pdf` | CBOM PDF export |
| GET | `/api/v1/cbom/history` | Recent CBOM scan snapshots |
| GET | `/api/v1/cbom/diff` | Before/after diff of the two latest snapshots |
| GET | `/api/v1/cbom/divergence` | Assets flagged with declared-vs-actual drift |
| GET | `/api/v1/compliance/rbi` | RBI CSF 2.0 control mapping |
| GET | `/api/v1/compliance/frameworks` | RBI + NIST IR 8547 + India DST/TEC mapping |
| GET | `/api/v1/reports/board-brief` | Executive board-brief PDF |
| GET | `/api/v1/threat-intel` | Aggregated quantum/cyber intelligence feed |
| POST | `/api/v1/chat` | Advisor chat (rule-based + offline RAG) |

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | `production` hardens defaults (docs off) |
| `SECRET_KEY` | (required) | JWT signing secret; startup fails if missing/weak |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` | (required) | Demo/admin credentials (bcrypt) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | Token lifetime |
| `DATABASE_URL` | `sqlite:///./qguardian.db` | SQLModel connection string (PostgreSQL supported) |
| `FRONTEND_ORIGINS` | localhost:5173/8000 | CORS allow-list |
| `FRONTEND_ORIGIN_REGEX` | (empty) | Optional CORS origin regex (for preview deployments) |
| `DISCOVERY_MAX_ASSETS` | unlimited | Cap on discovered subdomains per scan |
| `ALLOW_PRIVATE_SCAN_TARGETS` | `false` | Permit scanning private/internal ranges |
| `ENABLE_API_DOCS` | `true` (dev) | Expose `/docs` |

---

## Standards Alignment

- **CycloneDX 1.6 (ECMA-424)** — CBOM serialisation with per-component crypto
  properties.
- **NIST FIPS 203 / 204 / 205** — ML-KEM, ML-DSA, SLH-DSA reference targets in
  scoring and migration playbooks.
- **NIST IR 8547** — PQC transition planning milestones (T1-T4).
- **NIST SP 800-38D / FIPS 180-4 / FIPS 202** — algorithm guidance referenced
  by rule recommendations.
- **RBI Cyber Security Framework 2.0** — Indian banking controls mapping.
- **India DST National Quantum Mission / TEC** — national quantum-safe horizon
  flags.
- **NSA HNDL advisory** — harvest-now-decrypt-later threat modelling baseline.

---

## Security and Ethical Use

- All scanning endpoints are JWT-protected. Login is the only public route.
- The API refuses to start with a missing or placeholder `SECRET_KEY`, and
  OpenAPI docs are disabled in production by default.
- Source/container/binary scanners accept local paths only; remote URLs are
  rejected. Network and API scanners generate real probes — use them only
  against domains and services you own or are explicitly authorised to test.
- Threat-intel and certificate-transparency lookups require outbound network
  access; the demo and multi-source scan paths work fully offline.

## Known Limitations

- HNDL figures are model-based ceilings derived from tiered traffic
  baselines, not telemetry-verified measurements.
- Binary constant detection is signature-based: custom or obfuscated
  implementations that hide known constants may be missed.
- The default SQLite store suits single-node or demo use; switch
  `DATABASE_URL` to PostgreSQL for multi-analyst deployments.
- The UI still carries demo-branding leftovers from its origin (the default
  scan-domain placeholder and export filenames); replace the domain and
  credentials before any production use.
