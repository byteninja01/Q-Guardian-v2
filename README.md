# Q-Guardian — Quantum Transition Intelligence Platform

> **Enterprise-grade post-quantum cryptography (PQC) risk assessment and migration engine for the Indian banking sector.**

Q-Guardian is a full-stack cybersecurity platform built to help banks understand *where* their current cryptography is vulnerable to quantum-era attacks, *when* the risk window opens, and *how* to migrate to quantum-safe algorithms — before it is too late.

It operates across three core threat pillars:
- **Cryptographic Inventory** — What algorithms does the target organisation use?
- **Timeline Risk Modeling** — When does each asset cross the Mosca safety threshold?
- **Active API Surface Mapping** — What undiscovered endpoints and hidden attack vectors exist beyond the certificate ledger?

---

## Architecture Overview

```
Q-Guardian/
├── run.ps1                          ← Launch both servers (Backend + Frontend)
│
├── backend/                         ← FastAPI Python application
│   ├── requirements.txt
│   ├── qguardian.db                 ← SQLite database (auto-created on startup)
│   └── app/
│       ├── main.py                  ← FastAPI routes, background scan orchestration
│       ├── database.py              ← SQLModel ORM (DBAsset, DBScanJob)
│       ├── auth.py                  ← JWT authentication, token verification
│       ├── settings.py              ← Environment config, CORS origins
│       └── engines/
│           ├── discovery.py         ← Subdomain discovery (crt.sh) + TLS scanner
│           ├── active_discovery.py  ← Active API surface mapping (JS crawl, fuzzing, spec parsing)
│           ├── port_scanner.py      ← Async TCP port scanner
│           ├── api_scanner.py       ← Deep OWASP API Top 10 penetration engine
│           ├── scoring.py           ← Dynamic Q-TRI score engine (tier-weighted)
│           ├── mosca.py             ← Mosca countdown clock (X+Y>Z)
│           ├── hndl.py              ← Harvest-Now-Decrypt-Later risk exposure
│           ├── cbom.py              ← Cryptographic Bill of Materials generator
│           ├── migration.py         ← PQC migration playbook generator
│           ├── compliance.py        ← RBI CSF 2.0 compliance mapper
│           ├── reporting.py         ← Board Brief PDF generator (ReportLab)
│           ├── chatbot.py           ← Context-aware security advisor chatbot
│           └── threat_intel.py      ← Live threat intelligence (RSS aggregation)
│
└── frontend/                        ← React 18 + Vite SPA
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js           ← Custom PNB color palette
    └── src/
        ├── App.jsx                  ← Root router + ErrorBoundary
        ├── context/
        │   ├── AuthContext.jsx      ← JWT session management
        │   └── ToastContext.jsx     ← Global notification system
        └── components/
            ├── LoginPage.jsx        ← Authenticated entry point
            ├── Header.jsx           ← Navigation + scan trigger
            ├── Dashboard.jsx        ← Posture overview + live threat feed
            ├── AssetTable.jsx       ← Crypto asset inventory + PATHS surface badge
            ├── ApiScanner.jsx       ← OWASP Deep Scan UI + vector tags
            ├── HNDLSimulator.jsx    ← HNDL exposure timeline + grounding advisory
            ├── DependencyGraph.jsx  ← Force-directed crypto topology graph
            ├── ComplianceMapper.jsx ← RBI CSF 2.0 violation viewer
            ├── CBOMViewer.jsx       ← CBOM viewer + PDF/JSON export
            ├── PlaybookModal.jsx    ← PQC migration playbook modal
            └── Chatbot.jsx          ← Floating security advisor widget
```

---

## Technology Stack

**Backend**
| Library | Purpose |
|---|---|
| FastAPI | Async web framework, automatic OpenAPI docs |
| Uvicorn | ASGI production server |
| SQLModel | ORM (SQLAlchemy + Pydantic) |
| SQLite | Embedded file-based database |
| python-jose | JWT creation and verification |
| cryptography | X.509 certificate parsing |
| requests | HTTP client (discovery, fuzzing, threat intel) |
| reportlab | PDF board brief generation |

**Frontend**
| Library | Purpose |
|---|---|
| React 18 | UI component framework |
| Vite 5 | Build tool and hot-module replacement server |
| TailwindCSS 3 | Utility-first CSS with PNB custom theme |
| Recharts | AreaChart, BarChart, PieChart visualisations |
| Framer Motion | Micro-animations and page transitions |
| Lucide React | Consistent SVG icon set |
| axios | HTTP client for API communication |

---

## Core Analytical Engines

### 1. Passive Discovery (crt.sh)
Queries the Certificate Transparency log at `crt.sh` to enumerate all publicly registered subdomains for a target domain. Each discovered hostname is then deep-scanned for real TLS metadata using Python's `ssl` module and the `cryptography` library (no sslyze dependency).

### 2. Active API Surface Mapping (`active_discovery.py`)
Goes beyond certificate logs to probe live API surfaces:
- **Spec Parsing** — Fetches `/swagger.json`, `/openapi.json`, `/v2/api-docs` to index hidden schemas.
- **JS/HTML Crawling** — Loads frontend HTML and linked JavaScript files, extracting API routes using regex pattern matching.
- **Banking Sector Fuzzer** — Asynchronously probes a curated wordlist of banking middleware paths: `/finacle`, `/rtgs-api`, `/swift-gateway`, `/neft`, etc.

Discovered endpoints are stored in the `discovered_endpoints_data` field of each `DBAsset` and rendered in the Asset Inventory as a "PATHS" hover-badge.

### 3. Deep OWASP API Scanner (`api_scanner.py`)
A genuine penetration testing engine, not a checklist scanner. Probes the following attack vectors:

| OWASP ID | Attack Class | Method |
|---|---|---|
| API1 | IDOR — Broken Object Level Auth | Sequential ID probing on `/api/v1/users/1`, `/accounts/2` |
| API2 | Broken Auth — JWT Bypass | `alg:none` null-signature injection |
| API3 | Excessive Data Exposure | GraphQL `__schema` introspection query |
| API4 | Rate Limiting Absent | 15-request burst probe |
| API5 | Broken Function Level Auth | HTTP method switching (`DELETE`, `PUT` on unauthenticated routes) |
| API6 | Mass Assignment | POST with `"role":"admin"`, `"is_admin":true` |
| API7 | Security Misconfiguration | Wildcard CORS origin detection |
| API8 | Insecure TLS | Certificate validation + HTTP plaintext detection |

Each finding includes a `vector` tag (e.g., `VECTOR: JWT_ALG_NONE`, `VECTOR: GRAPHQL_INTRO`) rendered inline in the UI for immediate analyst context.

### 4. Q-TRI Scoring Engine — Dynamic Tier-Weighted (`scoring.py`)
The Quantum Threat Resilience Index (Q-TRI) scores each asset from 0–100. Critically, weights are **not fixed** — they shift based on the asset's RBI sensitivity tier:

| Tier | TLS | Forward Secrecy | Cert Hygiene | Cipher | PQC |
|---|---|---|---|---|---|
| S1 (Core Payment) | 25% | 20% | 20% | 15% | **20%** |
| S2 (Auth/Identity) | 25% | 20% | 20% | 15% | **20%** |
| S3 (Transactions) | 30% | 20% | 20% | 20% | 10% |
| S4 (Internal API) | 35% | 25% | 25% | 15% | Bonus only |
| S5 (Public Portal) | 35% | 25% | 25% | 15% | Bonus only |

S4/S5 assets that *voluntarily* implement PQC receive a **+15 bonus** rather than being treated as deficient for lacking it.

### 5. Mosca Timeline Engine (`mosca.py`)
Implements the **Mosca Inequality**: `X + Y > Z`
- **X** = Migration complexity (derived from algorithm, TLS version, key size, sensitivity tier)
- **Y** = Data shelf life (how long the data remains sensitive by tier: S1=10yr, S5=1yr)
- **Z** = Time to Cryptographically Relevant Quantum Computer (CRQC: worst=5yr, best=15yr)

When `X + Y > Z`, the asset is flagged `CRITICAL`. All values are fully deterministic — zero random jitter or variance.

### 6. HNDL Exposure Engine (`hndl.py`)
Models the **Harvest-Now-Decrypt-Later** attack trajectory for assets without Perfect Forward Secrecy (PFS). Traffic volumes are calculated from static RBI-tiered baselines (S1: 800 GB/month, S5: 20 GB/month) and accumulated from a configurable harvest start date.

> **⚠️ Grounding Advisory:** HNDL exposure volumes are a *theoretical risk ceiling*, not a telemetry-verified exfiltration measurement. Without real-time PCAP or network monitoring integration, these figures should be used for risk prioritisation only.

---

## Security Architecture

- **JWT Authentication**: All API routes (except `/api/v1/auth/login`) are protected with `Depends(verify_token)`. Tokens are signed using a configurable `SECRET_KEY` from the environment.
- **Startup Validation**: `validate_auth_configuration()` on FastAPI startup halts the server if `SECRET_KEY` is missing or insecure, preventing accidental production exposure.
- **SSRF Protection**: The API scanner and active discovery engines are restricted behind authentication to prevent unauthorized probing of internal targets.
- **CORS Policy**: Production origins are explicitly allowlisted in `settings.py`. Wildcard origins are not permitted server-side.

---

## Running Locally

**Prerequisites:** Python 3.10+, Node.js 18+, Git

```powershell
# Clone the repository
git clone <repo-url>
cd "AMD project"

# Create backend environment file
cp backend/.env.example backend/.env
# Edit SECRET_KEY in .env to a strong random string

# Launch both servers
.\run.ps1
```

- **Backend API**: `http://localhost:8000`
- **Frontend UI**: `http://localhost:5173`
- **API Docs (Swagger)**: `http://localhost:8000/docs`

**Default credentials** (change immediately in production):
```
Username: qguardian_admin
Password: QGuardian@2026
```

## Deployment Notes

For production, deploy the frontend and backend as separate services unless you have an explicit reverse proxy in front of both.

- **Frontend (Vercel)**: set `VITE_API_BASE` to your backend API base URL, for example `https://your-backend.example.com/api/v1`.
- **Backend**: set `FRONTEND_ORIGINS` to your production frontend origin, for example `https://pnb-q-guardian.vercel.app`.
- **Preview Deployments**: if you use Vercel preview URLs, also set `FRONTEND_ORIGIN_REGEX=https://.*\.vercel\.app` on the backend.

If the backend does not allow the exact frontend origin, browser preflight `OPTIONS` requests to `/api/v1/auth/login` will fail with a CORS error before login reaches the API.

---

## Regulatory Alignment

This platform is designed to map to:
- **RBI Cybersecurity Framework (CSF) 2.0** — Control mapping via the Compliance Mapper module
- **NIST IR 8547** — PQC Migration Planning Guidelines
- **NSA HNDL Advisory (2023)** — Harvest-Now-Decrypt-Later threat modelling baseline
- **NIST FIPS 140-3** — Algorithm strength classification (RSA, ECDSA, ML-KEM, SLH-DSA)

---

## Limitations & Disclaimers

1. **Active Discovery** increases scan time and generates real network probes against target infrastructure. Use only on systems you have explicit authorisation to test.
2. **HNDL Metrics** are model-based projections, not measured exfiltration volumes. Real telemetry integration would require PCAP or SIEM feed ingestion.
3. **PQC Detection** depends on cipher suite string matching. Hybrid PQC implementations that do not surface standard KYBER/KEM identifiers in TLS handshake metadata may be missed.
4. **SQLite** is appropriate for single-node deployments. For multi-analyst enterprise deployments, migrate to PostgreSQL via the SQLModel connection string in `database.py`.

---

## Live Deployment

Q-Guardian is currently deployed and accessible at:

🔗 https://pnb-q-guardian.vercel.app

This instance represents the active production frontend environment.
