# AutoSupplyGuard
### Evidence-Driven Cybersecurity Assurance for Multi-Tier Automotive Supply Chains (Volvo Group Context)

[![CI](https://github.com/itssaideep/AutoSupplyGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/itssaideep/AutoSupplyGuard/actions)
[![Python 3.10 | 3.12](https://img.shields.io/badge/python-3.10%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-teal.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)

---

## 1. Overview

Modern connected and autonomous commercial vehicles manufactured by **Volvo Group** (such as heavy-duty freight trucks, electric haulers, and autonomous buses) execute distributed software stacks across over 100 Electronic Control Units (ECUs) sourced through multi-tier supplier networks. International automotive cybersecurity regulations—specifically **UNECE R155/R156**, **ISO/SAE 21434:2021**, and the **EU Cyber Resilience Act (CRA)**—mandate continuous vulnerability management, third-party software transparency via Software Bills of Materials (SBOMs), and evidence-backed cybersecurity assurance.

However, existing industrial practices encounter two fundamental failures:
1. **Misaligned Severity Triage:** Vulnerability prioritization relies strictly on static CVSS base scores. An offline developer utility with CVSS 9.8 triggers an emergency triage, while a CVSS 6.5 vulnerability in a shared cryptographic library operating on a cellular Telematics Control Unit (TCU) is deferred.
2. **False Assurance and Compliance Theatre:** Verification relies on static document checklists. If a supplier submits a scan report, the claim is marked "Satisfied"—even if the report is 300 days old, lacks package versions, or directly contradicts a published vendor advisory.

**AutoSupplyGuard** solves these challenges by coupling deterministic SBOM ingestion (SPDX & CycloneDX), multi-dimensional quality assessment, 4-stage vulnerability correlation, directed multi-tier dependency graph traversal, binary linker exposure analysis (`GNU ld -Map` and ELF symbols), and an evidence-based assurance engine with strict temporal freshness ($\le 90$ days) and contradiction detection.

---

## 2. Core Capabilities & Benchmark Performance

| Capability / Benchmark | Focus | Measured Performance |
| :--- | :--- | :--- |
| **SBOM Quality & Graceful Degradation** | Effect of SBOM quality and field degradation on component resolution and vulnerability matching | With complete Package URLs, matching is unambiguous ($F_1 = 0.72$ on curated benchmarks); with missing fields it degrades gracefully to `candidate_match`. Monotonic degradation is demonstrated across 5 seeds in Experiment B1; wild noisy SBOMs exhibit lower completeness ($6.51 \pm 1.12$). |
| **Context-Aware Prioritisation** | Downstream impact and product reachability vs. severity-only ranking | Critical vehicle gateway vulnerability (CVSS 6.5) **elevated from Rank 5 to Rank 1**; isolated offline tool (CVSS 9.8) **downranked from Rank 1 to Rank 4**. |
| **Evidence-Based Assurance** | Automated detection of missing, stale, or contradictory security claims | **0 of 6** false assurances on the initial suite (checklist baseline: 5 of 6); **0 of 98** false assurances on the full-factorial assurance corpus (Wilson 95% CI upper bound: **3.8%** vs. 81.6% for checklist existence baselines). |
| **Scalability & Invariant Graph Traversal** | Performance as SBOM count and component volume increase | Curated benchmark resolves **995 packages and exactly 949 true component dependencies** (filtering 46 top-level document wrappers), executed in **0.359s** at **2,770 comps/sec** with **3.35 MB peak RAM**. |

---

## 3. System Architecture

AutoSupplyGuard follows a modular, 6-layer decoupled architecture:

```
+-------------------------------------------------------------------------------+
| Layer 6: Reporting & UI (FastAPI Endpoints & Streamlit Dashboard)             |
+-------------------------------------------------------------------------------+
                                        ^
+-------------------------------------------------------------------------------+
| Layer 5: Evidence-Based Assurance Engine (ISO/SAE 21434, UNECE R155, CRA)    |
+-------------------------------------------------------------------------------+
                                        ^
+-------------------------------------------------------------------------------+
| Layer 4: Multi-Tier Traceability Graph (NetworkX MultiDiGraph & Reachability) |
+-------------------------------------------------------------------------------+
                                        ^
+-------------------------------------------------------------------------------+
| Layer 3: Vulnerability Correlation (4-Stage Matcher, VEX/CSAF, Binary Symbol) |
+-------------------------------------------------------------------------------+
                                        ^
+-------------------------------------------------------------------------------+
| Layer 2: Normalisation & Quality (Package-URL purl-spec, C++ SemVer)          |
+-------------------------------------------------------------------------------+
                                        ^
+-------------------------------------------------------------------------------+
| Layer 1: Ingestion (SPDX 2.2/2.3, CycloneDX 1.3-1.6, Automotive Feeds, OSV)   |
+-------------------------------------------------------------------------------+
```

### Deterministic Security Principles
- **No AI in Security Decisions:** Vulnerability applicability, risk scoring, and assurance claim satisfaction are calculated strictly through deterministic rule-based algorithms. AI/LLMs may only draft human explanations and are forbidden from modifying risk scores.
- **Explicit Uncertainty States:** Any component lacking an exact version is tagged `candidate_match` rather than confirmed vulnerable. Claims lacking fresh evidence are tagged `insufficient_evidence`.
- **Strict Entity Separation:** **Volvo Group** (commercial vehicles, heavy trucks) and **Volvo Cars** (passenger vehicles) are modeled as distinct, separate organizations. No relationship or vulnerability is ever transferred between them.
- **Specification Compliance:** Canonical Package URL formatting adheres strictly to the official [Package-URL (purl) specification](https://github.com/package-url/purl-spec).

---

## 4. Repository Structure

```
AutoSupplyGuard/
├── .github/
│   └── workflows/
│       └── ci.yml            # GitHub Actions CI matrix (Python 3.10 & 3.12, lint, large-file guard)
├── .pre-commit-config.yaml   # Pre-commit hooks (Ruff, 50MB file size guard)
├── app/
│   ├── api/                  # FastAPI REST API, state management, and route schemas
│   ├── assurance/            # Evidence-based assurance engine & ISO/SAE 21434 catalogs
│   ├── evidence/             # Binary linker map (-Map) & symbol table exposure analysis
│   ├── ingestion/            # SPDX & CycloneDX parsers, checksum validation
│   ├── models/               # Canonical Pydantic v2 entities (Component, SBOM, Claim)
│   ├── normalisation/        # Package URL (purl-spec) & C/C++ version comparators
│   ├── sbom_quality/         # 5 formal quality metrics calculator
│   ├── traceability/         # NetworkX directed graph & context prioritisation engine
│   └── vulnerability/        # Automotive vulnerability feed, OSV client, 4-stage matcher
├── dashboard/                # 6-page interactive Streamlit assurance dashboard
├── data/
│   ├── raw/                  # Immutable external datasets (Automotive CVEs, Curated SBOMs)
│   ├── interim/              # OSV API cache & intermediate indexes
│   ├── processed/            # Verified real corporate relationships (Volvo Group, NVIDIA, etc.)
│   ├── synthetic/            # Controlled multi-tier automotive supply chain fixtures
│   └── manifests/            # SHA-256 provenance manifests
├── docs/                     # Technical specifications (Architecture, Data Model, Methodology)
├── research/
│   ├── final_report.md       # Comprehensive evaluation and technical documentation
│   ├── literature_review.md  # State-of-the-art survey on supply chain cybersecurity
│   ├── literature_matrix.csv # Comparative matrix of foundation reference papers
│   ├── research_gap.md       # Explicit gaps and engineering contributions
│   ├── references.bib        # BibTeX citations
│   ├── figures/              # Generated evaluation curves & figures
│   └── results/              # Reproducible raw result CSVs (Experiments 1-4, B1, B2)
├── scripts/                  # Automated runners for benchmark experiments and data fetching
└── tests/                    # 75 unit, property, and evaluation test cases
```

---

## 5. Quickstart & Installation

### 5.1 Environment Setup
```bash
# Clone the repository
git clone https://github.com/itssaideep/AutoSupplyGuard.git
cd AutoSupplyGuard

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate

# Install package with all development and binary analysis dependencies
pip install -e ".[dev,binary]"
# Or using uv:
uv pip install -e ".[dev,binary]"
```

> **Continuous Integration:** CI runs automatically on GitHub Actions across a test matrix of Python 3.10 and 3.12 with all deprecation warnings treated as errors.

### 5.2 Execute Automated Tests
Run all 75 unit, property, and evaluation tests:
```bash
pytest -v
```

### 5.3 Run Benchmark Experiments
Execute benchmark experiments via console entry points or python modules:
```bash
# Run via console entry points
autosupplyguard-exp1   # Quality & matchability
autosupplyguard-exp2   # Dependency impact prioritisation
autosupplyguard-exp3   # Assurance gap & staleness detection
autosupplyguard-exp4   # Scalability & memory profiling
autosupplyguard-b1     # Metadata degradation & wild SBOM analysis
autosupplyguard-b2     # Full factorial N=98 assurance evaluation

# Verify dataset integrity (SHA-256)
autosupplyguard-fetch --verify-only
```
Raw result CSVs are stored in `research/results/`.

### 5.4 Launch the REST API
```bash
uvicorn app.api.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at `http://localhost:8000/docs`.

### 5.5 Launch the Interactive Dashboard
```bash
streamlit run dashboard/app.py
```
Open your browser at `http://localhost:8501`.

---

## 6. Documented Corporate Relationships

AutoSupplyGuard models independently documented corporate disclosures with strict scope boundaries:

- **Volvo Group & NVIDIA:** Official joint development agreement for end-to-end autonomous commercial transport systems. *Scope:* Commercial vehicles and autonomous haulage.
- **Volvo Cars & NVIDIA:** Centralized DRIVE Orin core computing deployment for passenger vehicles. *(Strictly isolated from Volvo Group)*.
- **Volvo Cars & Zenseact:** Full ownership of autonomous driving software subsidiary.
- **Zenseact & Luminar:** Production partnership integrating Iris LiDAR into autonomous software stacks.
- **Volvo Cars & Google:** Android Automotive OS infotainment integration in passenger cars.

---

## 7. License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
