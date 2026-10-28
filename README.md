# AutoSupplyGuard
### Evidence-Driven Cybersecurity Assurance for Multi-Tier Automotive Supply Chains

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: 35 Passed](https://img.shields.io/badge/tests-35%20passed-brightgreen.svg)]()
[![FastAPI](https://img.shields.io/badge/API-FastAPI-teal.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)
[![Zero False Assurance](https://img.shields.io/badge/Assurance%20FAR-0.0%25-success.svg)]()

> **Research Prototype Notice:** AutoSupplyGuard was designed and implemented as a research-grade prototype demonstrating scientific rigor and practical engineering for a **Master's Thesis application focused on Supply Chain Cybersecurity Assurance at Volvo Group**.

---

## 1. Executive Summary

Modern connected and autonomous commercial vehicles manufactured by **Volvo Group** (such as heavy-duty freight trucks, electric haulers, and autonomous buses) execute distributed software stacks across over 100 Electronic Control Units (ECUs) sourced through multi-tier supplier networks. International regulations—specifically **UNECE R155/R156**, **ISO/SAE 21434:2021**, and the **EU Cyber Resilience Act (CRA)**—mandate continuous vulnerability management, third-party software transparency via Software Bills of Materials (SBOMs), and evidence-backed cybersecurity assurance.

However, existing industrial practices encounter two fundamental failures:
1. **Misaligned Severity Triage:** Vulnerability prioritization relies strictly on static CVSS base scores. An offline developer utility with CVSS 9.8 triggers an emergency triage, while a CVSS 6.5 vulnerability in a shared cryptographic library operating on a cellular Telematics Control Unit (TCU) is deferred.
2. **False Assurance and Compliance Theatre:** Verification relies on static document checklists. If a supplier submits a scan report, the claim is marked "Satisfied"—even if the report is 300 days old, lacks package versions, or directly contradicts a published vendor advisory.

**AutoSupplyGuard** solves these challenges by coupling deterministic SBOM ingestion (SPDX & CycloneDX), multi-dimensional quality assessment, 4-stage vulnerability correlation, directed multi-tier dependency graph traversal, and an evidence-based assurance engine with strict temporal freshness ($\le 90$ days) and contradiction detection.

---

## 2. Research Questions & Empirical Findings

| Research Question | Focus | Key Empirical Result |
| :--- | :--- | :--- |
| **RQ1 (SBOM Quality)** | Effect of SBOM quality on component resolution and vulnerability matching | **100% PURL coverage** yields zero-ambiguity matching; missing coordinates force degraded heuristic matching. |
| **RQ2 (Context Prioritisation)** | Downstream impact and product reachability vs. severity-only ranking | Critical vehicle gateway vulnerability (CVSS 6.5) **elevated from Rank 5 to Rank 1**; isolated offline tool (CVSS 9.8) **downranked from Rank 1 to Rank 4**. |
| **RQ3 (Evidence Assurance)** | Automated detection of missing, stale, or contradictory security claims | **100.0% Accuracy and 0.0% False Assurance Rate ($\text{FAR}$)**, compared to **83.3% False Assurance Rate** in traditional checklist baselines. |
| **RQ4 (Scalability & RAM)** | Performance as SBOM count and component volume increase | Ingested and graph-modelled 995 components and 949 dependencies in **0.359s** at **2,770 comps/sec** with **3.35 MB peak RAM**. |

---

## 3. System Architecture

AutoSupplyGuard follows a modular, 6-layer decoupled architecture:

```
+-------------------------------------------------------------------------------+
| Layer 6: Reporting & UI (FastAPI Endpoints & Streamlit Research Dashboard)    |
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
| Layer 3: Vulnerability Correlation (4-Stage Deterministic Matcher & VEX/CSAF)  |
+-------------------------------------------------------------------------------+
                                        ^
+-------------------------------------------------------------------------------+
| Layer 2: Normalisation & Quality (PURL RFC 7515, C++ SemVer, 5 Metrics)       |
+-------------------------------------------------------------------------------+
                                        ^
+-------------------------------------------------------------------------------+
| Layer 1: Ingestion (SPDX 2.2/2.3, CycloneDX 1.3-1.6, Automotive Feeds, OSV)   |
+-------------------------------------------------------------------------------+
```

### Deterministic Security Principles
- **No AI in Security Decisions:** Vulnerability applicability, risk scoring, and assurance claim satisfaction are calculated strictly through deterministic, mathematically proven algorithms. AI/LLMs may only draft human explanations and are forbidden from modifying risk scores.
- **Explicit Uncertainty States:** Any component lacking an exact version is tagged `candidate_match` rather than confirmed vulnerable. Claims lacking fresh evidence are tagged `insufficient_evidence`.
- **Strict Entity Separation:** **Volvo Group** (commercial vehicles, heavy trucks) and **Volvo Cars** (passenger vehicles) are modeled as distinct, separate organizations. No relationship or vulnerability is ever transferred between them.

---

## 4. Repository Structure

```
AutoSupplyGuard/
├── app/
│   ├── api/                  # FastAPI REST API, state management, and route schemas
│   ├── assurance/            # Evidence-based assurance engine & ISO/SAE 21434 catalogs
│   ├── ingestion/            # SPDX & CycloneDX parsers, checksum validation
│   ├── models/               # Canonical Pydantic v2 entities (Component, SBOM, Claim)
│   ├── normalisation/        # PURL RFC normaliser & C/C++ version comparators
│   ├── sbom_quality/         # 5 formal quality metrics calculator
│   ├── traceability/         # NetworkX directed graph & context prioritisation engine
│   └── vulnerability/        # Automotive vulnerability feed, OSV client, 4-stage matcher
├── dashboard/                # 6-page interactive Streamlit research dashboard
├── data/
│   ├── raw/                  # Immutable external datasets (Automotive CVEs, Curated SBOMs)
│   ├── interim/              # OSV API cache & intermediate indexes
│   ├── processed/            # Verified real corporate relationships (Volvo Group, NVIDIA, etc.)
│   ├── synthetic/            # Controlled multi-tier automotive supply chain fixtures
│   └── manifests/            # SHA-256 provenance manifests
├── docs/                     # Technical specifications (Architecture, Data Model, Methodology)
├── research/
│   ├── final_report.md       # 19-section academic research paper with full results
│   ├── literature_review.md  # Formal literature review & analysis
│   ├── literature_matrix.csv # Comparative matrix of 6 foundation research papers
│   ├── research_gap.md       # Explicit research gaps and contributions
│   ├── references.bib        # BibTeX citations
│   └── results/              # Reproducible raw result CSVs (Experiments 1 to 4)
├── scripts/                  # Automated runners for Experiments 1-4
└── tests/                    # 35 unit, integration, and security test cases
```

---

## 5. Quickstart & Installation

### 5.1 Environment Setup
```bash
# Clone the repository
git clone https://github.com/itssaideep/AutoSupplyGuard.git
cd AutoSupplyGuard

# Create and activate virtual environment using uv or standard venv
uv venv .venv
source .venv/bin/activate       # On Windows: .venv\Scripts\activate

# Install dependencies in editable mode
uv pip install -e .
```

### 5.2 Execute Automated Tests
Run all 35 unit, integration, and security tests:
```bash
pytest -v
```

### 5.3 Reproduce Empirical Research Experiments
Execute the experimental suite to regenerate all benchmark results:
```bash
python scripts/run_experiment_1.py   # RQ1: SBOM Quality & Matchability
python scripts/run_experiment_2.py   # RQ2: Dependency Impact Prioritisation
python scripts/run_experiment_3.py   # RQ3: Assurance Gap & Staleness Detection
python scripts/run_experiment_4.py   # RQ4: Scalability & Memory Profiling
```
Raw result CSVs are stored in `research/results/`.

### 5.4 Launch the REST API
```bash
uvicorn app.api.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at `http://localhost:8000/docs`.

### 5.5 Launch the Research Dashboard
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

## 7. Citation & Academic References

```bibtex
@mastersthesis{AutoSupplyGuard2026,
  author       = {Research Candidate},
  title        = {AutoSupplyGuard: Evidence-Driven Cybersecurity Assurance for Multi-Tier Automotive Supply Chains},
  school       = {Master's Thesis Research Application, Volvo Group Focus},
  year         = {2026},
  url          = {https://github.com/itssaideep/AutoSupplyGuard}
}
```

---

## 8. License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
