# AutoSupplyGuard — Master Implementation Plan
## Evidence-Driven Cybersecurity Assurance for Multi-Tier Automotive Supply Chains

**Target Context:** Cybersecurity Assurance Platform (Volvo Group Supply Chain Context)  
**Primary Research Question:** How can provenance-aware component traceability improve vulnerability visibility and evidence-based cybersecurity assurance in multi-tier automotive supply chains?

---

## 1. Architectural Blueprint & Layered Design

```
+-----------------------------------------------------------------------------------+
|                            Layer 6: Reporting & Interface                        |
|   Streamlit Research Dashboard  |  FastAPI REST Endpoints  |  JSON / CSV Exporter |
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                              Layer 5: Assurance Engine                            |
|  Requirements (ISO/SAE 21434, UNECE R155) -> Claims -> Evidence Req -> Artifacts  |
|  Status Evaluator (supported, partially_supported, insufficient_evidence, etc.)   |
|  Freshness Checker  |  Contradiction Detector  |  Zero False Assurance Guarantee  |
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                         Layer 4: Multi-Tier Traceability Graph                    |
|  NetworkX Heterogeneous Graph (Orgs, Products, Components, SBOMs, Vulnerabilities) |
|  Documented Real Relationships (Volvo/NVIDIA/Zenseact) vs. Synthetic Test Graph   |
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                  Layer 3: Vulnerability Intelligence & Correlation               |
|  Automotive CVEs (Basu et al.)  |  Google OSV API  |  NVD / CSAF VEX Feeds        |
|  Stage 1: Exact PURL -> Stage 2: Ecosystem/Name/Ver -> Stage 3: CPE -> Stage 4:   |
|  Candidate Match (Explicit Uncertainty)  |  Context & Evidence Prioritisation     |
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                   Layer 2: Normalisation & SBOM Quality Engine                    |
|  Identifier Normaliser (PURL, CPE)  |  Version Parsing & Semantic Constraints      |
|  Quality Metrics (Completeness, PURL Rate, Dep Resolution, Duplicates, Matchability)
+-----------------------------------------+-----------------------------------------+
                                          |
+-----------------------------------------v-----------------------------------------+
|                            Layer 1: Data Ingestion & Storage                      |
|  CycloneDX Parser (JSON/XML)  |  SPDX Parser (JSON/Tag-Value)  |  File Checksums  |
|  Immutable Raw Storage  |  SQLite Canonical Database (with PostgreSQL path)       |
+-----------------------------------------------------------------------------------+
```

---

## 2. Milestone Breakdown & Phased Execution

### Phase 0: Foundations & Data Audit (Current State — COMPLETED)
- [x] **Milestone 0: Environment & Tooling Inspection**
  - Inspected repository, Python versions, installed `uv 0.13.5`, created `.venv` virtual environment.
  - Installed core processing dependencies: `zstandard`, `pandas`, `openpyxl`, `pydantic`, `numpy`.
  - Created directory structure (`data/raw/`, `data/manifests/`, `research/papers/`, `docs/`, etc.).
- [x] **Milestone 1: Literature & Dataset Audit**
  - Acquired and audited **Dataset A** (`SriAbir/CV_Vulnerability_22-24`): 8 sheets, 1,556 total rows, 1,507 unique CVE records (411 unique in 2022–2024 focus).
  - Acquired and audited **Dataset B** (`Wild SBOMs` Zenodo 17397281): 78,612 SBOMs, standard/format distributions, 1.16M filenames.
  - Acquired and audited **Supplementary Benchmark** (`Curated SBOMs` Zenodo 14808410): 46 projects, 46 validated SPDX-2.2 JSON docs, 995 packages, 995 dependency edges.
  - Downloaded open-access research papers (Mohamad et al. 2020, O'Donoghue et al. 2024, Zacchiroli et al. 2025, Curated SBOMs 2025).
  - Produced research documentation: `research/references.bib`, `research/literature_matrix.csv`, `research/dataset_inventory.md`, `research/research_gap.md`, `research/literature_review.md`, `research/metrics.md`, `research/experimental_plan.md`.

---

### Phase 1: Core Domain Models & Ingestion (Milestones 2 & 3)
*Goal: Ingest real-world SBOMs reproducibly, normalise component identifiers, and compute mathematical quality metrics.*

- [ ] **Milestone 2: Canonical Data Model & SBOM Ingestion Pipeline**
  - Define canonical Pydantic models in `app/models/`:
    - `Component`: internal ID, name, version, purl, cpe, supplier, ecosystem, license, raw_identifier, resolution_status.
    - `SBOM`: id, format (`CycloneDX` | `SPDX`), spec_version, author, creation_timestamp, sha256_checksum, component_count, dependency_count, raw_path.
    - `DependencyEdge`: source_component_id, target_component_id, relationship_type, scope (`runtime`, `build`, `transitive`).
  - Implement parsers in `app/ingestion/`:
    - `SPDXParser`: parse SPDX 2.2 and 2.3 JSON documents (tested on Curated Benchmark).
    - `CycloneDXParser`: parse CycloneDX 1.3, 1.4, 1.5 JSON documents.
  - Implement `app/normalisation/`:
    - Package URL normaliser using `packageurl-python` logic (standardising `pkg:npm/...`, `pkg:pypi/...`, `pkg:maven/...`).
    - Version normaliser preserving raw strings alongside parsed SemVer/PEP440 representations.
  - Unit and integration tests for malformed JSON, empty files, duplicate package IDs, and circular dependency references.
  - **Exit Criterion:** 100% of the 46 Curated SBOMs and a stratified sample of 50 Wild SBOMs parsed with zero unhandled exceptions and full audit logs.

- [ ] **Milestone 3: SBOM Quality Assessment Engine**
  - Implement quality calculators in `app/sbom_quality/`:
    - $M_{\text{comp}}$: Required-field completeness (Name, Version, Identifier).
    - $M_{\text{purl}}$: Valid PURL extraction rate.
    - $M_{\text{dep}}$: Dependency reference resolution rate.
    - $M_{\text{dup}}$: Duplicate component rate.
    - $M_{\text{matchable}}$: Vulnerability matchability index.
  - Generate machine-readable validation reports in JSON/CSV.
  - Compare source-provided NTIA score against AutoSupplyGuard Matchability Index.
  - **Exit Criterion:** Reproducible quality reports generated for all sample SBOMs with documented formula breakdowns.

---

### Phase 2: Vulnerability Intelligence & Dependency Impact (Milestones 4 & 5)
*Goal: Correlate components with automotive vulnerabilities, query live/cached feeds, and prioritize risks using dependency context.*

- [ ] **Milestone 4: Vulnerability Intelligence & Correlation Engine**
  - Ingest automotive vulnerability dataset (`GitHubAutomotiveVulnerabilities_2022_2024.xlsx`):
    - Map CVEs, descriptions, CVSS v3 base scores, CAPEC attack vectors, vendor strings, and SDLC phases.
  - Build connector in `app/vulnerability/`:
    - `OSVClient`: Async connector to Google OSV API (`https://api.osv.dev/v1/query`) with local caching and retry logic.
  - Deterministic 4-stage matching pipeline:
    - **Stage 1 (Exact PURL Match):** Matches exact ecosystem, package name, and version against OSV records.
    - **Stage 2 (Ecosystem + Name + SemVer Range):** Matches package name and tests version constraint satisfaction.
    - **Stage 3 (CPE Match):** Matches vendor and product attributes against NVD records.
    - **Stage 4 (Candidate / Fuzzy Match):** Flags potential name overlaps with explicit `candidate_match` status and uncertainty score. (Never counted as confirmed).
  - VEX / CSAF Status Handler: Incorporate product status (`known_affected`, `not_affected`, `fixed`) with supporting evidence.
  - **Exit Criterion:** Every vulnerability match produces an audit trail containing matching method, version constraint evaluation, confidence category, and source retrieval timestamp.

- [ ] **Milestone 5: Directed Dependency Impact Analysis & Risk Prioritisation**
  - Implement directed dependency graph engine using NetworkX in `app/traceability/`:
    - Directed acyclic and cyclic dependency traversal.
    - Upstream ancestor tracking (which products/components depend on this node).
    - Downstream descendant tracking (what does this node depend on).
  - Implement 3 Vulnerability Prioritisation Schemes:
    - **Baseline A (Severity-Only):** Ranked strictly by CVSS base score.
    - **Baseline B (Severity + Dependency):** Ranked by $\text{CVSS} \times (1 + \log(1 + \text{Descendants}))$.
    - **Proposed Method (AutoSupplyGuard Context & Evidence Score):** Combines CVSS, downstream impact degree, reachable vehicle product count, identity confidence, and evidence freshness.
  - **Exit Criterion:** Baseline comparisons evaluated on real SBOMs and synthetic test scenarios with ranking metric outputs.

---

### Phase 3: Multi-Tier Traceability & Assurance Engine (Milestones 6 & 7)
*Goal: Build the evidence graph linking components to products and suppliers, and automate regulatory cybersecurity assurance reasoning.*

- [ ] **Milestone 6: Documented Supplier Relationships & Synthetic Ecosystem**
  - Build verified real corporate relationship dataset (`data/processed/corporate_relationships.json`):
    - Volvo Group & NVIDIA (Autonomous transport solutions / compute partnerships).
    - Volvo Cars & NVIDIA (Drive Orin platform integration).
    - Volvo Cars & Zenseact (Autonomous driving software subsidiary).
    - Zenseact & Luminar (LiDAR sensor and perception integration).
    - Volvo Cars & Google (Android Automotive OS infotainment).
    - *Constraint:* Strict separation between Volvo Group and Volvo Cars. Every edge carries exact source URL, date, excerpt, relationship type (`OWNS`, `DEVELOPS_WITH`, `INTEGRATES`, `SUPPLIES_COMPONENT_TO`), and documented limitations.
  - Construct controlled synthetic automotive multi-tier supply chain fixture (`data/synthetic/synthetic_supply_chain.json`):
    - 1 OEM (Synthetic Volvo Truck Division).
    - 2 Tier 1 suppliers (Telematics Gateway Supplier, Cockpit In-Vehicle Infotainment Supplier).
    - 3 Tier 2 suppliers (Crypto Middleware Provider, Real-Time OS Kernel Provider, Network Protocol Stack Vendor).
    - Injected test scenarios: transitive dependency vulnerabilities, missing supplier assurance evidence, stale vulnerability scans (>90 days), and conflicting component versions.
  - **Exit Criterion:** Complete separation between real public evidence and synthetic test data; clear visual tagging in models and UI.

- [ ] **Milestone 7: Evidence-Based Assurance Engine (Primary Research Contribution)**
  - Implement canonical assurance models in `app/assurance/`:
    - `RegulatoryRequirement`: Standard ID (ISO/SAE 21434, UNECE R155), clause, wording, source.
    - `AssuranceClaim`: claim ID, claim text, related requirement, required evidence types, review status.
    - `EvidenceArtifact`: evidence ID, evidence type (`SBOM`, `VulnerabilityAssessment`, `VEX`, `SupplierAttestation`, `AuditLog`), source URL/file, hash, effective_date, expiration_date.
  - Implement Deterministic Assurance Assessment Algorithm:
    - Verifies evidence presence against required types.
    - Evaluates evidence freshness against configurable threshold (default 90 days).
    - Checks provenance checksums.
    - Detects contradictions (e.g., supplier declares `not_affected` while independent OSV match proves active component vulnerability with no mitigation).
    - Flags unresolved component identities.
    - Assigns deterministic status: `supported`, `partially_supported`, `insufficient_evidence`, `contradicted`, `not_assessed`.
  - **Exit Criterion:** Verified **Zero False Assurance ($\text{FAR} = 0.0\%$)** across 20 positive, negative, stale, and contradictory test fixtures.

---

### Phase 4: API, Interactive Dashboard & Evaluation (Milestones 8 & 9)
*Goal: Provide a REST API and a research dashboard, and execute the 4 formal experiments.*

- [ ] **Milestone 8: FastAPI REST API & Streamlit Research Dashboard**
  - Implement FastAPI backend in `app/api/`:
    - `/health`: System status and database readiness.
    - `/sboms` (POST / GET): Upload and retrieve SBOMs and quality scorecards.
    - `/components` (GET): Query components, package identifiers, and dependencies.
    - `/vulnerabilities` (GET): Query correlated vulnerabilities and match confidence.
    - `/traceability/products/{id}`: Traverse product dependency tree to components and suppliers.
    - `/assurance/claims` and `/assurance/gaps`: Retrieve assurance case graph, evidence status, and compliance gaps.
    - `/analysis/run`: Trigger end-to-end evaluation pipeline.
  - Implement Streamlit Research Dashboard in `dashboard/`:
    - **Page 1: Executive Overview:** High-level metrics, total SBOMs, confirmed vs candidate vulnerabilities, assurance gap count.
    - **Page 2: SBOM Quality Deep-Dive:** Format comparisons, field completeness distributions, NTIA vs Matchability Index.
    - **Page 3: Vulnerability & Dependency Impact:** CVSS vs Context-Aware priority rankings, transitive paths, affected vehicle products.
    - **Page 4: Multi-Tier Traceability Graph:** Interactive PyVis/Graphviz visualizer with distinct badges for Documented Real vs Synthetic nodes.
    - **Page 5: Regulatory Assurance Matrix:** ISO/SAE 21434 & UNECE R155 claim trees, evidence freshness indicators, contradiction alerts.
    - **Page 6: Experimental Results & Benchmarking:** Interactive plots reproducing RQ1–RQ4 experiments, baseline comparisons, exportable CSV/JSON.
  - **Exit Criterion:** Complete end-to-end workflow operating via browser and REST API.

- [ ] **Milestone 9: Formal Experimental Evaluation & Reproducibility**
  - Execute automated experiment scripts in `scripts/`:
    - `run_experiment_1.py`: RQ1 (Quality vs Matchability on 200 Wild + 46 Curated SBOMs).
    - `run_experiment_2.py`: RQ2 (Dependency Context Prioritisation on real and synthetic graphs).
    - `run_experiment_3.py`: RQ3 (Assurance Gap & Contradiction Detection accuracy).
    - `run_experiment_4.py`: RQ4 (Scalability stress test: 1 to 500 SBOMs).
  - Save all raw output JSON/CSV files in `research/results/`.
  - Compile summary statistics, confidence intervals, and failure case analyses.
  - **Exit Criterion:** Every number reported in the final report is generated from reproducible command line scripts.

---

### Phase 5: Final Deliverables & Documentation (Milestone 10)
*Goal: Produce comprehensive technical documentation and a public GitHub repository.*

- [ ] **Milestone 10: Final Research Deliverables & Academic Report**
  - Author `research/final_report.md` following the required academic structure:
    1. Abstract
    2. Introduction and Motivation (Volvo Group context)
    3. Research Questions (RQ1–RQ4)
    4. Related Work & Research Gap
    5. Datasets and Data Provenance
    6. System Architecture & Component Resolution
    7. Vulnerability Correlation & Dependency Traversal
    8. Multi-Tier Supplier Traceability
    9. Evidence-Based Assurance Engine (Core Contribution)
    10. Experimental Methodology & Results
    11. Error & Failure Case Analysis
    12. Discussion & Industry Implications (Volvo Group Supply Chains)
    13. Threats to Validity & Limitations
    14. Ethical and Legal Considerations
    15. Conclusion & Future Work
    16. References
  - Author comprehensive `README.md` with architecture diagrams, installation instructions, reproducibility guide, and quickstart commands.
  - Deliver clean Git history with atomic commits for each completed milestone.
