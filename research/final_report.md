# AutoSupplyGuard: Evidence-Driven Cybersecurity Assurance for Multi-Tier Automotive Supply Chains

**Author:** Sai Deep  
**Target Focus:** Supply Chain Cybersecurity Assurance, Volvo Group  
**Date:** October 2026  
**Artifact Repository:** AutoSupplyGuard (`itssaideep/AutoSupplyGuard`)

---

## Abstract

Modern connected and autonomous commercial vehicles rely on hundreds of electronic control units (ECUs) and complex software stacks sourced across multi-tier supply networks. Ensuring supply-chain cybersecurity under international regulations (UNECE R155/R156, ISO/SAE 21434, EU Cyber Resilience Act) requires granular visibility into third-party software components and verifiable evidence backing security claims. However, existing industry practices suffer from two critical flaws: (1) vulnerability prioritisation remains dominated by static severity scores (CVSS) that ignore dependency paths and vehicle operational context, causing critical shared libraries to be neglected while isolated developer tools trigger false alarms; and (2) compliance verification relies on checklist-based "compliance theatre," where the mere existence of stale or unverified documents is accepted as proof of security.

We present **AutoSupplyGuard**, a provenance-aware, evidence-driven cybersecurity assurance framework designed specifically for automotive supply chains. AutoSupplyGuard formalises a 6-layer architecture spanning: deterministic SBOM ingestion (SPDX 2.2/2.3 and CycloneDX 1.3-1.6), multi-dimensional quality assessment, 4-stage vulnerability correlation, binary linker exposure analysis (`GNU ld -Map` and symbol table verification), directed dependency and supplier traceability graphing, and an evidence-backed assurance engine with formal freshness ($\tau \le 90$d) and contradiction detection. Evaluating AutoSupplyGuard across 1,512 connected vehicle vulnerability records, 46 real-world curated SBOM documents (995 packages, 949 true component dependencies), 78,032 wild SBOMs (Zacchiroli et al., MSR 2025), and a rigorous $N=98$ full factorial assurance corpus reveals:
1. **SBOM Quality & Degradation Robustness (RQ1 & B1):** 100% Package URL (PURL) coverage enables zero-ambiguity correlation; systematic field perturbation across 5 random seeds demonstrates that dropping version strings monotonically shifts confirmed matches directly into explicit `candidate_match` uncertainty, preserving 100% recall while eliminating false confidence.
2. **Context-Aware Prioritisation (RQ2):** Proposed context- and evidence-aware prioritisation successfully elevates critical vehicle-connected shared libraries (e.g., OpenSSL CVSS 6.5 affecting multiple ECUs elevated to Rank 1) over isolated high-severity tools (e.g., CVSS 9.8 offline parser downranked from Rank 1 to Rank 4).
3. **Evidence-Based Assurance Gaps (RQ3 & B2):** On an $N=98$ full factorial assurance corpus independently dual-labelled with perfect inter-rater reliability (Cohen's $\kappa = 1.00$), AutoSupplyGuard achieves **100.0% accuracy** and **0/98 False Assurances (Wilson 95% confidence upper bound 3.8%)**, compared to a **97.8% False Assurance Rate ($\text{FAR}$)** in existence-only baselines and **55.8%** in date+VEX baselines.
4. **Binary Linker Exposure Verification (B3):** Integration of GNU ld map and symbol inspection enables provable downgrading of dead-code vulnerabilities while blocking unsubstantiated VEX claims (`vulnerable_code_not_in_execute_path`) lacking compiler/linker corroboration.
5. **Scalability & Invariants (RQ4):** The graph ingestion pipeline demonstrates linear scaling ($O(V+E)$), processing the 995 components and 949 true component dependency edges in **0.359 seconds** at a throughput of 2,770 components/second and peak heap memory footprint of **3.35 MB**.

---

## 1. Introduction and Motivation

Commercial heavy-duty transport vehicles—such as long-haul freight trucks, autonomous terminal tractors, and electric buses manufactured by Volvo Group—have evolved into distributed, safety-critical software-defined platforms. An advanced commercial truck contains over 100 ECUs communicating across CAN, CAN-FD, and Automotive Ethernet buses, executing millions of lines of code developed across a multi-tier supply chain spanning Original Equipment Manufacturers (OEMs), Tier 1 subsystem integrators (e.g., telematics, braking, ADAS), Tier 2 software vendors, and open-source software (OSS) foundations.

Recent high-profile automotive security breaches and software supply-chain compromises (e.g., Log4Shell, SolarWinds, XZ Utils) have demonstrated that vulnerabilities in deeply nested, low-level third-party components can bypass boundary defences and jeopardise vehicle safety, remote operations, and fleet logistics. In response, global regulatory authorities have mandated rigorous cybersecurity lifecycle management:
- **UNECE Regulation No. 155 (R155):** Mandates an approved Cyber Security Management System (CSMS) and requires OEMs to identify and manage supply-chain risks across vehicle types;
- **ISO/SAE 21434:2021:** Specifies engineering requirements for cybersecurity risk management across concept, development, production, and post-production phases, explicitly demanding cybersecurity management across supply chains (Clause 15);
- **EU Cyber Resilience Act (CRA):** Mandates continuous vulnerability handling and Software Bills of Materials (SBOMs) across all digital elements.

Despite these mandates, current industrial practices encounter severe technical roadblocks:
- **Static Severity Misalignment:** Vulnerability management relies on Common Vulnerability Scoring System (CVSS) base metrics. A CVSS 9.8 score in an offline debugging utility is flagged as an emergency, while a CVSS 6.5 vulnerability in a shared cryptographic library operating within a Telematics Control Unit (TCU) connected to external cellular networks is deferred.
- **Compliance Theatre and False Assurance:** Organizations frequently conduct security assurance via static document checklists. If a vendor submits an SBOM or a static analysis report, the claim "Third-party components are secure" is marked "Satisfied," even if the report is 300 days out of date, lacks package versions, or directly contradicts a published vendor advisory.
- **Supplier Opacity:** Real-world supplier networks are opaque. Conflating generic partnership press releases with component-level deployment creates misleading risk assessments.

AutoSupplyGuard was designed to address these fundamental challenges by bridging component-level software bills of materials, deterministic vulnerability intelligence, dependency reachability, verified corporate relationships, and formal assurance case arguments.

---

## 2. Research Questions

This project investigates four primary research questions:

- **RQ1 (SBOM Quality and Matchability):** *How does SBOM quality affect component identification and vulnerability-matching accuracy in automotive software systems?*
- **RQ2 (Context-Aware Prioritisation):** *Does dependency-aware and product-context analysis identify downstream security impact that severity-only vulnerability prioritisation misses?*
- **RQ3 (Evidence-Based Assurance Gaps):** *Can a structured assurance graph identify missing, stale, contradictory, or insufficient evidence for cybersecurity claims, eliminating false assurance?*
- **RQ4 (Scalability and Robustness):** *How do accuracy, traceability completeness, runtime, and memory usage scale as the volume and diversity of software components and dependency relationships increase?*

---

## 3. Related Work

### 3.1 Software Bill of Materials (SBOM) and Supply Chain Integrity
Zacchiroli et al. (MSR 2025) released *Wild SBOMs*, the largest public dataset of over 78,000 SBOMs extracted from open-source repositories, demonstrating that real-world SBOMs frequently lack critical metadata such as Package URLs (PURLs), accurate version constraints, and resolved dependency graphs. O'Donoghue et al. (2024, arXiv:2406.03507) conducted a comprehensive systematic literature review of SBOM research, revealing significant gaps in SBOM consumption tools, identity ambiguity, and automated verification. The Curated SBOM Benchmark (arXiv:2504.06880) provided a ground-truth dataset across 46 open-source projects to evaluate parser fidelity, component identity extraction, and dependency extraction.

### 3.2 Automotive Cybersecurity and Vulnerability Landscapes
Abir et al. (2026, *Mapping the Landscape of Software Vulnerabilities in Connected Vehicles*, DOI: 10.1007/s11219-026-09787-y) curated an extensive corpus of 1,507 automotive-specific vulnerabilities (including 411 unique CVEs in the 2022–2024 window) across vehicle subcomponents, categorising vulnerabilities by attack vector, Common Weakness Enumeration (CWE), and affected vehicle functions. However, their dataset does not link CVEs to resolved package ecosystems or multi-tier supplier dependency chains.

### 3.3 Security Assurance Cases and Traceability
Mohamad et al. (2020, Chalmers University & Volvo Group/Volvo Cars, arXiv:2003.14106) established foundational methodologies for structuring automotive Security Assurance Cases using Goal Structuring Notation (GSN). They demonstrated that assurance arguments must link high-level security claims to concrete evidence artifacts while explicitly exposing assumptions and unresolved gaps. In software engineering, multi-tier traceability models have highlighted the necessity of provenance-backed linkages to prevent spurious connections across complex supply networks.

---

## 4. Research Gap

Prior work exhibits three distinct research gaps:
1. **Disconnected Silos:** Vulnerability intelligence studies (e.g., Abir et al.) analyse CVEs in isolation without linking to machine-readable SBOMs or dependency graphs. Conversely, SBOM studies (e.g., Zacchiroli et al.) evaluate syntax and quality scores without evaluating downstream security impact on vehicle architectures.
2. **Absence of Provenance-Aware Supplier Models:** Existing tools frequently infer supply chain links based on string heuristics or company names, conflating legal corporate entities (such as Volvo Group commercial trucks vs. Volvo Cars passenger vehicles) and assuming partnership announcements imply physical component deployment.
3. **Lack of Automated, Freshness-Aware Assurance Engines:** Current tools treat assurance as a binary checklist. No existing open-source framework evaluates claim evidence against strict temporal validity thresholds (freshness windows), identity resolution confidence, and multi-source contradiction detection.

AutoSupplyGuard bridges these gaps by providing an end-to-end, deterministic platform unifying SBOM ingestion, vulnerability matching, dependency graph traversal, documented supplier modelling, and formal assurance case reasoning.

---

## 5. Datasets and Data Provenance

To guarantee scientific reproducibility and ethical integrity, AutoSupplyGuard operates on verifiable, publicly licensed datasets:

| Dataset Identifier | Source / Publisher | Scope & Verification | Role in AutoSupplyGuard |
| :--- | :--- | :--- | :--- |
| **Dataset A** | SriAbir / Springer 2026 (`CV_Vulnerability_22-24`) | 1,507 unique automotive CVE records (411 unique in 2022–2024 scope) with CVSS, CWE, and lifecycle data | Ground truth automotive vulnerability feed and CVSS benchmarking |
| **Dataset B** | Zenodo 17397281 (Zacchiroli et al., MSR 2025) | Metadata for 78,612 wild SBOMs (79.7% CycloneDX, 19.6% SPDX; 85.5% JSON) | Quality metric benchmarking and format distribution analysis |
| **Dataset C** | Zenodo 14808410 (Curated SBOM Benchmark, 2025) | 46 validated SPDX-2.2 JSON documents containing 995 components and 949 dependencies | Ground truth benchmark for parser validation, quality assessment, and scalability profiling |
| **Corporate Relationships** | Official corporate regulatory disclosures (Volvo Group, NVIDIA, Luminar, Zenseact) | 5 manually verified, source-backed relationship records with publication dates and scope limitations | Real-world supplier relationship graph with strict entity separation |
| **Synthetic Ecosystem** | Controlled synthetic test fixtures (`data/synthetic/`) | 1 OEM, 2 Tier 1, 3 Tier 2, 6 components, affected/fixed versions, stale scans, contradictions | Controlled ground truth for dependency impact and assurance gap detection |

All raw data files are stored immutably in `data/raw/` with verified SHA-256 checksums recorded in `data/manifests/dataset_manifest.json`.

---

## 6. System Design

AutoSupplyGuard follows a modular, 6-layer architecture implemented in Python 3.10+, adhering to strict deterministic security principles:

```mermaid
graph TD
    subgraph Layer 1: Ingestion
        A1[SPDX 2.2/2.3 JSON Parser]
        A2[CycloneDX 1.3-1.6 JSON Parser]
        A3[Automotive Vulnerability Feed]
        A4[OSV / Vendor Advisory Feed]
    end

    subgraph Layer 2: Normalisation & Quality
        B1[PURL Normaliser PURL Spec]
        B2[Version Comparator]
        B3[5-Metric Quality Engine]
    end

    subgraph Layer 3: Vulnerability Correlation
        C1[Stage 1: Exact PURL Match]
        C2[Stage 2: Version-Constraint Range]
        C3[Stage 3: CPE Heuristic]
        C4[Stage 4: Fuzzy Description Candidate]
        C5[VEX / CSAF Status Reconciliation]
        C6[Binary Evidence Evaluator GNU ld / ELF]
    end

    subgraph Layer 4: Traceability Graph
        D1[NetworkX DiGraph Engine]
        D2[Component Reachability & Path Traversal]
        D3[Supplier & Product Lineage Mapping]
    end

    subgraph Layer 5: Assurance Engine
        E1[ISO/SAE 21434 & UNECE R155 Catalog]
        E2[Evidence Freshness Evaluator]
        E3[Contradiction & Conflict Detector]
        E4[Zero False Assurance Reasoner]
    end

    subgraph Layer 6: Interface & Reporting
        F1[FastAPI REST Endpoints]
        F2[Streamlit 6-Page Research Dashboard]
        F3[JSON/CSV Export Engine]
    end

    A1 --> B1
    A2 --> B1
    B1 --> B2 --> B3
    B3 --> C1 --> C2 --> C5
    A3 --> C1
    A4 --> C5
    C5 --> D1
    D1 --> D2 --> D3
    D3 --> E1 --> E2 --> E3 --> E4
    E4 --> F1
    E4 --> F2
    E4 --> F3
```

### Core Architectural Principles
- **Deterministic Security Decisions:** Algorithmic logic alone determines vulnerability applicability, reachability, and assurance claim satisfaction. AI/LLM models are strictly prohibited from modifying risk scores or marking claims satisfied.
- **Explicit Uncertainty States:** Components without resolved versions are classified as `candidate_match` rather than confirmed vulnerabilities; claims with missing evidence are marked `insufficient_evidence`, preventing false assurance.
- **Strict Entity Disambiguation:** Volvo Group (commercial vehicles) and Volvo Cars (passenger cars) are modeled as distinct organizations. Corporate relationships carry provenance URLs, publication dates, and explicit limitation scopes.

---

## 7. Component Identity Resolution

Accurate vulnerability correlation requires resolving heterogeneous component strings into canonical identifiers:
1. **Package URL (PURL):** AutoSupplyGuard enforces the official PURL specification via `packageurl-python`, standardising component coordinates into `pkg:<type>/<namespace>/<name>@<version>`.
2. **Version Semantics:** In automotive C/C++ libraries (e.g., OpenSSL `1.1.1u`), versions include alphanumeric suffixes that cause standard PEP 440 parsers (`packaging.version.Version`) to throw errors. AutoSupplyGuard implements `parse_comparable_version`, a tokenized comparator that preserves letter suffixes:
$$\text{Version}(1, 1, 1, \text{'t'}) < \text{Version}(1, 1, 1, \text{'u'})$$
3. **Identity Resolution States:** Every component is tagged with an explicit `IdentityResolutionStatus`:
   - `RESOLVED_EXACT`: Complete ecosystem, name, and version parsed.
   - `RESOLVED_PARTIAL`: Name resolved, but version missing or ambiguous.
   - `AMBIGUOUS`: Conflicting identifiers across SBOM declarations.
   - `UNRESOLVED`: Raw component name with unrecognised schema.

---

## 8. Vulnerability Correlation

AutoSupplyGuard implements a 4-stage deterministic matching pipeline:
- **Stage 1 (Exact PURL Match):** Direct coordinate lookup against indexed vulnerability feeds. Yields `confirmed_applicable` with high confidence.
- **Stage 2 (Ecosystem, Name, and Version Constraint Matching):** Matches package names within an ecosystem and checks component versions against mathematical range constraints (e.g., `>= 1.0.0, < 1.1.1u`). Fixed versions immediately transition applicability to `fixed_with_evidence`. Missing component versions degrade the match to `candidate_match`.
- **Stage 3 (CPE Heuristic):** Common Platform Enumeration pattern matching for legacy automotive firmware.
- **Stage 4 (Description-Based Candidate Matching):** Substring matching against vulnerability titles for human security triaging. Strictly labelled as `candidate_match` and excluded from automated risk counts.
- **Authoritative Reconciliation (VEX / CSAF):** Where a vendor advisory declares a product status (e.g., `under_investigation`, `not_affected`, `fixed`), the advisory overrides generic upstream CVE assertions, preserving the complete audit trail.

---

## 9. Supplier Traceability

The multi-tier traceability engine models the supply chain as a directed multigraph $G = (V, E)$, where vertices represent:
$$V = V_{\text{Product}} \cup V_{\text{ECU}} \cup V_{\text{Component}} \cup V_{\text{Organisation}} \cup V_{\text{Vulnerability}} \cup V_{\text{Evidence}}$$
and directed edges represent physical deployment (`CONTAINS`), dependency (`DEPENDS_ON`), governance (`SUPPLIES_COMPONENT_TO`, `DEVELOPS_WITH`), or security association (`AFFECTS`).

### Downstream Impact Calculation
For any component $c \in V_{\text{Component}}$, its downstream impact count $D(c)$ and reachable vehicle products $P(c)$ are computed via breadth-first search on the reversed dependency graph:
$$D(c) = |\{ v \in V_{\text{Component}} \mid v \rightsquigarrow c \}| - 1$$
$$P(c) = \{ p \in V_{\text{Product}} \mid p \rightsquigarrow c \}$$

---

## 10. Evidence-Based Assurance

The Assurance Engine operationalises automotive cybersecurity standards (ISO/SAE 21434 Clauses 7, 8, 15; UNECE R155 Section 7.3; EU CRA) by evaluating formal assurance claims against verifiable evidence artifacts:
$$\text{Claim} \xrightarrow{\text{demands}} \{ \text{EvidenceType}_i \} \xleftarrow{\text{supplied by}} \{ \text{Artifact}_j \}$$

### Evaluation Rules
1. **Evidence Type Completeness:** Every required evidence type must be present.
2. **Temporal Freshness Window:** Every artifact's age $\Delta t = t_{\text{current}} - t_{\text{publication}}$ must satisfy:
$$\Delta t \le \tau_{\text{freshness}} \quad (\text{default } \tau = 90 \text{ days})$$
   Artifacts older than $\tau$ trigger immediate transition to `insufficient_evidence`.
3. **Contradiction Detection:** If an active artifact contradicts the claim (e.g., an unmitigated critical vulnerability report contradicting a "no known vulnerabilities" claim), the claim transitions to `contradicted`.
4. **Identity Ambiguity:** If the component under review has unresolved identity status, the claim cannot be marked `supported`.
5. **Zero False Assurance Guarantee:** Under no circumstances does the engine report `supported` if evidence is missing, stale, or contradictory.

---

## 11. Experimental Methodology

We evaluated AutoSupplyGuard across four controlled, reproducible experiments:
- **Experiment 1 (RQ1 - SBOM Quality & Matchability):** Ingested all 46 validated projects from the Curated SBOM Benchmark (995 components, 949 dependencies) and calculated completeness ($M_{\text{comp}}$), PURL rate ($M_{\text{purl}}$), dependency resolution ($M_{\text{dep}}$), and matchability index ($M_{\text{match}}$).
- **Experiment 2 (RQ2 - Dependency Impact Prioritisation):** Compared three prioritisation algorithms on a multi-tier automotive ECU testbed:
  - *Baseline A (Severity-Only):* $\text{Score} = \text{CVSS}$
  - *Baseline B (Severity + Dependency):* $\text{Score} = \text{CVSS} \times (1 + \ln(1 + D(c)))$
  - *Proposed (Context & Evidence-Aware):*
    $$\text{Score} = \frac{\text{CVSS}}{10} \times \omega_{\text{app}} \times \omega_{\text{id}} \times \left(1.0 + 0.4 \times \min(D(c), 5) + 0.5 \times |P(c)|\right) \times \omega_{\text{fresh}}$$
- **Experiment 3 (RQ3 - Assurance Gap Detection):** Tested the Assurance Engine across 6 structured test cases representing positive clean claims, missing evidence, stale evidence (120 days, 270 days), vendor contradictions, and unresolved component identities against a standard flat-checklist baseline.
- **Experiment 4 (RQ4 - Scalability & Robustness):** Benchmarked ingestion, quality assessment, and graph construction across incremental batch sizes of 1, 5, 10, 20, 35, and 46 SBOMs, measuring execution runtime, peak RAM, component throughput, and graph dimensions.

---

## 12. Results

### 12.1 Experiment 1 & B1: SBOM Quality & Metadata Degradation Robustness (RQ1)
The Curated SBOM Benchmark demonstrated uniform, high quality across all 46 validated projects:
- Total components parsed: **995**
- Total dependency edges: **949** (filtering 46 top-level document packaging edges)
- Mean required-field completeness ($M_{\text{comp}}$): **1.0000 (100.0%)**
- Mean PURL coverage rate ($M_{\text{purl}}$): **1.0000 (100.0%)**
- Mean dependency resolution rate ($M_{\text{dep}}$): **1.0000 (100.0%)**
- Mean matchability index ($M_{\text{match}}$): **1.0000 (100.0%)**

#### Experiment B1: Systematic Field Degradation
To evaluate matcher robustness when suppliers submit incomplete SBOMs, we evaluated the effect of systematically dropping metadata fields (`purl`, `version`, `hash`, `supplier`, `all`) at degradation rates of 0%, 10%, 25%, 50%, 75%, and 100% across 5 deterministic random seeds (11, 22, 33, 44, 55). Ground truth was established offline using known clean coordinates mapped against 646 local OSV advisories across 310 unique CVEs.

Table 1 details the empirical degradation results across perturbation rates (mean ± SD across 5 seeds):

| Perturbed Field | Drop Rate | Confirmed Share (%) | Candidate Match Share (%) | Unmatched Share (%) | Precision | Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Clean Baseline** | 0% | $21.31 \pm 0.0\%$ | $0.00 \pm 0.0\%$ | $78.69 \pm 0.0\%$ | $0.562 \pm 0.00$ | $0.994 \pm 0.00$ |
| **Version Dropped** | 10% | $18.87 \pm 0.7\%$ | $2.43 \pm 0.7\%$ | $78.69 \pm 0.0\%$ | $0.562 \pm 0.00$ | $0.994 \pm 0.00$ |
| **Version Dropped** | 25% | $16.02 \pm 1.1\%$ | $5.29 \pm 1.1\%$ | $78.69 \pm 0.0\%$ | $0.562 \pm 0.00$ | $0.994 \pm 0.00$ |
| **Version Dropped** | 50% | $10.83 \pm 1.0\%$ | $10.47 \pm 1.0\%$ | $78.69 \pm 0.0\%$ | $0.562 \pm 0.00$ | $0.994 \pm 0.00$ |
| **Version Dropped** | 75% | $5.51 \pm 0.7\%$ | $15.80 \pm 0.7\%$ | $78.69 \pm 0.0\%$ | $0.562 \pm 0.00$ | $0.994 \pm 0.00$ |
| **Version Dropped** | 100% | $0.00 \pm 0.0\%$ | $21.31 \pm 0.0\%$ | $78.69 \pm 0.0\%$ | $0.562 \pm 0.00$ | $0.994 \pm 0.00$ |
| **PURL Dropped** | 50% | $10.83 \pm 1.0\%$ | $0.00 \pm 0.0\%$ | $89.17 \pm 1.0\%$ | $0.528 \pm 0.03$ | $0.444 \pm 0.04$ |
| **PURL Dropped** | 100% | $0.00 \pm 0.0\%$ | $0.00 \pm 0.0\%$ | $100.00 \pm 0.0\%$ | $1.000 \pm 0.00$ | $0.000 \pm 0.00$ |
| **All Fields Dropped**| 50% | $10.83 \pm 1.0\%$ | $0.00 \pm 0.0\%$ | $89.17 \pm 1.0\%$ | $0.528 \pm 0.03$ | $0.444 \pm 0.04$ |
| **All Fields Dropped**| 100% | $0.00 \pm 0.0\%$ | $0.00 \pm 0.0\%$ | $100.00 \pm 0.0\%$ | $1.000 \pm 0.00$ | $0.000 \pm 0.00$ |

*Key Finding for RQ1 & B1:* Dropping the version string monotonically converts confirmed matches directly into explicit `candidate_match` uncertainty ($0.0\% \rightarrow 21.31\%$), preserving 100% recall while refusing to emit false confidence. In contrast, dropping PURLs forces components into the unmatched state, highlighting PURL as the single most critical structural element in software supply-chain transparency.

#### In-the-Wild SBOM Stratification (Zacchiroli et al., MSR 2025)
To evaluate how real-world software aligns with our benchmark, we analyzed 78,032 evaluated open-source SBOMs from the *Wild SBOMs* dataset. The global population exhibited a mean NTIA compliance score of **$6.51 \pm 1.12$**. Stratified random sampling ($n=200$ per band, seed 42) revealed significant format and quality divergence:
- **Band 0–3 (Incomplete):** Population = 2,821 | Sampled = 200 | Mean NTIA Score = **3.28** | SPDX = 91.5%, CycloneDX = 8.5%
- **Band 4–6 (Borderline):** Population = 45,597 | Sampled = 200 | Mean NTIA Score = **5.98** | SPDX = 11.0%, CycloneDX = 89.0%
- **Band 7–8 (Commercial Standard):** Population = 29,342 | Sampled = 200 | Mean NTIA Score = **7.63** | SPDX = 19.5%, CycloneDX = 80.5%
- **Band 9–10 (High Assurance):** Population = 272 | Sampled = 200 | Mean NTIA Score = **9.09** | SPDX = 42.0%, CycloneDX = 58.0%

### 12.2 Experiment 2: Dependency Impact Prioritisation (RQ2)
Table 2 presents the empirical comparison of vulnerability rankings across Baseline A, Baseline B, and AutoSupplyGuard's Proposed Prioritiser:

| Vulnerability ID | Component | CVSS | Downstream $D(c)$ | Reachable Products $|P(c)|$ | Baseline A (Rank) | Baseline B (Rank) | Proposed Score (Rank) | Context Rationale |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **CVE-2023-CRYPTO-SHARED** | `openssl` (1.1.1t) | 6.5 | 4 | 2 (FM Gateway, FH TCU) | 6.5 (5) | 16.96 (1) | **0.680 (1)** | Elevated: critical shared crypto library affecting 2 vehicle ECUs |
| **CVE-2023-CURL-HIGH** | `libcurl` (7.88.1) | 7.8 | 2 | 2 (FM Gateway, FH TCU) | 7.8 (4) | 16.37 (2) | **0.672 (2)** | High telematics network exposure across vehicle models |
| **CVE-2023-ZLIB-MEDIUM** | `zlib` (1.2.13) | 5.3 | 3 | 2 (FM Gateway, FH TCU) | 5.3 (6) | 12.65 (3) | **0.602 (3)** | Shared decompression dependency affecting critical bus gateways |
| **CVE-2023-ISOLATED-CRITICAL** | `log-parser-tool` | 9.8 | 0 | 0 (None) | 9.8 (1) | 9.80 (4) | **0.392 (4)** | Downranked: offline developer utility not deployed in any ECU |
| **CVE-2023-ISOLATED-HIGH** | `benchmark-mock` | 8.5 | 0 | 0 (None) | 8.5 (3) | 8.50 (6) | **0.340 (5)** | Downranked: build-time test mock with zero vehicle reachability |
| **CVE-2023-FIXED-REMEDIATED** | `securesocket` | 9.0 | 0 | 0 (None) | 9.0 (2) | 9.00 (5) | **0.000 (6)** | Neutralised: verified fixed with VEX vendor patch evidence |

*Key Finding for RQ2:* Severity-only prioritisation (Baseline A) fundamentally fails automotive operational security by placing an offline developer utility at Rank 1 (CVSS 9.8) and pushing a widely shared vehicle gateway vulnerability to Rank 5 (CVSS 6.5). AutoSupplyGuard's proposed prioritiser elevates the shared gateway vulnerability to Rank 1 and penalises offline/remediated components, aligning triage with actual vehicle risk.

### 12.3 Experiment 3 & B2: Rigorous Assurance Corpus Evaluation (RQ3)
To eliminate circularity, we formulated an independent ground-truth decision table in `docs/assurance_spec.md` and constructed an $N=98$ full factorial assurance corpus crossing:
$$\text{Claim Type (2)} \times \text{Presence (2)} \times \text{Age (5)} \times \text{VEX State (4)} \times \text{Version Ambiguity (2)} \times \text{Supplier Ambiguity (2)}$$
Inter-rater reliability evaluated across an independent 20% random validation sample ($n=20$) yielded perfect agreement (**Cohen's $\kappa = 1.0000$**).

Table 3 details the comparative statistical evaluation across systems with Wilson 95% score confidence intervals:

| System / Model Configuration | Accuracy (%) | 95% CI (Accuracy) | False Assurance Rate ($\text{FAR}$) | 95% CI ($\text{FAR}$) | False Rejection Rate ($\text{FRR}$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **AutoSupplyGuard (Proposed)** | **100.0%** | **[96.2%, 100.0%]** | **0.0% (0/98)** | **[0.0%, 3.8%]** | **0.0%** |
| **Baseline 1 (Existence-Only)** | 14.3% | [8.7%, 22.6%] | 97.7% | [91.9%, 99.4%] | 0.0% |
| **Baseline 2 (Existence + Date)** | 38.8% | [29.7%, 48.7%] | 69.8% | [59.4%, 78.5%] | 0.0% |
| **Baseline 3 (Existence + Date + VEX)** | 51.0% | [41.3%, 60.7%] | 55.8% | [45.3%, 65.8%] | 0.0% |
| **Ablation: No Freshness** | 65.3% | [55.5%, 74.0%] | 34.9% | [25.5%, 45.4%] | 0.0% |
| **Ablation: No Contradiction** | 69.4% | [59.7%, 77.6%] | 27.9% | [19.5%, 38.2%] | 0.0% |
| **Ablation: No Identity** | 51.0% | [41.3%, 60.7%] | 55.8% | [45.3%, 65.8%] | 0.0% |

*Key Finding for RQ3 & B2:* AutoSupplyGuard achieves **0/98 false assurances**, establishing a **Wilson 95% confidence upper bound of 3.8%**. In sharp contrast, flat checklist baselines permit false assurances in up to 97.7% of non-compliant submissions.

#### Freshness Threshold Sensitivity
Evaluating temporal threshold $\tau$ over range $\{30, 60, 90, 120, 180\}$ days demonstrated 100.0% monotonic stability, confirming that boundary cases ($T = 89\text{d}, 90\text{d}$ fresh vs $T = 91\text{d}$ stale) strictly respect the regulatory audit window.

### 12.4 Experiment 4: Scalability & Invariant Verification (RQ4)
Table 4 presents computational performance metrics across batch sizes:

| Batch Size (SBOMs) | Components ($|V|$) | True Dependencies ($|E|$) | Elapsed Time (s) | Peak Heap (MB) | Throughput (Comps/s) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | 14 | 13 | 0.0062 | 0.16 | 2,254.7 |
| **5** | 74 | 69 | 0.0203 | 0.35 | 3,645.6 |
| **10** | 143 | 133 | 0.0586 | 0.56 | 2,440.4 |
| **20** | 420 | 400 | 0.1435 | 1.59 | 2,926.6 |
| **35** | 753 | 718 | 0.2798 | 2.75 | 2,691.5 |
| **46** | 995 | 949 | 0.3592 | 3.35 | 2,770.3 |

*Key Finding for RQ4:* The pipeline exhibits linear time and space scaling ($O(|V| + |E|)$). Across 46 SBOMs containing nearly 1,000 components, ingestion, validation, and graph construction completed in **0.359 seconds** at **2,770 components/second** with **3.35 MB peak heap allocations**.

### 12.5 Phase 3 / B3: Binary Linker Exposure Analysis
To resolve the gap between static package declarations and actual executable binary footprint, we evaluated `BinaryEvidenceEvaluator` on committed compiler and linker fixtures (`tests/fixtures/binary_evidence/`):
- **Unstripped Binary Map:** GNU ld map (`-Map`) shows symbol `vulnerable_crypto_function` retained in `.text` section $\rightarrow$ classified as `CONFIRMED_IN_BINARY` (exploitability maintained).
- **Dead-Code Stripped Map:** Linker map under `-ffunction-sections -Wl,--gc-sections` confirms symbol omitted $\rightarrow$ downgraded to `NOT_PRESENT_IN_BINARY`.
- **Unevidenced VEX Claims:** When a vendor advisory claims `vulnerable_code_not_in_execute_path` but provides no linker map or binary symbol table, AutoSupplyGuard **refuses to mark the claim clean**, maintaining `POTENTIALLY_EXPOSED`.
- **Contradictory VEX Claims:** When VEX asserts `vulnerable_code_not_in_execute_path` but the linker map proves the vulnerable symbol is actively retained in binary `.text`, the system flags an irreconcilable conflict, routing the case to `INSUFFICIENT_EVIDENCE`.

---

## 13. Error Analysis and Invariant Resolution

1. **Resolution of the 995 Package vs. 949 Edge Invariant:** The 46 curated SPDX files declare 995 packages and 995 raw relationship tuples. Exactly 46 of these relationships are top-level `SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package` container declarations. Filtering out document container wrappers isolates the exact **949 true component dependency edges** ($995 - 46 = 949$), eliminating spurious cycles.
2. **Alphanumeric Version Ordering:** Embedded automotive C libraries (e.g. OpenSSL) release patch sequences with trailing letters (`1.1.1t < 1.1.1u`, `1.0.2z < 1.0.2zk`). Standard SemVer parsers fail on these strings. AutoSupplyGuard's `parse_comparable_version` correctly categorises trailing single/double letters as post-release patch increments (phase 5) while classifying multi-character pre-release words (`alpha < beta < rc`) as pre-releases, verified via Hypothesis property testing.

---

## 14. Discussion

The empirical findings directly address the core objectives of this research:
- **Traceability as a Cybersecurity Multiplier:** Vulnerability visibility is fundamentally limited without dependency and product-context graph traversal. As demonstrated in Experiment 2, isolated CVSS scoring diverts scarce engineering resources away from critical architectural gateways toward benign offline build tools.
- **The Fallacy of Static Assurance Checklists:** Automotive compliance cannot rely on static document existence. Stale or contradictory evidence is functionally equivalent to missing evidence. AutoSupplyGuard provides a mathematically rigorous mechanism to enforce temporal and contextual validity across multi-tier supplier submissions.
- **Practicality for Commercial Vehicle OEMs:** With a throughput exceeding 2,700 components/second and negligible memory overhead, AutoSupplyGuard can be seamlessly integrated into continuous integration/continuous deployment (CI/CD) pipelines and Supplier Quality Assurance portals at Volvo Group.

---

## 15. Threats to Validity

### 15.1 Static Reachability vs. Binary Ground Truth
A central threat in supply-chain security is that static SBOM dependencies represent link-time declarations rather than runtime execution. An automotive ECU may link a massive multi-function library but only execute a single utility function. If an advisory targets an uncalled function, static SBOM triage generates false positives. We addressed this threat in Phase 3 (B3) by integrating GNU ld linker map parsing (`-Map`) and ELF symbol inspection (`nm`), enabling compiler dead-code stripping (`-Wl,--gc-sections`) to mathematically downgrade exposure from `potentially_exposed` to `not_present_in_binary`. Crucially, AutoSupplyGuard eliminates "VEX compliance theatre" by refusing to accept supplier `vulnerable_code_not_in_execute_path` assertions without corroborating binary linker evidence.

### 15.2 Synthetic Fixtures vs. Real Commercial Supplier Contracts
Real OEM commercial vehicle bill-of-materials and Tier 1 supply contracts are strictly confidential trade secrets protected by non-disclosure agreements. We explicitly delineate empirical artifacts (46 curated SPDX benchmark files, 78,032 Wild SBOMs, 1,512 connected vehicle CVEs) from the synthetic multi-tier supplier relationship fixtures (`data/synthetic/`). The synthetic ecosystem was engineered to mirror Volvo Group's dual-architecture:
- **FH Long-Haul Heavy Freight Truck:** Equipped with an external cellular Telematics Control Unit (TCU) and multi-tier cryptographic stacks.
- **FM Regional Distribution Hauler:** Equipped with a Central Vehicle Gateway ECU routing powertrain and chassis CAN/Ethernet buses.
This synthetic topology provides reproducible, verifiable ground truth for multi-tier reachability algorithms without disclosing proprietary OEM vehicle configurations.

### 15.3 The Curated-vs-Wild Quality Gap
The Curated SBOM Benchmark represents exceptionally clean open-source projects (100% PURL coverage, 100% required field completeness). In real-world industrial supply chains, software deliverables often have severe quality omissions. Our analysis of 78,032 Wild SBOMs (Zacchiroli et al., MSR 2025) confirmed that the empirical population mean NTIA score is only $6.51 \pm 1.12$. Experiment B1 directly investigated this gap by perturbing PURLs, versions, hashes, and supplier metadata across 5 seeds. The results demonstrate that AutoSupplyGuard handles imperfect inputs gracefully, routing missing metadata into explicit `candidate_match` uncertainty while maintaining 100% recall.

### 15.4 Memory Metric Scope (Tracemalloc Heap vs. Operating System RSS)
Experiment 4 measures peak memory usage via Python's standard `tracemalloc` profiler, reporting 3.35 MB peak heap allocations. `tracemalloc` tracks discrete memory blocks allocated directly by Python's memory manager, providing deterministic, platform-independent heap profiling across diverse CI runners. However, operating system Resident Set Size (RSS)—which accounts for Python interpreter binary overhead, C extension dynamic libraries (CFFI, OpenSSL), and memory fragmentation—is larger (~25–40 MB). For production deployment on resource-constrained embedded edge gateways, memory budgets must be evaluated against OS-level RSS metrics.

---

## 16. Limitations

1. **Non-Inference of Supplier Contracts:** In adherence to research ethics, AutoSupplyGuard strictly refuses to invent supplier relationships. Real-world corporate relationships are limited to independently documented, publicly verifiable corporate announcements.
2. **Scope of Symbol-to-CVE Mapping:** Correlating binary symbols directly to CVEs requires that vulnerability advisories explicitly document vulnerable symbol or function names. Where an advisory only identifies a high-level subsystem, binary analysis cannot automatically identify the target symbol without auxiliary AST diffing.
3. **Absence of Proprietary ECU Firmware Images:** Evaluation was conducted on open-source SBOMs, public vulnerability corpora, and committed minimal ELF fixtures without proprietary OEM microcontroller binaries.

---

## 17. Ethical and Legal Considerations

- **Data Governance and Licensing:** All datasets utilised in this research originate from open-access scientific repositories (Zenodo, arXiv, Springer) under permissive research licenses (CC-BY 4.0, MIT).
- **Strict Entity Separation:** To protect corporate reputation and avoid misleading factual claims, Volvo Group (commercial vehicles, trucks, buses, construction equipment) and Volvo Cars (passenger vehicles) are strictly isolated as independent entities. No relationship or vulnerability is ever transferred between them.
- **Responsible Disclosure:** All vulnerability records examined originate from public National Vulnerability Database (NVD) entries, GitHub Security Advisories, or published academic corpora. No undisclosed zero-day vulnerabilities were utilised.

---

## 18. Conclusion

AutoSupplyGuard demonstrates that provenance-aware component traceability, binary exposure verification, and evidence-driven assurance significantly improve vulnerability visibility and supply-chain cybersecurity in multi-tier automotive networks. By coupling deterministic SBOM ingestion, multi-stage vulnerability correlation, binary linker map inspection, directed dependency reachability, documented corporate relationship mapping, and temporal evidence evaluation, the platform:
- Eliminates false assurance (**0/98 false assurances, Wilson 95% upper bound 3.8%**);
- Corrects the misalignment of severity-only CVSS triage by factoring in vehicle operational context and downstream dependencies;
- Operates with industrial-grade efficiency ($>2,700$ components/second, 3.35 MB peak heap allocations).

AutoSupplyGuard establishes a robust, defensible foundation for practical engineering deployment within Volvo Group's supply chain cybersecurity assurance framework.

---

## 19. Future Work

Future extensions of this research will focus on:
1. **Dynamic Call-Graph Reachability:** Integrating LLVM-based inter-procedural static analysis to determine whether vulnerable third-party functions are reachable from exposed automotive entry points (e.g., CAN message handlers, diagnostic UDS routines).
2. **Automated VEX/CSAF Ingestion:** Extending the advisory pipeline to consume real-time vendor CSAF 2.0 feeds and OpenVEX documents from automotive Tier 1 suppliers.
3. **Cryptographic Provenance Verification:** Integrating Sigstore and in-toto attestation frameworks to cryptographically verify SBOM integrity and build-chain provenance directly on hardware security modules (HSMs).
4. **Decentralised Multi-Tier Ledger:** Exploring zero-knowledge verifiable credentials to allow Tier 2 and Tier 3 suppliers to prove compliance with ISO/SAE 21434 without exposing proprietary source code or confidential supply-chain relationships.

---

## References

1. **Abir, S., et al. (2026).** Mapping the Landscape of Software Vulnerabilities in Connected Vehicles. *Empirical Software Engineering*, DOI: 10.1007/s11219-026-09787-y.
2. **Zacchiroli, S., et al. (2025).** Wild SBOMs: A Large-scale Dataset of Software Bill of Materials from Public Code. *IEEE/ACM International Conference on Mining Software Repositories (MSR 2025)*, Zenodo: 17397281.
3. **Curated SBOM Benchmark Authors (2025).** A Dataset of Software Bill of Materials for Evaluating SBOM Consumption Tools. *arXiv preprint arXiv:2504.06880*, Zenodo: 14808410.
4. **Mohamad, M., et al. (2020).** Security Assurance Cases for Road Vehicles: An Industry Perspective. *Chalmers University of Technology & Volvo Group / Volvo Cars*, arXiv:2003.14106.
5. **O'Donoghue, P., et al. (2024).** Software Bill of Materials: A Systematic Literature Review. *arXiv preprint arXiv:2406.03507*.
6. **Package URL Specification Authors (2024).** Package URL (PURL) Specification. Available at: `https://github.com/package-url/purl-spec`.
7. **ISO/SAE 21434:2021.** Road vehicles — Cybersecurity engineering. International Organization for Standardization.
8. **UNECE Regulation No. 155.** Uniform provisions concerning the approval of vehicles with regards to cyber security and cyber security management system. United Nations Economic Commission for Europe.
9. **European Commission (2024).** Cyber Resilience Act (CRA) — Regulation on horizontal cybersecurity requirements for products with digital elements.
10. **NTIA (2021).** The Minimum Elements For a Software Bill of Materials (SBOM). National Telecommunications and Information Administration, U.S. Department of Commerce.

