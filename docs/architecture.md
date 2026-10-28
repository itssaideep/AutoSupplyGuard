# AutoSupplyGuard Architecture Specification

## 1. System Overview

**AutoSupplyGuard** is an evidence-driven cybersecurity assurance platform designed for multi-tier automotive supply chains. It bridges the gap between low-level Software Bills of Materials (SBOMs), vulnerability intelligence, dependency reachability, verified corporate relationships, and regulatory assurance cases (ISO/SAE 21434, UNECE R155/R156, EU CRA).

## 2. 6-Layer Architecture

AutoSupplyGuard is structured into six strictly decoupled layers:

```
+-------------------------------------------------------------------------+
| Layer 6: Reporting and Interface (FastAPI REST API & Streamlit Dashboard)|
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Layer 5: Evidence-Based Assurance Engine (Claim, Freshness, Contradiction)|
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Layer 4: Multi-Tier Traceability Graph (NetworkX DiGraph, Reachability) |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Layer 3: Vulnerability Correlation Engine (4-Stage Matching, VEX/CSAF)  |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Layer 2: Normalisation and Quality Engine (PURL Spec, SemVer, 5 Metrics) |
+-------------------------------------------------------------------------+
                                    ^
+-------------------------------------------------------------------------+
| Layer 1: Data Ingestion (SPDX 2.2/2.3, CycloneDX 1.3-1.6, CVE Feeds)    |
+-------------------------------------------------------------------------+
```

### Layer 1: Data Ingestion
- **Parsers:** `SPDXParser` (SPDX 2.2/2.3 JSON), `CycloneDXParser` (CycloneDX 1.3-1.6 JSON), and `AutomotiveVulnerabilityFeed`.
- **Integrations:** `OSVClient` with async HTTP polling and local persistent disk caching in `data/interim/vulnerability_cache/`.
- **Integrity:** SHA-256 computation on every input file, recorded immutably in provenance manifests.

### Layer 2: Normalisation & Quality Assessment
- **Package URLs:** Normalized via `packageurl-python` adhering to the Package URL specification (https://github.com/package-url/purl-spec).
- **Version Comparators:** Implements `parse_comparable_version` for C/C++ alphanumeric suffixes (e.g., `1.1.1u`).
- **Quality Metrics:** Computes 5 formal metrics:
  - $M_{\text{comp}}$: Required-field completeness
  - $M_{\text{purl}}$: Package URL coverage rate
  - $M_{\text{dep}}$: Dependency reference resolution rate
  - $M_{\text{dup}}$: Duplicate component rate
  - $M_{\text{match}}$: Vulnerability matchability index

### Layer 3: Vulnerability Correlation Engine
- **4-Stage Deterministic Matcher:**
  - Stage 1: Exact PURL match (`confirmed_applicable`)
  - Stage 2: Ecosystem, Name, and Version Constraint range (`confirmed_applicable` or `fixed_with_evidence`)
  - Stage 3: CPE heuristic pattern matching
  - Stage 4: Fuzzy description candidate matching (`candidate_match` - strictly tagged as uncertain)
- **VEX/CSAF Reconciler:** Applies vendor advisories (`under_investigation`, `not_affected`, `fixed`) to override generic upstream CVE records while preserving full provenance.

### Layer 4: Multi-Tier Traceability Graph
- **Directed Multigraph ($G = (V, E)$):** Backed by NetworkX, containing Components, Products, ECUs, Organisations, Vulnerabilities, and Evidence Artifacts.
- **Reachability Engine:** Traverses reversed dependency edges to calculate downstream affected components ($D(c)$) and reachable vehicle models ($P(c)$).
- **Supplier Separation:** Manages real corporate relationships and synthetic supply chain fixtures in strictly isolated subgraphs.

### Layer 5: Evidence-Based Assurance Engine
- **Regulatory Catalogs:** Pre-configured mappings to ISO/SAE 21434 (Clauses 7, 8, 15), UNECE R155 (Section 7.3), and EU Cyber Resilience Act.
- **Assurance Reasoning:** Evaluates claims against required evidence types, temporal validity ($\le 90$ days freshness window), contradictory records, and unresolved component identities.
- **Zero False Assurance Guarantee:** Guarantees that no claim transitions to `supported` unless all required evidence is present, fresh, and uncontradicted.

### Layer 6: Interface and Reporting
- **REST API:** 9 documented FastAPI endpoints providing machine-readable JSON exports.
- **Interactive Dashboard:** 6-page Streamlit application enabling real-time inspection of SBOM quality, vulnerability triage, traceability graphs, assurance claims, and empirical benchmark data.

## 3. Deterministic Security Philosophy

AutoSupplyGuard enforces deterministic security decision-making:
1. **No AI/LLM in the Decision Loop:** Security classifications, vulnerability applicability, and assurance claim statuses are computed exclusively via deterministic, auditable algorithms.
2. **Explicit Uncertainty:** Any component lacking an exact version or PURL is marked `candidate_match` or `insufficient_evidence`, preventing false positives and false security.
3. **Immutability of Raw Data:** External datasets, vendor advisories, and original SBOM files are stored immutably with SHA-256 hashes.
