# AutoSupplyGuard — Research Gap & Contribution Statement

## 1. Competitive Analysis & Existing Tools Overlap

To establish a rigorous, defensible research gap, AutoSupplyGuard is compared against the closest state-of-the-art tools and academic frameworks in SBOM ingestion, vulnerability scanning, graph analysis, and cybersecurity assurance:

| Tool / Framework | Primary Purpose | Strengths | Critical Limitations vs. AutoSupplyGuard |
| :--- | :--- | :--- | :--- |
| **OWASP Dependency-Track** | Component Analysis & Vulnerability Management | Robust SBOM ingestion (CycloneDX/SPDX), VEX integration, policy engine, enterprise UI. | Treats SBOMs as flat inventories per project; ignores multi-tier supplier organizational relationships; uses severity-centric scoring (CVSS/EPSS) without contextual dependency reachability or assurance graph semantics. |
| **Anchore Grype / Aqua Trivy** | Container & Filesystem Vulnerability Scanner | Fast exact matching, PURL/CPE resolution against upstream databases. | Scanners operate locally on filesystem/images; they do not assess SBOM quality, do not model multi-tier supplier relationships, and do not track claims, evidence freshness, or regulatory compliance. |
| **OpenSSF GUAC (Graph for Understanding Artifact Composition)** | Supply Chain Knowledge Graph | Ingests SLSA provenance, SBOMs, and scorecards into a GraphQL/Neo4j graph. | GUAC is an infrastructure data collector; it does not evaluate SBOM quality metrics, lacks formal automotive assurance cases (ISO/SAE 21434 / UNECE R155), and does not test claim-to-evidence sufficiency. |
| **OpenVEX / CSAF** | Vulnerability Exploitability Exchange | Standardized machine-readable format for asserting `not_affected`, `fixed`, etc. | VEX is a data representation schema, not an assurance engine. It does not detect missing evidence, does not assess evidence freshness or contradictory supplier claims, and does not model multi-tier supply chain opacity. |
| **Eclipse Capra** | Traceability Management Tool | Traces requirements to code/tests in Eclipse for ISO 26262 functional safety. | Built for functional safety requirements management; does not ingest SBOMs, does not interface with vulnerability feeds (CVE/OSV), and does not evaluate cybersecurity assurance. |
| **CASCADE / Mohamad et al. (2020)** | Automotive Security Assurance Cases | Proposes conceptual models for automotive security assurance cases (ISO/SAE 21434). | Qualitative and conceptual; no automated software implementation connecting low-level SBOM component graphs to high-level assurance claims; lacks empirical vulnerability evaluation. |

---

## 2. The Identified Research Gaps

Despite recent advances, a fundamental disconnect exists in both industry and literature:

1. **Gap 1: Disconnect between SBOM Syntactic Quality and Vulnerability Matchability.**
   Existing SBOM quality tools (such as NTIA minimum elements checkers) score documents purely on syntactic field presence (e.g., "is author present?"). However, in-the-wild studies (Zacchiroli et al., 2025; O'Donoghue et al., 2024) demonstrate that having an author field does not guarantee that package names, ecosystems, and versions can be deterministically matched to vulnerability feeds (such as OSV or NVD). Current research lacks an empirical assessment of how real-world SBOM quality directly impacts vulnerability detection precision and recall.

2. **Gap 2: Severity-Centric Prioritisation Ignores Downstream Automotive Dependency Context.**
   Automotive software consists of deeply layered software stacks across ECUs, telematics, and infotainment units. Standard vulnerability triage relies heavily on CVSS base scores. As Basu et al. (2024) and Maro et al. (2018) reveal, high CVSS vulnerabilities in isolated or dead code paths are routinely over-prioritized, while moderate vulnerabilities in deeply embedded transitive dependencies that propagate to critical vehicle functions are missed.

3. **Gap 3: Absence of Structured Evidence Verification for Multi-Tier Cybersecurity Assurance.**
   While automotive cybersecurity regulations (UNECE R155, ISO/SAE 21434) mandate supplier cybersecurity management, OEMs have virtually no visibility beyond Tier 1 (Fraser et al., 2020). When suppliers provide security attestations or SBOMs, existing tools treat their mere existence as proof of compliance. There is no automated assurance engine that verifies claim-to-evidence sufficiency, detects stale or expired evidence, flags contradictory vendor claims, or handles unresolved component identities.

---

## 3. Traceable Research Chains

AutoSupplyGuard directly addresses these gaps through the following traceable research chains:

### Chain 1: SBOM Quality & Vulnerability Matchability (RQ1)
- **Paper Finding:** Zacchiroli et al. (2025) find that 79.7% of public SBOMs follow CycloneDX but display high variance in supplier and version metadata (mean score 6.51/10). O'Donoghue et al. (2024) identify that generation tooling gaps cause false positives and missing transitive packages.
- **Identified Limitation:** Syntactic NTIA scores do not measure whether components can actually be resolved and matched to vulnerability intelligence.
- **Research Question (RQ1):** How does SBOM quality affect component identification and vulnerability-matching accuracy?
- **Implemented Method:** Multi-metric SBOM Quality Engine evaluating field completeness, version presence, PURL/CPE presence, and vulnerability matchability, correlated against deterministic matching stages in Layer 3.
- **Experiment (Exp 1):** Stratified evaluation across quality quartiles of Wild SBOMs and Curated Benchmark SBOMs to measure parsing success, precision, recall, and false-positive/negative rates.
- **Expected Result:** Demonstrating that higher syntactic completeness only partially correlates with vulnerability matchability, and that missing package identifiers (PURL) cause the largest drop in detection recall.

### Chain 2: Dependency & Product-Context Impact (RQ2)
- **Paper Finding:** Basu et al. (2024) document 413 automotive vulnerabilities and show external apps and telematics have tripled, while Maro et al. (2018) show that software traceability links decay rapidly across automotive subsystems.
- **Identified Limitation:** Severity-only (CVSS) ranking fails to identify whether a vulnerability resides in a root product component, a transitive library, or an unlinked third-party package.
- **Research Question (RQ2):** Does dependency and product-context analysis identify downstream security impact that severity-only vulnerability prioritisation misses?
- **Implemented Method:** Directed Dependency Graph Traversal (NetworkX) computing transitive downstream impact, reachable vehicle products, and an evidence-weighted context score.
- **Experiment (Exp 2):** Comparative evaluation of Baseline A (Severity-Only), Baseline B (Severity + Dependency), and Proposed Method (Context & Evidence-Aware Prioritisation) on real SBOMs and controlled synthetic automotive ecosystems.
- **Expected Result:** Context-aware prioritisation correctly elevates transitive vulnerabilities with multiple downstream vehicle product dependencies while penalizing unverified or dead components, outperforming CVSS-only ranking.

### Chain 3: Assurance Graph & Evidence Sufficiency (RQ3)
- **Paper Finding:** Mohamad et al. (2020) find that automotive OEMs (Volvo Group, Volvo Cars) struggle to link low-level software engineering artifacts to high-level security claims under ISO/SAE 21434. Fraser et al. (2020) demonstrate that self-reported supplier claims beyond Tier 1 lack verifiable evidence.
- **Identified Limitation:** No existing cybersecurity tool dynamically checks whether required evidence artifacts exist, are fresh, are uncontradicted, or have sufficient scope to support a regulatory cybersecurity claim.
- **Research Question (RQ3):** Can a structured assurance graph identify missing, stale, contradictory, or insufficient evidence for cybersecurity claims?
- **Implemented Method:** Evidence-Based Assurance Engine mapping Regulatory Requirements (ISO/SAE 21434, UNECE R155) → Claims → Evidence Requirements → Evidence Artifacts, with deterministic status resolution (`supported`, `partially_supported`, `insufficient_evidence`, `contradicted`, `not_assessed`).
- **Experiment (Exp 3):** Test suite of positive, negative, stale, contradictory, and incomplete evidence scenarios evaluated against gold-standard human review adjudications.
- **Expected Result:** Zero false assurance (the system never reports adequate support when required evidence is missing or stale) and 100% detection of contradictory supplier statements.

### Chain 4: Scalability & Graph Robustness (RQ4)
- **Paper Finding:** Real-world supply chains involve thousands of multi-tier components across heterogeneous suppliers, creating significant ingestion and graph analysis performance bottlenecks.
- **Identified Limitation:** Complex graph algorithms and deep transitive queries often suffer from exponential memory growth or non-linear latency.
- **Research Question (RQ4):** How do accuracy, traceability completeness, runtime, and memory usage change as the number and diversity of SBOMs increase?
- **Implemented Method:** Streaming parsing, batch graph operations, and benchmark profiling harness measuring processing latency, peak memory, and resolution success.
- **Experiment (Exp 4):** Scalability stress-testing across 1 to 500+ SBOMs and thousands of component nodes.
- **Expected Result:** Documented linear runtime scaling with sub-second single-SBOM processing and predictable memory bounds.
