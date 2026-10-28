# AutoSupplyGuard — Experimental Plan & Scientific Protocol

This document defines the formal experimental protocol, hypotheses, datasets, baselines, and evaluation scripts for validating AutoSupplyGuard against its research questions.

---

## Experiment 1: SBOM Quality & Vulnerability Matchability (RQ1)

- **Research Question:** How does SBOM quality affect component identification and vulnerability-matching accuracy?
- **Hypothesis ($H_1$):** Higher syntactic quality (NTIA score) does not guarantee vulnerability matchability; missing package identifiers (PURL/CPE) and unnormalized version strings represent the primary cause of vulnerability-matching false negatives.
- **Experimental Design:**
  1. Sample 200 SBOMs from Wild SBOMs stratified across standards (`cdx` vs `spdx`), formats (`json` vs `xml` vs `tag-value`), and 4 quality quartiles ($Q_1 \le 6.0$, $Q_2 \in (6.0, 6.5]$, $Q_3 \in (6.5, 7.4]$, $Q_4 > 7.4$), plus all 46 Curated Benchmark SBOMs.
  2. Compute AutoSupplyGuard Quality Metrics ($M_{\text{comp}}, M_{\text{purl}}, M_{\text{dep}}, M_{\text{matchable}}$).
  3. Execute deterministic matching (Stages 1–3) against OSV and CVE feeds.
  4. Compare vulnerability detection counts, candidate matches, and failure modes across quality tiers.
- **Baselines:**
  - Baseline 1: Standard NTIA Minimum Elements Score.
  - Baseline 2: Naive string-matching parser without identifier normalisation.
- **Metrics:** Parsing success rate, PURL extraction rate, matchability index, confirmed vs candidate match count.

---

## Experiment 2: Dependency Impact & Contextual Prioritisation (RQ2)

- **Research Question:** Does dependency and product-context analysis identify downstream security impact that severity-only vulnerability prioritisation misses?
- **Hypothesis ($H_2$):** Severity-only (CVSS) ranking over-prioritizes isolated high-severity vulnerabilities while missing moderate-severity vulnerabilities in critical multi-dependent shared libraries; context-aware scoring correctly elevates vulnerabilities that propagate to vehicle products.
- **Experimental Design:**
  1. Select 10 real-world dependency graphs from Curated SBOMs and construct a controlled automotive synthetic ecosystem (Volvo OEM → Tier 1 Telematics / Infotainment → Tier 2 Middleware / OS / Crypto libraries).
  2. Inject 15 known vulnerabilities spanning different CVSS scores (Low, Medium, High, Critical) across root components, leaf libraries, and deeply nested transitive dependencies.
  3. Run three prioritisation algorithms:
     - **Baseline A (Severity-Only):** Rank strictly by CVSS base score.
     - **Baseline B (Severity + Dependency):** Rank by $\text{CVSS} \times (1 + \log(1 + \text{Descendants}))$.
     - **Proposed Method (AutoSupplyGuard Context & Evidence Score):** Equation in `research/metrics.md`.
  4. Compare Top-K rankings against gold-standard impact rankings.
- **Metrics:** Top-K Precision@5, Mean Reciprocal Rank (MRR), downstream product reachability recovery.

---

## Experiment 3: Assurance-Gap & Evidence Sufficiency Detection (RQ3)

- **Research Question:** Can a structured assurance graph identify missing, stale, contradictory, or insufficient evidence for cybersecurity claims?
- **Hypothesis ($H_3$):** An evidence-based assurance graph achieves a 0.0% False Assurance Rate ($\text{FAR} = 0.0\%$), successfully catching missing, stale, and contradictory evidence that flat checklist compliance misses.
- **Experimental Design:**
  1. Define 5 core automotive cybersecurity claims mapped to ISO/SAE 21434 (Clause 7, 8, 15) and UNECE R155 (Annex 5).
  2. Construct 20 test cases across 5 evidence categories:
     - Positive cases (all evidence present, valid, and fresh).
     - Missing evidence cases (missing SBOM, missing vulnerability assessment).
     - Stale evidence cases (vulnerability scan older than 90-day threshold).
     - Contradictory evidence cases (supplier claims `not_affected` but upstream NVD confirms active exploit without VEX justification).
     - Unresolved identity cases (component version ambiguous or unverified).
  3. Evaluate automated claim states (`supported`, `partially_supported`, `insufficient_evidence`, `contradicted`).
- **Baselines:**
  - Flat Checklist Baseline: Marks claim satisfied if any document file is attached.
- **Metrics:** False Assurance Rate (FAR), Gap Detection Precision, Gap Detection Recall, Contradiction Detection Accuracy.

---

## Experiment 4: Scalability & Graph Robustness (RQ4)

- **Research Question:** How do accuracy, traceability completeness, runtime, and memory usage change as the number and diversity of SBOMs increase?
- **Experimental Design:**
  1. Batch ingestion stress test across increasing batch sizes: 1, 10, 50, 100, 200, 500 SBOMs.
  2. Track:
     - Total execution runtime (seconds).
     - Throughput (SBOMs/second, components/second).
     - Peak memory usage (MB via `tracemalloc`).
     - Parsing error frequency and unhandled exceptions.
- **Metrics:** Latency per document, Peak RSS Memory (MB), Throughput scaling curve.
