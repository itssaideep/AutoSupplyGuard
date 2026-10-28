# AutoSupplyGuard — Comprehensive Literature Review

## 1. Executive Summary & Research Motivation

The automotive industry is undergoing a paradigm shift from hardware-defined mechanics to Software-Defined Vehicles (SDVs). Modern commercial vehicles and passenger cars integrate tens of millions of lines of code across distributed Electronic Control Units (ECUs), central vehicle compute modules, telematics gateways, and cloud backends. Original Equipment Manufacturers (OEMs) such as Volvo Group and Volvo Cars rely on multi-tier supplier networks spanning Tier 1 system integrators, Tier 2 component vendors, and commercial-off-the-shelf (COTS) or open-source software (OSS) packages.

However, modern connected vehicles communicate externally with cellular networks, cloud platforms, and roadside infrastructure. This hyper-connectivity dramatically widens the automotive attack surface. International regulations—most notably **UNECE Regulation 155 (Cybersecurity Management Systems)**, **UNECE Regulation 156 (Software Update Management Systems)**, and **ISO/SAE 21434 (Road Vehicles — Cybersecurity Engineering)**—now place legal obligations on vehicle manufacturers to identify cybersecurity risks across their entire supply chains.

The goal of **AutoSupplyGuard** is to provide an evidence-driven cybersecurity assurance platform that ingests real-world Software Bills of Materials (SBOMs), correlates components with vulnerability intelligence, constructs an evidence-backed supply chain traceability graph, and automates cybersecurity assurance reasoning.

---

## 2. Review of Core Literature & Theoretical Foundations

### 2.1 Automotive Software Vulnerability Landscape
In their empirical study on automotive software security, **Basu et al. (2024)** analyze the landscape of software vulnerabilities across connected vehicles. Evaluating 413 recently disclosed vulnerabilities and scanning 20 automotive software repositories containing 827 vulnerable libraries, their primary finding is that automotive vulnerability locations have structurally shifted. While historical vulnerabilities (pre-2018) concentrated inside physical in-vehicle components and CAN buses, modern risks have tripled in external companion apps, web portals, telematics gateways, and backend cloud services. 

*Critical Implications for AutoSupplyGuard:*
- Automotive software vulnerability analysis cannot be limited to embedded firmware; it must encompass full-stack dependencies across cloud, OS, and edge middleware.
- The released dataset from Basu et al. (curated in GitHub repository `SriAbir/CV_Vulnerability_22-24` and audited by our team at 1,507 unique historical CVE records) forms our primary automotive vulnerability intelligence benchmark.

### 2.2 Software Bill of Materials (SBOM) Quality & Adoption in the Wild
A Software Bill of Materials (SBOM) is a formal, machine-readable inventory of software components, dependencies, and hierarchical relationships. In the largest empirical study of public SBOMs to date, **Zacchiroli et al. (2025)** mined over 78,000 SBOM files from the Software Heritage archive. Their empirical findings establish that:
1. CycloneDX is the dominant format in public code (79.7%), followed by SPDX (19.6%).
2. The vast majority of files use JSON serialization (85.5%).
3. The average NTIA Minimum Elements quality score is only 6.51 out of 10.
4. Severe gaps exist in package versioning, author/supplier identity, and dependency graph resolution.

Complementing this, the systematic literature review by **O'Donoghue et al. (2024)** evaluates 40 peer-reviewed SBOM studies, mapping adoption barriers to the ISO/IEC 25019:2023 Quality-in-Use model. They show that vulnerability management is the primary operational use case (representing ~45% of literature), yet adoption is crippled by tooling inconsistencies, format fragmentation, high false-positive rates, and hidden transitive packages.

*Critical Implications for AutoSupplyGuard:*
- Real-world SBOM ingestion must be resilient to malformed, incomplete, and noisy inputs.
- High syntactic completeness does not equal vulnerability matchability; our quality engine must distinguish field presence from security utility.

### 2.3 Software Traceability & Supply Chain Opacity
The challenges of software traceability in the automotive domain were rigorously investigated by **Maro, Steghöfer, and Staron (2018)**. In an industrial study with automotive OEMs and suppliers, the authors cataloged 22 practical challenges in maintaining traceability links across standards such as ISO 26262 and Automotive SPICE. They proved that traceability links decay rapidly over time when maintained manually, and heterogeneous tools across supplier tiers create broken visibility paths.

Expanding into multi-tier supply chains, **Fraser, Müller, and Schwarzkopf (2020)** examined supply chain transparency in the automotive industry. They showed that vehicle OEMs have almost zero visibility beyond Tier 1 suppliers, and self-reported supplier compliance questionnaires are frequently incomplete or misleading.

*Critical Implications for AutoSupplyGuard:*
- A software supply chain model must separate observed physical facts from inferred or self-reported claims.
- Missing traceability edges must be explicitly flagged rather than filled with plausible guesses.

### 2.4 Automotive Security Assurance Cases
In an empirical investigation conducted with **Volvo Group** and **Volvo Cars**, **Mohamad et al. (2020)** studied the industrial requirements for Security Assurance Cases (SACs) under ISO/SAE 21434. They demonstrated that automotive engineers struggle to connect low-level engineering artifacts (code scans, unit tests, SBOMs) to high-level security claims (e.g., "All third-party components have been assessed for applicable vulnerabilities"). Furthermore, security assurance requires continuous evidence maintenance because new vulnerabilities emerge long after a vehicle has entered production.

*Critical Implications for AutoSupplyGuard:*
- AutoSupplyGuard's core contribution is an **Evidence-Based Assurance Engine** that formally models the relationship: `Requirement → Claim → Evidence Requirement → Evidence Artifact → Assessment Result`.
- Evidence freshness, provenance, and contradiction detection are mandatory first-class primitives.

---

## 3. Regulatory & Standards Context

AutoSupplyGuard maps evidence requirements to four major cybersecurity frameworks:

1. **ISO/SAE 21434 (Road vehicles — Cybersecurity engineering):**
   - Clause 7: Cybersecurity management (supplier cybersecurity requirements).
   - Clause 8: Continual cybersecurity activities (vulnerability monitoring, triage, remediation).
   - Clause 15: Tool qualification and supply chain cybersecurity assurance.
2. **UNECE Regulation 155 (Cybersecurity and CSMS):**
   - Mandates that vehicle manufacturers implement a Cyber Security Management System across development, production, and post-production phases.
   - Specifically requires OEMs to identify and manage cybersecurity risks in the supply chain (Annex 5, Part A & B).
3. **UNECE Regulation 156 (Software Updates and SUMS):**
   - Mandates vehicle software update management systems, ensuring software integrity, compatibility, and traceability of updated components.
4. **EU Cyber Resilience Act (CRA):**
   - Enforces mandatory SBOM generation, vulnerability disclosure obligations within 24 hours, and continuous maintenance of software security artifacts for connected hardware and software products.

---

## 4. Synthesis of Research Questions

Based on the verified literature and identified gaps, AutoSupplyGuard addresses four central research questions:

- **RQ1 (SBOM Quality vs. Matchability):** How does SBOM quality affect component identification and vulnerability-matching accuracy?
- **RQ2 (Dependency & Contextual Prioritisation):** Does dependency and product-context analysis identify downstream security impact that severity-only vulnerability prioritisation misses?
- **RQ3 (Structured Assurance Graph):** Can a structured assurance graph identify missing, stale, contradictory, or insufficient evidence for cybersecurity claims?
- **RQ4 (Scalability & Robustness):** How do accuracy, traceability completeness, runtime, and memory usage change as the number and diversity of SBOMs increase?
