# AutoSupplyGuard — Dataset Inventory & Data Governance Manifest

This inventory documents all primary, secondary, and benchmark datasets acquired, verified, and audited for the **AutoSupplyGuard** research prototype.

---

## 1. Primary Dataset: Automotive Vulnerabilities in Connected Vehicles (Dataset A)

- **Source Title:** Mapping the Landscape of Software Vulnerabilities in Connected Vehicles
- **Publisher / Authors:** Srijita Basu, Miroslaw Staron, Magnus Almgren, Jennifer Horkoff, Christian Berger (Chalmers University of Technology & University of Gothenburg)
- **Repository URL:** [https://github.com/SriAbir/CV_Vulnerability_22-24](https://github.com/SriAbir/CV_Vulnerability_22-24)
- **Publication Venue:** *Software Quality Journal* (Springer), DOI: [10.1007/s11219-026-09787-y](https://doi.org/10.1007/s11219-026-09787-y)
- **Local Storage Path:** `data/raw/automotive_vulnerabilities/CV_Vulnerability_22-24/`
- **Primary Artifact:** `GitHubAutomotiveVulnerabilities_2022_2024.xlsx` (271,442 bytes, SHA-256: verified in manifest)
- **Licence:** Public Academic Research Repository (MIT/Open Data terms per repository release)
- **Audited Schema & Structure:**
  The Excel workbook contains 8 distinct sheets:
  1. `2024`: 92 rows, 9 columns (`Sl. No`, `Vul ID`, `Description `, `CVSS Severity`, `Published Date `, `Attack Vector`, `CAPEC`, `Vendor/Supplier/OEM`, `SDLC phase`)
  2. `2023`: 142 rows, 9 columns (Identical schema to 2024)
  3. `2022`: 140 rows, 9 columns (Identical schema to 2024)
  4. `AdditionalVulnerabilityDatabase`: 50 rows, 1 column (`CVE-2013-2597 `)
  5. `2021`: 300 rows, 6 columns (Headerless: CVE, Description, Component Category [e.g. ECU, External Application], CWE, CWE Name, CVSS Score)
  6. `2020`: 295 rows, 7 columns (Headerless: CVE, Description, Component Category, CWE, CWE Name, CVSS Score, Unnamed)
  7. `2019`: 363 rows, 6 columns (Headerless: CVE, Description, Component Category, CWE, CWE Name, CVSS Score)
  8. `2018`: 174 rows, 6 columns (Headerless: CVE, Description, Component Category, CWE, CWE Name, CVSS Score)
- **Verified Record Counts:**
  - 2022–2024 core focus: 374 raw rows (362 CVE entries).
  - Combined 2022–2024 + Additional: **411 unique CVEs** (matching the ~413 reported in the publication).
  - Total historical database (2018–2024): **1,556 rows, 1,507 unique CVE records**.
- **Data Limitations & Governance Constraints:**
  - The dataset does *not* provide formal Package URLs (purl) or CPE identifiers.
  - The `Vendor/Supplier/OEM` field contains high-level text labels (e.g., "Android", "Qualcomm", "Mercedes-Benz", "Tesla", "SAP", "QNX"), not formal supplier entity IDs or contract identifiers.
  - Vulnerability applicability cannot be assumed across all models of a manufacturer without component-level evidence.
  - Categorizations such as `SDLC phase` and `Attack Vector` are manual classifications from the authors, which must be treated as derived external claims, not physical observations.

---

## 2. Primary Dataset: Wild SBOMs Dataset (Dataset B)

- **Source Title:** Wild SBOMs: A Large-scale Dataset of Software Bill of Materials from Public Code
- **Publisher / Authors:** Stefano Zacchiroli et al. (Software Heritage, MSR 2025)
- **Repository / Zenodo Record:** [https://zenodo.org/records/17397281](https://zenodo.org/records/17397281)
- **Publication:** Proceedings of the 22nd IEEE/ACM International Conference on Mining Software Repositories (MSR 2025)
- **DOI:** `10.5281/zenodo.17397281`
- **Licence:** CC-BY-4.0
- **Local Storage Path:** `data/raw/wild_sboms/`
- **Downloaded Artifacts:**
  - `README.md` (10,608 bytes) — Replication instructions and schema definition.
  - `sboms-01.csv.zstd` / `sboms-01.csv` (11,819,635 bytes decompressed) — Master SBOM metadata table.
  - `sboms-02-filenames.csv.zstd` / `sboms-02-filenames.csv` (113,798,908 bytes decompressed) — 1,168,305 filename occurrences across 78,612 SBOMs.
  - `analysis.tar.zstd` (120 KB) — Contains `examples.ipynb` replication analysis notebook.
- **Audited Empirical Findings:**
  - **Total unique SBOM files:** Exactly **78,612**.
  - **Standard Distribution:**
    - CycloneDX (`cdx`): 62,649 (79.7%)
    - SPDX (`spdx`): 15,383 (19.6%)
    - Unidentified / NaN: 580 (0.7%)
  - **Format Distribution:**
    - JSON: 67,224 (85.5%)
    - Tag-Value: 4,934 (6.3%)
    - XML: 4,772 (6.1%)
    - YAML: 1,102 (1.4%)
    - Unidentified: 580 (0.7%)
  - **Specification Versions:**
    - CycloneDX 1.3: 39,183 (49.8%)
    - SPDX 2.3: 15,383 (19.6%)
    - CycloneDX 1.4: 11,533 (14.7%)
    - CycloneDX 1.5: 9,619 (12.2%)
    - CycloneDX 1.2: 1,466 (1.9%)
    - CycloneDX 1.1 / 1.6 / 1.0: 844 (1.1%)
  - **NTIA-based Source Quality Score (`score`):**
    - Mean: 6.51 / 10.0 (std: 1.12, median: 6.50, min: 1.3, max: 9.2).
- **Sampling Strategy for AutoSupplyGuard:**
  - The complete raw archive (`sbom-files.tar.ztsd`) is 4.83 GB compressed (~25 GB uncompressed).
  - To ensure reproducibility and prevent unmanaged storage bloat, AutoSupplyGuard uses a **stratified random sampling procedure** across (1) Standard (`cdx` vs `spdx`), (2) Format (`json` vs `xml` vs `tag-value`), and (3) Quality Score quartiles (Q1 <= 6.0, Q2 6.0-6.5, Q3 6.5-7.4, Q4 >= 7.4), with a fixed random seed (`seed=42`).

---

## 3. Supplementary Benchmark: Curated SBOMs Benchmark

- **Source Title:** A Dataset of Software Bill of Materials for Evaluating SBOM Consumption Tools
- **Zenodo Record:** [https://zenodo.org/records/14808410](https://zenodo.org/records/14808410)
- **Publication:** arXiv:2504.06880
- **DOI:** `10.5281/zenodo.14808410`
- **Licence:** CC-BY-4.0
- **Local Storage Path:** `data/raw/curated_sboms/extracted/`
- **Audited Empirical Structure:**
  - 46 curated open-source software project directories.
  - 46 validated `sbom.spdx.json` documents (SPDX Version 2.2).
  - Total packages cataloged: **995 packages**.
  - Total dependency relationships cataloged: **995 relationships**.
  - Includes companion `sbom.data-sources.json` ground-truth manifests documenting upstream package repositories, commit IDs, and provenance.
- **Role in AutoSupplyGuard:**
  - Serves as the ground truth validation suite for SPDX 2.2 parser compliance, package identity resolution, and dependency graph integrity before testing on noisy in-the-wild documents.

---

## 4. Official Vulnerability & Advisory Feeds (Layer 1 Connectors)

- **Google OSV (Open Source Vulnerabilities):**
  - Schema: Open Source Vulnerability (OSV) Schema v1.6.0 (`https://ossf.github.io/osv-schema/`).
  - Access: Deterministic REST API (`https://api.osv.dev/v1/query`) and bulk ecosystem archives.
  - Ecosystem Coverage: PyPI, npm, Maven, Go, crates.io, Debian, Alpine, Linux kernel.
- **NVD (National Vulnerability Database):**
  - Schema: NVD CVE JSON 2.0 API.
  - Role: Source for CVSS vector strings, CWE classifications, and official publication/modification timestamps.
- **CSAF / VEX (Common Security Advisory Framework):**
  - Role: Ingest machine-readable product status declarations (`fixed`, `known_affected`, `known_not_affected`, `under_investigation`).
