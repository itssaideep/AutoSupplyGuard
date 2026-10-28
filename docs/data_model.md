# AutoSupplyGuard Canonical Data Model

## 1. Domain Entities and Schema

AutoSupplyGuard enforces strongly typed canonical entities using Pydantic v2 domain models located in `app/models/`.

### 1.1 Component (`app/models/component.py`)
Represents an individual software library, module, or package within an SBOM.

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `str` | Unique internal component identifier (`c-<uuid>` or normalized PURL) |
| `name` | `str` | Package or library name |
| `version` | `Optional[str]` | Declared release version string |
| `purl` | `Optional[str]` | Canonical Package URL string (RFC 7515) |
| `cpe` | `Optional[str]` | Common Platform Enumeration identifier |
| `ecosystem` | `Optional[str]` | Package manager ecosystem (`maven`, `pypi`, `npm`, `generic`, etc.) |
| `supplier_name` | `Optional[str]` | Declared author, vendor, or supplier organization |
| `license_concluded` | `Optional[str]` | Declared or concluded open-source / proprietary license |
| `sbom_id` | `str` | Identifier of parent SBOM document |
| `original_id` | `str` | Raw identifier from original SBOM (e.g., `SPDXRef-Package-1`) |
| `identity_status` | `IdentityResolutionStatus` | State: `RESOLVED_EXACT`, `RESOLVED_PARTIAL`, `AMBIGUOUS`, `UNRESOLVED` |

### 1.2 SBOM (`app/models/sbom.py`)
Represents an ingested Software Bill of Materials document.

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `str` | Internal unique SBOM identifier |
| `format` | `SBOMFormat` | Format: `SPDX` or `CYCLONEDX` |
| `spec_version` | `str` | Specification version (e.g., `SPDX-2.2`, `1.4`) |
| `serial_number` | `Optional[str]` | CycloneDX serial number or SPDX document namespace |
| `author` | `Optional[str]` | Author or tool that generated the SBOM |
| `timestamp` | `Optional[datetime]` | Document generation timestamp |
| `sha256_checksum` | `str` | Cryptographic SHA-256 hash of original file |
| `component_count` | `int` | Total components contained |
| `dependency_count` | `int` | Total directed dependency relationships |
| `quality_metrics` | `Optional[SBOMQualityMetrics]` | In-memory computed quality vector |

### 1.3 Vulnerability & Match (`app/models/vulnerability.py`)
Represents security vulnerability intelligence and correlation records.

- **`Vulnerability`:**
  - `id`: Unique identifier (e.g., `CVE-2023-CRYPTO-SHARED`)
  - `source`: Source feed (`AUTOMOTIVE_FEED`, `OSV`, `NVD`, `VENDOR_ADVISORY`)
  - `description`: Text summary of vulnerability
  - `cvss_score`: Float score (0.0 to 10.0)
  - `affected_ranges`: List of SemVer version constraints (e.g., `< 1.1.1u`)
  - `fixed_versions`: List of known remediated version strings
  - `cwe_ids`: Common Weakness Enumeration identifiers

- **`VulnerabilityMatch`:**
  - `match_id`: Unique match identifier
  - `vulnerability_id`: Matched vulnerability identifier
  - `component_id`: Target component identifier
  - `method`: `EXACT_PURL`, `VERSION_CONSTRAINT`, `CPE`, `DESCRIPTION_FUZZY`
  - `applicability`: `CONFIRMED_APPLICABLE`, `LIKELY_APPLICABLE`, `CANDIDATE_MATCH`, `NOT_AFFECTED_WITH_EVIDENCE`, `FIXED_WITH_EVIDENCE`, `UNKNOWN`
  - `confidence`: `HIGH`, `MEDIUM`, `LOW`
  - `evidence_notes`: Audit rationale explaining the match decision

### 1.4 Traceability Entities (`app/models/product.py`, `app/models/organisation.py`)
- **`Product`:** Vehicle model or ECU subsystem (e.g., `VOLVO-FM-AUTONOMOUS-GATEWAY`, `VOLVO-FH-ELECTRIC-TCU`).
- **`Organisation`:** Corporate legal entity (e.g., `Volvo Group`, `NVIDIA`, `Zenseact`).
- **`CorporateRelationship`:** Documented relationship between organizations with source URL, publication date, relationship type (`OWNS`, `DEVELOPS_WITH`, `INTEGRATES`, `SUPPLIES_COMPONENT_TO`), and explicit limitations.

### 1.5 Assurance Claim & Evidence Artifact (`app/models/evidence.py`, `app/models/assurance.py`)
- **`EvidenceArtifact`:** A verifiable document, scan output, or audit log.
  - `id`: Unique artifact identifier
  - `evidence_type`: `SBOM_DOCUMENT`, `VULNERABILITY_SCAN_REPORT`, `PENETRATION_TEST_REPORT`, `VENDOR_VEX_ADVISORY`, `SUPPLIER_DECLARATION`
  - `publication_date`: Date the artifact was created
  - `retrieval_date`: Timestamp artifact was ingested into AutoSupplyGuard
  - `sha256_checksum`: Artifact content hash
  - `provenance`: Originating organization or scanner tool

- **`AssuranceClaim`:** High-level security assertion mapped to standards.
  - `id`: Unique claim identifier
  - `standard`: `ISO_SAE_21434`, `UNECE_R155`, `EU_CRA`
  - `clause`: Standard clause (e.g., `Clause 15 (Supply chain cybersecurity)`)
  - `statement`: Natural language security claim
  - `required_evidence_types`: List of required evidence categories
  - `status`: `SUPPORTED`, `PARTIALLY_SUPPORTED`, `INSUFFICIENT_EVIDENCE`, `CONTRADICTED`, `NOT_ASSESSED`
  - `freshness_window_days`: Allowed age threshold (default 90 days)
  - `unresolved_gaps`: Detailed list of detected evidence defects
