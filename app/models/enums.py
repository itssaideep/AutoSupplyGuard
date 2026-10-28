"""Domain enumerations for AutoSupplyGuard."""

from enum import Enum

class SBOMFormat(str, Enum):
    CYCLONEDX = "CycloneDX"
    SPDX = "SPDX"
    UNKNOWN = "Unknown"

class SBOMValidationStatus(str, Enum):
    VALID = "valid"
    VALID_WITH_WARNINGS = "valid_with_warnings"
    MALFORMED = "malformed"
    UNSUPPORTED_VERSION = "unsupported_version"

class IdentityResolutionStatus(str, Enum):
    RESOLVED_EXACT = "resolved_exact"        # Name, version, and valid PURL present
    RESOLVED_PARTIAL = "resolved_partial"    # Name and version present, no PURL
    AMBIGUOUS = "ambiguous"                  # Multiple candidates or conflicting IDs
    UNRESOLVED = "unresolved"                # Missing name or version

class VulnerabilityMatchMethod(str, Enum):
    EXACT_PURL = "exact_purl"
    ECOSYSTEM_NAME_VERSION = "ecosystem_name_version"
    CPE_MATCH = "cpe_match"
    CANDIDATE_FUZZY = "candidate_fuzzy"
    MANUAL_ADJUDICATION = "manual_adjudication"

class VulnerabilityApplicability(str, Enum):
    CONFIRMED_APPLICABLE = "confirmed_applicable"
    LIKELY_APPLICABLE = "likely_applicable"
    CANDIDATE_MATCH = "candidate_match"
    NOT_AFFECTED_WITH_EVIDENCE = "not_affected_with_evidence"
    FIXED_WITH_EVIDENCE = "fixed_with_evidence"
    UNKNOWN = "unknown"

class ConfidenceCategory(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

class CorporateRelationshipType(str, Enum):
    OWNS = "OWNS"
    DEVELOPS_WITH = "DEVELOPS_WITH"
    INTEGRATES = "INTEGRATES"
    SUPPLIES_COMPONENT_TO = "SUPPLIES_COMPONENT_TO"
    DEPENDS_ON = "DEPENDS_ON"
    USES_PRODUCT = "USES_PRODUCT"
    UNKNOWN_RELATIONSHIP = "UNKNOWN_RELATIONSHIP"

class EvidenceType(str, Enum):
    SBOM = "sbom"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    VEX_ADVISORY = "vex_advisory"
    SUPPLIER_ATTESTATION = "supplier_attestation"
    SECURITY_AUDIT = "security_audit"
    OFFICIAL_COMPANY_DISCLOSURE = "official_company_disclosure"
    BINARY_MAP = "binary_map"
    BINARY_SYMBOLS = "binary_symbols"

class BinaryExposureState(str, Enum):
    POTENTIALLY_EXPOSED = "potentially_exposed"     # Default: static SBOM dependency without binary inspection
    LIKELY_PRESENT = "likely_present"               # Binary present, symbol likely retained
    CONFIRMED_IN_BINARY = "confirmed_in_binary"     # Vulnerable symbol confirmed present in ELF/map
    NOT_PRESENT_IN_BINARY = "not_present_in_binary" # Vulnerable symbol stripped or eliminated by linker

class AssuranceClaimStatus(str, Enum):
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONTRADICTED = "contradicted"
    NOT_ASSESSED = "not_assessed"

class DependencyScope(str, Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"
    RUNTIME = "runtime"
    BUILD = "build"
    TEST = "test"
    OPTIONAL = "optional"
    UNKNOWN = "unknown"
