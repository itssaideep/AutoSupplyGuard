"""Catalog of formal Automotive Regulatory Requirements and Standard Assurance Claims."""

from typing import List
from app.models.assurance import RegulatoryRequirement, AssuranceClaim
from app.models.enums import EvidenceType, AssuranceClaimStatus

def get_standard_requirements() -> List[RegulatoryRequirement]:
    """Returns official regulatory requirements from ISO/SAE 21434, UNECE R155, and EU CRA."""
    return [
        RegulatoryRequirement(
            requirement_id="ISO-21434-RQ-07-01",
            standard_name="ISO/SAE 21434:2021",
            clause="Clause 7.4.3",
            title="Supplier Cybersecurity Management",
            wording="The customer and supplier shall establish cybersecurity responsibilities and ensure component cybersecurity capability across the development lifecycle.",
            source_url="https://www.iso.org/standard/70918.html"
        ),
        RegulatoryRequirement(
            requirement_id="ISO-21434-RQ-08-01",
            standard_name="ISO/SAE 21434:2021",
            clause="Clause 8.4",
            title="Vulnerability Monitoring and Triage",
            wording="The organization shall continuously monitor for cybersecurity information, evaluate applicability of disclosed vulnerabilities, and manage remediation.",
            source_url="https://www.iso.org/standard/70918.html"
        ),
        RegulatoryRequirement(
            requirement_id="ISO-21434-RQ-15-01",
            standard_name="ISO/SAE 21434:2021",
            clause="Clause 15.4",
            title="Component-level Cybersecurity Verification",
            wording="Component software artifacts shall be verified for completeness, integrity, and known vulnerabilities prior to system integration.",
            source_url="https://www.iso.org/standard/70918.html"
        ),
        RegulatoryRequirement(
            requirement_id="UNECE-R155-ANNEX5-A",
            standard_name="UNECE Regulation No. 155",
            clause="Annex 5 Part A",
            title="Supply Chain Cyber Threat Mitigation",
            wording="Vehicle manufacturers shall implement processes to identify and manage cybersecurity risks in the supply chain, including third-party software.",
            source_url="https://unece.org/transport/standards/transport/vehicle-regulations-wp29/resolutions"
        ),
        RegulatoryRequirement(
            requirement_id="EU-CRA-ANNEX1-01",
            standard_name="EU Cyber Resilience Act (2024)",
            clause="Annex I Part I",
            title="SBOM & Vulnerability Transparency",
            wording="Manufacturers shall identify and document software components in a machine-readable Software Bill of Materials (SBOM) and address known exploitable vulnerabilities.",
            source_url="https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52022PC0454"
        )
    ]

def get_standard_claims(target_product_id: str = "VOLVO-VEHICLE-PLATFORM") -> List[AssuranceClaim]:
    """Generates standard cybersecurity claims scoped to a target vehicle platform."""
    return [
        AssuranceClaim(
            claim_id="CLAIM-SBOM-TRANSPARENCY-01",
            claim_text="A validated, machine-readable Software Bill of Materials (SBOM) is maintained for all integrated third-party software components.",
            claim_category="Supply Chain Transparency",
            related_requirement_id="EU-CRA-ANNEX1-01",
            target_product_id=target_product_id,
            required_evidence_types=[EvidenceType.SBOM],
            status=AssuranceClaimStatus.NOT_ASSESSED
        ),
        AssuranceClaim(
            claim_id="CLAIM-VULN-ASSESSMENT-02",
            claim_text="All identified third-party software components have been assessed for applicable known vulnerabilities using fresh intelligence feeds.",
            claim_category="Vulnerability Management",
            related_requirement_id="ISO-21434-RQ-08-01",
            target_product_id=target_product_id,
            required_evidence_types=[EvidenceType.SBOM, EvidenceType.VULNERABILITY_ASSESSMENT],
            status=AssuranceClaimStatus.NOT_ASSESSED
        ),
        AssuranceClaim(
            claim_id="CLAIM-REMEDIATION-VEX-03",
            claim_text="All confirmed applicable vulnerabilities in production components have documented remediation evidence or authoritative VEX justifications.",
            claim_category="Remediation Assurance",
            related_requirement_id="ISO-21434-RQ-15-01",
            target_product_id=target_product_id,
            required_evidence_types=[EvidenceType.VULNERABILITY_ASSESSMENT, EvidenceType.VEX_ADVISORY],
            status=AssuranceClaimStatus.NOT_ASSESSED
        ),
        AssuranceClaim(
            claim_id="CLAIM-SUPPLIER-ATTESTATION-04",
            claim_text="Tier 1 and Tier 2 supplier organisations have provided verified security attestations without contradictory vulnerability findings.",
            claim_category="Supplier Governance",
            related_requirement_id="UNECE-R155-ANNEX5-A",
            target_product_id=target_product_id,
            required_evidence_types=[EvidenceType.SUPPLIER_ATTESTATION],
            status=AssuranceClaimStatus.NOT_ASSESSED
        ),
        AssuranceClaim(
            claim_id="CLAIM-IDENTITY-COMPLETENESS-05",
            claim_text="All software components possess unambiguous name and version identity metadata enabling deterministic vulnerability tracking.",
            claim_category="Component Integrity",
            related_requirement_id="ISO-21434-RQ-07-01",
            target_product_id=target_product_id,
            required_evidence_types=[EvidenceType.SBOM],
            status=AssuranceClaimStatus.NOT_ASSESSED
        )
    ]
