"""Unit tests for the Evidence-Based Assurance Engine (Milestone 7 & RQ3)."""

from datetime import timedelta, date
import pytest
from app.assurance.catalog import get_standard_claims
from app.assurance.evaluator import AssuranceEngine
from app.models.evidence import EvidenceArtifact
from app.models.component import Component
from app.models.vulnerability import VulnerabilityMatch
from app.models.enums import (
    EvidenceType,
    AssuranceClaimStatus,
    IdentityResolutionStatus,
    VulnerabilityApplicability,
    VulnerabilityMatchMethod,
    ConfidenceCategory
)

@pytest.fixture
def engine():
    return AssuranceEngine(freshness_days_threshold=90)

def test_positive_supported_assurance_claim(engine):
    """Case 1: All required evidence present, valid, fresh (<90 days), and uncontradicted."""
    claim = get_standard_claims()[0]  # CLAIM-SBOM-TRANSPARENCY-01

    # Fresh SBOM evidence created 10 days ago
    fresh_sbom = EvidenceArtifact(
        evidence_id="ev-sbom-fresh",
        evidence_type=EvidenceType.SBOM,
        title="Production SBOM for Telematics Unit",
        source_url_or_file="data/raw/curated_sboms/extracted/102307552_monkeyWie+proxyee/sbom.spdx.json",
        source_organisation="Volvo Group Supplier",
        publication_date=date.today() - timedelta(days=10),
        content_checksum="abc123sha256",
        provenance="Verified supplier ingestion pipeline"
    )
    claim.supporting_evidence_ids = ["ev-sbom-fresh"]

    result = engine.evaluate_claims(
        claims=[claim],
        evidence_artifacts=[fresh_sbom]
    )
    assert result.supported_count == 1
    assert result.false_assurance_rate == 0.0
    evaluated = result.evaluated_claims[0]
    assert evaluated.status == AssuranceClaimStatus.SUPPORTED

def test_missing_evidence_yields_insufficient_evidence(engine):
    """Case 2: Claim requires both SBOM and Vulnerability Assessment, but only SBOM is supplied."""
    claim = get_standard_claims()[1]  # CLAIM-VULN-ASSESSMENT-02 requires SBOM and VULN_ASSESSMENT

    fresh_sbom = EvidenceArtifact(
        evidence_id="ev-sbom-only",
        evidence_type=EvidenceType.SBOM,
        title="Production SBOM",
        source_url_or_file="sbom.json",
        source_organisation="Tier 1 Vendor",
        publication_date=date.today() - timedelta(days=5),
        content_checksum="checksum-1",
        provenance="Ingested"
    )
    claim.supporting_evidence_ids = ["ev-sbom-only"]

    result = engine.evaluate_claims([claim], [fresh_sbom])
    assert result.supported_count == 0
    assert result.insufficient_evidence_count == 1
    evaluated = result.evaluated_claims[0]
    assert evaluated.status == AssuranceClaimStatus.INSUFFICIENT_EVIDENCE
    assert any("Missing mandatory evidence types: ['vulnerability_assessment']" in r for r in evaluated.status_reasons)

def test_stale_evidence_yields_insufficient_evidence(engine):
    """Case 3: Evidence is 180 days old, exceeding the 90-day freshness threshold."""
    claim = get_standard_claims()[0]

    stale_sbom = EvidenceArtifact(
        evidence_id="ev-sbom-stale",
        evidence_type=EvidenceType.SBOM,
        title="Outdated SBOM",
        source_url_or_file="old_sbom.json",
        source_organisation="Tier 2 Vendor",
        publication_date=date.today() - timedelta(days=180),
        content_checksum="checksum-stale",
        provenance="Archival"
    )
    claim.supporting_evidence_ids = ["ev-sbom-stale"]

    result = engine.evaluate_claims([claim], [stale_sbom])
    assert result.supported_count == 0
    assert result.insufficient_evidence_count == 1
    evaluated = result.evaluated_claims[0]
    assert evaluated.status == AssuranceClaimStatus.INSUFFICIENT_EVIDENCE
    assert any("Stale evidence artifact" in r for r in evaluated.status_reasons)

def test_contradictory_evidence_detection(engine):
    """Case 4: Supplier attestation asserts 'no vulnerabilities', but matching confirms active CVE."""
    claim = get_standard_claims()[3]  # CLAIM-SUPPLIER-ATTESTATION-04

    supplier_attest = EvidenceArtifact(
        evidence_id="ev-attest-01",
        evidence_type=EvidenceType.SUPPLIER_ATTESTATION,
        title="Supplier Annual Security Statement",
        source_url_or_file="attest.pdf",
        source_organisation="Untrusted Supplier",
        publication_date=date.today() - timedelta(days=15),
        content_checksum="attest-hash",
        provenance="Supplier portal"
    )
    claim.supporting_evidence_ids = ["ev-attest-01"]

    # Active confirmed vulnerability
    match = VulnerabilityMatch(
        match_id="m-active",
        component_id="comp-1",
        vulnerability_id="CVE-2024-CRITICAL-ACTIVE",
        matching_method=VulnerabilityMatchMethod.EXACT_PURL,
        applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE,
        confidence=ConfidenceCategory.HIGH,
        version_constraint_result="Satisfied <2.0"
    )

    result = engine.evaluate_claims(
        claims=[claim],
        evidence_artifacts=[supplier_attest],
        vulnerability_matches=[match]
    )
    assert result.supported_count == 0
    assert result.contradicted_count == 1
    evaluated = result.evaluated_claims[0]
    assert evaluated.status == AssuranceClaimStatus.CONTRADICTED
    assert any("Contradiction" in r for r in evaluated.status_reasons)

def test_unresolved_component_identity_gap(engine):
    """Case 5: Components lack version strings, creating an assurance gap."""
    claim = get_standard_claims()[4]  # CLAIM-IDENTITY-COMPLETENESS-05

    fresh_sbom = EvidenceArtifact(
        evidence_id="ev-sbom-unresolved",
        evidence_type=EvidenceType.SBOM,
        title="Incomplete SBOM",
        source_url_or_file="noisy.json",
        source_organisation="Vendor",
        publication_date=date.today() - timedelta(days=2),
        content_checksum="hash",
        provenance="Ingested"
    )
    claim.supporting_evidence_ids = ["ev-sbom-unresolved"]

    unresolved_comp = Component(
        internal_id="comp-anon",
        name="crypto-driver",
        version=None,
        source_sbom_id="sbom-1",
        original_id="anon-1",
        identity_status=IdentityResolutionStatus.UNRESOLVED
    )

    result = engine.evaluate_claims(
        claims=[claim],
        evidence_artifacts=[fresh_sbom],
        components=[unresolved_comp]
    )
    assert result.supported_count == 0
    assert result.insufficient_evidence_count == 1
    evaluated = result.evaluated_claims[0]
    assert evaluated.status == AssuranceClaimStatus.INSUFFICIENT_EVIDENCE
    assert any("unresolved or ambiguous identity metadata" in r for r in evaluated.status_reasons)

def test_zero_false_assurance_rate(engine):
    """Verifies that the False Assurance Rate is strictly 0.0% across all evaluated scenarios."""
    claims = get_standard_claims()
    # No evidence provided
    result = engine.evaluate_claims(claims=claims, evidence_artifacts=[])
    assert result.false_assurance_rate == 0.0
    assert result.supported_count == 0
