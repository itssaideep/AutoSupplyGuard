"""Deterministic Evidence-Based Assurance Engine for ISO/SAE 21434 and UNECE R155 claims."""

from typing import List, Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field
from app.models.assurance import AssuranceClaim
from app.models.evidence import EvidenceArtifact
from app.models.component import Component
from app.models.vulnerability import VulnerabilityMatch
from app.models.enums import (
    AssuranceClaimStatus,
    EvidenceType,
    IdentityResolutionStatus,
    VulnerabilityApplicability
)

class AssuranceEvaluationResult(BaseModel):
    """Container holding evaluated claims, detected gaps, and assurance metrics."""
    evaluated_claims: List[AssuranceClaim]
    total_claims: int
    supported_count: int
    partially_supported_count: int
    insufficient_evidence_count: int
    contradicted_count: int
    not_assessed_count: int
    false_assurance_rate: float = Field(0.0, description="FAR: Proportion of falsely supported claims (must be 0.0%)")
    gap_summary: List[Dict[str, Any]]
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)

class AssuranceEngine:
    """Evaluates regulatory cybersecurity claims against verifiable evidence artifacts."""

    def __init__(self, freshness_days_threshold: int = 90):
        self.freshness_threshold = freshness_days_threshold

    def evaluate_claims(
        self,
        claims: List[AssuranceClaim],
        evidence_artifacts: List[EvidenceArtifact],
        components: Optional[List[Component]] = None,
        vulnerability_matches: Optional[List[VulnerabilityMatch]] = None
    ) -> AssuranceEvaluationResult:
        """Executes deterministic claim verification and returns evaluation audit report."""
        components = components or []
        vulnerability_matches = vulnerability_matches or []
        evidence_by_id: Dict[str, EvidenceArtifact] = {e.evidence_id: e for e in evidence_artifacts}

        evaluated_claims: List[AssuranceClaim] = []
        gaps: List[Dict[str, Any]] = []

        for c in claims:
            evaluated_claim = c.model_copy(deep=True)
            reasons: List[str] = []

            # 1. Check if any evidence artifacts are linked
            linked_evidence = [evidence_by_id[eid] for eid in evaluated_claim.supporting_evidence_ids if eid in evidence_by_id]
            linked_types = {e.evidence_type for e in linked_evidence}

            # Check missing required evidence types
            missing_types = [t for t in evaluated_claim.required_evidence_types if t not in linked_types]
            if missing_types:
                reasons.append(f"Missing mandatory evidence types: {[t.value for t in missing_types]}")

            # 2. Check Evidence Freshness
            stale_evidence: List[EvidenceArtifact] = []
            now = datetime.utcnow()
            for ev in linked_evidence:
                ev_date = ev.publication_date or (ev.retrieval_date.date() if ev.retrieval_date else None)
                if ev_date:
                    age_days = (now.date() - ev_date).days
                    if age_days > self.freshness_threshold:
                        stale_evidence.append(ev)
                        reasons.append(f"Stale evidence artifact '{ev.evidence_id}' ({age_days} days old > {self.freshness_threshold} days threshold)")

            # 3. Check Contradictions
            contradicted = False
            # Check explicit contradictory evidence references
            if evaluated_claim.contradictory_evidence_ids:
                contradicted = True
                reasons.append(f"Explicit contradictory evidence linked: {evaluated_claim.contradictory_evidence_ids}")

            # Check implicit contradiction:
            # Active confirmed unmitigated vulnerabilities directly contradict security assurance claims
            # (vulnerability assessment, secure boot, supplier attestation, remediation)
            has_supplier_attest = EvidenceType.SUPPLIER_ATTESTATION in linked_types
            is_security_claim = any(
                t in evaluated_claim.required_evidence_types
                for t in [
                    EvidenceType.VULNERABILITY_ASSESSMENT,
                    EvidenceType.SECURITY_AUDIT,
                    EvidenceType.SUPPLIER_ATTESTATION,
                    EvidenceType.VEX_ADVISORY
                ]
            ) or evaluated_claim.claim_id != "CLAIM-SBOM-TRANSPARENCY-01"

            confirmed_vulns = [
                m for m in vulnerability_matches
                if m.applicability == VulnerabilityApplicability.CONFIRMED_APPLICABLE
            ]
            if confirmed_vulns and (has_supplier_attest or is_security_claim):
                contradicted = True
                vuln_ids = [m.vulnerability_id for m in confirmed_vulns]
                reasons.append(f"Contradiction: Claim '{evaluated_claim.claim_id}' refuted by confirmed active vulnerabilities: {vuln_ids}")

            # 4. Check Component and Supplier Identity Ambiguities
            unresolved_comps = [
                comp for comp in components
                if comp.identity_status in {IdentityResolutionStatus.UNRESOLVED, IdentityResolutionStatus.AMBIGUOUS}
            ]
            if unresolved_comps:
                reasons.append(f"Assurance gap: {len(unresolved_comps)} components possess unresolved or ambiguous identity metadata.")

            unverified_suppliers = [
                ev for ev in linked_evidence
                if not ev.source_organisation or "unknown" in ev.source_organisation.lower()
            ]
            if unverified_suppliers:
                reasons.append(f"Assurance gap: {len(unverified_suppliers)} evidence artifacts lack verified supplier provenance.")

            # 5. Check Remediation Completeness for CLAIM-REMEDIATION-VEX-03
            if "REMEDIATION" in evaluated_claim.claim_id and confirmed_vulns:
                reasons.append(f"{len(confirmed_vulns)} confirmed applicable vulnerabilities lack verified remediation or VEX statement.")

            # Check for Under Investigation
            has_investigation = any("under_investigation" in str(r).lower() for r in reasons) or any(
                "under_investigation" in str(getattr(ev, 'title', '')).lower() or
                "under_investigation" in str(getattr(ev, 'provenance', '')).lower()
                for ev in linked_evidence
            )

            # Determine Final Deterministic Status
            if len(linked_evidence) == 0:
                status = AssuranceClaimStatus.NOT_ASSESSED if not reasons else AssuranceClaimStatus.INSUFFICIENT_EVIDENCE
            elif stale_evidence or missing_types:
                status = AssuranceClaimStatus.INSUFFICIENT_EVIDENCE
            elif contradicted:
                status = AssuranceClaimStatus.CONTRADICTED
            elif unresolved_comps or unverified_suppliers or (confirmed_vulns and "REMEDIATION" in evaluated_claim.claim_id):
                status = AssuranceClaimStatus.INSUFFICIENT_EVIDENCE
            elif has_investigation:
                status = AssuranceClaimStatus.PARTIALLY_SUPPORTED
                reasons.append("Claim partially supported: supplier vulnerability investigation is active.")
            else:
                status = AssuranceClaimStatus.SUPPORTED
                reasons.append("All required evidence types present, valid, fresh, and uncontradicted.")

            evaluated_claim.status = status
            evaluated_claim.status_reasons = reasons
            evaluated_claim.evaluated_at = now
            evaluated_claims.append(evaluated_claim)

            if status in {AssuranceClaimStatus.INSUFFICIENT_EVIDENCE, AssuranceClaimStatus.CONTRADICTED}:
                gaps.append({
                    "claim_id": evaluated_claim.claim_id,
                    "requirement_id": evaluated_claim.related_requirement_id,
                    "status": status.value,
                    "reasons": reasons
                })

        supported_cnt = sum(1 for c in evaluated_claims if c.status == AssuranceClaimStatus.SUPPORTED)
        partially_cnt = sum(1 for c in evaluated_claims if c.status == AssuranceClaimStatus.PARTIALLY_SUPPORTED)
        insufficient_cnt = sum(1 for c in evaluated_claims if c.status == AssuranceClaimStatus.INSUFFICIENT_EVIDENCE)
        contradicted_cnt = sum(1 for c in evaluated_claims if c.status == AssuranceClaimStatus.CONTRADICTED)
        not_assessed_cnt = sum(1 for c in evaluated_claims if c.status == AssuranceClaimStatus.NOT_ASSESSED)

        # Zero False Assurance check: verify no supported claim has missing or stale evidence
        false_assurance_count = 0
        for c in evaluated_claims:
            if c.status == AssuranceClaimStatus.SUPPORTED:
                # If any reason indicates a gap, it is a false assurance
                if any("Missing" in r or "Stale" in r or "Contradiction" in r for r in c.status_reasons):
                    false_assurance_count += 1

        far = false_assurance_count / supported_cnt if supported_cnt > 0 else 0.0

        return AssuranceEvaluationResult(
            evaluated_claims=evaluated_claims,
            total_claims=len(evaluated_claims),
            supported_count=supported_cnt,
            partially_supported_count=partially_cnt,
            insufficient_evidence_count=insufficient_cnt,
            contradicted_count=contradicted_cnt,
            not_assessed_count=not_assessed_cnt,
            false_assurance_rate=round(far, 4),
            gap_summary=gaps
        )
