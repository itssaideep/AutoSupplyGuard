"""Canonical Assurance Claim and Regulatory Requirement domain models."""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field
from app.models.enums import AssuranceClaimStatus, EvidenceType

class RegulatoryRequirement(BaseModel):
    """Represents a formal cybersecurity standard requirement (e.g. ISO/SAE 21434, UNECE R155)."""
    requirement_id: str = Field(..., description="Unique standard clause identifier (e.g. ISO-21434-RQ-08-01)")
    standard_name: str = Field(..., description="Name of regulation or standard (e.g. ISO/SAE 21434:2021)")
    clause: str = Field(..., description="Specific clause or section reference")
    title: str = Field(..., description="Requirement title or summary")
    wording: str = Field(..., description="Verbatim or summarized requirement mandate")
    source_url: str = Field(..., description="Official publication reference or regulatory link")

class AssuranceClaim(BaseModel):
    """Represents an explicit cybersecurity claim requiring auditable evidence."""
    claim_id: str = Field(..., description="Unique claim ID (e.g. CLAIM-SEC-3RD-PARTY-01)")
    claim_text: str = Field(..., description="Proposition to be proven (e.g. All identified components have been assessed)")
    claim_category: str = Field(default="Vulnerability Management", description="Thematic category")
    related_requirement_id: str = Field(..., description="Associated RegulatoryRequirement ID")
    target_product_id: Optional[str] = Field(None, description="Product under assessment if scoped to product")
    target_component_id: Optional[str] = Field(None, description="Component under assessment if scoped to component")
    required_evidence_types: List[EvidenceType] = Field(..., description="Types of evidence mandatory to support claim")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="IDs of valid, fresh evidence artifacts")
    contradictory_evidence_ids: List[str] = Field(default_factory=list, description="IDs of evidence contradicting the claim")
    status: AssuranceClaimStatus = Field(
        default=AssuranceClaimStatus.NOT_ASSESSED,
        description="Current deterministic evaluation status"
    )
    status_reasons: List[str] = Field(default_factory=list, description="Explicit reasons justifying current status")
    reviewer_notes: Optional[str] = Field(None, description="Auditor or engineer notes")
    evaluated_at: Optional[datetime] = Field(None, description="Timestamp of latest automated evaluation")
    is_synthetic: bool = Field(default=False, description="Whether claim is synthetic evaluation test fixture")
