"""Canonical domain models package for AutoSupplyGuard."""

from app.models.enums import (
    SBOMFormat,
    SBOMValidationStatus,
    IdentityResolutionStatus,
    VulnerabilityMatchMethod,
    VulnerabilityApplicability,
    ConfidenceCategory,
    CorporateRelationshipType,
    EvidenceType,
    AssuranceClaimStatus,
    DependencyScope,
)
from app.models.component import Component
from app.models.sbom import SBOM, DependencyEdge, SBOMQualityMetrics
from app.models.vulnerability import Vulnerability, VulnerabilityMatch
from app.models.product import Product
from app.models.organisation import Organisation
from app.models.relationship import CorporateRelationship
from app.models.evidence import EvidenceArtifact
from app.models.assurance import RegulatoryRequirement, AssuranceClaim

__all__ = [
    "SBOMFormat",
    "SBOMValidationStatus",
    "IdentityResolutionStatus",
    "VulnerabilityMatchMethod",
    "VulnerabilityApplicability",
    "ConfidenceCategory",
    "CorporateRelationshipType",
    "EvidenceType",
    "AssuranceClaimStatus",
    "DependencyScope",
    "Component",
    "SBOM",
    "DependencyEdge",
    "SBOMQualityMetrics",
    "Vulnerability",
    "VulnerabilityMatch",
    "Product",
    "Organisation",
    "CorporateRelationship",
    "EvidenceArtifact",
    "RegulatoryRequirement",
    "AssuranceClaim",
]
