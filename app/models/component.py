"""Canonical Component domain model."""

from typing import Optional, List
from pydantic import BaseModel, Field
from app.models.enums import IdentityResolutionStatus

class Component(BaseModel):
    """Represents a discrete software package, module, or library identified within an SBOM."""
    
    internal_id: str = Field(..., description="Unique internal UUID or deterministic hash for component")
    name: str = Field(..., description="Normalised component name")
    version: Optional[str] = Field(None, description="Normalised component version string")
    purl: Optional[str] = Field(None, description="Standardised Package URL (PURL)")
    cpe: Optional[str] = Field(None, description="Common Platform Enumeration string if declared")
    supplier: Optional[str] = Field(None, description="Reported supplier or publisher organisation")
    ecosystem: Optional[str] = Field(None, description="Identified package manager or ecosystem (e.g. npm, pypi, maven)")
    license: Optional[str] = Field(None, description="Declared or concluded SPDX license expression")
    source_sbom_id: str = Field(..., description="Internal ID of the originating SBOM document")
    original_id: str = Field(..., description="Exact original component ID from raw SBOM (e.g. SPDXRef-Package or BOM-ref)")
    original_name: Optional[str] = Field(None, description="Raw unnormalized component name as read from input")
    original_version: Optional[str] = Field(None, description="Raw unnormalized version string as read from input")
    identity_status: IdentityResolutionStatus = Field(
        default=IdentityResolutionStatus.UNRESOLVED,
        description="Confidence status of component identity resolution"
    )
    is_synthetic: bool = Field(default=False, description="Explicit flag indicating whether record is synthetic test fixture")
    notes: Optional[str] = Field(None, description="Auditing or parsing notes regarding ambiguities")
