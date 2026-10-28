"""Canonical Product domain model."""

from typing import Optional, List
from pydantic import BaseModel, Field
from app.models.enums import ConfidenceCategory

class Product(BaseModel):
    """Represents a vehicular system, ECU, software package, or finished vehicle platform."""
    product_id: str = Field(..., description="Unique product identifier (e.g. VOLVO-FH-TCU-01)")
    name: str = Field(..., description="Product commercial or engineering name")
    version: Optional[str] = Field(None, description="Software release or hardware revision version")
    category: str = Field(default="Automotive Subsystem", description="Product domain (e.g. Telematics, Infotainment, Gateway)")
    supporting_source: str = Field(..., description="Evidence source proving product existence and specification")
    related_sbom_ids: List[str] = Field(default_factory=list, description="IDs of SBOMs associated with this product")
    related_component_ids: List[str] = Field(default_factory=list, description="Direct or root component IDs in this product")
    confidence: ConfidenceCategory = Field(default=ConfidenceCategory.HIGH, description="Product identification confidence")
    is_synthetic: bool = Field(default=False, description="Whether product is synthetic scenario fixture")
    notes: Optional[str] = Field(None, description="Scope or deployment context notes")
