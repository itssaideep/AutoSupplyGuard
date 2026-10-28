"""Canonical Organisation domain model."""

from typing import List
from pydantic import BaseModel, Field

class Organisation(BaseModel):
    """Represents an automotive entity, supplier, OEM, or software vendor."""
    organisation_id: str = Field(..., description="Unique slug or canonical ID (e.g. volvo-group, nvidia)")
    name: str = Field(..., description="Full legal or commercial name")
    canonical_name: str = Field(..., description="Standardised canonical representation")
    aliases: List[str] = Field(default_factory=list, description="Known alternate names or trade brands")
    organisation_type: str = Field(..., description="OEM, Tier 1, Tier 2, Semiconductor, OpenSourceFoundation")
    source_references: List[str] = Field(default_factory=list, description="Public sources establishing organisation validity")
    is_synthetic: bool = Field(default=False, description="Whether organisation is synthetic test data")
