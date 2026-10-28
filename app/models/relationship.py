"""Canonical Corporate and Supplier Relationship domain model."""

from typing import Optional, List
from datetime import date, datetime
from pydantic import BaseModel, Field
from app.models.enums import CorporateRelationshipType, ConfidenceCategory

class CorporateRelationship(BaseModel):
    """Represents an independently documented or synthetic organisational relationship."""
    relationship_id: str = Field(..., description="Unique ID for this relationship record")
    entity_a: str = Field(..., description="Originating organisation ID (e.g. volvo-group)")
    entity_b: str = Field(..., description="Target organisation ID (e.g. nvidia)")
    relationship_type: CorporateRelationshipType = Field(..., description="Strictly defined relationship type")
    scope: str = Field(..., description="Documented scope of relationship (e.g. autonomous driving compute platform)")
    source_url: str = Field(..., description="Official or verifiable public source URL")
    source_title: str = Field(..., description="Title or headline of the publication source")
    publication_date: Optional[date] = Field(None, description="Date source was originally published")
    retrieved_at: datetime = Field(default_factory=datetime.utcnow, description="ISO-8601 retrieval timestamp")
    supporting_excerpt: str = Field(..., description="Verbatim short evidence excerpt from source")
    confidence: ConfidenceCategory = Field(default=ConfidenceCategory.HIGH, description="Confidence in relationship")
    evidence_type: str = Field(default="official_company_disclosure", description="Source classification")
    limitations: List[str] = Field(default_factory=list, description="Explicit statements of what the evidence does NOT prove")
    validation_state: str = Field(default="manually_verified", description="Review state")
    is_synthetic: bool = Field(default=False, description="Explicit flag indicating whether relationship is synthetic")
