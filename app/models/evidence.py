"""Canonical Evidence Artifact domain model."""

from typing import Optional
from datetime import date, datetime
from pydantic import BaseModel, Field
from app.models.enums import EvidenceType

class EvidenceArtifact(BaseModel):
    """Represents an immutable, verifiable evidence document or record supporting an assurance claim."""
    evidence_id: str = Field(..., description="Unique identifier for evidence artifact")
    evidence_type: EvidenceType = Field(..., description="Type of evidence artifact")
    title: str = Field(..., description="Descriptive title of evidence artifact")
    source_url_or_file: str = Field(..., description="Source URL or relative file path")
    source_organisation: str = Field(..., description="Entity that published or attested the evidence")
    publication_date: Optional[date] = Field(None, description="Original publication date")
    retrieval_date: datetime = Field(default_factory=datetime.utcnow, description="Timestamp artifact was acquired")
    effective_date: Optional[date] = Field(None, description="Date evidence became operative")
    expiration_date: Optional[date] = Field(None, description="Date evidence expires or requires review")
    content_checksum: str = Field(..., description="SHA-256 hash of evidence artifact content")
    provenance: str = Field(..., description="Chain of custody and acquisition notes")
    validation_status: str = Field(default="verified", description="Verified, unverified, corrupted")
    is_synthetic: bool = Field(default=False, description="Whether evidence artifact is synthetic test fixture")
