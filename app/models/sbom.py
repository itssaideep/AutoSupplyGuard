"""Canonical SBOM and Dependency domain models."""

from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field
from app.models.enums import SBOMFormat, SBOMValidationStatus, DependencyScope

class DependencyEdge(BaseModel):
    """Represents a directed dependency edge between two components."""
    source_component_id: str = Field(..., description="ID of the parent / depending component")
    target_component_id: str = Field(..., description="ID of the child / depended-upon component")
    relationship_type: str = Field(default="DEPENDS_ON", description="SPDX or CycloneDX relationship type")
    scope: DependencyScope = Field(default=DependencyScope.UNKNOWN, description="Identified scope of dependency")
    is_transitive: bool = Field(default=False, description="Whether relationship is inferred as transitive")
    raw_source_ref: Optional[str] = Field(None, description="Original source identifier in raw document")
    raw_target_ref: Optional[str] = Field(None, description="Original target identifier in raw document")

class SBOMQualityMetrics(BaseModel):
    """Quantified quality metrics calculated by the SBOM Quality Engine."""
    field_completeness: float = Field(0.0, description="M_comp: Proportion with Name, Version, and PURL/CPE")
    purl_rate: float = Field(0.0, description="M_purl: Proportion with valid PURL")
    dependency_resolution_rate: float = Field(0.0, description="M_dep: Proportion of valid dependency references")
    duplicate_component_rate: float = Field(0.0, description="M_dup: Proportion of duplicate components")
    vulnerability_matchability_index: float = Field(0.0, description="M_matchable: Proportion matchable to vuln feeds")
    source_quality_score: Optional[float] = Field(None, description="External NTIA quality score if available (e.g. from Wild SBOMs)")

class SBOM(BaseModel):
    """Represents an ingested Software Bill of Materials (SPDX or CycloneDX)."""
    internal_id: str = Field(..., description="Unique internal identifier for the SBOM")
    format: SBOMFormat = Field(..., description="SBOM Standard (CycloneDX or SPDX)")
    format_version: Optional[str] = Field(None, description="Serialization format version (e.g. JSON, XML, Tag-Value)")
    spec_version: Optional[str] = Field(None, description="Standard specification version (e.g. 1.4, 2.2, 2.3)")
    document_name: Optional[str] = Field(None, description="Original document or project name declared in metadata")
    author: Optional[str] = Field(None, description="Author or tool creator declared in metadata")
    supplier: Optional[str] = Field(None, description="Supplier or manufacturer organisation declared in document")
    creation_timestamp: Optional[datetime] = Field(None, description="Document creation timestamp in UTC")
    source_identifier: str = Field(..., description="Originating filename, URL, or dataset identifier")
    sha256_checksum: str = Field(..., description="SHA-256 checksum of original raw input document")
    component_count: int = Field(default=0, description="Total number of components parsed")
    dependency_count: int = Field(default=0, description="Total number of dependency relationships parsed")
    validation_status: SBOMValidationStatus = Field(
        default=SBOMValidationStatus.VALID,
        description="Parsing and schema validation status"
    )
    validation_errors: List[str] = Field(default_factory=list, description="Parsing warnings or schema errors")
    quality_metrics: Optional[SBOMQualityMetrics] = Field(None, description="Assessed quality metrics")
    is_synthetic: bool = Field(default=False, description="Whether document is synthetic test data")
