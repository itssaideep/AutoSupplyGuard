"""Base class and result containers for SBOM parsers."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from app.models.sbom import SBOM, DependencyEdge
from app.models.component import Component

class ParsedSBOMResult(BaseModel):
    """Container holding parsed domain entities and validation audit results."""
    sbom: SBOM
    components: List[Component] = Field(default_factory=list)
    dependencies: List[DependencyEdge] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

class BaseSBOMParser(ABC):
    """Abstract base parser interface for SBOM documents."""

    @abstractmethod
    def can_parse(self, raw_data: Dict[str, Any]) -> bool:
        """Determines if the parser can handle the given raw JSON data."""
        pass

    @abstractmethod
    def parse(self, raw_data: Dict[str, Any], source_identifier: str, sha256_checksum: str) -> ParsedSBOMResult:
        """Parses raw data into canonical SBOM, Component, and DependencyEdge entities."""
        pass
