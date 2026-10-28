"""SBOM Quality Assessment Engine calculating formal quality metrics."""

from typing import Dict, Any, Optional
from app.models.sbom import SBOMQualityMetrics
from app.models.enums import IdentityResolutionStatus
from app.ingestion.base import ParsedSBOMResult

class QualityAssessmentEngine:
    """Calculates formal, reproducible SBOM quality metrics defined in research/metrics.md."""

    def assess(self, parsed_result: ParsedSBOMResult, source_quality_score: Optional[float] = None) -> SBOMQualityMetrics:
        """Computes all 5 quality metrics for a parsed SBOM result and updates the SBOM object."""
        components = parsed_result.components
        dependencies = parsed_result.dependencies
        total_components = len(components)

        if total_components == 0:
            metrics = SBOMQualityMetrics(
                field_completeness=0.0,
                purl_rate=0.0,
                dependency_resolution_rate=1.0 if len(dependencies) == 0 else 0.0,
                duplicate_component_rate=0.0,
                vulnerability_matchability_index=0.0,
                source_quality_score=source_quality_score
            )
            parsed_result.sbom.quality_metrics = metrics
            return metrics

        # 1. Field Completeness (M_comp)
        complete_count = 0
        for c in components:
            has_name = bool(c.name and c.name != "unknown-package")
            has_version = bool(c.version)
            has_id = bool(c.purl or c.cpe)
            if has_name and has_version and has_id:
                complete_count += 1
        m_comp = complete_count / total_components

        # 2. PURL Rate (M_purl)
        purl_count = sum(1 for c in components if c.purl and c.identity_status == IdentityResolutionStatus.RESOLVED_EXACT)
        m_purl = purl_count / total_components

        # 3. Dependency Resolution Rate (M_dep)
        comp_id_set = {c.internal_id for c in components}
        if len(dependencies) == 0:
            m_dep = 1.0  # vacuously resolved if no edges declared
        else:
            resolved_edges = sum(
                1 for d in dependencies
                if d.source_component_id in comp_id_set and d.target_component_id in comp_id_set
            )
            m_dep = resolved_edges / len(dependencies)

        # 4. Duplicate Component Rate (M_dup)
        identities = {f"{c.name}@{c.version}@{c.ecosystem}" for c in components}
        m_dup = max(0.0, 1.0 - (len(identities) / total_components))

        # 5. Vulnerability Matchability Index (M_matchable)
        matchable_count = 0
        for c in components:
            has_purl = bool(c.purl)
            has_name_ver_eco = bool(c.name and c.version and c.ecosystem)
            if has_purl or has_name_ver_eco:
                matchable_count += 1
        m_matchable = matchable_count / total_components

        metrics = SBOMQualityMetrics(
            field_completeness=round(m_comp, 4),
            purl_rate=round(m_purl, 4),
            dependency_resolution_rate=round(m_dep, 4),
            duplicate_component_rate=round(m_dup, 4),
            vulnerability_matchability_index=round(m_matchable, 4),
            source_quality_score=source_quality_score
        )

        # Attach metrics back to SBOM model
        parsed_result.sbom.quality_metrics = metrics
        return metrics

    def generate_report(self, parsed_result: ParsedSBOMResult) -> Dict[str, Any]:
        """Generates an auditable, machine-readable validation and quality report."""
        sbom = parsed_result.sbom
        metrics = sbom.quality_metrics or self.assess(parsed_result)

        return {
            "sbom_id": sbom.internal_id,
            "document_name": sbom.document_name,
            "format": sbom.format.value,
            "spec_version": sbom.spec_version,
            "source_identifier": sbom.source_identifier,
            "sha256_checksum": sbom.sha256_checksum,
            "component_count": sbom.component_count,
            "dependency_count": sbom.dependency_count,
            "validation_status": sbom.validation_status.value,
            "validation_errors": sbom.validation_errors,
            "quality_metrics": {
                "field_completeness": metrics.field_completeness,
                "purl_rate": metrics.purl_rate,
                "dependency_resolution_rate": metrics.dependency_resolution_rate,
                "duplicate_component_rate": metrics.duplicate_component_rate,
                "vulnerability_matchability_index": metrics.vulnerability_matchability_index,
                "source_quality_score": metrics.source_quality_score,
            }
        }
