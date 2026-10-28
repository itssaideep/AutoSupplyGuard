"""Test CycloneDX fixture parsing and quality scoring."""

from pathlib import Path
from app.ingestion.manager import SBOMIngestionManager
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.models.enums import SBOMFormat, SBOMValidationStatus, IdentityResolutionStatus

def test_parse_sample_cyclonedx():
    manager = SBOMIngestionManager()
    quality_engine = QualityAssessmentEngine()
    
    fixture_path = Path("tests/fixtures/sample_cyclonedx.json")
    result = manager.parse_file(fixture_path)
    
    assert result.sbom.format == SBOMFormat.CYCLONEDX
    assert result.sbom.spec_version == "1.4"
    assert result.sbom.validation_status == SBOMValidationStatus.VALID
    assert len(result.errors) == 0
    assert len(result.warnings) == 0
    
    # 1 root component + 4 libraries = 5 components
    assert len(result.components) == 5
    # 2 parent dependency entries: 2 children for root, 2 children for curl = 4 edges
    assert len(result.dependencies) == 4
    
    # Check openssl component
    openssl = next(c for c in result.components if c.name == "openssl")
    assert openssl.version == "1.1.1u"
    assert openssl.purl == "pkg:generic/openssl@1.1.1u"
    assert openssl.cpe == "cpe:2.3:a:openssl:openssl:1.1.1u:*:*:*:*:*:*:*"
    assert openssl.supplier == "OpenSSL Project"
    assert openssl.license == "OpenSSL"
    assert openssl.identity_status == IdentityResolutionStatus.RESOLVED_EXACT
    
    # Assess quality
    metrics = quality_engine.assess(result)
    assert metrics.field_completeness == 1.0  # All have name, version, and purl
    assert metrics.purl_rate == 1.0           # All have valid PURLs
    assert metrics.dependency_resolution_rate == 1.0 # All 4 edges resolve
    assert metrics.duplicate_component_rate == 0.0   # No duplicates
    assert metrics.vulnerability_matchability_index == 1.0 # All matchable
    
    # Generate report
    report = quality_engine.generate_report(result)
    assert report["format"] == "CycloneDX"
    assert report["component_count"] == 5
    assert report["quality_metrics"]["field_completeness"] == 1.0
