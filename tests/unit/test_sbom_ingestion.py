"""Unit tests for SBOM Ingestion, Normalisation, and Quality Assessment."""

import pytest
from app.ingestion.manager import SBOMIngestionManager
from app.ingestion.spdx_parser import SPDXParser
from app.ingestion.cyclonedx_parser import CycloneDXParser
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.normalisation.purl_normaliser import normalise_purl, construct_purl
from app.normalisation.version_normaliser import normalise_version, matches_version_constraint
from app.models.enums import SBOMValidationStatus, IdentityResolutionStatus, SBOMFormat

@pytest.fixture
def manager():
    return SBOMIngestionManager()

@pytest.fixture
def quality_engine():
    return QualityAssessmentEngine()

# 1. PURL Normalisation Tests
def test_purl_normalisation_valid():
    raw = "pkg:npm/%40angular/animation@12.3.1?foo=bar#subpath"
    canonical, eco, name, ver, is_valid = normalise_purl(raw)
    assert is_valid is True
    assert eco == "npm"
    assert name == "@angular/animation"
    assert ver == "12.3.1"
    assert canonical.startswith("pkg:npm/")

def test_purl_normalisation_invalid():
    canonical, eco, name, ver, is_valid = normalise_purl("not-a-purl")
    assert is_valid is False
    assert canonical is None

def test_construct_purl():
    purl = construct_purl("pypi", "requests", "2.28.1")
    assert purl == "pkg:pypi/requests@2.28.1"

# 2. Version Normalisation Tests
def test_version_normalisation():
    # Leading 'v'
    v_norm, is_valid, is_mod = normalise_version("v1.2.3")
    assert v_norm == "1.2.3"
    assert is_valid is True
    assert is_mod is True
    
    # Null / Unknown
    v_none, is_valid_none, _ = normalise_version("unknown")
    assert v_none is None
    assert is_valid_none is False

def test_version_constraint_matching():
    assert matches_version_constraint("1.2.3", "==1.2.3") is True
    assert matches_version_constraint("1.2.3", "<2.0.0") is True
    assert matches_version_constraint("2.1.0", "<2.0.0") is False
    assert matches_version_constraint("1.2.3", "*") is True

# 3. Ingestion: Empty SBOM
def test_empty_sbom(manager):
    res = manager.parse_dict({}, source_identifier="empty.json")
    assert res.sbom.validation_status in {SBOMValidationStatus.UNSUPPORTED_VERSION, SBOMValidationStatus.MALFORMED}
    assert len(res.components) == 0

# 4. Ingestion: Malformed JSON File
def test_malformed_json_file(tmp_path, manager):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{this is not valid json")
    res = manager.parse_file(bad_file)
    assert res.sbom.validation_status == SBOMValidationStatus.MALFORMED
    assert "JSON decoding error" in res.errors[0]

# 5. Ingestion: Missing Versions in SPDX
def test_spdx_missing_version(manager, quality_engine):
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "TestDoc",
        "packages": [
            {
                "SPDXID": "SPDXRef-Pkg1",
                "name": "lib-without-version"
                # Missing versionInfo and externalRefs
            }
        ]
    }
    res = manager.parse_dict(spdx_doc, source_identifier="test_spdx.json")
    assert len(res.components) == 1
    comp = res.components[0]
    assert comp.name == "lib-without-version"
    assert comp.version is None
    assert comp.identity_status == IdentityResolutionStatus.UNRESOLVED
    assert res.sbom.validation_status == SBOMValidationStatus.VALID_WITH_WARNINGS

    metrics = quality_engine.assess(res)
    assert metrics.field_completeness == 0.0  # missing version and purl

# 6. Ingestion: Duplicate Packages in CycloneDX
def test_cyclonedx_duplicate_packages(manager, quality_engine):
    cdx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:12345",
        "components": [
            {"bom-ref": "pkg1", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
            {"bom-ref": "pkg2", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"}
        ]
    }
    res = manager.parse_dict(cdx_doc, source_identifier="dup.cdx.json")
    assert len(res.components) == 2
    assert any("Duplicate component identity detected" in w for w in res.warnings)
    
    metrics = quality_engine.assess(res)
    assert metrics.duplicate_component_rate > 0.0  # 1 duplicate out of 2 components

# 7. Ingestion: Unresolved References in Dependencies
def test_unresolved_dependency_references(manager, quality_engine):
    cdx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"bom-ref": "comp-A", "name": "pkg-a", "version": "1.0.0"}
        ],
        "dependencies": [
            {"ref": "comp-A", "dependsOn": ["comp-B-nonexistent"]}
        ]
    }
    res = manager.parse_dict(cdx_doc, source_identifier="unresolved.json")
    assert len(res.components) == 1
    assert len(res.dependencies) == 0  # Unresolved target dropped from valid graph
    assert any("Unresolved dependency child ref: 'comp-B-nonexistent'" in w for w in res.warnings)

# 8. Ingestion: Dependency Cycles Handling
def test_dependency_cycles(manager):
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {"SPDXID": "SPDXRef-A", "name": "node-a", "versionInfo": "1.0.0"},
            {"SPDXID": "SPDXRef-B", "name": "node-b", "versionInfo": "1.0.0"}
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-A", "relatedSpdxElement": "SPDXRef-B", "relationshipType": "DEPENDS_ON"},
            {"spdxElementId": "SPDXRef-B", "relatedSpdxElement": "SPDXRef-A", "relationshipType": "DEPENDS_ON"}
        ]
    }
    res = manager.parse_dict(spdx_doc, source_identifier="cycle.json")
    assert len(res.components) == 2
    assert len(res.dependencies) == 2
    # Parser should cleanly ingest both edges without infinite recursion
