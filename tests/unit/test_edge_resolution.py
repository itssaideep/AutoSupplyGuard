"""Unit tests verifying dependency edge extraction without document-level inflation (A2)."""

import json
import pytest
from app.ingestion.spdx_parser import SPDXParser
from app.ingestion.cyclonedx_parser import CycloneDXParser
from app.core.config import settings

def test_spdx_filters_document_describes_edges():
    """Verify that SPDXRef-DOCUMENT DESCRIBES relationships are excluded from component dependencies."""
    spdx_json = {
        "spdxVersion": "SPDX-2.2",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "TestDocument",
        "documentNamespace": "http://spdx.org/spdxdocs/test",
        "packages": [
            {
                "name": "pkg-a",
                "SPDXID": "SPDXRef-Package-A",
                "versionInfo": "1.0.0"
            },
            {
                "name": "pkg-b",
                "SPDXID": "SPDXRef-Package-B",
                "versionInfo": "2.0.0"
            }
        ],
        "relationships": [
            # Top-level packaging edge: must be filtered out
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Package-A",
                "relationshipType": "DESCRIBES"
            },
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Package-B",
                "relationshipType": "DESCRIBES"
            },
            # Real component dependency edge: must be kept
            {
                "spdxElementId": "SPDXRef-Package-A",
                "relatedSpdxElement": "SPDXRef-Package-B",
                "relationshipType": "DEPENDS_ON"
            }
        ]
    }

    parser = SPDXParser()
    result = parser.parse(spdx_json, source_identifier="memory://test.spdx.json", sha256_checksum="abc123sha")

    assert len(result.components) == 2
    # Exactly 1 true dependency edge must be extracted, filtering out the 2 DESCRIBES edges
    assert len(result.dependencies) == 1
    edge = result.dependencies[0]
    assert edge.source_component_id != "SPDXRef-DOCUMENT"
    assert edge.target_component_id != "SPDXRef-DOCUMENT"
    assert edge.relationship_type == "DEPENDS_ON"

def test_cyclonedx_metadata_component_packaging_handling():
    """Verify that CycloneDX metadata.component is not treated as an internal component dependency of itself."""
    cyclonedx_json = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "name": "VehicleGatewaySystem",
                "version": "1.0.0",
                "type": "application",
                "bom-ref": "pkg:generic/VehicleGatewaySystem@1.0.0"
            }
        },
        "components": [
            {
                "name": "sub-lib-1",
                "version": "1.2.0",
                "type": "library",
                "bom-ref": "pkg:generic/sub-lib-1@1.2.0"
            },
            {
                "name": "sub-lib-2",
                "version": "2.3.0",
                "type": "library",
                "bom-ref": "pkg:generic/sub-lib-2@2.3.0"
            }
        ],
        "dependencies": [
            {
                "ref": "pkg:generic/VehicleGatewaySystem@1.0.0",
                "dependsOn": ["pkg:generic/sub-lib-1@1.2.0"]
            },
            {
                "ref": "pkg:generic/sub-lib-1@1.2.0",
                "dependsOn": ["pkg:generic/sub-lib-2@2.3.0"]
            }
        ]
    }

    parser = CycloneDXParser()
    result = parser.parse(cyclonedx_json, source_identifier="memory://test.cdx.json", sha256_checksum="dummy")

    assert len(result.components) == 3
    # Check that root metadata.component is recognized as the application root
    root_comp = next((c for c in result.components if c.name == "VehicleGatewaySystem"), None)
    assert root_comp is not None
    assert root_comp.ecosystem == "application"

    # Verify sub-lib-1 -> sub-lib-2 is extracted
    assert any(d.raw_target_ref == "pkg:generic/sub-lib-2@2.3.0" for d in result.dependencies)

def test_curated_benchmark_exact_949_edge_invariant():
    """Verifies that across the 46 curated benchmark files, exactly 949 component dependencies exist."""
    curated_dir = settings.RAW_DATA_DIR / "curated_sboms" / "extracted"
    if not curated_dir.exists():
        pytest.skip("Curated SBOMs raw directory not extracted")

    parser = SPDXParser()
    total_components = 0
    total_dependencies = 0

    for pdir in curated_dir.iterdir():
        if not pdir.is_dir():
            continue
        sbom_path = pdir / "sbom.spdx.json"
        if not sbom_path.exists():
            continue
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        parsed = parser.parse(data, source_identifier=str(sbom_path), sha256_checksum="test")
        total_components += len(parsed.components)
        total_dependencies += len(parsed.dependencies)

        # Verify no edge contains SPDXRef-DOCUMENT
        for edge in parsed.dependencies:
            assert "DOCUMENT" not in edge.source_component_id
            assert "DOCUMENT" not in edge.target_component_id

    assert total_components == 995
    assert total_dependencies == 949
