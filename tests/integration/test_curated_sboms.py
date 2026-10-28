"""Integration tests running ingestion and quality assessment on Curated SBOM Benchmark."""

import os
from pathlib import Path
import pytest
from app.ingestion.manager import SBOMIngestionManager
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.models.enums import SBOMValidationStatus, SBOMFormat

CURATED_DIR = Path("data/raw/curated_sboms/extracted")

@pytest.mark.skipif(not CURATED_DIR.exists(), reason="Curated SBOM dataset not extracted")
def test_ingest_all_curated_sboms():
    manager = SBOMIngestionManager()
    quality_engine = QualityAssessmentEngine()
    
    project_dirs = [d for d in CURATED_DIR.iterdir() if d.is_dir()]
    assert len(project_dirs) == 46, f"Expected 46 curated project directories, found {len(project_dirs)}"
    
    total_components = 0
    total_dependencies = 0
    passed_sboms = 0
    
    for pdir in project_dirs:
        spdx_file = pdir / "sbom.spdx.json"
        assert spdx_file.exists(), f"Missing sbom.spdx.json in {pdir}"
        
        result = manager.parse_file(spdx_file)
        assert result.sbom.format == SBOMFormat.SPDX
        assert result.sbom.spec_version == "2.2"
        assert result.sbom.validation_status in {SBOMValidationStatus.VALID, SBOMValidationStatus.VALID_WITH_WARNINGS}
        assert len(result.errors) == 0, f"Unexpected errors parsing {spdx_file}: {result.errors}"
        
        # Assess quality
        metrics = quality_engine.assess(result)
        assert 0.0 <= metrics.field_completeness <= 1.0
        assert 0.0 <= metrics.purl_rate <= 1.0
        assert 0.0 <= metrics.dependency_resolution_rate <= 1.0
        assert 0.0 <= metrics.vulnerability_matchability_index <= 1.0
        
        total_components += len(result.components)
        total_dependencies += len(result.dependencies)
        passed_sboms += 1
    
    print(f"\n[INTEGRATION] Ingested {passed_sboms} curated SBOMs: {total_components} components, {total_dependencies} dependencies.")
    # Total relationships in the raw files is 995. Exactly 46 of them are top-level
    # 'SPDXRef-DOCUMENT DESCRIBES' relations, leaving 949 pure component-to-component dependencies.
    assert passed_sboms == 46
    assert total_components == 995
    assert total_dependencies == 949

