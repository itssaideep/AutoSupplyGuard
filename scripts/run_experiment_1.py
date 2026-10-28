import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import json
import pandas as pd
from app.ingestion.manager import SBOMIngestionManager
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.vulnerability.automotive_feed import AutomotiveVulnerabilityFeed
from app.vulnerability.matcher import VulnerabilityMatcher

RESULTS_DIR = Path("research/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def run_experiment_1():
    print("=== Running Experiment 1: SBOM Quality & Matchability (RQ1) ===")
    manager = SBOMIngestionManager()
    quality_engine = QualityAssessmentEngine()
    auto_feed = AutomotiveVulnerabilityFeed()
    vulns = list(auto_feed.load().values())
    matcher = VulnerabilityMatcher(vulns)
    
    curated_dir = Path("data/raw/curated_sboms/extracted")
    results = []
    
    if curated_dir.exists():
        project_dirs = [d for d in curated_dir.iterdir() if d.is_dir()]
        for pdir in project_dirs:
            spdx_f = pdir / "sbom.spdx.json"
            if not spdx_f.exists():
                continue
            
            res = manager.parse_file(spdx_f)
            metrics = quality_engine.assess(res)
            
            # Match components against automotive feed
            total_matches = 0
            confirmed = 0
            candidates = 0
            for c in res.components:
                m = matcher.correlate_component(c)
                total_matches += len(m)
                for item in m:
                    if item.applicability.value == "confirmed_applicable":
                        confirmed += 1
                    elif item.applicability.value == "candidate_match":
                        candidates += 1
            
            results.append({
                "document": spdx_f.name,
                "project": pdir.name,
                "components": len(res.components),
                "completeness": metrics.field_completeness,
                "purl_rate": metrics.purl_rate,
                "dep_resolution": metrics.dependency_resolution_rate,
                "matchability_index": metrics.vulnerability_matchability_index,
                "total_vuln_matches": total_matches,
                "confirmed_vulns": confirmed,
                "candidate_matches": candidates
            })
    
    df = pd.DataFrame(results)
    output_csv = RESULTS_DIR / "experiment_1_results.csv"
    df.to_csv(output_csv, index=False)
    
    print(f"[OK] Experiment 1 completed across {len(df)} SBOM documents.")
    print(f"Mean Completeness: {df['completeness'].mean():.4f}")
    print(f"Mean PURL Rate: {df['purl_rate'].mean():.4f}")
    print(f"Mean Matchability: {df['matchability_index'].mean():.4f}")
    print(f"Saved raw results to {output_csv}")

if __name__ == '__main__':
    run_experiment_1()
