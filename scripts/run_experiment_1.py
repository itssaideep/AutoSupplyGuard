"""Experiment 1: SBOM Quality & Component Matchability (RQ1)."""

import argparse
import pandas as pd
from app.ingestion.manager import SBOMIngestionManager
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.vulnerability.automotive_feed import AutomotiveVulnerabilityFeed
from app.vulnerability.matcher import VulnerabilityMatcher
from app.core.config import settings

RESULTS_DIR = settings.RESULTS_DIR
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def run_experiment_1(smoke: bool = False):
    print("=== Running Experiment 1: SBOM Quality & Matchability (RQ1) ===")
    manager = SBOMIngestionManager()
    quality_engine = QualityAssessmentEngine()
    auto_feed = AutomotiveVulnerabilityFeed()
    vulns = list(auto_feed.load().values())
    matcher = VulnerabilityMatcher(vulns)

    curated_dir = settings.RAW_DATA_DIR / "curated_sboms" / "extracted"
    results = []

    if curated_dir.exists():
        project_dirs = [d for d in curated_dir.iterdir() if d.is_dir()]
        if smoke:
            project_dirs = project_dirs[:3]
        for pdir in project_dirs:
            sbom_file = pdir / "sbom.spdx.json"
            if not sbom_file.exists():
                continue
            parsed = manager.parse_file(sbom_file)
            metrics = quality_engine.assess(parsed)

            # Match vulnerabilities
            all_matches = []
            for c in parsed.components:
                all_matches.extend(matcher.match(c))

            confirmed = sum(1 for m in all_matches if m.applicability.value == "confirmed_applicable")
            candidates = sum(1 for m in all_matches if m.applicability.value == "candidate_match")

            results.append({
                "document": sbom_file.name,
                "project": pdir.name,
                "components": len(parsed.components),
                "completeness": round(metrics.field_completeness, 4),
                "purl_rate": round(metrics.purl_rate, 4),
                "dep_resolution": round(metrics.dependency_resolution_rate, 4),
                "matchability_index": round(metrics.vulnerability_matchability_index, 4),
                "total_vuln_matches": len(all_matches),
                "confirmed_vulns": confirmed,
                "candidate_matches": candidates
            })

    df = pd.DataFrame(results)
    output_csv = RESULTS_DIR / ("experiment_1_smoke.csv" if smoke else "experiment_1_results.csv")
    df.to_csv(output_csv, index=False)

    print(f"[OK] Experiment 1 completed across {len(df)} SBOM documents.")
    if len(df) > 0:
        print(f"Mean Completeness: {df['completeness'].mean():.4f}")
        print(f"Mean PURL Rate: {df['purl_rate'].mean():.4f}")
        print(f"Mean Matchability: {df['matchability_index'].mean():.4f}")
    print(f"Saved raw results to {output_csv}")

def main():
    parser = argparse.ArgumentParser(description="Run Experiment 1 (RQ1).")
    parser.add_argument("--smoke", action="store_true", help="Run in smoke test mode with small subset.")
    args = parser.parse_args()
    run_experiment_1(smoke=args.smoke)

if __name__ == '__main__':
    main()
