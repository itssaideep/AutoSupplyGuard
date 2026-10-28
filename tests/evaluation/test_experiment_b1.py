"""Test suite for Experiment B1: Robustness of Vulnerability Matching Under Degradation (Milestone 8 / RQ1)."""

import pandas as pd
from pathlib import Path
from scripts.run_experiment_b1 import (
    load_curated_clean_components,
    build_offline_ground_truth,
    perturb_component,
    run_degradation_experiment
)
from app.models.enums import IdentityResolutionStatus

def test_curated_clean_components_loaded():
    """Verify that all 995 components from 46 curated benchmark SBOMs are loaded."""
    components = load_curated_clean_components()
    assert len(components) == 995

def test_offline_ground_truth_construction():
    """Verify offline ground truth mapping contains no network dependency and retrieves known advisories."""
    components = load_curated_clean_components()
    gt_map, all_vulns = build_offline_ground_truth(components)
    assert len(gt_map) == 995
    assert len(all_vulns) > 0
    total_links = sum(len(v) for v in gt_map.values())
    assert total_links > 0

def test_perturb_component_fields():
    """Verify that metadata fields are properly removed during perturbation."""
    components = load_curated_clean_components()
    sample = next(c for c in components if c.purl and c.version)

    # Drop PURL
    p_purl = perturb_component(sample, "purl", drop=True)
    assert p_purl.purl is None
    assert p_purl.version == sample.version

    # Drop Version
    p_ver = perturb_component(sample, "version", drop=True)
    assert p_ver.version is None
    assert p_ver.identity_status == IdentityResolutionStatus.AMBIGUOUS

    # Drop All
    p_all = perturb_component(sample, "all", drop=True)
    assert p_all.purl is None
    assert p_all.version is None

def test_experiment_b1_results_and_wild_sample():
    """Verify that Experiment B1 outputs exist and satisfy quality and stratification requirements."""
    run_degradation_experiment()

    res_path = Path("research/results/exp1_degradation_results.csv")
    assert res_path.exists()
    df_deg = pd.read_csv(res_path)
    assert len(df_deg) == 30  # 5 fields x 6 perturbation rates

    # Monotonic property: dropping version must shift confirmed matches to candidate matches
    df_ver = df_deg[df_deg["field_dropped"] == "version"].sort_values("perturbation_rate")
    assert df_ver.iloc[0]["confirmed_share_mean"] > df_ver.iloc[-1]["confirmed_share_mean"]
    assert df_ver.iloc[-1]["candidate_share_mean"] > df_ver.iloc[0]["candidate_share_mean"]

    # Wild SBOM sample verification
    strat_path = Path("research/results/exp1_wild_stratified_sample.csv")
    assert strat_path.exists()
    df_strat = pd.read_csv(strat_path)
    assert len(df_strat) == 800  # 200 per band x 4 bands
    assert set(df_strat["ntia_band"].unique()) == {"0-3", "4-6", "7-8", "9-10"}
