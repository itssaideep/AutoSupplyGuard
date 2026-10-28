"""Experiment B1: Robustness of Vulnerability Matching Under Real-World SBOM Degradation.

Evaluates how dropping critical SBOM metadata fields (PURL, Version, Hash, Supplier, All)
at perturbation rates [0%, 10%, 25%, 50%, 75%, 100%] impacts vulnerability matching
precision, recall, and uncertainty across 5 deterministic random seeds [11, 22, 33, 44, 55].

Ground truth is constructed offline using known component identities and cached OSV advisories.
Additionally conducts quality-stratified sampling across 78,032 Wild SBOMs (Zacchiroli et al., MSR 2025).
"""

import random
from typing import Dict, List, Any, Tuple
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app.ingestion.manager import SBOMIngestionManager
from app.models.component import Component
from app.models.vulnerability import Vulnerability
from app.models.enums import VulnerabilityApplicability, IdentityResolutionStatus
from app.vulnerability.osv_client import OSVClient
from app.vulnerability.matcher import VulnerabilityMatcher
from app.core.config import settings

RESULTS_DIR = settings.RESULTS_DIR
FIGURES_DIR = settings.FIGURES_DIR
CURATED_DIR = settings.RAW_DATA_DIR / "curated_sboms" / "extracted"
WILD_SBOMS_CSV = settings.RAW_DATA_DIR / "wild_sboms" / "sboms-01.csv"

RESULTS_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

PERTURBATION_RATES = [0.0, 0.10, 0.25, 0.50, 0.75, 1.00]
SEEDS = [11, 22, 33, 44, 55]
FIELDS_TO_DROP = ["purl", "version", "hash", "supplier", "all"]

def load_curated_clean_components() -> List[Component]:
    """Loads all components from the 46 curated benchmark SBOMs."""
    manager = SBOMIngestionManager()
    all_components: List[Component] = []

    for pdir in sorted(CURATED_DIR.iterdir()):
        if not pdir.is_dir():
            continue
        sbom_file = pdir / "sbom.spdx.json"
        if not sbom_file.exists():
            continue
        parsed = manager.parse_file(sbom_file)
        all_components.extend(parsed.components)

    return all_components

def build_offline_ground_truth(components: List[Component]) -> Tuple[Dict[str, List[Vulnerability]], List[Vulnerability]]:
    """Builds ground-truth vulnerability mappings using cached OSV advisories for exact PURLs."""
    client = OSVClient(enable_network=False)
    purls = list({c.purl for c in components if c.purl})
    batch_res = client.query_batch_purls(purls)

    ground_truth_map: Dict[str, List[Vulnerability]] = {}
    all_known_vulns: Dict[str, Vulnerability] = {}

    for c in components:
        if not c.purl:
            ground_truth_map[c.internal_id] = []
            continue

        vulns = batch_res.get(c.purl, [])
        ground_truth_map[c.internal_id] = vulns
        for v in vulns:
            all_known_vulns[v.vulnerability_id] = v

    return ground_truth_map, list(all_known_vulns.values())

def perturb_component(comp: Component, field: str, drop: bool) -> Component:
    """Returns a perturbed copy of a Component with specific metadata fields removed."""
    if not drop:
        return comp.model_copy(deep=True)

    p_comp = comp.model_copy(deep=True)
    if field in ["purl", "all"]:
        p_comp.purl = None
    if field in ["version", "all"]:
        p_comp.version = None
        p_comp.identity_status = IdentityResolutionStatus.AMBIGUOUS
    if field in ["hash", "all"]:
        p_comp.checksum = None
    if field in ["supplier", "all"]:
        p_comp.supplier = None

    return p_comp

def run_degradation_experiment():
    print("=== Running Experiment B1: SBOM Metadata Degradation & Matchability ===")
    components = load_curated_clean_components()
    print(f"[OK] Ingested {len(components)} clean components from 46 curated benchmark SBOMs.")

    ground_truth_map, all_known_vulns = build_offline_ground_truth(components)
    total_gt_vulns = sum(len(v) for v in ground_truth_map.values())
    print(f"[OK] Constructed offline ground truth with {total_gt_vulns} true vulnerability links across {len(all_known_vulns)} unique CVEs.")

    matcher = VulnerabilityMatcher(known_vulnerabilities=all_known_vulns)

    run_records: List[Dict[str, Any]] = []

    for field in FIELDS_TO_DROP:
        print(f"--> Evaluating perturbation of field: '{field}'")
        for rate in PERTURBATION_RATES:
            rate_confirmed = []
            rate_candidate = []
            rate_unmatched = []
            rate_precision = []
            rate_recall = []
            rate_fpr = []

            for seed in SEEDS:
                rng = random.Random(seed)
                # Determine which components have their metadata dropped
                drop_flags = [rng.random() < rate for _ in components]

                n_confirmed = 0
                n_candidate = 0
                n_unmatched = 0

                tp = 0
                fp = 0
                fn = 0
                tn = 0

                for comp, do_drop in zip(components, drop_flags):
                    perturbed = perturb_component(comp, field, do_drop)
                    matches = matcher.correlate_component(perturbed)
                    gt_vulns = ground_truth_map.get(comp.internal_id, [])
                    gt_vuln_ids = {v.vulnerability_id for v in gt_vulns}

                    if not matches:
                        n_unmatched += 1
                        if len(gt_vulns) > 0:
                            fn += len(gt_vulns)
                        else:
                            tn += 1
                    else:
                        is_conf = any(
                            m.applicability in [VulnerabilityApplicability.CONFIRMED_APPLICABLE, VulnerabilityApplicability.LIKELY_APPLICABLE]
                            for m in matches
                        )
                        if is_conf:
                            n_confirmed += 1
                        else:
                            n_candidate += 1

                        # Calculate match classification metrics against ground truth
                        matched_ids = {m.vulnerability_id for m in matches}
                        tp_matches = matched_ids.intersection(gt_vuln_ids)
                        fp_matches = matched_ids.difference(gt_vuln_ids)

                        tp += len(tp_matches)
                        fp += len(fp_matches)
                        fn += len(gt_vuln_ids.difference(matched_ids))

                n_total = len(components)
                c_rate = n_confirmed / n_total
                cand_rate = n_candidate / n_total
                u_rate = n_unmatched / n_total

                prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
                rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

                rate_confirmed.append(c_rate)
                rate_candidate.append(cand_rate)
                rate_unmatched.append(u_rate)
                rate_precision.append(prec)
                rate_recall.append(rec)
                rate_fpr.append(fpr)

            run_records.append({
                "field_dropped": field,
                "perturbation_rate": rate,
                "confirmed_share_mean": round(float(np.mean(rate_confirmed)), 4),
                "confirmed_share_sd": round(float(np.std(rate_confirmed)), 4),
                "candidate_share_mean": round(float(np.mean(rate_candidate)), 4),
                "candidate_share_sd": round(float(np.std(rate_candidate)), 4),
                "unmatched_share_mean": round(float(np.mean(rate_unmatched)), 4),
                "unmatched_share_sd": round(float(np.std(rate_unmatched)), 4),
                "precision_mean": round(float(np.mean(rate_precision)), 4),
                "precision_sd": round(float(np.std(rate_precision)), 4),
                "recall_mean": round(float(np.mean(rate_recall)), 4),
                "recall_sd": round(float(np.std(rate_recall)), 4),
                "fpr_mean": round(float(np.mean(rate_fpr)), 4),
                "fpr_sd": round(float(np.std(rate_fpr)), 4),
            })

    df_results = pd.DataFrame(run_records)
    out_csv = RESULTS_DIR / "exp1_degradation_results.csv"
    df_results.to_csv(out_csv, index=False)
    print(f"[OK] Saved degradation curve metrics to {out_csv}")

    # Generate Degradation Figures
    plot_degradation_curves(df_results)

    # Part 2: Wild SBOM Sample Stratification
    run_wild_sbom_stratification()

def plot_degradation_curves(df: pd.DataFrame):
    """Generates publication-quality degradation plots for precision, recall, and match states."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5), dpi=300)

    # Left subplot: Precision and Recall under "all" fields dropped
    df_all = df[df["field_dropped"] == "all"]
    axes[0].errorbar(
        df_all["perturbation_rate"] * 100,
        df_all["precision_mean"] * 100,
        yerr=df_all["precision_sd"] * 100,
        fmt="-o", label="Precision (%)", color="#1f77b4", capsize=4
    )
    axes[0].errorbar(
        df_all["perturbation_rate"] * 100,
        df_all["recall_mean"] * 100,
        yerr=df_all["recall_sd"] * 100,
        fmt="-s", label="Recall (%)", color="#ff7f0e", capsize=4
    )
    axes[0].set_title("(A) Matching Performance vs. Metadata Loss (All Fields Dropped)", fontsize=11, fontweight="bold")
    axes[0].set_xlabel("Perturbation Rate (% Metadata Dropped)", fontsize=10)
    axes[0].set_ylabel("Metric (%)", fontsize=10)
    axes[0].set_ylim(-5, 105)
    axes[0].grid(True, linestyle="--", alpha=0.6)
    axes[0].legend(loc="lower left")

    # Right subplot: Match State Transitions (Confirmed vs Candidate vs Unmatched)
    axes[1].plot(
        df_all["perturbation_rate"] * 100,
        df_all["confirmed_share_mean"] * 100,
        "-o", label="Confirmed Applicable", color="#2ca02c"
    )
    axes[1].plot(
        df_all["perturbation_rate"] * 100,
        df_all["candidate_share_mean"] * 100,
        "--^", label="Candidate Match (Uncertain)", color="#d62728"
    )
    axes[1].plot(
        df_all["perturbation_rate"] * 100,
        df_all["unmatched_share_mean"] * 100,
        ":x", label="Unmatched", color="#7f7f7f"
    )
    axes[1].set_title("(B) State Transition Distribution (Curated Benchmark N=995)", fontsize=11, fontweight="bold")
    axes[1].set_xlabel("Perturbation Rate (% Metadata Dropped)", fontsize=10)
    axes[1].set_ylabel("Share of Components (%)", fontsize=10)
    axes[1].set_ylim(-5, 105)
    axes[1].grid(True, linestyle="--", alpha=0.6)
    axes[1].legend(loc="center left")

    plt.tight_layout()
    fig_path = FIGURES_DIR / "exp1_degradation_curve.png"
    plt.savefig(fig_path)
    plt.close()
    print(f"[OK] Generated degradation curve figure: {fig_path}")

def run_wild_sbom_stratification():
    """Performs stratified sampling of 800 Wild SBOMs across NTIA compliance score bands."""
    print("\n--- Stratified Sampling of Wild SBOMs (N=78,032, Zacchiroli et al. MSR 2025) ---")
    if not WILD_SBOMS_CSV.exists():
        print(f"[WARN] Wild SBOM file {WILD_SBOMS_CSV} not found. Skipping stratification.")
        return

    df_wild = pd.read_csv(WILD_SBOMS_CSV)
    df_valid = df_wild.dropna(subset=["score"]).copy()

    mean_score = df_valid["score"].mean()
    print(f"Total Valid Evaluated Wild SBOMs: {len(df_valid)}")
    print(f"Overall Population NTIA Compliance Score: Mean = {mean_score:.2f} (SD = {df_valid['score'].std():.2f})")

    # Stratify by score bands: [0-3], [4-6], [7-8], [9-10]
    bands = [
        ("0-3", (df_valid["score"] >= 0.0) & (df_valid["score"] < 4.0)),
        ("4-6", (df_valid["score"] >= 4.0) & (df_valid["score"] < 7.0)),
        ("7-8", (df_valid["score"] >= 7.0) & (df_valid["score"] < 9.0)),
        ("9-10", (df_valid["score"] >= 9.0) & (df_valid["score"] <= 10.0))
    ]

    sample_records = []
    band_summaries = []

    for band_name, condition in bands:
        sub = df_valid[condition]
        n_avail = len(sub)
        n_sample = min(200, n_avail)
        sampled = sub.sample(n=n_sample, random_state=42)
        sampled["ntia_band"] = band_name
        sample_records.append(sampled)

        std_dist = sampled["standard"].value_counts(normalize=True).to_dict()
        band_summaries.append({
            "ntia_band": band_name,
            "population_count": n_avail,
            "sampled_count": n_sample,
            "mean_score": round(float(sampled["score"].mean()), 2),
            "spdx_share": round(float(std_dist.get("spdx", 0.0)), 3),
            "cyclonedx_share": round(float(std_dist.get("cdx", 0.0)), 3)
        })
        print(f"Band '{band_name:5s}': Pop = {n_avail:5d} | Sampled = {n_sample:3d} | Mean Score = {sampled['score'].mean():.2f}")

    df_stratified = pd.concat(sample_records, ignore_index=True)
    out_strat_csv = RESULTS_DIR / "exp1_wild_stratified_sample.csv"
    df_stratified.to_csv(out_strat_csv, index=False)

    df_band_summary = pd.DataFrame(band_summaries)
    summary_csv = RESULTS_DIR / "exp1_wild_band_summary.csv"
    df_band_summary.to_csv(summary_csv, index=False)
    print(f"[OK] Saved stratified sample of {len(df_stratified)} Wild SBOMs to {out_strat_csv}")

if __name__ == "__main__":
    run_degradation_experiment()
