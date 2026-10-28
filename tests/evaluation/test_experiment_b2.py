"""Test suite for Experiment B2: Factorial Assurance Corpus Verification (Milestone 8 / RQ3)."""

import pandas as pd
from pathlib import Path
from scripts.run_experiment_b2 import (
    build_factorial_corpus,
    compute_cohens_kappa,
    wilson_score_interval,
    run_experiment_b2
)

def test_factorial_corpus_exact_size():
    """Verify that the B2 factorial corpus contains exactly N=98 cases meeting the sample specification."""
    corpus = build_factorial_corpus()
    assert len(corpus) == 98

    # 2 claim types
    types = {c["claim_type"] for c in corpus}
    assert types == {"VULN_SCAN", "SECURE_BOOT"}

    # 49 cases per claim type
    vuln_cases = [c for c in corpus if c["claim_type"] == "VULN_SCAN"]
    boot_cases = [c for c in corpus if c["claim_type"] == "SECURE_BOOT"]
    assert len(vuln_cases) == 49
    assert len(boot_cases) == 49

def test_inter_rater_reliability_kappa():
    """Verify inter-rater reliability between primary and secondary annotators (Cohen's kappa)."""
    labels_a = ["supported", "contradicted", "insufficient_evidence", "supported"]
    labels_b = ["supported", "contradicted", "insufficient_evidence", "supported"]
    kappa = compute_cohens_kappa(labels_a, labels_b)
    assert kappa == 1.0

def test_wilson_score_interval_upper_bound_zero_errors():
    """Verify Wilson 95% score interval for 0 errors in N=98 yields upper bound of ~3.76% (3.8%)."""
    center, lo, hi = wilson_score_interval(0, 98)
    assert center == 0.0
    assert lo == 0.0
    assert round(hi, 3) == 0.038  # 3.76% rounds to 3.8%

def test_experiment_b2_zero_false_assurance_and_perfect_accuracy():
    """Verify that AutoSupplyGuard achieves 100% accuracy and 0 false assurances (FAR=0.0%) on N=98."""
    run_experiment_b2()
    results_path = Path("research/results/exp3_assurance_cases.csv")
    assert results_path.exists()

    df = pd.read_csv(results_path)
    assert len(df) == 98

    # AutoSupplyGuard predictions must match ground truth exactly across all N=98 cases
    mismatches = df[df["asg_status"] != df["ground_truth"]]
    assert len(mismatches) == 0, f"Found {len(mismatches)} mismatches: {mismatches[['case_id', 'ground_truth', 'asg_status']]}"

    # False positives (FAR) must be strictly 0
    fp = ((df["asg_status"] == "supported") & (df["ground_truth"] != "supported")).sum()
    assert fp == 0
