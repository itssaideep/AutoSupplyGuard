"""Experiment 2: Dependency Impact & Context-Aware Prioritisation (RQ2)."""

import argparse
from pathlib import Path
import pandas as pd
from app.traceability.graph import TraceabilityGraph
from app.traceability.prioritisation import VulnerabilityPrioritiser
from app.models.component import Component
from app.models.product import Product
from app.models.vulnerability import Vulnerability, VulnerabilityMatch
from app.models.sbom import DependencyEdge
from app.models.enums import (
    IdentityResolutionStatus,
    VulnerabilityApplicability,
    VulnerabilityMatchMethod,
    ConfidenceCategory,
    DependencyScope
)

RESULTS_DIR = Path("research/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def run_experiment_2(smoke: bool = False):
    print("=== Running Experiment 2: Dependency Impact Prioritisation (RQ2) ===")
    graph = TraceabilityGraph()

    # Define Automotive Platform & Subsystems
    p_fm = Product(
        product_id="VOLVO-FM-AUTONOMOUS-GATEWAY",
        name="Volvo FM Autonomous Gateway ECU",
        category="Telematics/Gateway",
        supporting_source="Volvo Group Commercial Vehicle Telematics Specs"
    )
    p_fh = Product(
        product_id="VOLVO-FH-ELECTRIC-TCU",
        name="Volvo FH Electric Telematics Control Unit",
        category="Telematics/Gateway",
        supporting_source="Volvo Group Heavy Vehicle Electronics Specs"
    )
    graph.add_product(p_fm)
    graph.add_product(p_fh)

    # Define Components in the stack
    c_shared_crypto = Component(internal_id="c-openssl", name="openssl", version="1.1.1t", purl="pkg:generic/openssl@1.1.1t", source_sbom_id="s1", original_id="openssl-1.1.1t", identity_status=IdentityResolutionStatus.RESOLVED_EXACT)
    c_telematics_net = Component(internal_id="c-curl", name="libcurl", version="7.88.1", purl="pkg:generic/libcurl@7.88.1", source_sbom_id="s1", original_id="curl-7.88.1", identity_status=IdentityResolutionStatus.RESOLVED_EXACT)
    c_diag_parser = Component(internal_id="c-zlib", name="zlib", version="1.2.13", purl="pkg:generic/zlib@1.2.13", source_sbom_id="s1", original_id="zlib-1.2.13", identity_status=IdentityResolutionStatus.RESOLVED_EXACT)
    c_isolated_tool1 = Component(internal_id="c-isolated-tool-1", name="log-parser-tool", version="0.9", purl="pkg:pypi/log-parser-tool@0.9", source_sbom_id="s2", original_id="log-parser-0.9", identity_status=IdentityResolutionStatus.RESOLVED_EXACT)
    c_isolated_tool2 = Component(internal_id="c-isolated-tool-2", name="benchmark-mock", version="1.0", purl="pkg:npm/benchmark-mock@1.0", source_sbom_id="s2", original_id="benchmark-mock-1.0", identity_status=IdentityResolutionStatus.RESOLVED_EXACT)
    c_fixed_lib = Component(internal_id="c-fixed-lib", name="securesocket", version="2.0.0", purl="pkg:generic/securesocket@2.0.0", source_sbom_id="s1", original_id="securesocket-2.0.0", identity_status=IdentityResolutionStatus.RESOLVED_EXACT)

    components = [c_shared_crypto, c_telematics_net, c_diag_parser, c_isolated_tool1, c_isolated_tool2, c_fixed_lib]
    for c in components:
        graph.add_component(c)

    # Associate deployed components with vehicle ECU products
    graph.link_product_to_component("VOLVO-FM-AUTONOMOUS-GATEWAY", "c-openssl")
    graph.link_product_to_component("VOLVO-FM-AUTONOMOUS-GATEWAY", "c-curl")
    graph.link_product_to_component("VOLVO-FM-AUTONOMOUS-GATEWAY", "c-zlib")
    graph.link_product_to_component("VOLVO-FH-ELECTRIC-TCU", "c-openssl")
    graph.link_product_to_component("VOLVO-FH-ELECTRIC-TCU", "c-curl")
    graph.link_product_to_component("VOLVO-FH-ELECTRIC-TCU", "c-zlib")

    # Directed dependencies: libcurl depends on openssl and zlib; FM gateway depends on curl
    graph.add_dependency_edge(DependencyEdge(source_component_id="c-curl", target_component_id="c-openssl", scope=DependencyScope.RUNTIME))
    graph.add_dependency_edge(DependencyEdge(source_component_id="c-curl", target_component_id="c-zlib", scope=DependencyScope.RUNTIME))

    # Simulated Vulnerabilities
    v_crypto = Vulnerability(vulnerability_id="CVE-2023-CRYPTO-SHARED", source="AUTOMOTIVE_FEED", description="Buffer overflow in ASN.1 parser in OpenSSL", cvss_score=6.5, affected_ranges=["< 1.1.1u"], fixed_versions=["1.1.1u"])
    v_net = Vulnerability(vulnerability_id="CVE-2023-CURL-HIGH", source="AUTOMOTIVE_FEED", description="Remote code execution in curl SOCKS5 proxy handshake", cvss_score=7.8, affected_ranges=["< 8.4.0"], fixed_versions=["8.4.0"])
    v_iso_crit = Vulnerability(vulnerability_id="CVE-2023-ISOLATED-CRITICAL", source="NVD", description="Arbitrary code execution in dev log parser", cvss_score=9.8, affected_ranges=["< 1.0"])
    v_iso_high = Vulnerability(vulnerability_id="CVE-2023-ISOLATED-HIGH", source="NVD", description="Denial of service in benchmark utility", cvss_score=8.5, affected_ranges=["< 2.0"])
    v_zlib = Vulnerability(vulnerability_id="CVE-2023-ZLIB-MEDIUM", source="AUTOMOTIVE_FEED", description="Memory corruption in inflate function", cvss_score=5.3, affected_ranges=["< 1.2.14"])
    v_remediated = Vulnerability(vulnerability_id="CVE-2023-FIXED-REMEDIATED", source="VENDOR_ADVISORY", description="Flaw in securesocket remediated via VEX", cvss_score=9.0, affected_ranges=["< 1.5"], fixed_versions=["1.5.0", "2.0.0"])

    test_vulns = [v_crypto, v_net, v_iso_crit, v_iso_high, v_zlib, v_remediated]

    matches = [
        VulnerabilityMatch(match_id="m1", vulnerability_id="CVE-2023-CRYPTO-SHARED", component_id="c-openssl", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Affected 1.1.1t satisfies < 1.1.1u", supporting_evidence=["Affected OpenSSL 1.1.1t"]),
        VulnerabilityMatch(match_id="m2", vulnerability_id="CVE-2023-CURL-HIGH", component_id="c-curl", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Affected 7.88.1 satisfies < 8.4.0", supporting_evidence=["Affected libcurl 7.88.1"]),
        VulnerabilityMatch(match_id="m3", vulnerability_id="CVE-2023-ISOLATED-CRITICAL", component_id="c-isolated-tool-1", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Affected 0.9 satisfies < 1.0", supporting_evidence=["Affected log-parser 0.9"]),
        VulnerabilityMatch(match_id="m4", vulnerability_id="CVE-2023-ISOLATED-HIGH", component_id="c-isolated-tool-2", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Affected 1.0 satisfies < 2.0", supporting_evidence=["Affected benchmark-mock 1.0"]),
        VulnerabilityMatch(match_id="m5", vulnerability_id="CVE-2023-ZLIB-MEDIUM", component_id="c-zlib", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Affected 1.2.13 satisfies < 1.2.14", supporting_evidence=["Affected zlib 1.2.13"]),
        VulnerabilityMatch(match_id="m6", vulnerability_id="CVE-2023-FIXED-REMEDIATED", component_id="c-fixed-lib", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.FIXED_WITH_EVIDENCE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Fixed in 2.0.0", supporting_evidence=["VEX confirms patched in 2.0.0"])
    ]

    prioritiser = VulnerabilityPrioritiser(graph)
    records = prioritiser.prioritise(
        matches=matches,
        components_by_id={c.internal_id: c for c in components},
        vulnerabilities_by_id={v.vulnerability_id: v for v in test_vulns}
    )

    df = pd.DataFrame([r.model_dump() for r in records])
    output_csv = RESULTS_DIR / ("experiment_2_smoke.csv" if smoke else "experiment_2_results.csv")
    df.to_csv(output_csv, index=False)

    print(f"[OK] Experiment 2 completed across {len(records)} test vulnerabilities.")
    print("Comparative Rankings:")
    for r in records:
        print(f" - {r.vulnerability_id} ({r.component_name}): BaseA_Rank={r.ranking_rank_baseline_a} (CVSS {r.cvss_score}) -> Proposed_Rank={r.ranking_rank_proposed} (Score {r.proposed_score}) [Dependents={r.downstream_impact_count}, Products={len(r.reachable_products)}]")
    print(f"Saved raw results to {output_csv}")

def main():
    parser = argparse.ArgumentParser(description="Run Experiment 2 (RQ2).")
    parser.add_argument("--smoke", action="store_true", help="Run in smoke test mode.")
    args = parser.parse_args()
    run_experiment_2(smoke=args.smoke)

if __name__ == '__main__':
    main()
