import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import json
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

def run_experiment_2():
    print("=== Running Experiment 2: Dependency Impact Prioritisation (RQ2) ===")
    graph = TraceabilityGraph()
    
    # Define Automotive Platform & Subsystems
    products = [
        Product(product_id="VOLVO-FH-ELECTRIC-TCU", name="Volvo FH Heavy Truck TCU", version="2.4", supporting_source="Volvo Tech Docs"),
        Product(product_id="VOLVO-FM-AUTONOMOUS-GATEWAY", name="Volvo FM Autonomous Gateway", version="1.1", supporting_source="Volvo Tech Docs")
    ]
    for p in products:
        graph.add_product(p)
    
    # 10 Components spanning root services, shared crypto middleware, and isolated test utilities
    components = [
        Component(internal_id="c-tcu-daemon", name="tcu-daemon", version="2.4.0", source_sbom_id="s1", original_id="c1", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-gateway-core", name="gateway-core", version="1.1.0", source_sbom_id="s1", original_id="c2", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-curl", name="libcurl", version="7.88.1", source_sbom_id="s1", original_id="c3", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-openssl", name="openssl", version="1.1.1t", source_sbom_id="s1", original_id="c4", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-zlib", name="zlib", version="1.2.13", source_sbom_id="s1", original_id="c5", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-paho-mqtt", name="paho-mqtt", version="1.3.12", source_sbom_id="s1", original_id="c6", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-isolated-tool-1", name="log-parser-tool", version="0.9", source_sbom_id="s2", original_id="c7", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-isolated-tool-2", name="benchmark-mock", version="1.0", source_sbom_id="s2", original_id="c8", identity_status=IdentityResolutionStatus.RESOLVED_EXACT),
        Component(internal_id="c-unversioned-helper", name="can-helper", version=None, source_sbom_id="s1", original_id="c9", identity_status=IdentityResolutionStatus.UNRESOLVED),
        Component(internal_id="c-fixed-lib", name="securesocket", version="2.0.0", source_sbom_id="s1", original_id="c10", identity_status=IdentityResolutionStatus.RESOLVED_EXACT)
    ]
    for c in components:
        graph.add_component(c)
        
    # Product linkages
    graph.link_product_to_component("VOLVO-FH-ELECTRIC-TCU", "c-tcu-daemon")
    graph.link_product_to_component("VOLVO-FM-AUTONOMOUS-GATEWAY", "c-gateway-core")
    
    # Dependency edges
    edges = [
        DependencyEdge(source_component_id="c-tcu-daemon", target_component_id="c-curl"),
        DependencyEdge(source_component_id="c-gateway-core", target_component_id="c-curl"),
        DependencyEdge(source_component_id="c-curl", target_component_id="c-openssl"),
        DependencyEdge(source_component_id="c-curl", target_component_id="c-zlib"),
        DependencyEdge(source_component_id="c-tcu-daemon", target_component_id="c-paho-mqtt"),
        DependencyEdge(source_component_id="c-paho-mqtt", target_component_id="c-openssl")
    ]
    for e in edges:
        graph.add_dependency_edge(e)
    
    # Injected Vulnerabilities across the stack
    test_vulns = [
        Vulnerability(vulnerability_id="CVE-2023-CRYPTO-SHARED", source="NVD", cvss_score=6.5, affected_packages=["openssl"]),
        Vulnerability(vulnerability_id="CVE-2023-CURL-HIGH", source="NVD", cvss_score=7.8, affected_packages=["libcurl"]),
        Vulnerability(vulnerability_id="CVE-2023-ISOLATED-CRITICAL", source="NVD", cvss_score=9.8, affected_packages=["log-parser-tool"]),
        Vulnerability(vulnerability_id="CVE-2023-ISOLATED-HIGH", source="NVD", cvss_score=8.5, affected_packages=["benchmark-mock"]),
        Vulnerability(vulnerability_id="CVE-2023-ZLIB-MEDIUM", source="NVD", cvss_score=5.3, affected_packages=["zlib"]),
        Vulnerability(vulnerability_id="CVE-2023-FIXED-REMEDIATED", source="NVD", cvss_score=9.0, affected_packages=["securesocket"], fixed_versions=["2.0.0"])
    ]
    
    matches = [
        VulnerabilityMatch(match_id="m1", component_id="c-openssl", vulnerability_id="CVE-2023-CRYPTO-SHARED", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Applicable"),
        VulnerabilityMatch(match_id="m2", component_id="c-curl", vulnerability_id="CVE-2023-CURL-HIGH", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Applicable"),
        VulnerabilityMatch(match_id="m3", component_id="c-isolated-tool-1", vulnerability_id="CVE-2023-ISOLATED-CRITICAL", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Applicable"),
        VulnerabilityMatch(match_id="m4", component_id="c-isolated-tool-2", vulnerability_id="CVE-2023-ISOLATED-HIGH", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Applicable"),
        VulnerabilityMatch(match_id="m5", component_id="c-zlib", vulnerability_id="CVE-2023-ZLIB-MEDIUM", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Applicable"),
        VulnerabilityMatch(match_id="m6", component_id="c-fixed-lib", vulnerability_id="CVE-2023-FIXED-REMEDIATED", matching_method=VulnerabilityMatchMethod.EXACT_PURL, applicability=VulnerabilityApplicability.FIXED_WITH_EVIDENCE, confidence=ConfidenceCategory.HIGH, version_constraint_result="Remediated")
    ]
    
    prioritiser = VulnerabilityPrioritiser(graph)
    records = prioritiser.prioritise(
        matches=matches,
        components_by_id={c.internal_id: c for c in components},
        vulnerabilities_by_id={v.vulnerability_id: v for v in test_vulns}
    )
    
    df = pd.DataFrame([r.model_dump() for r in records])
    output_csv = RESULTS_DIR / "experiment_2_results.csv"
    df.to_csv(output_csv, index=False)
    
    print(f"[OK] Experiment 2 completed across {len(records)} test vulnerabilities.")
    print("Comparative Rankings:")
    for r in records:
        print(f" - {r.vulnerability_id} ({r.component_name}): BaseA_Rank={r.ranking_rank_baseline_a} (CVSS {r.cvss_score}) -> Proposed_Rank={r.ranking_rank_proposed} (Score {r.proposed_score}) [Dependents={r.downstream_impact_count}, Products={len(r.reachable_products)}]")
    print(f"Saved raw results to {output_csv}")

if __name__ == '__main__':
    run_experiment_2()
