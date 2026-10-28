"""Unit tests for Dependency Graph traversal and Baseline vs Proposed Vulnerability Prioritisation (RQ2)."""

import pytest
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
from app.traceability.graph import TraceabilityGraph
from app.traceability.prioritisation import VulnerabilityPrioritiser

def test_traceability_graph_traversal():
    graph = TraceabilityGraph()
    
    # 1. Product: Volvo Truck Connectivity Gateway
    product = Product(
        product_id="VOLVO-TCU-GEN4",
        name="Telematics Control Unit Gen 4",
        version="v4.2.0",
        supporting_source="Volvo Group Technical Disclosures"
    )
    graph.add_product(product)
    
    # 2. Components: Gateway App -> Curl -> OpenSSL
    comp_gw = Component(
        internal_id="comp-gw",
        name="tcu-gateway-daemon",
        version="4.2.0",
        source_sbom_id="sbom-1",
        original_id="gw-1",
        identity_status=IdentityResolutionStatus.RESOLVED_EXACT
    )
    comp_curl = Component(
        internal_id="comp-curl",
        name="libcurl",
        version="7.88.1",
        source_sbom_id="sbom-1",
        original_id="curl-1",
        identity_status=IdentityResolutionStatus.RESOLVED_EXACT
    )
    comp_crypto = Component(
        internal_id="comp-crypto",
        name="openssl",
        version="1.1.1t",
        source_sbom_id="sbom-1",
        original_id="crypto-1",
        identity_status=IdentityResolutionStatus.RESOLVED_EXACT
    )
    
    for c in [comp_gw, comp_curl, comp_crypto]:
        graph.add_component(c)
        
    # Link Product -> Gateway App
    graph.link_product_to_component("VOLVO-TCU-GEN4", "comp-gw")
    
    # Gateway App -> Curl -> OpenSSL
    graph.add_dependency_edge(DependencyEdge(
        source_component_id="comp-gw",
        target_component_id="comp-curl",
        scope=DependencyScope.RUNTIME
    ))
    graph.add_dependency_edge(DependencyEdge(
        source_component_id="comp-curl",
        target_component_id="comp-crypto",
        scope=DependencyScope.RUNTIME
    ))
    
    # Verify graph ancestry
    crypto_ancestors = graph.get_ancestors("comp-crypto")
    assert "comp-curl" in crypto_ancestors
    assert "comp-gw" in crypto_ancestors
    assert "VOLVO-TCU-GEN4" in crypto_ancestors
    
    # Verify reachable products
    reachable = graph.get_reachable_products("comp-crypto")
    assert reachable == ["VOLVO-TCU-GEN4"]
    
    # Verify paths
    paths = graph.get_dependency_paths("VOLVO-TCU-GEN4", "comp-crypto")
    assert len(paths) == 1
    assert paths[0] == ["VOLVO-TCU-GEN4", "comp-gw", "comp-curl", "comp-crypto"]

def test_prioritisation_context_elevation_over_severity_only():
    """
    RQ2 Validation Test:
    Demonstrates that severity-only prioritisation misses downstream security impact,
    whereas AutoSupplyGuard Proposed Method correctly elevates a moderate vulnerability
    in a core shared library reaching the vehicle product over an isolated high-CVSS leaf.
    """
    graph = TraceabilityGraph()
    
    # Add Product
    prod = Product(
        product_id="VOLVO-TRUCK-COCKPIT",
        name="Volvo Truck Digital Cockpit",
        version="1.0",
        supporting_source="Volvo Tech Specifications"
    )
    graph.add_product(prod)
    
    # Comp 1: Deeply embedded crypto library (OpenSSL) connected to vehicle cockpit
    comp_crypto = Component(
        internal_id="comp-shared-crypto",
        name="openssl",
        version="1.1.1t",
        source_sbom_id="sbom-1",
        original_id="crypto",
        identity_status=IdentityResolutionStatus.RESOLVED_EXACT
    )
    comp_app = Component(
        internal_id="comp-ui-app",
        name="infotainment-ui",
        version="2.0",
        source_sbom_id="sbom-1",
        original_id="ui",
        identity_status=IdentityResolutionStatus.RESOLVED_EXACT
    )
    
    # Comp 2: Isolated test tool with zero vehicle product links
    comp_isolated = Component(
        internal_id="comp-isolated-test-tool",
        name="test-mock-runner",
        version="1.0",
        source_sbom_id="sbom-2",
        original_id="mock",
        identity_status=IdentityResolutionStatus.RESOLVED_EXACT
    )
    
    for c in [comp_crypto, comp_app, comp_isolated]:
        graph.add_component(c)
        
    # Link: Product -> Infotainment -> Crypto
    graph.link_product_to_component("VOLVO-TRUCK-COCKPIT", "comp-ui-app")
    graph.add_dependency_edge(DependencyEdge(
        source_component_id="comp-ui-app",
        target_component_id="comp-shared-crypto"
    ))
    # Note: comp-isolated has no product links and no downstream dependents
    
    # Vulnerability A (Moderate CVSS 6.5 in OpenSSL reaching vehicle cockpit)
    vuln_crypto = Vulnerability(
        vulnerability_id="CVE-2023-MODERATE-CRYPTO",
        source="NVD",
        cvss_score=6.5,
        affected_packages=["openssl"]
    )
    
    # Vulnerability B (Critical CVSS 9.8 in isolated test runner)
    vuln_isolated = Vulnerability(
        vulnerability_id="CVE-2023-CRITICAL-ISOLATED",
        source="NVD",
        cvss_score=9.8,
        affected_packages=["test-mock-runner"]
    )
    
    match_crypto = VulnerabilityMatch(
        match_id="m1",
        component_id="comp-shared-crypto",
        vulnerability_id="CVE-2023-MODERATE-CRYPTO",
        matching_method=VulnerabilityMatchMethod.ECOSYSTEM_NAME_VERSION,
        applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE,
        confidence=ConfidenceCategory.HIGH,
        version_constraint_result="Satisfied"
    )
    
    match_isolated = VulnerabilityMatch(
        match_id="m2",
        component_id="comp-isolated-test-tool",
        vulnerability_id="CVE-2023-CRITICAL-ISOLATED",
        matching_method=VulnerabilityMatchMethod.ECOSYSTEM_NAME_VERSION,
        applicability=VulnerabilityApplicability.CONFIRMED_APPLICABLE,
        confidence=ConfidenceCategory.HIGH,
        version_constraint_result="Satisfied"
    )
    
    prioritiser = VulnerabilityPrioritiser(graph)
    records = prioritiser.prioritise(
        matches=[match_crypto, match_isolated],
        components_by_id={
            "comp-shared-crypto": comp_crypto,
            "comp-ui-app": comp_app,
            "comp-isolated-test-tool": comp_isolated
        },
        vulnerabilities_by_id={
            "CVE-2023-MODERATE-CRYPTO": vuln_crypto,
            "CVE-2023-CRITICAL-ISOLATED": vuln_isolated
        }
    )
    
    assert len(records) == 2
    rec_crypto = next(r for r in records if r.vulnerability_id == "CVE-2023-MODERATE-CRYPTO")
    rec_isolated = next(r for r in records if r.vulnerability_id == "CVE-2023-CRITICAL-ISOLATED")
    
    # Baseline A (Severity-Only): Isolated critical flaw ranks #1, Crypto flaw ranks #2
    assert rec_isolated.baseline_a_score > rec_crypto.baseline_a_score
    assert rec_isolated.ranking_rank_baseline_a == 1
    assert rec_crypto.ranking_rank_baseline_a == 2
    
    # Proposed Context-Aware Method:
    # Crypto flaw has downstream impact count > 0 and reachable product "VOLVO-TRUCK-COCKPIT",
    # whereas isolated tool has 0 product links and 0 dependents.
    # Therefore, Proposed Method elevates Crypto flaw to rank #1!
    assert rec_crypto.proposed_score > rec_isolated.proposed_score
    assert rec_crypto.ranking_rank_proposed == 1
    assert rec_isolated.ranking_rank_proposed == 2
