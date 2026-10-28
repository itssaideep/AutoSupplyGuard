"""Unit tests for Real Documented Corporate Relationships and Synthetic Supply Chain Ecosystem (Milestone 6)."""

from app.traceability.supplier_graph import SupplierGraphManager
from app.models.enums import CorporateRelationshipType

def test_real_corporate_relationships():
    mgr = SupplierGraphManager()
    rels = mgr.get_real_relationships()
    assert len(rels) >= 5, f"Expected at least 5 real relationships, got {len(rels)}"

    # Check Volvo Group & NVIDIA
    vg_nvidia = next((r for r in rels if r.entity_a == "volvo-group" and r.entity_b == "nvidia"), None)
    assert vg_nvidia is not None
    assert vg_nvidia.relationship_type == CorporateRelationshipType.DEVELOPS_WITH
    assert "volvogroup.com" in vg_nvidia.source_url
    assert vg_nvidia.is_synthetic is False
    assert len(vg_nvidia.limitations) >= 1
    assert any("strictly to Volvo Group" in lim for lim in vg_nvidia.limitations)

    # Check Volvo Cars & NVIDIA
    vc_nvidia = next((r for r in rels if r.entity_a == "volvo-cars" and r.entity_b == "nvidia"), None)
    assert vc_nvidia is not None
    assert vc_nvidia.relationship_type == CorporateRelationshipType.INTEGRATES
    assert "volvocars.com" in vc_nvidia.source_url
    assert vc_nvidia.is_synthetic is False

    # Check Volvo Cars & Zenseact ownership
    vc_zenseact = next((r for r in rels if r.entity_a == "volvo-cars" and r.entity_b == "zenseact"), None)
    assert vc_zenseact is not None
    assert vc_zenseact.relationship_type == CorporateRelationshipType.OWNS

    # Critical Integrity Rule: Volvo Group and Volvo Cars must be separate
    # Ensure no relationship transfers Volvo Group to Zenseact or Volvo Cars to heavy trucks
    vg_zenseact = next((r for r in rels if r.entity_a == "volvo-group" and r.entity_b == "zenseact"), None)
    assert vg_zenseact is None, "Integrity violation: Volvo Group must not be linked to Zenseact without evidence"

def test_synthetic_supply_chain_fixture():
    mgr = SupplierGraphManager()
    entities = mgr.get_synthetic_entities()

    # Verify products
    products = entities["products"]
    assert len(products) == 2
    assert all(p.is_synthetic is True for p in products)

    # Verify components
    components = entities["components"]
    assert len(components) >= 5
    assert all(c.is_synthetic is True for c in components)

    # Verify dependencies
    dependencies = entities["dependencies"]
    assert len(dependencies) >= 3

    # Verify synthetic vulnerabilities
    vulns = entities["vulnerabilities"]
    assert len(vulns) >= 1
    synth_vuln = vulns[0]
    assert synth_vuln.vulnerability_id == "SYNTH-CVE-2024-0001"
    assert synth_vuln.is_synthetic is True

    # Verify evidence scenarios exist
    scenarios = entities["evidence_scenarios"]
    assert len(scenarios) == 5
    case_ids = {s["case_id"] for s in scenarios}
    assert "CASE-01-CLEAN-SUPPORTED" in case_ids
    assert "CASE-03-STALE-EVIDENCE" in case_ids
    assert "CASE-04-CONTRADICTION" in case_ids
