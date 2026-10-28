"""Main FastAPI application entry point for AutoSupplyGuard."""

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Optional, Any
from app.core.config import settings
from app.api.state import state
from app.models.sbom import SBOM
from app.models.component import Component
from app.models.vulnerability import Vulnerability, VulnerabilityMatch
from app.models.relationship import CorporateRelationship
from app.models.assurance import AssuranceClaim, RegulatoryRequirement
from app.traceability.prioritisation import PrioritisedVulnerabilityRecord

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Evidence-Driven Cybersecurity Assurance for Multi-Tier Automotive Supply Chains (Volvo Group Context)",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. Health Endpoint
@app.get("/health", tags=["System"])
def get_health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "sboms_loaded": len(state.sboms),
        "components_loaded": len(state.components),
        "vulnerabilities_loaded": len(state.vulnerabilities),
        "graph_nodes": state.graph.graph.number_of_nodes(),
        "graph_edges": state.graph.graph.number_of_edges()
    }

# 2. SBOM Endpoints
@app.post("/sboms", tags=["SBOMs"])
async def upload_sbom(file: UploadFile = File(...)) -> Dict[str, Any]:
    try:
        content = await file.read()
        import json
        raw_data = json.loads(content.decode("utf-8"))
        report = state.ingest_sbom(raw_data, source_id=file.filename or "upload.json")
        return {"message": "SBOM ingested successfully", "report": report}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process SBOM: {str(e)}")

@app.get("/sboms", tags=["SBOMs"])
def list_sboms(skip: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500)) -> List[SBOM]:
    return list(state.sboms.values())[skip : skip + limit]

@app.get("/sboms/{sbom_id}", tags=["SBOMs"])
def get_sbom(sbom_id: str) -> SBOM:
    if sbom_id not in state.sboms:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return state.sboms[sbom_id]

@app.get("/sboms/{sbom_id}/quality", tags=["SBOMs"])
def get_sbom_quality(sbom_id: str) -> Dict[str, Any]:
    if sbom_id not in state.sboms:
        raise HTTPException(status_code=404, detail="SBOM not found")
    sbom = state.sboms[sbom_id]
    return {
        "sbom_id": sbom.internal_id,
        "format": sbom.format.value,
        "spec_version": sbom.spec_version,
        "quality_metrics": sbom.quality_metrics
    }

# 3. Component Endpoints
@app.get("/components", tags=["Components"])
def list_components(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    sbom_id: Optional[str] = None
) -> List[Component]:
    comps = list(state.components.values())
    if sbom_id:
        comps = [c for c in comps if c.source_sbom_id == sbom_id]
    return comps[skip : skip + limit]

@app.get("/components/{component_id}", tags=["Components"])
def get_component(component_id: str) -> Component:
    if component_id not in state.components:
        raise HTTPException(status_code=404, detail="Component not found")
    return state.components[component_id]

@app.get("/components/{component_id}/vulnerabilities", tags=["Components"])
def get_component_vulnerabilities(component_id: str) -> List[VulnerabilityMatch]:
    if component_id not in state.components:
        raise HTTPException(status_code=404, detail="Component not found")
    return [m for m in state.matches if m.component_id == component_id]

@app.get("/components/{component_id}/dependents", tags=["Components"])
def get_component_dependents(component_id: str) -> Dict[str, Any]:
    if component_id not in state.components:
        raise HTTPException(status_code=404, detail="Component not found")
    upstream = list(state.graph.get_ancestors(component_id))
    downstream = list(state.graph.get_descendants(component_id))
    reachable_products = state.graph.get_reachable_products(component_id)
    return {
        "component_id": component_id,
        "upstream_dependent_count": len(upstream),
        "upstream_dependents": upstream,
        "downstream_dependency_count": len(downstream),
        "downstream_dependencies": downstream,
        "reachable_vehicle_products": reachable_products
    }

# 4. Vulnerability Endpoints
@app.get("/vulnerabilities", tags=["Vulnerabilities"])
def list_vulnerabilities(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    min_cvss: Optional[float] = None
) -> List[Vulnerability]:
    vulns = list(state.vulnerabilities.values())
    if min_cvss is not None:
        vulns = [v for v in vulns if v.cvss_score and v.cvss_score >= min_cvss]
    return vulns[skip : skip + limit]

@app.get("/vulnerabilities/prioritised", tags=["Vulnerabilities"])
def get_prioritised_vulnerabilities() -> List[PrioritisedVulnerabilityRecord]:
    return state.prioritised_records

@app.get("/vulnerabilities/{vulnerability_id}", tags=["Vulnerabilities"])
def get_vulnerability(vulnerability_id: str) -> Vulnerability:
    vuln = state.vulnerabilities.get(vulnerability_id) or state.auto_feed.get_by_cve(vulnerability_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability record not found")
    return vuln

# 5. Relationship Endpoints
@app.get("/relationships", tags=["Corporate Relationships"])
def list_relationships(entity_id: Optional[str] = None) -> List[CorporateRelationship]:
    return state.supplier_manager.get_real_relationships(entity_id)

@app.post("/relationships", tags=["Corporate Relationships"])
def create_relationship(relationship: CorporateRelationship) -> CorporateRelationship:
    state.supplier_manager.real_relationships.append(relationship)
    return relationship

# 6. Traceability Graph Endpoints
@app.get("/traceability/graph", tags=["Traceability"])
def get_traceability_graph() -> Dict[str, Any]:
    return state.graph.to_dict()

@app.get("/traceability/products/{product_id}", tags=["Traceability"])
def get_product_traceability(product_id: str) -> Dict[str, Any]:
    if product_id not in state.graph.graph:
        raise HTTPException(status_code=404, detail="Product not found in traceability graph")
    descendants = list(state.graph.get_descendants(product_id))
    return {
        "product_id": product_id,
        "total_deployed_components": len(descendants),
        "component_ids": descendants
    }

# 7. Assurance Endpoints
@app.get("/assurance/requirements", tags=["Assurance"])
def list_requirements() -> List[RegulatoryRequirement]:
    return state.requirements

@app.get("/assurance/claims", tags=["Assurance"])
def list_assurance_claims() -> List[AssuranceClaim]:
    return state.claims

@app.get("/assurance/gaps", tags=["Assurance"])
def get_assurance_gaps() -> List[Dict[str, Any]]:
    eval_res = state.latest_evaluation or state.run_full_assurance_evaluation()
    return eval_res.gap_summary

# 8. Analysis & Reports
@app.post("/analysis/run", tags=["Analysis"])
def run_full_analysis() -> Dict[str, Any]:
    eval_res = state.run_full_assurance_evaluation()
    return {
        "status": "completed",
        "timestamp": eval_res.evaluated_at.isoformat(),
        "total_claims": eval_res.total_claims,
        "supported_claims": eval_res.supported_count,
        "insufficient_evidence_claims": eval_res.insufficient_evidence_count,
        "contradicted_claims": eval_res.contradicted_count,
        "false_assurance_rate": eval_res.false_assurance_rate,
        "gaps_detected": len(eval_res.gap_summary)
    }

@app.get("/reports/summary", tags=["Analysis"])
def get_executive_summary() -> Dict[str, Any]:
    confirmed = sum(1 for m in state.matches if m.applicability.value == "confirmed_applicable")
    candidates = sum(1 for m in state.matches if m.applicability.value == "candidate_match")
    unresolved_identities = sum(1 for c in state.components.values() if c.identity_status.value in {"unresolved", "ambiguous"})
    
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "total_sboms_ingested": len(state.sboms),
        "total_components": len(state.components),
        "unresolved_component_identities": unresolved_identities,
        "confirmed_applicable_vulnerabilities": confirmed,
        "candidate_matches_requiring_review": candidates,
        "traceability_nodes": state.graph.graph.number_of_nodes(),
        "traceability_edges": state.graph.graph.number_of_edges(),
        "assurance_gaps": len(state.latest_evaluation.gap_summary) if state.latest_evaluation else 0
    }
