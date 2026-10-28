"""Unit tests for FastAPI REST endpoints."""

import pytest
from fastapi.testclient import TestClient
from app.api.main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_api_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "AutoSupplyGuard"

def test_api_list_vulnerabilities(client):
    resp = client.get("/vulnerabilities?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) <= 5

def test_api_list_relationships(client):
    resp = client.get("/relationships")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 5

def test_api_traceability_graph(client):
    resp = client.get("/traceability/graph")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data
    assert "metrics" in data

def test_api_assurance_endpoints(client):
    # Test claims
    resp_claims = client.get("/assurance/claims")
    assert resp_claims.status_code == 200
    claims = resp_claims.json()
    assert len(claims) >= 5

    # Test gaps
    resp_gaps = client.get("/assurance/gaps")
    assert resp_gaps.status_code == 200
    gaps = resp_gaps.json()
    assert isinstance(gaps, list)

def test_api_summary_report(client):
    resp = client.get("/reports/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["project"] == "AutoSupplyGuard"
    assert "total_sboms_ingested" in data
