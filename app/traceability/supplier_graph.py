"""Loader and manager for real corporate relationships and synthetic supply chain fixtures."""

import json
from pathlib import Path
from typing import List, Dict, Optional, Any
import networkx as nx
from app.models.relationship import CorporateRelationship
from app.models.component import Component
from app.models.product import Product
from app.models.vulnerability import Vulnerability
from app.models.sbom import DependencyEdge
from app.core.config import settings

DEFAULT_REAL_REL_PATH = settings.PROCESSED_DATA_DIR / "corporate_relationships.json"
DEFAULT_SYNTH_PATH = settings.SYNTHETIC_DIR / "synthetic_supply_chain.json"

class SupplierGraphManager:
    """Manages real public corporate evidence and synthetic multi-tier supplier ecosystems."""

    def __init__(self, real_rel_path: Optional[Path] = None, synth_path: Optional[Path] = None):
        self.real_rel_path = real_rel_path or DEFAULT_REAL_REL_PATH
        self.synth_path = synth_path or DEFAULT_SYNTH_PATH
        self.corp_graph = nx.DiGraph()
        self.real_relationships: List[CorporateRelationship] = []
        self.synthetic_data: Dict[str, Any] = {}
        self._load_data()

    def _load_data(self):
        # 1. Load real corporate relationships
        if self.real_rel_path.exists():
            with open(self.real_rel_path, "r", encoding="utf-8") as f:
                raw_rels = json.load(f)
                for r in raw_rels:
                    rel_obj = CorporateRelationship(**r)
                    self.real_relationships.append(rel_obj)
                    # Add to corporate knowledge graph
                    self.corp_graph.add_node(rel_obj.entity_a, is_synthetic=False)
                    self.corp_graph.add_node(rel_obj.entity_b, is_synthetic=False)
                    self.corp_graph.add_edge(
                        rel_obj.entity_a,
                        rel_obj.entity_b,
                        relationship_type=rel_obj.relationship_type.value,
                        scope=rel_obj.scope,
                        source_url=rel_obj.source_url,
                        confidence=rel_obj.confidence.value,
                        limitations=rel_obj.limitations,
                        is_synthetic=False
                    )

        # 2. Load synthetic fixture
        if self.synth_path.exists():
            with open(self.synth_path, "r", encoding="utf-8") as f:
                self.synthetic_data = json.load(f)
                for org in self.synthetic_data.get("organisations", []):
                    self.corp_graph.add_node(
                        org["organisation_id"],
                        name=org["name"],
                        canonical_name=org["canonical_name"],
                        organisation_type=org["organisation_type"],
                        is_synthetic=True
                    )

    def get_real_relationships(self, entity_id: Optional[str] = None) -> List[CorporateRelationship]:
        """Returns verified real corporate relationships, optionally filtered by organisation."""
        if not entity_id:
            return self.real_relationships
        clean = entity_id.lower().strip()
        return [
            r for r in self.real_relationships
            if r.entity_a.lower() == clean or r.entity_b.lower() == clean
        ]

    def get_synthetic_entities(self) -> Dict[str, List[Any]]:
        """Returns parsed synthetic components, products, vulnerabilities, and scenarios."""
        return {
            "products": [Product(**p) for p in self.synthetic_data.get("products", [])],
            "components": [Component(**c) for c in self.synthetic_data.get("components", [])],
            "dependencies": [DependencyEdge(**d) for d in self.synthetic_data.get("dependencies", [])],
            "vulnerabilities": [Vulnerability(**v) for v in self.synthetic_data.get("vulnerabilities", [])],
            "evidence_scenarios": self.synthetic_data.get("evidence_scenarios", [])
        }

    def export_corporate_graph_json(self) -> Dict[str, Any]:
        """Serializes the corporate graph into JSON format with distinct real vs synthetic tags."""
        nodes = []
        for n, d in self.corp_graph.nodes(data=True):
            nodes.append({"id": n, **d})
        edges = []
        for u, v, d in self.corp_graph.edges(data=True):
            edges.append({"source": u, "target": v, **d})
        return {"nodes": nodes, "edges": edges}
