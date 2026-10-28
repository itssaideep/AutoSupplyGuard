"""Directed dependency and multi-tier traceability graph engine using NetworkX."""

from typing import Dict, List, Set, Optional, Any
import networkx as nx
from app.models.component import Component
from app.models.sbom import DependencyEdge
from app.models.product import Product
from app.ingestion.base import ParsedSBOMResult

class TraceabilityGraph:
    """Represents multi-tier software dependency and product composition graphs."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self._components_by_id: Dict[str, Component] = {}
        self._products_by_id: Dict[str, Product] = {}

    def add_component(self, component: Component):
        """Adds a component node to the graph."""
        self._components_by_id[component.internal_id] = component
        self.graph.add_node(
            component.internal_id,
            node_type="component",
            name=component.name,
            version=component.version,
            purl=component.purl,
            supplier=component.supplier,
            ecosystem=component.ecosystem,
            identity_status=component.identity_status.value,
            is_synthetic=component.is_synthetic
        )

    def add_product(self, product: Product):
        """Adds a product root node to the graph."""
        self._products_by_id[product.product_id] = product
        self.graph.add_node(
            product.product_id,
            node_type="product",
            name=product.name,
            version=product.version,
            category=product.category,
            confidence=product.confidence.value,
            is_synthetic=product.is_synthetic
        )
        for comp_id in product.related_component_ids:
            if comp_id in self.graph:
                self.link_product_to_component(product.product_id, comp_id)

    def add_dependency_edge(self, edge: DependencyEdge):
        """Adds a directed dependency edge (parent depends on child: parent -> child)."""
        self.graph.add_edge(
            edge.source_component_id,
            edge.target_component_id,
            relationship_type=edge.relationship_type,
            scope=edge.scope.value,
            is_transitive=edge.is_transitive
        )

    def add_sbom_result(self, parsed_result: ParsedSBOMResult, product_id: Optional[str] = None):
        """Ingests all components and dependency edges from a parsed SBOM."""
        for c in parsed_result.components:
            self.add_component(c)

        for d in parsed_result.dependencies:
            self.add_dependency_edge(d)

        if product_id and product_id in self.graph:
            # Link root or all components to product
            for c in parsed_result.components:
                # If component has no in-degree within the SBOM (root package), link product -> component
                in_degree = self.graph.in_degree(c.internal_id)
                if in_degree == 0:
                    self.link_product_to_component(product_id, c.internal_id)

    def link_product_to_component(self, product_id: str, component_id: str):
        """Creates an edge indicating that a product deploys or includes a component."""
        self.graph.add_edge(
            product_id,
            component_id,
            relationship_type="CONTAINS_COMPONENT",
            scope="direct",
            is_transitive=False
        )

    def get_descendants(self, node_id: str) -> Set[str]:
        """Returns all transitive downstream nodes that node_id depends on."""
        if node_id not in self.graph:
            return set()
        return nx.descendants(self.graph, node_id)

    def get_ancestors(self, node_id: str) -> Set[str]:
        """Returns all transitive upstream nodes that depend on node_id."""
        if node_id not in self.graph:
            return set()
        return nx.ancestors(self.graph, node_id)

    def get_reachable_products(self, component_id: str) -> List[str]:
        """Identifies which product nodes depend on this component."""
        ancestors = self.get_ancestors(component_id)
        reachable = []
        for anc in ancestors:
            if self.graph.nodes[anc].get("node_type") == "product":
                reachable.append(anc)
        return reachable

    def get_dependency_paths(self, source_id: str, target_id: str, max_paths: int = 5) -> List[List[str]]:
        """Returns all simple paths between source and target in the graph."""
        if source_id not in self.graph or target_id not in self.graph:
            return []
        try:
            paths = list(nx.all_simple_paths(self.graph, source_id, target_id, cutoff=10))
            return paths[:max_paths]
        except Exception:
            return []

    def detect_cycles(self) -> List[List[str]]:
        """Finds any circular dependency loops in the graph."""
        try:
            return list(nx.simple_cycles(self.graph))
        except Exception:
            return []

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Calculates graph structural metrics."""
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "product_count": len([n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "product"]),
            "component_count": len([n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "component"]),
            "is_dag": nx.is_directed_acyclic_graph(self.graph),
            "cycle_count": len(self.detect_cycles())
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serializes graph to JSON-friendly dictionary for visualization and API responses."""
        nodes_list = []
        for node_id, data in self.graph.nodes(data=True):
            nodes_list.append({"id": node_id, **data})

        edges_list = []
        for u, v, data in self.graph.edges(data=True):
            edges_list.append({"source": u, "target": v, **data})

        return {
            "nodes": nodes_list,
            "edges": edges_list,
            "metrics": self.get_metrics_summary()
        }
