"""Centralized in-memory state and application service layer for AutoSupplyGuard API."""

from typing import Dict, List, Optional, Any
from pathlib import Path
from app.models.sbom import SBOM, DependencyEdge
from app.models.component import Component
from app.models.vulnerability import Vulnerability, VulnerabilityMatch
from app.models.assurance import AssuranceClaim, RegulatoryRequirement
from app.models.evidence import EvidenceArtifact
from app.ingestion.manager import SBOMIngestionManager
from app.sbom_quality.calculator import QualityAssessmentEngine
from app.vulnerability.automotive_feed import AutomotiveVulnerabilityFeed
from app.vulnerability.matcher import VulnerabilityMatcher
from app.traceability.graph import TraceabilityGraph
from app.traceability.prioritisation import VulnerabilityPrioritiser, PrioritisedVulnerabilityRecord
from app.traceability.supplier_graph import SupplierGraphManager
from app.assurance.catalog import get_standard_claims, get_standard_requirements
from app.assurance.evaluator import AssuranceEngine, AssuranceEvaluationResult

class ApplicationState:
    """Singleton service managing in-memory repository, graphs, and evaluation state."""

    def __init__(self):
        self.ingestion_manager = SBOMIngestionManager()
        self.quality_engine = QualityAssessmentEngine()
        self.auto_feed = AutomotiveVulnerabilityFeed()
        self.supplier_manager = SupplierGraphManager()
        self.graph = TraceabilityGraph()
        self.assurance_engine = AssuranceEngine()

        # Repositories
        self.sboms: Dict[str, SBOM] = {}
        self.components: Dict[str, Component] = {}
        self.dependencies: List[DependencyEdge] = []
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.matches: List[VulnerabilityMatch] = []
        self.prioritised_records: List[PrioritisedVulnerabilityRecord] = []
        self.evidence_artifacts: List[EvidenceArtifact] = []
        self.claims: List[AssuranceClaim] = []
        self.requirements: List[RegulatoryRequirement] = []
        self.latest_evaluation: Optional[AssuranceEvaluationResult] = None

        self._initialize_baseline_data()

    def _initialize_baseline_data(self):
        """Loads baseline automotive CVEs, corporate relationships, and standard claims."""
        try:
            # 1. Load automotive vulnerability records
            vulns = self.auto_feed.load()
            self.vulnerabilities.update(vulns)
        except Exception:
            pass

        # 2. Load standard regulatory requirements and claims
        self.requirements = get_standard_requirements()
        self.claims = get_standard_claims("VOLVO-FH-ELECTRIC-TCU")

        # 3. Load synthetic fixture entities
        synth_entities = self.supplier_manager.get_synthetic_entities()
        for p in synth_entities.get("products", []):
            self.graph.add_product(p)
        for c in synth_entities.get("components", []):
            self.components[c.internal_id] = c
            self.graph.add_component(c)
        for d in synth_entities.get("dependencies", []):
            self.dependencies.append(d)
            self.graph.add_dependency_edge(d)
        for v in synth_entities.get("vulnerabilities", []):
            self.vulnerabilities[v.vulnerability_id] = v

    def ingest_sbom(self, file_path_or_dict, source_id: str = "upload") -> Dict[str, Any]:
        """Ingests an SBOM file or dict, computes quality metrics, and updates the graph."""
        if isinstance(file_path_or_dict, (str, Path)):
            result = self.ingestion_manager.parse_file(file_path_or_dict)
        else:
            result = self.ingestion_manager.parse_dict(file_path_or_dict, source_identifier=source_id)

        # Assess quality
        self.quality_engine.assess(result)

        # Store entities
        self.sboms[result.sbom.internal_id] = result.sbom
        for c in result.components:
            self.components[c.internal_id] = c
        self.dependencies.extend(result.dependencies)

        # Update dependency graph
        self.graph.add_sbom_result(result)

        # Run vulnerability matching on newly ingested components
        matcher = VulnerabilityMatcher(list(self.vulnerabilities.values()))
        new_matches = []
        for c in result.components:
            m = matcher.correlate_component(c)
            new_matches.extend(m)
        self.matches.extend(new_matches)

        # Re-run prioritisation
        prioritiser = VulnerabilityPrioritiser(self.graph)
        self.prioritised_records = prioritiser.prioritise(
            matches=self.matches,
            components_by_id=self.components,
            vulnerabilities_by_id=self.vulnerabilities
        )

        return self.quality_engine.generate_report(result)

    def run_full_assurance_evaluation(self) -> AssuranceEvaluationResult:
        """Executes the AssuranceEngine across all claims, evidence, components, and matches."""
        eval_result = self.assurance_engine.evaluate_claims(
            claims=self.claims,
            evidence_artifacts=self.evidence_artifacts,
            components=list(self.components.values()),
            vulnerability_matches=self.matches
        )
        self.latest_evaluation = eval_result
        return eval_result

state = ApplicationState()
