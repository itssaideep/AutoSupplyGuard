"""Vulnerability prioritisation algorithms: Baseline A, Baseline B, and Proposed Context-Aware Score."""

import math
from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from app.models.component import Component
from app.models.vulnerability import Vulnerability, VulnerabilityMatch
from app.models.enums import VulnerabilityApplicability, IdentityResolutionStatus
from app.traceability.graph import TraceabilityGraph

class PrioritisedVulnerabilityRecord(BaseModel):
    """Container for scored and ranked vulnerability findings."""
    match_id: str
    vulnerability_id: str
    component_id: str
    component_name: str
    component_version: Optional[str]
    cvss_score: float
    downstream_impact_count: int
    reachable_products: List[str]
    applicability: str
    identity_status: str
    baseline_a_score: float = Field(..., description="Severity-only CVSS base score")
    baseline_b_score: float = Field(..., description="Severity + Dependency logarithmic score")
    proposed_score: float = Field(..., description="AutoSupplyGuard Context & Evidence-Aware priority score (0.0 to 1.0)")
    ranking_rank_baseline_a: int = 0
    ranking_rank_baseline_b: int = 0
    ranking_rank_proposed: int = 0

class VulnerabilityPrioritiser:
    """Computes and compares Baseline A, Baseline B, and AutoSupplyGuard Context-Aware Prioritisation."""

    def __init__(
        self,
        graph: TraceabilityGraph,
        weight_severity: float = 0.4,
        weight_dependency: float = 0.3,
        weight_product: float = 0.3,
        norm_k: float = 10.0,
        freshness_threshold_days: int = 90
    ):
        self.graph = graph
        self.alpha = weight_severity
        self.beta = weight_dependency
        self.gamma = weight_product
        self.k = norm_k
        self.freshness_threshold_days = freshness_threshold_days

    def prioritise(
        self,
        matches: List[VulnerabilityMatch],
        components_by_id: Dict[str, Component],
        vulnerabilities_by_id: Dict[str, Vulnerability]
    ) -> List[PrioritisedVulnerabilityRecord]:
        """Calculates all three prioritisation scores for each match and assigns comparative ranks."""
        records: List[PrioritisedVulnerabilityRecord] = []

        for m in matches:
            comp = components_by_id.get(m.component_id)
            vuln = vulnerabilities_by_id.get(m.vulnerability_id)
            if not comp or not vuln:
                continue

            cvss = float(vuln.cvss_score) if vuln.cvss_score is not None else 5.0

            # Graph metrics:
            # Downstream impact is the count of nodes that depend on comp (ancestors in graph where parent -> child)
            upstream_dependents = self.graph.get_ancestors(comp.internal_id)
            downstream_impact_count = len([n for n in upstream_dependents if self.graph.graph.nodes[n].get("node_type") == "component"])
            reachable_products = self.graph.get_reachable_products(comp.internal_id)

            # 1. Baseline A: Severity-Only
            score_a = cvss

            # 2. Baseline B: Severity + Dependency (CVSS * (1 + log(1 + dependents)))
            score_b = cvss * (1.0 + math.log(1.0 + downstream_impact_count))

            # 3. Proposed Method: Context & Evidence-Aware Score
            score_proposed = self._calculate_proposed_score(
                cvss=cvss,
                downstream_count=downstream_impact_count,
                reachable_products_count=len(reachable_products),
                applicability=m.applicability,
                identity_status=comp.identity_status,
                retrieved_at=vuln.retrieved_at
            )

            record = PrioritisedVulnerabilityRecord(
                match_id=m.match_id,
                vulnerability_id=vuln.vulnerability_id,
                component_id=comp.internal_id,
                component_name=comp.name,
                component_version=comp.version,
                cvss_score=cvss,
                downstream_impact_count=downstream_impact_count,
                reachable_products=reachable_products,
                applicability=m.applicability.value,
                identity_status=comp.identity_status.value,
                baseline_a_score=round(score_a, 2),
                baseline_b_score=round(score_b, 3),
                proposed_score=round(score_proposed, 4)
            )
            records.append(record)

        # Calculate comparative ranks (1 is highest priority)
        # Rank Baseline A
        records.sort(key=lambda r: r.baseline_a_score, reverse=True)
        for i, r in enumerate(records, 1):
            r.ranking_rank_baseline_a = i

        # Rank Baseline B
        records.sort(key=lambda r: r.baseline_b_score, reverse=True)
        for i, r in enumerate(records, 1):
            r.ranking_rank_baseline_b = i

        # Rank Proposed
        records.sort(key=lambda r: r.proposed_score, reverse=True)
        for i, r in enumerate(records, 1):
            r.ranking_rank_proposed = i

        return records

    def _calculate_proposed_score(
        self,
        cvss: float,
        downstream_count: int,
        reachable_products_count: int,
        applicability: VulnerabilityApplicability,
        identity_status: IdentityResolutionStatus,
        retrieved_at: Optional[datetime]
    ) -> float:
        # Zero priority if confirmed remediated or not affected with evidence
        if applicability in {
            VulnerabilityApplicability.NOT_AFFECTED_WITH_EVIDENCE,
            VulnerabilityApplicability.FIXED_WITH_EVIDENCE
        }:
            return 0.0

        # Identity confidence multiplier
        conf_map = {
            IdentityResolutionStatus.RESOLVED_EXACT: 1.0,
            IdentityResolutionStatus.RESOLVED_PARTIAL: 0.75,
            IdentityResolutionStatus.AMBIGUOUS: 0.4,
            IdentityResolutionStatus.UNRESOLVED: 0.2
        }
        conf = conf_map.get(identity_status, 0.5)

        # Evidence freshness factor
        freshness = 1.0
        if retrieved_at:
            age_days = (datetime.utcnow() - retrieved_at).days
            if age_days > self.freshness_threshold_days:
                # Linear decay between 90 and 365 days from 1.0 down to 0.4
                freshness = max(0.4, 1.0 - 0.6 * ((age_days - 90) / 275))

        # Core context formula: (alpha * (CVSS/10) + beta * min(1, DID/K) + gamma * (1 if PR > 0 else 0))
        norm_cvss = cvss / 10.0
        norm_did = min(1.0, downstream_count / self.k)
        norm_pr = 1.0 if reachable_products_count > 0 else 0.0

        base_priority = (
            self.alpha * norm_cvss +
            self.beta * norm_did +
            self.gamma * norm_pr
        )

        # Downweight candidate matches with explicit uncertainty
        if applicability == VulnerabilityApplicability.CANDIDATE_MATCH:
            base_priority *= 0.5

        return base_priority * conf * freshness
