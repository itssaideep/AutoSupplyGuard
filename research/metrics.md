# AutoSupplyGuard — Metric Definitions & Mathematical Formulations

This document establishes the exact, unambiguous definitions, numerators, denominators, and interpretations for all metrics across AutoSupplyGuard.

---

## 1. Layer 2: SBOM Quality Metrics

Let an SBOM document $S = (C, D)$ consist of a set of components $C = \{c_1, c_2, \dots, c_n\}$ and a set of directed dependency relations $D \subseteq C \times C$.

### 1.1 Field Completeness ($M_{\text{comp}}$)
Measures the proportion of components in an SBOM that contain all mandatory security-relevant identity attributes (Name, Version, and at least one Package Identifier like PURL or CPE).
$$\text{Completeness}(S) = \frac{\sum_{c \in C} \mathbf{1}_{\{\text{Name}(c) \neq \emptyset \land \text{Version}(c) \neq \emptyset \land (\text{PURL}(c) \neq \emptyset \lor \text{CPE}(c) \neq \emptyset)\}}}{|C|}$$
- **Numerator:** Count of components possessing Name, Version, and either PURL or CPE.
- **Denominator:** Total component count $|C|$ in the SBOM.
- **Range:** $[0.0, 1.0]$. Higher is better.

### 1.2 Package Identifier Usability ($M_{\text{purl}}$)
$$\text{PURL\_Rate}(S) = \frac{\sum_{c \in C} \mathbf{1}_{\{\text{PURL}(c) \neq \emptyset \land \text{IsValidPURL}(\text{PURL}(c))\}}}{|C|}$$
- **Numerator:** Components with valid, parsable Package URLs.
- **Denominator:** Total component count $|C|$.

### 1.3 Dependency Resolution Rate ($M_{\text{dep}}$)
Measures whether declared dependency references point to actual identified components within the document.
$$\text{Dep\_Resolution}(S) = \frac{|\{(u, v) \in D : u \in C \land v \in C\}|}{|D|}$$
- **Numerator:** Valid edges where both source and target exist in $C$.
- **Denominator:** Total declared dependency edges $|D|$ (returns $1.0$ if $|D| = 0$).

### 1.4 Duplicate Component Rate ($M_{\text{dup}}$)
$$\text{Duplicate\_Rate}(S) = 1.0 - \frac{|\text{UniqueIdentities}(C)|}{|C|}$$
- **Numerator:** Difference between total components and unique component identities (Name + Version + Ecosystem).
- **Denominator:** Total component count $|C|$.

### 1.5 Vulnerability Matchability Index ($M_{\text{matchable}}$)
Determines the proportion of components with sufficient identity metadata to query public vulnerability intelligence (OSV, NVD) deterministically.
$$\text{Matchability}(S) = \frac{\sum_{c \in C} \mathbf{1}_{\{(\text{PURL}(c) \neq \emptyset) \lor (\text{Name}(c) \neq \emptyset \land \text{Version}(c) \neq \emptyset \land \text{Ecosystem}(c) \neq \emptyset)\}}}{|C|}$$

---

## 2. Layer 3: Vulnerability Correlation Metrics

For a set of ground-truth component-vulnerability pairs $G$ and detected pairs $P$:

### 2.1 Precision ($P_{\text{vuln}}$)
$$P_{\text{vuln}} = \frac{|\text{Confirmed Matches} \cap G|}{|\text{All Claimed Matches}|}$$

### 2.2 Recall ($R_{\text{vuln}}$)
$$R_{\text{vuln}} = \frac{|\text{Confirmed Matches} \cap G|}{|G|}$$

### 2.3 Unresolved Ambiguity Rate ($A_{\text{vuln}}$)
Proportion of matches classified as `candidate_match` due to missing version bounds or fuzzy package name alignment.
$$\text{Ambiguity\_Rate} = \frac{|\text{Candidate Matches}|}{|\text{Confirmed Matches}| + |\text{Candidate Matches}|}$$

---

## 3. Layer 5: Dependency Impact & Contextual Prioritisation

### 3.1 Downstream Impact Degree ($\text{DID}$)
For a vulnerable component $c$, let $\text{Descendants}(c)$ be all reachable nodes in the directed dependency graph $G_{\text{dep}}$:
$$\text{DID}(c) = |\text{Descendants}(c)|$$

### 3.2 Vehicle Product Reachability ($\text{PR}$)
$$\text{PR}(c) = |\{p \in \text{Products} : \exists \text{ path from } c \text{ to } p \text{ in } G_{\text{trace}}\}|$$

### 3.3 Proposed Context & Evidence-Aware Priority Score ($\text{ASG\_Score}$)
For vulnerability $v$ affecting component $c$ in product context $p$:
$$\text{ASG\_Score}(v, c, p) = \left( \alpha \cdot \frac{\text{CVSS}(v)}{10.0} + \beta \cdot \min\left(1.0, \frac{\text{DID}(c)}{K}\right) + \gamma \cdot \mathbf{1}_{\{\text{PR}(c) > 0\}} \right) \cdot \text{Conf}(c) \cdot \text{Freshness}(E)$$
- $\alpha, \beta, \gamma$: Calibrated weights ($\alpha=0.4, \beta=0.3, \gamma=0.3$).
- $K$: Normalization constant for dependency depth ($K=10$).
- $\text{Conf}(c) \in \{1.0 \text{ [exact]}, 0.5 \text{ [candidate]}, 0.0 \text{ [unresolved]}\}$.
- $\text{Freshness}(E) \in [0.0, 1.0]$ based on advisory and SBOM timestamp age.

---

## 4. Layer 5: Assurance Graph Metrics

### 4.1 False Assurance Rate ($\text{FAR}$) — Critical Safety Metric
A false assurance occurs when a claim is marked `supported` even though required evidence is missing, stale, or contradictory:
$$\text{FAR} = \frac{|\{\text{Claim } k : \text{Status}(k) = \text{supported} \land \text{GroundTruth}(k) \neq \text{supported}\}|}{|\{\text{Claim } k : \text{Status}(k) = \text{supported}\}|}$$
**Target for AutoSupplyGuard:** $\text{FAR} = 0.00\%$ (Zero False Assurance Guarantee).

### 4.2 Gap Detection Precision & Recall
- **Gap Precision:** Proportion of reported assurance gaps (`insufficient_evidence`, `stale_evidence`, `contradicted`) that represent genuine compliance deficits.
- **Gap Recall:** Proportion of actual compliance deficits correctly flagged by the engine.
