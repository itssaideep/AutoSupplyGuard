# AutoSupplyGuard Mathematical & Algorithmic Methodology

## 1. Quality Assessment Metrics

AutoSupplyGuard evaluates each ingested SBOM across five formal, normalized metrics ($M \in [0.0, 1.0]$):

### 1.1 Required-Field Completeness ($M_{\text{comp}}$)
Measures the proportion of components providing both a non-empty name and a declared version:
$$M_{\text{comp}} = \frac{|\{ c \in C \mid c.\text{name} \neq \emptyset \land c.\text{version} \neq \emptyset \}|}{|C|}$$

### 1.2 Package URL Coverage ($M_{\text{purl}}$)
Measures the proportion of components providing a valid, parser-compliant Package URL:
$$M_{\text{purl}} = \frac{|\{ c \in C \mid c.\text{purl} \neq \emptyset \land \text{Valid}(c.\text{purl}) \}|}{|C|}$$

### 1.3 Dependency Reference Resolution Rate ($M_{\text{dep}}$)
Measures the proportion of dependency edges where both the source and target component identifiers resolve to known components within the SBOM:
$$M_{\text{dep}} = \frac{|\{ (u, v) \in E \mid u \in C \land v \in C \}|}{|E|}$$
*(If $|E| = 0$, $M_{\text{dep}}$ defaults to $1.0$ if component count is $1$, or $0.0$ if multi-component).*

### 1.4 Duplicate Component Rate ($M_{\text{dup}}$)
Measures the ratio of redundant component coordinate declarations:
$$M_{\text{dup}} = 1.0 - \frac{|\{ (c.\text{name}, c.\text{version}) \mid c \in C \}|}{|C|}$$

### 1.5 Vulnerability Matchability Index ($M_{\text{match}}$)
Harmonic mean combining required-field completeness and PURL coverage:
$$M_{\text{match}} = \begin{cases} 
\frac{2 \cdot M_{\text{comp}} \cdot M_{\text{purl}}}{M_{\text{comp}} + M_{\text{purl}}}, & \text{if } M_{\text{comp}} + M_{\text{purl}} > 0 \\
0.0, & \text{otherwise}
\end{cases}$$

---

## 2. Dependency Reachability and Downstream Impact

Let $G = (V, E)$ be the directed dependency graph where an edge $(u, v) \in E$ indicates that component $u$ depends on component $v$.

### Downstream Impact Calculation
To find all components affected if library $c$ is vulnerable, we compute the ancestor set in the directed graph (or reachable nodes in the reversed graph $G^T$):
$$D(c) = |\{ u \in V_{\text{Component}} \mid u \rightsquigarrow c \}| - 1$$
where $u \rightsquigarrow c$ denotes a directed path from $u$ to $c$.

### Reachable Vehicle Products
The set of affected vehicle models or ECU subsystems $P(c)$ is defined as:
$$P(c) = \{ p \in V_{\text{Product}} \mid p \rightsquigarrow c \}$$

---

## 3. Vulnerability Prioritisation Algorithms

### Baseline A: Severity-Only (CVSS Base Score)
$$\text{Score}_A = \text{CVSS}(v)$$

### Baseline B: Severity + Dependency Count
$$\text{Score}_B = \text{CVSS}(v) \cdot (1.0 + \ln(1 + D(c)))$$

### Proposed Method: Context & Evidence-Aware Prioritisation
$$\text{Score}_{\text{proposed}} = \frac{\text{CVSS}(v)}{10.0} \cdot \omega_{\text{app}} \cdot \omega_{\text{id}} \cdot \left[1.0 + 0.4 \cdot \min(D(c), 5) + 0.5 \cdot |P(c)|\right] \cdot \omega_{\text{fresh}}$$

Where:
- **Applicability Multiplier ($\omega_{\text{app}}$):**
  - $\text{CONFIRMED\_APPLICABLE} = 1.0$
  - $\text{LIKELY\_APPLICABLE} = 0.8$
  - $\text{CANDIDATE\_MATCH} = 0.4$
  - $\text{FIXED\_WITH\_EVIDENCE} = 0.0$
  - $\text{NOT\_AFFECTED} = 0.0$
- **Identity Confidence ($\omega_{\text{id}}$):**
  - $\text{RESOLVED\_EXACT} = 1.0$
  - $\text{RESOLVED\_PARTIAL} = 0.6$
  - $\text{AMBIGUOUS} = 0.3$
- **Evidence Freshness ($\omega_{\text{fresh}}$):**
  - $\Delta t \le 90 \text{ days} = 1.0$
  - $\Delta t > 90 \text{ days} = 0.5$ (stale evidence penalty)

---

## 4. Assurance Engine Reasoning Logic

For each assurance claim $K$, let:
- $R(K)$ be the set of required evidence types.
- $A(K)$ be the set of supplied evidence artifacts.
- $\tau$ be the freshness window (default: 90 days).
- $C(K)$ be the set of active contradictions.

The claim status is evaluated deterministically:

1. **Check Contradictions:**
   $$\text{If } |C(K)| > 0 \implies \text{Status} = \text{CONTRADICTED}$$

2. **Check Evidence Type Completeness:**
   $$\text{If } \exists r \in R(K) \text{ s.t. } \neg \exists a \in A(K) \text{ with } a.\text{type} = r \implies \text{Status} = \text{INSUFFICIENT\_EVIDENCE}$$

3. **Check Freshness:**
   $$\text{If } \exists a \in A(K) \text{ s.t. } (t_{\text{current}} - a.\text{publication\_date}) > \tau \implies \text{Status} = \text{INSUFFICIENT\_EVIDENCE}$$

4. **Check Identity Resolution:**
   $$\text{If } \exists c \in \text{TargetComponents}(K) \text{ s.t. } c.\text{identity\_status} \neq \text{RESOLVED\_EXACT} \implies \text{Status} = \text{INSUFFICIENT\_EVIDENCE}$$

5. **Supported State:**
   $$\text{If none of the above fail} \implies \text{Status} = \text{SUPPORTED}$$
