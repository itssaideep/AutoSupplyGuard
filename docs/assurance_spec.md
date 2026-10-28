# Formal Cybersecurity Assurance Specification & Decision Table (B2)

## 1. Assurance Problem Formulation

In automotive supply chain cybersecurity assurance (ISO/SAE 21434 Clause 15, UNECE R155 Annex 5), high-level security claims regarding third-party software components must be evaluated against verifiable evidence artifacts. 

To eliminate circular evaluation, this document defines the **ground truth decision logic** independently of the evaluation engine.

## 2. Factorial Corpus Dimensions

The B2 assurance corpus is constructed via a full factorial design over six operational factors:

1. **Claim Type ($C \in \{1, 2\}$):**
   - $C_1$: Component Vulnerability Assessment (`CLAIM-VULN-ASSESSMENT-02`)
   - $C_2$: Component Secure Boot & Firmware Attestation (`CLAIM-SECURE-BOOT-04`)
2. **Evidence Presence ($E \in \{\text{PRESENT}, \text{ABSENT}\}$)**
3. **Evidence Age ($T \in \{30, 89, 90, 91, 200\}$ days):**
   - Fresh: 30 days
   - Borderline Fresh: 89 days, 90 days ($\le \tau_{\text{freshness}}$)
   - Borderline Stale: 91 days ($> \tau_{\text{freshness}}$)
   - Stale: 200 days
4. **VEX Status ($V \in \{\text{NONE}, \text{AFFECTED}, \text{NOT\_AFFECTED}, \text{UNDER\_INVESTIGATION}\}$)**
5. **Version Ambiguity ($A_{\text{ver}} \in \{\text{EXACT}, \text{AMBIGUOUS}\}$)**
6. **Supplier Identity Ambiguity ($A_{\text{supp}} \in \{\text{EXACT}, \text{AMBIGUOUS}\}$)**

*Collapse Rule:* When evidence is `ABSENT`, factors 3, 4, 5, and 6 collapse into a single unevidenced state per claim type. Across the 2 claim types, the factorial design yields **$N = 98$ discrete evaluation cases**.

---

## 3. Formal Ground Truth Decision Table

| Rule ID | Evidence Presence | Age ($T$) | VEX Status | Version Ambiguity | Supplier Ambiguity | Ground Truth Status | Rationale |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **R-01** | `ABSENT` | - | - | - | - | `insufficient_evidence` | Required evidence type is missing entirely. |
| **R-02** | `PRESENT` | $\le 90$d | `AFFECTED` | Any | Any | `contradicted` | Active unmitigated CVE directly refutes security claim. |
| **R-03** | `PRESENT` | $> 90$d | Any | Any | Any | `insufficient_evidence` | Stale evidence violates temporal freshness threshold ($\tau = 90$d). |
| **R-04** | `PRESENT` | $\le 90$d | `NONE` / `NOT_AFFECTED` | `AMBIGUOUS` | Any | `insufficient_evidence` | Unresolved version identity creates unacceptable uncertainty. |
| **R-05** | `PRESENT` | $\le 90$d | `NONE` / `NOT_AFFECTED` | `EXACT` | `AMBIGUOUS` | `insufficient_evidence` | Unverified supplier provenance cannot support compliance claim. |
| **R-06** | `PRESENT` | $\le 90$d | `UNDER_INVESTIGATION` | `EXACT` | `EXACT` | `partially_supported` | Supplier investigation is active; interim claim is partially supported. |
| **R-07** | `PRESENT` | $\le 90$d | `NONE` / `NOT_AFFECTED` | `EXACT` | `EXACT` | `supported` | All required evidence is present, fresh, unambiguous, and uncontradicted. |

---

## 4. Evaluated Systems & Baselines

1. **Baseline 1 (Existence-Only):**
   - Marks claim `supported` if any artifact exists on disk; `insufficient_evidence` otherwise.
2. **Baseline 2 (Existence + Date):**
   - Marks claim `supported` if artifact exists and $T \le 90$ days; ignores VEX and ambiguity.
3. **Baseline 3 (Existence + Date + VEX):**
   - Checks existence, date, and marks `contradicted` if VEX is `AFFECTED`; ignores version and supplier identity ambiguity.
4. **AutoSupplyGuard (Proposed Engine):**
   - Evaluates completeness, temporal freshness ($\tau \le 90$d), active contradictions, version identity resolution, and supplier provenance.

---

## 5. Statistical Metrics & Confidence Intervals

- **False Assurance Rate ($\text{FAR}$):**
  $$\text{FAR} = \frac{\text{False Positives (Reported Supported when Ground Truth is Not Supported)}}{\text{Total Non-Supported Cases}}$$
- **False Rejection Rate ($\text{FRR}$):**
  $$\text{FRR} = \frac{\text{False Negatives (Reported Non-Supported when Ground Truth is Supported)}}{\text{Total Supported Cases}}$$
- **Wilson 95% Confidence Interval:**
  $$\text{CI}_{95\%} = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
  Where $z = 1.95996$. For $\hat{p} = 0.0$ and $n = 98$, the upper bound is **3.76%**.
- **Inter-Rater Reliability (Cohen's Kappa $\kappa$):**
  Evaluated on a 20% random sample ($n = 20$) against an independent second annotator.
