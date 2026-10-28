# AutoSupplyGuard Limitations & Research Boundaries

AutoSupplyGuard is a scientific research prototype and cybersecurity assurance engine. In accordance with rigorous scientific ethics and legal transparency, this document details known limitations and boundaries.

## 1. Corporate Identity and Disambiguation Boundaries
- **Strict Isolation of Volvo Group and Volvo Cars:** Volvo Group (commercial vehicles, heavy trucks, buses, construction equipment, marine engines) and Volvo Cars (passenger motor vehicles) are distinct, independent corporate entities with separate legal structures, cybersecurity management systems, and supplier contracts. AutoSupplyGuard strictly isolates records for both entities. No corporate partnership, supplier relationship, or vulnerability finding is ever transferred or assumed between them.
- **Non-Inference of Commercial Contracts:** Corporate relationship edges are restricted to official, publicly verifiable announcements (e.g., regulatory filings, joint press releases). A generic technology partnership announcement (e.g., development of autonomous driving stacks) does not prove that a specific third-party library is physically deployed in a commercial vehicle. Such relationships are tagged with explicit limitation scopes.

## 2. Technical and Operational Limitations
- **Static vs. Runtime Reachability:** AutoSupplyGuard evaluates static dependency reachability derived from machine-readable SBOM declarations. It does not perform dynamic binary tracing, symbol resolution, or inter-procedural control flow analysis to determine if a vulnerable function is reachable at execution time.
- **Compiler Optimisations and Dead Code Stripping:** In embedded C/C++ ECU compilation, unused functions and libraries may be eliminated by linker dead-code stripping. AutoSupplyGuard conservatively assumes static dependency reachability unless overridden by an authoritative VEX or CSAF advisory.
- **Dependency on Input SBOM Quality:** If an upstream supplier delivers an SBOM omitting transitive dependencies or utilizing non-standard package naming schemes, the resulting graph coverage will be degraded. AutoSupplyGuard explicitly surfaces this uncertainty via $M_{\text{comp}}$, $M_{\text{purl}}$, and $M_{\text{match}}$ metrics rather than fabricating missing nodes.

## 3. Regulatory and Compliance Disclaimers
- **No Formal Legal Certification:** AutoSupplyGuard operationalises technical clauses of ISO/SAE 21434 and UNECE R155 to structure cybersecurity evidence. Output reports do not constitute formal legal certification, type approval, or regulatory conformity under UNECE or European Union law. Type approval requires formal assessment by accredited Technical Services.
- **Zero False Assurance Policy:** To prevent dangerous overconfidence, AutoSupplyGuard defaults to `insufficient_evidence` whenever evidence is incomplete, stale, or contradictory. It does not consider the absence of a reported vulnerability as proof of component security.
