# AutoSupplyGuard Deployment & Execution Guide

This guide describes how to install, configure, test, and run AutoSupplyGuard in research and operational environments.

## 1. Prerequisites

- **Operating System:** Linux, macOS, or Windows 10/11
- **Python:** Python 3.10, 3.11, or 3.12
- **Package Manager:** `uv` (recommended for ultra-fast deterministic installs) or standard `pip`
- **Git:** Git 2.30+

## 2. Environment Setup

Clone the repository and set up a virtual environment:

```bash
git clone https://github.com/itssaideep/AutoSupplyGuard.git
cd AutoSupplyGuard

# Using uv (recommended)
uv venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
uv pip install -e .

# Or using standard pip
python -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
pip install -e .
```

Verify dependencies and configuration:
```bash
cp .env.example .env
```

## 3. Running Automated Tests

Run the full automated test suite (35+ unit, integration, and security tests):
```bash
pytest -v
```

All tests execute offline without requiring active external internet access.

## 4. Running the Reproducible Empirical Experiments

Execute the four experimental evaluation scripts to regenerate all empirical research findings:

```bash
# Experiment 1: SBOM Quality & Matchability (RQ1)
python scripts/run_experiment_1.py

# Experiment 2: Dependency Impact Prioritisation (RQ2)
python scripts/run_experiment_2.py

# Experiment 3: Assurance Gap & Staleness Detection (RQ3)
python scripts/run_experiment_3.py

# Experiment 4: Scalability & Memory Profiling (RQ4)
python scripts/run_experiment_4.py
```

Raw result CSV files are stored in `research/results/`.

## 5. Starting the FastAPI Backend

Launch the REST API server:
```bash
uvicorn app.api.main:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Key Endpoints:
- `GET /health`: Health and engine status
- `GET /sboms`: Ingested SBOMs and quality metrics
- `GET /components`: Normalized software components
- `GET /vulnerabilities`: Indexed CVE records and correlation matches
- `GET /relationships`: Verified and synthetic corporate relationships
- `GET /traceability/products/{product_id}`: Vehicle ECU dependency graph
- `GET /assurance/claims`: Assurance claims and assessment results
- `GET /assurance/gaps`: Active compliance gaps and stale evidence
- `GET /reports/summary`: Executive cybersecurity assurance summary

## 6. Launching the Interactive Streamlit Dashboard

Run the research dashboard:
```bash
streamlit run dashboard/app.py
```

Access the dashboard in your browser at `http://localhost:8501`.

### Dashboard Navigation:
1. **Executive Overview:** High-level KPIs, vulnerability counts, and assurance health.
2. **SBOM Quality:** Format distribution, completeness rates, and PURL metrics.
3. **Vulnerability Prioritisation:** Interactive CVSS vs. Context-Aware score comparison.
4. **Traceability Graph:** Vehicle-to-supplier multi-tier dependency visualization.
5. **Cybersecurity Assurance Cases:** ISO/SAE 21434 and UNECE R155 claim audits.
6. **Empirical Research:** Live experimental results and performance benchmarks.
